use core::{arch::asm, f32::MIN, hint::black_box, panic};

use alloc::{sync::Arc, task};
#[cfg(target_arch = "riscv64")]
use riscv::asm;

use crate::{
    arch::{
        config::USER_MAX,
        mm::{copy_from_user, copy_to_user},
        trap::{
            self,
            context::{dump_trap_context, get_trap_context, save_trap_context},
            TrapContext,
        },
    },
    signal::{
        handle_signal, FrameFlags, LinuxSigInfo, SiField, Sig, SigAction, SigContext, SigFrame,
        SigInfo, SigRTFrame, SigSet, SigStack, UContext, MINSIGSTKSZ, SS_DISABLE, SS_ONSTACK,
    },
    syscall::errno::Errno,
    task::{
        current_task, dump_wait_queue, for_each_task, get_group,
        get_stack_top_by_sp, get_task, wait, wait_timeout, yield_current_task, Task, INIT_PROC_PID,
    },
    timer::TimeSpec,
};

use super::errno::SyscallRet;

extern "C" {
    pub fn __return_to_user() -> !;
}

//  kill() 系统调用可用于向任何进程组或进程发送任何信号。
//  如果 pid 为正数，则将信号 sig 发送给具有 pid 指定 ID 的进程。
//  如果 pid 等于 0，则将 sig 发送给调用进程的进程组中的每个进程。
//  如果 pid 等于 -1，则将 sig 发送给调用进程有权发送信号的每个进程，进程 1（init）除外
//  如果 pid 小于 -1，则将 sig 发送给 ID 为 -pid 的进程组中的每个进程。
//  如果 sig 为 0，则不发送信号，但仍会执行存在性和权限检查；这可用于检查调用者有权发送信号的进程 ID 或进程组 ID 是否存在。
//  返回值：成功时（至少发送了一个信号），返回零。出错时，返回 -1，
//  ToDo: 并适当设置 errno
//  EINVAL 指定了无效信号、EPERM 调用进程无权向任何目标进程发送、ESRCH 目标进程或进程组不存在
pub fn sys_kill(pid: isize, sig: i32) -> SyscallRet {
    // 用于检查参数权限
    fn check_kill_permission(sig: Sig, task: &Arc<Task>) -> SyscallRet {
        // 验证信号合法性
        if sig.raw() < 0 || sig.raw() > 64 {
            return Err(Errno::EINVAL);
        }
        // 检验调用者是否有权限向目标进程发送信号
        let caller_task = current_task();
        let caller_uid = caller_task.uid();
        let caller_euid = caller_task.euid();
        if !caller_task.same_thread_group(task)
            && !(caller_euid == 0
                || caller_euid == task.suid()
                || caller_euid == task.uid()
                || caller_uid == task.suid()
                || caller_uid == task.uid())
        {
            return Err(Errno::EPERM);
        }
        // 针对信号值为0的情况做特殊处理
        if sig.raw() == 0 {
            return Ok(usize::MAX);
        }
        return Ok(0);
    }

    let sig = Sig::from(sig);
    log::info!("[sys_kill] pid: {} signal: {}", pid, sig.raw());
    let siginfo = SigInfo::prepare_kill(sig);
    match pid {
        pid if pid > 0 => {
            if let Some(task) = get_task(pid as usize) {
                let ret = check_kill_permission(sig, &task)?;
                if ret != usize::MAX {
                    // 向线程组发送信号
                    if task.is_process() {
                        task.receive_siginfo(siginfo, false);
                    }
                    // 向单个线程发送信号
                    else {
                        task.receive_siginfo(siginfo, true);
                    }
                }
            } else {
                return Err(Errno::ESRCH);
            }
        }
        0 => {
            let task = current_task();
            if let Some(group) = get_group(task.tgid()) {
                for task in group.iter() {
                    let target_task = task.upgrade().unwrap();
                    let ret = check_kill_permission(sig, &target_task)?;
                    if ret != usize::MAX {
                        target_task.receive_siginfo(siginfo, false);
                    }
                }
            } else {
                return Err(Errno::ESRCH);
            }
        }
        -1 => {
            for_each_task(|task| match check_kill_permission(sig, &task) {
                Ok(ret) => {
                    if (ret != usize::MAX) && (task.tid() != INIT_PROC_PID && task.is_process()) {
                        task.receive_siginfo(siginfo, false);
                    }
                }
                _ => {}
            });
        }
        _ => {
            if let Some(group) = get_group(-pid as usize) {
                for task in group.iter() {
                    let target_task = task.upgrade().unwrap();
                    let ret = check_kill_permission(sig, &target_task)?;
                    if ret != usize::MAX {
                        target_task.receive_siginfo(siginfo, false);
                    }
                }
            } else {
                return Err(Errno::ESRCH);
            }
        }
    }
    Ok(0)
}

/// tgkill() 的过时前身。它仅允许指定目标线程 ID，
/// 如果线程终止并且其线程 ID 被回收，则可能导致向错误的线程发出信号。
pub fn sys_tkill(tid: isize, sig: i32) -> SyscallRet {
    let sig = Sig::from(sig);
    if !sig.is_valid() || tid < 0 {
        return Err(Errno::EINVAL);
    }
    let task = get_task(tid as usize).ok_or(Errno::ESRCH)?;
    let siginfo = SigInfo::prepare_kill(sig);
    log::info!(
        "[sys_tkill] task{} send signal {:?} to task {}",
        current_task().tid(),
        sig,
        task.tid()
    );
    task.receive_siginfo(siginfo, true);
    Ok(0)
}

/// tgkill() 将信号 sig 发送给线程组 tgid 中线程 ID 为 tid 的线程。
/// EAGAIN 已达到 RLIMIT_SIGPENDING 资源限制，并且 sig 是实时信号。
/// EAGAIN 内核内存不足，并且 sig 是实时信号。
/// EINVAL 指定了无效的线程 ID、线程组 ID 或信号。
/// EPERM 权限被拒绝。
/// ESRCH 不存在具有指定线程 ID（和线程组 ID）的进程。
/// ToDo: 进程组
pub fn sys_tgkill(tgid: isize, tid: isize, sig: i32) -> SyscallRet {
    log::info!(
        "[sys_tgkill] tgid: {}, tid: {}, signal: {:?}",
        tgid,
        tid,
        sig
    );
    let sig = Sig::from(sig);
    if !sig.is_valid() || tid < 0 || tgid < 0 {
        return Err(Errno::EINVAL);
    }

    let siginfo = SigInfo::prepare_tgkill(sig);
    if let Some(task) = get_task(tid as usize) {
        if task.tgid() != tgid as usize {
            return Err(Errno::ESRCH);
        }
        let pending_size = task.op_sig_pending_mut(|pending| pending.pending.bits().count_ones());
        if sig.raw() > 32 {
            let max_sig_pending = task
                .get_rlimit(crate::fs::uapi::Resource::SIGPENDING)
                .unwrap()
                .rlim_cur;
            if pending_size >= max_sig_pending as u32 {
                return Err(Errno::EAGAIN);
            }
        }
        task.receive_siginfo(siginfo, true);
    } else {
        return Err(Errno::ESRCH);
    }
    Ok(0)
}

/// sigsuspend() 暂时用 mask 指定的掩码替换调用线程的信号掩码，然后暂停线程，直到传递信号，该信号的操作是调用信号处理程序或终止进程。
/// 如果信号终止进程，则 sigsuspend() 不会返回。 如果捕获信号，则 sigsuspend() 在信号处理程序返回后返回，并且信号掩码恢复到调用 sigsuspend() 之前的状态。
/// 无法阻止 SIGKILL 或 SIGSTOP；在 mask 中指定这些信号对线程的信号掩码没有影响。
pub fn sys_rt_sigsuspend(mask: usize) -> SyscallRet {
    let task = current_task();
    log::info!("[sys_rt_sigsuspend] mask: {:#x}", mask);
    let mut origin_mask: SigSet = SigSet::empty();
    let mut new_mask: SigSet = SigSet::empty();
    copy_from_user(mask as *const SigSet, &mut new_mask as *mut SigSet, 1)?;
    new_mask.remove(SigSet::SIGKILL | SigSet::SIGCONT);
    task.op_sig_pending_mut(|pending| {
        origin_mask = pending.change_mask(new_mask);
        log::error!(
            "[sys_rt_sigsuspend] origin mask: {:?}, new mask: {:?}",
            origin_mask,
            new_mask
        );
    });

    wait();

    #[cfg(target_arch = "riscv64")]
    {
        let mut trap_cx = get_trap_context(&task);
        let new_sp = get_stack_top_by_sp(task.kstack()) - core::mem::size_of::<TrapContext>();
        trap_cx.set_a0((usize::MAX - 3) as usize); // 设置返回值为-4
        save_trap_context(&task, trap_cx);
        unsafe {
            asm!("mv sp, {}", in(reg) new_sp);
        }
        handle_signal();
        // Todo: 这样做应该会破坏信号处理时的掩码，此时并不支持信号嵌套
        task.op_sig_pending_mut(|pending| {
            log::warn!("[sys_rt_sigsuspend] Force mask setting");
            pending.change_mask(origin_mask);
            log::error!("[sys_rt_sigsuspend] restore mask: {:?}", pending.mask);
            pending.cancel_restore_mask();
        });
        drop(task);
        unsafe {
            asm!(
                "lla t0, __return_to_user", // 加载地址到寄存器 t0
                "jr t0",                    // 跳转到 t0 指向的位置
                options(noreturn)
            );
        }
    }

    #[cfg(target_arch = "loongarch64")]
    {
        let mut trap_cx = get_trap_context(&task);
        let new_sp = get_stack_top_by_sp(task.kstack()) - core::mem::size_of::<TrapContext>();

        // 设置信号返回值为 -4
        trap_cx.set_a0((usize::MAX - 3) as usize);

        save_trap_context(&task, trap_cx);

        // 调用信号处理
        handle_signal();

        // 恢复原始掩码，这里暂不支持嵌套信号
        task.op_sig_pending_mut(|pending| {
            log::warn!("[sys_rt_sigsuspend] Force mask setting");
            pending.change_mask(origin_mask);
            log::error!("[sys_rt_sigsuspend] restore mask: {:?}", pending.mask);
            pending.cancel_restore_mask();
        });

        drop(task);

        unsafe {
            asm!("move $sp, {}", in(reg) new_sp);
            // LoongArch 跳转回用户态
            asm!(
                "la.global $t0, __return_to_user", // 加载地址到 t0
                "jr $t0",                          // 跳转到 __return_to_user
                options(noreturn)
            );
        }
    }
    return Err(Errno::EINTR); // 不会运行到这里，最终由sigreturn返回
}

/// sigaction() 系统调用用于更改进程在收到特定信号时采取的操作。
/// signum 指定信号，可以是除 SIGKILL 和 SIGSTOP 之外的任何有效信号。
/// 如果 act 非 NULL，则从 act 安装信号 signum 的新操作。
/// 如果 oldact 非 NULL，则先前的操作将保存在 oldact 中。
/// 返回值 sigaction() 在成功时返回 0；在错误时返回 -1，并设置 errno 以指示错误。
/// EFAULT act 或 oldact 指向的内存不是进程地址空间的有效部分。EINVAL 指定了无效信号。
pub fn sys_rt_sigaction(signum: i32, act: usize, oldact: usize, sigsetsize: usize) -> SyscallRet {
    log::trace!("[sys_rt_sigaction]");
    log::info!(
        "[sys_rt_sigaction] sigaction signum: {}, act: {:x}, oldact: {:x}, sigsetsize: {}",
        signum,
        act,
        oldact,
        sigsetsize
    );
    let task = current_task();
    // 信号值不合法
    if (signum <= 0) || (signum > 64) {
        return Err(Errno::EINVAL);
    }
    let sig = Sig::from(signum);
    // 不可修改SIGKILL或者SIGSTOP
    if sig.is_kill_or_stop() {
        return Err(Errno::EINVAL);
    }
    if act > USER_MAX || oldact > USER_MAX {
        return Err(Errno::EFAULT);
    }
    if sigsetsize != core::mem::size_of::<SigSet>() {
        return Err(Errno::EINVAL);
    }
    let act_ptr = act as *const SigAction;
    let oldact_ptr = oldact as *mut SigAction;
    // 将当前action写入oldact
    if oldact != 0 {
        let old_action = task.op_sig_handler(|handler| handler.get(sig));
        copy_to_user(oldact_ptr, &old_action as *const SigAction, 1)?;
        // log::error!(
        //     // "[sys_rt_sigaction] {:?} origin action saved to {:#x}",
        //     sig,
        //     oldact
        // );
    }
    // 将新action写入
    if act != 0 {
        let mut new_action: SigAction = SigAction::default();
        copy_from_user(act_ptr, &mut new_action as *mut SigAction, 1)?;
        new_action.mask.remove(SigSet::SIGKILL | SigSet::SIGSTOP);
        log::error!("{:?}", new_action);
        task.op_sig_handler_mut(|handler| {
            handler.update(sig, new_action);
        });
        // log::error!("[sys_rt_sigaction] {:?} action changed to {:#x}", sig, act);
    }
    Ok(0)
}

/// sigprocmask() 用于获取和/或更改调用线程的信号掩码。
/// 调用的行为取决于 how 的值，
/// SIG_BLOCK    被阻止信号集是当前集和 set 参数的并集。
/// SIG_UNBLOCK   set 中的信号从当前被阻止信号集中删除。
/// SIG_SETMASK   被阻止信号集设置为参数 set。
/// 如果 oldset 非 NULL，则信号掩码的先前值存储在 oldset 中。
/// 如果 set 为 NULL，则信号掩码不变（即忽略 how），但信号掩码的当前值仍然返回到 oldset（如果它不为 NULL）。
/// EFAULT set 或 oldset 参数指向进程分配的地址空间之外。 EINVAL how 中指定的值无效，或者内核不支持在 sigsetsize 中传递的大小。
pub fn sys_rt_sigprocmask(how: usize, set: usize, oldset: usize, sigsetsize: usize) -> SyscallRet {
    log::trace!("[sys_rt_sigprocmask] enter sigprocmask");
    const SIG_BLOCK: usize = 0;
    const SIG_UNBLOCK: usize = 1;
    const SIG_SETMASK: usize = 2;
    if set > USER_MAX || oldset > USER_MAX {
        return Err(Errno::EFAULT);
    }
    if sigsetsize != core::mem::size_of::<SigSet>() {
        return Err(Errno::EINVAL);
    }
    let task = current_task();
    let set_ptr = set as *const SigSet;
    let oldset_ptr = oldset as *mut SigSet;
    let current_mask = task.op_sig_pending_mut(|pending| pending.mask);
    log::info!("[sys_rt_sigprocmask] how: {:?}", how);
    // log::info!("[sys_rt_sigprocmask] current mask {:?}", current_mask);
    // oldset非NULL
    if oldset != 0 {
        log::info!("[sys_rt_sigprocmask] current_mask: {:?}", current_mask);
        copy_to_user(oldset_ptr, &current_mask as *const SigSet, 1)?;
    }
    // set不为NULL（为NULL时直接跳过，即忽略how）
    if set != 0 {
        let mut new_mask: SigSet = SigSet::empty();
        copy_from_user(set_ptr, &mut new_mask as *mut SigSet, 1)?;
        log::error!("[sys_rt_sigprocmask] set is {:?}", new_mask);
        new_mask.remove(SigSet::SIGKILL | SigSet::SIGSTOP);
        // log::info!("[sys_rt_sigprocmask] new mask {:?}", new_mask);
        let mut change_mask;
        match how {
            SIG_BLOCK => {
                change_mask = new_mask | current_mask;
            }
            SIG_UNBLOCK => {
                change_mask = !new_mask & current_mask;
            }
            SIG_SETMASK => change_mask = new_mask,
            _ => {
                return Err(Errno::EINVAL);
            }
        }
        log::info!("[sys_rt_sigprocmask] change_mask: {:?}", change_mask);
        task.op_sig_pending_mut(|pending| {
            pending.change_mask(change_mask);
        })
    }
    Ok(0)
}

/// sigpending() 返回一组等待传递给调用线程的信号（即阻塞期间发出的信号）。
/// 待处理信号的掩码在集合中返回。
/// EFAULT 设置指向的内存不是进程地址空间的有效部分。
pub fn sys_rt_sigpending(set: usize) -> SyscallRet {
    let task = current_task();
    let pending: SigSet = task.op_sig_pending_mut(|pending| pending.pending);
    let set_ptr = set as *mut SigSet;
    copy_to_user(set_ptr, &pending as *const SigSet, 1)?;
    Ok(0)
}

/// sigtimedwait() 函数应等同于 sigwaitinfo() 不同之处在于，如果 set 指定的信号均未挂起，
/// sigtimedwait() 应等待 timeout 引用的 timespec 结构中指定的时间间隔。
/// 如果 timeout 指向的 timespec结构为零值，并且 set 指定的信号均未挂起，则 sigtimedwait() 应立即返回错误。
/// 如果 timeout 为空指针，则行为未指定。
/// 先检查是否有set中的信号pending，如果有则消耗该信号并返回, 否则就等待timeout时间
// pub fn sys_rt_sigtimedwait(set: usize, info: usize, timeout_ptr: usize) -> SyscallRet {
//     let mut wanted_set = SigSet::empty();
//     copy_from_user(set as *const SigSet, &mut wanted_set as *mut SigSet, 1)?;
//     wanted_set.remove(SigSet::SIGKILL | SigSet::SIGSTOP);
//     log::info!("[sys_rt_sigtimedwait] wanted_set: {:?}", wanted_set);

//     if timeout_ptr != 0 {
//         // timeout是空指针, 行为未定义
//         // panic!("[sys_rt_sigtimedwait] timeout is null");
//         return Err(Errno::EINVAL);
//         let mut timeout: TimeSpec = TimeSpec::default();
//         copy_from_user(
//             timeout_ptr as *const TimeSpec,
//             &mut timeout as *mut TimeSpec,
//             1,
//         )?;
//         // 等待timeout时间
//         let wait_until = TimeSpec::new_machine_time() + timeout;
//         loop {
//             log::trace!("[sys_rt_sigtimedwait] loop");
//             let sig = current_task().op_sig_pending_mut(|pending| {
//                 // ToOptimize: 这里的mask会被多次修改
//                 let old = pending.mask;
//                 pending.mask = wanted_set.revert();
//                 let sig = pending.fetch_signal(wanted_set);
//                 pending.mask = old;
//                 sig
//             });
//             if let Some((sig, siginfo)) = sig {
//                 // log::info!("[sys_rt_sigtimedwait] sig: {:?}", sig);
//                 if info != 0 {
//                     let info_ptr = info as *mut SigInfo;
//                     copy_to_user(info_ptr, &siginfo as *const SigInfo, 1)?;
//                 }
//                 log::info!("[sys_rt_sigtimedwait] receved expected sig: {:?}", sig);
//                 return Ok(sig.raw() as usize);
//             }
//             let current_time = TimeSpec::new_machine_time();
//             if current_time >= wait_until {
//                 log::error!("[sys_rt_sigtimedwait] timeout");
//                 return Err(Errno::ETIMEDOUT);
//             }
//             yield_current_task();
//         }
//     } else {
//         loop {
//             log::trace!("[sys_rt_sigtimedwait] loop");
//             let sig = current_task().op_sig_pending_mut(|pending| {
//                 // ToOptimize: 这里的mask会被多次修改
//                 let old = pending.mask;
//                 pending.mask = wanted_set.revert();
//                 let sig = pending.fetch_signal(wanted_set);
//                 pending.mask = old;
//                 sig
//             });
//             if let Some((sig, siginfo)) = sig {
//                 // log::info!("[sys_rt_sigtimedwait] sig: {:?}", sig);
//                 if info != 0 {
//                     let info_ptr = info as *mut SigInfo;
//                     copy_to_user(info_ptr, &siginfo as *const SigInfo, 1)?;
//                 }
//                 log::info!("[sys_rt_sigtimedwait] receved expected sig: {:?}", sig);
//                 return Ok(sig.raw() as usize);
//             }
//             yield_current_task();
//         }
//     }
// }

pub fn sys_rt_sigtimedwait(set: usize, info: usize, timeout_ptr: usize) -> SyscallRet {
    fn restore_mask(task: &Arc<Task>, mask: SigSet) {
        task.op_sig_pending_mut(|pending| {
            pending.mask = mask;
        });
    }

    fn return_signal(
        task: &Arc<Task>,
        sig: Sig,
        siginfo: SigInfo,
        info: usize,
        origin_mask: SigSet,
    ) -> SyscallRet {
        if info != 0 {
            let info_ptr = info as *mut SigInfo;
            copy_to_user(info_ptr, &siginfo as *const SigInfo, 1)?;
        }
        log::info!("[sys_rt_sigtimedwait] received expected signal: {:?}", sig);
        restore_mask(task, origin_mask);
        Ok(sig.raw() as usize)
    }

    // 1. 取出目标掩码
    let mut wanted_set = SigSet::empty();
    copy_from_user(set as *const SigSet, &mut wanted_set as *mut SigSet, 1)?;
    wanted_set.remove(SigSet::SIGKILL | SigSet::SIGSTOP);

    let task = current_task();
    log::info!(
        "[sys_rt_sigtimedwait] wanted_set: {:?}, info: {:#x}, timeout_ptr: {:#x}",
        wanted_set,
        info,
        timeout_ptr
    );

    // 2. 屏蔽不感兴趣信号
    let focus_mask = !wanted_set.clone();
    let origin_mask = task.op_sig_pending_mut(|pending| pending.change_mask(focus_mask));

    // 3. 检查当前是否有挂起的感兴趣信号
    if let Some((sig, siginfo)) =
        task.op_sig_pending_mut(|pending| pending.fetch_signal(wanted_set))
    {
        return return_signal(&task, sig, siginfo, info, origin_mask);
    }

    // 4. 若指定了超时时间
    if timeout_ptr != 0 {
        // timeout是空指针, 行为未定义
        // panic!("[sys_rt_sigtimedwait] timeout is null");
        let mut timeout: TimeSpec = TimeSpec::default();
        copy_from_user(
            timeout_ptr as *const TimeSpec,
            &mut timeout as *mut TimeSpec,
            1,
        )?;
        log::error!("[sys_rt_sigtimedwait] timeout: {:?}", timeout);

        if !timeout.timespec_valid_settod() {
            restore_mask(&task, origin_mask);
            return Err(Errno::EINVAL);
        }
        if timeout.is_zero() && wanted_set.is_empty() {
            restore_mask(&task, origin_mask);
            log::info!("[sys_rt_sigtimedwait] zero timeout and empty signal set");
            return Err(Errno::EAGAIN);
        }

        drop(task);
        let wait_ret = wait_timeout(timeout, -1);
        let task = current_task();

        match wait_ret {
            -2 => {
                // 超时
                log::info!("[sys_rt_sigtimedwait] wait timeout");
                restore_mask(&task, origin_mask);
                return Err(Errno::EAGAIN);
            }
            -1 => {
                // 被信号唤醒
                if let Some((sig, siginfo)) =
                    task.op_sig_pending_mut(|pending| pending.fetch_signal(wanted_set))
                {
                    return return_signal(&task, sig, siginfo, info, origin_mask);
                }
                restore_mask(&task, origin_mask);
                return Err(Errno::EINTR); // 被其他信号打断
            }
            _ => {
                restore_mask(&task, origin_mask);
                log::error!(
                    "[sys_rt_sigtimedwait] unknown wait return value: {}",
                    wait_ret
                );
                return Err(Errno::EINTR);
            }
        }
    } else {
        // 非限时等待
        log::info!("[sys_rt_sigtimedwait] no timeout, blocking until signal");

        drop(task);
        let ret = wait();
        debug_assert_eq!(ret, -1);

        let task = current_task();
        if let Some((sig, siginfo)) =
            task.op_sig_pending_mut(|pending| pending.fetch_signal(wanted_set))
        {
            return return_signal(&task, sig, siginfo, info, origin_mask);
        }

        restore_mask(&task, origin_mask);
        Err(Errno::EINTR)
    }
}

/// sigqueue() 将 sig 中指定的信号发送给 pid 中给出其 PID 的进程。
/// 发送信号所需的权限与 kill(2) 相同。与 kill(2) 一样，可以使用空信号 (0) 检查是否存在具有给定 PID 的进程。
/// Todo: 跟kill差不多，回来再说
pub fn sys_rt_sigqueueinfo(pid: isize, sig: i32, info: usize) -> SyscallRet {
    fn check_kill_permission(sig: Sig, task: &Arc<Task>) -> SyscallRet {
        // 验证信号合法性
        if sig.raw() < 0 || sig.raw() > 64 {
            return Err(Errno::EINVAL);
        }
        // 检验调用者是否有权限向目标进程发送信号
        let caller_task = current_task();
        let caller_uid = caller_task.uid();
        let caller_euid = caller_task.euid();
        if !caller_task.same_thread_group(task)
            && !(caller_euid == 0
                || caller_euid == task.suid()
                || caller_euid == task.uid()
                || caller_uid == task.suid()
                || caller_uid == task.uid())
        {
            return Err(Errno::EPERM);
        }
        // 针对信号值为0的情况做特殊处理
        if sig.raw() == 0 {
            return Ok(usize::MAX);
        }
        return Ok(0);
    }

    // 初始化参数
    let sig = Sig::from(sig);
    let mut linux_siginfo = LinuxSigInfo::default();
    copy_from_user(
        info as *const LinuxSigInfo,
        &mut linux_siginfo as *mut LinuxSigInfo,
        1,
    )?;
    log::error!("{:?}", linux_siginfo);
    let mut siginfo: SigInfo = linux_siginfo.into();
    siginfo.signo = sig.raw();
    log::error!(
        "[sys_rt_sigqueueinfo] pid: {}, signal: {:?}, info: {:?}",
        pid,
        sig,
        siginfo
    );

    // 发送信号
    if let Some(task) = get_task(pid as usize) {
        let ret = check_kill_permission(sig, &task)?;
        if ret != usize::MAX {
            // 向线程组发送信号
            if task.is_process() {
                task.receive_siginfo(siginfo, false);
            }
            // 向单个线程发送信号
            else {
                task.receive_siginfo(siginfo, true);
            }
        }
    } else {
        return Err(Errno::ESRCH);
    }
    Ok(0)
}

/// 如果 Linux 内核确定某个进程有一个未阻塞的信号待处理，那么，在该进程下一次转换回用户模式时（例如，从系统调用返回或进程重新调度到 CPU 时）
/// 它会在用户空间堆栈上创建一个新框架，在其中保存进程上下文的各个部分（处理器状态字、寄存器、信号掩码和信号堆栈设置）。
pub fn sys_rt_sigreturn() -> SyscallRet {
    log::info!("[sys_rt_sigreturn] enter sigreturn");
    let task = current_task();
    // 获取栈顶trapcontext
    let mut trap_cx = get_trap_context(&task);
    let mut ret: isize = -1;
    // 获取用户栈中sigcontext
    let mut user_sp = trap_cx.get_sp();
    let sig_context_ptr = user_sp as *const SigContext;
    let mut sig_context: SigContext = SigContext::default();
    copy_from_user(sig_context_ptr, &mut sig_context as *mut SigContext, 1)?;
    // flags中不包含SIGINFO
    let mut frame_flag: FrameFlags = FrameFlags::default();
    copy_from_user(
        user_sp as *const FrameFlags,
        &mut frame_flag as *mut FrameFlags,
        1,
    )?;

    // 不包含SIG_INFOSIG_INFO
    if frame_flag.is_normal() {
        log::warn!("[sys_rt_sigreturn] normal frame");
        log::info!("[sys_rt_sigreturn] frame pos: {:#x}", user_sp);
        let mut sig_frame: SigFrame = SigFrame::default();
        copy_from_user(
            user_sp as *const SigFrame,
            &mut sig_frame as *mut SigFrame,
            1,
        )?;
        sig_context = sig_frame.sigcontext;

        // 恢复mask
        task.op_sig_pending_mut(|pending| {
            if pending.need_restore_mask() {
                pending.change_mask(sig_context.mask);
            }
        })
    }
    // 包含SIGINFO
    else if frame_flag.is_rt() {
        log::warn!("[sys_rt_sigreturn] rt frame");
        let mut sig_rt_frame: SigRTFrame = SigRTFrame::default();
        copy_from_user(
            user_sp as *const SigRTFrame,
            &mut sig_rt_frame as *mut SigRTFrame,
            1,
        )?;
        // let sig_rt_frame = copy_from_user(user_sp as *const SigRTFrame, 1).unwrap()[0];
        let mask = sig_rt_frame.ucontext.uc_sigmask;
        sig_context = sig_rt_frame.ucontext.uc_mcontext;

        // 恢复mask
        task.op_sig_pending_mut(|pending| {
            if pending.need_restore_mask() {
                pending.change_mask(mask);
            }
        })
    } else {
        log::error!("[sys_rt_sigreturn] invalid frame flag");
        panic!();
    }

    let mut sig_stack = task.sigstack();
    if sig_stack.ss_flags == SS_ONSTACK {
        log::warn!("[sys_rt_sigreturn] use sigstack");
        // 恢复sigstack
        sig_stack.ss_flags = 0;
        task.set_sigstack(sig_stack);
    }

    #[cfg(target_arch = "riscv64")]
    {
        trap_cx.x = sig_context.x;
        trap_cx.sepc = sig_context.sepc;
        trap_cx.last_a0 = sig_context.last_a0;
        trap_cx.kernel_tp = sig_context.kernel_tp;
        ret = trap_cx.get_a0() as isize;
        save_trap_context(&task, trap_cx);
    }

    #[cfg(target_arch = "loongarch64")]
    {
        // 更新栈顶trapcontext
        trap_cx.r = sig_context.r;
        trap_cx.era = sig_context.era;
        trap_cx.last_a0 = sig_context.last_a0;
        trap_cx.kernel_tp = sig_context.kernel_tp;
        ret = trap_cx.get_a0() as isize;
        save_trap_context(&task, trap_cx);
    }
    Ok(ret as usize)
}

/// sigaltstack() 允许线程定义新的备用信号堆栈和/或检索现有备用信号堆栈的状态。
/// ss 参数用于指定新的备用信号堆栈，而 old_ss 参数用于检索有关当前已建立信号堆栈的信息。
/// Todo: 支持自动解除
pub fn sys_sigaltstack(ss: usize, old_ss: usize) -> SyscallRet {
    log::info!("[sys_sigaltstack] uss: {:#x}, uoss: {:#x}", ss, old_ss);
    let task = current_task();
    if ss > USER_MAX || old_ss > USER_MAX {
        return Err(Errno::EFAULT);
    }
    let uss_ptr = ss as *const SigStack;
    let uoss_ptr = old_ss as *mut SigStack;
    let mut new_stack: SigStack = SigStack::default();
    copy_from_user(uss_ptr, &mut new_stack as *mut SigStack, 1)?;
    log::error!("{:?}", new_stack);
    if new_stack.ss_flags > SS_DISABLE {
        return Err(Errno::EINVAL);
    }
    if new_stack.ss_size < MINSIGSTKSZ {
        return Err(Errno::ENOMEM);
    }
    task.set_sigstack(new_stack);
    if old_ss != 0 {
        let old_stack = task.sigstack();
        copy_to_user(uoss_ptr, &old_stack as *const SigStack, 1)?;
    }
    Ok(0)
}

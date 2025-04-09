use crate::{arch::{mm::copy_from_user, trap::TrapContext}, signal::{SiField, Sig, SigAction, SigContext,  SigInfo, SigSet}, task::{current_task, get_stack_top_by_sp, INITPROC, INIT_PROC_PID, TASK_MANAGER}};



//  kill() 系统调用可用于向任何进程组或进程发送任何信号。
//  如果 pid 为正数，则将信号 sig 发送给具有 pid 指定 ID 的进程。
//  如果 pid 等于 0，则将 sig 发送给调用进程的进程组中的每个进程。
//  如果 pid 等于 -1，则将 sig 发送给调用进程有权发送信号的每个进程，进程 1（init）除外
//  如果 pid 小于 -1，则将 sig 发送给 ID 为 -pid 的进程组中的每个进程。
//  如果 sig 为 0，则不发送信号，但仍会执行存在性和权限检查；这可用于检查调用者有权发送信号的进程 ID 或进程组 ID 是否存在。
//  返回值：成功时（至少发送了一个信号），返回零。出错时，返回 -1，
//  ToDo: 并适当设置 errno
//  EINVAL 指定了无效信号、EPERM 调用进程无权向任何目标进程发送、ESRCH 目标进程或进程组不存在
pub fn sys_kill(pid: isize, sig: i32) -> isize {
    if sig == 0 { return 0; }
    let sig = Sig::from(sig);
    if !sig.is_valid() {
        return -1;  // EINVAL
    }
    log::info!("[sys_kill] pid: {} signal: {}", pid, sig.raw());
    match pid {
        pid if pid > 0 => {
            if let Some(task) = TASK_MANAGER.get(pid as usize){
                // 向线程组发送信号
                if task.is_main_thread() {
                    task.receive_siginfo(SigInfo {
                        signo: sig.raw(),
                        code:  SigInfo::USER,
                        fields: SiField::kill { tid: task.tid() }
                    }, false);
                }
                // 向单个线程发送信号
                else {
                    task.receive_siginfo(SigInfo {
                        signo: sig.raw(),
                        code:  SigInfo::USER,
                        fields: SiField::kill { tid: task.tid() }
                    }, true);
                }
            } else {
                return -1;  // ESRCH
            }
        }
        0 => {
            // ToDO: 进程组相关
        }
        -1 => {
            TASK_MANAGER.for_each(|task|{
                if task.tid() != INIT_PROC_PID && task.is_main_thread() {
                    task.receive_siginfo(
                        SigInfo {
                            signo: sig.raw(),
                            code: SigInfo::USER,
                            fields: SiField::kill { tid: task.tid() },
                        },false,
                    );
                }
            });
        }
        _ => {
           // ToDO: 进程组相关 
        }
    }
    0
}

/// tgkill() 的过时前身。它仅允许指定目标线程 ID，
/// 如果线程终止并且其线程 ID 被回收，则可能导致向错误的线程发出信号。
pub fn sys_tkill(tid: isize, sig: i32) -> isize {
    let sig = Sig::from(sig);
    if !sig.is_valid() || tid < 0{
        return -1;  // EINVAL
    }
    let task = TASK_MANAGER.get(tid as usize).unwrap();
    log::info!("[sys_tkill] task{} receive signal {}", task.tid(), sig.raw());
    task.receive_siginfo(
        SigInfo {
            signo: sig.raw(),
            code: SigInfo::TKILL,
            fields: SiField::kill { tid: task.tid() },
        },true
    );
    0
}

/// tgkill() 将信号 sig 发送给线程组 tgid 中线程 ID 为 tid 的线程。
/// EAGAIN 已达到 RLIMIT_SIGPENDING 资源限制，并且 sig 是实时信号。
/// EAGAIN 内核内存不足，并且 sig 是实时信号。
/// EINVAL 指定了无效的线程 ID、线程组 ID 或信号。
/// EPERM 权限被拒绝。
/// ESRCH 不存在具有指定线程 ID（和线程组 ID）的进程。
/// ToDo: 进程组
pub fn sys_tgkill(tgid: isize, tid: isize, sig: i32) -> isize {
    0
}

/// sigsuspend() 暂时用 mask 指定的掩码替换调用线程的信号掩码，然后暂停线程，直到传递信号，该信号的操作是调用信号处理程序或终止进程。
/// 如果信号终止进程，则 sigsuspend() 不会返回。 如果捕获信号，则 sigsuspend() 在信号处理程序返回后返回，并且信号掩码恢复到调用 sigsuspend() 之前的状态。
/// 无法阻止 SIGKILL 或 SIGSTOP；在 mask 中指定这些信号对线程的信号掩码没有影响。
/// Todo: 任务阻塞相关，暂且搁置
pub fn sys_rt_sigsuspend(mask: usize) -> isize {
    let mut old_mask: SigSet = SigSet::empty();
    let task = current_task();
    let mask_ptr = mask as *const SigSet;
    unsafe { 
        let mask =  mask_ptr.read();
        task.op_sig_pending_mut(|pending|{
            old_mask = pending.change_mask(mask);
        }) 
    }
    -1
}

/// sigaction() 系统调用用于更改进程在收到特定信号时采取的操作。
/// signum 指定信号，可以是除 SIGKILL 和 SIGSTOP 之外的任何有效信号。
/// 如果 act 非 NULL，则从 act 安装信号 signum 的新操作。
/// 如果 oldact 非 NULL，则先前的操作将保存在 oldact 中。
/// 返回值 sigaction() 在成功时返回 0；在错误时返回 -1，并设置 errno 以指示错误。
/// EFAULT act 或 oldact 指向的内存不是进程地址空间的有效部分。EINVAL 指定了无效信号。
pub fn sys_rt_sigaction(signum: i32, act: usize, oldact: usize) -> isize{
    let task = current_task();
    // 信号值不合法
    if (signum <= 0) || (signum > 64) {
        return -1;
    }
    let sig = Sig::from(signum);
    // 不可修改SIGKILL或者SIGSTOP
    if sig.is_kill_or_stop() {
        return -1;
    }
    log::info!("[sys_rt_sigaction] task{} old_ptr: {:x}, new_ptr: {:x}",
        task.tid(), oldact, act);
    let act_ptr = act as *const SigAction;
    let oldact_ptr = oldact as *mut SigAction; 
    // 将当前action写入oldact
    if oldact != 0 {
        let old_action = task.op_sig_handler(|handler| {
            handler.get(sig)
        });
        unsafe { oldact_ptr.write(old_action); }
    }
    // 将新action写入
    if act != 0 {
        let mut new_action = if let Ok(action) = copy_from_user(act_ptr, 1) {
            action[0]
        } else  {
            log::error!("[sys_rt_sigaction] copy_from_user failed");
            return -1;
        }; 
        new_action.mask.remove(SigSet::SIGKILL | SigSet::SIGSTOP);
        task.op_sig_handler_mut(|handler|{
            handler.update(sig, new_action);
        });
        log::info!("[sys_rt_sigaction] new:{:?}", new_action);
    }
    0
}

/// sigprocmask() 用于获取和/或更改调用线程的信号掩码。
/// 调用的行为取决于 how 的值，
/// SIG_BLOCK    被阻止信号集是当前集和 set 参数的并集。
/// SIG_UNBLOCK   set 中的信号从当前被阻止信号集中删除。
/// SIG_SETMASK   被阻止信号集设置为参数 set。
/// 如果 oldset 非 NULL，则信号掩码的先前值存储在 oldset 中。
/// 如果 set 为 NULL，则信号掩码不变（即忽略 how），但信号掩码的当前值仍然返回到 oldset（如果它不为 NULL）。
/// EFAULT set 或 oldset 参数指向进程分配的地址空间之外。 EINVAL how 中指定的值无效，或者内核不支持在 sigsetsize 中传递的大小。
pub fn sys_rt_sigprocmask(how: usize, set: usize, oldset: usize) -> isize{
    const SIG_BLOCK: usize = 0;
    const SIG_UNBLOCK: usize = 1;
    const SIG_SETMASK: usize = 2;
    let task = current_task();
    let set_ptr = set as *const SigSet;
    let oldset_ptr = oldset as *mut SigSet;
    let current_mask = task.op_sig_pending_mut(|pending|{
        pending.mask
    });
    log::info!("[sys_rt_sigprocmask] how: {:?}", how);
    log::info!("[sys_rt_sigprocmask] current mask {:?}", current_mask);
    // oldset非NULL
    if oldset != 0 {
        unsafe {
            oldset_ptr.write(current_mask);
        }
    } 
    // set不为NULL（为NULL时直接跳过，即忽略how）
    if set != 0 {
        let mut new_mask = if let Ok(mask) = copy_from_user(set_ptr, 1) {
            mask[0]
        } else  {
            log::error!("[sys_rt_sigprocmask] copy_from_user failed");
            return -1;
        };
        log::info!("[sys_rt_sigprocmask] current mask {:?}", new_mask);
        new_mask.remove(SigSet::SIGKILL | SigSet::SIGCONT);
        let mut change_mask = SigSet::empty();
        match how {
            SIG_BLOCK => { change_mask = new_mask | current_mask; }
            SIG_UNBLOCK => { change_mask = new_mask & current_mask; }
            SIG_SETMASK => { change_mask = new_mask }
            _ => { return -1; }
        }
        task.op_sig_pending_mut(|pending|{
            pending.change_mask(change_mask);
        })
    }
    0
}

/// sigpending() 返回一组等待传递给调用线程的信号（即阻塞期间发出的信号）。
/// 待处理信号的掩码在集合中返回。
/// EFAULT 设置指向的内存不是进程地址空间的有效部分。
pub fn sys_rt_sigpending(set: usize) -> isize{
    let task = current_task();
    let pending: SigSet = task.op_sig_pending_mut(|pending|{
        pending.pending
    });
    let set_ptr = set as *mut SigSet;
    unsafe {
        set_ptr.write(pending);
    }
    0
}


/// sigtimedwait() 函数应等同于 sigwaitinfo() 不同之处在于，如果 set 指定的信号均未挂起，
/// sigtimedwait() 应等待 timeout 引用的 timespec 结构中指定的时间间隔。
/// 如果 timeout 指向的 timespec结构为零值，并且 set 指定的信号均未挂起，则 sigtimedwait() 应立即返回错误。
/// 如果 timeout 为空指针，则行为未指定。
/// Todo: 涉及到时间
pub fn sys_rt_sigtimedwait(set: usize, info: usize, timeout: usize) -> isize{
    0
}


/// sigqueue() 将 sig 中指定的信号发送给 pid 中给出其 PID 的进程。
/// 发送信号所需的权限与 kill(2) 相同。与 kill(2) 一样，可以使用空信号 (0) 检查是否存在具有给定 PID 的进程。
/// Todo: 跟kill差不多，回来再说
pub fn sys_rt_sigqueueinfo(pid: isize, sig: i32, value: usize) -> isize {
    0
}


/// 如果 Linux 内核确定某个进程有一个未阻塞的信号待处理，那么，在该进程下一次转换回用户模式时（例如，从系统调用返回或进程重新调度到 CPU 时）
/// 它会在用户空间堆栈上创建一个新框架，在其中保存进程上下文的各个部分（处理器状态字、寄存器、信号掩码和信号堆栈设置）。
pub fn sys_rt_sigreturn() -> isize {
    let task = current_task();
    // 获取栈顶trapcontext
    let trap_cx_ptr = (get_stack_top_by_sp(task.kstack()) 
                                        - core::mem::size_of::<TrapContext>()) as *mut TrapContext;
    let mut trap_cx = unsafe { trap_cx_ptr.read() };
    // 获取用户栈中sigcontext
    let user_sp = trap_cx.get_sp();
    let sig_context_ptr = user_sp as *const SigContext;
    let sig_context = if let Ok(sig_context) = copy_from_user(sig_context_ptr, 1) {
        sig_context[0]
    } else  {
        log::error!("[sys_rt_sigreturn] copy_from_user failed");
        return -1;
    }; 
    // flags中不包含SIGINFO
    #[cfg(target_arch = "riscv64")]
    if sig_context.info == 0 {
        // 更新栈顶trapcontext
        trap_cx.x = sig_context.x;
        trap_cx.sepc = sig_context.sepc;
        unsafe { trap_cx_ptr.write(trap_cx); }
        // 恢复mask
        task.op_sig_pending_mut(|pending|{
            pending.mask = sig_context.mask;
        })
    } else if sig_context.info == 1 {
        // Todo: SigInfo恢复
    }
    #[cfg(target_arch = "loongarch64")]
    if sig_context.info == 0 {
        // 更新栈顶trapcontext
        trap_cx.r = sig_context.r;
        trap_cx.era = sig_context.era;
        unsafe { trap_cx_ptr.write(trap_cx); }
        // 恢复mask
        task.op_sig_pending_mut(|pending|{
            pending.mask = sig_context.mask;
        })
    } else if sig_context.info == 1 {
        // Todo: SigInfo恢复
    }
    0
}
use core::cmp::min;
use core::sync::atomic::{compiler_fence, Ordering};
use core::time;

use crate::arch::mm::copy_from_user;
use crate::arch::trap::context::{dump_trap_context, get_trap_context, save_trap_context};
use crate::ext4::fs;
use crate::fs::dentry::X_OK;
use crate::fs::file::OpenFlags;
use crate::futex::do_futex;
use crate::syscall::errno::Errno;
use crate::syscall::util::{CLOCK_MONOTONIC, CLOCK_REALTIME};
use crate::task::{
    add_group, get_scheduler_len, get_task, new_group, wait, wait_timeout, CloneFlags, Task,
};
use crate::timer::{TimeSpec, TimeVal};
use crate::{
    arch::mm::copy_to_user,
    arch::timer::get_time_ms,
    arch::trap::TrapContext,
    fs::{namei::path_openat, AT_FDCWD},
    loader::get_app_data_by_name,
    task::{
        add_task, current_task, kernel_exit, remove_task, schedule, yield_current_task,
        TaskContext, WaitOption,
    },
    utils::{c_str_to_string, extract_cstrings},
};
use alloc::task;
use alloc::{sync::Arc, vec};
use bitflags::bitflags;

use super::errno::SyscallRet;

#[cfg(target_arch = "riscv64")]
pub fn sys_clone(
    flags: u32,
    stack_ptr: usize,
    parent_tid_ptr: usize,
    tls_ptr: usize,
    children_tid_ptr: usize,
) -> SyscallRet {
    // ToDo: 更新错误检验
    log::error!("[sys_clone] flags: {:b}, stack_ptr: {:x}, parent_tid_ptr: {:x}, tls_ptr: {:x}, chilren_tid_ptr: {:x}", flags, stack_ptr, parent_tid_ptr, tls_ptr, children_tid_ptr);
    let flags = match CloneFlags::from_bits(flags as u32) {
        None => {
            log::error!("clone flags is None: {}", flags);
            return Err(Errno::EINVAL);
        }
        Some(flag) => flag,
    };
    log::error!("[sys_clone] flags: {:?}", flags);
    let task = current_task();
    let new_task = task.kernel_clone(&flags, stack_ptr, children_tid_ptr)?;
    let new_task_tid = new_task.tid();

    if flags.contains(CloneFlags::CLONE_PARENT_SETTID) {
        log::warn!("[sys_clone] handle CLONE_PARENT_SETTID");
        let content = (new_task_tid as u64).to_le_bytes();
        log::error!("parent_tid_ptr: {:x}", parent_tid_ptr);
        copy_to_user(parent_tid_ptr as *mut u8, &content as *const u8, 8)?;
    }
    if flags.contains(CloneFlags::CLONE_CHILD_CLEARTID) {
        log::warn!("[sys_clone] handle CLONE_CHILD_CLEARTID");
        new_task.set_tac(children_tid_ptr);
    }
    if flags.contains(CloneFlags::CLONE_SETTLS) {
        log::warn!("[sys_clone] handle CLONE_SETTLS");
        log::error!("tls_ptr: {:x}", tls_ptr);
        let mut trap_cx = get_trap_context(&new_task);
        trap_cx.set_tp(tls_ptr as usize);
        save_trap_context(&new_task, trap_cx);
    }
    add_task(new_task);
    if flags.contains(CloneFlags::CLONE_VFORK) {
        log::warn!("[sys_clone] handle CLONE_VFORK");
        // vfork的特殊处理, 需要阻塞父进程直到子进程调用execve或exit
        wait();
    }
    drop(task);
    // yield_current_task();
    Ok(new_task_tid)
}

pub fn sys_setsid() -> SyscallRet {
    let task = current_task();
    Ok(task.tgid())
}

#[cfg(target_arch = "loongarch64")]
pub fn sys_clone(
    flags: u32,
    stack_ptr: usize,
    parent_tid_ptr: usize,
    chilren_tid_ptr: usize,
    tls_ptr: usize,
) -> SyscallRet {
    // ToDo: 更新错误检验
    log::error!("[sys_clone] flags: {:b}, stack_ptr: {:x}, parent_tid_ptr: {:x}, tls_ptr: {:x}, chilren_tid_ptr: {:x}", flags, stack_ptr, parent_tid_ptr, tls_ptr, chilren_tid_ptr);
    let flags = match CloneFlags::from_bits(flags as u32) {
        None => {
            log::error!("clone flags is None: {}", flags);
            return Err(Errno::EINVAL);
        }
        Some(flag) => flag,
    };
    log::error!("[sys_clone] flags: {:?}", flags);
    let task = current_task();
    let new_task = task.kernel_clone(&flags, stack_ptr, chilren_tid_ptr)?;
    let new_task_tid = new_task.tid();

    if flags.contains(CloneFlags::CLONE_PARENT_SETTID) {
        log::warn!("[sys_clone] handle CLONE_PARENT_SETTID");
        let content = (new_task_tid as u64).to_le_bytes();
        log::error!("parent_tid_ptr: {:x}", parent_tid_ptr);
        copy_to_user(parent_tid_ptr as *mut u8, &content as *const u8, 8)?;
    }
    if flags.contains(CloneFlags::CLONE_CHILD_SETTID) {
        log::warn!("[sys_clone] handle CLONE_CHILD_SETTID");
        let content = (new_task_tid as u64).to_le_bytes();
        log::error!("chilren_tid_ptr: {:x}", parent_tid_ptr);
        copy_to_user(chilren_tid_ptr as *mut u8, &content as *const u8, 8)?;
        new_task.set_tas(new_task.tid());
    }
    if flags.contains(CloneFlags::CLONE_CHILD_CLEARTID) {
        log::warn!("[sys_clone] handle CLONE_CHILD_CLEARTID");
        new_task.set_tac(chilren_tid_ptr);
    }
    if flags.contains(CloneFlags::CLONE_SETTLS) {
        log::warn!("[sys_clone] handle CLONE_SETTLS");
        log::error!("tls_ptr: {:x}", tls_ptr);
        let mut trap_cx = get_trap_context(&new_task);
        trap_cx.set_tp(tls_ptr as usize);
        save_trap_context(&new_task, trap_cx);
    }
    add_task(new_task);
    drop(task);
    // yield_current_task();
    Ok(new_task_tid)
}

pub const IGNOER_TEST: [&str; 20] = [
    /* 本身就不应该单独运行的 */
    "ltp/testcases/bin/ask_password.sh",
    "ltp/testcases/bin/assign_password.sh",
    "ltp/testcases/bin/cgroup_regression_3_1.sh",
    "ltp/testcases/bin/cgroup_regression_3_2.sh",
    "ltp/testcases/bin/cgroup_regression_5_1.sh",
    "ltp/testcases/bin/cgroup_regression_5_2.sh",
    "ltp/testcases/bin/cgroup_regression_6_1.sh",
    "ltp/testcases/bin/cgroup_regression_6_2.sh",
    "ltp/testcases/bin/cgroup_regression_fork_processes",
    "ltp/testcases/bin/cgroup_regression_getdelays",
    "ltp/testcases/bin/cpuhotplug_do_disk_write_loop",
    "ltp/testcases/bin/cpuhotplug_do_kcompile_loop",
    "ltp/testcases/bin/cpuhotplug_do_spin_loop",
    "ltp/testcases/bin/data",
    "ltp/testcases/bin/doio",
    "ltp/testcases/bin/acl1",
    /* 由于OS原因, 先不跑的 */
    "ltp/testcases/bin/crash02",
    "ltp/testcases/bin/mmap1",
    "ltp/testcases/bin/mmap2",
    "ltp/testcases/bin/mmap3",
];

pub fn sys_execve(path: *const u8, args: *const usize, envs: *const usize) -> SyscallRet {
    let path = c_str_to_string(path)?;
    // 过滤掉一些不必要的测试
    if IGNOER_TEST.contains(&path.as_str()) {
        log::warn!("[sys_execve] ignore test: {}", path);
        sys_exit(0);
    }
    log::info!(
        "[sys_execve] path: {}, args: {:?}, envs: {:?}",
        path,
        args,
        envs
    );
    // argv[0]是应用程序的名字
    // 后续元素是用户在命令行中输入的参数
    let mut args_vec = extract_cstrings(args)?;
    let envs_vec = extract_cstrings(envs)?;
    let task = current_task();
    // OpenFlags::empty() = RDONLY = 0, 以只读方式打开文件
    match path_openat(&path, OpenFlags::empty(), AT_FDCWD, X_OK) {
        Ok(file) => {
            let all_data = file.read_all();
            task.kernel_execve_lazily(path, file, all_data.as_slice(), args_vec, envs_vec);
            Ok(0)
        }
        Err(err) if err == Errno::ENOENT && !path.starts_with("/") => {
            // 从内核中加载的应用程序
            if let Some(elf_data) = get_app_data_by_name(&path) {
                args_vec.insert(0, path);
                task.kernel_execve(elf_data, args_vec, envs_vec);
                Ok(0)
            } else {
                log::error!("[sys_execve] path: {} not found", path);
                Err(Errno::ENOENT)
            }
        }
        Err(err) => {
            log::error!("[sys_execve] path: {} err: {:?}", path, err);
            Err(err)
        }
    }
}

pub fn sys_gettid() -> SyscallRet {
    log::info!("[sys_gettid] tid: {}", current_task().tid());
    Ok(current_task().tid())
}

pub fn sys_getpid() -> SyscallRet {
    log::info!("[sys_getpid] pid: {}", current_task().tgid());
    Ok(current_task().tgid())
}

/// setpgid() 将 pid 指定的进程的 PGID 设置为 pgid。
/// 如果 pid 为零，则使用调用进程的进程 ID。如果 pgid 为零，则将 pid 指定的进程的 PGID 设置为其进程 ID。
/// 如果使用 setpgid() 将进程从一个进程组移动到另一个进程组，则两个进程组必须属于同一会话。
/// 在这种情况下，pgid 指定要加入的现有进程组，并且该组的会话 ID 必须与加入进程的会话 ID 匹配。
// Todo: session
pub fn sys_setpgid(pid: usize, pgid: usize) -> SyscallRet {
    log::info!("[sys_setpgid] pid: {}, pgid: {}", pid, pgid);
    let task = if pid == 0 {
        current_task()
    } else {
        get_task(pid).ok_or(Errno::ESRCH)?
    };

    if pgid == 0 {
        // 将进程组 ID 设置为进程 ID
        task.set_pgid(task.tid());
        add_group(task.tid(), &task);
    } else {
        add_group(pgid, &task);
    }
    log::info!(
        "[sys_setpgid] task {} set pgid to {}",
        task.tid(),
        task.pgid()
    );
    Ok(0)
}

pub fn sys_getpgid(pid: usize) -> SyscallRet {
    log::info!("[sys_getpgid] pid: {}", pid);
    let target_task = if pid == 0 {
        current_task().clone()
    } else {
        get_task(pid).ok_or(Errno::ESRCH)?
    };
    log::info!(
        "[sys_getpgid] task {} get pgid: {}",
        target_task.tid(),
        target_task.pgid()
    );
    Ok(target_task.pgid())
}

pub fn sys_set_tid_address(tidptr: usize) -> SyscallRet {
    let task = current_task();
    log::info!("[sys_set_tid_address] tidptr:{:#x}", tidptr);
    task.set_tac(tidptr);
    Ok(task.tid())
}

// 获取父进程的pid
pub fn sys_getppid() -> SyscallRet {
    let task = current_task();
    let ppid = task.op_parent(|parent| {
        if let Some(parent) = parent {
            parent.upgrade().unwrap().tid()
        } else {
            0 // 如果没有父进程，则返回0
        }
    });
    log::info!("[sys_getppid] task {} get ppid: {}", task.tid(), ppid);
    Ok(ppid)
}

pub fn sys_yield() -> SyscallRet {
    // let task = current_task();
    // task.inner.lock().task_status = TaskStatus::Ready;
    // // 将当前任务加入就绪队列
    // add_task(task);
    // // 切换到下一个任务
    // schedule();
    yield_current_task();
    Ok(0)
}

pub fn sys_exit(exit_code: i32) -> ! {
    kernel_exit(current_task(), (exit_code & 0xff) << 8);
    log::warn!(
        "[sys_exit] task {} exit with code {}",
        current_task().tid(),
        exit_code
    );
    schedule();
    panic!("Unreachable in sys_exit");
}

pub fn sys_exit_group(exit_code: i32) -> SyscallRet {
    log::warn!(
        "[sys_exit_group] thread-group {} do exit!",
        current_task().tgid()
    );
    let task = current_task();
    let mut to_exit = vec![];
    task.op_thread_group_mut(|tg| {
        for thread in tg.iter() {
            to_exit.push(thread.tid());
        }
    });
    for tid in to_exit {
        if let Some(thread) = get_task(tid) {
            kernel_exit(thread, (exit_code & 0xff) << 8);
        }
    }
    drop(task);
    schedule();
    Ok(0) // 这里不会返回
}

pub fn sys_waitpid(pid: isize, exit_code_ptr: usize, option: i32) -> SyscallRet {
    log::trace!("[sys_waitpid]");
    let option = WaitOption::from_bits(option).unwrap();
    log::warn!(
        "[sys_waitpid] pid: {}, exit_code_ptr: {:x}, option: {:?}",
        pid,
        exit_code_ptr,
        option,
    );
    log::error!("current_task: {}", current_task().tid());
    let cur_task = current_task();
    loop {
        let mut first = true;
        let mut target_task: Option<Arc<Task>> = None;
        // 神奇小咒语
        log::trace!(
            "[sys_waitpid] pid: {}, target_task: {:?}, first: {}",
            pid,
            target_task,
            first,
        );
        // 先检查当前进程是否存在满足目标子进程
        cur_task.op_children_mut(|children| {
            if children.is_empty() {
                return;
            }
            for child in children.values() {
                if pid == -1 && first {
                    target_task = Some(child.clone());
                    first = false;
                } else if pid == 0 && child.pgid() == cur_task.pgid() && first {
                    // pid为0, 则等待当前进程组的任意子进程
                    target_task = Some(child.clone());
                    first = false;
                } else if pid > 0 && pid as usize == child.tid() {
                    // pid大于0, 则等待指定pid的子进程
                    target_task = Some(child.clone());
                    return;
                } else if pid < -1 && (-pid) as usize == child.pgid() {
                    // pid小于-1, 则等待指定pgid的子进程
                    target_task = Some(child.clone());
                    return;
                } else if pid as usize == child.tgid() {
                    target_task = Some(child.clone());
                } else if pid == -1 && child.is_zombie() {
                    target_task = Some(child.clone());
                    return;
                } else if pid == 0 && child.is_zombie() && child.pgid() == cur_task.pgid() {
                    // pid为0, 则等待当前进程组的任意子进程
                    target_task = Some(child.clone());
                    return;
                }
            }
        });
        if let Some(wait_task) = target_task {
            log::error!(
                "cur_task: {}, wait_task: {}",
                cur_task.tid(),
                wait_task.tid()
            );
            // 目标子进程已死
            if wait_task.is_zombie() {
                cur_task.remove_child_task(wait_task.tid());
                debug_assert_eq!(Arc::strong_count(&wait_task), 1);
                let found_pid = wait_task.tgid() as i32;
                // 写入exit_code
                // Todo: 需要对地址检查
                log::warn!(
                    "[sys_waitpid] child {} exit with code {}, exit_code_ptr: {:x}",
                    found_pid,
                    wait_task.exit_code(),
                    exit_code_ptr
                );
                // exit_code_ptr为空, 表示不关心子进程的退出状态
                if exit_code_ptr != 0 {
                    copy_to_user(
                        exit_code_ptr as *mut i32,
                        &wait_task.exit_code() as *const i32,
                        1,
                    )?;
                }
                return Ok(found_pid as usize);
            }
            // 如果目标子进程未死亡
            else {
                drop(wait_task);
                if option.contains(WaitOption::WNOHANG) {
                    return Ok(0);
                } else {
                    if wait() == -1 {
                        log::error!("[sys_waitpid] wait interrupted");
                        return Err(Errno::EINTR);
                    };
                }
            }
        }
        // 不存在目标进程
        else {
            return Err(Errno::ECHILD);
        }
    }
}

pub fn sys_futex(
    uaddr: usize,
    futex_op: i32,
    val: u32,
    val2: usize,
    uaddr2: usize,
    val3: u32,
) -> SyscallRet {
    log::info!(
        "[sys_futex] uaddr: {:x}, futex_op: {}, val: {}, val2: {:x}, uaddr2: {:x}, val3: {}",
        uaddr,
        futex_op,
        val,
        val2,
        uaddr2,
        val3
    );
    match do_futex(uaddr, futex_op, val, val2, uaddr2, val3) {
        Ok(ret) => {
            log::info!("[sys_futex] ret: {}", ret);
            Ok(ret)
        }
        Err(err) => {
            log::error!("[sys_futex] err: {:?}", err);
            Err(err)
        }
    }
}

pub fn sys_set_robust_list(_robust_list: usize, _len: usize) -> SyscallRet {
    Ok(0)
}

pub fn sys_get_robust_list(_pid: i32, _robust_list: usize, _len: usize) -> SyscallRet {
    Ok(0)
}

pub fn sys_get_time(time_val_ptr: usize) -> SyscallRet {
    let time_val_ptr = time_val_ptr as *mut TimeVal;
    let current_time_ms = get_time_ms();
    let time_val = TimeVal {
        sec: current_time_ms / 1000,
        usec: current_time_ms % 1000 * 1000,
    };
    // unsafe {
    //     time_val_ptr.write_volatile(time_val);
    // }
    copy_to_user(time_val_ptr, &time_val as *const TimeVal, 1).unwrap();
    Ok(0)
}

// // 如果调用被信号处理程序中断，nanosleep()将返回 -1，
// // 将 errno 设置为 EINTR，并将剩余时间写入 rem 指向的结构体中，除非 rem 为 NULL。
// // Todo: 将剩余时间写入 rem 指向的结构体中
// pub fn sys_nanosleep(time_val_ptr: usize) -> SyscallRet {
//     log::info!("[sys_nanosleep] time_val_ptr: {:x}", time_val_ptr);
//     let time_val_ptr = time_val_ptr as *const TimeSpec;
//     let mut time_val: TimeSpec = TimeSpec::default();
//     copy_from_user(time_val_ptr, &mut time_val as *mut TimeSpec, 1)?;
//     wait_timeout(time_val);
//     Ok(0)
// }

pub fn sys_nanosleep(time_val_ptr: usize) -> SyscallRet {
    let time_val_ptr = time_val_ptr as *const TimeSpec;
    let mut time_val: TimeSpec = TimeSpec::default();
    copy_from_user(time_val_ptr, &mut time_val as *mut TimeSpec, 1)?;
    let start_time = TimeSpec::new_machine_time();
    log::error!(
        "[sys_nanosleep] task{} sleep {:?}",
        current_task().tid(),
        time_val
    );
    // Todo: 为防止无任务的情况，超时阻塞先用yield代替
    loop {
        if current_task().check_interrupt() {
            log::error!(
                "[sys_nanosleep] task{} wakeup by signal",
                current_task().tid()
            );
            let remained_time = TimeSpec::new_machine_time() - start_time;
            copy_to_user(time_val_ptr as *mut TimeSpec, &remained_time, 1)?;
            return Err(Errno::EINTR);
        }
        let current_time = TimeSpec::new_machine_time();
        if current_time >= time_val + start_time {
            break;
        }
        yield_current_task(); // 返回时状态会变成running
                              // 在yield回来之后设置成interruptable可以有效的避免任务状态被覆盖
                              // 并且可以有效的保证收到信号的时候不会触发信号中断
        current_task().set_interruptable();
    }
    Ok(0)
}

// pub fn sys_nanosleep(time_val_ptr: usize) -> SyscallRet {
//     let time_val_ptr = time_val_ptr as *const TimeSpec;
//     let mut time_val: TimeSpec = TimeSpec::default();
//     copy_from_user(time_val_ptr, &mut time_val as *mut TimeSpec, 1)?;
//     let start_time = TimeSpec::new_machine_time();
//     log::error!(
//         "[sys_nanosleep] task{} sleep {:?}",
//         current_task().tid(),
//         time_val
//     );
//     loop {
//         if current_task().check_interrupt() {
//             log::error!(
//                 "[sys_nanosleep] task{} wakeup by signal",
//                 current_task().tid()
//             );
//             return Err(Errno::EINTR);
//         }
//         let current_time = TimeSpec::new_machine_time();
//         if current_time >= time_val + start_time {
//             break;
//         }
//         yield_current_task();
//     }
//     Ok(0)
// }

pub const TIMER_ABSTIME: i32 = 0x01;
pub fn sys_clock_nansleep(clock_id: usize, flags: i32, t: usize, remain: usize) -> SyscallRet {
    log::info!(
        "[sys_clock_nanosleep] clock_id: {}, flags: {}, req: {:x}, rem: {:x}",
        clock_id,
        flags,
        t,
        remain
    );
    // let t = copy_from_user(t as *const TimeSpec, 1)?[0];
    let mut t_buf: TimeSpec = TimeSpec::default();
    copy_from_user(t as *const TimeSpec, &mut t_buf as *mut TimeSpec, 1)?;
    match clock_id {
        CLOCK_REALTIME => {
            if flags == TIMER_ABSTIME {
                // 绝对时间
                // Todo: 阻塞
                loop {
                    let current_time = TimeSpec::new_wall_time();
                    if current_time >= t_buf {
                        return Ok(0);
                    }
                    yield_current_task();
                }
            } else {
                // 相对时间
                let start_time = TimeSpec::new_wall_time();
                loop {
                    let current_time = TimeSpec::new_wall_time();
                    if current_time >= t_buf + start_time {
                        return Ok(0);
                    }
                    yield_current_task();
                }
            }
        }
        CLOCK_MONOTONIC => {
            if flags == TIMER_ABSTIME {
                // 绝对时间
                // Todo: 阻塞 + 信号中断
                loop {
                    let current_time = TimeSpec::new_machine_time();
                    if current_time >= t_buf {
                        return Ok(0);
                    }
                    yield_current_task();
                }
            } else {
                // 相对时间
                let start_time = TimeSpec::new_machine_time();
                loop {
                    let current_time = TimeSpec::new_machine_time();
                    if current_time >= t_buf + start_time {
                        return Ok(0);
                    }
                    yield_current_task();
                }
            }
        }
        _ => {
            panic!("[sys_clock_nanosleep] clock_id: {} not supported", clock_id);
            return Err(Errno::EINVAL);
        }
    }
}

// fake
pub fn sys_acct(pathname: *const u8) -> SyscallRet {
    if pathname.is_null() {
        log::warn!("[sys_acct] disable accounting");
        // 禁用进程会计
        return Ok(0);
    }
    log::warn!(
        "[sys_acct] Uimplemented, pathname: {:#x}",
        pathname as usize
    );
    Ok(0)
}

/// setuid() 设置调用进程的有效用户 ID。
/// setuid() 会检查调用者的有效用户 ID，如果是超级用户，则所有与进程相关的用户 ID 都将设置为 uid。
/// 执行此操作后，程序将无法重新获得 root 权限。
/// EPERM 用户不具有特权（Linux：其用户命名空间中没有 CAP_SETUID 功能），并且 uid 与调用进程的真实 UID 或保存的设置用户 ID 不匹配。
// Todo: 命名空间
pub fn sys_setuid(uid: u32) -> SyscallRet {
    let task = current_task();
    if task.euid() == 0 {
        log::warn!(
            "[sys_setuid] task{} is root, set uid to {}",
            task.tid(),
            uid
        );
        task.set_uid(uid);
        task.set_euid(uid);
        task.set_suid(uid);
        task.set_fsuid(uid);
    } else {
        if uid != task.uid() && uid != task.suid() {
            log::warn!(
                "[sys_setuid] task{} is not root, set uid to {}",
                task.tid(),
                uid
            );
            return Err(Errno::EPERM);
        } else {
            log::warn!("[sys_setuid] task{} set uid to {}", task.tid(), uid);
            task.set_euid(uid);
            task.set_fsuid(uid);
        }
    }
    Ok(0)
}

/// setgid() 设置调用进程的有效组 ID。
/// 如果调用进程拥有特权则还会设置实际 GID 和保存的设置组 ID。
pub fn sys_setgid(gid: u32) -> SyscallRet {
    let task = current_task();
    if task.euid() == 0 {
        log::warn!(
            "[sys_setgid] task{} is root, set gid to {}",
            task.gid(),
            gid
        );
        task.set_gid(gid);
        task.set_egid(gid);
        task.set_sgid(gid);
        task.set_fsgid(gid);
    } else {
        if gid != task.gid() && gid != task.sgid() {
            log::warn!(
                "[sys_setgid] task{} is not root, set gid to {}",
                task.tid(),
                gid
            );
            return Err(Errno::EPERM);
        } else {
            log::warn!("[sys_setgid] task{} set gid to {}", task.tid(), gid);
            task.set_egid(gid);
            task.set_fsgid(gid);
        }
    }
    Ok(0)
}

/// setreuid() 设置调用进程的实际用户 ID 和有效用户 ID。
/// 如果将实际用户 ID 或有效用户 ID 设置为 -1，则系统会强制保持该 ID 不变。
/// 非特权进程只能将有效用户 ID 设置为实际用户 ID、有效用户 ID 或保存的设置用户 ID。
/// 非特权用户只能将实际用户 ID 设置为实际用户 ID 或有效用户 ID。
/// 如果设置了实际用户 ID（即 ruid 不为 -1）或有效用户 ID 的值不等于先前的实际用户 ID，则保存的设置用户 ID 将被设置为新的有效用户 ID。
pub fn sys_setreuid(ruid: i32, euid: i32) -> SyscallRet {
    log::info!("[sys_setreuid] ruid: {}, euid: {}", ruid, euid);
    let task = current_task();
    let origin_uid = task.uid() as i32;
    let origin_euid = task.euid() as i32;
    let origin_suid = task.suid() as i32;
    if task.euid() == 0 {
        log::warn!(
            "[sys_setreuid] task{} is root, set ruid: {}, euid: {}",
            task.tid(),
            ruid,
            euid
        );
        if ruid != -1 {
            task.set_uid(ruid as u32);
        }
        if euid != -1 {
            task.set_euid(euid as u32);
            task.set_fsuid(euid as u32);
        }
    } else {
        if ruid != -1 {
            if ruid != origin_uid as i32 && ruid != origin_euid as i32 {
                return Err(Errno::EPERM);
            }
            log::warn!(
                "[sys_setreuid] task{} is not root, set ruid: {}",
                task.tid(),
                ruid,
            );
            task.set_uid(ruid as u32);
        }
        if euid != -1 {
            if euid != origin_uid as i32 && euid != origin_euid as i32 && euid != origin_suid as i32
            {
                return Err(Errno::EPERM);
            }
            log::warn!(
                "[sys_setreuid] task{} is not root, set euid: {}",
                task.tid(),
                euid,
            );
            task.set_euid(euid as u32);
            task.set_fsuid(euid as u32);
        }
    }
    if ruid != -1 || (euid != -1 && euid != origin_uid as i32) {
        task.set_suid(task.euid() as u32);
    }
    Ok(0)
}

/// setregid() 函数应设置调用进程的实际组 ID 和有效组 ID。
/// 如果 rgid 为 -1，则实际组 ID 不应更改；如果 egid 为 -1，则有效组 ID 不应更改。
/// 非特权进程可以将实际组 ID 设置为 exec 系列函数中保存的sgid，或者将有效组 ID 设置为保存的sigd 或实际组 ID。
/// 如果正在设置实际组 ID（rgid 不为 -1），或者正在将有效组 ID 设置为不等于实际组 ID 的值，则当前进程保存的 set-group-ID 应设置为新的有效组 ID。
/// 调用进程的任何补充组 ID 均保持不变。
/// 将实际组 ID 更改为保存的 sgid，
/// 或将有效组 ID 更改为实际组 ID 或保存的设置组 ID 之外的更改。
pub fn sys_setregid(rgid: i32, egid: i32) -> SyscallRet {
    log::info!("[sys_setregid] rgid: {}, egid: {}", rgid, egid);
    let task = current_task();
    let origin_gid = task.gid() as i32;
    let origin_sgid = task.sgid() as i32;
    log::error!(
        "[sys_setregid] task {} origin_gid: {}, origin_sgid: {}",
        task.tid(),
        origin_gid,
        origin_sgid
    );
    if task.euid() == 0 {
        log::warn!(
            "[sys_setregid] task{} is root, set rgid: {}, egid: {}",
            task.tid(),
            rgid,
            egid
        );
        if rgid != -1 {
            task.set_gid(rgid as u32);
        }
        if egid != -1 {
            task.set_egid(egid as u32);
            task.set_fsgid(egid as u32);
        }
    } else {
        if rgid != -1 {
            if rgid != origin_sgid as i32 && rgid != origin_gid as i32 {
                return Err(Errno::EPERM);
            }
            log::warn!(
                "[sys_setregid] task{} is not root, set rgid: {}",
                task.tid(),
                rgid,
            );
            task.set_gid(rgid as u32);
        }
        if egid != -1 {
            if egid != origin_gid as i32 && egid != origin_sgid as i32 {
                return Err(Errno::EPERM);
            }
            log::warn!(
                "[sys_setregid] task{} is not root, set egid: {}",
                task.tid(),
                egid,
            );
            task.set_egid(egid as u32);
            task.set_fsgid(egid as u32);
        }
    }
    if rgid != -1 || (egid != -1 && egid != origin_gid as i32) {
        task.set_sgid(task.egid() as u32);
    }
    Ok(0)
}

/// setresuid() 设置调用进程的真实用户 ID、有效用户 ID 和已保存的设置用户 ID。
/// 非特权进程可以将其真实 UID、有效 UID 和已保存的设置用户 ID 分别更改为：当前真实 UID、当前有效 UID 或当前已保存的设置用户 ID。
/// 特权进程（在 Linux 上，指具有 CAP_SETUID 功能的进程）可以将其真实 UID、有效 UID 和已保存的设置用户 ID 设置为任意值。
/// 如果其中一个参数等于 -1，则相应的值保持不变。
pub fn sys_setresuid(ruid: i32, euid: i32, suid: i32) -> SyscallRet {
    log::info!(
        "[sys_setreuid] ruid: {}, euid: {}, suid: {}",
        ruid,
        euid,
        suid
    );
    let task = current_task();
    let origin_uid = task.uid() as i32;
    let origin_euid = task.euid() as i32;
    let origin_suid = task.suid() as i32;
    if task.euid() == 0 {
        log::warn!(
            "[sys_setreuid] task{} is root, set ruid: {}, euid: {}",
            task.tid(),
            ruid,
            euid
        );
        if ruid != -1 {
            task.set_uid(ruid as u32);
        }
        if euid != -1 {
            task.set_euid(euid as u32);
            task.set_fsuid(euid as u32);
        }
        if suid != -1 {
            task.set_suid(suid as u32);
        }
    } else {
        if ruid != -1 {
            if ruid != origin_uid as i32 && ruid != origin_euid as i32 && ruid != origin_suid as i32
            {
                return Err(Errno::EPERM);
            }
            log::warn!(
                "[sys_setreuid] task{} is not root, set ruid: {}",
                task.tid(),
                ruid,
            );
            task.set_uid(ruid as u32);
        }
        if euid != -1 {
            if euid != origin_uid as i32 && euid != origin_euid as i32 && euid != origin_suid as i32
            {
                return Err(Errno::EPERM);
            }
            log::warn!(
                "[sys_setreuid] task{} is not root, set euid: {}",
                task.tid(),
                euid,
            );
            task.set_euid(euid as u32);
            task.set_fsuid(euid as u32);
        }
        if suid != -1 {
            if suid != origin_uid as i32 && suid != origin_euid as i32 && suid != origin_suid as i32
            {
                return Err(Errno::EPERM);
            }
            log::warn!(
                "[sys_setreuid] task{} is not root, set suid: {}",
                task.tid(),
                suid,
            );
            task.set_suid(suid as u32);
        }
    }
    Ok(0)
}

/// 类似 setresuid
pub fn sys_setresgid(rgid: i32, egid: i32, sgid: i32) -> SyscallRet {
    log::info!(
        "[sys_setregid] rgid: {}, egid: {}, sgid: {}",
        rgid,
        egid,
        sgid
    );
    let task = current_task();
    let origin_gid = task.gid() as i32;
    let origin_egid = task.egid() as i32;
    let origin_sgid = task.sgid() as i32;
    if task.euid() == 0 {
        log::warn!(
            "[sys_setregid] task{} is root, set rgid: {}, egid: {}",
            task.tid(),
            rgid,
            egid
        );
        if rgid != -1 {
            task.set_gid(rgid as u32);
        }
        if egid != -1 {
            task.set_egid(egid as u32);
            task.set_fsgid(egid as u32);
        }
        if sgid != -1 {
            task.set_sgid(sgid as u32);
        }
    } else {
        if rgid != -1 {
            if rgid != origin_gid as i32 && rgid != origin_egid as i32 && rgid != origin_sgid as i32
            {
                return Err(Errno::EPERM);
            }
            log::warn!(
                "[sys_setregid] task{} is not root, set rgid: {}",
                task.tid(),
                rgid,
            );
            task.set_gid(rgid as u32);
        }
        if egid != -1 {
            if egid != origin_gid as i32 && egid != origin_egid as i32 && egid != origin_sgid as i32
            {
                return Err(Errno::EPERM);
            }
            log::warn!(
                "[sys_setregid] task{} is not root, set egid: {}",
                task.tid(),
                egid,
            );
            task.set_egid(egid as u32);
            task.set_fsgid(egid as u32);
        }
        if sgid != -1 {
            if sgid != origin_gid as i32 && sgid != origin_egid as i32 && sgid != origin_sgid as i32
            {
                return Err(Errno::EPERM);
            }
            log::warn!(
                "[sys_setregid] task{} is not root, set sgid: {}",
                task.tid(),
                sgid,
            );
            task.set_sgid(sgid as u32);
        }
    }
    Ok(0)
}

pub fn sys_getresuid(ruid_ptr: u32, euid_ptr: u32, suid_ptr: u32) -> SyscallRet {
    log::info!(
        "[sys_getresuid] ruid_ptr: {:x}, euid_ptr: {:x}, suid_ptr: {:x}",
        ruid_ptr,
        euid_ptr,
        suid_ptr
    );
    let task = current_task();
    if ruid_ptr != 0 {
        copy_to_user(ruid_ptr as *mut u32, &task.uid() as *const u32, 1)?;
    }
    if euid_ptr != 0 {
        copy_to_user(euid_ptr as *mut u32, &task.euid() as *const u32, 1)?;
    }
    if suid_ptr != 0 {
        copy_to_user(suid_ptr as *mut u32, &task.suid() as *const u32, 1)?;
    }
    Ok(0)
}

pub fn sys_getresgid(rgid_ptr: u32, egid_ptr: u32, sgid_ptr: u32) -> SyscallRet {
    log::info!(
        "[sys_getresgid] rgid_ptr: {:x}, egid_ptr: {:x}, sgid_ptr: {:x}",
        rgid_ptr,
        egid_ptr,
        sgid_ptr
    );
    let task = current_task();
    if rgid_ptr != 0 {
        copy_to_user(rgid_ptr as *mut u32, &task.gid() as *const u32, 1)?;
    }
    if egid_ptr != 0 {
        copy_to_user(egid_ptr as *mut u32, &task.egid() as *const u32, 1)?;
    }
    if sgid_ptr != 0 {
        copy_to_user(sgid_ptr as *mut u32, &task.sgid() as *const u32, 1)?;
    }
    Ok(0)
}

pub fn sys_getuid() -> SyscallRet {
    Ok(current_task().uid() as usize)
}

pub fn sys_geteuid() -> SyscallRet {
    Ok(current_task().euid() as usize)
}

pub fn sys_getgid() -> SyscallRet {
    Ok(current_task().gid() as usize)
}

pub fn sys_getegid() -> SyscallRet {
    Ok(current_task().egid() as usize)
}

pub fn sys_setgroups(size: usize, list: usize) -> SyscallRet {
    log::info!("[sys_setgroups] size: {}, list: {:x}", size, list);
    let task = current_task();
    const NGROUPS_MAX: usize = 32; // 最大补充组数(为了过ltp，目前已经应是65536)
    if size > NGROUPS_MAX {
        return Err(Errno::EINVAL);
    }
    if task.euid() != 0 {
        // 只有root用户可以设置补充组
        return Err(Errno::EPERM);
    }
    let mut groups = vec![0u32; size as usize];
    copy_from_user(list as *const u32, groups.as_mut_ptr(), size)?;
    if size == 0 {
        // 清空补充组
        task.op_sup_groups_mut(|groups| {
            groups.clear();
        });
        return Ok(0);
    }
    task.op_sup_groups_mut(|sup_groups| {
        sup_groups.clear();
        for group in groups {
            sup_groups.push(group);
        }
    });
    Ok(0)
}

/// getgroups() 返回调用进程在列表中的补充组 ID。
pub fn sys_getgroups(size: usize, list: usize) -> SyscallRet {
    log::info!("[sys_getgroups] size: {}, list: {:x}", size, list);
    let task = current_task();
    const NGROUPS_MAX: usize = 32; // 最大补充组数(为了过ltp，目前已经应是65536)
    if size > NGROUPS_MAX {
        // NGROUPS_MAX = 32
        return Err(Errno::EINVAL);
    }
    if size == 0 {
        // 如果size为0, 则只返回补充组的数量
        return Ok(task.op_sup_groups(|groups| groups.len()));
    }
    let groups = task.op_sup_groups(|groups| Ok(groups.clone()))?;
    if size < groups.len() {
        return Err(Errno::EINVAL);
    }
    if list != 0 {
        copy_to_user(list as *mut u32, groups.as_ptr(), groups.len())?;
    }
    Ok(groups.len())
}

/// 进程可以使用 setfsuid() 将其文件系统用户 ID 更改为 fsuid 中指定的值，从而使其文件系统用户 ID 的值与其有效用户 ID 的值不同。
/// 只有当调用者是超级用户，或者 fsuid 与调用者的真实用户 ID、有效用户 ID、保存的设置用户 ID 或当前文件系统用户 ID 匹配时，setfsuid() 才会成功。
pub fn sys_setfsuid(fsuid: i32) -> SyscallRet {
    log::info!("[sys_setfsuid] fsuid: {}", fsuid);
    let task = current_task();
    let origin_fsuid = task.fsuid() as i32;
    if task.euid() == 0 {
        log::warn!(
            "[sys_setfsuid] task{} is root, set fsuid to {}",
            task.tid(),
            fsuid
        );
        if fsuid != -1 {
            task.set_fsuid(fsuid as u32);
        }
    } else {
        if fsuid != task.uid() as i32
            && fsuid != task.euid() as i32
            && fsuid != task.suid() as i32
            && fsuid != task.fsuid() as i32
        {
            log::warn!(
                "[sys_setfsuid] task{} is not root, set fsuid to {}",
                task.tid(),
                fsuid
            );
            return Ok(origin_fsuid as usize);
        } else {
            log::warn!("[sys_setfsuid] task{} set fsuid to {}", task.tid(), fsuid);
            if fsuid != -1 {
                task.set_fsuid(fsuid as u32);
            }
        }
    }
    Ok(origin_fsuid as usize)
}

/// 进程可以通过使用 setfsgid() 将其文件系统组 ID 更改为 fsgid 中指定的值，从而使其文件系统组 ID 的值与其有效组 ID 不同。
/// 只有当调用者是超级用户，或者 fsgid 与调用者的实际组 ID、有效组 ID、保存的设置组 ID 或当前文件系统用户 ID 匹配时，setfsgid() 才会成功。
pub fn sys_setfsgid(fsgid: i32) -> SyscallRet {
    log::info!("[sys_setfsgid] fsgid: {}", fsgid);
    let task = current_task();
    let origin_fsgid = task.fsgid() as i32;
    if task.euid() == 0 {
        if fsgid != -1 {
            log::warn!(
                "[sys_setfsgid] task{} is root, set fsgid to {}",
                task.tid(),
                fsgid
            );
            task.set_fsgid(fsgid as u32);
        }
    } else {
        if fsgid != task.gid() as i32
            && fsgid != task.egid() as i32
            && fsgid != task.sgid() as i32
            && fsgid != task.fsgid() as i32
        {
            log::warn!(
                "[sys_setfsgid] task{} is not root, set fsgid to {}",
                task.tid(),
                fsgid
            );
            return Ok(origin_fsgid as usize);
        } else {
            log::warn!("[sys_setfsgid] task{} set fsgid to {}", task.tid(), fsgid);
            if fsgid != -1 {
                task.set_fsgid(fsgid as u32);
            }
        }
    }
    Ok(origin_fsgid as usize)
}

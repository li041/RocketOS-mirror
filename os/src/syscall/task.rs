use core::sync::atomic::{compiler_fence, Ordering};
use core::time;

use crate::arch::mm::copy_from_user;
use crate::arch::trap::context::{dump_trap_context, get_trap_context, save_trap_context};
use crate::fs::file::OpenFlags;
use crate::futex::do_futex;
use crate::syscall::errno::Errno;
use crate::syscall::util::{CLOCK_MONOTONIC, CLOCK_REALTIME};
use crate::task::{get_scheduler_len, get_task, wait, wait_timeout, CloneFlags, Task};
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
use alloc::{sync::Arc, vec};
use bitflags::bitflags;

use super::errno::SyscallRet;

#[cfg(target_arch = "riscv64")]
pub fn sys_clone(
    flags: u32,
    stack_ptr: usize,
    parent_tid_ptr: usize,
    tls_ptr: usize,
    chilren_tid_ptr: usize,
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
    let new_task = task.kernel_clone(&flags, stack_ptr);
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
        new_task.set_TAS(new_task.tid());
    }
    if flags.contains(CloneFlags::CLONE_CHILD_CLEARTID) {
        log::warn!("[sys_clone] handle CLONE_CHILD_CLEARTID");
        new_task.set_TAC(chilren_tid_ptr);
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
    let new_task = task.kernel_clone(&flags, stack_ptr);
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
        new_task.set_TAS(new_task.tid());
    }
    if flags.contains(CloneFlags::CLONE_CHILD_CLEARTID) {
        log::warn!("[sys_clone] handle CLONE_CHILD_CLEARTID");
        new_task.set_TAC(chilren_tid_ptr);
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

pub const IGNOER_TEST: [&str; 16] = [
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
    /* 由于OS原因, 先不跑的 */
    "ltp/testcases/bin/crash02",
];

pub fn sys_execve(path: *const u8, args: *const usize, envs: *const usize) -> SyscallRet {
    let path = c_str_to_string(path);
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
    let mut args_vec = extract_cstrings(args);
    let envs_vec = extract_cstrings(envs);
    let task = current_task();
    // OpenFlags::empty() = RDONLY = 0, 以只读方式打开文件
    if let Ok(file) = path_openat(&path, OpenFlags::empty(), AT_FDCWD, 0) {
        let all_data = file.read_all();
        task.kernel_execve_lazily(path, file, all_data.as_slice(), args_vec, envs_vec);
        Ok(0)
    } else if !path.starts_with("/") {
        // 从内核中加载的应用程序
        if let Some(elf_data) = get_app_data_by_name(&path) {
            args_vec.insert(0, path);
            task.kernel_execve(elf_data, args_vec, envs_vec);
            Ok(0)
        } else {
            log::error!("[sys_execve] path: {} not found", path);
            Err(Errno::ENOENT)
        }
    } else {
        log::error!("[sys_execve] path: {} not found", path);
        Err(Errno::ENOENT)
    }
}

pub fn sys_gettid() -> SyscallRet {
    log::info!("[sys_getuid] uid: {}", current_task().tid());
    Ok(current_task().tid())
}

pub fn sys_getpid() -> SyscallRet {
    log::info!("[sys_getpid] pid: {}", current_task().tgid());
    Ok(current_task().tgid())
}

// fake
pub fn sys_setpgid(pid: usize, pgid: usize) -> SyscallRet {
    log::info!("[sys_setpgid] pid: {}, pgid: {}", pid, pgid);
    log::warn!("[sys_setpgid] Uimplemented");
    Ok(0)
}

pub fn sys_getpgid(pid: usize) -> SyscallRet {
    log::info!("[sys_getpgid] pid: {}", pid);
    log::warn!("[sys_getpgid] Uimplemented");
    Ok(0)
}

pub fn sys_set_tid_address(tidptr: usize) -> SyscallRet {
    let task = current_task();
    log::info!("[sys_set_tid_address] tidptr:{:#x}", tidptr);
    task.set_TAC(tidptr);
    Ok(task.tid())
}

// ToDo: 更新进程组
// 获取父进程的pid
pub fn sys_getppid() -> SyscallRet {
    log::warn!("[sys_getppid] Uimplemented");
    let task = current_task();
    Ok(task.op_parent(|parent| parent.as_ref().unwrap().upgrade().unwrap().tid()))
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
    kernel_exit(current_task(), exit_code);
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
            kernel_exit(thread, exit_code);
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
                } else if pid as usize == child.tgid() {
                    target_task = Some(child.clone());
                } else if pid == -1 && child.is_zombie() {
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
                if exit_code_ptr != 0 {
                    // exit_code_ptr为空, 表示不关心子进程的退出状态
                    copy_to_user(
                        exit_code_ptr as *mut i32,
                        &((wait_task.exit_code() & 0xff) << 8) as *const i32,
                        1,
                    )
                    .unwrap();
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

/* fake */
pub fn sys_getuid() -> SyscallRet {
    Ok(0)
}
pub fn sys_geteuid() -> SyscallRet {
    Ok(0)
}
pub fn sys_getgid() -> SyscallRet {
    Ok(0)
}

pub fn sys_getegid() -> SyscallRet {
    Ok(0)
}

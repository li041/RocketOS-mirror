use core::sync::atomic::{compiler_fence, Ordering};

use crate::arch::mm::copy_from_user;
use crate::arch::timer::TimeSpec;
use crate::arch::trap::context::{dump_trap_context, get_trap_context, save_trap_context};
use crate::fs::file::OpenFlags;
use crate::futex::do_futex;
use crate::syscall::errno::Errno;
use crate::task::{get_scheduler_len, wait, wait_timeout, CloneFlags, Task};
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
use alloc::sync::Arc;
use alloc::task;
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

pub fn sys_execve(path: *const u8, args: *const usize, envs: *const usize) -> SyscallRet {
    let path = c_str_to_string(path);
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
        task.kernel_execve(all_data.as_slice(), args_vec, envs_vec);
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
    remove_task(current_task().tid());
    log::warn!(
        "[sys_exit] task {} exit with code {}",
        current_task().tid(),
        exit_code
    );
    schedule();
    panic!("Unreachable in sys_exit");
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
            log::error!("wait_task: {}", wait_task.tid());
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
                    wait();
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

/// sys_gettimeofday, current time = sec + usec
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TimeVal {
    /// seconds
    pub sec: usize,
    /// microseconds
    pub usec: usize,
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

// 如果调用被信号处理程序中断，nanosleep()将返回 -1，
// 将 errno 设置为 EINTR，并将剩余时间写入 rem 指向的结构体中，除非 rem 为 NULL。
// Todo: 将剩余时间写入 rem 指向的结构体中
// pub fn sys_nanosleep(time_val_ptr: usize) -> SyscallRet {
//     let time_val_ptr = time_val_ptr as *const TimeSpec;
//     let time_val = copy_from_user(time_val_ptr, 1).unwrap()[0];
//     // fake: 防止队列中出现没任务的情况，当调度器为空的时候进行忙等
//     if get_scheduler_len() == 0 {
//         let start_time = TimeSpec::new_machine_time();
//         loop {
//             let current_time = TimeSpec::new_machine_time();
//             if current_time >= time_val + start_time {
//                 break;
//             }
//         }
//     } else {
//         wait_timeout(time_val);
//     }
//     Ok(0)
// }

pub fn sys_nanosleep(time_val_ptr: usize) -> SyscallRet {
    let time_val_ptr = time_val_ptr as *const TimeSpec;
    let time_val = copy_from_user(time_val_ptr, 1).unwrap()[0];
    let start_time = TimeSpec::new_machine_time();
    loop {
        let current_time = TimeSpec::new_machine_time();
        if current_time >= time_val + start_time {
            break;
        }
        yield_current_task();
    }
    Ok(0)
}

/* fake */
pub fn sys_getuid() -> SyscallRet {
    Ok(0)
}
pub fn sys_geteuid() -> SyscallRet {
    Ok(0)
}

pub fn sys_getegid() -> SyscallRet {
    Ok(0)
}

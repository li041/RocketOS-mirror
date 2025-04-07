use core::sync::atomic::{compiler_fence, Ordering};

use crate::arch::mm::copy_from_user;
use crate::task::CloneFlags;
use crate::{
    arch::mm::copy_to_user,
    arch::timer::get_time_ms,
    arch::trap::TrapContext,
    fs::{namei::path_openat, AT_FDCWD},
    loader::get_app_data_by_name,
    task::{
        add_task, current_task, kernel_exit, remove_task, switch_to_next_task, yield_current_task,
        TaskContext, WaitOption,
    },
    utils::{c_str_to_string, extract_cstrings},
};
use alloc::sync::Arc;
use bitflags::bitflags;

#[cfg(target_arch = "riscv64")]
pub fn sys_clone(
    flags: u32,
    stack_ptr: usize,
    _parent_tid_ptr: usize,
    _tls_ptr: usize,
    _chilren_tid_ptr: usize,
) -> isize {
    // ToDo: 更新错误检验
    log::error!("[sys_clone] flags: {:x}, stack_ptr: {:x}", flags, stack_ptr);
    let flags = match CloneFlags::from_bits(flags as u32) {
        None => {
            log::error!("clone flags is None: {}", flags);
            return 22;
        }
        Some(flag) => flag,
    };
    let task = current_task();
    let new_task = task.kernel_clone(flags);
    let new_tid = new_task.tid();
    // 设定进程返回值
    let new_kstack = new_task.kstack();
    let new_trap_cx_ptr = (new_kstack + core::mem::size_of::<TaskContext>()) as *mut TrapContext;
    unsafe {
        // 设定子任务返回值为0，令tp指向该任务结构
        // ToDo: 检验用户栈指针
        if stack_ptr != 0 {
            (*new_trap_cx_ptr).x[2] = stack_ptr;
        }
        (*new_trap_cx_ptr).x[4] = Arc::as_ptr(&new_task) as usize;
        (*new_trap_cx_ptr).x[10] = 0;
    }
    log::info!(
        "[sys_clone]: strong_count: {}",
        Arc::strong_count(&new_task),
    );
    // ToDo: 更新信号检验
    add_task(new_task);
    new_tid as isize
}

#[cfg(target_arch = "loongarch64")]
pub fn sys_clone(
    flags: u32,
    stack_ptr: usize,
    _parent_tid_ptr: usize,
    _tls_ptr: usize,
    _chilren_tid_ptr: usize,
) -> isize {
    // debug
    log::error!("[sys_clone] flags: {}, stack_ptr: {}", flags, stack_ptr);
    // ToDo: 更新错误检验
    let flags = match CloneFlags::from_bits(flags as u32) {
        None => {
            log::error!("clone flags is None: {}", flags);
            return 22;
        }
        Some(flag) => flag,
    };
    let task = current_task();
    let new_task = task.kernel_clone(flags);
    let new_tid = new_task.tid();
    // 设定进程返回值
    let new_kstack = new_task.kstack();
    let new_trap_cx_ptr = (new_kstack + core::mem::size_of::<TaskContext>()) as *mut TrapContext;
    unsafe {
        // 设定子任务返回值为0，令tp指向该任务结构
        // ToDo: 检验用户栈指针
        if stack_ptr != 0 {
            (*new_trap_cx_ptr).r[3] = stack_ptr;
        }
        (*new_trap_cx_ptr).r[2] = Arc::as_ptr(&new_task) as usize;
        (*new_trap_cx_ptr).r[4] = 0;
    }
    log::info!(
        "[sys_clone]: strong_count: {}",
        Arc::strong_count(&new_task),
    );
    // ToDo: 更新信号检验
    add_task(new_task);
    new_tid as isize
}

pub fn sys_execve(path: *const u8, args: *const usize, envs: *const usize) -> isize {
    let path = c_str_to_string(path);
    log::error!(
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
    // flags = RDONLY = 0, 以只读方式打开文件
    if let Ok(file) = path_openat(&path, 0, AT_FDCWD, 0) {
        let all_data = file.read_all();
        task.kernel_execve(all_data.as_slice(), args_vec, envs_vec);
        0
    } else if !path.starts_with("/") {
        // 从内核中加载的应用程序
        if let Some(elf_data) = get_app_data_by_name(&path) {
            args_vec.insert(0, path);
            task.kernel_execve(elf_data, args_vec, envs_vec);
            0
        } else {
            -1
        }
    } else {
        -1
    }
}

pub fn sys_getpid() -> isize {
    current_task().tid() as isize
}

// ToDo: 更新进程组
// 获取父进程的pid
pub fn sys_getppid() -> isize {
    let task = current_task();
    task.op_parent(|parent| parent.as_ref().unwrap().upgrade().unwrap().tid()) as isize
}

pub fn sys_yield() -> isize {
    // let task = current_task();
    // task.inner.lock().task_status = TaskStatus::Ready;
    // // 将当前任务加入就绪队列
    // add_task(task);
    // // 切换到下一个任务
    // schedule();
    yield_current_task();
    0
}

pub fn sys_exit(exit_code: i32) -> ! {
    kernel_exit(current_task(), exit_code);
    remove_task(current_task().tid());
    // 切换任务
    switch_to_next_task();
    panic!("Unreachable in sys_exit");
}

// 使用block
#[no_mangle]
pub fn sys_waitpid(pid: isize, exit_code_ptr: usize, option: i32) -> isize {
    let option = WaitOption::from_bits(option).unwrap();
    if pid != -1 {
        log::warn!(
            "[sys_waitpid] pid: {}, exit_code_ptr: {:x}, option: {:?}",
            pid,
            exit_code_ptr,
            option
        );
    }
    let current_task = current_task();

    loop {
        // 先检查当前进程是否存在满足目标子进程
        let target_task = current_task.op_children_mut(|children| {
            for child in children.values() {
                if pid == -1 || pid as usize == child.tid() {
                    return Some(child.clone());
                }
            }
            None
        });

        if let Some(wait_task) = target_task {
            // 目标子进程已死
            if wait_task.is_zombie() {
                current_task.remove_child_task(wait_task.tid());
                debug_assert_eq!(Arc::strong_count(&wait_task), 1);
                let found_tid = wait_task.tid() as i32;
                // 写入exit_code
                // Todo: 需要对地址检查
                log::warn!(
                    "[sys_waitpid] child {} exit with code {}, exit_code_ptr: {:x}",
                    found_tid,
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
                return found_tid as isize;
            }
            // 如果目标子进程未死亡
            else {
                drop(wait_task);
                if option.contains(WaitOption::WNOHANG) {
                    return 0;
                } else {
                    yield_current_task();
                }
            }
        }
        // 不存在目标进程
        else {
            return -1;
        }
    }
}

// #[no_mangle]
// pub fn sys_waitpid(pid: isize, exit_code_ptr: usize, option: i32) -> isize {
//     let option = WaitOption::from_bits(option).unwrap();
//     log::warn!(
//         "[sys_waitpid] pid: {}, exit_code_ptr: {:x}, option: {:?}",
//         pid,
//         exit_code_ptr,
//         option
//     );
//     let task = current_task();
//     task.op_children_mut(|children| {
//         // 没有子进程
//         if !children
//             .values()
//             .any(|p| pid == -1 || pid as usize == p.tid())
//         {
//             return -1;
//         }
//         // 有子进程, 进一步看是否有子进程退出
//         else {
//             loop {
//                 let wait_task = children.values().find(|task| {
//                     let task = task.as_ref();
//                     task.is_zombie() && (pid == -1 || pid as usize == task.tid())
//                 });

//                 // 如果pid > 0, 则等待指定的子进程
//                 if let Some(wait_task) = wait_task {
//                     let child = children.remove(&wait_task.tid()).unwrap();
//                     assert_eq!(Arc::strong_count(&child), 1);
//                     let found_tid = child.tid() as i32;
//                     // 写入exit_code
//                     // Todo: 需要对地址检查
//                     log::warn!(
//                         "[sys_waitpid] child {} exit with code {}, exit_code_ptr: {:x}",
//                         found_tid,
//                         child.exit_code(),
//                         exit_code_ptr
//                     );
//                     if exit_code_ptr != 0 {
//                         // exit_code_ptr为空, 表示不关心子进程的退出状态
//                         copy_to_user(
//                             exit_code_ptr as *mut i32,
//                             &((child.exit_code() & 0xff) << 8) as *const i32,
//                             1,
//                         )
//                         .unwrap();
//                     }
//                     return found_tid as isize;
//                 } else {
//                     if option.contains(WaitOption::WNOHANG) {
//                         return 0;
//                     } else {
//                         // 没有子进程退出, 则挂起当前进程
//                         yield_current_task();
//                         // blocking_current_task_and_run_next();
//                     }
//                 }
//             }
//         }
//     })
// }

/// sys_gettimeofday, current time = sec + usec
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TimeVal {
    /// seconds
    pub sec: usize,
    /// microseconds
    pub usec: usize,
}

pub fn sys_get_time(time_val_ptr: usize) -> isize {
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
    0
}

pub fn sys_nanosleep(time_val_ptr: usize) -> isize {
    let time_val_ptr = time_val_ptr as *const TimeVal;
    let time_val = copy_from_user(time_val_ptr, 1).unwrap()[0];
    let time_ms = time_val.sec * 1000 + time_val.usec / 1000;
    let start_time = get_time_ms();
    loop {
        let current_time = get_time_ms();
        if current_time - start_time >= time_ms {
            break;
        }
    }
    0
}

use crate::{
    fs::{namei::path_openat, AT_FDCWD},
    loader::get_app_data_by_name,
    task::{add_task, current_task, kernel_exit, remove_task, switch_to_next_task, yield_current_task, TaskContext, WaitOption},
    timer::get_time_ms,
    trap::TrapContext,
    utils::{c_str_to_string, extract_cstrings},
};
use alloc::sync::Arc;
use bitflags::bitflags;

pub fn sys_clone(
    flags: u32,
    stack_ptr: usize,
    _parent_tid_ptr: usize,
    _tls_ptr: usize,
    _chilren_tid_ptr: usize,
) -> isize {
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
        if stack_ptr != 0 {(*new_trap_cx_ptr).x[2] = stack_ptr;}
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

pub fn sys_execve(path: *const u8, args: *const usize, envs: *const usize) -> isize {
    let path = c_str_to_string(path);
    log::error!("path: {}", path);
    // argv[0]是应用程序的名字
    // 后续元素是用户在命令行中输入的参数
    let mut args_vec = extract_cstrings(args);
    let envs_vec = extract_cstrings(envs);
    let task = current_task();
    // flags = RDONLY = 0, 以只读方式打开文件
    if let Ok(file) = path_openat(&path, 0, AT_FDCWD, 0) {
        args_vec.insert(0, path);
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
    log::warn!(
        "[sys_waitpid] pid: {}, exit_code_ptr: {:x}, option: {:?}",
        pid,
        exit_code_ptr,
        option
    );
    let task = current_task();
    task.op_children_mut(|children| {
        // 没有子进程
        if !children
            .values()
            .any(|p| pid == -1 || pid as usize == p.tid())
        {
            return -1;
        }
        // 有子进程, 进一步看是否有子进程退出
        else {
            loop {
                let wait_task = children.values().find(|task| {
                    let task = task.as_ref();
                    task.is_zombie() && (pid == -1 || pid as usize == task.tid())
                });

                // 如果pid > 0, 则等待指定的子进程
                if let Some(wait_task) = wait_task {
                    let child = children.remove(&wait_task.tid()).unwrap();
                    assert_eq!(Arc::strong_count(&child), 1);
                    let found_tid = child.tid() as i32;
                    // 写入exit_code
                    // Todo: 需要对地址检查
                    unsafe {
                        log::warn!(
                            "[sys_waitpid] child {} exit with code {}, exit_code_ptr: {:x}",
                            found_tid,
                            child.exit_code(),
                            exit_code_ptr
                        );
                        let exit_code_ptr = exit_code_ptr as *mut i32;
                        if exit_code_ptr != core::ptr::null_mut() {
                            exit_code_ptr.write_volatile((child.exit_code() & 0xff) << 8);
                        }
                    }
                    return found_tid as isize;
                } else {
                    if option.contains(WaitOption::WNOHANG) {
                        return 0;
                    } else {
                        // 没有子进程退出, 则挂起当前进程
                        yield_current_task();
                        // blocking_current_task_and_run_next();
                    }
                }
            }
        }
    })
}

// pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
//     let task = current_task();
//     let mut inner = task.inner.lock();
//     if !inner
//         .children
//         .iter()
//         .any(|p| pid == -1 || pid as usize == p.tid.0)
//     {
//         return -1;
//     }
//     let pair = inner.children.iter().enumerate().find(|(_, p)| {
//         p.inner.lock().task_status == TaskStatus::Zombie && (pid == -1 || pid as usize == p.tid.0)
//     });
//     if let Some((idx, _)) = pair {
//         let child = inner.children.remove(idx);
//         assert_eq!(Arc::strong_count(&child), 1);
//         let found_tid = child.tid.0 as i32;
//         // 写入exit_code
//         // Todo: 需要对地址检查
//         if exit_code_ptr != core::ptr::null_mut() {
//             unsafe {
//                 *exit_code_ptr = child.inner.lock().exit_code;
//             }
//         }
//         return found_tid as isize;
//     } else {
//         -2
//     }
// }

// /// 成功返回退出子进程的pid, 失败返回-1
// pub fn wait_pid(pid: i32, exit_code_ptr: *mut i32) -> Result<usize, WaitError> {
//     let current_task = current_task();
//     let mut idx_to_remove = None;
//     {
//         let children = current_task.inner.lock().children.clone();
//         if children.is_empty() {
//             return Err(WaitError::NoChild);
//         }
//         for (idx, child) in children.iter().enumerate() {
//             if pid == 0 {
//                 log::error!("[wait_pid] process group wait is not implemented");
//             } else if pid == -1 || pid == child.tid as i32 {
//                 // pid == -1, 等待任意子进程
//                 let child_inner = child.inner.lock();
//                 if child_inner.task_status == TaskStatus::Zombie {
//                     let exit_code = child_inner.exit_code;
//                     let from = &exit_code as *const i32;
//                     // unsafe {
//                     //     *exit_code_ptr = exit_code;
//                     // }
//                     if let Err(err) = copy_to_user(exit_code_ptr, from, 1) {
//                         panic!("[wait_pid]copy exit_code failed: {}", err);
//                     }
//                     log::info!(
//                         "[wait_pid] child {} exit with code {}",
//                         child.tid,
//                         exit_code
//                     );
//                     idx_to_remove = Some(idx);
//                     break;
//                 }
//             }
//         }
//     } // children释放

//     // 移除已经退出的子进程
//     if let Some(idx) = idx_to_remove {
//         let child = current_task.inner.lock().children.remove(idx);
//         assert!(
//             Arc::strong_count(&child) == 1,
//             "child strong count: {}",
//             Arc::strong_count(&child)
//         );
//         return Ok(child.tid);
//     }
//     Err(WaitError::NotFound)
// }

// pub fn sys_wait4(pid: isize, exit_code_ptr: *mut i32, option: i32) -> isize {
//     let options = WaitOption::from_bits(option).unwrap();
//     let task = current_task();
//     loop {
//         match wait_pid(pid as i32, exit_code_ptr) {
//             Ok(tid) => return tid as isize,
//             Err(_) => {
//                 if options.contains(WaitOption::WNOHANG) {
//                     // 返回0, 表示没有子进程退出
//                     return 0;
//                 } else {
//                     // 没有子进程退出, 则挂起当前进程
//                     suspend_current_and_run_next();
//                 }
//             }
//         }
//     }
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
    unsafe {
        time_val_ptr.write_volatile(time_val);
    }
    0
}

pub fn sys_nanosleep(time_val_ptr: usize) -> isize {
    let time_val_ptr = time_val_ptr as *const TimeVal;
    let time_val = unsafe { time_val_ptr.read() };
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

bitflags! {
    /// Open file flags
    pub struct CloneFlags: u32 {
        // SIGCHLD 是一个信号，在UNIX和类UNIX操作系统中，当一个子进程改变了它的状态时，内核会向其父进程发送这个信号。这个信号可以用来通知父进程子进程已经终止或者停止了。父进程可以采取适当的行动，比如清理资源或者等待子进程的状态。
        // 以下是SIGCHLD信号的一些常见用途：
        // 子进程终止：当子进程结束运行时，无论是正常退出还是因为接收到信号而终止，操作系统都会向其父进程发送SIGCHLD信号。
        // 资源清理：父进程可以处理SIGCHLD信号来执行清理工作，例如释放子进程可能已经使用的资源。
        // 状态收集：父进程可以通过调用wait()或waitpid()系统调用来获取子进程的终止状态，了解子进程是如何结束的。
        // 孤儿进程处理：在某些情况下，如果父进程没有适当地处理SIGCHLD信号，子进程可能会变成孤儿进程。孤儿进程最终会被init进程（PID为1的进程）收养，并由init进程来处理其终止。
        // 避免僵尸进程：通过正确响应SIGCHLD信号，父进程可以避免产生僵尸进程（zombie process）。僵尸进程是已经终止但父进程尚未收集其终止状态的进程。
        // 默认情况下，SIGCHLD信号的处理方式是忽略，但是开发者可以根据需要设置自定义的信号处理函数来响应这个信号。在多线程程序中，如果需要，也可以将SIGCHLD信号的传递方式设置为线程安全。
        const SIGCHLD = (1 << 4) | (1 << 0);
        // 如果设置此标志，调用进程和子进程将共享同一内存空间。
        // 在一个进程中的内存写入在另一个进程中可见。
        const CLONE_VM = 1 << 8;
        // 如果设置此标志，子进程将与父进程共享文件系统信息（如当前工作目录）
        const CLONE_FS = 1 << 9;
        // 如果设置此标志，子进程将与父进程共享文件描述符表。
        const CLONE_FILES = 1 << 10;
        const CLONE_SIGHAND = 1 << 11;
        const CLONE_PIDFD = 1 << 12;
        const CLONE_PTRACE = 1 << 13;
        const CLONE_VFORK = 1 << 14;
        const CLONE_PARENT = 1 << 15;
        const CLONE_THREAD = 1 << 16;
        const CLONE_NEWNS = 1 << 17;
        const CLONE_SYSVSEM = 1 << 18;
        const CLONE_SETTLS = 1 << 19;
        const CLONE_PARENT_SETTID = 1 << 20;
        const CLONE_CHILD_CLEARTID = 1 << 21;
        const CLONE_DETACHED = 1 << 22;
        const CLONE_UNTRACED = 1 << 23;
        const CLONE_CHILD_SETTID = 1 << 24;
        const CLONE_NEWCGROUP = 1 << 25;
        const CLONE_NEWUTS = 1 << 26;
        const CLONE_NEWIPC = 1 << 27;
        const CLONE_NEWUSER = 1 << 28;
        const CLONE_NEWPID = 1 << 29;
        const CLONE_NEWNET = 1 << 30;
        const CLONE_IO = 1 << 31;
    }
}

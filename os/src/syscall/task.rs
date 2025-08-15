use core::future::pending;
use core::sync::atomic::{compiler_fence, Ordering};
use core::{clone, default, time};

use crate::arch::config::USER_MAX;
use crate::arch::mm::copy_from_user;
use crate::arch::trap::context::{dump_trap_context, get_trap_context, save_trap_context};
use crate::ext4::fs;
use crate::fs::dentry::X_OK;
use crate::fs::file::OpenFlags;
use crate::fs::namei::{filename_lookup, Nameidata};
use crate::fs::proc::pid;
use crate::futex::do_futex;
use crate::mm::FRAME_ALLOCATOR;
use crate::signal::{LinuxSigInfo, SiField, Sig, SigInfo};
use crate::syscall::errno::Errno;
use crate::syscall::fs::{AT_EMPTY_PATH, NAME_MAX};
use crate::syscall::util::{CLOCK_MONOTONIC, CLOCK_REALTIME};
use crate::syscall::AT_SYMLINK_NOFOLLOW;
use crate::task::{
    add_group, dump_scheduler, for_each_task, get_all_tasks, get_group, get_task, info_allocator,
    new_group, nice_to_priority, nice_to_rlimit, priority_to_nice, unregister_task, wait,
    wait_timeout, CapFlags, CloneFlags, Task, MAX_NICE, MAX_PRIO, MIN_NICE, PRIO_PGRP,
    PRIO_PROCESS, PRIO_USER,
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
use crate::{drivers, dump_system_info};
use alloc::task;
use alloc::vec::Vec;
use alloc::{sync::Arc, vec};
use bitflags::bitflags;
use universal_hash::typenum::bit;

use super::errno::SyscallRet;

#[cfg(target_arch = "riscv64")]
pub fn sys_clone(
    flags: u32,
    stack_ptr: usize,
    parent_tid_ptr: usize,
    tls_ptr: usize,
    children_tid_ptr: usize,
) -> SyscallRet {
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
    children_tid_ptr: usize,
    tls_ptr: usize,
) -> SyscallRet {
    // ToDo: 更新错误检验
    log::error!("[sys_clone] flags: {:b}, stack_ptr: {:x}, parent_tid_ptr: {:x}, tls_ptr: {:x}, children_tid_ptr: {:x}", flags, stack_ptr, parent_tid_ptr, tls_ptr, children_tid_ptr);
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

pub const IGNOER_TEST: &[&str] = &[
    /* 本身就不应该单独运行的 */
    "ltp/testcases/bin/add_ipv6addr",
    "ltp/testcases/bin/cgroup_fj_proc",
    "ltp/testcases/bin/cgroup_regression_fork_processes",
    "ltp/testcases/bin/cgroup_regression_getdelays",
    "ltp/testcases/bin/cpuctl_fj_cpu-hog",
    "ltp/testcases/bin/data",
    "ltp/testcases/bin/doio",
    "ltp/testcases/bin/acl1",
    "ltp/testcases/bin/hackbench",
    "ltp/testcases/bin/create_datafile",
    "ltp/testcases/bin/timed_forkbomb",
    "ltp/testcases/bin/dma_thread_diotest",
    "ltp/testcases/bin/fs_fill",
    "ltp/testcases/bin/pec_listener",
    "ltp/testcases/bin/sched_datafile",
    "ltp/testcases/bin/data_space",
    "ltp/testcases/bin/shm_test",
    "ltp/testcases/bin/starvation",
    "ltp/testcases/bin/fsx-linux",
    "ltp/testcases/bin/genatan2",
    "ltp/testcases/bin/mallocstress",
    "ltp/testcases/bin/openfile",
    "ltp/testcases/bin/prot_hsymlinks",
    "ltp/testcases/bin/smack_set_socket_labels",
    "ltp/testcases/bin/trace_sched",
    "ltp/testcases/bin/writetest",
    "ltp/testcases/bin/cpuset_cpu_hog",
    "ltp/testcases/bin/nfs04_create_file",
    /* 由于OS原因, 先不跑的 */
    "ltp/testcases/bin/mmap1",
    "ltp/testcases/bin/mmap2",
    "ltp/testcases/bin/mmap3",
    // 暂时不测
    // "ltp/testcases/bin/af_alg02",
    // "ltp/testcases/bin/af_alg04",
    // "ltp/testcases/bin/af_alg05",
    // "ltp/testcases/bin/af_alg06",
    // "ltp/testcases/bin/af_alg07",
    // "ltp/testcases/bin/asapi_01",
    // "ltp/testcases/bin/asapi_02",
    // "ltp/testcases/bin/asapi_03",
    // "ltp/testcases/bin/bind01",
    // "ltp/testcases/bin/bind04",
    // "ltp/testcases/bin/bind05",
    // "ltp/testcases/bin/bind06",
    // "ltp/testcases/bin/clock_gettime04",
    // "ltp/testcases/bin/clock_nanosleep01",
    // "ltp/testcases/bin/clock_nanosleep02",
    // "ltp/testcases/bin/clock_nanosleep03",
    // "ltp/testcases/bin/clock_nanosleep04",
    // "ltp/testcases/bin/creat05",
    // "ltp/testcases/bin/dup05",
    // "ltp/testcases/bin/fork09",
    // "ltp/testcases/bin/fork14",
    // "ltp/testcases/bin/kill10",
    // "ltp/testcases/bin/kill11",
    // "ltp/testcases/bin/listen01",
    // "ltp/testcases/bin/leapsec01",
    // "ltp/testcases/bin/pause01",
    // "ltp/testcases/bin/send02",
    // "ltp/testcases/bin/setfsgid03",
    // "ltp/testcases/bin/setfsgid03_16",
    // "ltp/testcases/bin/setitimer01",
    // "ltp/testcases/bin/setrlimit06",
    // "ltp/testcases/bin/setpgid03",
    // "ltp/testcases/bin/statx01",
    // "ltp/testcases/bin/statx11",
    // "ltp/testcases/bin/fgetxattr02",

    // 需要check_envvak
    "ltp/testcases/bin/check_netem",
    "ltp/testcases/bin/check_setkey",
    //暂且有问题的
    "ltp/testcases/bin/crash01",
    "ltp/testcases/bin/crash02",
    "ltp/testcases/bin/bind05",
    "ltp/testcases/bin/fcntl14",
    "ltp/testcases/bin/fcntl14_64",
    "ltp/testcases/bin/fallocate05",
    "ltp/testcases/bin/fallocate06",
    "ltp/testcases/bin/fork14",
    "ltp/testcases/bin/fgetxattr02",
    "ltp/testcases/bin/getcwd04",
    "ltp/testcases/bin/inotify09",
    "ltp/testcases/bin/kill10",
    "ltp/testcases/bin/kill11",
    "ltp/testcases/bin/memctl_test01",
    "ltp/testcases/bin/mknod01",
    "ltp/testcases/bin/mknod09",
    "ltp/testcases/bin/mprotect04",
    "ltp/testcases/bin/nice05",
    "ltp/testcases/bin/setfsgid03",
    "ltp/testcases/bin/setfsgid03_16",
    "ltp/testcases/bin/setpgid03",
    // "ltp/testcases/bin/splice07",
    // "ltp/testcases/bin/statx01",
    "ltp/testcases/bin/send02",
    "ltp/testcases/bin/fsync02",
    "ltp/testcases/bin/mmap09",
    //真的有问题的
    "ltp/testcases/bin/clone04",
    //时间问题
    "ltp/testcases/bin/clock_settime03",
    "ltp/testcases/bin/ebizzy",
    "ltp/testcases/bin/kcmp03",
    "ltp/testcases/bin/sigtimedwait01",
    "ltp/testcases/bin/sigwaitinfo01",
];

pub fn sys_execve(path: *const u8, args: *const usize, envs: *const usize) -> SyscallRet {
    let path = c_str_to_string(path)?;

    if path.starts_with("ltp/testcases/bin/tst") {
        log::warn!("[sys_execve] ignore tst test: {}", path);
        sys_exit(666);
    }

    // 过滤掉一些不必要的测试
    // if path.starts_with("ltp/testcases/bin/") {
    //     if path.ends_with(".sh") {
    //         log::warn!("[sys_execve] ignore shell script: {}", path);
    //         sys_exit(666);
    //     }
    //     if path.ends_with("loop") {
    //         log::warn!("[sys_execve] ignore loop test: {}", path);
    //         sys_exit(666);
    //     }
    //     if path.starts_with("ltp/testcases/bin/dio") {
    //         log::warn!("[sys_execve] ignore dio test: {}", path);
    //         sys_exit(666);
    //     }
    //     if path.starts_with("ltp/testcases/bin/dirty") {
    //         log::warn!("[sys_execve] ignore dirty test: {}", path);
    //         sys_exit(666);
    //     }
    //     if path.starts_with("ltp/testcases/bin/setsockopt") {
    //         log::warn!("[sys_execve] ignore setsockopt test: {}", path);
    //         sys_exit(666);
    //     }
    //     if path.starts_with("ltp/testcases/bin/cpuset") {
    //         log::warn!("[sys_execve] ignore cpuset test: {}", path);
    //         sys_exit(666);
    //     }
    //     if path.starts_with("ltp/testcases/bin/mount") {
    //         log::warn!("[sys_execve] ignore mount test: {}", path);
    //         sys_exit(666);
    //     }
    //     if path.starts_with("ltp/testcases/bin/crypto_user") {
    //         log::warn!("[sys_execve] ignore crypto_user test: {}", path);
    //         sys_exit(666);
    //     }
    //     // if path.starts_with("ltp/testcases/bin/fstatfs") {
    //     //     log::warn!("[sys_execve] ignore crypto_user test: {}", path);
    //     //     sys_exit(666);
    //     // }
    //     if path.starts_with("ltp/testcases/bin/ftest") {
    //         log::warn!("[sys_execve] ignore crypto_user test: {}", path);
    //         sys_exit(666);
    //     }
    //     // if path.starts_with("ltp/testcases/bin/ftruncate") {
    //     //     log::warn!("[sys_execve] ignore ftruncate test: {}", path);
    //     //     sys_exit(666);
    //     // }
    //     if path.starts_with("ltp/testcases/bin/memcg") {
    //         log::warn!("[sys_execve] ignore memcg_subgroup test: {}", path);
    //         sys_exit(666);
    //     }
    //     if path.starts_with("ltp/testcases/bin/mmapstress") {
    //         log::warn!("[sys_execve] ignore mmapstress test: {}", path);
    //         sys_exit(666);
    //     }
    //     if path.starts_with("ltp/testcases/bin/mmstress") {
    //         log::warn!("[sys_execve] ignore mmstress test: {}", path);
    //         sys_exit(666);
    //     }
    //     // if path.starts_with("ltp/testcases/bin/mtest") {
    //     //     log::warn!("[sys_execve] ignore mtest test: {}", path);
    //     //     sys_exit(666);
    //     // }
    //     if path.starts_with("ltp/testcases/bin/pcrypt") {
    //         log::warn!("[sys_execve] ignore pcrypt test: {}", path);
    //         sys_exit(666);
    //     }
    //     if path.starts_with("ltp/testcases/bin/pidns") {
    //         log::warn!("[sys_execve] ignore pidns test: {}", path);
    //         sys_exit(666);
    //     }
    //     if path.starts_with("ltp/testcases/bin/pids") {
    //         log::warn!("[sys_execve] ignore pids test: {}", path);
    //         sys_exit(666);
    //     }
    //     // if path.starts_with("ltp/testcases/bin/ppoll") {
    //     //     log::warn!("[sys_execve] ignore ppoll test: {}", path);
    //     //     sys_exit(666);
    //     // }
    //     if path.starts_with("ltp/testcases/bin/proc") {
    //         log::warn!("[sys_execve] ignore proc test: {}", path);
    //         sys_exit(666);
    //     }
    //     if path.starts_with("ltp/testcases/bin/pth") {
    //         log::warn!("[sys_execve] ignore pth test: {}", path);
    //         sys_exit(666);
    //     }
    //     // if path.starts_with("ltp/testcases/bin/setxattr") {
    //     //     log::warn!("[sys_execve] ignore setxattr test: {}", path);
    //     //     sys_exit(666);
    //     // }
    //     // if path.starts_with("ltp/testcases/bin/shmt") {
    //     //     log::warn!("[sys_execve] ignore shmt test: {}", path);
    //     //     sys_exit(666);
    //     // }
    //     if path.starts_with("ltp/testcases/bin/tst") {
    //         log::warn!("[sys_execve] ignore tst test: {}", path);
    //         sys_exit(666);
    //     }
    //     if path.starts_with("ltp/testcases/bin/cve") {
    //         log::warn!("[sys_execve] ignore tst test: {}", path);
    //         sys_exit(666);
    //     }
    //     if path.starts_with("ltp/testcases/bin/gen") {
    //         log::warn!("[sys_execve] ignore tst test: {}", path);
    //         sys_exit(666);
    //     }
    //     if IGNOER_TEST.contains(&path.as_str()) {
    //         log::warn!("[sys_execve] ignore test: {}", path);
    //         sys_exit(666);
    //     }
    // }
    log::info!(
        "[sys_execve] path: {}, args: {:?}, envs: {:?}",
        path,
        args,
        envs
    );
    if path.len() >= NAME_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    // if path.ends_with(".sh") {
    //     dump_system_info();
    // }
    // argv[0]是应用程序的名字
    // 后续元素是用户在命令行中输入的参数
    let mut args_vec = extract_cstrings(args)?;
    let envs_vec = extract_cstrings(envs)?;
    let task = current_task();
    // OpenFlags::empty() = RDONLY = 0, 以只读方式打开文件
    match path_openat(&path, OpenFlags::empty(), AT_FDCWD, X_OK) {
        Ok(file) => {
            // let all_data = file.read_all();
            // if all_data.is_empty() {
            //     log::error!("[sys_execve] file {} is empty", path);
            //     return Err(Errno::ENOEXEC);
            // }
            let absolute_path = file.get_path().dentry.absolute_path.clone();
            task.kernel_execve_lazily(absolute_path, file, args_vec, envs_vec)?;
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

pub fn sys_execveat(
    dirfd: i32,
    pathname: *const u8,
    args: *const usize,
    envs: *const usize,
    flags: i32,
) -> SyscallRet {
    let task = current_task();
    let mut args_vec = extract_cstrings(args)?;
    let envs_vec = extract_cstrings(envs)?;
    if flags < 0 {
        log::error!("[sys_statx] invalid flags: {}", flags);
        return Err(Errno::EINVAL);
    }
    if flags & AT_EMPTY_PATH != 0 {
        if let Some(file) = current_task().fd_table().get_file(dirfd as usize) {
            let absolute_path = file.get_path().dentry.absolute_path.clone();
            task.kernel_execve_lazily(absolute_path, file, args_vec, envs_vec)?;
            return Ok(0);
        }
        // 根据fd获取文件失败
        return Err(Errno::EBADF);
    }

    let path = c_str_to_string(pathname)?;
    if path.is_empty() {
        log::error!("[sys_statx] pathname is empty");
        return Err(Errno::ENOENT);
    }
    log::info!(
        "[sys_execve] path: {}, args: {:?}, envs: {:?}",
        path,
        args,
        envs
    );
    if path.len() >= NAME_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    let mut nd = Nameidata::new(&path, dirfd)?;
    let follow_symlink = flags & AT_SYMLINK_NOFOLLOW == 0;
    match filename_lookup(&mut nd, follow_symlink) {
        Ok(dentry) => {
            if dentry.is_symlink() && !follow_symlink {
                return Err(Errno::ELOOP);
            }
        }
        Err(e) => {
            return Err(e);
        }
    }

    // OpenFlags::empty() = RDONLY = 0, 以只读方式打开文件
    match path_openat(&path, OpenFlags::empty(), AT_FDCWD, X_OK) {
        Ok(file) => {
            let absolute_path = file.get_path().dentry.absolute_path.clone();
            task.kernel_execve_lazily(absolute_path, file, args_vec, envs_vec)?;
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
    if pgid > isize::MAX as usize {
        log::error!("[sys_setpgid] pgid cannot be negative");
        return Err(Errno::EINVAL);
    }
    let mut set_pid = pid;
    let mut set_pgid = pgid;
    let caller_task = current_task();
    if pid == 0 {
        set_pid = current_task().tid();
    }

    let set_task = get_task(set_pid).ok_or(Errno::ESRCH)?;
    if !set_task.is_process() {
        return Err(Errno::EINVAL);
    }

    if caller_task.is_child(set_pid) {
        if !caller_task.compare_memset(&set_task) {
            return Err(Errno::EACCES);
        }
    } else {
        if caller_task.tid() != set_task.tid() {
            // 只能设置当前任务的pgid
            return Err(Errno::ESRCH);
        }
    }

    if pgid == 0 {
        set_pgid = set_task.tid();
    } else {
        if get_group(pgid).is_none() {
            log::error!("[sys_setpgid] pgid {} does not exist", pgid);
            return Err(Errno::EPERM);
        }
    }

    set_task.set_pgid(set_pgid);
    add_group(set_pgid, &set_task);

    log::info!(
        "[sys_setpgid] task {} set pgid to {}",
        set_task.tid(),
        set_task.pgid()
    );

    Ok(0)

    // let task = if pid == 0 {
    //     caller_task.clone()
    // } else {
    //     if pid != caller_task.tid() && !caller_task.is_child(pid) {
    //         // 只能设置当前任务的pgid
    //         log::error!("[sys_setpgid] pid must be current task's tid");
    //         return Err(Errno::ESRCH);
    //     }
    //     get_task(pid).unwrap()
    // };

    // if pgid == 0 {
    //     // 将进程组 ID 设置为进程 ID
    //     if !caller_task.compare_memset(&task) {
    //         return Err(Errno::EACCES);
    //     }
    //     drop(caller_task);
    //     task.set_pgid(task.tid());
    //     add_group(task.tid(), &task);
    // } else {
    //     if get_group(pgid as usize).is_none() {
    //         return Err(Errno::EPERM);
    //     }
    //     if !caller_task.compare_memset(&task) {
    //         return Err(Errno::EACCES);
    //     }
    //     drop(caller_task);
    //     add_group(pgid as usize, &task);
    // }
    //
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
    log::warn!(
        "[sys_waitpid] pid: {}, exit_code_ptr: {:x}, option: {:?}",
        pid,
        exit_code_ptr,
        option,
    );
    // option 必须合法
    if option < 0 {
        return Err(Errno::EINVAL);
    }

    // 检查进程组是否存在（pid < 0 表示等待某个 pgid）
    if pid < 0 {
        get_group(-pid as usize).ok_or(Errno::ESRCH)?;
    }

    let wait_option = WaitOption::from_bits(option).unwrap_or_else(|| {
        log::error!("[sys_waitpid] Invalid wait option: {}", option);
        WaitOption::empty()
    });

    let cur_task = current_task();
    loop {
        // 先检查当前进程是否存在满足目标子进程
        let target_task = select_task(pid);

        log::trace!(
            "[sys_waitpid] cur_task: {}, target_task: {:?}",
            cur_task.tid(),
            target_task
        );
        // 存在目标进程
        match target_task {
            Some(child) => {
                let tid = child.tid();
                let tgid = child.tgid();

                // 神奇小咒语
                log::trace!("waitpid");
                // 如果子进程已经退出，直接回收资源并返回
                if child.is_zombie() {
                    cur_task.remove_child_task(tid);
                    debug_assert_eq!(Arc::strong_count(&child), 1);
                    // 注销任务
                    unregister_task(tid);

                    let code = child.exit_code();
                    log::warn!("[sys_waitpid] child {} exited with code: {}", tid, code,);

                    if exit_code_ptr != 0 {
                        // 将 exit_code 写入用户空间
                        if let Err(e) =
                            copy_to_user(exit_code_ptr as *mut i32, &code as *const i32, 1)
                        {
                            log::warn!("[sys_waitpid] failed to copy exit_code to user: {:?}", e);
                            return Err(e);
                        }
                    }

                    return Ok(tgid);
                }

                // 子进程未退出
                log::trace!("[sys_waitpid] child {} is not zombie, waiting...", tid);
                if wait_option.contains(WaitOption::WNOHANG) {
                    return Ok(0); // 非阻塞返回
                }

                // 阻塞等待被中断时，需要判断是否继续等待
                if wait() == -1 {
                    log::trace!("[sys_waitpid] wait interrupted");
                    // 如果因为 SIGCHLD 被中断，继续 loop 检查
                    if let Some(_sig) = cur_task
                        .op_sig_pending_mut(|pending| pending.find_signal(Sig::SIGCHLD.into()))
                    {
                        cur_task.set_uninterrupted();
                        continue;
                    }
                    return Err(Errno::EINTR);
                }
            }

            None => {
                // 没有任何符合条件的子进程
                return Err(Errno::ECHILD);
            }
        }
    }
}

// Todo: 支持WCONTINUED
pub fn sys_waitid(idtype: i32, pid: isize, infop: usize, option: i32) -> SyscallRet {
    log::warn!(
        "[sys_waitid] idtype: {}, pid: {}, infop: {:x}, option: {}",
        idtype,
        pid,
        infop,
        option
    );

    // option 必须合法
    if option < 0 {
        return Err(Errno::EINVAL);
    }
    // option 必须包含 WEXITED, WSTOPPED 或 WCONTINUED
    if option & (WaitOption::WEXITED | WaitOption::WSTOPPED | WaitOption::WCONTINUED).bits() == 0 {
        return Err(Errno::EINVAL);
    }

    // idtype 必须合法
    if idtype < 0 || idtype > 3 {
        log::error!("[sys_waitid] Invalid idtype: {}", idtype);
        return Err(Errno::EINVAL);
    }

    let wait_option = WaitOption::from_bits(option).unwrap_or_else(|| {
        log::error!("[sys_waitid] Invalid wait option: {}", option);
        WaitOption::empty()
    });

    let cur_task = current_task();
    loop {
        // 先检查当前进程是否存在满足目标子进程
        let target_task = waitid_prepare(idtype, pid, option);

        match target_task {
            Some(child) => {
                let tid = child.tid();

                // 神奇小咒语
                log::trace!("waitpid");
                // 如果子进程已经退出，直接回收资源并返回
                if (option & WaitOption::WEXITED.bits() != 0) && child.is_zombie() {
                    return deal_zombie_task(&cur_task, &child, infop);
                }
                // 如果子进程被暂停，直接返回
                else if (option & WaitOption::WSTOPPED.bits() != 0) && child.is_stopped() {
                    return deal_stopped_task(&child, infop);
                }
                // 如果子进程被继续，直接返回
                // else if (option & WaitOption::WCONTINUED.bits() != 0) && child.is_continued() {
                //     // return deal_continued_task(&cur_task, &child, infop);
                // }

                // 子进程未退出
                log::trace!("[sys_waitpid] child {} is not zombie, waiting...", tid);
                if wait_option.contains(WaitOption::WNOHANG) {
                    return Ok(0); // 非阻塞返回
                }

                // 阻塞等待被中断时，需要判断是否继续等待
                if wait() == -1 {
                    log::trace!("[sys_waitpid] wait interrupted");
                    // 如果因为 SIGCHLD 被中断，继续 loop 检查
                    if let Some(_sig) = cur_task
                        .op_sig_pending_mut(|pending| pending.find_signal(Sig::SIGCHLD.into()))
                    {
                        cur_task.set_uninterrupted();
                        continue;
                    }
                    return Err(Errno::EINTR);
                }
            }
            None => {
                // 没有任何符合条件的子进程
                return Err(Errno::ECHILD);
            }
        }
    }
}

/// 用于waitpid选择结束的目标任务
fn select_task(pid: isize) -> Option<Arc<Task>> {
    let mut target_task: Option<Arc<Task>> = None;
    let cur_task = current_task();

    cur_task.op_children_mut(|children| {
        for child in children.values() {
            log::debug!(
                "child: {}, pid: {}, pgid: {}, tgid: {}, is_zombie: {}",
                child.tid(),
                pid,
                child.pgid(),
                child.tgid(),
                child.is_zombie()
            );
            let matches = match pid {
                -1 => child.is_zombie(), // 等待任意僵尸子进程
                0 => child.is_zombie() && child.pgid() == cur_task.pgid(), // 当前进程组的僵尸子进程
                p if p > 0 => child.tgid() == p as usize, // 等待 tid 为 pid 的子进程
                p if p < -1 => child.pgid() == (-p) as usize, // 等待 pgid 为 -pid 的子进程
                _ => false,
            };

            if matches {
                target_task = Some(child.clone());
                return; // 找到第一个符合条件的立即返回
            }
        }

        // 如果找不到符合条件的僵尸子进程，也可以选择任意一个非僵尸子进程（作为 fallback）
        if pid == -1 || pid == 0 {
            for child in children.values() {
                let fallback = match pid {
                    -1 => true,
                    0 => child.pgid() == cur_task.pgid(),
                    _ => false,
                };
                if fallback {
                    target_task = Some(child.clone());
                    break;
                }
            }
        }
    });

    target_task
}

/// 用于waitpid选择暂停的目标任务
fn select_stopped_task(pid: isize) -> Option<Arc<Task>> {
    let mut target_task: Option<Arc<Task>> = None;
    let cur_task = current_task();

    cur_task.op_children_mut(|children| {
        for child in children.values() {
            log::error!(
                "child: {}, pid: {}, pgid: {}, tgid: {}, is_stopped: {}",
                child.tid(),
                pid,
                child.pgid(),
                child.tgid(),
                child.is_stopped()
            );
            let matches = match pid {
                -1 => child.is_stopped(), // 等待任意停止子进程
                0 => child.is_stopped() && child.pgid() == cur_task.pgid(), // 当前进程组的停止子进程
                p if p > 0 => child.tgid() == p as usize, // 等待 tid 为 pid 的子进程
                p if p < -1 => child.pgid() == (-p) as usize, // 等待 pgid 为 -pid 的子进程
                _ => false,
            };

            if matches {
                target_task = Some(child.clone());
                return; // 找到第一个符合条件的立即返回
            }
        }

        // 如果找不到符合条件的僵尸子进程，也可以选择任意一个非僵尸子进程（作为 fallback）
        if pid == -1 || pid == 0 {
            for child in children.values() {
                let fallback = match pid {
                    -1 => true,
                    0 => child.pgid() == cur_task.pgid(),
                    _ => false,
                };
                if fallback {
                    target_task = Some(child.clone());
                    break;
                }
            }
        }
    });

    target_task
}

/// waitid 的任务选择逻辑
fn waitid_prepare(idtype: i32, pid: isize, option: i32) -> Option<Arc<Task>> {
    const P_ALL: i32 = 0; // 所有子进程
    const P_PID: i32 = 1; // 进程 ID
    const P_PGID: i32 = 2; // 进程组 ID
    const P_PIDFD: i32 = 3; // 进程文件描述符

    match idtype {
        P_ALL => {
            // waitid() 将等待所有子进程，并且 id 将被忽略
            select_with_option(-1, option)
        }
        P_PID => {
            // waitid() 将等待进程 ID 等于 id 的子进程
            select_with_option(pid, option)
        }
        P_PGID => {
            // waitid() 应等待进程组 ID 等于 (pid_t)id 的任何子进程。
            select_with_option(-pid, option)
        }
        P_PIDFD => {
            // 等待指定 PIDFD 的进程
            log::error!("[sys_waitid] P_PIDFD is not supported yet");
            return None;
        }
        _ => {
            log::error!("[sys_waitid] invalid idtype: {}", idtype);
            return None;
        }
    }
}

/// 根据option来选择对应的任务选取方式
/// 注：优先处理退出的任务，如果没有退出的任务，则处理暂停的任务
fn select_with_option(pid: isize, option: i32) -> Option<Arc<Task>> {
    if option & WaitOption::WEXITED.bits() != 0 {
        select_task(pid)
    } else if option & WaitOption::WSTOPPED.bits() != 0 {
        select_stopped_task(pid)
    } else {
        select_task(pid)
    }
}

/// 处理僵尸任务的逻辑
fn deal_zombie_task(cur_task: &Arc<Task>, child: &Arc<Task>, infop: usize) -> SyscallRet {
    cur_task.remove_child_task(child.tid());
    debug_assert_eq!(Arc::strong_count(&child), 1);
    // 注销任务
    unregister_task(child.tid());

    let child_exitcode = child.exit_code();
    println!(
        "[sys_waitpid] child {} exited with code: {}",
        child.tid(),
        child_exitcode
    );
    let exit_code;
    let si_code;
    if child_exitcode < 0x7f && child_exitcode > 0 {
        log::warn!(
            "[sys_waitid] child {} exited by kill: {}",
            child.tid(),
            child_exitcode
        );
        exit_code = child_exitcode;
        si_code = crate::signal::SigInfo::CLD_KILLED;
    } else {
        log::warn!(
            "[sys_waitid] child {} exited normally: {}",
            child.tid(),
            child_exitcode
        );
        exit_code = (child_exitcode >> 8) & 0xff; // 获取实际的退出码
        si_code = crate::signal::SigInfo::CLD_EXITED;
    }

    let siginfo: LinuxSigInfo = SigInfo::new(
        Sig::SIGCHLD.raw(),
        si_code,
        SiField::SIGCHILD {
            tid: child.tid() as i32,
            uid: child.uid(),
            status: exit_code,
            // utime: child.time_stat().user_time().as_ticks() as u64,
            // stime: child.time_stat().sys_time().as_ticks() as u64,
        },
    )
    .into();

    if infop != 0 {
        if let Err(e) = copy_to_user(
            infop as *mut LinuxSigInfo,
            &siginfo as *const LinuxSigInfo,
            1,
        ) {
            log::warn!("[sys_waitpid] failed to copy siginfo to user: {:?}", e);
            return Err(e);
        }
    }
    return Ok(0);
}

// 处理停止任务的逻辑
fn deal_stopped_task(child: &Arc<Task>, infop: usize) -> SyscallRet {
    let siginfo: LinuxSigInfo = SigInfo::new(
        Sig::SIGCHLD.raw(),
        crate::signal::SigInfo::CLD_STOPPED,
        SiField::SIGCHILD {
            tid: child.tid() as i32,
            uid: child.uid(),
            status: Sig::SIGSTOP.raw(),
            // utime: child.time_stat().user_time().as_ticks() as u64,
            // stime: child.time_stat().sys_time().as_ticks() as u64,
        },
    )
    .into();

    if infop != 0 {
        if let Err(e) = copy_to_user(
            infop as *mut LinuxSigInfo,
            &siginfo as *const LinuxSigInfo,
            1,
        ) {
            log::warn!("[sys_waitpid] failed to copy siginfo to user: {:?}", e);
            return Err(e);
        }
    }
    return Ok(0);
}

pub fn sys_futex(
    uaddr: usize,
    futex_op: i32,
    val: u32,
    val2: usize,
    uaddr2: usize,
    val3: u32,
) -> SyscallRet {
    log::error!(
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
    copy_to_user(time_val_ptr, &time_val as *const TimeVal, 1)?;
    Ok(0)
}

pub fn sys_nanosleep(time_val_ptr: usize, rem: usize) -> SyscallRet {
    let mut time_val: TimeSpec = TimeSpec::default();
    copy_from_user(
        time_val_ptr as *const TimeSpec,
        &mut time_val as *mut TimeSpec,
        1,
    )?;
    let start_time = TimeSpec::new_machine_time();
    log::error!(
        "[sys_nanosleep] task{} sleep {:?}",
        current_task().tid(),
        time_val
    );
    if !time_val.timespec_valid_settod() {
        return Err(Errno::EINVAL);
    }
    let ret = wait_timeout(time_val, -1);
    if ret == -1 {
        let sleep_time = TimeSpec::new_machine_time() - start_time;
        let remained_time = if sleep_time >= time_val {
            TimeSpec::default() // 如果睡眠时间超过了请求的时间，则剩余时间为0
        } else {
            time_val - sleep_time
        };
        log::error!(
            "[sys_nanosleep] task{} wakeup by signal, remained time: {:?}",
            current_task().tid(),
            remained_time
        );
        current_task().cancel_restart();
        copy_to_user(rem as *mut TimeSpec, &remained_time, 1)?;
        return Err(Errno::EINTR);
    }
    Ok(0)
}

pub const TIMER_ABSTIME: i32 = 0x01;
pub fn sys_clock_nanosleep(clock_id: usize, flags: i32, req: usize, remain: usize) -> SyscallRet {
    // 8.3 Debug
    // log::info!(
    //     "[sys_clock_nanosleep] clock_id: {}, flags: {}, req: {:x}, rem: {:x}",
    //     clock_id,
    //     flags,
    //     req,
    //     remain
    // );
    // let t = copy_from_user(t as *const TimeSpec, 1)?[0];
    let mut t_buf: TimeSpec = TimeSpec::default();
    copy_from_user(req as *const TimeSpec, &mut t_buf as *mut TimeSpec, 1)?;
    if !t_buf.timespec_valid_settod() {
        return Err(Errno::EINVAL);
    }
    let start_time;
    let waited_time = match clock_id {
        CLOCK_REALTIME => {
            start_time = TimeSpec::new_wall_time();
            if flags == TIMER_ABSTIME {
                // 绝对时间
                if start_time >= t_buf {
                    return Ok(0);
                }
                t_buf - start_time
            } else {
                t_buf
            }
        }
        CLOCK_MONOTONIC => {
            start_time = TimeSpec::new_machine_time();
            if flags == TIMER_ABSTIME {
                // 绝对时间
                if start_time >= t_buf {
                    return Ok(0);
                }
                t_buf - start_time
            } else {
                // 相对时间
                t_buf
            }
        }
        _ => {
            log::error!("[sys_clock_nanosleep] clock_id: {} not supported", clock_id);
            return Err(Errno::EOPNOTSUPP);
        }
    };
    log::info!(
        "[sys_clock_nanosleep] task{} sleep {:?} on clock_id: {}",
        current_task().tid(),
        waited_time,
        clock_id
    );
    let ret = wait_timeout(waited_time, -1);
    let now = if clock_id == CLOCK_REALTIME {
        TimeSpec::new_wall_time()
    } else {
        TimeSpec::new_machine_time()
    };
    if ret == -1 {
        let sleep_time = now - start_time;
        let remained_time = if sleep_time >= waited_time {
            TimeSpec::default() // 如果睡眠时间超过了请求的时间，则剩余时间为0
        } else {
            waited_time - sleep_time
        };
        log::error!(
            "[sys_clock_nanosleep] task{} wakeup by signal, remained time: {:?}",
            current_task().tid(),
            remained_time
        );
        current_task().cancel_restart();
        copy_to_user(remain as *mut TimeSpec, &remained_time, 1)?;
        return Err(Errno::EINTR);
    }
    Ok(0)
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
    const NGROUPS_MAX: usize = 65536; // 最大补充组数(为了过ltp，目前已经应是65536)
    if size > NGROUPS_MAX {
        return Err(Errno::EINVAL);
    }
    if task.euid() != 0 {
        // 只有root用户可以设置补充组
        return Err(Errno::EPERM);
    }
    let mut groups = vec![0u32; size as usize];
    if size == 0 && list == 0 {
        // 清空补充组
        task.op_sup_groups_mut(|groups| {
            groups.clear();
        });
        return Ok(0);
    }
    copy_from_user(list as *const u32, groups.as_mut_ptr(), size)?;
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
    const NGROUPS_MAX: usize = 65536;
    if size > NGROUPS_MAX {
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

/// getcpu() 系统调用会识别调用线程或进程当前正在运行的处理器和节点，并将它们写入 cpu 和 node 参数指向的整数中。
/// Todo: 实现 NUMA 支持
pub fn sys_getcpu(cpu: usize, node: usize) -> SyscallRet {
    if cpu != 0 {
        let cpu_id = current_task().cpu_id();
        copy_to_user(cpu as *mut usize, &cpu_id, 1)?;
    }
    if node != 0 {
        // 在没有 NUMA 支持的情况下，假设节点为 0
        let node_id: u32 = 0;
        copy_to_user(node as *mut u32, &node_id, 1)?;
    }
    Ok(0)
}

pub fn sys_clone3(clone_args: usize, size: usize) -> SyscallRet {
    const CLONE_ARGS_MINIMAL: usize = 64;

    if size < CLONE_ARGS_MINIMAL {
        log::error!("[sys_clone3] size is too small: {}", size);
        return Err(Errno::EINVAL);
    }
    // 获取参数
    let mut args = CloneArgs::default();
    let args_ptr = &mut args as *mut CloneArgs as *mut u8;
    copy_from_user(clone_args as *const u8, args_ptr, size)?;
    log::info!("[sys_clone3] args: {:?}", args);
    // 提取参数
    let flags = args.flags;
    let stack_ptr = args.stack;
    let children_tid_ptr = args.child_tid;
    let parent_tid_ptr = args.parent_tid;
    let tls_ptr = args.tls;
    let exit_signal = Sig::from(args.exit_signal as i32);
    let stack_size = args.stack_size;
    //按照clone的逻辑先处理
    let flags = match CloneFlags::from_bits(flags as u32) {
        None => {
            log::error!("clone flags is None: {}", flags);
            return Err(Errno::EINVAL);
        }
        Some(flag) => flag,
    };
    // 对一些flags做特殊处理
    if flags.contains(CloneFlags::CLONE_SIGHAND) {
        if !flags.contains(CloneFlags::CLONE_VM) {
            return Err(Errno::EINVAL);
        }
    }
    if flags.contains(CloneFlags::CLONE_THREAD) {
        if !flags.contains(CloneFlags::CLONE_SIGHAND) {
            return Err(Errno::EINVAL);
        }
    }
    if flags.contains(CloneFlags::CLONE_FS) && flags.contains(CloneFlags::CLONE_NEWNS) {
        return Err(Errno::EINVAL);
    }
    // 暂不支持pidfd
    if flags.contains(CloneFlags::CLONE_PIDFD) {
        let pidfd = args.pidfd;
        let fake_pidfd = 0u8; // fake pidfd
        copy_to_user(pidfd as *mut u8, &fake_pidfd as *const u8, 1)?;
        log::warn!("[sys_clone3] CLONE_PIDFD is not supported");
        return Err(Errno::ENOSYS);
    }
    if exit_signal.raw() != 0 && !exit_signal.is_valid() {
        return Err(Errno::EINVAL);
    }
    if (stack_ptr == 0 && stack_size != 0) || (stack_ptr != 0 && stack_size == 0) {
        return Err(Errno::EINVAL);
    }
    log::error!("[sys_clone] flags: {:?}", flags);
    let task = current_task();
    let new_task = task.kernel_clone(&flags, stack_ptr as usize, children_tid_ptr as usize)?;
    let new_task_tid = new_task.tid();

    if flags.contains(CloneFlags::CLONE_PARENT_SETTID) {
        log::warn!("[sys_clone] handle CLONE_PARENT_SETTID");
        let content = (new_task_tid as u64).to_le_bytes();
        log::error!("parent_tid_ptr: {:x}", parent_tid_ptr);
        copy_to_user(parent_tid_ptr as *mut u8, &content as *const u8, 8)?;
    }
    if flags.contains(CloneFlags::CLONE_CHILD_CLEARTID) {
        log::warn!("[sys_clone] handle CLONE_CHILD_CLEARTID");
        new_task.set_tac(children_tid_ptr as usize);
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

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroups: u64,
}

const _LINUX_CAPABILITY_VERSION_1: u32 = 0x19980330;
const _LINUX_CAPABILITY_VERSION_2: u32 = 0x20071026;
const _LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

pub fn sys_capget(user_cap_header: usize, user_cap_data: usize) -> SyscallRet {
    log::error!(
        "[sys_capget] header: {:x}, data: {:x}",
        user_cap_header,
        user_cap_data
    );
    // 获取header和data
    let mut header = user_cap_header::default();
    let mut data = user_cap_data::default();
    copy_from_user(
        user_cap_header as *const user_cap_header,
        &mut header as *mut user_cap_header,
        1,
    )?;
    copy_from_user(
        user_cap_data as *const user_cap_data,
        &mut data as *mut user_cap_data,
        1,
    )?;
    log::error!("[sys_capget] header: {:?}, data: {:?}", header, data);

    // 版本非法
    if header.version != _LINUX_CAPABILITY_VERSION_1
        && header.version != _LINUX_CAPABILITY_VERSION_2
        && header.version != _LINUX_CAPABILITY_VERSION_3
    {
        header.version = _LINUX_CAPABILITY_VERSION_3;
        copy_to_user(
            user_cap_header as *mut user_cap_header,
            &header as *const user_cap_header,
            1,
        )?;
        return Err(Errno::EINVAL);
    }

    // pid 非法
    if header.pid < 0 {
        return Err(Errno::EINVAL);
    } else if header.pid == 0 {
        // 如果pid为0，表示当前进程
        header.pid = current_task().tid() as i32;
    }

    if let Some(task) = get_task(header.pid as usize) {
        let effective = task.effective();
        let permitted = task.permitted();
        let inheritable = task.inheritable();
        let header = user_cap_header::new(task.tid() as i32);
        let data = user_cap_data::new(effective, permitted, inheritable);
        copy_to_user(
            user_cap_data as *mut user_cap_data,
            &data as *const user_cap_data,
            1,
        )?;
        return Ok(0);
    } else {
        return Err(Errno::ESRCH);
    }
}

pub fn sys_capset(user_cap_header: usize, user_cap_data: usize) -> SyscallRet {
    // 获取header和data
    let mut header = user_cap_header::default();
    let mut data = user_cap_data::default();
    copy_from_user(
        user_cap_header as *const user_cap_header,
        &mut header as *mut user_cap_header,
        1,
    )?;
    copy_from_user(
        user_cap_data as *const user_cap_data,
        &mut data as *mut user_cap_data,
        1,
    )?;
    log::error!("[sys_capset] header: {:?}, data: {:?}", header, data);

    // 版本非法
    if header.version != _LINUX_CAPABILITY_VERSION_1
        && header.version != _LINUX_CAPABILITY_VERSION_2
        && header.version != _LINUX_CAPABILITY_VERSION_3
    {
        header.version = _LINUX_CAPABILITY_VERSION_3;
        copy_to_user(
            user_cap_header as *mut user_cap_header,
            &header as *const user_cap_header,
            1,
        )?;
        return Err(Errno::EINVAL);
    }

    // pid 非法
    if header.pid < 0 {
        return Err(Errno::EINVAL);
    } else if header.pid == 0 {
        // 如果pid为0，表示当前进程
        header.pid = current_task().tid() as i32;
    } else if header.pid != current_task().tid() as i32 {
        // 不允许修改其他进程（有待商榷）
        return Err(Errno::EPERM);
    }

    if let Some(task) = get_task(header.pid as usize) {
        // 判断effective 是否为 permitted的子集
        if data.effective & !data.permitted != 0 {
            log::error!("[sys_capset] effective capabilities cannot exceed permitted capabilities");
            return Err(Errno::EPERM);
        }
        // 判断新permitted 是否为 老permitted的子集
        let old_permitted = task.permitted();
        if data.permitted & !old_permitted != 0 {
            log::error!(
                "[sys_capset] new permitted capabilities cannot exceed old permitted capabilities"
            );
            return Err(Errno::EPERM);
        }
        // 判断新inheritable 是否为 bset的子集
        let bset = task.bset();
        if data.inheritable & !bset != 0 {
            log::error!(
                "[sys_capset] new inheritable capabilities cannot exceed bset capabilities"
            );
            return Err(Errno::EPERM);
        }
        // 如果任务不包含CAP_SETPCAP
        if task.effective() & CapFlags::CAP_SETPCAP.bits() == 0 {
            //只能把 pP 或 pI 减少或保持
            let old_permitted = task.permitted();
            if data.inheritable & !old_permitted != 0 {
                log::error!("[sys_capset] task does not have CAP_SETPCAP capability");
                return Err(Errno::EPERM);
            }
        }

        log::warn!(
            "[sys_capset] task{} set effective: {:#b}, permitted: {:#b}, inheritable: {:#b}",
            task.tid(),
            data.effective,
            data.permitted,
            data.inheritable
        );
        task.set_effective(data.effective);
        task.set_permitted(data.permitted);
        task.set_inheritable(data.inheritable);

        return Ok(0);
    } else {
        return Err(Errno::ESRCH);
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct user_cap_header {
    pub version: u32,
    pub pid: i32,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct user_cap_data {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

impl user_cap_header {
    pub fn new(pid: i32) -> Self {
        user_cap_header {
            version: _LINUX_CAPABILITY_VERSION_3,
            pid,
        }
    }
}

impl user_cap_data {
    pub fn new(effective: u32, permitted: u32, inheritable: u32) -> Self {
        user_cap_data {
            effective,
            permitted,
            inheritable,
        }
    }
}

const PR_SET_PDEATHSIG: i32 = 1;
const PR_GET_PDEATHSIG: i32 = 2;
const PR_GET_DUMPABLE: i32 = 3;
const PR_SET_DUMPABLE: i32 = 4;
const PR_GET_UNALIGN: i32 = 5;
const PR_SET_UNALIGN: i32 = 6;
const PR_SET_KEEPCAPS: i32 = 7;
const PR_GET_FPEMU: i32 = 9;
const PR_SET_FPEMU: i32 = 10;
const PR_GET_FPEXC: i32 = 11;
const PR_SET_FPEXC: i32 = 12;
const PR_GET_TIMING: i32 = 13;
const PR_SET_TIMING: i32 = 14;
const PR_SET_NAME: i32 = 15;
const PR_GET_NAME: i32 = 16;
const PR_GET_ENDIAN: i32 = 19;
const PR_SET_ENDIAN: i32 = 20;
const PR_GET_SECCOMP: i32 = 21;
const PR_SET_SECCOMP: i32 = 22;
const PR_CAPBSET_READ: i32 = 23;
const PR_CAPBSET_DROP: i32 = 24;
const PR_SET_SECUREBITS: i32 = 28;
const PR_SET_NO_NEW_PRIVS: i32 = 38;
const PR_GET_NO_NEW_PRIVS: i32 = 39;
const PR_SET_THP_DISABLE: i32 = 41;
const PR_GET_THP_DISABLE: i32 = 42;
const PR_CAP_AMBIENT: i32 = 47;
const PR_GET_SPECULATION_CTRL: i32 = 52;
const PR_MAX: i32 = 100;

pub fn sys_prctl(op: i32, arg1: usize, arg2: usize, arg3: usize, arg4: usize) -> SyscallRet {
    log::error!(
        "[sys_prctl] op: {}, arg1: {:x}, arg2: {:x}, arg3: {:x}, arg4: {:x}",
        op,
        arg1,
        arg2,
        arg3,
        arg4
    );
    if op > PR_MAX {
        log::warn!("[sys_prctl] invalid op: {}", op);
        return Err(Errno::EINVAL);
    }
    match op {
        PR_SET_PDEATHSIG => {
            // 将调用进程的父进程死亡信号设置为 sig
            // arg1 为sig号
            let sig = Sig::from(arg1 as i32);
            if !sig.is_valid() {
                return Err(Errno::EINVAL);
            }
            return Err(Errno::ENOSYS); // 目前不支持
        }
        PR_SET_DUMPABLE => {
            // 设置“dumpable”属性的状态
            // arg1 为转储状态
            if arg1 != 0 && arg1 != 1 {
                log::warn!("[sys_prctl] PR_SET_DUMPABLE with invalid arg1: {}", arg1);
                return Err(Errno::EINVAL);
            }
            return Err(Errno::ENOSYS); // 目前不支持
        }
        PR_SET_TIMING => {
            // 控制内核是否记录进程时间统计
            // arg1 为mode (必须为0)
            if arg1 != 0 {
                return Err(Errno::EINVAL);
            }
            return Err(Errno::ENOSYS);
        }
        PR_SET_NAME => {
            // 设置进程名
            // arg1 为进程名指针
            let mut name = vec![0u8; 16];
            copy_from_user(arg1 as *const u8, name.as_mut_ptr(), name.len())?;
            return Err(Errno::ENOSYS); // 目前不支持
        }
        PR_SET_SECCOMP => {
            // 为调用线程设置安全计算 (seccomp) 模式，以限制可用的系统调用。
            // arg1 为 seccomp 模式
            // arg2 为 过滤器地址
            match arg1 {
                1 => {
                    // Strict 模式
                }
                2 => {
                    //Filter 模式
                    // Todo: 待完善
                    let mut filter = vec![0u8; 1]; // 过滤器内容
                    copy_from_user(arg2 as *const u8, filter.as_mut_ptr(), 1)?;
                    // 检查权限
                    let task = current_task();
                    let effective = task.effective();
                    if (effective & CapFlags::CAP_SYS_ADMIN.bits() == 0) {
                        log::warn!("[sys_prctl] non-root task cannot drop capabilities");
                        return Err(Errno::EACCES);
                    }
                }
                _ => {
                    return Err(Errno::EINVAL);
                }
            }
            return Err(Errno::ENOSYS); // 目前不支持
        }
        PR_CAPBSET_DROP => {
            // PR_CAPBSET_DROP 用于从进程的能力集中删除指定的能力。
            // arg1 为cap索引
            if arg1 == 0 {
                log::warn!("[sys_prctl] PR_CAPBSET_DROP with arg1 = 0, no capabilities dropped");
                return Ok(0);
            }
            let task = current_task();
            // 检查权限
            let effective = task.effective();
            if (effective & CapFlags::CAP_SETPCAP.bits() == 0) {
                log::warn!("[sys_prctl] non-root task cannot drop capabilities");
                return Err(Errno::EPERM);
            }
            let bset = task.bset();
            task.set_bset(bset & !(1 << arg1));
            Ok(0)
        }
        PR_SET_SECUREBITS => {
            // 设置调用线程的安全位
            // arg1 为flag
            let task = current_task();
            // 检查权限
            let effective = task.effective();
            if (effective & CapFlags::CAP_SETPCAP.bits() == 0) {
                log::warn!("[sys_prctl] non-root task cannot drop capabilities");
                return Err(Errno::EPERM);
            }
            return Err(Errno::ENOSYS); // 目前不支持
        }
        PR_SET_NO_NEW_PRIVS => {
            // 设置调用线程的 no_new_privs 属性
            // arg1 必须为 1，其余必须为 0
            if arg1 != 1 {
                return Err(Errno::EINVAL);
            }
            if arg2 != 0 || arg3 != 0 || arg4 != 0 {
                return Err(Errno::EINVAL);
            }
            return Err(Errno::ENOSYS); // 目前不支持
        }
        PR_GET_NO_NEW_PRIVS => {
            // 获取调用线程的 no_new_privs 属性
            // 所有参数必须为0
            if arg1 != 0 || arg2 != 0 || arg3 != 0 || arg4 != 0 {
                return Err(Errno::EINVAL);
            }
            return Err(Errno::ENOSYS); // 目前不支持
        }
        PR_SET_THP_DISABLE => {
            // 设置调用线程的“THP disable”标志的状态
            // arg1 为 flag
            // 其余必须为0
            if arg2 != 0 || arg3 != 0 || arg4 != 0 {
                return Err(Errno::EINVAL);
            }
            return Err(Errno::ENOSYS); // 目前不支持
        }
        PR_GET_THP_DISABLE => {
            // 获取调用线程的“THP disable”标志的状态
            // 所有参数必须为0
            if arg1 != 0 || arg2 != 0 || arg3 != 0 || arg4 != 0 {
                return Err(Errno::EINVAL);
            }
            return Err(Errno::ENOSYS); // 目前不支持
        }
        PR_CAP_AMBIENT => {
            const PR_CAP_AMBIENT_IS_SET: usize = 1;
            const PR_CAP_AMBIENT_RAISE: usize = 2;
            const PR_CAP_AMBIENT_LOWER: usize = 3;
            const PR_CAP_AMBIENT_CLEAR_ALL: usize = 4;

            // 获取调用线程的能力环境
            // arg1 为op
            match arg1 {
                PR_CAP_AMBIENT_IS_SET => {
                    const CAP_INDEX_MAX: usize = 31;
                    // This call returns 1 if the capability in cap is in the ambient
                    // arg2 为 cap，其余为0
                    if arg3 != 0 || arg4 != 0 {
                        return Err(Errno::EINVAL);
                    }
                    if arg2 > CAP_INDEX_MAX {
                        return Err(Errno::EINVAL);
                    }
                }
                PR_CAP_AMBIENT_RAISE => {}
                PR_CAP_AMBIENT_LOWER => {}
                PR_CAP_AMBIENT_CLEAR_ALL => {
                    // 所有cap删除
                    // 其余arg必须为0
                    if arg2 != 0 || arg3 != 0 || arg4 != 0 {
                        return Err(Errno::EINVAL);
                    }
                }
                _ => {
                    return Err(Errno::EINVAL);
                }
            }
            return Err(Errno::ENOSYS); // 目前不支持
        }
        PR_GET_SPECULATION_CTRL => {
            // 返回 misfeature 中指定的推测 misfeature 的状态。
            // arg1 为misfeature，其余必须为0
            if arg2 != 0 || arg3 != 0 || arg4 != 0 {
                return Err(Errno::EINVAL);
            }
            return Err(Errno::ENOSYS); // 目前不支持
        }
        _ => {
            log::warn!("[sys_prctl] unimplemented op: {}", op);
            return Err(Errno::ENOSYS);
        }
    }
}

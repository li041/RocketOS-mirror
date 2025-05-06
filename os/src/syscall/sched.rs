use crate::{arch::mm::copy_to_user, task::{current_task, get_task, CpuMask, Tid}};

use super::errno::{Errno, SyscallRet};

/* 
    sched_setaffinity() 将 ID 为 pid 的线程的 CPU 亲和性掩码设置为 mask 指定的值。
    如果 pid 指定的线程当前未在 mask 指定的 CPU 上运行，则该线程将迁移到 mask 指定的 CPU 上。
    如果 pid 为零，则使用调用线程。cpusetsize 参数是 mask 指向的数据的长度（以字节为单位）。

    EFAULT: 提供的内存地址无效。
    EINVAL：亲和位掩码 mask 不包含任何处理器，这些处理器当前物理存在于系统上，
            并且根据 cpuset cgroups 或 cpuset(7) 中描述的“cpuset”机制可能施加的任何限制，允许该线程使用。
    EINVAL: cpusetsize 小于内核使用的亲和位掩码的大小。
    EPERM: 调用线程没有适当的权限。
    ESRCH: 找不到 ID 为 pid 的线程。

    成功时，sched_setaffinity() 和 sched_getaffinity() 返回 0
*/
pub fn sys_sched_setaffinity(_pid: isize, _cpusetsize: usize, _mask: usize) -> SyscallRet {
    log::error!("Unimplemented syscall: sched_setaffinity");
    Ok(0)
}

/*
    sched_getaffinity() 将 ID 为 pid 的线程的亲和性掩码写入 mask 指向的 cpu_set_t 结构体中。
    cpusetsize 参数指定 mask 的大小（以字节为单位）。如果 pid 为零，则返回调用线程的掩码。

    EFAULT: 提供的内存地址无效。
    EINVAL：亲和位掩码 mask 不包含任何处理器，这些处理器当前物理存在于系统上，
            并且根据 cpuset cgroups 或 cpuset(7) 中描述的“cpuset”机制可能施加的任何限制，允许该线程使用。
    EINVAL: cpusetsize 小于内核使用的亲和位掩码的大小。
    ESRCH: 找不到 ID 为 pid 的线程。

    成功时，sched_setaffinity() 和 sched_getaffinity() 返回 0
*/
pub fn sys_sched_getaffinity(pid: isize, cpusetsize: usize, mask: usize) -> SyscallRet {
    log::info!("pid: {}, cpusetsize: {}, mask: {:#x}", pid, cpusetsize, mask);
    if cpusetsize < core::mem::size_of::<CpuMask>() {
        return Err(Errno::EINVAL)
    }
    
    if pid == 0 {
        let task = current_task();
        let cpu_mask = task.cpu_mask();
        log::error!("cpu_mask: {:#x}", cpu_mask.bits());
        copy_to_user(mask as *mut CpuMask, &cpu_mask, 1)?;
        return Ok(cpu_mask.bits());
    }  else {
        if let Some(task)  = get_task(pid as Tid) {
            let cpu_mask = task.cpu_mask();
            copy_to_user(mask as *mut CpuMask, &cpu_mask, 1)?;
        } else {
            log::error!("[sched_getaffinity] invalid pid: {}", pid);
            return Err(Errno::ESRCH);
        }
    }

    Ok(0)
}

pub fn sys_sched_setscheduler(_pid: isize, _policy: i32, _param: usize) -> SyscallRet {
    log::error!("Unimplemented syscall: sys_sched_setscheduler");
    Ok(0)
}


pub fn sys_sched_getscheduler(_pid: isize) -> SyscallRet {
    log::error!("Unimplemented syscall: sys_sched_getscheduler");
    Ok(0)
}

pub fn sys_sched_getparam(_pid:isize, _param: usize) -> SyscallRet {
    log::error!("Unimplemented syscall: sys_sched_getparam");
    Ok(0)
}
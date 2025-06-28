use alloc::sync::Arc;
use fdt::standard_nodes::Cpu;

use crate::{
    arch::mm::{copy_from_user, copy_to_user},
    futex::flags,
    task::{
        current_task, get_all_tasks, get_group, get_task, nice_to_priority, nice_to_rlimit,
        priority_to_nice, CpuMask, SchedAttr, Task, Tid, MAX_NICE, MAX_PRIO, MAX_RT_PRIO, MIN_NICE,
        MIN_RT_PRIO, PRIO_PGRP, PRIO_PROCESS, PRIO_USER, SCHED_BATCH, SCHED_DEADLINE, SCHED_EXT,
        SCHED_FIFO, SCHED_IDLE, SCHED_OTHER, SCHED_RR,
    },
    timer::TimeSpec,
};

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
pub fn sys_sched_setaffinity(mut pid: isize, cpusetsize: usize, mask: usize) -> SyscallRet {
    log::info!(
        "pid: {}, cpusetsize: {}, mask: {:#x}",
        pid,
        cpusetsize,
        mask
    );
    if pid == 0 {
        pid = current_task().tid() as isize; // 如果 pid 为 0，则使用当前线程
    }
    if let Some(task) = get_task(pid as Tid) {
        let mut cpu_mask = CpuMask::ALL;
        let cur_task = current_task();
        if cur_task.euid() != 0 {
            return Err(Errno::EPERM);
        } // 只有root用户可以设置其他线程的亲和性掩码
        copy_from_user(mask as *const CpuMask, &mut cpu_mask as *mut CpuMask, 1)?;
        if cur_task.cpu_mask().bits() & cpu_mask.bits() == 0 {
            log::error!(
                "[sched_setaffinity] invalid cpu mask: {:#x}",
                cpu_mask.bits()
            );
            return Err(Errno::EINVAL);
        }
        task.set_cpu_mask(cpu_mask)
    } else {
        log::error!("[sched_setaffinity] invalid pid: {}", pid);
        return Err(Errno::ESRCH);
    }
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
    log::info!(
        "pid: {}, cpusetsize: {}, mask: {:#x}",
        pid,
        cpusetsize,
        mask
    );
    if cpusetsize < core::mem::size_of::<CpuMask>() {
        return Err(Errno::EINVAL);
    }

    if pid == 0 {
        let task = current_task();
        let cpu_mask = task.cpu_mask();
        log::error!("cpu_mask: {:#x}", cpu_mask.bits());
        copy_to_user(mask as *mut CpuMask, &cpu_mask, 1)?;
        return Ok(cpu_mask.bits());
    } else {
        if let Some(task) = get_task(pid as Tid) {
            let cpu_mask = task.cpu_mask();
            copy_to_user(mask as *mut CpuMask, &cpu_mask, 1)?;
        } else {
            log::error!("[sched_getaffinity] invalid pid: {}", pid);
            return Err(Errno::ESRCH);
        }
    }

    Ok(0)
}

/// sched_setscheduler() 系统调用会为 pid 中指定的线程设置调度策略和参数。
/// 如果 pid 等于零，则会设置调用线程的调度策略和参数。
pub fn sys_sched_setscheduler(mut pid: isize, policy: u32, param: usize) -> SyscallRet {
    log::info!(
        "[sys_sched_setscheduler] pid: {}, policy: {}, param: {:#x}",
        pid,
        policy,
        param
    );
    if pid < 0 || param == 0 || policy > 6 {
        return Err(Errno::EINVAL);
    }
    if pid == 0 {
        pid = current_task().tid() as isize; // 如果 pid 为 0，则使用当前线程
    }
    if let Some(task) = get_task(pid as Tid) {
        let cur_task = current_task();
        if policy != SCHED_OTHER
            && policy != SCHED_BATCH
            && policy != SCHED_IDLE
            && cur_task.euid() != 0
        {
            return Err(Errno::EPERM);
        }
        let mut priority: i32 = 0;
        copy_from_user(param as *const i32, &mut priority as *mut i32, 1)?;
        log::error!("[sys_sched_setscheduler] priority: {}", priority);
        if policy != SCHED_FIFO && policy != SCHED_RR && priority != 0 {
            log::error!("[sched_setscheduler] invalid priority: {}", priority);
            return Err(Errno::EINVAL);
        }
        if policy == SCHED_FIFO || policy == SCHED_RR {
            if (priority as u32) < MIN_RT_PRIO || (priority as u32) > MAX_RT_PRIO {
                log::error!(
                    "[sched_setscheduler] invalid priority for policy {}: {}",
                    policy,
                    priority
                );
                return Err(Errno::EINVAL);
            }
            task.set_policy(policy as u32);
            task.set_priority(priority as u32);
        } else if policy == SCHED_OTHER
            || policy == SCHED_BATCH
            || policy == SCHED_IDLE
            || policy == SCHED_EXT
        {
            if priority != 0 {
                log::error!(
                    "[sched_setscheduler] invalid priority for policy {}: {}",
                    policy,
                    priority
                );
                return Err(Errno::EINVAL);
            }
            task.set_policy(policy as u32);
            task.set_priority(nice_to_priority(priority));
        } else if policy == SCHED_DEADLINE {
            // Todo：完善功能
            // 目前不支持DL
            log::error!("[sched_setscheduler] SCHED_DEADLINE is not supported yet");
            return Ok(0);
        } else {
            log::error!("[sched_setscheduler] invalid policy: {}", policy);
            return Err(Errno::EINVAL);
        }
    } else {
        log::error!("[sched_setscheduler] invalid pid: {}", pid);
        return Err(Errno::ESRCH);
    }
    Ok(0)
}

pub fn sys_sched_getscheduler(pid: isize) -> SyscallRet {
    log::info!("[sys_sched_getscheduler] pid: {}", pid);
    if pid < 0 {
        return Err(Errno::EINVAL);
    }
    if pid == 0 {
        return Ok(current_task().policy() as usize); // 如果 pid 为 0，则使用当前线程
    }
    if let Some(task) = get_task(pid as Tid) {
        Ok(task.policy() as usize)
    } else {
        log::error!("[sched_getscheduler] invalid pid: {}", pid);
        Err(Errno::ESRCH)
    }
}

/// sched_setattr() 系统调用为 pid 中指定的线程设置调度策略和相关属性。
/// 如果 pid 等于零，则将设置调用线程的调度策略和属性。
/// 提供 flags 参数是为了允许将来扩展接口；在当前实现中，必须将其指定为 0。
pub fn sys_sched_setattr(mut pid: isize, attr: usize, flags: u32) -> SyscallRet {
    log::info!(
        "[sys_sched_setattr] pid: {}, attr: {:#x}, flags: {}",
        pid,
        attr,
        flags
    );
    if pid < 0 || attr == 0 || flags != 0 {
        return Err(Errno::EINVAL);
    }
    if pid == 0 {
        pid = current_task().tid() as isize; // 如果 pid 为 0，则使用当前线程
    }
    if let Some(task) = get_task(pid as Tid) {
        let mut sched_attr = SchedAttr::default();
        copy_from_user(
            attr as *const SchedAttr,
            &mut sched_attr as *mut SchedAttr,
            1,
        )?;
        log::error!("[sys_sched_setattr] sched_attr: {:?}", sched_attr);
        match sched_attr.sched_policy {
            SCHED_FIFO | SCHED_RR => {
                if sched_attr.sched_priority < MIN_RT_PRIO
                    || sched_attr.sched_priority > MAX_RT_PRIO
                {
                    log::error!(
                        "[sched_setattr] invalid priority for policy {}: {}",
                        sched_attr.sched_policy,
                        sched_attr.sched_priority
                    );
                    return Err(Errno::EINVAL);
                }
                task.set_policy(sched_attr.sched_policy);
                task.set_priority(sched_attr.sched_priority as u32);
            }
            SCHED_OTHER | SCHED_BATCH | SCHED_IDLE | SCHED_EXT => {
                if sched_attr.sched_priority != 0 {
                    log::error!(
                        "[sched_setattr] invalid priority for policy {}: {}",
                        sched_attr.sched_policy,
                        sched_attr.sched_priority
                    );
                    return Err(Errno::EINVAL);
                }
                task.set_policy(sched_attr.sched_policy);
                task.set_priority(nice_to_priority(sched_attr.sched_nice as i32));
            }
            SCHED_DEADLINE => {
                // Todo：完善功能
                // 目前不支持DL
                log::error!("[sched_setattr] SCHED_DEADLINE is not supported yet");
                return Ok(0);
            }
            _ => {
                log::error!(
                    "[sched_setattr] invalid policy: {}",
                    sched_attr.sched_policy
                );
                return Err(Errno::EINVAL);
            }
        }
    } else {
        log::error!("[sched_setattr] invalid pid: {}", pid);
        return Err(Errno::ESRCH);
    }
    Ok(0)
}

/// sched_getattr() 系统调用会获取线程（其 ID 由 pid 指定）的调度策略及其相关属性。
/// 如果 pid 等于零，则会检索调用线程的调度策略和属性。
/// 提供 flags 参数是为了允许接口在未来进行扩展；在当前实现中，必须将其指定为 0。
pub fn sys_sched_getattr(mut pid: isize, attr: usize, size: u32, flags: u32) -> SyscallRet {
    log::info!(
        "[sys_sched_getattr] pid: {}, attr: {:#x}, size: {}, flags: {}",
        pid,
        attr,
        size,
        flags
    );
    if pid < 0 || attr == 0 || size < core::mem::size_of::<SchedAttr>() as u32 || flags != 0 {
        return Err(Errno::EINVAL);
    }
    if pid == 0 {
        pid = current_task().tid() as isize; // 如果 pid 为 0，则使用当前线程
    }
    if let Some(task) = get_task(pid as Tid) {
        let mut sched_attr = SchedAttr::default();
        sched_attr.size = core::mem::size_of::<SchedAttr>() as u32;
        match task.policy() {
            SCHED_FIFO | SCHED_RR => {
                sched_attr.sched_policy = task.policy();
                sched_attr.sched_priority = task.priority();
            }
            SCHED_OTHER | SCHED_BATCH | SCHED_IDLE | SCHED_EXT => {
                sched_attr.sched_policy = task.policy();
                sched_attr.sched_nice = priority_to_nice(task.priority()) as i32;
            }
            SCHED_DEADLINE => {
                // Todo：完善功能
                // 目前不支持DL
                log::error!("[sched_getattr] SCHED_DEADLINE is not supported yet");
            }
            _ => {
                log::error!("[sched_getattr] invalid policy: {}", task.policy());
                return Err(Errno::EINVAL);
            }
        }
        log::error!("[sys_sched_getattr] sched_attr: {:?}", sched_attr);
        copy_to_user(attr as *mut SchedAttr, &sched_attr, 1)?;
    } else {
        log::error!("[sched_getattr] invalid pid: {}", pid);
        return Err(Errno::ESRCH);
    }
    Ok(0)
}

/// sched_setparam() 设置与线程 ID（由 pid 指定）对应的调度策略相关的调度参数。
/// 如果 pid 为零，则设置调用线程的参数。
pub fn sys_sched_setparam(mut pid: isize, param: usize) -> SyscallRet {
    log::info!("[sys_sched_setparam] pid: {}, param: {:#x}", pid, param);
    if pid < 0 || param == 0 {
        return Err(Errno::EINVAL);
    }
    if pid == 0 {
        pid = current_task().tid() as isize; // 如果 pid 为 0，则使用当前线程
    }
    if let Some(task) = get_task(pid as Tid) {
        let cur_task = current_task();
        let mut priority: u32 = 0;
        copy_from_user(param as *const u32, &mut priority as *mut u32, 1)?;
        match task.policy() {
            SCHED_FIFO | SCHED_RR => {
                if priority < MIN_RT_PRIO || priority > MAX_RT_PRIO {
                    log::error!("[sched_setparam] invalid priority: {}", priority);
                    return Err(Errno::EINVAL);
                }
                if cur_task.euid() != 0 {
                    log::error!(
                        "[sched_setparam] permission denied for policy {}: {}",
                        task.policy(),
                        priority
                    );
                    return Err(Errno::EPERM);
                }
                task.set_priority(priority as u32);
            }
            SCHED_OTHER | SCHED_BATCH | SCHED_IDLE | SCHED_EXT => {
                if priority != 0 {
                    log::error!(
                        "[sched_setparam] invalid priority for policy {}: {}",
                        task.policy(),
                        priority
                    );
                    return Err(Errno::EINVAL);
                }
                if cur_task.euid() != 0 && (priority as i32) < priority_to_nice(task.priority()) {
                    log::error!(
                        "[sched_setparam] permission denied for policy {}: {}",
                        task.policy(),
                        priority
                    );
                    return Err(Errno::EPERM);
                }
                task.set_priority(nice_to_priority(priority as i32)); // 将优先级转换为nice值
            }
            _ => {
                log::error!("[sched_setparam] invalid policy: {}", task.policy());
                return Err(Errno::EINVAL);
            }
        }
    } else {
        log::error!("[sched_setparam] invalid pid: {}", pid);
        return Err(Errno::ESRCH);
    }
    Ok(0)
}

pub fn sys_sched_getparam(mut pid: isize, param: usize) -> SyscallRet {
    log::info!("[sys_sched_getparam] pid: {}, param: {:#x}", pid, param);
    if pid < 0 || param == 0 {
        return Err(Errno::EINVAL);
    }
    if pid == 0 {
        pid = current_task().tid() as isize; // 如果 pid 为 0，则使用当前线程
    }
    if let Some(task) = get_task(pid as Tid) {
        match task.policy() {
            SCHED_FIFO | SCHED_RR => {
                let priority = task.priority();
                log::error!("[sys_sched_getparam] priority: {}", priority);
                copy_to_user(param as *mut u32, &priority, 1)?;
            }
            SCHED_OTHER | SCHED_BATCH | SCHED_IDLE | SCHED_EXT => {
                let nice = priority_to_nice(task.priority()) as i32;
                log::error!("[sys_sched_getparam] nice: {}", nice);
                copy_to_user(param as *mut i32, &nice, 1)?;
            }
            _ => {
                log::error!("[sched_getparam] invalid policy: {}", task.policy());
                return Err(Errno::EINVAL);
            }
        }
    } else {
        log::error!("[sched_getparam] invalid pid: {}", pid);
        return Err(Errno::ESRCH);
    }
    Ok(0)
}

/// sched_get_priority_max() 返回策略指定的调度算法可以使用的最大优先级值。
/// Linux 允许 SCHED_FIFO 和 SCHED_RR 策略使用 1 到 99 的静态优先级范围，其余策略的优先级为 0
pub fn sys_sched_get_priority_max(policy: i32) -> SyscallRet {
    log::info!("[sys_sched_get_priority_max] policy: {}", policy);
    match policy as u32 {
        // SCHED_FIFO, SCHED_RR, SCHED_OTHER
        SCHED_FIFO | SCHED_RR => Ok(MAX_RT_PRIO as usize),
        SCHED_BATCH | SCHED_EXT | SCHED_IDLE | SCHED_OTHER | SCHED_DEADLINE => Ok(0),
        _ => {
            log::error!("[sys_sched_get_priority_max] invalid policy: {}", policy);
            Err(Errno::EINVAL)
        }
    }
}

/// sched_get_priority_min() 返回策略指定的调度算法可以使用的最小优先级值。
/// Linux 允许 SCHED_FIFO 和 SCHED_RR 策略使用 1 到 99 的静态优先级范围，其余策略的优先级为 0
pub fn sys_sched_get_priority_min(policy: i32) -> SyscallRet {
    log::info!("[sys_sched_get_priority_max] policy: {}", policy);
    match policy as u32 {
        // SCHED_FIFO, SCHED_RR, SCHED_OTHER
        SCHED_FIFO | SCHED_RR => Ok(MIN_RT_PRIO as usize),
        SCHED_BATCH | SCHED_EXT | SCHED_IDLE | SCHED_OTHER => Ok(0),
        _ => {
            log::error!("[sys_sched_get_priority_max] invalid policy: {}", policy);
            Err(Errno::EINVAL)
        }
    }
}

/// setpriority() 调用将所有指定进程的优先级设置为指定值。
pub fn sys_setpriority(which: i32, mut who: i32, mut prio: i32) -> SyscallRet {
    fn check_permission(task: &Arc<Task>) -> SyscallRet {
        let cur_task = current_task();
        if cur_task.euid() == task.uid() || cur_task.euid() == task.euid() || cur_task.euid() == 0 {
            return Ok(0);
        }
        Err(Errno::EPERM)
    }

    // Todo: rlimit
    fn set_one_prio(task: &Arc<Task>, prio: u32) -> SyscallRet {
        check_permission(task)?;
        if prio < task.priority() && !(task.euid() == 0) {
            return Err(Errno::EACCES);
        }
        task.set_priority(prio);
        Ok(0)
    }

    log::info!(
        "[sys_setpriority] which: {}, who: {}, prio: {}",
        which,
        who,
        prio
    );

    match prio {
        ..MIN_NICE => {
            prio = MIN_NICE as i32; // 最小优先级
        }
        MAX_NICE.. => {
            prio = MAX_NICE as i32; // 最大优先级
        }
        _ => {}
    }
    let priority = nice_to_priority(prio as i32);

    match which {
        PRIO_PROCESS => {
            // 设置单个进程/线程的优先级
            if who == 0 {
                set_one_prio(&current_task(), priority)?;
            } else if let Some(target_task) = get_task(who as usize) {
                set_one_prio(&target_task, priority)?;
            } else {
                log::error!("[sys_setpriority] no such process: {}", who);
                return Err(Errno::ESRCH);
            }
        }
        PRIO_PGRP => {
            if who == 0 {
                who = current_task().pgid() as i32; // 如果 who 为 0，则设置为当前进程组
            }
            if let Some(target_process_group) = get_group(who as usize) {
                for task in target_process_group.iter() {
                    let task = task.upgrade().unwrap();
                    set_one_prio(&task, priority)?;
                }
            } else {
                log::error!("[sys_setpriority] no such process group: {}", who);
                return Err(Errno::ESRCH);
            }
        }
        PRIO_USER => {
            let mut has_task = false;
            for task in get_all_tasks().iter() {
                if task.euid() == who as u32 || task.uid() == who as u32 {
                    has_task = true;
                    set_one_prio(&task, priority)?;
                }
            }
            if !has_task {
                log::error!("[sys_getpriority] no such user: {}", who);
                return Err(Errno::ESRCH);
            }
        }
        _ => {
            log::error!("[sys_setpriority] invalid which: {}", which);
            return Err(Errno::EINVAL);
        }
    }
    Ok(0)
}

/// getpriority() 调用返回所有指定进程享有的最高优先级（最低的数值）
/// 注：linux中以rlimit的方式返回，即返回值[1-40]
pub fn sys_getpriority(which: i32, mut who: i32) -> SyscallRet {
    log::info!("[sys_getpriority] which: {}, who: {}", which, who);
    let mut min_priority: u32 = MAX_PRIO; // 返回的最小优先级
    match which {
        PRIO_PROCESS => {
            if who == 0 {
                min_priority = current_task().priority();
            } else if let Some(target_task) = get_task(who as usize) {
                min_priority = target_task.priority();
            } else {
                log::error!("[sys_getpriority] no such process: {}", who);
                return Err(Errno::ESRCH);
            }
        }
        PRIO_PGRP => {
            if who == 0 {
                who = current_task().pgid() as i32; // 如果 who 为 0，则设置为当前进程组
            }
            if let Some(target_process_group) = get_group(who as usize) {
                for task in target_process_group.iter() {
                    let task = task.upgrade().unwrap();
                    let task_priority = task.priority();
                    if task_priority < min_priority {
                        min_priority = task_priority;
                    }
                }
            } else {
                log::error!("[sys_getpriority] no such process group: {}", who);
                return Err(Errno::ESRCH);
            }
        }
        PRIO_USER => {
            let mut has_task = false;
            for task in get_all_tasks().iter() {
                if task.euid() == who as u32 {
                    has_task = true;
                    let task_priority = task.priority();
                    if task_priority < min_priority {
                        min_priority = task_priority;
                    }
                }
            }
            if !has_task {
                log::error!("[sys_getpriority] no such user: {}", who);
                return Err(Errno::ESRCH);
            }
        }
        _ => {
            log::error!("[sys_getpriority] invalid which: {}", which);
            return Err(Errno::EINVAL);
        }
    }
    let min_nice = priority_to_nice(min_priority);
    let ret = nice_to_rlimit(min_nice);
    Ok(ret as usize)
}

pub fn sys_sched_rr_get_interval(mut pid: isize, interval: usize) -> SyscallRet {
    log::info!(
        "[sched_rr_get_interval] pid: {}, interval: {:#x}",
        pid,
        interval
    );
    if pid < 0 || interval == 0 {
        return Err(Errno::EINVAL);
    }
    if pid == 0 {
        pid = current_task().tid() as isize; // 如果 pid 为 0，则使用当前线程
    }
    if let Some(task) = get_task(pid as Tid) {
        if task.policy() != SCHED_RR {
            let interval_val = TimeSpec {
                sec: 0,
                nsec: 0, // 默认时间间隔为100ms
            };
            copy_to_user(interval as *mut TimeSpec, &interval_val, 1)?;
        } else {
            let interval_val = TimeSpec {
                sec: 0,
                nsec: 100000000, // 默认时间间隔为100ms
            };
            copy_to_user(interval as *mut TimeSpec, &interval_val, 1)?;
        }
    } else {
        log::error!("[sched_rr_get_interval] invalid pid: {}", pid);
        return Err(Errno::ESRCH);
    }
    Ok(0)
}

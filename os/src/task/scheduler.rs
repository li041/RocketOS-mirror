use super::{current_task, Task, Tid};
#[cfg(not(feature = "cfs"))]
use crate::sched::FIFOScheduler as Scheduler;
#[cfg(feature = "cfs")]
use crate::sched::{fetch_rt_task, remove_rt_task, CFSScheduler as Scheduler};
use crate::{
    arch::{config::MAX_HARTS, switch},
    sched::get_idle_scheduler,
    task::{
        self, dump_wait_queue, get_task, handle_timeout,
        manager::dump_time_manager,
        processor::{current_hart_id, current_tp, preempte, Processor, PROCESSOR},
        task::compare_task_priority,
    },
    timer::TimeVal,
};

use alloc::{
    boxed::Box,
    collections::{btree_map::BTreeMap, vec_deque::VecDeque},
    sync::Arc,
    vec::{self, Vec},
};
use bitflags::bitflags;
use core::{
    cell::SyncUnsafeCell,
    fmt::Debug,
    mem::MaybeUninit,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use hashbrown::HashMap;
use lazy_static::lazy_static;

pub const PRIO_PROCESS: i32 = 0; // 进程优先级
pub const PRIO_PGRP: i32 = 1; // 进程组
pub const PRIO_USER: i32 = 2; // 用户优先级

pub const DEFAULT_PRIO: u32 = 120; // 默认优先级
pub const MAX_PRIO: u32 = 139; // 最大优先级
pub const MAX_RT_PRIO: u32 = 99; // 最大实时优先级
pub const MIN_RT_PRIO: u32 = 1; // 最小实时优先级
pub const MAX_NICE: i32 = 19; // 最大nice值
pub const MIN_NICE: i32 = -20; // 最小nice值

pub const SCHED_OTHER: u32 = 0; // 普通调度策略
pub const SCHED_FIFO: u32 = 1; // FIFO调度策略
pub const SCHED_RR: u32 = 2; // RR调度策略
pub const SCHED_BATCH: u32 = 3; // 批处理调度策略
pub const SCHED_IDLE: u32 = 5; // 空闲调度策略
pub const SCHED_DEADLINE: u32 = 6; // 截止时间调度策略
pub const SCHED_EXT: u32 = 7; // 扩展调度策略

static NEXT_CPU: AtomicUsize = AtomicUsize::new(0);

// 初始化调度器
lazy_static! {
    static ref SCHEDULER: Vec<SyncUnsafeCell<Scheduler>> = (0..MAX_HARTS)
        .map(|_| SyncUnsafeCell::new(Scheduler::new()))
        .collect();
}

/// 添加新任务到就绪队列
pub fn add_task(next_task: Arc<Task>) {
    debug_assert!(next_task.is_ready());
    let hart_id = next_task.cpu_id();
    // 如果是实时任务, 则添加到实时调度器
    #[cfg(feature = "cfs")]
    if next_task.is_rt() {
        use crate::sched::add_rt_task;
        add_rt_task(next_task, hart_id);
        return;
    }
    // 添加普通任务
    let scheduler = unsafe { &mut *SCHEDULER[hart_id].get() };
    scheduler.add(next_task);
}

/// 非抢占式添加任务(用于初始化)
pub fn add_task_init(next_task: Arc<Task>) {
    debug_assert!(next_task.is_ready());
    let hart_id = next_task.cpu_id();
    let scheduler = unsafe { &mut *SCHEDULER[hart_id].get() };
    scheduler.add(next_task);
}

/// 从就绪队列中取出最高优先级任务
pub fn fetch_task() -> Option<Arc<Task>> {
    let hart_id = current_hart_id();
    let scheduler = unsafe { &mut *SCHEDULER[hart_id].get() };
    // 优先取出实时任务
    #[cfg(feature = "cfs")]
    {
        if let Some(task) = fetch_rt_task(hart_id) {
            return Some(task);
        }
        if let Some(se) = scheduler.fetch() {
            return get_task(se.tid);
        } else {
            return None;
        }
    }
    #[cfg(not(feature = "cfs"))]
    scheduler.fetch()
    // check_and_promote_task_priority();
}

/// 从就绪队列中取出空闲任务
// pub fn fetch_idle_task() -> Option<Arc<Task>> {
//     let hart_id = current_hart_id();
//     let scheduler = unsafe { &mut *SCHEDULER[hart_id].get() };
//     scheduler.fetch_idle_task()
// }

/// 初始化获取任务的任务
pub fn init_fetch_task(hart_id: usize) -> Option<Arc<Task>> {
    let scheduler = unsafe { &mut *SCHEDULER[hart_id].get() };
    #[cfg(feature = "cfs")]
    if let Some(se) = scheduler.fetch() {
        return get_task(se.tid);
    } else {
        get_idle_scheduler(hart_id)
    }
    #[cfg(not(feature = "cfs"))]
    scheduler.fetch().or_else(|| get_idle_scheduler(hart_id))
}

/// 从就绪队列中移除任务
pub fn remove_task(tid: Tid) {
    // SCHEDULER.lock().remove(tid);
    let hart_id = current_hart_id();
    #[cfg(feature = "cfs")]
    remove_rt_task(tid, hart_id);
    let scheduler = unsafe { &mut *SCHEDULER[hart_id].get() };
    scheduler.remove(tid);
}

// /// 查看调度器中任务数量
// pub fn get_scheduler_len() -> usize {
//     // SCHEDULER.lock().len()
//     let hart_id = current_hart_id();
//     let scheduler = unsafe { &*SCHEDULER[hart_id].get() };
//     scheduler.len()
// }

/// 打印调度器中任务信息
pub fn dump_scheduler() {
    for i in 0..MAX_HARTS {
        println!(
            "**************************** dump scheduler {} ****************************",
            i
        );
        let scheduler = unsafe { &mut *SCHEDULER[i].get() };
        scheduler.dump();
        println!("current task: {:?}", PROCESSOR[i].read().current_task());
        println!(
            "**************************** dump scheduler {} ****************************",
            i
        );
    }
    dump_wait_queue();
}

/// 选择下一个任务要执行的目标cpu
pub fn select_cpu() -> usize {
    let next = NEXT_CPU.fetch_add(1, Ordering::Relaxed) % MAX_HARTS;
    next
}

pub fn selecter_init(hart_id: usize) {
    NEXT_CPU.store(hart_id % MAX_HARTS, Ordering::Relaxed);
}

/// 空闲任务, 用于没有就绪任务时的占位
// pub fn idle_task() -> ! {
//     loop {
//         core::hint::spin_loop();
//     }
// }

// 由caller保证原任务的状态切换
// 注：schedule将不会将当前任务放回调度器中
#[no_mangle]
pub fn schedule() {
    // 1. 切换内核栈
    // 2. 切换Processor的current
    // 3. 切换tp(在__switch中完成)
    // 4. 切换memory set(在__switch中完成)

    // 获得下一个任务的内核栈
    // 可以保证`Ready`的任务`Task`中的内核栈与实际运行的sp保持一致
    // log::error!("[schedule] scheduler len: {}", get_scheduler_len());
    log::trace!("[schedule]");
    let hart_id = current_task().cpu_id();
    if let Some(next_task) = fetch_task() {
        // 取出任务即认为不再等待并恢复其原始优先级
        // next_task.time_stat().wait_time_clear();
        // next_task.restore_sched_prio();
        let next_task_kernel_stack = next_task.kstack();
        {
            log::debug!(
            "**********************************  task {} end **********************************",
            current_task().tid()
        );
            log::debug!(
            "**********************************  task {} start **********************************",
            next_task.tid()
        );
            // check_task_context_in_kernel_stack(next_task_kernel_stack);
            // 切换Processor的current
            crate::task::processor::PROCESSOR[hart_id]
                .write()
                .switch_to(next_task);
        }
        unsafe {
            switch::__switch(next_task_kernel_stack);
        }
    } else {
        // 如果没有下一个任务, 则busyloop等待计时器超时
        loop {
            log::trace!("[schedule] no next task, waiting for timeout");
            if let Some(next_task) = fetch_task() {
                // next_task.time_stat().wait_time_clear();
                // next_task.restore_sched_prio();
                let next_task_kernel_stack = next_task.kstack();
                {
                    log::debug!(
            "**********************************  task {} end **********************************",
            current_task().tid());
                    log::debug!(
            "**********************************  task {} start **********************************",
            next_task.tid());
                    // check_task_context_in_kernel_stack(next_task_kernel_stack);
                    // 切换Processor的current
                    crate::task::processor::PROCESSOR[hart_id]
                        .write()
                        .switch_to(next_task);
                }
                unsafe {
                    switch::__switch(next_task_kernel_stack);
                }
                break;
            }
            if !handle_timeout().is_empty() {
                // 计时器超时
                if let Some(next_task) = fetch_task() {
                    // next_task.time_stat().wait_time_clear();
                    // next_task.restore_sched_prio();
                    let next_task_kernel_stack = next_task.kstack();
                    {
                        log::debug!(
                            "**********************************  task {} end **********************************",
                            current_task().tid()
                        );
                        log::debug!(
                            "**********************************  task {} start **********************************",
                            next_task.tid()
                        );
                        if current_task().tid() == next_task.tid() {
                            // 不能从自己切换到自己
                            break;
                        }
                        // check_task_context_in_kernel_stack(next_task_kernel_stack);
                        // 切换Processor的current
                        crate::task::processor::PROCESSOR[hart_id]
                            .write()
                            .switch_to(next_task);
                    }
                    unsafe {
                        switch::__switch(next_task_kernel_stack);
                    }
                    break;
                } else {
                    // 计时器超时, 但是没有就绪任务, 继续执行当前任务
                    break;
                }
            }
        }
    }
}

// 不能从自己切换到自己
// 注意调用者要释放原任务的锁, 否则会死锁
#[no_mangle]
#[cfg(not(feature = "cfs"))]
pub fn yield_current_task() {
    // 注意下面这行日志不要删, 是loongarch64 release跑起来的神奇小咒语
    log::trace!("[yield_current_task] enter");
    let task = current_task();
    let hart_id = task.cpu_id();
    if let Some(next_task) = fetch_task() {
        let should_preempt = compare_task_priority(&task, &next_task);
        // 当前任务优先级小于等于下一个任务
        if !should_preempt {
            // next_task.time_stat().wait_time_clear();
            // next_task.restore_sched_prio();
            task.set_ready();
            // 将当前任务加入就绪队列
            add_task(task);
            log::debug!(
                "**********************************  task {} end **********************************",
                current_task().tid()
            );
            log::debug!(
                "**********************************  task {} start **********************************",
                next_task.tid()
            );
            // 获得下一个任务的内核栈
            // 可以保证`Ready`的任务`Task`中的内核栈与实际运行的sp保持一致
            let next_task_kernel_stack = next_task.kstack();
            // check_task_context_in_kernel_stack(next_task_kernel_stack);
            // 切换Processor的current
            crate::task::processor::PROCESSOR[hart_id]
                .write()
                .switch_to(next_task);
            unsafe {
                switch::__switch(next_task_kernel_stack);
            }
        } else {
            add_task(next_task);
        }
    } else {
        // 5.3 如果没有下一个任务, 先检查计时器超时
        if !handle_timeout().is_empty() {
            // 超时任务已唤醒
            if let Some(next_task) = fetch_task() {
                let should_preempt = compare_task_priority(&task, &next_task);
                if !should_preempt {
                    let next_task_kernel_stack = next_task.kstack();
                    // next_task.time_stat().wait_time_clear();
                    // next_task.restore_sched_prio();
                    task.set_ready();
                    // 将当前任务加入就绪队列
                    add_task(task);
                    log::debug!(
                        "**********************************  task {} end **********************************",
                        current_task().tid()
                    );
                    log::debug!(
                        "**********************************  task {} start **********************************",
                        next_task.tid()
                    );
                    if current_task().tid() == next_task.tid() {
                        // 不能从自己切换到自己
                        return;
                    }
                    // check_task_context_in_kernel_stack(next_task_kernel_stack);
                    // 切换Processor的current
                    crate::task::processor::PROCESSOR[hart_id]
                        .write()
                        .switch_to(next_task);
                    unsafe {
                        switch::__switch(next_task_kernel_stack);
                    }
                } else {
                    add_task(next_task);
                }
            }
        }
    }
    // 如果没有下一个任务, 则继续执行当前任务
}

#[no_mangle]
#[cfg(feature = "cfs")]
pub fn yield_current_task() {
    // 注意下面这行日志不要删, 是loongarch64 release跑起来的神奇小咒语
    log::trace!("[yield_current_task] enter");
    let task = current_task();
    let hart_id = task.cpu_id();
    if let Some(next_task) = fetch_task() {
        // next_task.time_stat().wait_time_clear();
        // next_task.restore_sched_prio();
        task.set_ready();
        add_task(task);
        log::debug!(
            "**********************************  task {} end **********************************",
            current_task().tid()
        );
        log::debug!(
            "**********************************  task {} start **********************************",
            next_task.tid()
        );
        // 获得下一个任务的内核栈
        // 可以保证`Ready`的任务`Task`中的内核栈与实际运行的sp保持一致
        let next_task_kernel_stack = next_task.kstack();
        // check_task_context_in_kernel_stack(next_task_kernel_stack);
        // 切换Processor的current
        crate::task::processor::PROCESSOR[hart_id]
            .write()
            .switch_to(next_task);
        unsafe {
            switch::__switch(next_task_kernel_stack);
        }
    } else {
        // 5.3 如果没有下一个任务, 先检查计时器超时
        if !handle_timeout().is_empty() {
            // 超时任务已唤醒
            if let Some(next_task) = fetch_task() {
                let next_task_kernel_stack = next_task.kstack();
                // next_task.time_stat().wait_time_clear();
                // next_task.restore_sched_prio();
                task.set_ready();
                add_task(task);
                log::debug!(
                    "**********************************  task {} end **********************************",
                    current_task().tid()
                );
                log::debug!(
                    "**********************************  task {} start **********************************",
                    next_task.tid()
                );
                if current_task().tid() == next_task.tid() {
                    // 不能从自己切换到自己
                    return;
                }
                // check_task_context_in_kernel_stack(next_task_kernel_stack);
                // 切换Processor的current
                crate::task::processor::PROCESSOR[hart_id]
                    .write()
                    .switch_to(next_task);
                unsafe {
                    switch::__switch(next_task_kernel_stack);
                }
            }
        }
    }
    // 如果没有下一个任务, 则继续执行当前任务
}

// 支持任务取出时不切换任务
// 只用在了check_slice
#[cfg(feature = "cfs")]
pub fn change_task() {
    let task = current_task();
    let hart_id = task.cpu_id();
    if let Some(next_task) = fetch_task() {
        log::warn!("next_task vruntime: {}, current vruntime: {}", next_task.sched_entity().vruntime(), task.sched_entity().vruntime());
        if next_task.sched_entity().vruntime() > task.sched_entity().vruntime() {
            add_task(next_task);
            return;
        }
        task.set_ready();
        add_task(task);
        log::debug!(
            "**********************************  task {} end **********************************",
            current_task().tid()
        );
        log::debug!(
            "**********************************  task {} start **********************************",
            next_task.tid()
        );
        // 获得下一个任务的内核栈
        // 可以保证`Ready`的任务`Task`中的内核栈与实际运行的sp保持一致
        let next_task_kernel_stack = next_task.kstack();
        // check_task_context_in_kernel_stack(next_task_kernel_stack);
        // 切换Processor的current
        crate::task::processor::PROCESSOR[hart_id]
            .write()
            .switch_to(next_task);
        unsafe {
            switch::__switch(next_task_kernel_stack);
        }
    }
}

// priority：[0-139], DEFAULT_PRIO = 120
pub fn priority_to_nice(priority: u32) -> i32 {
    (priority - DEFAULT_PRIO) as i32
}

pub fn nice_to_priority(nice: i32) -> u32 {
    (nice + DEFAULT_PRIO as i32) as u32
}

// nice值范围[-20, 19], 对应的rlimit范围[1, 40]
// nice值越小, 优先级越高
// nice值为-20时, rlimit为1; nice值为19时, rlimit为40
pub fn nice_to_rlimit(nice: i32) -> u32 {
    (20 - nice) as u32
}

pub fn rlimit_to_nice(rlimit: u32) -> i32 {
    (20 - rlimit) as i32
}

// /// 检查低优先级任务的等待时间决定是否提升其优先级
// fn check_and_promote_task_priority() {
//     const UPDATE_TASK_COUNT: usize = 3;
//     const WAIT_THRESHOLD_TICKS: usize = 3;

//     let mut task_vec: Vec<Arc<Task>> = Vec::new();
//     let mut task_count = 0;
//     let hart_id = current_hart_id();
//     let scheduler = unsafe { &mut *SCHEDULER[hart_id].get() };
//     while task_count < UPDATE_TASK_COUNT {
//         let lowest_priority_task = scheduler.fetch_lowest_priority();
//         // 在最低优先级队列中选取最多UPDATE_TASK_COUNT个任务来验证等待时间
//         if let Some(task) = lowest_priority_task {
//             task_count += 1;
//             task.time_stat().record_wait_end();
//             // 若等待时间超过阈值, 则提升优先级
//             // 此处采用ticks当作阈值，1ticks为10ms
//             if task.time_stat().wait_time().timespec_to_ticks() > WAIT_THRESHOLD_TICKS {
//                 log::error!(
//                     "task{} raise priority from {}",
//                     task.tid(),
//                     task.sched_prio()
//                 );
//                 task.raise_sched_prio();
//             }
//             task_vec.push(task);
//         } else {
//             break;
//         }
//     }
//     for task in task_vec {
//         // 将任务重新加入调度器
//         scheduler.add(task);
//     }
// }

#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct SchedAttr {
    pub size: u32,           /* Size of this structure */
    pub sched_policy: u32,   /* Policy (SCHED_*) */
    pub sched_flags: u64,    /* Flags */
    pub sched_nice: i32,     /* Nice value */
    pub sched_priority: u32, /* Static priority (SCHED_FIFO,SCHED_RR) */

    /* For SCHED_DEADLINE */
    pub sched_runtime: u64,  /* Runtime in nanoseconds */
    pub sched_deadline: u64, /* Deadline in nanoseconds */
    pub sched_period: u64,   /* Period in nanoseconds */

                             /* Utilization hints */
                             // pub shed_util_min: u32,     /* Minimum utilization */
                             // pub sched_util_max: u32,    /* Maximum utilization */
}

bitflags! {
    pub struct WaitOption: i32 {
        /// 这个选项用于非阻塞挂起。当与 wait 或 waitpid 一起使用时，如果没有任何子进程状态改变，
        /// 这些系统调用不会阻塞父进程，而是立即返回。在 Linux 中，如果没有子进程处于可等待的状态，wait 或 waitpid 会返回 0。
        const WNOHANG = 1;
        /// 这个选项告诉 wait 或 waitpid 也报告那些已经停止（stopped），但尚未终止的子进程的状态。默认情况下，
        /// 只有当子进程终止时，它们的结束状态才会被报告。如果子进程被某种信号（如 SIGSTOP 或 SIGTSTP）停止，
        /// 并且父进程没有设置 WUNTRACED 选项，那么父进程将不会感知到子进程的停止状态，直到子进程被继续执行或终止。
        const WSTOPPED = 1 << 1;
        const WUNTRACED = 1 << 1;
        /// 这个选项用于等待子进程的终止状态。它会使 wait 或 waitpid 阻塞，直到至少一个子进程终止。
        const WEXITED = 1 << 2; 
        /// 当子进程被停止后又继续执行时，使用这个选项。如果子进程之前被一个停止信号（如SIGSTOP 或 SIGTSTP）暂停，
        /// 然后通过继续信号（如 SIGCONT）被继续执行，那么 wait 或 waitpid 将报告这个子进程的状态，
        /// 即使它还没有终止。这允许父进程知道子进程已经从停止状态恢复。
        const WCONTINUED = 1 << 3;

    }
}
impl Debug for WaitOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        write!(f, "WaitOption {{")?;
        if self.contains(WaitOption::WNOHANG) {
            if first {
                write!(f, "WNOHANG")?;
                first = false;
            } else {
                write!(f, " | WNOHANG")?;
            }
        }
        if self.contains(WaitOption::WUNTRACED) {
            if first {
                write!(f, "WUNTRACED")?;
                first = false;
            } else {
                write!(f, " | WUNTRACED")?;
            }
        }
        if self.contains(WaitOption::WCONTINUED) {
            if first {
                write!(f, "WCONTINUED")?;
            } else {
                write!(f, " | WCONTINUED")?;
            }
        }
        write!(f, "}}")
    }
}

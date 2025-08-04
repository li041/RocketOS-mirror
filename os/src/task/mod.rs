pub mod aux;
mod context;
mod id;
mod kstack;
mod manager;
mod processor;
pub mod rusage;
mod scheduler;
mod signal;
mod task;
mod timer;
mod wait;

#[cfg(target_arch = "riscv64")]
use crate::arch::hart;
use crate::{
    arch::trap::TrapContext,
    drivers::BLOCK_DEVICE,
    fs::{
        fdtable::FdTable, file::FileOp, mount::do_ext4_mount, namei::path_openat, path::Path,
        AT_FDCWD,
    },
    loader::get_app_data_by_name,
    mutex::SpinNoIrqLock,
    utils::{c_str_to_string, extract_cstrings},
};
use alloc::sync::Arc;
use alloc::{string::String, vec};

use core::arch::asm;
use lazy_static::lazy_static;

pub use context::TaskContext;
pub use id::{info_allocator, IdAllocator};
pub use kstack::{get_stack_top_by_sp, KSTACK_SIZE};
pub use manager::{
    add_common_timer, add_group, add_posix_timer, dump_wait_queue, for_each_task, get_all_tasks,
    get_group, get_task, handle_timeout, new_group, remove_timer, unregister_task,
    update_common_timer, update_posix_timer, wait, wait_timeout, wakeup, ITIMER_PROF, ITIMER_REAL,
    ITIMER_VIRTUAL,
};
pub use processor::{current_task, run_tasks, other_run_tasks};
pub use scheduler::{
    add_task, dump_scheduler, nice_to_priority, nice_to_rlimit, priority_to_nice,
    remove_task, schedule, yield_current_task, SchedAttr, WaitOption, MAX_NICE, MAX_PRIO,
    MAX_RT_PRIO, MIN_NICE, MIN_RT_PRIO, PRIO_PGRP, PRIO_PROCESS, PRIO_USER, SCHED_BATCH,
    SCHED_DEADLINE, SCHED_EXT, SCHED_FIFO, SCHED_IDLE, SCHED_OTHER, SCHED_RR,
};
#[cfg(feature = "cfs")]
pub use scheduler::{change_task};
pub use task::kernel_exit;
pub use task::CloneFlags;
pub use task::{CpuMask, Task, TaskStatus, INIT_PROC_PID};
pub use timer::{
    ClockId, PosixTimer, Sigevent, TimerFd, MAX_POSIX_TIMER_COUNT, SIGEV_COUNT, SIGEV_NONE,
    SIGEV_SIGNAL, SIGEV_THREAD, SIGEV_THREAD_ID, TFD_CLOEXEC, TFD_NONBLOCK,
};

pub type Tid = usize;

lazy_static! {
    /// 初始进程
    pub static ref INITPROC: Arc<Task> = Task::initproc(get_app_data_by_name("initproc").unwrap(), do_ext4_mount(BLOCK_DEVICE.clone()));
}

#[cfg(target_arch = "riscv64")]
pub fn boot_initproc(hart_id: usize) {
    // 暂时使tp指向hart_id
    // 用于途中的current_task，所以需要模拟task结构体来减少一个kstack大小
    let address = &hart_id as *const usize;
    let hart_id_ptr = address as usize - core::mem::size_of::<usize>();
    unsafe {
        asm!("mv tp, {}", in(reg) hart_id_ptr);
    }
    let initproc_tp = Arc::as_ptr(&INITPROC) as usize;
    unsafe {
        asm!("mv tp, {}", in(reg) initproc_tp);
    }
    // Task::init_idle_task(hart_id);
    // scheduler::selecter_init(hart_id);
}

#[cfg(target_arch = "riscv64")]
pub fn other_initproc(hart_id: usize) {
    let idle_task = Task::init_idle_task(hart_id);
    let initproc_tp = Arc::as_ptr(&idle_task) as usize;
    unsafe {
        asm!("mv tp, {}", in(reg) initproc_tp);
    }
}

#[cfg(target_arch = "loongarch64")]
// 设置tp寄存器指向INITPROC
pub fn add_initproc(hart_id: usize) {
    let address = &hart_id as *const usize;
    let hart_id_ptr = address as usize - core::mem::size_of::<usize>();
    unsafe {
        asm!("addi.d $r2, {}, 0", in(reg) hart_id_ptr);
    }
    let initproc_tp = Arc::as_ptr(&INITPROC) as usize;
    log::error!("initproc_tp: {:#x}", initproc_tp);
    unsafe {
        asm!("addi.d $r2, {}, 0", in(reg) initproc_tp);
    }
}

#[cfg(target_arch = "loongarch64")]
pub fn other_initproc(hart_id: usize) {
    let idle_task = Task::init_idle_task(hart_id);
    let initproc_tp = Arc::as_ptr(&idle_task) as usize;
    unsafe {
        asm!("addi.d $r2, {}, 0", in(reg) initproc_tp);
    }
}

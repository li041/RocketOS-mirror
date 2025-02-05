pub mod aux;
mod context;
mod id;
mod kstack;
mod processor;
mod scheduler;
mod switch;
mod task;

use crate::{
    drivers::BLOCK_DEVICE,
    fs::{
        fdtable::FdTable, file::FileOp, mount::do_ext4_mount, namei::path_openat, path::Path,
        AT_FDCWD,
    },
    loader::get_app_data_by_name,
    mutex::SpinNoIrqLock,
    sbi::shutdown,
    timer::get_time_ms,
    trap::TrapContext,
    utils::{c_str_to_string, extract_cstrings},
};
use alloc::sync::Arc;
use alloc::{string::String, vec};

use core::arch::asm;
use lazy_static::lazy_static;
use task::{Task, TaskStatus};

pub use context::TaskContext;
pub use task::kernel_exit;
pub use processor::{current_task, run_tasks};
pub use scheduler::{add_task, yield_current_task, switch_to_next_task, WaitOption, remove_task};

pub type Tid = usize;

lazy_static! {
    /// 初始进程
    pub static ref INITPROC: Arc<Task> = Task::initproc(get_app_data_by_name("initproc").unwrap(), do_ext4_mount(BLOCK_DEVICE.clone()));
}

pub fn add_initproc() {
    // 设置tp寄存器指向INITPROC
    let initproc_tp = Arc::as_ptr(&INITPROC) as usize;
    unsafe {
        asm!("mv tp, {}", in(reg) initproc_tp);
    }
}

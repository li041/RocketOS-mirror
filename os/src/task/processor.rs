use alloc::sync::Arc;
use core::arch::asm;
use lazy_static::lazy_static;
use spin::RwLock;

use super::Task;
use crate::arch::switch;

// 创建空闲任务

#[cfg(target_arch = "riscv64")]
lazy_static! {
    pub static ref IDLE_TASK: Arc<Task> = {
        let idle_task = Task::zero_init();
        // 将tp寄存器指向idle_task
        unsafe {
            // 注意这里需要对Arc指针先解引用再取`IDLE_TASK`地址
            // 两种方法都可以, Arc::as_ptr或者直接解引用然后引用
            asm!("mv tp, {}", in(reg) &(*idle_task) as *const _ as usize);

        }
        idle_task
    };
}

#[cfg(target_arch = "loongarch64")]
lazy_static! {
    pub static ref IDLE_TASK: Arc<Task> = {
        let idle_task = Task::zero_init();
        // 将tp寄存器指向idle_task
        unsafe {
            // 注意这里需要对Arc指针先解引用再取`IDLE_TASK`地址
            // 两种方法都可以, Arc::as_ptr或者直接解引用然后引用
            asm!("addi.d $r2, {}, 0", in(reg) &(*idle_task) as *const _ as usize);

        }
        idle_task
    };
}

// 创建任务管理器
lazy_static! {
    ///Processor management structure
    pub static ref PROCESSOR: RwLock<Processor> = RwLock::new(Processor::new());
}

/// 运行初始任务
/// 功能：用于激活任务管理器
pub fn run_tasks() {
    loop {
        if let Some(next_task) = crate::task::scheduler::fetch_task() {
            let idle_task = IDLE_TASK.clone();
            let next_task_kstack = next_task.kstack();
            idle_task.set_ready();
            next_task.set_running();
            let mut processor = PROCESSOR.write();
            processor.current = next_task.clone();
            drop(processor);
            drop(next_task);
            // 将tp寄存器指向idle_task
            #[cfg(target_arch = "riscv64")]
            unsafe {
                // 注意这里需要对Arc指针先解引用再取`IDLE_TASK`地址
                // 两种方法都可以, Arc::as_ptr或者直接解引用然后引用
                asm!("mv tp, {}", in(reg) &(*idle_task) as *const _ as usize);
            }
            #[cfg(target_arch = "loongarch64")]
            unsafe {
                // 注意这里需要对Arc指针先解引用再取`IDLE_TASK`地址
                // 两种方法都可以, Arc::as_ptr或者直接解引用然后引用
                asm!("addi.d $r2, {}, 0", in(reg) &(*idle_task) as *const _ as usize);
            }
            unsafe {
                switch::__switch(next_task_kstack);
            }
            unreachable!("Unreachable in run_tasks");
        }
    }
}

/// 获取当前任务
pub fn current_task() -> Arc<Task> {
    log::trace!("current_task");
    PROCESSOR.read().current_task()
}

#[cfg(target_arch = "riscv64")]
#[allow(unused)]
pub fn current_tp() -> usize {
    let mut tp: usize;
    unsafe {
        asm!("mv {}, tp", out(reg) tp);
    }
    tp
}
#[cfg(target_arch = "loongarch64")]
#[allow(unused)]
pub fn current_tp() -> usize {
    let mut tp: usize;
    unsafe {
        asm!("addi.d {}, $r2, 0", out(reg) tp);
    }
    tp
}

///Processor management structure
pub struct Processor {
    ///The task currently executing on the current processor
    current: Arc<Task>,
}

impl Processor {
    /// Create a empty Processor
    pub fn new() -> Self {
        Self {
            current: IDLE_TASK.clone(),
        }
    }
    pub fn current_task(&self) -> Arc<Task> {
        // 神奇小咒语
        log::trace!("[current_task]");
        self.current.clone()
    }
    /// 将switch的时间算到switch_in的task
    pub fn switch_to(&mut self, task: Arc<Task>) {
        self.current.time_stat().record_switch_out();
        task.time_stat().record_switch_in();
        self.current = task;
    }
}

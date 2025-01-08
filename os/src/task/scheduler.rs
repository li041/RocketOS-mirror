use core::{arch::asm, cell::RefCell};

use alloc::{collections::vec_deque::VecDeque, sync::Arc, task};

use crate::{
    mutex::{SpinNoIrq, SpinNoIrqLock},
    task::{context::check_task_context_in_kernel_stack, switch},
};

use super::Task;
use lazy_static::lazy_static;

// FIFO Task scheduler
pub struct Scheduler {
    ready_queue: VecDeque<Arc<Task>>,
}

impl Scheduler {
    ///Creat an empty TaskManager
    pub fn new() -> Self {
        Self {
            ready_queue: VecDeque::new(),
        }
    }
    ///Add a task to `TaskManager`
    pub fn add(&mut self, task: Arc<Task>) {
        self.ready_queue.push_back(task);
    }
    ///Remove the first task and return it,or `None` if `TaskManager` is empty
    pub fn fetch(&mut self) -> Option<Arc<Task>> {
        self.ready_queue.pop_front()
    }
}

// every processor
lazy_static! {
    pub static ref SCHEDULER: SpinNoIrqLock<Scheduler> = SpinNoIrqLock::new(Scheduler::new());
}

pub fn add_task(task: Arc<Task>) {
    SCHEDULER.lock().add(task);
}

pub fn fetch_task() -> Option<Arc<Task>> {
    SCHEDULER.lock().fetch()
}

// 由caller保证原任务的状态切换
// 不能从自己切换到自己, 否则会死循环
#[no_mangle]
pub fn switch_to_next_task() {
    // 1. 切换内核栈
    // 2. 切换Processor的current
    // 3. 切换tp(在__switch中完成)
    // 4. 切换memory set(在__switch中完成)

    // 获得下一个任务的内核栈
    // 可以保证`Ready`的任务`Task`中的内核栈与实际运行的sp保持一致
    let next_task = fetch_task().unwrap();
    let next_task_kernel_stack = next_task.kstack.0;
    log::info!("next_task_kernel_stack: {:#x}", next_task_kernel_stack);
    // check_task_context_in_kernel_stack(next_task_kernel_stack);
    // 切换Processor的current
    crate::task::processor::PROCESSOR
        .lock()
        .switch_to(next_task);

    unsafe {
        switch::__switch(next_task_kernel_stack);
    }
    log::info!("return from switch");
}

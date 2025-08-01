use alloc::{sync::Arc, vec::Vec};
use lazy_static::lazy_static;

use crate::{arch::config::MAX_HARTS, task::Task};

lazy_static! {
    static ref IDLESCHEDULER: Vec<IDLEScheduler> = (0..MAX_HARTS)
        .map(|hart_id| IDLEScheduler::new(hart_id))
        .collect();
}

pub fn get_idle_scheduler(hart_id: usize) -> Option<Arc<Task>> {
   IDLESCHEDULER[hart_id].fetch()
}

pub struct IDLEScheduler {
    idle_task: Arc<Task>,
}

impl IDLEScheduler {
    pub fn new(hart_id: usize) -> Self {
        let idle_task = Task::init_idle_task(hart_id);
        Self { idle_task }
    }
    pub fn fetch(&self) -> Option<Arc<Task>> {
        Some(self.idle_task.clone())
    }
}

/// 空闲任务, 用于没有就绪任务时的占位
pub fn idle_task() -> ! {
    loop {
        core::hint::spin_loop();
    }
}
use alloc::sync::{Arc, Weak};
use hashbrown::HashMap;
use lazy_static::lazy_static;
use crate::mutex::SpinNoIrqLock;

use super::{task::Task, Tid};

// 任务管理器
lazy_static!{
    pub static ref TASK_MANAGER: TaskManager = TaskManager::new();
}

pub struct TaskManager(SpinNoIrqLock<HashMap<Tid, Weak<Task>>>);

impl TaskManager {
    pub fn new() -> Self{
        Self (SpinNoIrqLock::new(HashMap::new()))
    }

    pub fn add(&self, task: &Arc<Task>) {
        self.0.lock().insert(task.tid(), Arc::downgrade(task));
    }

    pub fn remove(&self, tid: Tid) {
        self.0.lock().remove(&tid);
    }

    pub fn len(&self) -> usize {
        self.0.lock().len()
    }

    pub fn get(&self, tid: Tid) -> Option<Arc<Task>>{
        match self.0.lock().get(&tid) {
            Some(task) => task.upgrade(),
            None => None,
        }
    }

    pub fn for_each(&self, f: impl Fn(&Arc<Task>)) {
        for task in self.0.lock().values() {
            f(&task.upgrade().unwrap())
        }
    }
}


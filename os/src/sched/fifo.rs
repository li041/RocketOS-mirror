//! real time scheduler is not implemented yet

use core::ops::Deref;

use alloc::sync::Arc;

use crate::index_list::{IndexList, ListIndex};

use super::Scheduler;

#[derive(PartialEq)]
pub struct FIFOTask<T: PartialEq> {
    inner: T,
    // Todo: add fields with real time scheduling
}

impl<T> FIFOTask<T> 
    where T: PartialEq,
{
    pub const fn new(inner: T) -> Self {
        FIFOTask {
            inner,
        }
    }
    /// getter for inner
    pub const fn inner(&self) -> &T {
        &self.inner
    }
}

impl<T> Deref for FIFOTask<T> 
    where T: PartialEq,
{
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct FIFOScheduler<T: PartialEq> {
    ready_queue: IndexList<Arc<FIFOTask<T>>>,
} 

impl<T> FIFOScheduler<T> 
    where T: PartialEq,
{
    pub fn new() -> Self {
        FIFOScheduler {
            ready_queue: IndexList::new(),
        }
    }
}

impl<T> Scheduler for FIFOScheduler<T> 
    where T: PartialEq,
{
    type SchedEntity = Arc<FIFOTask<T>>;
    fn init(&mut self) {
    }
    /// add task to the end of the ready queue
    fn enqueue_task(&mut self, task: Self::SchedEntity) {
        self.ready_queue.insert_last(task);
    }
    fn dequeue_task(&mut self, index: ListIndex) -> Option<Self::SchedEntity> {
        // self.ready_queue.remove(task)
        self.ready_queue.remove(index)
    }
    /// get the first task in the ready queue
    fn pick_next_task(&mut self) -> Option<Self::SchedEntity> {
        self.ready_queue.remove_first()
    }
    fn load_balance(&mut self) {
        unimplemented!("load_balance() is not implemented yet");
    }
    fn set_user_nice(&mut self) {
        unimplemented!("set_user_nice() is not implemented yet");
    }
}


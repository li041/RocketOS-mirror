use crate::index_list::ListIndex;

// mod cfs;
mod fifo;
mod prio;

// Todo:
// 1. update_curr()更新当前进程的运行时间
// 2. 完善Scheduler trait

pub trait Scheduler {
    /// associate type
    type SchedEntity: PartialEq;
    fn init(&mut self);
    fn enqueue_task(&mut self, task: Self::SchedEntity);
    fn dequeue_task(&mut self, index: ListIndex) -> Option<Self::SchedEntity>;
    fn pick_next_task(&mut self) -> Option<Self::SchedEntity>;
    fn load_balance(&mut self);
    fn set_user_nice(&mut self);
}

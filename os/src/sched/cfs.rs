use core::{
    ops::Deref,
    sync::atomic::{AtomicIsize, AtomicUsize},
};

use alloc::{collections::btree_map::BTreeMap, sync::Arc};

use super::{
    prio::{SCHED_PRIO_TO_WEIGHT, SCHED_PRIO_TO_WMULT, WMULT_SHIFT},
    Scheduler,
};

use crate::index_list::ListIndex;

pub struct CFSTask<T> {
    inner: T,
    vruntime: AtomicUsize,
    nice: AtomicIsize,
    load: LoadWeight,
}

impl<T> CFSTask<T>
where
    T: PartialEq,
{
    pub const fn new(inner: T) -> Self {
        CFSTask {
            inner,
            vruntime: AtomicUsize::new(0),
            nice: AtomicIsize::new(0),
            load: LoadWeight::new(0),
        }
    }
    pub fn calc_delta_fair(&mut self, delta: u64) -> u64 {
        if self.load.weight != NICE_0_LOAD {
            _calc_delta_fair(delta, self.load.weight as u64, &mut self.load) as u64
        } else {
            delta
        }
    }
}

impl<T> Deref for CFSTask<T>
where
    T: PartialEq,
{
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct CFSScheduler<T>
where
    T: PartialEq,
{
    // (vruntime, taskid) -> sched_entity
    ready_queue: BTreeMap<(isize, isize), CFSTask<T>>,
}

impl<T> Scheduler for CFSScheduler<T>
where
    T: PartialEq,
{
    type SchedEntity = Arc<CFSTask<T>>;
    fn init(&mut self) {}
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

struct LoadWeight {
    inv_weight: u32, // 负载权重的倒数
    weight: u64,     // 任务权重
}

impl LoadWeight {
    const fn new(nice: i32) -> Self {
        let weight = SCHED_PRIO_TO_WEIGHT[(nice + 20) as usize] as u64;
        let inv_weight = SCHED_PRIO_TO_WMULT[(nice + 20) as usize] as u32;
        LoadWeight { inv_weight, weight }
    }
}

fn set_load_weight() {
    todo!();
}

// weight = NICE_0_LOAD = 1024
const NICE_0_LOAD: u64 = 1024;

/*
 * delta_exec * weight / lw.weight
 *   OR
 * (delta_exec * (weight * lw->inv_weight)) >> WMULT_SHIFT
 *
 * Either weight := NICE_0_LOAD and lw \e sched_prio_to_wmult[], in which case
 * we're guaranteed shift stays positive because inv_weight is guaranteed to
 * fit 32 bits, and NICE_0_LOAD gives another 10 bits; therefore shift >= 22.
 *
 * Or, weight =< lw.weight (because lw.weight is the runqueue weight), thus
 * weight/lw.weight <= 1, and therefore our shift will also be positive.
 */
fn _calc_delta_fair(delta_exec: u64, weight: u64, lw: &mut LoadWeight) -> u64 {
    // linux: scale_load_down(weight), 其中scale_load_down是一个恒等映射
    let mut fact = weight;
    let mut fact_hi = (fact >> 32) as u32;
    let mut shift: i32 = WMULT_SHIFT;
    let mut fs;

    // lw.update_inv_weight();

    if fact_hi != 0 {
        fs = fact_hi.leading_zeros() as i32;
        shift -= fs;
        fact >>= fs;
    }

    fact = fact * lw.inv_weight as u64;

    fact_hi = (fact >> 32) as u32;

    if fact_hi != 0 {
        fs = fact_hi.leading_zeros() as i32;
        shift -= fs;
        fact >>= fs;
    }

    (delta_exec * fact) >> shift
}

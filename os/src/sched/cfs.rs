use core::{
    ops::Deref,
    sync::atomic::{AtomicIsize, AtomicU64, AtomicUsize},
};

use alloc::{collections::btree_map::BTreeMap, sync::Arc};
use lazy_static::lazy_static;
use spin::Mutex;

use super::prio::{SCHED_PRIO_TO_WEIGHT, SCHED_PRIO_TO_WMULT, WMULT_SHIFT};

use crate::{
    index_list::ListIndex, sched, task::{add_task, change_task, current_task, get_task, handle_timeout, schedule, yield_current_task, Task}, timer::TimeSpec
};

const SYSCTL_SCHED_MIN_GRANULARITY: usize = 750_000; // 0.75ms
const SCHED_NR_LATENCY: usize = 8; // 调度延迟
const SYSCTL_SCHED_LATENCY: usize = 6_000_000; // 6ms

// 在trap_handler中检查时间片
pub fn check_slice() {
    // 计算当次用户运行时间
    let current_time = crate::timer::TimeVal::new_machine_time();
    let user_start_time = current_task().time_stat().user_start_time();
    let user_time = current_time - user_start_time;
    let se = current_task().sched_entity();
    let slice = se.slice();
    // log::error!(
    //     "sched_entity: slice = {}, vruntime: {}, user_time: {}",
    //     se.slice(),
    //     se.vruntime(),
    //     user_time.as_ns()
    // );
    // 与当前任务slice比较
    if slice > user_time.as_ns() {
        se.set_slice(slice - user_time.as_ns());
    } else {
        // 超出分配的时间片
        se.set_slice(0);
        // yield_current_task();
        change_task();
    }
}

pub struct CFSScheduler {
    // (vruntime, tid) -> CFSSchedEntity
    pub tasks_timeline: BTreeMap<(u64, usize), Arc<CFSSchedEntity>>,
    pub load: LoadWeight,
    pub nr_running: usize,
}

impl CFSScheduler {
    pub fn new() -> Self {
        CFSScheduler {
            tasks_timeline: BTreeMap::new(),
            load: LoadWeight::zero_init(),
            nr_running: 0,
        }
    }

    // 将任务加入到CFS调度器
    pub fn add(&mut self, task: Arc<Task>) {
        let se = task.sched_entity();
        update_curr(&se);
        // log::error!("CFSScheduler::add: task {} added with vruntime {}", task.tid(), se.vruntime());
        self.update_add_load(se.load.weight());
        self.nr_running += 1;
        // log::error!("CFSScheduler::add: task {} added with vruntime {}", task.tid(), se.vruntime());
        self.tasks_timeline.insert((se.vruntime(), task.tid()), se);
    }

    // 选出vruntime最小的CFSSchedEntity
    pub fn fetch(&mut self) -> Option<Arc<CFSSchedEntity>> {
        if let Some(((vruntime, tid), se)) = self.tasks_timeline.pop_first() {
            // log::error!("[fetch] se.vruntime: {}, tid: {}", vruntime, tid);
            // update_curr(&se);
            // let se_clone = se.clone();
            // self.tasks_timeline.insert((se.vruntime(), tid), se_clone);
            se.update_exec_start(TimeSpec::new_machine_time());
            self.sched_slice(&se);
            self.update_del_load(se.load.weight());
            self.nr_running -= 1;
            Some(se)
        } else {
            None
        }
    }

    pub fn remove(&mut self, tid: usize) -> Option<Arc<Task>> {
        let key_to_remove =
            self.tasks_timeline.iter().find_map(
                |(&(vruntime, t), se)| {
                    if t == tid {
                        Some((vruntime, t))
                    } else {
                        None
                    }
                },
            );

        // 删除对应的 key
        if let Some(key) = key_to_remove {
            let se = self.tasks_timeline.remove(&key).unwrap();
            self.update_del_load(se.load.weight());
            self.nr_running -= 1;
            get_task(tid)
        } else {
            None
        }
    }

    pub fn dump(&self) {
        log::info!("CFS Scheduler Dump:");
        log::info!("Number of running tasks: {}", self.nr_running);
        log::info!("Total load weight: {}", self.load.weight());
        for ((vruntime, tid), se) in &self.tasks_timeline {
            log::info!(
                "Task ID: {}, VRuntime: {}, Weight: {}",
                tid,
                vruntime,
                se.load.weight()
            );
        }
    }

    // 增加调度器中总体权重
    fn update_add_load(&mut self, weight: u64) {
        self.load
            .weight
            .fetch_add(weight, core::sync::atomic::Ordering::Relaxed);
        let weight = self.load.weight();
        let inv_weight = calc_inv_weight(weight);
        self.load
            .inv_weight
            .store(inv_weight, core::sync::atomic::Ordering::Relaxed);
    }

    // 减少调度器中总体权重
    pub fn update_del_load(&mut self, weight: u64) {
        self.load
            .weight
            .fetch_sub(weight, core::sync::atomic::Ordering::Relaxed);
        let new_weight = self.load.weight();
        let inv_weight = calc_inv_weight(new_weight);
        self.load
            .inv_weight
            .store(inv_weight, core::sync::atomic::Ordering::Relaxed);
    }

    // 计算分配到各个任务的运行时间
    fn sched_slice(&self, se: &Arc<CFSSchedEntity>) {
        let period = sched_period(self.nr_running);
        // 额外加上当前任务的权重
        let current_task_weight = current_task().sched_entity().load.weight();
        let load = LoadWeight::new_with_weight(self.load.weight() + current_task_weight);
        let slice = calc_delta(period as u64, se.load.weight(), &load);
        // 如果当前任务的时间片为0，则设置为计算出的时间片
        if se.slice() == 0 {
            se.set_slice(slice as usize);
        }
    }
}

fn sched_period(nr_running: usize) -> usize {
    if nr_running >= SCHED_NR_LATENCY {
        return nr_running * SYSCTL_SCHED_MIN_GRANULARITY;
    } else {
        return SYSCTL_SCHED_LATENCY;
    }
}

/// 更新当前调度实体的执行时间和虚拟运行时间
pub fn update_curr(se: &Arc<CFSSchedEntity>) {
    let now = TimeSpec::new_machine_time();
    let delta_exec = now - se.exec_start();
    // log::error!("delta_exec: {}", delta_exec.to_nanos());
    // 更新调度实体字段
    // se.update_exec_start(now);
    // 更新虚拟运行时间
    let delta_fair = calc_delta_fair(delta_exec.to_nanos() as u64, se);
    // log::error!("update_curr: delta_fair = {}", delta_fair);
    se.update_vruntime(delta_fair);
}

// weight = NICE_0_LOAD = 1024
const NICE_0_LOAD: u64 = 1024;

/// 计算进程的虚拟运行时间
fn calc_delta_fair(delta_exec: u64, se: &Arc<CFSSchedEntity>) -> u64 {
    if se.weight() != NICE_0_LOAD {
        return calc_delta(delta_exec, NICE_0_LOAD, &se.load);
    }
    delta_exec
}

/// 将进程的实际执行时间delta_exec计算成虚拟运算时间
/// delta_exec * weight * inv_weight >> WMULT_SHIFT
fn calc_delta(delta_exec: u64, weight: u64, lw: &LoadWeight) -> u64 {
    // linux: scale_load_down(weight), 其中scale_load_down是一个恒等映射
    let mut fact = weight;
    let mut fact_hi = (fact >> 32) as u32;
    let mut shift: i32 = WMULT_SHIFT;
    let mut fs;

    // 防止溢出
    if fact_hi != 0 {
        fs = fact_hi.leading_zeros() as i32;
        shift -= fs;
        fact >>= fs;
    }

    fact = fact * lw.inv_weight();

    // 防止溢出
    fact_hi = (fact >> 32) as u32;
    if fact_hi != 0 {
        fs = fact_hi.leading_zeros() as i32;
        shift -= fs;
        fact >>= fs;
    }

    (delta_exec * fact) >> shift
}

pub struct CFSSchedEntity {
    pub tid: usize, // 线程ID
    pub load: LoadWeight,
    pub vruntime: AtomicU64,
    pub exec_start: AtomicU64,
    pub slice: AtomicUsize, // 任务分配的运行时间
}

impl CFSSchedEntity {
    pub fn zero_init() -> Self {
        CFSSchedEntity {
            tid: 0,
            load: LoadWeight::zero_init(),
            vruntime: AtomicU64::new(u64::MAX / 2),
            exec_start: AtomicU64::new(TimeSpec::new_machine_time().to_nanos() as u64),
            slice: AtomicUsize::new(0),
        }
    }

    pub fn new(tid: usize, nice: i32, vruntime: u64) -> Self {
        CFSSchedEntity {
            tid,
            load: LoadWeight::new(nice),
            vruntime: AtomicU64::new(vruntime),
            exec_start: AtomicU64::new(TimeSpec::new_machine_time().to_nanos() as u64),
            slice: AtomicUsize::new(0),
        }
    }

    pub fn weight(&self) -> u64 {
        self.load.weight.load(core::sync::atomic::Ordering::Relaxed)
    }

    pub fn vruntime(&self) -> u64 {
        self.vruntime.load(core::sync::atomic::Ordering::Relaxed)
    }

    pub fn exec_start(&self) -> TimeSpec {
        TimeSpec::from_nanos(self.exec_start.load(core::sync::atomic::Ordering::Relaxed) as usize)
    }

    pub fn slice(&self) -> usize {
        self.slice.load(core::sync::atomic::Ordering::Relaxed)
    }

    pub fn update_exec_start(&self, now: TimeSpec) {
        self.exec_start
            .store(now.to_nanos() as u64, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn update_vruntime(&self, delta_fair: u64) {
        let mut vruntime = self.vruntime.load(core::sync::atomic::Ordering::Relaxed);
        vruntime += delta_fair;
        self.vruntime
            .store(vruntime, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn set_slice(&self, slice: usize) {
        self.slice
            .store(slice, core::sync::atomic::Ordering::Relaxed);
    }
}

pub struct LoadWeight {
    pub weight: AtomicU64,     // 任务权重
    pub inv_weight: AtomicU64, // 负载权重的倒数
}

impl LoadWeight {
    const fn zero_init() -> Self {
        LoadWeight {
            weight: AtomicU64::new(0),
            inv_weight: AtomicU64::new(0),
        }
    }

    const fn new(nice: i32) -> Self {
        LoadWeight {
            weight: AtomicU64::new(SCHED_PRIO_TO_WEIGHT[nice as usize + 20]),
            inv_weight: AtomicU64::new(SCHED_PRIO_TO_WMULT[nice as usize + 20]),
        }
    }

    pub fn new_with_weight(weight: u64) -> Self {
        LoadWeight {
            weight: AtomicU64::new(weight),
            inv_weight: AtomicU64::new(calc_inv_weight(weight)),
        }
    }

    pub fn weight(&self) -> u64 {
        self.weight.load(core::sync::atomic::Ordering::Relaxed)
    }

    pub fn inv_weight(&self) -> u64 {
        self.inv_weight.load(core::sync::atomic::Ordering::Relaxed)
    }

    pub fn set_weight(&self, nice: i32) {
        let weight = SCHED_PRIO_TO_WEIGHT[nice as usize + 20];
        self.weight
            .store(weight, core::sync::atomic::Ordering::Relaxed);
        let inv_weight = SCHED_PRIO_TO_WMULT[nice as usize + 20];
        self.inv_weight
            .store(inv_weight, core::sync::atomic::Ordering::Relaxed);
    }
}

// 计算inv_weight
fn calc_inv_weight(weight: u64) -> u64 {
    if weight == 0 {
        return 0;
    } else {
        (1 << 32) / weight
    }
}

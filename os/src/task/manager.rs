use crate::{
    arch::{config::SysResult, trap::context::dump_trap_context}, signal::{SiField, Sig, SigInfo}, syscall::errno::SyscallRet, task::{add_task, current_task, processor::current_tp, schedule, scheduler::dump_scheduler}, timer::{self, ITimerVal, TimeSpec}
};
use alloc::{
    boxed::Box,
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    sync::{Arc, Weak},
    vec::Vec,
};
use alloc::{task, vec};
use hashbrown::HashMap;
use lazy_static::lazy_static;
use spin::Mutex;

use super::{task::Task, wait::WaitQueue, Tid};

// 任务管理器
lazy_static! {
    static ref TASK_MANAGER: TaskManager = TaskManager::new();
}

// 进程组管理器
lazy_static! {
    static ref PROCESS_GROUP_MANAGER: ProcessGroupManager = ProcessGroupManager::new();
}

// 阻塞管理器
lazy_static! {
    static ref WAIT_MANAGER: WaitManager = WaitManager::init();
}

// 时间管理器
lazy_static! {
    static ref TIME_MANAGER: TimeManager = TimeManager::new();
}

/************************************** 任务管理器 **************************************/
// 创建任务时向其注册任务信息
pub fn register_task(task: &Arc<Task>) {
    TASK_MANAGER.add(task);
}
// 删除任务时注销任务信息
pub fn unregister_task(tid: Tid) {
    TASK_MANAGER.remove(tid);
}
// 根据tid获取某个任务
pub fn get_task(tid: Tid) -> Option<Arc<Task>> {
    TASK_MANAGER.get(tid)
}
// 遍历所有任务
pub fn for_each_task<T>(f: impl Fn(&Arc<Task>) -> T) -> Vec<T> {
    TASK_MANAGER.for_each(f)
}

pub struct TaskManager(Mutex<HashMap<Tid, Weak<Task>>>);

impl TaskManager {
    pub fn new() -> Self {
        Self(Mutex::new(HashMap::new()))
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

    pub fn get(&self, tid: Tid) -> Option<Arc<Task>> {
        match self.0.lock().get(&tid) {
            Some(task) => task.upgrade(),
            None => None,
        }
    }

    pub fn for_each<T>(&self, f: impl Fn(&Arc<Task>) -> T) -> Vec<T> {
        let mut results = Vec::new();
        for task in self.0.lock().values() {
            let task = task.upgrade().unwrap();
            results.push(f(&task));
        }
        results
    }
}

/************************************** 进程组管理器 **************************************/

/// 向进程组管理器中添加新进程组
/// 注：该函数会将该任务的pgid设置为其tid
pub fn new_group(task: &Arc<Task>) {
    PROCESS_GROUP_MANAGER.new_group(task);
}

/// 向指定进程组中添加新任务
/// 注：当指定进程组不存在时会依照参数pgid创建一个新的进程组
pub fn add_group(pgid: usize, task: &Arc<Task>) {
    PROCESS_GROUP_MANAGER.add_group(pgid, task);
}

/// 获取指定进程组的任务列表
pub fn get_group(pgid: usize) -> Option<Vec<Weak<Task>>> {
    PROCESS_GROUP_MANAGER.get_group(pgid)
}

/// 将当前任务从所在的进程组中移除
pub fn remove_group(task: &Arc<Task>) {
    PROCESS_GROUP_MANAGER.remove(task);
}

pub struct ProcessGroupManager(Mutex<BTreeMap<usize, Vec<Weak<Task>>>>);

impl ProcessGroupManager {
    pub const fn new() -> Self {
        Self(Mutex::new(BTreeMap::new()))
    }

    pub fn new_group(&self, group_leader: &Arc<Task>) {
        let pgid = group_leader.pgid();
        let mut group = Vec::new();
        group.push(Arc::downgrade(group_leader));
        self.0.lock().insert(pgid, group);
    }

    pub fn add_group(&self, pgid: usize, process: &Arc<Task>) {
        // Todo: 对于线程更改进程组需要更严格的限制
        if !process.is_process() {
            log::warn!("[ProcessGroupManager::add_process] try adding task that is not a process");
            return;
        }
        process.set_pgid(pgid);
        let mut inner = self.0.lock();
        if let Some(process_group) = inner.get_mut(&pgid) {
            process_group.push(Arc::downgrade(process));
        } else {
            let mut group = Vec::new();
            group.push(Arc::downgrade(process));
            inner.insert(pgid, group);
        }
    }

    pub fn get_group(&self, pgid: usize) -> Option<Vec<Weak<Task>>> {
        self.0.lock().get(&pgid).cloned()
    }

    pub fn remove(&self, process: &Arc<Task>) {
        self.0
            .lock()
            .get_mut(&process.pgid())
            .unwrap()
            .retain(|task| task.upgrade().map_or(false, |t| !Arc::ptr_eq(process, &t)))
    }
    
    pub fn dump_group(&self) {
        log::info!("[ProcessGroupManager] dump process groups:");
        for (pgid, group) in self.0.lock().iter() {
            log::info!("Process Group ID: {}", pgid);
            for task in group {
                if let Some(task) = task.upgrade() {
                    log::info!("  Task ID: {}", task.tid());
                } else {
                    log::info!("Task has been dropped");
                }
            }
        }
    }
}

/************************************** 阻塞管理器 **************************************/
// Todo: 为可中断的任务的支持

// 将当前任务加入到basic队列并阻塞
// 返回值：0：正常被唤醒； -1：被中断唤醒
pub fn wait() -> isize {
    log::trace!("[wait]");
    let task = current_task();
    task.set_interruptable();
    WAIT_MANAGER.add(task);
    // log::warn!("[wait] task{} block", current_task().tid());
    schedule(); // 调度其他任务
    let task = current_task();
    if task.is_interrupted() {
        task.set_uninterruptable();
        return -1;
    }
    return 0;
}

// 条件阻塞，只有当满足条件时才会被唤醒
// pub fn wait_event<F>(name: &String, condition: F)
// where
//     F: Fn() -> bool,
// {
//     // loop作用：防止被唤醒到被调度这段期间条件再次失效
//     loop {
//         // 检查条件是否满足
//         if condition() {
//             break;
//         }
//         // 条件不满足，加入阻塞队列
//         let task = current_task();
//         task.set_uninterruptable();
//         WAIT_MANAGER.add_cond(name, task);
//         log::warn!("[wait_event] task{} cond_block", current_task().tid());
//         schedule();
//     }
// }

// 时间阻塞，当达到指定时间后自动唤醒
// 返回值：0：正常被唤醒； -1：被中断唤醒  -2：超时唤醒
pub fn wait_timeout(dur: timer::TimeSpec, clock_id: i32) -> isize {
    let task = current_task();
    let tid = task.tid();
    task.set_interruptable();
    // 超时后唤醒任务
    let deadline = set_wait_alarm(dur, tid, clock_id);
    WAIT_MANAGER.add(task);
    schedule();
    let task = current_task();
    if task.is_interrupted() {
        return -1;
    }
    let timeout = TimeSpec::new_machine_time() >= deadline;
    if timeout {
        log::warn!("[wait_timeout] task{} timeout", tid);
        return -2; // 超时唤醒
    }
    return 0; // 正常被唤醒
}

/// 唤醒某一特定任务
/// wait_timeout的回调函数
pub fn wakeup(tid: Tid) {
    if let Ok(task) = WAIT_MANAGER.remove(tid) {
        task.set_ready();
        add_task(task);
    }
}

// 唤醒条件阻塞队列中的一个任务（FIFO顺序）
// pub fn wake_cond_one(name: &String) {
//     if let Some(task) = WAIT_MANAGER.fetch_cond(name) {
//         log::warn!("[wake_cond_one] task{} cond_unblock", task.tid());
//         task.set_ready();
//         add_task(task);
//     }
// }

// // 唤醒条件阻塞队列中的所有任务
// pub fn wake_cond_all(name: &String) {
//     while let Some(task) = WAIT_MANAGER.fetch_cond(name) {
//         log::warn!("[wake_cond_one] task{} cond_unblock", task.tid());
//         task.set_ready();
//         add_task(task);
//     }
// }

// 将任务从阻塞队列中移除（用于线程异常退出）
pub fn delete_wait(tid: Tid) {
    log::warn!("[remove] task{} removed from queue", tid);
    WAIT_MANAGER.delete(tid);
}

// // 申请一个条件阻塞队列
// pub fn alloc_wait_queue(name: &String) {
//     WAIT_MANAGER.alloc_cond_queue(name);
// }

// // 释放一个条件阻塞队列
// pub fn dealloc_wait_queue(name: &String) {
//     WAIT_MANAGER.dealloc_cond_queue(name);
// }

// 打印所有阻塞队列中的内容
pub fn dump_wait_queue() -> () {
    let que = WAIT_MANAGER.wait_queue.lock();
    que.dump_queue();
}

pub struct WaitManager {
    // 阻塞队列
    pub wait_queue: Mutex<WaitQueue>,
}

impl WaitManager {
    // 创建一个新的阻塞队列
    fn init() -> Self {
        let wait_queue = WaitQueue::new();
        WaitManager {
            wait_queue: Mutex::new(wait_queue),
        }
    }

    // 向阻塞队列中添加一个任务
    fn add(&self, task: Arc<Task>) {
        let mut queue = self.wait_queue.lock();
        queue.add(task);
    }

    // 从阻塞队列中取出特定任务
    fn remove(&self, tid: Tid) -> Result<Arc<Task>, ()> {
        let mut queue = self.wait_queue.lock();
        if let Ok(task) = queue.remove(tid) {
            return Ok(task);
        }
        Err(())
    }

    // 从阻塞队列中删除特定任务
    fn delete(&self, tid: Tid) {
        let mut queue = self.wait_queue.lock();
        queue.remove(tid);
    }
}

/************************************** 时间管理器 **************************************/
pub type Callback = Box<dyn Fn() + Send>;
/// -1是内核自用定时器
pub type ClockId = i32;
pub const ITIMER_REAL: ClockId = 0;
pub const ITIMER_VIRTUAL: ClockId = 1;
pub const ITIMER_PROF: ClockId = 2;

pub type AlarmEntry = (Tid, ClockId, Callback);

/// 为任务设置超时阻塞时限
pub fn set_wait_alarm(dur: timer::TimeSpec, tid: Tid, clock_id: i32) -> TimeSpec {
    TIME_MANAGER.add_timer(dur, tid, clock_id, move || wakeup(tid))
}

/// 取消任务的阻塞时限
pub fn cancel_wait_alarm(tid: Tid) {
    TIME_MANAGER.remove_timer(tid, -1);
}

pub struct TimeManager {
    alarms: Mutex<BTreeMap<TimeSpec, Vec<AlarmEntry>>>,
}

impl TimeManager {
    fn new() -> Self {
        Self {
            alarms: Mutex::new(BTreeMap::new()),
        }
    }

    // 获取当前闹钟数量
    fn len(&self) -> usize {
        // self.alarms.lock().len()
        self.alarms.lock().values().map(|v| v.len()).sum()
    }
    /// 更新某个任务指定 clock_id 的定时器为新的时间
    pub fn update_timer<F>(
        &self,
        tid: Tid,
        clock_id: ClockId,
        dur: TimeSpec,
        callback: F,
    ) -> Option<TimeSpec>
    where
        F: Fn() + Send + 'static,
    {
        let mut alarms = self.alarms.lock();

        // 查找旧的 timer 项
        let mut old_key: Option<TimeSpec> = None;

        for (time, entries) in alarms.iter_mut() {
            if let Some(pos) = entries
                .iter()
                .position(|(t, c, _)| *t == tid && *c == clock_id)
            {
                entries.remove(pos);
                old_key = Some(*time);
                break;
            }
        }

        // 清理空 vec（如果有）
        if let Some(old_time) = old_key {
            if let Some(vec) = alarms.get(&old_time) {
                if vec.is_empty() {
                    alarms.remove(&old_time);
                }
            }
        }

        // 插入新的 timer
        let new_deadline = TimeSpec::new_machine_time() + dur;
        alarms
            .entry(new_deadline)
            .or_insert(vec![])
            .push((tid, clock_id, Box::new(callback)));

        Some(new_deadline)
    }
    // 设置闹钟
    // dur是相对时间
    fn add_timer<F>(
        &self,
        dur: timer::TimeSpec,
        tid: Tid,
        clock_id: ClockId,
        callback: F,
    ) -> TimeSpec
    where
        F: Fn() + Send + 'static,
    {
        let mut alarm = self.alarms.lock();
        let deadline = TimeSpec::new_machine_time() + dur;
        alarm
            .entry(deadline)
            .or_insert(vec![])
            .push((tid, clock_id, Box::new(callback)));
        deadline
    }

    // 取消指定tid的所有闹钟
    fn remove_timer(&self, tid: Tid, clock_id: ClockId) {
        let mut alarm = self.alarms.lock();
        alarm.retain(|_, vec| {
            vec.retain(|(t, c, _)| *t != tid || *c != clock_id);
            !vec.is_empty()
        });
    }

    // 执行超时回调 返回触发的tid列表
    fn split_off(&self) -> vec::Vec<Tid> {
        let now = TimeSpec::new_machine_time();
        let mut tids = vec![];
        // 第一步：先锁一次并记录所有要移除的键
        let mut guard = self.alarms.lock();
        let keys_to_remove: vec::Vec<_> = guard.range(..=&now).map(|(k, _)| k.clone()).collect();
        // 第二步：再移除这些键，收集对应的值
        for key in keys_to_remove {
            if let Some(entry) = guard.remove(&key) {
                for (tid, _clock_id, callback) in entry {
                    tids.push(tid);
                    // 执行回调
                    callback();
                }
            }
        }
        if tids.len() > 0 {
            log::warn!("[wakeup_timeout] task {:?} timeout", tids);
        }
        tids
    }
}

pub fn handle_timeout() -> Vec<Tid> {
    TIME_MANAGER.split_off()
}

pub fn remove_timer(tid: Tid, clock_id: ClockId) {
    TIME_MANAGER.remove_timer(tid, clock_id);
}

pub fn add_real_timer(tid: Tid, dur: TimeSpec) {
    TIME_MANAGER.add_timer(dur, tid, ITIMER_REAL, move || {
        // 触发定时器
        real_timer_callback(tid);
    });
}

pub fn update_real_timer(tid: Tid, dur: TimeSpec) {
    TIME_MANAGER.update_timer(tid, ITIMER_REAL, dur, move || {
        // 触发定时器
        real_timer_callback(tid);
    });
}

/// setitimer的回调函数
pub fn real_timer_callback(tid: Tid) {
    if let Some(task) = get_task(tid) {
        task.receive_siginfo(
            SigInfo {
                signo: Sig::SIGALRM.raw(),
                code: SigInfo::TIMER,
                fields: SiField::Kill { tid: current_task().tid() },
            },
            true,
        );
        task.op_itimerval(|itimerval| {
            let itimerval = &itimerval[0];
            if itimerval.it_interval.is_zero() {
                // 不再设置定时器
                return;
            } else {
                // 重新设置定时器
                let dur = itimerval.it_interval;
                add_real_timer(tid, dur.into());
            }
        })
    }
}

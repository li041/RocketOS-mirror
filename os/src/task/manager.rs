use core::clone;

use crate::{
    signal::{SiField, Sig, SigInfo},
    task::{add_task, current_task, schedule, scheduler::dump_scheduler},
    timer::{self, ITimerVal, TimeSpec},
};
use alloc::vec;
use alloc::{
    boxed::Box,
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    sync::{Arc, Weak},
    vec::Vec,
};
use hashbrown::HashMap;
use lazy_static::lazy_static;
use spin::Mutex;

use super::{task::Task, wait::WaitQueue, Tid};

// 任务管理器
lazy_static! {
    static ref TASK_MANAGER: TaskManager = TaskManager::new();
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
pub fn for_each_task(f: impl Fn(&Arc<Task>)) {
    TASK_MANAGER.for_each(f);
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

    pub fn for_each(&self, f: impl Fn(&Arc<Task>)) {
        for task in self.0.lock().values() {
            f(&task.upgrade().unwrap())
        }
    }
}

/************************************** 阻塞管理器 **************************************/
// Todo: 为可中断的任务的支持

// 将当前任务加入到basic队列并阻塞
pub fn wait() {
    log::trace!("[wait]");
    let task = current_task();
    task.set_uninterruptable();
    WAIT_MANAGER.add(task);
    // log::warn!("[wait] task{} block", current_task().tid());
    schedule(); // 调度其他任务
                // log::warn!("[wait] task{} unblock", current_task().tid());
}

// 条件阻塞，只有当满足条件时才会被唤醒
pub fn wait_event<F>(name: &String, condition: F)
where
    F: Fn() -> bool,
{
    // loop作用：防止被唤醒到被调度这段期间条件再次失效
    loop {
        // 检查条件是否满足
        if condition() {
            break;
        }
        // 条件不满足，加入阻塞队列
        let task = current_task();
        task.set_uninterruptable();
        WAIT_MANAGER.add_cond(name, task);
        log::warn!("[wait_event] task{} cond_block", current_task().tid());
        schedule();
    }
}

// 时间阻塞，当达到指定时间后自动唤醒
// 返回值：如果为true代表任务超时唤醒，为false代表任务被其他事务唤醒
pub fn wait_timeout(dur: timer::TimeSpec) -> bool {
    let task = current_task();
    let tid = task.tid();
    task.set_uninterruptable();
    // 超时后唤醒任务
    let deadline = set_wait_alarm(dur, tid);
    WAIT_MANAGER.add(task);
    log::warn!("[wait] task{} block(time)", tid);
    schedule();
    log::warn!("[wait] task{} unblock(time)", current_task().tid());
    let timeout = TimeSpec::new_machine_time() >= deadline;
    timeout
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
pub fn wake_cond_one(name: &String) {
    if let Some(task) = WAIT_MANAGER.fetch_cond(name) {
        log::warn!("[wake_cond_one] task{} cond_unblock", task.tid());
        task.set_ready();
        add_task(task);
    }
}

// 唤醒条件阻塞队列中的所有任务
pub fn wake_cond_all(name: &String) {
    while let Some(task) = WAIT_MANAGER.fetch_cond(name) {
        log::warn!("[wake_cond_one] task{} cond_unblock", task.tid());
        task.set_ready();
        add_task(task);
    }
}

// 将任务从阻塞队列中移除（用于线程异常退出）
pub fn delete_wait(tid: Tid) {
    log::warn!("[remove] task{} removed from queue", tid);
    WAIT_MANAGER.delete(tid);
}

// 申请一个条件阻塞队列
pub fn alloc_wait_queue(name: &String) {
    WAIT_MANAGER.alloc_cond_queue(name);
}

// 释放一个条件阻塞队列
pub fn dealloc_wait_queue(name: &String) {
    WAIT_MANAGER.dealloc_cond_queue(name);
}

// 打印所有阻塞队列中的内容
pub fn dump_task_queue() -> () {
    for (name, que) in WAIT_MANAGER.wait_queue.lock().iter() {
        log::error!("dump wait queue: {}", name);
        que.dump_queue();
    }
}

pub struct WaitManager {
    // 阻塞队列
    // 其中使用"basic"来当做任务阻塞队列，创建条件队列请使用别的名字
    pub wait_queue: Mutex<HashMap<String, WaitQueue>>,
    // 反向映射表
    pub registry: Mutex<HashMap<Tid, String>>,
}

impl WaitManager {
    // 创建一个新的阻塞队列(初始带有一个basic队列当作任务阻塞队列)
    fn init() -> Self {
        let mut wait_queue = HashMap::new();
        wait_queue.insert("basic".to_string(), WaitQueue::new());
        WaitManager {
            wait_queue: Mutex::new(wait_queue),
            registry: Mutex::new(HashMap::new()),
        }
    }

    // 创建新的条件队列
    fn alloc_cond_queue(&self, name: &String) {
        let mut queue = self.wait_queue.lock();
        if queue.get(name).is_none() {
            queue.insert(name.to_string(), WaitQueue::new());
        }
    }

    // 释放条件队列
    fn dealloc_cond_queue(&self, name: &String) {
        let mut queue = self.wait_queue.lock();
        queue.remove(name);
    }

    // 向basic队列中添加一个任务
    fn add(&self, task: Arc<Task>) {
        let mut queue = self.wait_queue.lock();
        let mut registry = self.registry.lock();
        registry.insert(task.tid(), "basic".to_string());
        queue.get_mut("basic").unwrap().add(task);
    }

    // 向条件队列中添加一个任务
    fn add_cond(&self, name: &String, task: Arc<Task>) {
        let mut queue = self.wait_queue.lock();
        let mut registry = self.registry.lock();
        if let Some(cond_que) = queue.get_mut(name) {
            registry.insert(task.tid(), name.to_string());
            cond_que.add(task);
        } else {
            log::error!("[add_cond] queue {} not found", name);
        }
    }

    // 从条件队列中首部取出一个任务
    fn fetch_cond(&self, name: &String) -> Option<Arc<Task>> {
        let mut queue = self.wait_queue.lock();
        if let Some(cond_que) = queue.get_mut(name) {
            if let Some(task) = cond_que.fetch() {
                return Some(task);
            }
        }
        None
    }

    // 从阻塞队列中取出特定任务
    fn remove(&self, tid: Tid) -> Result<Arc<Task>, ()> {
        let mut queue = self.wait_queue.lock();
        let mut registry = self.registry.lock();
        if let Some(name) = registry.get(&tid) {
            if let Some(cond_que) = queue.get_mut(name) {
                if let Ok(task) = cond_que.remove(tid) {
                    registry.remove(&task.tid());
                    return Ok(task);
                }
            }
        }
        Err(())
    }

    // 从阻塞队列中删除特定任务
    fn delete(&self, tid: Tid) {
        let mut queue = self.wait_queue.lock();
        let registry = self.registry.lock();
        if let Some(name) = registry.get(&tid) {
            if let Some(cond_que) = queue.get_mut(name) {
                cond_que.remove(tid);
            }
        }
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
pub fn set_wait_alarm(dur: timer::TimeSpec, tid: Tid) -> TimeSpec {
    TIME_MANAGER.add_timer(dur, tid, -1, move || wakeup(tid))
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
        let keys_to_remove: vec::Vec<_> = guard.range(..&now).map(|(k, _)| k.clone()).collect();
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
                fields: SiField::None,
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

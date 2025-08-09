use crate::{
    arch::{config::SysResult, trap::context::dump_trap_context},
    clear_bss,
    signal::{SiField, Sig, SigInfo},
    syscall::errno::SyscallRet,
    task::{add_task, current_task, processor::current_tp, schedule, TimerFd},
    timer::{self, ITimerVal, TimeSpec},
};
use alloc::{
    boxed::Box,
    collections::{btree_map::BTreeMap, vec_deque::VecDeque},
    string::{String, ToString},
    sync::{Arc, Weak},
    vec::Vec,
};
use alloc::{task, vec};
use hashbrown::HashMap;
use lazy_static::lazy_static;
use rand::distributions::Alphanumeric;
use spin::Mutex;

use super::{
    task::Task, wait::WaitQueue, Tid, MAX_POSIX_TIMER_COUNT, SIGEV_COUNT, SIGEV_NONE, SIGEV_SIGNAL,
    SIGEV_THREAD, SIGEV_THREAD_ID,
};

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

// 暂停管理器
lazy_static! {
    static ref STOP_MANAGER: StopManager = StopManager::init();
}

/************************************** 核心管理器 **************************************/

// // 全局核心管理器
// pub struct CpuManager {
//     pub cpus: [CpuLocal; MAX_HART_COUNT], // 核心列表
// }

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
// 获取所有任务列表
pub fn get_all_tasks() -> Vec<Arc<Task>> {
    TASK_MANAGER.for_each(|task| task.clone())
}

#[cfg(feature = "virt")]
pub struct TaskManager(Mutex<HashMap<Tid, Weak<Task>>>);
#[cfg(feature = "board")]
pub struct TaskManager(Mutex<BTreeMap<Tid, Weak<Task>>>);

impl TaskManager {
    #[cfg(feature = "board")]
    pub fn new() -> Self {
        Self(Mutex::new(BTreeMap::new()))
    }
    #[cfg(feature = "virt")]
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
// 将当前任务加入到basic队列并阻塞
// 返回值：0：正常被唤醒； -1：被中断唤醒
pub fn wait() -> isize {
    log::trace!("[wait]");
    let task = current_task();
    task.set_interruptable();
    WAIT_MANAGER.add(task);
    log::warn!("[wait] task{} block", current_task().tid());
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
        #[cfg(feature = "cfs")]
        {
            // 保证任务在阻塞期间vruntime不变
            let se = task.sched_entity();
            se.update_exec_start(TimeSpec::new_machine_time());
        }
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

    // 取消指定tid的clock_id闹钟
    fn remove_timer(&self, tid: Tid, clock_id: ClockId) {
        let mut alarm = self.alarms.lock();
        alarm.retain(|_, vec| {
            vec.retain(|(t, c, _)| *t != tid || *c != clock_id);
            !vec.is_empty()
        });
    }
    fn remove_all_timer(&self, tid: Tid) {
        let mut alarm = self.alarms.lock();
        // 先移除所有与tid相关的闹钟
        alarm.retain(|_, vec| {
            vec.retain(|(t, _, _)| *t != tid);
            !vec.is_empty()
        });
    }

    // 取消指定pid的clock_id闹钟
    fn remove_pid_timers(&self, pid: usize, clock_id: ClockId) {
        let mut alarm = self.alarms.lock();
        alarm.retain(|_, vec| {
            vec.retain(|(t, c, _)| {
                if let Some(task) = get_task(*t) {
                    task.tgid() != pid || *c != clock_id
                } else {
                    true // 如果任务不存在，则保留该闹钟
                }
            });
            !vec.is_empty()
        });
    }

    // 执行超时回调 返回触发的tid列表
    fn split_off(&self) -> vec::Vec<Tid> {
        let now = TimeSpec::new_machine_time();
        let mut tids = vec![];
        let mut callbacks = vec![];
        // 第一步：先锁一次并记录所有要移除的键
        let mut guard = self.alarms.lock();
        // dump_time_manager();
        let keys_to_remove: vec::Vec<_> = guard.range(..=&now).map(|(k, _)| k.clone()).collect();
        // let keys_to_remove: Vec<_> = guard
        // .iter()
        // .filter(|(k, _)| {
        //     log::error!("[wakeup_timeout] now: {:?}, key: {:?}", now, k);
        //     *k <= &now
        // })
        // .map(|(k, _)| k.clone())
        // .collect();

        // 第二步：再移除这些键，收集对应的值
        for key in keys_to_remove {
            if let Some(entry) = guard.remove(&key) {
                for (tid, _clock_id, callback) in entry {
                    tids.push(tid);
                    callbacks.push(callback); // 收集回调函数, 释放self.alarms后调用
                }
            }
        }
        drop(guard); // 释放锁
        for cb in callbacks {
            cb(); // 执行回调函数
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

/// 移除tid的所有计时器
pub fn remove_all_timer(tid: Tid) {
    TIME_MANAGER.remove_all_timer(tid);
}

pub fn add_common_timer(tid: Tid, dur: TimeSpec, clock_id: ClockId, signo: i32) {
    TIME_MANAGER.add_timer(dur, tid, clock_id, move || {
        // 触发定时器
        common_timer_callback(tid, signo, clock_id);
    });
}

pub fn update_common_timer(tid: Tid, dur: TimeSpec, clock_id: ClockId, signo: i32) {
    TIME_MANAGER.update_timer(tid, clock_id, dur, move || {
        // 触发定时器
        common_timer_callback(tid, signo, clock_id);
    });
}

/// 注意clock_id + 3, 为了区分sys_settimer的三个定时器
pub fn add_posix_timer(tid: Tid, dur: TimeSpec, mut timerid: usize) {
    let clock_id = (timerid + 3) as ClockId; // 0-2是setitimer的定时器
    TIME_MANAGER.add_timer(dur, tid, clock_id, move || {
        posix_timer_callback(tid, timerid);
    });
}

// 由调用者确保该定时器存在
pub fn update_posix_timer(tid: Tid, timerid: usize, dur: TimeSpec) {
    let clock_id = (timerid + 3) as ClockId; // 0-2是setitimer的定时器
    TIME_MANAGER.update_timer(tid, clock_id, dur, move || {
        posix_timer_callback(tid, timerid);
    });
}

/// setitimer的回调函数
pub fn common_timer_callback(tid: Tid, signo: i32, clock_id: ClockId) {
    if let Some(task) = get_task(tid) {
        task.receive_siginfo(
            SigInfo {
                signo,
                code: SigInfo::TIMER,
                fields: SiField::Kill {
                    tid: current_task().tid() as i32,
                    uid: current_task().uid() as u32,
                },
            },
            true,
        );
        task.op_itimerval(|itimerval| {
            let itimerval = &itimerval[clock_id as usize];
            if itimerval.it_interval.is_zero() {
                // 不再设置定时器
                return;
            } else {
                // 重新设置定时器
                let dur = itimerval.it_interval;
                add_common_timer(tid, dur.into(), clock_id, signo);
            }
        })
    }
}

pub fn posix_timer_callback(tid: Tid, timerid: usize) {
    if let Some(task) = get_task(tid) {
        task.op_timers_mut(|timers| {
            if timerid >= MAX_POSIX_TIMER_COUNT {
                return;
            }
            let timer = &mut timers[timerid];
            match timer.event.sigev_notify {
                SIGEV_SIGNAL => {
                    log::info!(
                        "[posix_timer_callback] sending signal {} to task {}",
                        timer.event.sigev_signo,
                        tid
                    );
                    let unhandle_before = task.op_sig_pending_mut(|pending| {
                        pending
                            .pending
                            .contain_signal(Sig::from(timer.event.sigev_signo))
                    });
                    if unhandle_before {
                        timer.overrun += 1;
                    }
                    task.receive_siginfo(
                        SigInfo {
                            signo: timer.event.sigev_signo,
                            code: SigInfo::TIMER,
                            fields: SiField::Rt {
                                tid: current_task().tid() as i32,
                                uid: current_task().uid() as u32,
                                sival_int: timer.event.sigev_value as i32,
                                sival_ptr: timer.event.sigev_value as usize,
                            },
                        },
                        true,
                    );
                }
                SIGEV_NONE => {
                    // 不发送信号
                }
                SIGEV_THREAD => {
                    // Todo: 线程通知
                    unimplemented!("SIGEV_THREAD is not implemented yet");
                }
                SIGEV_THREAD_ID => {
                    // 线程ID通知, 这里可以实现线程ID通知逻辑
                    let task = get_task(timer.event.sigev_notify_thread_id as Tid);
                    if let Some(task) = task {
                        log::info!(
                            "[posix_timer_callback] sending signal {} to thread {}",
                            timer.event.sigev_signo,
                            timer.event.sigev_notify_thread_id
                        );
                        let unhandle_before = task.op_sig_pending_mut(|pending| {
                            pending
                                .pending
                                .contain_signal(Sig::from(timer.event.sigev_signo))
                        });
                        if unhandle_before {
                            timer.overrun += 1;
                        }
                        task.receive_siginfo(
                            SigInfo {
                                signo: timer.event.sigev_signo,
                                code: SigInfo::TIMER,
                                fields: SiField::Rt {
                                    tid: current_task().tid() as i32,
                                    uid: current_task().uid() as u32,
                                    sival_int: timer.event.sigev_value as i32,
                                    sival_ptr: timer.event.sigev_value as usize,
                                },
                            },
                            true,
                        );
                    } else {
                        log::warn!("[posix_timer_callback] task not found for sigev_thread_id");
                    }
                }
                SIGEV_COUNT => {
                    // 记录超时次数
                    log::info!(
                        "[posix_timer_callback] timer {} for task {} overrun: {}",
                        timerid,
                        tid,
                        timer.overrun + 1
                    );
                    timer.overrun += 1;
                    // 唤醒waiter
                    let timer_fd = task.fd_table().get_file(timer.event.sigev_value as usize);
                    if let Some(timer_fd) = timer_fd {
                        if let Some(timer_fd) = timer_fd.as_any().downcast_ref::<TimerFd>() {
                            // 唤醒等待该定时器的任务
                            timer_fd.wakeup_waiters();
                        } else {
                            log::error!("[posix_timer_callback] timer_fd is not a TimerFd",);
                        }
                    } else {
                        log::error!(
                            "[posix_timer_callback] timer_fd not found for fd {}",
                            timer.event.sigev_value
                        );
                    }
                }
                _ => {
                    log::error!(
                        "[posix_timer_callback] unknown sigev_notify type: {}",
                        timer.event.sigev_notify
                    );
                }
            }

            // 如果是周期性定时器，重新注册
            if !timer.itimer_sepc.it_interval.is_zero() {
                log::info!(
                    "[posix_timer_callback] re-registering timer {} for task {}, interval: {:?}",
                    timerid,
                    tid,
                    timer.itimer_sepc.it_interval
                );
                TIME_MANAGER.add_timer(
                    timer.itimer_sepc.it_interval,
                    tid,
                    (timerid + 3) as ClockId,
                    move || {
                        posix_timer_callback(tid, timerid);
                    },
                );
            } else {
                return; // 如果是单次定时器，不再设置
            }
        });
    }
}

#[allow(unused)]
pub fn dump_time_manager() {
    let alarms = TIME_MANAGER.alarms.lock();
    log::info!("[TimeManager] dump alarms:");
    for (time, entries) in alarms.iter() {
        log::info!("Time: {:?}", time);
        for (tid, clock_id, _) in entries {
            log::info!("  Task ID: {}, Clock ID: {}", tid, clock_id);
        }
    }
}

/************************************** 暂停管理器 **************************************/
/// 向暂停管理器中添加一个任务
pub fn stop_task() -> isize {
    let task = current_task();
    task.set_stopped();
    STOP_MANAGER.add(task);
    log::warn!("[stop] task{} stopped", current_task().tid());
    schedule(); // 调度其他任务
    return 0;
}

/// 从暂停管理器中恢复某一个任务
pub fn continue_task(tid: Tid) {
    if let Ok(task) = STOP_MANAGER.remove(tid) {
        #[cfg(feature = "cfs")]
        {
            // 保证任务在阻塞期间vruntime不变
            let se = task.sched_entity();
            se.update_exec_start(TimeSpec::new_machine_time());
        }
        task.set_ready();
        add_task(task);
    }
}

pub struct StopManager {
    // 暂停队列
    pub stop_queue: Mutex<VecDeque<Arc<Task>>>,
}

impl StopManager {
    // 创建一个新的暂停队列
    fn init() -> Self {
        let stop_queue = VecDeque::new();
        StopManager {
            stop_queue: Mutex::new(stop_queue),
        }
    }

    // 向暂停队列中添加一个任务
    fn add(&self, task: Arc<Task>) {
        let mut queue = self.stop_queue.lock();
        queue.push_back(task);
    }

    // 从暂停队列中取出特定任务
    fn remove(&self, tid: Tid) -> Result<Arc<Task>, ()> {
        let mut queue = self.stop_queue.lock();
        if let Some(pos) = queue.iter().position(|task| task.tid() == tid) {
            return Ok(queue.remove(pos).unwrap());
        }
        Err(())
    }

    // 从暂停队列中删除特定任务
    fn delete(&self, tid: Tid) {
        let mut queue = self.stop_queue.lock();
        queue.retain(|task| task.tid() != tid);
    }
}
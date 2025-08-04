use alloc::{sync::Arc, vec::Vec};
use core::{
    default,
    sync::atomic::AtomicUsize,
    time::{self, Duration},
};
use spin::Mutex;

use crate::{
    fs::file::{FileOp, OpenFlags},
    syscall::errno::Errno,
    task::wakeup,
    timer::ITimerSpec,
};

use super::{current_task, wait, Tid};

pub const MAX_POSIX_TIMER_COUNT: usize = 16;

pub const SIGEV_SIGNAL: i32 = 0; // 信号通知
pub const SIGEV_NONE: i32 = 1; // 无通知
pub const SIGEV_THREAD: i32 = 2; // 线程通知
pub const SIGEV_THREAD_ID: i32 = 4; // 线程ID通知
pub const SIGEV_COUNT: i32 = 5; // 无通知, 记录超时次数

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub enum ClockId {
    RealTime,
    Monotonic,
    ProcessCpuTimeId,
    ThreadCpuTimeId,
    MonotonicRaw,
    RealTimeCoarse,
    MonotonicCoarse,
    BootTime,
    RealTimeAlarm,
    BootTimeAlarm,
    SgiCycle,
    Tai,
    #[default]
    IDLE = 666,
}

impl TryFrom<usize> for ClockId {
    type Error = Errno;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ClockId::RealTime),
            1 => Ok(ClockId::Monotonic),
            2 => Ok(ClockId::ProcessCpuTimeId),
            3 => Ok(ClockId::ThreadCpuTimeId),
            4 => Ok(ClockId::MonotonicRaw),
            5 => Ok(ClockId::RealTimeCoarse),
            6 => Ok(ClockId::MonotonicCoarse),
            7 => Ok(ClockId::BootTime),
            8 => Ok(ClockId::RealTimeAlarm),
            9 => Ok(ClockId::BootTimeAlarm),
            10 => Ok(ClockId::SgiCycle),
            11 => Ok(ClockId::Tai),
            _ => Err(Errno::EINVAL), // Invalid argument
        }
    }
}

pub enum SigeventNotify {
    None,
    Signal { signo: i32, sigval: usize },
    Thread,
    ThreadId { tid: usize, signo: i32 },
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Sigevent {
    pub sigev_value: u64,         // 信号值, union { sival_int: i32, sival_ptr: u64 }
    pub sigev_signo: i32,         // signal编号
    pub sigev_notify: i32,        // 通知方式
    sigev_notify_function: u64,   // 通知函数
    sigev_notify_attributes: u64, // 通知属性
    pub sigev_notify_thread_id: u64, // 通知线程ID
}

// 当sevp指针为NULL时, 使用默认值, sigev_notify = SIGEV_SIGNAL, sigev_signo = SIGALRM, sigev_value.sival_int = timer ID
impl Default for Sigevent {
    fn default() -> Self {
        Self {
            sigev_notify: 1, // SIGEV_SIGNAL
            sigev_signo: 14, // SIGALRM
            sigev_value: 0,
            sigev_notify_function: 0,
            sigev_notify_attributes: 0,
            sigev_notify_thread_id: 0,
        }
    }
}

impl Sigevent {
    pub fn fd_event(fd: usize) -> Self {
        Self {
            sigev_notify: SIGEV_COUNT,
            sigev_signo: 0,
            sigev_value: fd as u64,
            sigev_notify_function: 0,
            sigev_notify_attributes: 0,
            sigev_notify_thread_id: 0,
        }
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct PosixTimer {
    pub id: usize,               // 唯一的定时器 ID
    pub clock_id: ClockId,       // 时钟类型(CLOCK_MONOTONIC 等）
    pub event: Sigevent,         // 到期后的通知方式
    pub itimer_sepc: ITimerSpec, // 是否周期性
    pub overrun: usize,          // 超过多少次未处理
}

impl PosixTimer {
    pub fn new(clock_id: ClockId, event: Sigevent) -> Self {
        Self {
            id: 0, // ID 需要在内核中分配
            clock_id,
            event,
            itimer_sepc: ITimerSpec::default(),
            overrun: 0,
        }
    }
    pub fn idle() -> Self {
        Self {
            id: 0,
            clock_id: ClockId::IDLE,
            event: Sigevent::default(),
            itimer_sepc: ITimerSpec::default(),
            overrun: 0,
        }
    }
}

pub const TFD_NONBLOCK: i32 = 0o0004000;
pub const TFD_CLOEXEC: i32 = 0o02000000;
const POLLIN: u32 = 0x001;
/// 内核中代表 timerfd 对象的数据结构
pub struct TimerFd {
    pub id: usize,
    clock_id: ClockId,
    is_nonblocking: bool,
    // timer: Mutex<PosixTimer>,      // 假设你已有 PosixTimer 实现
    wait_queue: Mutex<Vec<Tid>>, // 等待队列
}

impl TimerFd {
    pub fn new(clock_id: ClockId, flags: i32) -> Result<Arc<Self>, Errno> {
        // 查找空闲的PosixTimer
        let id = current_task().op_timers_mut(|timers| {
            // 查找空闲的PosixTimer
            for (i, timer) in timers.iter_mut().enumerate() {
                if timer.clock_id == ClockId::IDLE {
                    timer.clock_id = clock_id; // 设置时钟ID
                    timer.id = i; // 设置ID
                    return Ok(i);
                }
            }
            return Err(Errno::ENOSPC); // 没有空闲的PosixTimer
        })?;
        Ok(Arc::new(Self {
            id,
            clock_id,
            is_nonblocking: flags & TFD_NONBLOCK != 0,
            // timer: Mutex::new(PosixTimer::new(clock_id)?),
            wait_queue: Mutex::new(Vec::new()),
        }))
    }
    pub fn wakeup_waiters(&self) {
        let mut wait_queue = self.wait_queue.lock();
        for &tid in wait_queue.iter() {
            log::warn!("[Pipe::drop] wake up waiter: {}", tid);
            wakeup(tid);
        }
        wait_queue.clear(); // 清空等待队列
    }
    fn add_waiter(&self, tid: Tid) {
        self.wait_queue.lock().push(tid);
    }
    fn expiration_count(&self) -> usize {
        // 根据id获取当前定时器的过期计数
        current_task().op_timers_mut(|timers| {
            let timer = &timers[self.id];
            if timer.overrun > 0 {
                // 返回过期计数
                let count = timer.overrun;
                // 重置过期计数
                // timers[self.id].overrun = 0;
                count
            } else {
                // 没有过期计数, 返回0
                0
            }
        })
    }
    fn clear_expiration_count(&self) {
        // 清除过期计数
        current_task().op_timers_mut(|timers| {
            timers[self.id].overrun = 0;
        });
    }
}

impl FileOp for TimerFd {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        if buf.len() < 8 {
            return Err(Errno::EINVAL);
        }

        let count = self.expiration_count();
        if self.expiration_count() == 0 {
            if self.is_nonblocking {
                return Err(Errno::EAGAIN);
            } else {
                // self.wait_queue.wait_interruptible()?;
                self.add_waiter(current_task().tid());
                if wait() == -1 {
                    log::warn!("[TimerFd::read] wait interrupted");
                    return Err(Errno::ERESTARTSYS);
                }
            }
        }
        // 清除过期计数
        self.clear_expiration_count();

        buf[..8].copy_from_slice(&count.to_ne_bytes());
        Ok(8)
    }
    fn hang_up(&self) -> bool {
        false
    }
    fn readable(&self) -> bool {
        true
    }
    fn r_ready(&self) -> bool {
        self.expiration_count() > 0
    }
    fn w_ready(&self) -> bool {
        false // TimerFd 通常不支持写操作
    }
    fn writable(&self) -> bool {
        false
    }
    fn add_wait_queue(&self, tid: usize) {
        self.add_waiter(tid);
    }
    fn get_flags(&self) -> OpenFlags {
        if self.is_nonblocking {
            OpenFlags::O_NONBLOCK
        } else {
            OpenFlags::empty()
        }
    }
    fn set_flags(&self, _flags: OpenFlags) {
        // TimerFd 通常不支持修改标志
        // 但可以在创建时设置非阻塞标志
        log::warn!("set_flags is not supported for TimerFd");
    }
}

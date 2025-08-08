use core::{cell::UnsafeCell, time};

use spin::Mutex;

use super::errno::SyscallRet;
use crate::{
    arch::{
        config::PAGE_SIZE,
        mm::{copy_from_user, copy_to_user},
        sbi::shutdown,
    },
    bpf::{uapi::BpfCmd, *},
    fs::{
        fdtable::FdFlags,
        file::OpenFlags,
        namei::path_openat,
        proc::tainted,
        uapi::{RLimit, Resource},
    },
    signal::Sig,
    syscall::errno::Errno,
    task::{
        add_common_timer, add_posix_timer, current_task, get_all_tasks, get_task, remove_timer,
        rusage::RUsage, update_common_timer, update_posix_timer, ClockId, PosixTimer, Sigevent,
        TimerFd, ITIMER_PROF, ITIMER_REAL, ITIMER_VIRTUAL, MAX_POSIX_TIMER_COUNT, TFD_CLOEXEC,
        TFD_NONBLOCK,
    },
    time::{config::ClockIdFlags, do_adjtimex, KernelTimex, LAST_TIMEX},
    timer::{ITimerSpec, ITimerVal, TimeSpec, TimeVal},
};
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Utsname {
    /// 系统名称
    pub sysname: [u8; 65],
    /// 网络上主机名称 from etc/hostname
    pub nodename: [u8; 65],
    /// 发行编号
    pub release: [u8; 65],
    /// 版本
    pub version: [u8; 65],
    /// 域名
    pub machine: [u8; 65],
    ///domainname
    pub domainname: [u8; 65],
}

impl Default for Utsname {
    fn default() -> Self {
        Self {
            sysname: Self::from_str("Linux"),
            nodename: Self::from_str("LAPTOP"),
            release: Self::from_str("5.15.146.1-standard"),
            version: Self::from_str("#1 SMP Thu Jan"),
            machine: Self::from_str("RISC-V SiFive Freedom U740 SoC"),
            domainname: Self::from_str("SHY"),
        }
    }
}

impl Utsname {
    fn from_str(info: &str) -> [u8; 65] {
        let mut data: [u8; 65] = [0; 65];
        data[..info.len()].copy_from_slice(info.as_bytes());
        data
    }
    pub fn set_nodename(&mut self, nodename: &[u8]) {
        //not longer than 64 bytes
        let len = core::cmp::min(nodename.len(), 64);
        self.nodename = [0u8; 65];
        self.nodename[..len].copy_from_slice(&nodename[..len]);
    }
    pub fn set_domainname(&mut self, domainname: &[u8]) {
        //not longer than 64 bytes
        let len = core::cmp::min(domainname.len(), 64);
        self.domainname = [0u8; 65];
        self.domainname[..len].copy_from_slice(&domainname[..len]);
    }
}

/// sys_times, 单位都是us
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Tms {
    /// CPU time spent executing instructions of the calling process
    pub utime: usize,
    /// inside the kernel
    pub stime: usize,
    /// the sum of the utime for all waited-for teminated children
    pub cutime: usize,
    /// the sum of stime for all waited-for teminated children
    pub cstime: usize,
}

impl Tms {
    fn new() -> Self {
        let task = current_task();
        let time_stat = task.time_stat();
        let utime = time_stat.user_time();
        let stime = time_stat.sys_time();
        let (cutime, cstime) = time_stat.child_user_system_time();
        Self {
            utime: utime.as_us(),
            stime: stime.as_us(),
            cutime: cutime.as_us(),
            cstime: cstime.as_us(),
        }
    }
}

/// fake uname  
///
/// Todo?:
pub fn sys_uname(uts: usize) -> SyscallRet {
    log::info!("[sys_uname] uts: {:#x}", uts);
    let uts = uts as *mut Utsname;
    //Todo!: check validarity
    let mut utsname = Utsname::default();
    //todo:还差其他的
    let hostnamefile = path_openat("/etc/hostname", OpenFlags::O_CLOEXEC, -100, 0)?;
    let nodename = hostnamefile.read_all();
    log::error!("[sys_uname] nodename is {:?}", nodename);
    if nodename.len() > 0 {
        utsname.set_nodename(nodename.as_slice());
    }
    let domainnamefile = path_openat("/etc/domainname", OpenFlags::O_CLOEXEC, -100, 0)?;
    let domainname = domainnamefile.read_all();
    log::error!("[sys_uname] domainname is {:?}", domainname);
    if domainname.len() > 0 {
        utsname.set_domainname(domainname.as_slice());
    }
    copy_to_user(uts, &utsname as *const Utsname, 1)?;
    Ok(0)
}

/// fake sys_times
/// Todo?:
#[allow(unused)]
pub fn sys_times(buf: usize) -> SyscallRet {
    let buf = buf as *mut Tms;
    let tms = Tms::new();
    copy_to_user(buf, &tms as *const Tms, 1)?;
    Ok(0)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SyslogAction {
    CLOSE = 0,
    OPEN = 1,
    READ = 2,
    READ_ALL = 3,
    READ_CLEAR = 4,
    CLEAR = 5,
    CONSOLE_OFF = 6,
    CONSOLE_ON = 7,
    CONSOLE_LEVEL = 8,
    SIZE_UNREAD = 9,
    SIZE_BUFFER = 10,
    #[default]
    ILLEAGAL,
}

impl TryFrom<usize> for SyslogAction {
    type Error = Errno;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SyslogAction::CLOSE),
            1 => Ok(SyslogAction::OPEN),
            2 => Ok(SyslogAction::READ),
            3 => Ok(SyslogAction::READ_ALL),
            4 => Ok(SyslogAction::READ_CLEAR),
            5 => Ok(SyslogAction::CLEAR),
            6 => Ok(SyslogAction::CONSOLE_OFF),
            7 => Ok(SyslogAction::CONSOLE_ON),
            8 => Ok(SyslogAction::CONSOLE_LEVEL),
            9 => Ok(SyslogAction::SIZE_UNREAD),
            10 => Ok(SyslogAction::SIZE_BUFFER),
            _ => Err(Errno::EINVAL),
        }
    }
}

pub fn sys_syslog(log_type: usize, buf: *mut u8, len: isize) -> SyscallRet {
    log::info!(
        "[syslog]log_type is {:?},buf is {:?},len is {:?}",
        log_type,
        buf,
        len
    );
    let task = current_task();
    if task.egid() != 0 && task.euid() != 0 {
        return Err(Errno::EPERM);
    }
    if buf.is_null() || len <= 1 {
        return Err(Errno::EINVAL);
    }
    const LOG_BUF_LEN: usize = 4096;
    const LOG: &str = "<5>[    0.000000] Linux version 5.10.102.1-microsoft-standard-WSL2 (rtrt@TEAM-NPUCORE) (gcc (Ubuntu 9.4.0-1ubuntu1~20.04) 9.4.0, GNU ld (GNU Binutils for Ubuntu) 2.34) #1 SMP Thu Mar 10 13:31:47 CST 2022";
    // let token = current_user_token();
    let log_type = SyslogAction::try_from(log_type)?;
    let log = LOG.as_bytes();
    let len = LOG.len().min(len as usize);
    if log_type == SyslogAction::CONSOLE_LEVEL && len > 8 {
        return Err(Errno::EINVAL);
    }
    match log_type {
        SyslogAction::CLOSE | SyslogAction::OPEN => Ok(0),
        SyslogAction::READ => copy_to_user(buf, log.as_ptr(), len),
        SyslogAction::READ_ALL => copy_to_user(buf, log.as_ptr(), len),
        _ => {
            log::error!("[sys_syslog] Unsupported syslog action: {:?}", log_type);
            return Err(Errno::ENOSYS);
        } // SyslogAction::READ_CLEAR => todo!(),
          // SyslogAction::CLEAR => todo!(),
          // SyslogAction::CONSOLE_OFF => todo!(),
          // SyslogAction::CONSOLE_ON => todo!(),
          // SyslogAction::CONSOLE_LEVEL => todo!(),
          // SyslogAction::SIZE_UNREAD => todo!(),
          // SyslogAction::SIZE_BUFFER => Ok(LOG_BUF_LEN),
          // SyslogAction::ILLEAGAL => return Err(Errno::EINVAL),
    }
}

// Todo: 检查当前进程是否有权限修改其他进程的rlimit, 检查是否有权限修改硬限制
pub fn sys_prlimit64(
    pid: usize,
    resource: i32,
    new_limit: *const RLimit,
    old_limit: *mut RLimit,
) -> SyscallRet {
    // 根据tid获取操作的进程
    let task = if pid == 0 {
        current_task()
    } else {
        get_task(pid).expect("[sys_prlimit64]: invalid pid")
    };
    let resource = Resource::try_from(resource)?;
    log::error!(
        "resource: {:?}, new_limit: {:#x}, old_limit: {:#x}",
        resource,
        new_limit as usize,
        old_limit as usize
    );
    // 如果old_limit不为NULL, 则将当前的rlimit写入old_limit
    if !old_limit.is_null() {
        let old_rlimit = task
            .get_rlimit(resource)
            .expect("[sys_prlimit64] get rlimit failed");
        // 这里需要copy_to_user
        copy_to_user(old_limit, &old_rlimit as *const RLimit, 1)?;
    }
    // 如果new_limit不为NULL, 则将new_limit写入当前的rlimit
    if !new_limit.is_null() {
        let mut limit_buf = RLimit::default();
        copy_from_user(new_limit, &mut limit_buf as *mut RLimit, 1)?;
        return task.set_rlimit(resource, &limit_buf);
    }
    Ok(0)
}

pub fn sys_getrlimit(resource: i32, rlim: *mut RLimit) -> SyscallRet {
    // 这里等价于 prlimit64(pid=0, new_limit=NULL, old_limit=rlim)
    sys_prlimit64(0, resource, core::ptr::null(), rlim)
}

pub fn sys_setrlimit(resource: i32, rlim: *const RLimit) -> SyscallRet {
    // 这里等价于 prlimit64(pid=0, new_limit=rlim, old_limit=NULL)
    sys_prlimit64(0, resource, rlim, core::ptr::null_mut())
}

// clockid
pub const SUPPORT_CLOCK: usize = 2;
/// 一个可设置的系统级实时时钟，用于测量真实（即墙上时钟）时间
pub const CLOCK_REALTIME: usize = 0;
/// 一个不可设置的系统级时钟，代表自某个未指定的过去时间点以来的单调时间
pub const CLOCK_MONOTONIC: usize = 1;
/// 用于测量调用进程消耗的CPU时间
pub const CLOCK_PROCESS_CPUTIME_ID: usize = 2;
/// 用于测量调用线程消耗的CPU时间
pub const CLOCK_THREAD_CPUTIME_ID: usize = 3;
/// 一个不可设置的系统级时钟，代表自某个未指定的过去时间点以来的单调时间
pub const CLOCK_MONOTONIC_RAW: usize = 4;
/// 一个不可设置的系统级实时时钟，用于测量真实（即墙上时钟）时间
pub const CLOCK_REALTIME_COARSE: usize = 5;
pub const CLOCK_MONOTONIC_COARSE: usize = 6;
pub const CLOCK_BOOTTIME: usize = 7;
pub const CLOCK_REALTIME_ALARM: usize = 8;
pub const CLOCK_BOOTTIME_ALARM: usize = 9;
pub const CLOCK_SGI_CYCLE: usize = 10; // SGI Cycle Counter
pub const CLOCK_TAI: usize = 11; // TAI时钟

pub const CPUCLOCK_PROF: usize = 0; // 000 - 进程总CPU时间(用户+内核)
pub const CPUCLOCK_VIRT: usize = 1; // 001 - 进程用户态CPU时间
pub const CPUCLOCK_SCHED: usize = 2; // 010 - 调度器时钟
pub const CPUCLOCK_MAX: usize = 3; // 011 - 最大时钟ID

pub fn sys_clock_gettime(clock_id: usize, timespec: *mut TimeSpec) -> SyscallRet {
    //如果tp是NULL, 函数不会存储时间值, 但仍然会执行其他检查（如 `clockid` 是否有效）。
    if timespec.is_null() {
        return Ok(0);
    }
    match clock_id {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE | CLOCK_REALTIME_ALARM | CLOCK_TAI => {
            let time = TimeSpec::new_wall_time();
            // 8.4 Debug
            log::info!("[sys_clock_gettime] CLOCK_REALTIME: {:?}", time);
            copy_to_user(timespec, &time as *const TimeSpec, 1)?;
        }
        CLOCK_MONOTONIC
        | CLOCK_MONOTONIC_RAW
        | CLOCK_MONOTONIC_COARSE
        | CLOCK_BOOTTIME
        | CLOCK_BOOTTIME_ALARM => {
            let time = TimeSpec::new_machine_time();
            // log::info!("[sys_clock_gettime] CLOCK_MONOTONIC: {:?}", time);
            copy_to_user(timespec, &time as *const TimeSpec, 1)?;
        }
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => {
            // let time = TimeSpec::new_process_time();
            let task = current_task();
            let (utime, stime) = task.process_us_time();
            let time = TimeSpec::from(utime + stime);
            // log::info!("[sys_clock_gettime] CLOCK_PROCESS_CPUTIME_ID: {:?}", time);
            copy_to_user(timespec, &time as *const TimeSpec, 1)?;
        }
        _ => {
            // 解析 Dynamic clocks
            let tid = (!(clock_id) >> 3);
            let dyn_clock_id = clock_id & 0b11;
            if let Some(task) = get_task(tid) {
                match dyn_clock_id {
                    CPUCLOCK_PROF | CPUCLOCK_SCHED => {
                        let time: TimeSpec = task.time_stat().user_time().into();
                        copy_to_user(timespec, &time as *const TimeSpec, 1)?;
                    }
                    CPUCLOCK_VIRT => {
                        let time: TimeSpec = task.time_stat().user_time().into();
                        copy_to_user(timespec, &time as *const TimeSpec, 1)?;
                    }
                    _ => {
                        log::error!(
                            "[sys_clock_gettime] Unsupported dynamic clock_id: {}",
                            dyn_clock_id
                        );
                        return Err(Errno::EINVAL);
                    }
                }
            } else {
                log::error!("[sys_clock_gettime] task {:#b} not found", tid);
                return Err(Errno::EINVAL);
            }
        }
    }
    Ok(0)
}
pub fn sys_clock_settime(clock_id: usize, timespec: *const TimeSpec) -> SyscallRet {
    if timespec.is_null() {
        return Ok(0);
    }
    log::error!("[sys_clock_settime] clock_id is {:?}", clock_id);
    let mut time = TimeSpec::default();
    copy_from_user(timespec, &mut time as *mut TimeSpec, 1)?;
    if !time.timespec_valid_settod() {
        log::error!("[sys_clock_settime] timespec is invalid: {:?}", time);
        return Err(Errno::EINVAL);
    }
    match clock_id {
        CLOCK_MONOTONIC
        | CLOCK_MONOTONIC_RAW
        | CLOCK_REALTIME_COARSE
        | CLOCK_PROCESS_CPUTIME_ID => {
            return Err(Errno::EINVAL);
        }

        CLOCK_REALTIME => {
            return Ok(0);
        }

        _ => {
            // panic!("[sys_clock_gettime] invalid clock_id: {}", clock_id);
            return Err(Errno::EINVAL);
        }
    }
    Ok(0)
}

pub fn sys_getitimer(which: i32, value_ptr: *mut ITimerVal) -> SyscallRet {
    if which > 2 {
        return Err(Errno::EINVAL);
    }
    let task = current_task();
    match which {
        ITIMER_REAL => task.op_itimerval_mut(|itimerval| {
            let real_itimeval = &itimerval[which as usize];
            log::info!(
                "[sys_getitimer] it_value: {:?}, it_interval: {:?}",
                real_itimeval.it_value,
                real_itimeval.it_interval
            );
            let current_time = TimeVal::new_wall_time();
            let old_it_value = if real_itimeval.it_value < current_time {
                TimeVal { sec: 0, usec: 0 }
            } else {
                real_itimeval.it_value - current_time
            };
            let old = ITimerVal {
                it_value: old_it_value,
                it_interval: real_itimeval.it_interval,
            };
            copy_to_user(value_ptr, &old as *const ITimerVal, 1)?;
            Ok(0)
        }),
        ITIMER_VIRTUAL => task.op_itimerval_mut(|itimerval| {
            let real_itimeval = &itimerval[which as usize];
            log::info!(
                "[sys_getitimer] it_value: {:?}, it_interval: {:?}",
                real_itimeval.it_value,
                real_itimeval.it_interval
            );
            let current_time = TimeVal::new_wall_time();
            let old_it_value = if real_itimeval.it_value < current_time {
                TimeVal { sec: 0, usec: 0 }
            } else {
                real_itimeval.it_value - current_time
            };
            let old = ITimerVal {
                it_value: old_it_value,
                it_interval: real_itimeval.it_interval,
            };
            copy_to_user(value_ptr, &old as *const ITimerVal, 1)?;
            Ok(0)
        }),
        ITIMER_PROF => task.op_itimerval_mut(|itimerval| {
            let real_itimeval = &itimerval[which as usize];
            log::info!(
                "[sys_getitimer] it_value: {:?}, it_interval: {:?}",
                real_itimeval.it_value,
                real_itimeval.it_interval
            );
            let current_time = TimeVal::new_wall_time();
            let old_it_value = if real_itimeval.it_value < current_time {
                TimeVal { sec: 0, usec: 0 }
            } else {
                real_itimeval.it_value - current_time
            };
            let old = ITimerVal {
                it_value: old_it_value,
                it_interval: real_itimeval.it_interval,
            };
            copy_to_user(value_ptr, &old as *const ITimerVal, 1)?;
            Ok(0)
        }),
        _ => {
            log::error!("Unexpected which");
            return Err(Errno::EINVAL);
        }
    }
}

pub fn sys_setitimer(
    which: i32,
    value_ptr: *const ITimerVal,
    ovalue_ptr: *mut ITimerVal,
) -> SyscallRet {
    if which > 2 {
        return Err(Errno::EINVAL);
    }
    let mut new = ITimerVal::default();
    copy_from_user(value_ptr, &mut new as *mut ITimerVal, 1)?;
    if !new.is_valid() {
        return Err(Errno::EINVAL);
    }
    log::info!(
        "[sys_setitimer] which: {}, it_value: {:?}, it_interval: {:?}",
        which,
        new.it_value,
        new.it_interval
    );
    match which {
        ITIMER_REAL => {
            let task = current_task();
            // 启用定时器
            let (should_update, old) = task.op_itimerval_mut(|itimerval| {
                let real_itimeval = &mut itimerval[which as usize];
                let should_update =
                    !real_itimeval.it_value.is_zero() || !real_itimeval.it_interval.is_zero();
                // 计算旧的定时器值(it_value)剩余时间
                let current_time = TimeVal::new_wall_time();
                let old_it_value = if real_itimeval.it_value < current_time {
                    TimeVal { sec: 0, usec: 0 }
                } else {
                    real_itimeval.it_value - current_time
                };
                let old = ITimerVal {
                    it_value: old_it_value,
                    it_interval: real_itimeval.it_interval,
                };
                log::warn!("old_value: {:?}", old);
                // 设定新的定时器值
                real_itimeval.it_value = current_time + new.it_value;
                real_itimeval.it_interval = new.it_interval;
                (should_update, old)
            });
            // 将旧的定时器值写入ovalue_ptr
            if !ovalue_ptr.is_null() {
                copy_to_user(ovalue_ptr, &old as *const ITimerVal, 1)?;
            }
            // 禁用定时器
            if new.it_value.is_zero() {
                log::info!("[sys_setitimer] disable timer");
                remove_timer(task.tid(), ITIMER_REAL);
                return Ok(0);
            }
            // 设置或更新已有定时器
            if should_update {
                log::warn!("[sys_setitimer] update timer");
                update_common_timer(
                    task.tid(),
                    new.it_value.into(),
                    ITIMER_REAL,
                    Sig::SIGALRM.raw(),
                );
            } else {
                add_common_timer(
                    task.tid(),
                    new.it_value.into(),
                    ITIMER_REAL,
                    Sig::SIGALRM.raw(),
                );
            }
            return Ok(0);
        }
        ITIMER_VIRTUAL => {
            // return Err(Errno::ENOSYS);
            // Todo:
            log::warn!("[sys_setitimer] ITIMER_VIRTUAL Unimplemented");
            let task = current_task();
            // 启用定时器
            let (should_update, old) = task.op_itimerval_mut(|itimerval| {
                let real_itimeval = &mut itimerval[which as usize];
                let should_update =
                    !real_itimeval.it_value.is_zero() || !real_itimeval.it_interval.is_zero();
                // 计算旧的定时器值(it_value)剩余时间
                let current_time = TimeVal::new_wall_time();
                let old_it_value = if real_itimeval.it_value < current_time {
                    TimeVal { sec: 0, usec: 0 }
                } else {
                    real_itimeval.it_value - current_time
                };
                let old = ITimerVal {
                    it_value: old_it_value,
                    it_interval: real_itimeval.it_interval,
                };
                log::warn!("old_value: {:?}", old);
                // 设定新的定时器值
                real_itimeval.it_value = current_time + new.it_value;
                real_itimeval.it_interval = new.it_interval;
                (should_update, old)
            });
            // 将旧的定时器值写入ovalue_ptr
            if !ovalue_ptr.is_null() {
                copy_to_user(ovalue_ptr, &old as *const ITimerVal, 1)?;
            }
            // 禁用定时器
            if new.it_value.is_zero() {
                log::info!("[sys_setitimer] disable timer");
                remove_timer(task.tid(), ITIMER_VIRTUAL);
                return Ok(0);
            }
            // 设置或更新已有定时器
            if should_update {
                log::warn!("[sys_setitimer] update timer");
                update_common_timer(
                    task.tid(),
                    new.it_value.into(),
                    ITIMER_VIRTUAL,
                    Sig::SIGVTALRM.raw(),
                );
            } else {
                add_common_timer(
                    task.tid(),
                    new.it_value.into(),
                    ITIMER_VIRTUAL,
                    Sig::SIGVTALRM.raw(),
                );
            }
            return Ok(0);
        }
        ITIMER_PROF => {
            // return Err(Errno::ENOSYS);
            //     // Todo:
            log::warn!("[sys_setitimer] ITIMER_PROF Unimplemented");
            let task = current_task();
            // 启用定时器
            let (should_update, old) = task.op_itimerval_mut(|itimerval| {
                let real_itimeval = &mut itimerval[which as usize];
                let should_update =
                    !real_itimeval.it_value.is_zero() || !real_itimeval.it_interval.is_zero();
                // 计算旧的定时器值(it_value)剩余时间
                let current_time = TimeVal::new_wall_time();
                let old_it_value = if real_itimeval.it_value < current_time {
                    TimeVal { sec: 0, usec: 0 }
                } else {
                    real_itimeval.it_value - current_time
                };
                let old = ITimerVal {
                    it_value: old_it_value,
                    it_interval: real_itimeval.it_interval,
                };
                log::warn!("old_value: {:?}", old);
                // 设定新的定时器值
                real_itimeval.it_value = current_time + new.it_value;
                real_itimeval.it_interval = new.it_interval;
                (should_update, old)
            });
            // 将旧的定时器值写入ovalue_ptr
            if !ovalue_ptr.is_null() {
                copy_to_user(ovalue_ptr, &old as *const ITimerVal, 1)?;
            }
            // 禁用定时器
            if new.it_value.is_zero() {
                log::info!("[sys_setitimer] disable timer");
                remove_timer(task.tid(), ITIMER_PROF);
                return Ok(0);
            }
            // 设置或更新已有定时器
            if should_update {
                log::warn!("[sys_setitimer] update timer");
                update_common_timer(
                    task.tid(),
                    new.it_value.into(),
                    ITIMER_PROF,
                    Sig::SIGPROF.raw(),
                );
            } else {
                add_common_timer(
                    task.tid(),
                    new.it_value.into(),
                    ITIMER_PROF,
                    Sig::SIGPROF.raw(),
                );
            }
            return Ok(0);
        }
        _ => {
            log::error!("Unexpected which");
            return Err(Errno::EINVAL);
        }
    };
}

pub fn sys_timerfd_create(clock_id: usize, flags: i32) -> SyscallRet {
    let clock_id = ClockId::try_from(clock_id)?;
    // 检查flags是否合法
    if flags & !(TFD_CLOEXEC | TFD_NONBLOCK) != 0 {
        return Err(Errno::EINVAL);
    }
    let fd_flags = if flags & TFD_CLOEXEC != 0 {
        FdFlags::FD_CLOEXEC
    } else {
        FdFlags::empty()
    };
    let task = current_task();
    let timer_fd = TimerFd::new(clock_id, flags)?;
    let timerid = timer_fd.id;
    let fd = task.fd_table().alloc_fd(timer_fd, fd_flags)?;
    // 更新定时器posix_timer.event的sigev_value记录对应的fd
    task.op_timers_mut(|timers| {
        // 设置定时器的sigevent
        timers[timerid].event = Sigevent::fd_event(fd);
    });
    Ok(fd)
}

const TFD_TIMER_ABSTIME: i32 = 0x1; // 绝对时间
const TFD_TIMER_CANCEL_ON_SET: i32 = 0x2; // 设置时取消定时器

// pub fn sys_timerfd_gettime(
pub fn sys_timerfd_settime(
    fd: usize,
    flags: i32,
    new_value_ptr: *const ITimerSpec,
    old_value_ptr: *mut ITimerSpec,
) -> SyscallRet {
    log::error!(
        "[sys_timerfd_settime] fd: {}, flags: {}, new_value_ptr: {:#x}, old_value_ptr: {:#x}",
        fd,
        flags,
        new_value_ptr as usize,
        old_value_ptr as usize
    );
    // 检查flags是否合法
    if flags & !(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET) != 0 {
        return Err(Errno::EINVAL);
    }
    let task = current_task();
    let timer_fd = task.fd_table().get_file(fd).ok_or(Errno::EBADF)?;
    let timer_fd = timer_fd
        .as_any()
        .downcast_ref::<TimerFd>()
        .ok_or(Errno::EINVAL)?;
    let mut new_value = ITimerSpec::default();
    if !new_value_ptr.is_null() {
        copy_from_user(new_value_ptr, &mut new_value as *mut ITimerSpec, 1)?;
        if !new_value.is_valid() {
            return Err(Errno::EINVAL);
        }
    }
    // 8.4 Debug
    log::info!("[sys_timerfd_settime] new_value: {:?}", new_value);
    // 获取旧的定时器值
    let old = task.op_timers_mut(|timers| {
        let timerid = timer_fd.id;
        let timer = &mut timers[timerid];
        match timer.clock_id {
            ClockId::Monotonic | ClockId::BootTime | ClockId::BootTimeAlarm => {
                // Todo: flags: ClockIdFlags::TIMER_ABSTIME,
                let should_update = !timer.itimer_sepc.it_value.is_zero()
                    || !timer.itimer_sepc.it_interval.is_zero();
                let current_time = TimeSpec::new_machine_time();
                let old_it_spec = if timer.itimer_sepc.it_value < current_time {
                    TimeSpec { sec: 0, nsec: 0 }
                } else {
                    timer.itimer_sepc.it_value - current_time
                };
                let old = ITimerSpec {
                    it_value: old_it_spec,
                    it_interval: timer.itimer_sepc.it_interval,
                };
                log::warn!("old_value: {:?}", old);
                let mut dur;
                // 更新定时器的值
                if flags & TIMER_ABSTIME != 0 {
                    // 如果设置了TIMER_ABSTIME, 则it_value是绝对时间
                    timer.itimer_sepc.it_value = new_value.it_value;
                    dur = if new_value.it_value < current_time {
                        TimeSpec { sec: 0, nsec: 0 }
                    } else {
                        timer.itimer_sepc.it_value - current_time
                    };
                } else {
                    // 否则, it_value是相对时间
                    timer.itimer_sepc.it_value = new_value.it_value + current_time;
                    dur = new_value.it_value;
                }
                timer.itimer_sepc.it_interval = new_value.it_interval;
                // 将旧的定时器值写入old_value_ptr
                if !old_value_ptr.is_null() {
                    copy_to_user(old_value_ptr, &old as *const ITimerSpec, 1)?;
                }
                // 禁用定时器
                if new_value.it_value.is_zero() {
                    log::info!("[sys_timer_settimer] disable timer");
                    let clock_id = (timerid + 3) as i32;
                    remove_timer(task.tid(), clock_id);
                    return Ok(0);
                }
                // 设置或更新已有定时器
                if should_update {
                    log::warn!("[sys_timer_settimer] update timer");
                    update_posix_timer(task.tid(), timerid, dur);
                } else {
                    log::info!("[sys_timer_settimer] add timer");
                    add_posix_timer(task.tid(), dur, timerid);
                }
                return Ok(0);
            }
            ClockId::RealTime
            | ClockId::RealTimeAlarm
            | ClockId::Tai
            | ClockId::ProcessCpuTimeId
            | ClockId::ThreadCpuTimeId => {
                // Todo: flags: ClockIdFlags::TIMER_ABSTIME,
                let should_update = !timer.itimer_sepc.it_value.is_zero()
                    || !timer.itimer_sepc.it_interval.is_zero();
                let current_time = TimeSpec::new_wall_time();
                let old_it_spec = if timer.itimer_sepc.it_value < current_time {
                    TimeSpec { sec: 0, nsec: 0 }
                } else {
                    timer.itimer_sepc.it_value - current_time
                };
                let old = ITimerSpec {
                    it_value: old_it_spec,
                    it_interval: timer.itimer_sepc.it_interval,
                };

                log::warn!("old_value: {:?}", old);
                let mut dur;
                // 更新定时器的值
                if flags & TIMER_ABSTIME != 0 {
                    // 如果设置了TIMER_ABSTIME, 则it_value是绝对时间
                    timer.itimer_sepc.it_value = new_value.it_value;
                    dur = if new_value.it_value < current_time {
                        TimeSpec { sec: 0, nsec: 0 }
                    } else {
                        timer.itimer_sepc.it_value - current_time
                    };
                } else {
                    // 否则, it_value是相对时间
                    timer.itimer_sepc.it_value = new_value.it_value + current_time;
                    dur = new_value.it_value;
                }
                timer.itimer_sepc.it_interval = new_value.it_interval;
                // 将旧的定时器值写入old_value_ptr
                if !old_value_ptr.is_null() {
                    copy_to_user(old_value_ptr, &old as *const ITimerSpec, 1)?;
                }
                // 禁用定时器
                if new_value.it_value.is_zero() {
                    log::info!("[sys_timer_settimer] disable timer");
                    let clock_id = (timerid + 3) as i32;
                    remove_timer(task.tid(), clock_id);
                    return Ok(0);
                }
                // 设置或更新已有定时器
                if should_update {
                    log::warn!("[sys_timer_settimer] update timer");
                    update_posix_timer(task.tid(), timerid, dur);
                } else {
                    add_posix_timer(task.tid(), dur, timerid);
                }
                return Ok(0);
            }
            ClockId::IDLE => {
                log::error!("[sys_timer_settimer] timer not created: {}", timerid);
                return Err(Errno::EINVAL); // 定时器未创建
            }
            _ => {
                log::warn!(
                    "[sys_timer_settimer] timer {} clock_id: {:?}, Unimplemented",
                    timerid,
                    timer.clock_id
                );
                return Err(Errno::ENOSYS);
            }
        }
    })?;
    Ok(0)
}

pub fn sys_timerfd_gettime(fd: usize, curr_value_ptr: *mut ITimerSpec) -> SyscallRet {
    log::error!(
        "[sys_timerfd_gettime] fd: {}, curr_value_ptr: {:#x}",
        fd,
        curr_value_ptr as usize
    );
    let task = current_task();
    let timer_fd = task.fd_table().get_file(fd).ok_or(Errno::EBADF)?;
    let timer_fd = timer_fd
        .as_any()
        .downcast_ref::<TimerFd>()
        .ok_or(Errno::EINVAL)?;
    // 获取当前定时器值
    let timerid = timer_fd.id;
    task.op_timers_mut(|timers| {
        let timer = &timers[timerid];
        if timer.clock_id == ClockId::IDLE {
            log::error!("[sys_tiemr_gettimer] timer not created: {}", timerid);
            return Err(Errno::EINVAL); // 定时器未创建
        }
        match timer.clock_id {
            ClockId::Monotonic | ClockId::BootTime | ClockId::BootTimeAlarm => {
                let current_time = TimeSpec::new_machine_time();
                let curr_it_spec = if timer.itimer_sepc.it_value < current_time {
                    TimeSpec { sec: 0, nsec: 0 }
                } else {
                    timer.itimer_sepc.it_value - current_time
                };
                let curr_value = ITimerSpec {
                    it_value: curr_it_spec,
                    it_interval: timer.itimer_sepc.it_interval,
                };
                copy_to_user(curr_value_ptr, &curr_value as *const ITimerSpec, 1)?;
            }
            ClockId::RealTime
            | ClockId::RealTimeAlarm
            | ClockId::Tai
            | ClockId::ProcessCpuTimeId
            | ClockId::ThreadCpuTimeId => {
                let current_time = TimeSpec::new_wall_time();
                let curr_it_spec = if timer.itimer_sepc.it_value < current_time {
                    TimeSpec { sec: 0, nsec: 0 }
                } else {
                    timer.itimer_sepc.it_value - current_time
                };
                let curr_value = ITimerSpec {
                    it_value: curr_it_spec,
                    it_interval: timer.itimer_sepc.it_interval,
                };
                copy_to_user(curr_value_ptr, &curr_value as *const ITimerSpec, 1)?;
            }
            _ => {
                log::warn!(
                    "[sys_timer_gettimer] timer {} clock_id: {:?}, Unimplemented",
                    timerid,
                    timer.clock_id
                );
                return Err(Errno::ENOSYS); // 目前只实现了CLOCK_MONOTONIC
            }
        }
        Ok(0)
    })
}

pub fn sys_timer_create(clock_id: usize, sigevent_ptr: usize, timerid_ptr: usize) -> SyscallRet {
    log::error!(
        "[sys_timer_create] clock_id: {}, sigp: {:#x}, timerid_ptr: {:#x}",
        clock_id,
        sigevent_ptr,
        timerid_ptr
    );
    let clock_id = ClockId::try_from(clock_id)?;
    let mut sigevent = Sigevent::default();
    // 若为0, 使用Sigevent默认值
    if sigevent_ptr != 0 {
        copy_from_user(
            sigevent_ptr as *const Sigevent,
            &mut sigevent as *mut Sigevent,
            1,
        )?;
    }
    log::info!("[sys_timer_create] sigevent: {:?}", sigevent);
    current_task().op_timers_mut(|timers| {
        // 查找空闲的PosixTimer
        for (i, timer) in timers.iter_mut().enumerate() {
            if timer.clock_id == ClockId::IDLE {
                timer.id = i; // 分配一个唯一的ID
                timer.clock_id = clock_id;
                if sigevent_ptr == 0 {
                    sigevent.sigev_value = i as u64; // 默认值, sigev_value.sival_int = timer ID
                }
                timer.event = sigevent;
                copy_to_user(timerid_ptr as *mut usize, &timer.id as *const usize, 1)?;
                return Ok(0);
            }
        }
        Err(Errno::ENOSPC) // 没有空闲的PosixTimer
    })
}

const TIMER_ABSTIME: i32 = 0x01; // 定时器使用绝对时间

// new_value->it_value默认是相对时间, 除非flags设置了TIMER_ABSTIME
pub fn sys_timer_settimer(
    timerid: usize,
    flags: i32,
    new_value_ptr: *const ITimerSpec,
    old_value_ptr: *mut ITimerSpec,
) -> SyscallRet {
    log::error!(
        "[sys_timer_settimer] timerid: {}, flags: {}, new_value_ptr: {:#x}, old_value_ptr: {:#x}",
        timerid,
        flags,
        new_value_ptr as usize,
        old_value_ptr as usize
    );
    let task = current_task();
    let mut new_value = ITimerSpec::default();
    if new_value_ptr.is_null() {
        log::error!("[sys_timer_settimer] new_value_ptr is null");
        return Err(Errno::EINVAL);
    }
    copy_from_user(new_value_ptr, &mut new_value as *mut ITimerSpec, 1)?;
    if !new_value.is_valid() {
        log::error!("[sys_timer_settimer] new_value is invalid: {:?}", new_value);
        return Err(Errno::EINVAL);
    }
    if timerid >= MAX_POSIX_TIMER_COUNT {
        log::error!("[sys_timer_settimer] invalid timerid: {}", timerid);
        return Err(Errno::EINVAL);
    }
    // 8.4 Debug
    log::info!("[sys_timer_settimer] new_value: {:?}", new_value);
    task.op_timers_mut(|timers| {
        let timer = &mut timers[timerid];
        match timer.clock_id {
            ClockId::Monotonic | ClockId::BootTime | ClockId::BootTimeAlarm => {
                // Todo: flags: ClockIdFlags::TIMER_ABSTIME,
                let should_update = !timer.itimer_sepc.it_value.is_zero()
                    || !timer.itimer_sepc.it_interval.is_zero();
                let current_time = TimeSpec::new_machine_time();
                let old_it_spec = if timer.itimer_sepc.it_value < current_time {
                    TimeSpec { sec: 0, nsec: 0 }
                } else {
                    timer.itimer_sepc.it_value - current_time
                };
                let old = ITimerSpec {
                    it_value: old_it_spec,
                    it_interval: timer.itimer_sepc.it_interval,
                };
                log::warn!("old_value: {:?}", old);
                let mut dur;
                // 更新定时器的值
                if flags & TIMER_ABSTIME != 0 {
                    // 如果设置了TIMER_ABSTIME, 则it_value是绝对时间
                    timer.itimer_sepc.it_value = new_value.it_value;
                    dur = if new_value.it_value < current_time {
                        TimeSpec { sec: 0, nsec: 0 }
                    } else {
                        timer.itimer_sepc.it_value - current_time
                    };
                } else {
                    // 否则, it_value是相对时间
                    timer.itimer_sepc.it_value = new_value.it_value + current_time;
                    dur = new_value.it_value;
                }
                timer.itimer_sepc.it_interval = new_value.it_interval;
                // 将旧的定时器值写入old_value_ptr
                if !old_value_ptr.is_null() {
                    copy_to_user(old_value_ptr, &old as *const ITimerSpec, 1)?;
                }
                // 禁用定时器
                if new_value.it_value.is_zero() {
                    log::info!("[sys_timer_settimer] disable timer");
                    let clock_id = (timerid + 3) as i32;
                    remove_timer(task.tid(), clock_id);
                    return Ok(0);
                }
                // 设置或更新已有定时器
                if should_update {
                    log::warn!("[sys_timer_settimer] update timer");
                    update_posix_timer(task.tid(), timerid, dur);
                } else {
                    log::info!("[sys_timer_settimer] add timer");
                    add_posix_timer(task.tid(), dur, timerid);
                }
                return Ok(0);
            }
            ClockId::RealTime
            | ClockId::RealTimeAlarm
            | ClockId::Tai
            | ClockId::ProcessCpuTimeId
            | ClockId::ThreadCpuTimeId => {
                // Todo: flags: ClockIdFlags::TIMER_ABSTIME,
                let should_update = !timer.itimer_sepc.it_value.is_zero()
                    || !timer.itimer_sepc.it_interval.is_zero();
                let current_time = TimeSpec::new_wall_time();
                let old_it_spec = if timer.itimer_sepc.it_value < current_time {
                    TimeSpec { sec: 0, nsec: 0 }
                } else {
                    timer.itimer_sepc.it_value - current_time
                };
                let old = ITimerSpec {
                    it_value: old_it_spec,
                    it_interval: timer.itimer_sepc.it_interval,
                };

                log::warn!("old_value: {:?}", old);
                let mut dur;
                // 更新定时器的值
                if flags & TIMER_ABSTIME != 0 {
                    // 如果设置了TIMER_ABSTIME, 则it_value是绝对时间
                    timer.itimer_sepc.it_value = new_value.it_value;
                    dur = if new_value.it_value < current_time {
                        TimeSpec { sec: 0, nsec: 0 }
                    } else {
                        timer.itimer_sepc.it_value - current_time
                    };
                } else {
                    // 否则, it_value是相对时间
                    timer.itimer_sepc.it_value = new_value.it_value + current_time;
                    dur = new_value.it_value;
                }
                timer.itimer_sepc.it_interval = new_value.it_interval;
                // 将旧的定时器值写入old_value_ptr
                if !old_value_ptr.is_null() {
                    copy_to_user(old_value_ptr, &old as *const ITimerSpec, 1)?;
                }
                // 禁用定时器
                if new_value.it_value.is_zero() {
                    log::info!("[sys_timer_settimer] disable timer");
                    let clock_id = (timerid + 3) as i32;
                    remove_timer(task.tid(), clock_id);
                    return Ok(0);
                }
                // 设置或更新已有定时器
                if should_update {
                    log::warn!("[sys_timer_settimer] update timer");
                    update_posix_timer(task.tid(), timerid, dur);
                } else {
                    add_posix_timer(task.tid(), dur, timerid);
                }
                return Ok(0);
            }
            ClockId::IDLE => {
                log::error!("[sys_timer_settimer] timer not created: {}", timerid);
                return Err(Errno::EINVAL); // 定时器未创建
            }
            _ => {
                log::warn!(
                    "[sys_timer_settimer] timer {} clock_id: {:?}, Unimplemented",
                    timerid,
                    timer.clock_id
                );
                return Err(Errno::ENOSYS); // 目前只实现了CLOCK_MONOTONIC
            }
        }
    })
}

pub fn sys_timer_gettimer(timerid: usize, curr_value_ptr: *mut ITimerSpec) -> SyscallRet {
    log::error!(
        "[sys_timer_gettimer] timerid: {}, curr_value_ptr: {:#x}",
        timerid,
        curr_value_ptr as usize
    );
    if timerid >= MAX_POSIX_TIMER_COUNT {
        log::error!("[sys_timer_gettimer] timerid out of range: {}", timerid);
        return Err(Errno::EINVAL); // 定时器ID超出范围
    }

    let task = current_task();
    task.op_timers_mut(|timers| {
        let timer = &timers[timerid];
        if timer.clock_id == ClockId::IDLE {
            log::error!("[sys_tiemr_gettimer] timer not created: {}", timerid);
            return Err(Errno::EINVAL); // 定时器未创建
        }
        match timer.clock_id {
            ClockId::Monotonic | ClockId::BootTime | ClockId::BootTimeAlarm => {
                let current_time = TimeSpec::new_machine_time();
                let curr_it_spec = if timer.itimer_sepc.it_value < current_time {
                    TimeSpec { sec: 0, nsec: 0 }
                } else {
                    timer.itimer_sepc.it_value - current_time
                };
                let curr_value = ITimerSpec {
                    it_value: curr_it_spec,
                    it_interval: timer.itimer_sepc.it_interval,
                };
                copy_to_user(curr_value_ptr, &curr_value as *const ITimerSpec, 1)?;
            }
            ClockId::RealTime
            | ClockId::RealTimeAlarm
            | ClockId::Tai
            | ClockId::ProcessCpuTimeId
            | ClockId::ThreadCpuTimeId => {
                let current_time = TimeSpec::new_wall_time();
                let curr_it_spec = if timer.itimer_sepc.it_value < current_time {
                    TimeSpec { sec: 0, nsec: 0 }
                } else {
                    timer.itimer_sepc.it_value - current_time
                };
                let curr_value = ITimerSpec {
                    it_value: curr_it_spec,
                    it_interval: timer.itimer_sepc.it_interval,
                };
                copy_to_user(curr_value_ptr, &curr_value as *const ITimerSpec, 1)?;
            }
            _ => {
                log::warn!(
                    "[sys_timer_gettimer] timer {} clock_id: {:?}, Unimplemented",
                    timerid,
                    timer.clock_id
                );
                return Err(Errno::ENOSYS); // 目前只实现了CLOCK_MONOTONIC
            }
        }
        Ok(0)
    })
}

pub fn sys_timer_getoverrun(timerid: usize) -> SyscallRet {
    log::error!("[sys_timer_getoverrun] timerid: {}", timerid);
    if timerid >= MAX_POSIX_TIMER_COUNT {
        log::error!("[sys_timer_getoverrun] timerid out of range: {}", timerid);
        return Err(Errno::EINVAL); // 定时器ID超出范围
    }
    let task = current_task();
    task.op_timers_mut(|timers| {
        let timer = &timers[timerid];
        if timer.clock_id == ClockId::IDLE {
            log::error!("[sys_timer_getoverrun] timer not created: {}", timerid);
            return Err(Errno::EINVAL); // 定时器未创建
        }
        Ok(timer.overrun)
    })
}

pub fn sys_timer_delete(timerid: usize) -> SyscallRet {
    log::error!("[sys_timer_delete] timerid: {}", timerid);
    if timerid >= MAX_POSIX_TIMER_COUNT {
        log::error!("[sys_timer_delete] timerid out of range: {}", timerid);
        return Err(Errno::EINVAL); // 定时器ID超出范围
    }
    let task = current_task();
    task.op_timers_mut(|timers| {
        let timer = &mut timers[timerid];
        if timer.clock_id == ClockId::IDLE {
            log::error!("[sys_timer_delete] timer not created: {}", timerid);
            return Err(Errno::EINVAL); // 定时器未创建
        }
        remove_timer(task.tid(), (timerid + 3) as i32);
        *timer = PosixTimer::idle(); // 重置为idle状态
        Ok(0)
    })
}

/// 调用进程的资源使用情况。
pub const RUSAGE_SELF: i32 = 0;
/// 已终止并被等待的所有子进程的资源使用情况
pub const RUSAGE_CHILDREN: i32 = -1;
/// 调用线程的资源使用情况（需要 Linux 2.6.26 以上版本，并定义了 `_GNU_SOURCE` 宏）
pub const RUSAGE_THREAD: i32 = 1;
pub fn sys_getrusage(who: i32, rusage: *mut RUsage) -> SyscallRet {
    if rusage.is_null() {
        return Err(Errno::EINVAL);
    }
    let task = current_task();
    let mut usage = RUsage::default();
    match who {
        RUSAGE_SELF => {
            let (utime, stime) = task.process_us_time();
            usage.utime = utime;
            usage.stime = stime;
        }
        RUSAGE_CHILDREN => {
            log::warn!("[sys_getrusage] RUSAGE_CHILDREN is not implemented");
            return Err(Errno::ENOSYS);
        }
        RUSAGE_THREAD => {
            let (utime, stime) = task.time_stat().thread_us_time();
            usage.utime = utime;
            usage.stime = stime;
        }
        _ => {
            return Err(Errno::EINVAL);
        }
    }
    copy_to_user(rusage, &usage as *const RUsage, 1)?;
    Ok(0)
}

/*
   函数 clock_getres() 用于查找指定时钟 clockid 的分辨率（精度）
   如果 res 非空，则将其存储在 res 指向的 timespec 结构体中。
   如果 clock_settime() 的参数 tp 指向的时间值不是 res 的倍数，则将其截断为 res 的倍数。（Todo)
*/
pub fn sys_clock_getres(clockid: usize, res: usize) -> SyscallRet {
    if (clockid as isize) < 0 {
        return Err(Errno::EINVAL);
    }
    if res == 0 {
        return Ok(0);
    }
    log::info!("[sys_clock_getres] res set 1 nanos");
    copy_to_user(res as *mut TimeSpec, &TimeSpec::from_nanos(1), 1)?;
    Ok(0)
}

/// 调用进程的系统时间调整
/// 根据传入的kernelTimex调整时间并返回最新的内核结构体到指针
pub fn sys_adjtimex(user_timex: *mut KernelTimex) -> SyscallRet {
    log::error!("[sys_adjtimex] user_timex: {:#x}", user_timex as usize);
    if user_timex.is_null() {
        return Err(Errno::EFAULT);
    }
    if user_timex as usize == 0xffffffffffffffff {
        return Err(Errno::EFAULT);
    }
    let task = current_task();
    log::error!("[sys_adjtimex] task uid: {:?}", task.euid());
    let mut kernel_timex = KernelTimex::default();
    copy_from_user(
        user_timex as *const u8,
        &mut kernel_timex as *mut KernelTimex as *mut u8,
        size_of::<KernelTimex>(),
    )?;
    log::error!("[sys_adjtimex] kernel_timex: {:?}", kernel_timex);
    log::error!(
        "[sys_adjtimex] kernel_timex modes: {:?}",
        kernel_timex.modes
    );
    if kernel_timex.modes == 0x8000 {
        return Err(Errno::EINVAL);
    }
    if kernel_timex.modes == 0 {
        //只读
        unsafe {
            log::error!("[sys_adjtimex] last_timex is {:?}", LAST_TIMEX);
        }
        unsafe {
            copy_to_user(user_timex, &LAST_TIMEX as *const KernelTimex, 1)?;
        }
        return Ok(0);
    }
    //非只读模式下必须root权限
    if kernel_timex.modes != 0 && task.euid() != 0 {
        return Err(Errno::EPERM);
    }
    //保存非0设置的kernel_timex并在只读中返回回去
    let status = do_adjtimex(&mut kernel_timex)?;
    kernel_timex.tick = 10000;
    //写回到last_timex
    unsafe { LAST_TIMEX.clone_from(&kernel_timex) };
    unsafe {
        log::error!("[sys_adjtimex] last_timex is {:?}", LAST_TIMEX);
    }
    let out_from = &kernel_timex as *const KernelTimex;
    copy_to_user(user_timex, out_from, 1)?;
    Ok(status as usize)
}
//较adjtimex,可以选择调整哪个时钟
pub fn sys_clock_adjtime(clock_id: i32, user_timex: *mut KernelTimex) -> SyscallRet {
    log::error!(
        "[sys_clock_adjtime] clock_id: {}, user_timex: {:#x}",
        clock_id,
        user_timex as usize
    );
    if user_timex.is_null() {
        return Err(Errno::EINVAL);
    }
    let task = current_task();
    log::error!(
        "[sys_clock_adjtime] euid {:?},egid {:?}",
        task.euid(),
        task.egid()
    );
    let clock_type = ClockIdFlags::from_clockid(clock_id)?;
    if clock_type.contains(ClockIdFlags::REALTIME) {
        // 调整实时时钟
        return sys_adjtimex(user_timex);
    } else if clock_type.contains(ClockIdFlags::MONOTONIC) {
        // 调整单调时钟
        unimplemented!()
    } else {
        unimplemented!()
    }
}

pub fn sys_bpf(cmd: i32, bpf_attr_ptr: usize, size: usize) -> SyscallRet {
    log::error!(
        "[sys_bpf] cmd: {}, bpf_attr: {:#x}, size: {}",
        cmd,
        bpf_attr_ptr as usize,
        size
    );
    let cmd = BpfCmd::try_from(cmd)?;
    match cmd {
        BpfCmd::BpfMapCreate => bpf_map_create(bpf_attr_ptr, size),
        BpfCmd::BpfMapLookupElem => bpf_map_lookup_elem(bpf_attr_ptr, size),
        BpfCmd::BpfMapUpdateElem => bpf_map_update_elem(bpf_attr_ptr, size),
        // BpfCmd::BpfMapDeleteElem => todo!(),
        // BpfCmd::BpfMapGetNextKey => todo!(),
        BpfCmd::BpfProgLoad => bpf_prog_load(bpf_attr_ptr, size),
        // BpfCmd::BpfObjPin => todo!(),
        // BpfCmd::BpfObjGet => todo!(),
        // BpfCmd::BpfProgAttach => todo!(),
        // BpfCmd::BpfProgDetach => todo!(),
        // BpfCmd::BpfProcTestRun => todo!(),
        BpfCmd::BpfBtfLoad => bpf_btf_load(bpf_attr_ptr, size),
        BpfCmd::BpfLinkCreate => bpf_btf_link_create(bpf_attr_ptr, size),
        BpfCmd::BpfIterCreate => bpf_iter_create(bpf_attr_ptr, size),
        _ => {
            log::error!("[sys_bpf] Unsupported bpf command: {:?}", cmd);
            return Err(Errno::ENOSYS);
        }
    }
}

pub fn sys_shutdown() -> SyscallRet {
    shutdown(false);
}

#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub struct SysInfo {
    pub uptime: i64,
    pub loads: [u64; 3],
    pub totalram: u64,
    pub freeram: u64,
    pub sharedram: u64,
    pub bufferram: u64,
    pub totalswap: u64,
    pub freeswap: u64,
    pub procs: u16,
    pub totalhigh: u64,
    pub freehigh: u64,
    pub mem_unit: u32,
    pub _f: [u8; 20 - 2 * core::mem::size_of::<u64>() - core::mem::size_of::<u32>()],
}

pub fn sys_sysinfo(user_ptr: *mut SysInfo) -> SyscallRet {
    if user_ptr.is_null() {
        return Err(Errno::EFAULT);
    }

    let uptime = TimeSpec::new_machine_time().sec as u64; // 系统运行时间，单位为秒
    let (load1, load5, load15) = (0, 0, 0); // 1、5、15 分钟负载，按 Linux 的 "fixed point" 处理
    let mem_unit = PAGE_SIZE as u32;

    let (totalram, freeram, sharedram, bufferram) = (
        12345, // 总内存大小
        10000, // 可用内存大小
        1000,  // 共享内存大小
        1000,  // 缓冲区内存大小
    );
    let (totalswap, freeswap) = (0, 0);
    let (totalhigh, freehigh) = (0, 0);
    let procs = get_all_tasks().len();

    let info = SysInfo {
        uptime: uptime as i64,
        loads: [load1, load5, load15],
        totalram: totalram / mem_unit as u64,
        freeram: freeram / mem_unit as u64,
        sharedram: sharedram / mem_unit as u64,
        bufferram: bufferram / mem_unit as u64,
        totalswap: totalswap / mem_unit as u64,
        freeswap: freeswap / mem_unit as u64,
        procs: procs as u16,
        totalhigh: totalhigh / mem_unit as u64,
        freehigh: freehigh / mem_unit as u64,
        mem_unit,
        _f: [0u8; 20 - 2 * core::mem::size_of::<u64>() - core::mem::size_of::<u32>()],
    };

    copy_to_user(user_ptr, &info as *const SysInfo, 1)?;

    Ok(0)
}

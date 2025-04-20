use core::{fmt::Debug, ops::Add};

use crate::{
    arch::{boards::qemu::CLOCK_FREQ, sbi::set_timer},
    mm::{VirtAddr, KERNEL_SPACE},
};
use riscv::register::time;

use super::config::KERNEL_BASE;

const TICKS_PER_SEC: usize = 100;
const MSEC_PER_SEC: usize = 1000;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[repr(C)]
pub struct TimeSpec {
    // 秒数
    pub sec: usize,
    // 毫秒数中剩余的部分, 使用纳秒表示
    pub nsec: usize,
}

impl PartialOrd for TimeSpec {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        if self.sec == other.sec {
            Some(self.nsec.cmp(&other.nsec))
        } else {
            Some(self.sec.cmp(&other.sec))
        }
    }
}

impl Add for TimeSpec {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        let mut sec = self.sec + rhs.sec;
        let mut nsec = self.nsec + rhs.nsec;
        if nsec >= 1_000_000_000 {
            sec += 1;
            nsec -= 1_000_000_000;
        }
        Self { sec, nsec }
    }
}

impl TimeSpec {
    pub fn new_machine_time() -> Self {
        // new a time spec with machine time
        let current_time = get_time_ms();
        Self {
            sec: current_time / 1000,
            nsec: (current_time % 1000) * 1000000,
        }
    }
    pub fn new_wall_time() -> Self {
        // new a time spec with machine time
        let current_time = read_rtc();
        Self {
            sec: (current_time / NANOS_PER_SEC) as usize,
            nsec: (current_time % NANOS_PER_SEC) as usize,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct StatxTimeStamp {
    /// 自UNIX time以来的秒数
    pub sec: i64,
    /// 纳秒数, 表示秒数后剩余的部分
    pub nsec: u32,
}

impl StatxTimeStamp {
    pub fn new() -> Self {
        // new a time spec with machine time
        let current_time = get_time_ms();
        Self {
            sec: (current_time / 1000) as i64,
            nsec: ((current_time % 1000) * 1000000) as u32,
        }
    }
    pub fn new_real() -> Self {
        // new a time spec with wall time(自epoch以来的时间)
        let current_time = read_rtc();
        Self {
            sec: (current_time / NANOS_PER_SEC) as i64,
            nsec: (current_time % NANOS_PER_SEC) as u32,
        }
    }
}

impl From<TimeSpec> for StatxTimeStamp {
    fn from(ts: TimeSpec) -> Self {
        Self {
            sec: ts.sec as i64,
            nsec: ts.nsec as u32,
        }
    }
}

pub fn get_time() -> usize {
    time::read()
}

pub fn get_time_ms() -> usize {
    get_time() / (CLOCK_FREQ / MSEC_PER_SEC)
}

pub fn set_next_trigger() {
    set_timer(get_time() + CLOCK_FREQ / TICKS_PER_SEC);
}

const GOLDFISH_RTC_BASE: usize = 0x10_1000;
const TIME_LOW: usize = 0x00;
const TIME_HIGH: usize = 0x04;
pub const NANOS_PER_SEC: u64 = 1_000_000_000;

/**
 * Goldfish RTC 寄存器布局
 * 实际返回的是纳秒
 * 基地址: 0x101000 (RISC-V virt 机器)
 * 大小: 36 字节
 */
/// 返回的是自Epoch以来的纳秒数
pub fn read_rtc() -> u64 {
    let low = unsafe {
        core::ptr::read_volatile((KERNEL_BASE + GOLDFISH_RTC_BASE + TIME_LOW) as *const u32)
    } as u64;
    log::error!("low: {:#x}", low);
    let high = unsafe {
        core::ptr::read_volatile((KERNEL_BASE + GOLDFISH_RTC_BASE + TIME_HIGH) as *const u32)
    } as u64;
    log::error!("high: {:#x}", high);
    (high << 32) | low
}

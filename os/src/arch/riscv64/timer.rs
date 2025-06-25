use crate::{
    arch::{boards::qemu::CLOCK_FREQ, sbi::set_timer},
    timer::{StatxTimeStamp, TimeSpec, TimeVal, MSEC_PER_SEC, TICKS_PER_SEC, USEC_PER_SEC},
};
use riscv::register::time;

use super::config::KERNEL_BASE;

impl TimeSpec {
    pub fn new_machine_time() -> Self {
        // new a time spec with machine time
        let current_time = get_time_us();
        Self {
            sec: current_time / 1000000,
            nsec: (current_time % 1000000) * 1000,
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
    pub fn from_nanos(nanos: usize) -> Self {
        let sec = nanos / 1_000_000_000;
        let nsec = nanos % 1_000_000_000;
        TimeSpec { sec, nsec }
    }
}

impl TimeVal {
    pub fn new_machine_time() -> Self {
        // new a time spec with machine time
        let current_time = get_time_ms();
        Self {
            sec: (current_time / 1000) as usize,
            usec: (current_time % 1000) * 1000 as usize,
        }
    }
    pub fn new_wall_time() -> Self {
        // new a time spec with machine time
        let current_time = read_rtc();
        Self {
            sec: (current_time / NANOS_PER_SEC) as usize,
            usec: ((current_time % NANOS_PER_SEC) / 1000) as usize,
        }
    }
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

pub fn get_time() -> usize {
    time::read()
}

pub fn get_time_ms() -> usize {
    get_time() / (CLOCK_FREQ / MSEC_PER_SEC)
}

pub fn get_time_us() -> usize {
    get_time() / (CLOCK_FREQ / 1_000_000)
}

pub fn get_time_ns() -> usize {
    get_time() * (1_000_000_000 / CLOCK_FREQ)
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
    let high = unsafe {
        core::ptr::read_volatile((KERNEL_BASE + GOLDFISH_RTC_BASE + TIME_HIGH) as *const u32)
    } as u64;
    (high << 32) | low
}

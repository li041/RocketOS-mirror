use core::{
    arch::asm,
    cmp::Ordering,
    ops::{Add, Sub},
    ptr::{read_volatile, write_volatile},
};

use crate::{
    timer::{StatxTimeStamp, TimeSpec, TimeVal, MSEC_PER_SEC},
    utils::{seconds_to_beijing_datetime, DateTime},
};

use super::config::{self, CLOCK_FREQ};

const NANOS_PER_SEC: u64 = 1_000_000_000;

impl TimeSpec {
    pub fn new_machine_time() -> Self {
        log::trace!("new machine time");
        // new a time spec with machine time
        let current_time = get_time_us();
        Self {
            sec: current_time / 1000000,
            nsec: (current_time % 1000000) * 1000,
        }
    }
    pub fn new_wall_time() -> Self {
        //     // let base = LS7A_RTC_BASE as *mut u32;
        //     // let rtc_ticks = unsafe { read_volatile(base.byte_add(SYS_RTCREAD0) as *const u32) as u64 };
        //     // let sec = rtc_ticks / LS7A_RTC_FREQ; // 转换为秒
        //     // let nsec = (rtc_ticks % LS7A_RTC_FREQ) * 1000000000 / LS7A_RTC_FREQ; // 转换为纳秒
        //     // let mut date_time = TimeSpec::from(&unsafe { read_rtc() });
        //     // let mut time_spec = TimeSpec::default();
        let mut base_time = TimeSpec {
            sec: 1_757_088_000,
            nsec: 0,
        };
        let current_time = get_time_ns();
        base_time.nsec += (current_time % 1000000000);
        base_time.sec += current_time / 1000000000;
        base_time
    }
    pub fn from_nanos(nanos: usize) -> Self {
        let sec = nanos / 1_000_000_000;
        let nsec = nanos % 1_000_000_000;
        TimeSpec { sec, nsec }
    }
}

impl TimeVal {
    pub fn new_machine_time() -> Self {
        log::trace!("new machine time");
        // new a time spec with machine time
        let current_time = get_time_ms();
        Self {
            sec: current_time / 1000,
            usec: (current_time % 1000) * 1000,
        }
    }
    pub fn new_wall_time() -> Self {
        let mut base_time = TimeVal {
            sec: 1_757_088_000,
            usec: 0,
        };
        let current_time = get_time_ms();
        base_time.sec += current_time / 1000;
        base_time.usec = (current_time % 1000) * 1000;
        base_time
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
}

/// Return current time measured by ticks, which is NOT divided by frequency.
pub fn get_time() -> usize {
    let mut counter: usize;
    unsafe {
        asm!(
        "rdtime.d {},{}",
        out(reg)counter,
        out(reg)_,
        );
    }
    counter
}

pub fn get_time_ms() -> usize {
    log::trace!("get_time_ms");
    unsafe {
        debug_assert!(CLOCK_FREQ != 0, "CLOCK_FREQ is not initialized");
        get_time() / (CLOCK_FREQ / MSEC_PER_SEC)
    }
}

pub fn get_time_us() -> usize {
    log::trace!("get_time_us");
    unsafe {
        debug_assert!(CLOCK_FREQ != 0, "CLOCK_FREQ is not initialized");
        get_time() / (CLOCK_FREQ / 1000000)
    }
}

pub fn get_time_ns() -> usize {
    log::trace!("get_time_ns");
    unsafe {
        debug_assert!(CLOCK_FREQ != 0, "CLOCK_FREQ is not initialized");
        get_time() * (1_000_000_000 / CLOCK_FREQ)
    }
}

#[inline(always)]
pub fn get_clock_freq() -> usize {
    unsafe {
        debug_assert!(CLOCK_FREQ != 0, "CLOCK_FREQ is not initialized");
        super::config::CLOCK_FREQ
    }
}

/// clk freq: 100_000_000, 精度为 10ns
pub fn get_timer_freq_first_time() {
    // 获取时钟晶振频率
    // 配置信息字index:4
    let base_freq = config::CPUCfg4::read().get_bits(0, 31);
    // 获取时钟倍频因子
    // 配置信息字index:5 位:0-15
    let cfg5 = config::CPUCfg5::read();
    let mul = cfg5.get_bits(0, 15);
    let div = cfg5.get_bits(16, 31);
    // 计算时钟频率
    let cc_freq = base_freq * mul / div;
    println!(
        "[get_timer_freq_first_time] clk freq: {}(from CPUCFG)",
        cc_freq
    );
    unsafe { super::config::CLOCK_FREQ = cc_freq as usize }
}

// 硬编码, qemu的RTC寄存器地址
pub const LS7A_RTC_BASE: usize = 0x100d0100; // RTC基地址

// LS7A RTC 寄存器偏移量
const SYS_RTCSEC: usize = 0x04; // 秒寄存器
const SYS_RTCMIN: usize = 0x08; // 分钟寄存器
const SYS_RTCHOUR: usize = 0x0C; // 小时寄存器
const SYS_RTCDAY: usize = 0x10; // 日寄存器
const SYS_RTCMON: usize = 0x14; // 月寄存器
const SYS_RTCYEAR: usize = 0x18; // 年寄存器
const SYS_TOYWRITE0: usize = 0x20; // TOY 写寄存器 0
const SYS_TOYWRITE1: usize = 0x24; // TOY 写寄存器 1
const SYS_TOYREAD0: usize = 0x2C;
const SYS_TOYREAD1: usize = 0x30;
const SYS_RTCCTRL: usize = 0x40;
const SYS_RTCWRITE0: usize = 0x60;
const SYS_RTCREAD0: usize = 0x68;

// TOY 时间字段掩码和移位
const TOY_MON_SHIFT: u32 = 26;
const TOY_MON_MASK: u32 = 0x3F << TOY_MON_SHIFT;
const TOY_DAY_SHIFT: u32 = 21;
const TOY_DAY_MASK: u32 = 0x1F << TOY_DAY_SHIFT;
const TOY_HOUR_SHIFT: u32 = 16;
const TOY_HOUR_MASK: u32 = 0x1F << TOY_HOUR_SHIFT;
const TOY_MIN_SHIFT: u32 = 10;
const TOY_MIN_MASK: u32 = 0x3F << TOY_MIN_SHIFT;
const TOY_SEC_SHIFT: u32 = 4;
const TOY_SEC_MASK: u32 = 0x3F << TOY_SEC_SHIFT;

// RTC_CTRL 字段掩码和移位
const RTC_CTRL_TOYEN_SHIFT: u32 = 11;
const RTC_CTRL_TOYEN_MASK: u32 = 1 << RTC_CTRL_TOYEN_SHIFT;
const RTC_CTRL_EO_SHIFT: u32 = 8;
const RTC_CTRL_EO_MASK: u32 = 1 << RTC_CTRL_EO_SHIFT;
const RTC_CTRL_RTCEN_SHIFT: u32 = 13;
const RTC_CTRL_RTCEN_MASK: u32 = 1 << RTC_CTRL_RTCEN_SHIFT;

// LS7A RTC 时钟频率
const LS7A_RTC_FREQ: u64 = 32768;

/// 从 LS7A RTC 读取当前时间
///
/// # Arguments
/// * `base` - MMIO 基地址 (0x100d0100)
///
/// # Returns
/// 返回 (year, month, day, hour, minute, second) 的元组
/// 如果 TOY 未启用，返回自 UTC 以来的秒数转换为时间
// LS7A RTC 寄存器偏移量 (需要根据实际硬件手册调整)
// 控制寄存器位定义
pub const RTC_CTRL_WREN_MASK: u32 = 1 << 3; // 写使能位
pub const RTC_CTRL_32K_SEL_MASK: u32 = 1 << 4; // 32K 时钟选择位

// 位偏移量 (用于移位操作)
pub const RTC_CTRL_WREN_SHIFT: u32 = 3;

/// 初始化 LS7A RTC 和 TOY 时间
///
/// # Arguments
/// * `base` - RTC MMIO 基地址
/// * `datetime` - 时间结构体，包含年月日时分秒
/// 写入寄存器
fn rtc_write(offset: usize, val: u32) {
    let reg = (LS7A_RTC_BASE + offset) as *mut u32;
    unsafe {
        write_volatile(reg, val);
    }
}

/// 读取寄存器
fn rtc_read(offset: usize) -> u32 {
    let reg = (LS7A_RTC_BASE + offset) as *const u32;
    unsafe { read_volatile(reg) }
}

pub fn ls7a_rtc_init() {
    // 启用 TOYEN + EO
    rtc_write(
        SYS_RTCCTRL,
        RTC_CTRL_TOYEN_MASK | RTC_CTRL_RTCEN_MASK | RTC_CTRL_EO_MASK,
    );
}

pub fn ls7a_rtc_real_time() {
    let toyread0 = rtc_read(SYS_TOYREAD0);
    let toyread1 = rtc_read(SYS_TOYREAD1);

    let mon = (toyread0 >> 26) & 0x3F;
    let day = (toyread0 >> 21) & 0x1F;
    let hour = (toyread0 >> 16) & 0x1F;
    let min = (toyread0 >> 10) & 0x3F;
    let sec = (toyread0 >> 4) & 0x3F;

    let year = toyread1 + 1900;

    println!(
        "LS7A RTC time: {}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, mon, day, hour, min, sec
    );
}

/// Todo:
pub fn read_rtc() -> u64 {
    let low = rtc_read(SYS_TOYREAD0) as u64;
    let high = rtc_read(SYS_TOYREAD1) as u64;
    ((high << 32) | low)
}

pub fn time_test() {
    let time_befort = unsafe { read_rtc() };
    println!("time before: {:?}", time_befort);
    unsafe {
        let datetime = DateTime {
            year: 25,
            month: 9,
            day: 6,
            hour: 6,
            minute: 6,
            second: 6,
        };
        // ls7a_rtc_init(LS7A_RTC_BASE as *mut u32, datetime).expect("Failed to set LS7A RTC");
    }
    let time_after = unsafe { read_rtc() };
    println!("time after: {:?}", time_after);
}

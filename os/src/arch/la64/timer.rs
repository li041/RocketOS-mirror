use core::{arch::asm, ptr::read_volatile};

use crate::utils::{seconds_to_beijing_datetime, DateTime};

use super::config::{self, CLOCK_FREQ};

pub const TICKS_PER_SEC: usize = 100;
const MSEC_PER_SEC: usize = 1000;

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct TimeSpec {
    // 秒数
    pub sec: usize,
    // 毫秒数中剩余的部分, 使用纳秒表示
    pub nsec: usize,
}

impl TimeSpec {
    pub fn new() -> Self {
        // new a time spec with machine time
        let current_time = get_time_ms();
        Self {
            sec: current_time / 1000,
            nsec: (current_time % 1000) * 1000000,
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
}

impl From<TimeSpec> for StatxTimeStamp {
    fn from(ts: TimeSpec) -> Self {
        Self {
            sec: ts.sec as i64,
            nsec: ts.nsec as u32,
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
    unsafe {
        assert!(CLOCK_FREQ != 0, "CLOCK_FREQ is not initialized");
        get_time() / (CLOCK_FREQ / MSEC_PER_SEC)
    }
}

#[inline(always)]
pub fn get_clock_freq() -> usize {
    unsafe {
        assert!(CLOCK_FREQ != 0, "CLOCK_FREQ is not initialized");
        super::config::CLOCK_FREQ
    }
}
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
const SYS_TOYREAD0: usize = 0x2C;
const SYS_TOYREAD1: usize = 0x30;
const SYS_RTCCTRL: usize = 0x40;
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
pub unsafe fn read_ls7a_rtc(base: *mut u32) -> DateTime {
    // 读取控制寄存器
    let ctrl = read_volatile(base.byte_add(SYS_RTCCTRL) as *const u32);
    let toyen = (ctrl & RTC_CTRL_TOYEN_MASK) >> RTC_CTRL_TOYEN_SHIFT;
    let eo = (ctrl & RTC_CTRL_EO_MASK) >> RTC_CTRL_EO_SHIFT;
    log::error!("ctrl: {:#x}, toyen: {}, eo: {}", ctrl, toyen, eo);

    // 检查 TOY 是否启用
    if toyen == 1 && eo == 1 {
        // TOY 已启用，从寄存器读取
        log::info!("ls7a toy enabled");
        let toy0 = read_volatile(base.byte_add(SYS_TOYREAD0) as *const u32);
        let toy1 = read_volatile(base.byte_add(SYS_TOYREAD1) as *const u32);

        let mon = (toy0 & TOY_MON_MASK) >> TOY_MON_SHIFT;
        let day = (toy0 & TOY_DAY_MASK) >> TOY_DAY_SHIFT;
        let hour = (toy0 & TOY_HOUR_MASK) >> TOY_HOUR_SHIFT;
        let min = (toy0 & TOY_MIN_MASK) >> TOY_MIN_SHIFT;
        let sec = (toy0 & TOY_SEC_MASK) >> TOY_SEC_SHIFT;
        let year = toy1;
        let date_time = DateTime {
            year: year as u32,
            month: mon as u8,
            day: day as u8,
            hour: hour as u8,
            minute: min as u8,
            second: sec as u8,
        };
        date_time
    } else {
        // TOY 未启用，读取 RTC tick 并转换为时间
        log::info!("ls7a rtc enabled");
        let rtcen = (ctrl & RTC_CTRL_RTCEN_MASK) >> RTC_CTRL_RTCEN_SHIFT;
        if rtcen == 1 && eo == 1 {
            let rtc_ticks = read_volatile(base.byte_add(SYS_RTCREAD0) as *const u32) as u64;
            let seconds = rtc_ticks / LS7A_RTC_FREQ; // 转换为秒
            log::error!("rtc ticks: {:#x}, seconds: {}", rtc_ticks, seconds);

            // 将秒数转换为年月日时分秒（简化实现）
            let date_time = seconds_to_beijing_datetime(seconds);
            date_time
        } else {
            log::warn!("ls7a rtc not enabled");
            DateTime::default()
        }
    }
}

/// 启用 LS7A RTC 的 TOY 和 RTC 计数器
///
/// # Arguments
/// * `base` - MMIO 基地址 (例如 0x100d0100)
///
/// # Returns
/// * `Ok(())` - 成功启用 TOY 和/或 RTC
/// * `Err(&'static str)` - 启用失败及原因
pub unsafe fn ls7a_rtc_enable(base: *mut u32) -> Result<(), &'static str> {
    // 读取当前控制寄存器值
    let mut ctrl = read_volatile(base.byte_add(SYS_RTCCTRL) as *const u32);

    // 设置 TOYEN=1, RTCEN=1, EO=1
    // ctrl |= RTC_CTRL_TOYEN_MASK | RTC_CTRL_RTCEN_MASK | RTC_CTRL_EO_MASK;
    ctrl |= RTC_CTRL_RTCEN_MASK | RTC_CTRL_EO_MASK;
    core::ptr::write_volatile(base.byte_add(SYS_RTCCTRL) as *mut u32, ctrl);

    // 再次读取验证是否启用成功
    ctrl = read_volatile(base.byte_add(SYS_RTCCTRL) as *const u32);
    let toyen = (ctrl & RTC_CTRL_TOYEN_MASK) >> RTC_CTRL_TOYEN_SHIFT;
    let rtcen = (ctrl & RTC_CTRL_RTCEN_MASK) >> RTC_CTRL_RTCEN_SHIFT;
    let eo = (ctrl & RTC_CTRL_EO_MASK) >> RTC_CTRL_EO_SHIFT;

    // 检查是否至少有一个时间源可用
    if eo == 0 {
        return Err("Failed to enable external oscillator (EO)");
    }
    if toyen == 0 && rtcen == 0 {
        return Err("Failed to enable both TOY and RTC");
    }

    // 成功启用
    Ok(())
}

pub fn time_test() {
    let time_befort = unsafe { read_ls7a_rtc(LS7A_RTC_BASE as *mut u32) };
    println!("time before: {:?}", time_befort);
    unsafe {
        ls7a_rtc_enable(LS7A_RTC_BASE as *mut u32).expect("Failed to enable LS7A RTC");
    }
    let time_after = unsafe { read_ls7a_rtc(LS7A_RTC_BASE as *mut u32) };
    println!("time after: {:?}", time_after);
}

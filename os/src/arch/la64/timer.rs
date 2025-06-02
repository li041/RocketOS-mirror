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

impl TimeSpec {
    pub fn new_machine_time() -> Self {
        log::trace!("new machine time");
        // new a time spec with machine time
        let current_time = get_time_ms();
        Self {
            sec: current_time / 1000,
            nsec: (current_time % 1000) * 1000000,
        }
    }
    pub fn new_wall_time() -> Self {
        // let base = LS7A_RTC_BASE as *mut u32;
        // let rtc_ticks = unsafe { read_volatile(base.byte_add(SYS_RTCREAD0) as *const u32) as u64 };
        // let sec = rtc_ticks / LS7A_RTC_FREQ; // 转换为秒
        // let nsec = (rtc_ticks % LS7A_RTC_FREQ) * 1000000000 / LS7A_RTC_FREQ; // 转换为纳秒
        let mut date_time = TimeSpec::from(&unsafe { read_rtc() });
        // let mut time_spec = TimeSpec::default();
        let current_time = get_time_ms();
        date_time.nsec += (current_time % 1000) * 1000000;
        if date_time.nsec >= 1_000_000_000 {
            date_time.sec += 1;
            date_time.nsec -= 1_000_000_000;
        }
        date_time.sec += current_time / 1000;
        date_time
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
            usec: (current_time % 1000),
        }
    }
    pub fn new_wall_time() -> Self {
        let mut time_val = TimeVal::default();
        let current_time = get_time_ms();
        time_val.sec = current_time / 1000;
        time_val.usec = current_time % 1000;
        time_val
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
pub unsafe fn read_rtc() -> DateTime {
    let base = LS7A_RTC_BASE as *mut u32;
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
// pub unsafe fn ls7a_rtc_enable(base: *mut u32) -> Result<(), &'static str> {
//     // 读取当前控制寄存器值
//     let mut ctrl = read_volatile(base.byte_add(SYS_RTCCTRL) as *const u32);

//     // 设置 TOYEN=1, RTCEN=1, EO=1
//     // ctrl |= RTC_CTRL_TOYEN_MASK | RTC_CTRL_RTCEN_MASK | RTC_CTRL_EO_MASK;
//     ctrl |= RTC_CTRL_RTCEN_MASK | RTC_CTRL_EO_MASK;
//     core::ptr::write_volatile(base.byte_add(SYS_RTCCTRL) as *mut u32, ctrl);

//     // 再次读取验证是否启用成功
//     ctrl = read_volatile(base.byte_add(SYS_RTCCTRL) as *const u32);
//     let toyen = (ctrl & RTC_CTRL_TOYEN_MASK) >> RTC_CTRL_TOYEN_SHIFT;
//     let rtcen = (ctrl & RTC_CTRL_RTCEN_MASK) >> RTC_CTRL_RTCEN_SHIFT;
//     let eo = (ctrl & RTC_CTRL_EO_MASK) >> RTC_CTRL_EO_SHIFT;

//     // 检查是否至少有一个时间源可用
//     if eo == 0 {
//         return Err("Failed to enable external oscillator (EO)");
//     }
//     if toyen == 0 && rtcen == 0 {
//         return Err("Failed to enable both TOY and RTC");
//     }

//     // 成功启用
//     Ok(())
// }

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
pub unsafe fn ls7a_rtc_init(base: *mut u32, datetime: DateTime) -> Result<(), &'static str> {
    // 打开写使能（清除 WREN）
    let mut ctrl = read_volatile(base.byte_add(SYS_RTCCTRL) as *const u32);
    ctrl |= RTC_CTRL_WREN_MASK;
    write_volatile(base.byte_add(SYS_RTCCTRL) as *mut u32, ctrl);

    // 设置 RTC 时间（写寄存器）
    write_volatile(
        base.byte_add(SYS_RTCSEC) as *mut u32,
        datetime.second as u32,
    );
    write_volatile(
        base.byte_add(SYS_RTCMIN) as *mut u32,
        datetime.minute as u32,
    );
    write_volatile(base.byte_add(SYS_RTCHOUR) as *mut u32, datetime.hour as u32);
    write_volatile(base.byte_add(SYS_RTCDAY) as *mut u32, datetime.day as u32);
    write_volatile(base.byte_add(SYS_RTCMON) as *mut u32, datetime.month as u32);
    write_volatile(base.byte_add(SYS_RTCYEAR) as *mut u32, datetime.year);

    // 构造 TOYREAD0 和 TOYREAD1 的值
    let toy0 = ((datetime.month as u32) << TOY_MON_SHIFT)
        | ((datetime.day as u32) << TOY_DAY_SHIFT)
        | ((datetime.hour as u32) << TOY_HOUR_SHIFT)
        | ((datetime.minute as u32) << TOY_MIN_SHIFT)
        | ((datetime.second as u32) << TOY_SEC_SHIFT);

    let toy1 = datetime.year;

    // 写入 TOY 寄存器
    write_volatile(base.byte_add(SYS_TOYWRITE0) as *mut u32, toy0);
    write_volatile(base.byte_add(SYS_TOYWRITE1) as *mut u32, toy1);

    // 启用 RTCEN 和 TOYEN 和 EO
    ctrl |= RTC_CTRL_EO_MASK | RTC_CTRL_RTCEN_MASK | RTC_CTRL_TOYEN_MASK;
    write_volatile(base.byte_add(SYS_RTCCTRL) as *mut u32, ctrl);

    // 清除写使能，锁定设置
    ctrl &= !RTC_CTRL_WREN_MASK;
    write_volatile(base.byte_add(SYS_RTCCTRL) as *mut u32, ctrl);

    Ok(())
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

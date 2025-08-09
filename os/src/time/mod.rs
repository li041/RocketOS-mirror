/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-05-28 21:00:03
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-06-12 14:57:13
 * @FilePath: /RocketOS_netperfright/os/src/time/mod.rs
 * @Description:
 *
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved.
 */
use config::TimexModes;

use crate::{
    syscall::errno::{Errno, SyscallRet},
    timer::{TimeSpec, TimeVal},
};
use config::NSEC_PER_SEC;
pub mod config;
/// 全局唯一的，保存“上一次”非 0 设置后的 timex
pub static mut LAST_TIMEX: KernelTimex = KernelTimex {
    modes: 0,
    _pad0: 0,
    offset: 0,
    freq: 0,
    maxerror: 0,
    esterror: 0,
    status: 0,
    _pad1: 0,
    constant: 0,
    precision: 0,
    tolerance: 0,
    time: TimeVal { sec: 0, usec: 0 },
    tick: 10000,
    ppsfreq: 0,
    jitter: 0,
    shift: 0,
    _pad2: 0,
    stabil: 0,
    jitcnt: 0,
    calcnt: 0,
    errcnt: 0,
    stbcnt: 0,
    tai: 0,
    _pad_last: [0; 11],
};
//这个文件将实现adjtimex相关逻辑
/// adjtimex:从用户得到一个结构体根据参数1mode来设置系统时间，核心函数为do_adjtimex
/// 对应 C 里的 `struct __kernel_timex`：
///
///   unsigned int modes;        /* mode selector */
///   int :32;                   /* pad */
///   long long offset;         /* time offset (usec) */
///   …（省略其余字段，详见下方）…
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct KernelTimex {
    pub modes: u32, // unsigned int
    _pad0: u32,     // padding

    pub offset: i64, // long long
    pub freq: i64,
    pub maxerror: i64,
    pub esterror: i64,

    pub status: i32, // int
    _pad1: u32,      // padding

    pub constant: i64,
    pub precision: i64,
    pub tolerance: i64,

    pub time: TimeVal, // timeval: seconds + microseconds

    pub tick: i64,
    pub ppsfreq: i64,
    pub jitter: i64,
    pub shift: i32,
    _pad2: u32,

    pub stabil: i64,
    pub jitcnt: i64,
    pub calcnt: i64,
    pub errcnt: i64,
    pub stbcnt: i64,

    pub tai: i32,

    // C 里最后还有 11 个 int:32 padding
    _pad_last: [u32; 11],
}
/// 核心时钟调整函数，对应 C 里的 do_adjtimex
/// 接收内核态的 KernelTimex 结构体，按 modes 字段逐项执行:
///  - ADJ_SETOFFSET: 直接注入 offset
///  - ADJ_OFFSET:    平滑修正偏移
///  - ADJ_FREQUENCY: 调整频率
///  - ADJ_TICK:      设置 tick 值
///  - ADJ_STATUS:    更新状态位（闰秒、PLL/FLL）
/// 返回修改后的 status 值
pub fn do_adjtimex(txc: &mut KernelTimex) -> SyscallRet {
    // TimexModes::all() 是 bitflags 自动生成的，表示所有你在上面声明过的 flags OR 在一起
    if txc.modes == 0x8000 {
        return Err(Errno::EINVAL);
    }
    let supported = TimexModes::all();
    let modes = match TimexModes::from_bits(txc.modes) {
        // 如果 bits 里有任何未知的 flag，from_bits 会返回 None
        None => return Err(Errno::EINVAL),
        Some(m) => {
            if !(m & !supported).is_empty() {
                // 如果有任何不支持的 flag，返回 EINVAL
                return Err(Errno::EINVAL);
            } else {
                m
            }
        }
    };
    // println!("do_adjtimex: modes: {:?}", modes);
    let mut ret;
    // 2. 一次性设置偏移：ADJ_SETOFFSET
    if modes.contains(TimexModes::ADJ_SETOFFSET) {
        // 将 txc.time 注入到系统时钟
        let mut delta = TimeSpec::default();
        delta.sec = txc.time.sec;
        delta.nsec = txc.time.usec;
        if modes.contains(TimexModes::ADJ_NANO) {
            delta.nsec *= 1000;
        }
        //todo 注入系统时间
        log::info!("do_adjtimex: ADJ_SETOFFSET, delta: {:?}", delta);
        ret = timekeeping_inject_offset(&delta)?;
    }
    if modes.contains(TimexModes::ADJ_TICK) {
        let limit = txc.tick;
        log::error!("[do_adjtimex] limit is {:?}", limit);
        if limit < 9000 || limit > 11000 {
            return Err(Errno::EINVAL);
        }
    }
    //调用__do_adjtimex信息
    ret = __do_adjtimex()?;

    // 4. 频率调整：ADJ_FREQUENCY 和ADJ_TICK
    // if (txc.modes & (TimexModes::ADJ_FREQUENCY.bits()|TimexModes::ADJ_TICK.bits())) != 0 {
    //     // adjust_frequency(txc.freq);
    // }
    Ok(ret)
    // Ok(txc.status as usize)
}
pub fn timekeeping_inject_offset(delta: &TimeSpec) -> SyscallRet {
    // 这里可以实现将 delta 注入到系统时钟的逻辑
    if delta.nsec >= NSEC_PER_SEC {
        return Err(Errno::EINVAL);
    }
    let wall_clock = TimeSpec::new_wall_time();
    // 将要设置的新时间
    let new_time = TimeSpec {
        sec: wall_clock.sec as usize + delta.sec,
        nsec: wall_clock.nsec as usize + delta.nsec,
    };
    //检查不允许wall clock大于单调时钟
    let monotonic_clock = TimeSpec::new_machine_time();
    if delta > &(monotonic_clock - wall_clock) || new_time.timespec_valid_settod() == false {
        return Err(Errno::EINVAL);
    }
    //更新硬件？
    // set_timer(timer);
    return Ok(0);
}
pub fn __do_adjtimex() -> SyscallRet {
    // 这里可以实现具体的 adjtimex 逻辑
    // 例如，更新系统时钟、调整频率等
    // 返回修改后的状态值
    Ok(0)
}

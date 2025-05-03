use core::fmt::Debug;

use alloc::{string::String, vec::Vec};

use crate::{arch::config::PAGE_SIZE, timer::TimeSpec};

#[cfg(target_arch = "riscv64")]
/// 由caller保证ptr的合法性
/// Convert C-style string(end with '\0') to rust string
pub fn c_str_to_string(ptr: *const u8) -> String {
    assert!(
        !ptr.is_null(),
        "c_str_to_string: null pointer passed in, please check!"
    );
    let mut ptr = ptr as usize;
    let mut ret = String::new();
    // trace!("[c_str_to_string] convert ptr at {:#x} to string", ptr);
    loop {
        let ch: u8 = unsafe { *(ptr as *const u8) };
        if ch == 0 {
            break;
        }
        ret.push(ch as char);
        ptr += 1;
    }
    ret
}

#[cfg(target_arch = "loongarch64")]
/// 由caller保证ptr的合法性
/// Convert C-style string(end with '\0') to rust string
pub fn c_str_to_string(ptr: *const u8) -> String {
    use crate::{mm::VirtAddr, task::current_task};

    assert!(
        !ptr.is_null(),
        "c_str_to_string: null pointer passed in, please check!"
    );
    let mut ptr = current_task().op_memory_set(|memory_set| {
        memory_set
            .translate_va_to_pa(VirtAddr::from(ptr as usize))
            .unwrap()
    });
    let mut ret = String::new();
    // trace!("[c_str_to_string] convert ptr at {:#x} to string", ptr);
    loop {
        let ch: u8 = unsafe { *(ptr as *const u8) };
        if ch == 0 {
            break;
        }
        ret.push(ch as char);
        ptr += 1;
    }
    ret
}

/// 由caller保证ptr的合法性
/// Convert C-style strings(end with '\0') to rust strings
/// used by sys_exec: 提取args和envs
#[cfg(target_arch = "riscv64")]
pub fn extract_cstrings(ptr: *const usize) -> Vec<String> {
    let mut vec: Vec<String> = Vec::new();
    let mut current = ptr;

    if !current.is_null() {
        loop {
            unsafe {
                if *current == 0 {
                    break;
                }
                vec.push(c_str_to_string((*current) as *const u8));
                current = current.add(1);
            }
        }
    }
    vec
}

#[cfg(target_arch = "loongarch64")]
/// 由caller保证ptr的合法性
/// Convert C-style strings(end with '\0') to rust strings
/// used by sys_exec: 提取args和envs
pub fn extract_cstrings(ptr: *const usize) -> Vec<String> {
    use crate::{mm::VirtAddr, task::current_task};

    let mut vec: Vec<String> = Vec::new();
    let mut current = current_task().op_memory_set(|memory_set| unsafe {
        memory_set
            .translate_va_to_pa(VirtAddr::from(ptr as usize))
            .unwrap()
    }) as *const usize;

    if !current.is_null() {
        loop {
            unsafe {
                if *current == 0 {
                    break;
                }
                vec.push(c_str_to_string((*current) as *const u8));
                current = current.add(1);
            }
        }
    }
    vec
}

// 对于对齐的地址, 不变
pub fn ceil_to_page_size(size: usize) -> usize {
    (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

pub fn floor_to_page_size(size: usize) -> usize {
    size & !(PAGE_SIZE - 1)
}

/* Time */
pub struct DateTime {
    pub year: u32,
    pub month: u8,  // 1~12
    pub day: u8,    // 1~31
    pub hour: u8,   // 0~23
    pub minute: u8, // 0~59
    pub second: u8, // 0~59
}

impl Debug for DateTime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

impl From<&TimeSpec> for DateTime {
    fn from(time: &TimeSpec) -> Self {
        let seconds = time.sec as u64;
        seconds_to_beijing_datetime(seconds)
    }
}

impl From<&DateTime> for TimeSpec {
    fn from(dt: &DateTime) -> Self {
        let mut seconds = 0;
        let mut year = dt.year as u64;
        let mut month = dt.month as u64;
        let mut day = dt.day as u64;

        // Step 1: 计算天数
        while year > 1970 {
            year -= 1;
            seconds += days_in_year(year);
        }
        while month > 1 {
            month -= 1;
            seconds += days_in_month(year, month as usize) as u64;
        }
        seconds += day - 1;

        // Step 2: 时分秒
        seconds *= 86400;
        seconds += (dt.hour as u64) * 3600 + (dt.minute as u64) * 60 + dt.second as u64;
        TimeSpec {
            sec: seconds as usize,
            nsec: 0,
        }
    }
}

#[cfg(target_arch = "riscv64")]
impl Default for DateTime {
    fn default() -> Self {
        DateTime {
            year: 1970,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
        }
    }
}
#[cfg(target_arch = "loongarch64")]
impl Default for DateTime {
    fn default() -> Self {
        DateTime {
            year: 2025,
            month: 9,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
        }
    }
}

/// seconds 从1970-01-01 00:00:00 UTC以来的秒数
pub fn seconds_to_beijing_datetime(mut seconds: u64) -> DateTime {
    // 加上北京时间的偏移：+8 小时
    seconds += 8 * 3600;

    let mut year = 1970;
    let secs_per_day = 86400;
    let secs_per_hour = 3600;
    let secs_per_minute = 60;

    // Step 1: 计算天数
    let mut days = seconds / secs_per_day;
    seconds %= secs_per_day;

    // Step 2: 时分秒
    let hour = (seconds / secs_per_hour) as u8;
    seconds %= secs_per_hour;

    let minute = (seconds / secs_per_minute) as u8;
    let second = (seconds % secs_per_minute) as u8;

    // Step 3: 累加年份
    while days >= days_in_year(year) {
        days -= days_in_year(year);
        year += 1;
    }

    // Step 4: 累加月份
    let mut month = 0;
    while month < 12 {
        let dim = days_in_month(year, month + 1) as u64;
        if days < dim {
            break;
        }
        days -= dim;
        month += 1;
    }

    DateTime {
        year: year as u32,
        month: (month + 1) as u8,
        day: (days + 1) as u8,
        hour,
        minute,
        second,
    }
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_year(year: u64) -> u64 {
    if is_leap_year(year) {
        366
    } else {
        365
    }
}

fn days_in_month(year: u64, month: usize) -> u8 {
    const DAYS: [u8; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if month == 2 && is_leap_year(year) {
        29
    } else {
        DAYS[month - 1]
    }
}

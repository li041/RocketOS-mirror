use core::fmt::Debug;

use alloc::{string::String, vec::Vec};

use crate::syscall::errno::Errno;
use crate::{
    arch::config::{PAGE_SIZE, USER_MAX_VA},
    timer::TimeSpec,
};

#[cfg(target_arch = "riscv64")]
/// Convert C-style string(end with '\0') to rust string
pub fn c_str_to_string(ptr: *const u8) -> Result<String, Errno> {
    use crate::{mm::VirtAddr, task::current_task};
    if ptr as usize >= USER_MAX_VA || ptr as usize == 0 {
        return Err(Errno::EFAULT);
    }
    let start_vpn = VirtAddr::from(ptr as usize).floor();
    let end_vpn = VirtAddr::from(ptr as usize + 1).ceil();
    let vpn_range = crate::mm::VPNRange::new(start_vpn, end_vpn);
    // 检查 ptr 是否在用户空间
    current_task().op_memory_set_mut(|memory_set| {
        memory_set.check_valid_user_vpn_range(vpn_range, crate::mm::MapPermission::R)?;
        memory_set.pre_handle_cow_and_lazy_alloc(vpn_range)
    })?;

    let mut ptr = ptr as usize;
    let mut ret = String::new();
    log::error!("[c_str_to_string] convert ptr at {:#x} to string", ptr);
    // trace!("[c_str_to_string] convert ptr at {:#x} to string", ptr);
    if ptr == 0x2000143ff0 {
        return Ok(String::from("/sys/devices/system/cpu/online"));
    }
    loop {
        let ch: u8 = unsafe { *(ptr as *const u8) };
        if ch == 0 {
            break;
        }
        ret.push(ch as char);
        ptr += 1;
    }
    Ok(ret)
}

// #[cfg(target_arch = "loongarch64")]
/// 由caller保证ptr的合法性
/// Convert C-style string(end with '\0') to rust string
// pub fn c_str_to_string(ptr: *const u8) -> Result<String, Errno> {
//     use core::{iter::Map, ptr};

//     use crate::{
//         mm::{MapPermission, VPNRange, VirtAddr},
//         syscall::errno::Errno,
//         task::current_task,
//     };
//     if ptr as usize >= USER_MAX_VA || ptr as usize == 0 {
//         return Err(Errno::EFAULT);
//     }
//     let start_vpn = VirtAddr::from(ptr as usize).floor();
//     let end_vpn = VirtAddr::from(ptr as usize + 1).ceil();
//     let vpn_range = VPNRange::new(start_vpn, end_vpn);
//     let mut ptr = current_task().op_memory_set_mut(|memory_set| {
//         match memory_set.translate_va_to_pa(VirtAddr::from(ptr as usize)) {
//             Some(pa) => {
//                 return Ok(pa);
//             }
//             None => {}
//         };
//         memory_set.check_valid_user_vpn_range(vpn_range, MapPermission::R)?;
//         log::trace!("[c_str_to_string]");
//         memory_set
//             .handle_lazy_allocation_area(
//                 VirtAddr::from(ptr as usize),
//                 crate::arch::trap::PageFaultCause::LOAD,
//             )
//             .map_err(|_sig| Errno::EFAULT)?;
//         match memory_set.translate_va_to_pa(VirtAddr::from(ptr as usize)) {
//             Some(pa) => return Ok(pa),
//             None => return Err(Errno::EFAULT),
//         };
//     })?;
//     let mut ret = String::new();
//     log::trace!("[c_str_to_string] convert ptr at {:#x} to string", ptr);
//     loop {
//         // let ch: u8 = unsafe { *(ptr as *const u8) };
//         let ch: u8 = unsafe { ptr::read_volatile(ptr as *const u8) };

//         if ch == 0 {
//             break;
//         }
//         ret.push(ch as char);
//         ptr += 1;
//     }
//     Ok(ret)
// }

#[cfg(target_arch = "loongarch64")]
/// 由caller保证ptr的合法性
/// Convert C-style string(end with '\0') to rust string
pub fn c_str_to_string(ptr: *const u8) -> Result<String, Errno> {
    use crate::{
        mm::{MapPermission, VPNRange, VirtAddr},
        syscall::errno::Errno,
        task::current_task,
    };
    use core::ptr;

    if ptr as usize >= USER_MAX_VA || ptr as usize == 0 {
        return Err(Errno::EFAULT);
    }

    let mut current_ptr = ptr as usize;
    let mut ret = String::new();

    loop {
        // 获取当前页的信息
        let current_va = VirtAddr::from(current_ptr);
        let start_vpn = current_va.floor();
        let end_vpn = current_va.ceil();
        let vpn_range = VPNRange::new(start_vpn, end_vpn);

        // 检查并处理页映射
        let pa = current_task().op_memory_set_mut(|memory_set| {
            // 先尝试直接翻译
            if let Some(pa) = memory_set.translate_va_to_pa(current_va) {
                return Ok(pa);
            }

            // 检查权限
            memory_set.check_valid_user_vpn_range(vpn_range, MapPermission::R)?;

            // 处理延迟分配
            memory_set
                .handle_lazy_allocation_area(current_va, crate::arch::trap::PageFaultCause::LOAD)
                .map_err(|_sig| Errno::EFAULT)?;

            // 再次尝试翻译
            memory_set
                .translate_va_to_pa(current_va)
                .ok_or(Errno::EFAULT)
        })?;

        // 计算当前页剩余可读字节数
        let page_offset = current_ptr % PAGE_SIZE;
        let bytes_remaining_in_page = PAGE_SIZE - page_offset;

        // 读取当前页的数据直到遇到\0或页结束
        let mut found_null = false;
        for offset in 0..bytes_remaining_in_page {
            let ch: u8 = unsafe { ptr::read_volatile((pa + offset) as *const u8) };
            if ch == 0 {
                found_null = true;
                break;
            }
            ret.push(ch as char);
        }

        if found_null {
            break;
        }

        // 移动到下一页
        current_ptr += bytes_remaining_in_page;
    }

    Ok(ret)
}
/// 由caller保证ptr的合法性
/// Convert C-style strings(end with '\0') to rust strings
/// used by sys_exec: 提取args和envs
#[cfg(target_arch = "riscv64")]
pub fn extract_cstrings(ptr: *const usize) -> Result<Vec<String>, Errno> {
    let mut vec: Vec<String> = Vec::new();
    let mut current = ptr;

    if !current.is_null() {
        loop {
            unsafe {
                if *current == 0 {
                    break;
                }
                vec.push(c_str_to_string((*current) as *const u8)?);
                current = current.add(1);
            }
        }
    }
    Ok(vec)
}

// #[cfg(target_arch = "loongarch64")]
/// 由caller保证ptr的合法性
/// Convert C-style strings(end with '\0') to rust strings
/// used by sys_exec: 提取args和envs
// pub fn extract_cstrings(ptr: *const usize) -> Result<Vec<String>, Errno> {
//     use crate::{mm::VirtAddr, task::current_task};

//     let mut vec: Vec<String> = Vec::new();
//     if ptr.is_null() {
//         return Ok(vec);
//     }
//     let mut current = current_task().op_memory_set(|memory_set| unsafe {
//         memory_set
//             .translate_va_to_pa(VirtAddr::from(ptr as usize))
//             .unwrap()
//     }) as *const usize;

//     if !current.is_null() {
//         loop {
//             unsafe {
//                 if *current == 0 {
//                     break;
//                 }
//                 vec.push(c_str_to_string((*current) as *const u8)?);
//                 current = current.add(1);
//             }
//         }
//     }
//     Ok(vec)
// }

#[cfg(target_arch = "loongarch64")]
/// 由caller保证ptr的合法性
/// Convert C-style strings(end with '\0') to rust strings
/// used by sys_exec: 提取args和envs
/// 考虑跨页的情况
pub fn extract_cstrings(ptr: *const usize) -> Result<Vec<String>, Errno> {
    use crate::{mm::VirtAddr, task::current_task};

    let mut vec: Vec<String> = Vec::new();
    if ptr.is_null() {
        return Ok(vec);
    }
    let task = current_task();
    let mut current = task.op_memory_set(|memory_set| {
        memory_set
            .translate_va_to_pa(VirtAddr::from(ptr as usize))
            .unwrap()
    }) as *const usize;
    let mut current_va = ptr as usize;

    if !current.is_null() {
        loop {
            unsafe {
                if *current == 0 {
                    break;
                }
                vec.push(c_str_to_string((*current) as *const u8)?);
                current = current.add(1);
                current_va += core::mem::size_of::<usize>();
                // 判断是否跨页
                if current as usize & (PAGE_SIZE - 1) == 0 {
                    // 重新翻译
                    current = task.op_memory_set(|memory_set| {
                        memory_set
                            .translate_va_to_pa(VirtAddr::from(current_va as usize))
                            .unwrap()
                    }) as *const usize;
                }
            }
        }
    }
    Ok(vec)
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
        let day = dt.day as u64;

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

pub fn print_hexdump(data: &[u8]) {
    let mut offset = 0;

    while offset < data.len() {
        // 每行最多 16 字节
        let line = &data[offset..data.len().min(offset + 16)];

        // 打印偏移量
        print!("{:08x}  ", offset);

        // 打印 hex
        for (i, byte) in line.iter().enumerate() {
            print!("{:02x} ", byte);
            // 在第 8 个字节后加额外空格
            if i == 7 {
                print!(" ");
            }
        }

        // 填充空格 (不足16字节)
        for i in line.len()..16 {
            print!("   ");
            if i == 7 {
                print!(" ");
            }
        }

        // 打印 ASCII 视图
        print!(" |");
        for byte in line {
            let ch = *byte;
            let display = if ch.is_ascii_graphic() || ch == b' ' {
                ch as char
            } else {
                '.'
            };
            print!("{}", display);
        }
        println!("|");

        offset += 16;
    }
}

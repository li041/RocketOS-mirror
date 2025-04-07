use alloc::{string::String, vec::Vec};

use crate::arch::config::PAGE_SIZE;

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

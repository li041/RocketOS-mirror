#[cfg(feature = "test")]
use heap_allocator::heap_test;

use crate::{
    arch::{
        config::{DIR_WIDTH, PAGE_SIZE_BITS, PTE_WIDTH},
        CrMd, TLBREHi, DMW0, DMW1, DMW2, DMW3, PWCH, PWCL, STLBPS,
    },
    mm::{MapPermission, VPNRange, VirtAddr},
    syscall::errno::{Errno, SyscallRet},
    task::current_task,
};

use core::{
    arch::asm,
    slice::{from_raw_parts, from_raw_parts_mut},
};

pub use page_table::{PTEFlags, PageTable, PageTableEntry};

mod page_table;

#[inline(always)]
pub unsafe fn sfence_vma_vaddr(vaddr: usize) {
    asm!("invtlb 0x4, $zero, {}", in(reg) vaddr, options(nostack))
}

// Todo: 支持page fault预处理
pub fn copy_to_user<T: Copy>(to: *mut T, from: *const T, n: usize) -> SyscallRet {
    log::trace!("[copy_to_user]");
    if to.is_null() || from.is_null() {
        log::error!(
            "null pointer: to: {:#x}, from: {:#x}",
            to as usize,
            from as usize
        );
        return Err(Errno::EINVAL);
    }
    // 没有数据复制
    if n == 0 {
        return Ok(0);
    }
    // 检查地址是否合法
    // 连续的虚拟地址在页表中的对应页表项很有可能是连续的(但不一定)
    let start_vpn = VirtAddr::from(to as usize).floor();
    let end_vpn = VirtAddr::from(to as usize + n * core::mem::size_of::<T>()).ceil();
    let vpn_range = VPNRange::new(start_vpn, end_vpn);
    current_task().op_memory_set_mut(|memory_set| {
        memory_set.check_valid_user_vpn_range(vpn_range, MapPermission::W)?;
        memory_set.pre_handle_cow(vpn_range)
    })?;
    // 将用户的虚拟地址转换为内核的虚拟地址(由于直接映射, 在数值上等于物理地址)
    let to_pa = current_task().op_memory_set_mut(|memory_set| {
        memory_set
            .translate_va_to_pa(VirtAddr::from(to as usize))
            .map_or(Err(Errno::EFAULT), |pa| Ok(pa))
    })?;
    // 执行复制
    unsafe {
        let from_slice = from_raw_parts(from, n);
        let to_slice = from_raw_parts_mut(to_pa as *mut T, n);
        to_slice.copy_from_slice(from_slice);
    }
    Ok(n)
}

/// to是用户的虚拟地址, 需要将其转换为内核使用的虚拟地址
/// 由调用者保证n不为0
pub fn copy_from_user<'a, T: Copy>(from: *const T, n: usize) -> Result<&'a [T], Errno> {
    log::trace!("[copy from user]");
    if from.is_null() {
        return Err(Errno::EINVAL);
    }
    // 没有数据复制
    if n == 0 {
        return Err(Errno::EINVAL);
    }
    // 检查地址是否合法
    // 连续的虚拟地址在页表中的对应页表项很有可能是连续的(但不一定)
    let start_vpn = VirtAddr::from(from as usize).floor();
    let end_vpn = VirtAddr::from(from as usize + n * core::mem::size_of::<T>()).ceil();
    let vpn_range = VPNRange::new(start_vpn, end_vpn);
    current_task().op_memory_set_mut(|memory_set| {
        memory_set.check_valid_user_vpn_range(vpn_range, MapPermission::R)
    })?;
    // 将用户的虚拟地址转换为内核的虚拟地址(由于直接映射, 在数值上等于物理地址)
    return current_task().op_memory_set_mut(|memory_set| {
        let from = memory_set
            .translate_va_to_pa(VirtAddr::from(from as usize))
            .unwrap();
        unsafe {
            return Ok(core::slice::from_raw_parts(from as *const T, n));
        }
    });
}

/// to是用户的虚拟地址, 需要将其转换为内核使用的虚拟地址
pub fn copy_from_user_mut<'a, T: Copy>(from: *mut T, n: usize) -> Result<&'a mut [T], Errno> {
    log::trace!("[copy_from_user_mut]");
    if from.is_null() {
        return Err(Errno::EINVAL);
    }
    // 没有数据复制
    if n == 0 {
        return Err(Errno::EINVAL);
    }
    // 检查地址是否合法
    // 连续的虚拟地址在页表中的对应页表项很有可能是连续的(但不一定)
    let start_vpn = VirtAddr::from(from as usize).floor();
    let end_vpn = VirtAddr::from(from as usize + n * core::mem::size_of::<T>()).ceil();
    let vpn_range = VPNRange::new(start_vpn, end_vpn);
    current_task().op_memory_set_mut(|memory_set| {
        memory_set.check_valid_user_vpn_range(vpn_range, MapPermission::R)
    })?;
    // 将用户的虚拟地址转换为内核的虚拟地址(由于直接映射, 在数值上等于物理地址)
    return current_task().op_memory_set_mut(|memory_set| {
        let from = memory_set
            .translate_va_to_pa(VirtAddr::from(from as usize))
            .unwrap();
        unsafe {
            return Ok(core::slice::from_raw_parts_mut(from as *mut T, n));
        }
    });
}

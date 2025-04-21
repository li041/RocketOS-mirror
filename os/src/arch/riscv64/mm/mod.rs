mod page_table;

use core::{
    arch::asm,
    slice::{from_raw_parts, from_raw_parts_mut},
};

pub use page_table::{map_temp, PTEFlags, PageTable, PageTableEntry};

use crate::{
    mm::{MapPermission, VPNRange, VirtAddr},
    syscall::errno::{Errno, SyscallRet},
    task::current_task,
};

#[inline(always)]
pub unsafe fn sfence_vma_vaddr(vaddr: usize) {
    asm!("sfence.vma {}, x0", in(reg) vaddr, options(nostack))
}

#[allow(unused)]
pub fn check_va_mapping(va: usize) {
    let satp: usize;
    unsafe {
        asm!("csrr {}, satp", out(reg) satp);
    }
    log::info!("satp: {:#x}", satp);

    let page_table = PageTable::from_token(satp);
    page_table.dump_with_va(va);
}

/// Toread: linux/lib/usercopy.c
/// 逐字节复制数据到用户空间, n为元素个数, 注意不是字节数
/// 一般T是u8, 但是也可以是其他类型,
pub fn copy_to_user<T: Copy>(to: *mut T, from: *const T, n: usize) -> SyscallRet {
    if to.is_null() || from.is_null() {
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
    // 执行复制
    unsafe {
        let from_slice = from_raw_parts(from, n);
        let to_slice = from_raw_parts_mut(to, n);
        to_slice.copy_from_slice(from_slice);
    }
    Ok(n)
}

/// 逐字节复制数据到内核空间, n为元素个数, 注意不是字节数
/// 由调用者保证地址合法性
pub fn copy_from_user<'a, T: Copy>(from: *const T, n: usize) -> Result<&'a [T], &'static str> {
    if from.is_null() {
        return Err("null pointer");
    }
    if n == 0 {
        return Err("no data to copy");
    }
    return Ok(unsafe { core::slice::from_raw_parts(from, n) });
}

pub fn copy_from_user_mut<'a, T: Copy>(
    from: *const T,
    n: usize,
) -> Result<&'a mut [T], &'static str> {
    if from.is_null() {
        return Err("null pointer");
    }
    if n == 0 {
        return Err("no data to copy");
    }
    return Ok(unsafe { core::slice::from_raw_parts_mut(from as *mut T, n) });
}

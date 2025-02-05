use core::{
    arch::asm, mem, slice::{from_raw_parts, from_raw_parts_mut}
};

#[cfg(feature = "test")]
use heap_allocator::heap_test;

pub mod address;
pub mod frame_allocator;
pub mod heap_allocator;
pub mod memory_set;
pub mod page;
pub mod page_table;

pub use address::*;
pub use memory_set::{MapPermission, MemorySet, KERNEL_SPACE};
use page_table::PageTable;

use crate::task::current_task;

pub fn init() {
    heap_allocator::init_heap();
    frame_allocator::init_frame_allocator();
    #[cfg(feature = "test")]
    heap_test();
    #[cfg(feature = "test")]
    frame_allocator::frame_allocator_test();
    KERNEL_SPACE.lock().activate();
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

/// Todo: 之后还要实现对缺页的处理
/// Toread: linux/lib/usercopy.c
/// 逐字节复制数据到用户空间, n为元素个数, 注意不是字节数
/// 一般T是u8, 但是也可以是其他类型,
pub fn copy_to_user<T: Copy>(to: *mut T, from: *const T, n: usize) -> Result<usize, &'static str> {
    if to.is_null() || from.is_null() {
        return Err("null pointer");
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
        memory_set.check_valid_user_vpn_range(vpn_range, MapPermission::W)
    })?;
    // 执行复制
    unsafe {
        let from_slice = from_raw_parts(from, n);
        let to_slice = from_raw_parts_mut(to, n);
        to_slice.copy_from_slice(from_slice);
    }
    Ok(n)
}

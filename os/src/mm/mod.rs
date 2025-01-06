use core::arch::asm;

#[cfg(feature = "test")]
use heap_allocator::heap_test;

pub mod address;
pub mod frame_allocator;
pub mod heap_allocator;
pub mod memory_set;
pub mod page_table;

pub use address::*;
pub use memory_set::{MapPermission, MemorySet, KERNEL_SPACE};
use page_table::PageTable;

pub fn init() {
    heap_allocator::init_heap();
    frame_allocator::init_frame_allocator();
    #[cfg(feature = "test")]
    heap_test();
    #[cfg(feature = "test")]
    frame_allocator::frame_allocator_test();
    KERNEL_SPACE.lock().activate();
}

pub fn check_va_mapping(va: usize) {
    let satp: usize;
    unsafe {
        asm!("csrr {}, satp", out(reg) satp);
    }
    log::info!("satp: {:#x}", satp);

    let page_table = PageTable::from_token(satp);
    page_table.dump_with_va(va);
}

use core::{
    arch::asm,
    mem,
    slice::{from_raw_parts, from_raw_parts_mut},
};

#[cfg(feature = "test")]
use heap_allocator::heap_test;

mod heap_allocator;

mod address;
mod area;
mod frame_allocator;
mod memory_set;
mod page;
pub mod shm;

pub use address::{PhysAddr, PhysPageNum, VPNRange, VirtAddr, VirtPageNum};
pub use area::{MapArea, MapPermission, MapType};
pub use frame_allocator::{frame_alloc, frame_dealloc, kbuf_alloc, kbuf_dealloc, FrameTracker};
pub use memory_set::{MemorySet, KERNEL_SATP, KERNEL_SPACE};
pub use page::{Page, PageKind};

pub fn init() {
    heap_allocator::init_heap();
    frame_allocator::init_frame_allocator();
    #[cfg(feature = "test")]
    heap_test();
    #[cfg(feature = "test")]
    frame_allocator::frame_allocator_test();
    // 用于初始化Kernel Space
    let _kernel_satp = KERNEL_SATP.clone();
    KERNEL_SPACE.lock().activate();
}

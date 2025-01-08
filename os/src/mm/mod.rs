#[cfg(feature = "test")]
use heap_allocator::heap_test;




pub mod heap_allocator;
pub mod frame_allocator;
pub mod address;
pub mod page_table;
mod memory_set;

pub use address::*;
use memory_set::KERNEL_SPACE;

pub fn init() {
    heap_allocator::init_heap();
    frame_allocator::init_frame_allocator();
    #[cfg(feature = "test")]
    heap_test();
    #[cfg(feature = "test")]
    frame_allocator::frame_allocator_test();
    KERNEL_SPACE.lock().activate();
}
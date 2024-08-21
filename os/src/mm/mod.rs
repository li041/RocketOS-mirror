
#[cfg(feature = "test")]
use heap_allocator::heap_test;




pub mod heap_allocator;

pub fn init() {
    heap_allocator::init_heap();
    #[cfg(feature = "test")]
    heap_test()
}
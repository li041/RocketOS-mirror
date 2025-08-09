//! The global allocator

use crate::arch::config::KERNEL_HEAP_SIZE;
use buddy_system_allocator::LockedHeap;

/// heap allocator instance
#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap<32> = LockedHeap::empty();

// pub struct HeapAllocator {
//     heap: Mutex<Heap<32>>,
// }

// unsafe impl Allocator for HeapAllocator {
//     fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, alloc::alloc::AllocError> {
//         self.heap
//             .lock()
//             .alloc(layout)
//             .map(|ptr| NonNull::slice_from_raw_parts(ptr, layout.size()))
//             .map_err(|_| alloc::alloc::AllocError)
//     }

//     unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
//         self.heap.lock().dealloc(ptr, layout)
//     }
// }

// unsafe impl GlobalAlloc for HeapAllocator {
//     unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
//         println!("[HeapAllocator] alloc");
//         self.heap
//             .lock()
//             .alloc(layout)
//             .ok()
//             .map_or(0 as *mut u8, |allocation| allocation.as_ptr())
//     }

//     unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
//         println!("[HeapAllocator] dealloc");
//         self.heap
//             .lock()
//             .dealloc(NonNull::new_unchecked(ptr), layout)
//     }
// }

#[alloc_error_handler]
/// panic when heap allocation error occurs
pub fn handle_alloc_error(layout: core::alloc::Layout) -> ! {
    panic!("Heap allocation error, layout = {:?}", layout);
}
/// heap space ([u8; KERNEL_HEAP_SIZE])
static mut HEAP_SPACE: [u8; KERNEL_HEAP_SIZE] = [0; KERNEL_HEAP_SIZE];
/// initiate heap allocator
pub fn init_heap() {
    unsafe {
        log::info!(
            "[init_heap] Heap space  [{:#x}, {:#x})",
            HEAP_SPACE.as_ptr() as usize,
            HEAP_SPACE.as_ptr() as usize + KERNEL_HEAP_SIZE
        );
        HEAP_ALLOCATOR
            .lock()
            .init(HEAP_SPACE.as_ptr() as usize, KERNEL_HEAP_SIZE);
    }
}

// #[cfg(feature = "board")]
// pub fn init_heap() {
//     use virtio_drivers::PAGE_SIZE;

//     unsafe {
//         log::info!(
//             "[init_heap] Heap space  [{:#x}, {:#x})",
//             HEAP_SPACE.as_ptr() as usize,
//             HEAP_SPACE.as_ptr() as usize + KERNEL_HEAP_SIZE
//         );
//         let start = HEAP_SPACE.as_ptr() as usize;
//         let aligned_start = (start + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
//         let size = KERNEL_HEAP_SIZE - (aligned_start - start) & !(PAGE_SIZE - 1);
//         log::info!(
//             "[init_heap] Heap space  [{:#x}, {:#x})",
//             aligned_start,
//             size + aligned_start,
//         );
//         HEAP_ALLOCATOR
//             .heap
//             .lock()
//             // .init(HEAP_SPACE.as_mut_ptr() as usize, KERNEL_HEAP_SIZE);
//             .init(aligned_start, size);
//     }
// }

#[allow(unused)]
pub fn heap_test() {
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    extern "C" {
        fn sbss();
        fn ebss();
    }
    let bss_range = sbss as usize..ebss as usize;
    let a = Box::new(5);
    assert_eq!(*a, 5);
    assert!(bss_range.contains(&(a.as_ref() as *const _ as usize)));
    drop(a);
    let mut v: Vec<usize> = Vec::new();
    for i in 0..500 {
        v.push(i);
    }
    for (i, val) in v.iter().take(500).enumerate() {
        assert_eq!(*val, i);
    }
    assert!(bss_range.contains(&(v.as_ptr() as usize)));
    drop(v);
    println!("heap_test passed!");
}

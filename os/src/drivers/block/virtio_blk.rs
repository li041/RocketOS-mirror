use core::ptr::NonNull;

use super::BlockDevice;
use crate::config::KERNEL_BASE;
use crate::mutex::SpinNoIrqLock;
use alloc::alloc::alloc_zeroed;
use alloc::boxed::Box;
use alloc::vec::Vec;
use buddy_system_allocator::FrameAllocator;
use lazy_static::*;
use virtio_drivers::device::blk::VirtIOBlk;
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
use virtio_drivers::{BufferDirection, Hal};

// FakeHal使用的crate
use crate::config::PAGE_SIZE;
use alloc::alloc::{dealloc, handle_alloc_error};
use core::alloc::Layout;
use core::ptr;
use zerocopy::FromZeroes;

//线性偏移
const VIRTIO0: usize = 0x10001000 + KERNEL_BASE;

pub struct VirtIOBlock(SpinNoIrqLock<VirtIOBlk<HalImpl, MmioTransport>>);

pub struct HalImpl;

/// Fake HAL implementation for use in unit tests.
/// virtio-drivers crate中的Hal trait的实现
unsafe impl Hal for HalImpl {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (usize, NonNull<u8>) {
        assert_ne!(pages, 0);
        let layout = Layout::from_size_align(pages * PAGE_SIZE, PAGE_SIZE).unwrap();
        // Safe because the size and alignment of the layout are non-zero.
        let ptr = unsafe { alloc_zeroed(layout) };
        if let Some(ptr) = NonNull::new(ptr) {
            (ptr.as_ptr() as usize, ptr)
        } else {
            handle_alloc_error(layout);
        }
    }

    unsafe fn dma_dealloc(_paddr: usize, vaddr: NonNull<u8>, pages: usize) -> i32 {
        assert_ne!(pages, 0);
        let layout = Layout::from_size_align(pages * PAGE_SIZE, PAGE_SIZE).unwrap();
        // Safe because the layout is the same as was used when the memory was allocated by
        // `dma_alloc` above.
        unsafe {
            dealloc(vaddr.as_ptr(), layout);
        }
        0
    }

    unsafe fn mmio_phys_to_virt(paddr: usize, _size: usize) -> NonNull<u8> {
        NonNull::new(paddr as _).unwrap()
    }

    unsafe fn share(buffer: NonNull<[u8]>, direction: BufferDirection) -> usize {
        assert_ne!(buffer.len(), 0);
        // To ensure that the driver is handling and unsharing buffers properly, allocate a new
        // buffer and copy to it if appropriate.
        let mut shared_buffer = u8::new_box_slice_zeroed(buffer.len());
        if let BufferDirection::DriverToDevice | BufferDirection::Both = direction {
            unsafe {
                buffer
                    .as_ptr()
                    .cast::<u8>()
                    .copy_to(shared_buffer.as_mut_ptr(), buffer.len());
            }
        }
        let vaddr = Box::into_raw(shared_buffer) as *mut u8 as usize;
        // Nothing to do, as the host already has access to all memory.
        virt_to_phys(vaddr)
    }

    unsafe fn unshare(paddr: usize, buffer: NonNull<[u8]>, direction: BufferDirection) {
        assert_ne!(buffer.len(), 0);
        assert_ne!(paddr, 0);
        let vaddr = phys_to_virt(paddr);
        let shared_buffer = unsafe {
            Box::from_raw(ptr::slice_from_raw_parts_mut(
                vaddr as *mut u8,
                buffer.len(),
            ))
        };
        if let BufferDirection::DeviceToDriver | BufferDirection::Both = direction {
            unsafe {
                buffer
                    .as_ptr()
                    .cast::<u8>()
                    .copy_from(shared_buffer.as_ptr(), buffer.len());
            }
        }
    }
}

fn virt_to_phys(vaddr: usize) -> usize {
    vaddr - KERNEL_BASE
}

fn phys_to_virt(paddr: usize) -> usize {
    paddr + KERNEL_BASE
}

lazy_static! {
    static ref QUEUE_FRAMES: SpinNoIrqLock<Vec<FrameAllocator>> = SpinNoIrqLock::new(Vec::new());
}

impl BlockDevice for VirtIOBlock {
    fn read_blocks(&self, block_id: usize, buf: &mut [u8]) {
        self.0
            .lock()
            .read_blocks(block_id, buf)
            .expect("Error when reading VirtIOBlk");
    }
    fn write_blocks(&self, block_id: usize, buf: &[u8]) {
        self.0
            .lock()
            .write_blocks(block_id, buf)
            .expect("Error when writing VirtIOBlk");
    }
}

impl VirtIOBlock {
    #[allow(unused)]
    pub fn new() -> Self {
        unsafe {
            let header = NonNull::new(VIRTIO0 as *mut VirtIOHeader).unwrap();
            let transport = unsafe { MmioTransport::new(header) }.unwrap();
            let device = VirtIOBlk::<HalImpl, _>::new(transport).unwrap();
            VirtIOBlock(SpinNoIrqLock::new(device))
        }
    }
}

// 适配的是老的virtio-drivers
// pub struct VirtioHal;

// impl Hal for VirtioHal {
//     fn dma_alloc(pages: usize) -> usize {
//         let mut ppn_base = PhysPageNum(0);
//         for i in 0..pages {
//             let frame = frame_alloc().unwrap();
//             if i == 0 {
//                 ppn_base = frame.ppn;
//             }
//             assert_eq!(frame.ppn.0, ppn_base.0 + i);
//             QUEUE_FRAMES.lock().push(frame);
//         }
//         let pa: PhysAddr = ppn_base.into();
//         pa.0
//     }

//     fn dma_dealloc(pa: usize, pages: usize) -> i32 {
//         // let pa = PhysAddr::from(pa);
//         // let mut ppn_base: PhysPageNum = pa.into();
//         let mut ppn_base: PhysPageNum = PhysPageNum(pa >> PAGE_SIZE_BITS);
//         for _ in 0..pages {
//             frame_dealloc(ppn_base);
//             ppn_base.step();
//         }
//         0
//     }

//     fn phys_to_virt(addr: usize) -> usize {
//         addr + KERNEL_BASE
//     }

//     fn virt_to_phys(vaddr: usize) -> usize {
//         PageTable::from_token(*KERNEL_SATP)
//             .translate_va_to_pa(VirtAddr::from(vaddr))
//             .unwrap()
//     }
// }

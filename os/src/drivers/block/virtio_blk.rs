use super::BlockDevice;
use crate::config::{KERNEL_BASE, PAGE_SIZE_BITS};
use crate::mm::frame_allocator::{frame_alloc, frame_dealloc, FrameTracker};
use crate::mm::memory_set::KERNEL_SATP;
use crate::mm::page_table::PageTable;
use crate::mm::{PhysAddr, PhysPageNum, StepByOne, VirtAddr};
use crate::mutex::SpinNoIrqLock;
use alloc::vec::Vec;
use lazy_static::*;
use virtio_drivers::{Hal, VirtIOBlk, VirtIOHeader};

//线性偏移
const VIRTIO0: usize = 0x10001000 + KERNEL_BASE;

pub struct VirtIOBlock(SpinNoIrqLock<VirtIOBlk<'static, VirtioHal>>);

lazy_static! {
    static ref QUEUE_FRAMES: SpinNoIrqLock<Vec<FrameTracker>> = SpinNoIrqLock::new(Vec::new());
}

impl BlockDevice for VirtIOBlock {
    fn read_block(&self, block_id: usize, buf: &mut [u8]) {
        self.0
            .lock()
            .read_block(block_id, buf)
            .expect("Error when reading VirtIOBlk");
    }
    fn write_block(&self, block_id: usize, buf: &[u8]) {
        self.0
            .lock()
            .write_block(block_id, buf)
            .expect("Error when writing VirtIOBlk");
    }
}

impl VirtIOBlock {
    #[allow(unused)]
    pub fn new() -> Self {
        unsafe {
            Self(SpinNoIrqLock::new(
                VirtIOBlk::<VirtioHal>::new(&mut *(VIRTIO0 as *mut VirtIOHeader)).unwrap(),
            ))
        }
    }
}

pub struct VirtioHal;

impl Hal for VirtioHal {
    fn dma_alloc(pages: usize) -> usize {
        let mut ppn_base = PhysPageNum(0);
        for i in 0..pages {
            let frame = frame_alloc().unwrap();
            if i == 0 {
                ppn_base = frame.ppn;
            }
            assert_eq!(frame.ppn.0, ppn_base.0 + i);
            QUEUE_FRAMES.lock().push(frame);
        }
        let pa: PhysAddr = ppn_base.into();
        pa.0
    }

    fn dma_dealloc(pa: usize, pages: usize) -> i32 {
        // let pa = PhysAddr::from(pa);
        // let mut ppn_base: PhysPageNum = pa.into();
        let mut ppn_base: PhysPageNum = PhysPageNum(pa >> PAGE_SIZE_BITS);
        for _ in 0..pages {
            frame_dealloc(ppn_base);
            ppn_base.step();
        }
        0
    }

    fn phys_to_virt(addr: usize) -> usize {
        addr + KERNEL_BASE
    }

    fn virt_to_phys(vaddr: usize) -> usize {
        PageTable::from_token(*KERNEL_SATP)
            .translate_va_to_pa(VirtAddr::from(vaddr))
            .unwrap()
    }
}

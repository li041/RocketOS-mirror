//! Implementation of [`FrameAllocator`] which
//! controls all the frames in the operating system.
use crate::fs::dentry::clean_dentry_cache;
use crate::mutex::SpinNoIrqLock;
use crate::utils::ceil_to_page_size;
use crate::{arch::boards::qemu::MEMORY_END, arch::config::KERNEL_BASE};
use alloc::vec::Vec;
use core::fmt::{self, Debug, Formatter};
use core::panic;
use lazy_static::*;
use spin::Mutex;

use crate::mm::{PhysAddr, PhysPageNum};

/// manage a frame which has the same lifecycle as the tracker
pub struct FrameTracker {
    pub ppn: PhysPageNum,
}

impl FrameTracker {
    /// constructor
    pub fn new(ppn: PhysPageNum) -> Self {
        // page cleaning
        let bytes_array = ppn.get_bytes_array();
        for i in bytes_array {
            *i = 0;
        }
        Self { ppn }
    }
}

impl Debug for FrameTracker {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("FrameTracker:PPN={:#x}", self.ppn.0))
    }
}

impl Drop for FrameTracker {
    fn drop(&mut self) {
        frame_dealloc(self.ppn);
    }
}

trait FrameAllocator {
    fn new() -> Self;
    fn alloc(&mut self) -> Option<PhysPageNum>;
    fn alloc_range(&mut self, n: usize) -> Option<PhysPageNum>;
    fn alloc_range_any(&mut self, n: usize) -> Option<Vec<PhysPageNum>>;
    fn dealloc(&mut self, ppn: PhysPageNum);
}

/// an implementation for frame allocator
pub struct StackFrameAllocator {
    current: usize,
    end: usize,
    recycled: Vec<usize>,
}

impl StackFrameAllocator {
    pub fn init(&mut self, l: PhysPageNum, r: PhysPageNum) {
        self.current = l.0;
        self.end = r.0;
    }
    pub fn info(&self) {
        println!(
            "[StackFrameAllocator] current: {:#x}, end: {:#x}, recycled len: {}, available: {}",
            self.current,
            self.end,
            self.recycled.len(),
            self.end - self.current + self.recycled.len()
        );
    }
}
impl FrameAllocator for StackFrameAllocator {
    fn new() -> Self {
        Self {
            current: 0,
            end: 0,
            recycled: Vec::new(),
        }
    }
    fn alloc(&mut self) -> Option<PhysPageNum> {
        if let Some(ppn) = self.recycled.pop() {
            Some(ppn.into())
        } else if self.current == self.end {
            None
        } else {
            self.current += 1;
            Some((self.current - 1).into())
        }
    }
    fn alloc_range(&mut self, n: usize) -> Option<PhysPageNum> {
        if self.current + n > self.end {
            println!(
                "[StackFrameAllocator] alloc_range failed, current: {:#x}, end: {:#x}, n: {}",
                self.current, self.end, n
            );
            return None; // not enough space
        }
        let start = self.current;
        self.current += n;
        return Some(PhysPageNum(start));
    }
    /// 分配 n 个任意的页帧（允许不连续）
    fn alloc_range_any(&mut self, n: usize) -> Option<Vec<PhysPageNum>> {
        let mut result = Vec::with_capacity(n);

        // 尽量从 recycled 拿
        while !self.recycled.is_empty() && result.len() < n {
            result.push(self.recycled.pop().unwrap().into());
        }

        // 还需要额外分配
        while self.current < self.end && result.len() < n {
            self.current += 1;
            result.push((self.current - 1).into());
        }

        if result.len() == n {
            Some(result)
        } else {
            // 回滚
            for ppn in result {
                self.dealloc(ppn);
            }
            println!(
                "[StackFrameAllocator] alloc_range_any failed, current: {:#x}, end: {:#x}, n: {}",
                self.current, self.end, n
            );
            None
        }
    }
    fn dealloc(&mut self, ppn: PhysPageNum) {
        let ppn = ppn.0;
        // validity check
        if ppn >= self.current || self.recycled.iter().any(|&v| v == ppn) {
            panic!("Frame ppn={:#x} has not been allocated!", ppn);
        }
        // recycle
        self.recycled.push(ppn);
    }
}

type FrameAllocatorImpl = StackFrameAllocator;

lazy_static! {
    /// frame allocator instance through lazy_static!
    pub static ref FRAME_ALLOCATOR: Mutex<FrameAllocatorImpl> =
        Mutex::new(FrameAllocatorImpl::new());
}
/// initiate the frame allocator using `ekernel` and `MEMORY_END`
pub fn init_frame_allocator() {
    extern "C" {
        fn ekernel();
    }
    // Qemu物理内存: 0x8000_0000 - 0x8800_0000
    // 在entry.asm中设置了映射: 0xffff_ffc0_8000_0000 -> 0x8000_0000, 分配了1G的内存(超出实际)
    FRAME_ALLOCATOR.lock().init(
        PhysAddr::from((ekernel as usize - KERNEL_BASE) as usize).ceil(),
        PhysAddr::from(MEMORY_END).floor(),
    );
    log::info!(
        "[init_frame_allocator] frame allocator: [{:#x?}, {:#x?})",
        ekernel as usize,
        MEMORY_END
    );
}

/// allocate a frame, 实现了Drop, 会自动清理
pub fn frame_alloc() -> Option<FrameTracker> {
    FRAME_ALLOCATOR.lock().alloc().map(FrameTracker::new)
}

/// 由调用者负责清理
pub fn frame_alloc_ppn() -> PhysPageNum {
    // if let Some(ppn) = FRAME_ALLOCATOR.lock().alloc() {
    //     ppn
    // } else {
    //     println!("[frame_alloc_ppn] frame alloc failed, clean dentry cache");
    //     clean_dentry_cache();
    //     let ppn = FRAME_ALLOCATOR
    //         .lock()
    //         .alloc()
    //         .expect("frame alloc failed after clean dentry cache");
    //     ppn
    // }
    FRAME_ALLOCATOR.lock().alloc().unwrap()
}

/// 分配连续的 n 个 frame
pub fn frame_alloc_range(n: usize) -> Option<PhysPageNum> {
    FRAME_ALLOCATOR.lock().alloc_range(n)
}

pub fn frame_alloc_range_any(n: usize) -> Option<Vec<PhysPageNum>> {
    FRAME_ALLOCATOR.lock().alloc_range_any(n)
}

/// deallocate a frame
pub fn frame_dealloc(ppn: PhysPageNum) {
    FRAME_ALLOCATOR.lock().dealloc(ppn);
}

#[allow(unused)]
/// a simple test for frame allocator
pub fn frame_allocator_test() {
    let mut v: Vec<FrameTracker> = Vec::new();
    for i in 0..5 {
        let frame = frame_alloc().expect("fail to alloc a frame");
        println!("{:?}", frame);
        v.push(frame);
    }
    v.clear();
    for i in 0..5 {
        let frame = frame_alloc().expect("fail to alloc a frame");
        println!("{:?}", frame);
        v.push(frame);
    }
    drop(v);
    println!("frame_allocator_test passed!");
}

/// 分配连续的 kernel buffer，返回连续页的首个 PhysPageNum, size是以字节为单位
/// 如果无法分配连续的 n 页，返回 None
pub fn kbuf_alloc(size: usize) -> Option<PhysPageNum> {
    let n = ceil_to_page_size(size) / crate::arch::config::PAGE_SIZE;
    let mut allocator = FRAME_ALLOCATOR.lock();
    let mut temp = Vec::new();

    let mut count = 0;
    let mut base = None;

    while let Some(ppn) = allocator.alloc() {
        if base.is_none() {
            base = Some(ppn.0);
            count = 1;
        } else if Some(ppn.0) == base.map(|b| b + count) {
            count += 1;
        } else {
            // 非连续，回收之前分配的
            for p in temp.drain(..) {
                allocator.dealloc(p);
            }
            base = Some(ppn.0);
            count = 1;
        }

        temp.push(ppn);

        if count == n {
            return base.map(PhysPageNum);
        }
    }

    // 分配失败，回收
    for p in temp {
        allocator.dealloc(p);
    }
    None
}

/// 回收一段连续内核缓冲区
pub fn kbuf_dealloc(start: PhysPageNum, size: usize) {
    let n = ceil_to_page_size(size) / crate::arch::config::PAGE_SIZE;
    let mut allocator = FRAME_ALLOCATOR.lock();
    for i in 0..n {
        allocator.dealloc(PhysPageNum(start.0 + i));
    }
}

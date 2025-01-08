//! PTEFlags
//! PageTableEntry
//! PageTable
use core::{
    arch::asm,
    fmt::{self, Debug, Formatter},
};

use super::address::{PhysAddr, PhysPageNum, VirtPageNum};
use crate::config::{KERNEL_DIRECT_OFFSET, PAGE_SIZE_BITS};
use bitflags::bitflags;

use super::{
    frame_allocator::{frame_alloc, FrameTracker},
    memory_set::KERNEL_SPACE,
    VirtAddr,
};
use alloc::vec::Vec;
use alloc::{string::String, vec};

bitflags! {
    pub struct PTEFlags: u16 {
        const V = 1 << 0;
        const R = 1 << 1;
        const W = 1 << 2;
        const X = 1 << 3;
        const U = 1 << 4;
        const G = 1 << 5;
        const A = 1 << 6;
        const D = 1 << 7;
        const COW = 1 << 8;
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct PageTableEntry {
    bits: usize,
}

impl Debug for PageTableEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let ppn = self.bits >> 10;
        let flags = self.flags().readable_flags();

        write!(f, "PTE {{ ppn: {:#x}, flags: {} }}", ppn, flags)
    }
}

impl PageTableEntry {
    ///Create a PTE from ppn
    pub fn new(ppn: PhysPageNum, flags: PTEFlags) -> Self {
        PageTableEntry {
            bits: ppn.0 << 10 | flags.bits() as usize,
        }
    }
    /// Create a PTE from exist PTE, but clear PTE_W and set PTE_COW
    /// especially for COW
    pub fn from_pte_cow(pte: PageTableEntry) -> Self {
        let mut flags = pte.flags();
        flags.remove(PTEFlags::W);
        flags.insert(PTEFlags::COW);
        PageTableEntry {
            bits: pte.ppn().0 << 10 | flags.bits() as usize,
        }
    }
    ///Return an empty PTE
    pub fn empty() -> Self {
        PageTableEntry { bits: 0 }
    }
    ///Return 44bit ppn
    pub fn ppn(&self) -> PhysPageNum {
        (self.bits >> 10 & ((1usize << 44) - 1)).into()
    }
    ///Return 10bit flag
    pub fn flags(&self) -> PTEFlags {
        // PTEFlags::from_bits(self.bits as u16).unwrap()
        PTEFlags::from_bits_truncate(self.bits as u16)
    }
    ///Check PTE valid
    pub fn is_valid(&self) -> bool {
        self.flags().contains(PTEFlags::V)
    }
    ///Check PTE readable
    pub fn readable(&self) -> bool {
        self.flags().contains(PTEFlags::R)
    }
    ///Check PTE writable
    pub fn writable(&self) -> bool {
        self.flags().contains(PTEFlags::W)
    }
    ///Check PTE executable
    pub fn executable(&self) -> bool {
        self.flags().contains(PTEFlags::X)
    }
    ///Check PTE User mode
    pub fn is_user(&self) -> bool {
        self.flags().contains(PTEFlags::U)
    }
    /// Check PTE COW
    pub fn is_cow(&self) -> bool {
        self.flags().contains(PTEFlags::COW)
    }
}

#[allow(unused)]
impl PTEFlags {
    pub fn readable_flags(&self) -> String {
        let mut ret = String::new();
        if self.contains(PTEFlags::V) {
            ret.push_str("V");
        }
        if self.contains(PTEFlags::R) {
            ret.push_str("R");
        }
        if self.contains(PTEFlags::W) {
            ret.push_str("W");
        }
        if self.contains(PTEFlags::X) {
            ret.push_str("X");
        }
        if self.contains(PTEFlags::U) {
            ret.push_str("U");
        }
        if self.contains(PTEFlags::G) {
            ret.push_str("G");
        }
        if self.contains(PTEFlags::A) {
            ret.push_str("A");
        }
        if self.contains(PTEFlags::D) {
            ret.push_str("D");
        }
        if self.contains(PTEFlags::COW) {
            ret.push_str("COW");
        }
        ret
    }
}

pub struct PageTable {
    pub root_ppn: PhysPageNum,
    frames: Vec<FrameTracker>,
}

// 创建页表
impl PageTable {
    pub fn new() -> Self {
        let frame = frame_alloc().unwrap();
        PageTable {
            root_ppn: frame.ppn,
            frames: vec![frame],
        }
    }
    /// Temporarily used to get arguments from user space.
    pub fn from_token(satp: usize) -> Self {
        Self {
            root_ppn: PhysPageNum::from(satp & ((1 << 44) - 1)),
            frames: Vec::new(),
        }
    }
    /// 在用户空间中有内核空间的映射
    pub fn from_global() -> Self {
        let frame = frame_alloc().unwrap();
        let global_root_ppn = KERNEL_SPACE.lock().page_table.root_ppn;

        // Map kernel space, 只需要浅拷贝
        // only copy the kernel mapping
        let kernel_start_vpn = VirtPageNum::from(KERNEL_DIRECT_OFFSET);
        // 对于一级页表, 用户空间是前256个(0~255)页表项, 内核空间是后256个页表项
        // KERNEL_DIRECT_OFFSET: 0xFFFFFFC000000
        // vpn: 0b100000000_000000000_000000000
        let level_1_index = kernel_start_vpn.indexes()[0];

        // Copy from root page table
        let dst_1_table = &mut frame.ppn.get_pte_array()[level_1_index..];
        let src_1_table = global_root_ppn.get_pte_array();
        dst_1_table.copy_from_slice(&src_1_table[level_1_index..]);

        PageTable {
            root_ppn: frame.ppn,
            frames: vec![frame],
        }
    }
}

// 操作pte
impl PageTable {
    /// Find phsical address by virtual address, create a frame if not exist
    fn find_pte_create(&mut self, vpn: VirtPageNum) -> Option<&mut PageTableEntry> {
        let idxs = vpn.indexes();
        let mut ppn = self.root_ppn;
        let mut result: Option<&mut PageTableEntry> = None;
        for (i, idx) in idxs.iter().enumerate() {
            let pte = &mut ppn.get_pte_array()[*idx];
            if i == 2 {
                result = Some(pte);
                break;
            }
            if !pte.is_valid() {
                let frame = frame_alloc().unwrap();
                *pte = PageTableEntry::new(frame.ppn, PTEFlags::V);
                self.frames.push(frame);
            }
            ppn = pte.ppn();
        }
        result
    }
    /// return PageTableEntry by virtual page number if exist
    pub fn find_pte(&self, vpn: VirtPageNum) -> Option<&mut PageTableEntry> {
        let idxs = vpn.indexes();
        let mut ppn = self.root_ppn;
        let mut result: Option<&mut PageTableEntry> = None;
        for (i, idx) in idxs.iter().enumerate() {
            let pte = &mut ppn.get_pte_array()[*idx];
            if i == 2 {
                result = Some(pte);
                break;
            }
            if !pte.is_valid() {
                return None;
            }
            ppn = pte.ppn();
        }
        result
    }
    /// Create a mapping from `vpn` to `ppn`.
    pub fn map(&mut self, vpn: VirtPageNum, ppn: PhysPageNum, flags: PTEFlags) {
        // if flags.contains(PTEFlags::U) {
        //     log::debug!("map {:?} to {:?} with {}", vpn, ppn, flags.readable_flags());
        // }
        // if DEBUG_FLAG.load(core::sync::atomic::Ordering::Relaxed) != 0 {}
        let pte = self.find_pte_create(vpn).unwrap();
        assert!(!pte.is_valid(), "vpn {:?} is mapped before mapping", vpn);
        // *pte = PageTableEntry::new(ppn, flags | PTEFlags::V);
        *pte = PageTableEntry::new(ppn, flags | PTEFlags::V | PTEFlags::A | PTEFlags::D);
    }
    pub fn unmap(&mut self, vpn: VirtPageNum) {
        let pte = self.find_pte(vpn).unwrap();
        assert!(
            pte.is_valid(),
            "vpn {:?} is not mapped before unmapping",
            vpn
        );
        *pte = PageTableEntry::empty();
    }
}

impl PageTable {
    // 根据vpn找到对应的pte, 若找不到则返回None
    pub fn translate_vpn_to_pte(&self, vpn: VirtPageNum) -> Option<PageTableEntry> {
        self.find_pte(vpn).map(|pte| *pte)
    }
    // 返回虚拟地址对应的物理地址, 使用usize类型更加灵活
    pub fn translate_va_to_pa(&self, va: VirtAddr) -> Option<usize> {
        self.find_pte(va.clone().floor()).map(|pte| {
            let aligned_pa = PhysAddr::from(pte.ppn().0 << PAGE_SIZE_BITS);
            aligned_pa.0 + va.page_offset()
        })
    }
    /// Get root ppn
    pub fn token(&self) -> usize {
        8usize << 60 | self.root_ppn.0
    }
}

#[allow(unused)]
// 用于调试
impl PageTable {
    /// 只打印用户空间的映射
    pub fn dump_all_user_mapping(&self) {
        log::trace!("[dump_all]");
        log::error!("pagetable at {:?}", self.root_ppn);
        let pagetable = self.root_ppn.get_pte_array();
        let mut va = 0;
        // 一级页表
        for (index, entry) in pagetable.iter().enumerate() {
            if entry.is_valid() {
                va = va | index << 30;
                let pagetable = entry.ppn().get_pte_array();
                // 二级页表
                for (index, entry) in pagetable.iter().enumerate() {
                    if entry.is_valid() {
                        va = va | index << 21;
                        let pagetable = entry.ppn().get_pte_array();
                        // 三级页表
                        for (index, entry) in pagetable.iter().enumerate() {
                            if entry.is_valid() && entry.is_user() {
                                va = va | index << 12;
                                // log::error!("--- va: {:#x}: {:?}", va, entry);
                                log::error!("--- va: {:#x}: {:?}", va, entry);
                                va = va & !(index << 12);
                            }
                        }
                    }
                    va = va & !(index << 21);
                }
            }
            va = va & !(index << 30);
        }
        log::error!("dump_all end");
    }

    /// 这里的参数va选择使用usize类型, 更加灵活
    pub fn dump_with_va(&self, va: usize) {
        log::info!("[dump_with_va]");
        let pagetable = self.root_ppn.get_pte_array();
        let mut va = va;
        let vpn = va >> PAGE_SIZE_BITS;
        let indexes = VirtPageNum::from(vpn).indexes();
        let pte = pagetable[indexes[0]];
        if !pte.is_valid() {
            log::error!("level1: --- va: {:#x}, pte: None", va);
            return;
        }
        let pagetable = pte.ppn().get_pte_array();
        let pte = pagetable[indexes[1]];
        if !pte.is_valid() {
            log::error!("level2: --- va: {:#x}, pte: None", va);
            return;
        }
        let pagetable = pte.ppn().get_pte_array();
        let pte = pagetable[indexes[2]];
        if !pte.is_valid() {
            log::error!("level3: --- va: {:#x}, pte: None", va);
            return;
        }
        log::error!("--- va: {:#x}, pte: {:?}", va, pte);
    }
}

// return current satp
pub fn current_token() -> usize {
    let token: usize;
    unsafe {
        asm!("csrr {}, satp", out(reg) token, options(nostack));
    }
    token
}

/// temporarily mapping a page
/// for debug/test
pub fn map_temp(vpn: VirtPageNum, ppn: PhysPageNum) {
    let satp = current_token();
    let mut page_table = PageTable {
        root_ppn: PhysPageNum::from(satp & ((1 << 44) - 1)),
        frames: Vec::new(),
    };
    page_table.map(vpn, ppn, PTEFlags::V | PTEFlags::R | PTEFlags::W);
    unsafe {
        asm!("sfence.vma");
    }
}

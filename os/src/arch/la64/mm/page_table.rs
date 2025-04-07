use alloc::vec;
use alloc::{string::String, vec::Vec};
use bitflags::bitflags;
use core::fmt::{self, Debug};
use core::result;

use crate::arch::config::{PAGE_SIZE_BITS, PALEN, USER_MAX_VA};
use crate::arch::la64::tlb::{tlb_global_invalidate, tlb_invalidate};
use crate::arch::mm::sfence_vma_vaddr;
use crate::arch::{PGDH, PGDL};

use crate::mm::{
    frame_alloc, FrameTracker, MapPermission, PhysAddr, PhysPageNum, VirtAddr, VirtPageNum,
    KERNEL_SATP,
};

bitflags! {
    #[derive(Debug, Clone)]
    pub struct PTEFlags: usize {
        const V = 1 << 0;
        const D = 1 << 1;
        /// 特权等级PLV(3:2)
        const PLV0 = 0;
        const PLV1 = 1 << 2;
        const PLV2 = 2 << 2;
        const PLV3 = 3 << 2;
        /// 存储访问类型MAT(5:4)
        /// 强序非缓存(Strongly-ordered Uncached)
        const MAT_SUC = 0;
        /// 一致可缓存(Coherent Cached)
        const MAT_CC = 1 << 4;
        /// 弱序非缓存(Weakly-ordered Uncached)
        const MAT_WUC = 2 << 4;
        const G = 1 << 6;
        /// 存在位, 1表示已分配物理页(用于按需分配, COW)
        const P = 1 << 7;
        const W = 1 << 8;
        /// copy on write, 1表示该页表项是一个COW页表项
        /// 该页表项的物理页在写入时会被复制到一个新的物理页上
        const COW = 1 << 9;
        /// 共享位, 1表示该页表项可以被多个进程共享
        const S = 1 << 10;

        /// 不可读
        const NR = 1 << (usize::BITS - 3);
        /// 不可执行
        const NX = 1 << (usize::BITS - 2);
        // 受限特权等级使能, 当PRLV=0, 该页表项可以被任何特权等级不低于PLV的程序访问, 当PRLV=1, 该页表项只能被特权等级等于PLV的程序访问
        const RPLV = 1 << (usize::BITS - 1);
    }
}

impl From<MapPermission> for PTEFlags {
    fn from(perm: MapPermission) -> Self {
        let mut flags = PTEFlags::V | PTEFlags::MAT_CC | PTEFlags::P;
        if !perm.contains(MapPermission::R) {
            flags |= PTEFlags::NR;
        }
        if perm.contains(MapPermission::W) {
            flags |= PTEFlags::D | PTEFlags::W;
        }
        if !perm.contains(MapPermission::X) {
            flags |= PTEFlags::NX;
        }
        if perm.contains(MapPermission::U) {
            flags |= PTEFlags::PLV3;
        }
        if perm.contains(MapPermission::G) {
            flags |= PTEFlags::G;
        }
        if perm.contains(MapPermission::S) {
            flags |= PTEFlags::S;
        }
        flags
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct PageTableEntry {
    bits: usize,
}

impl Debug for PageTableEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ppn = self.ppn().0;
        let flags = self.flags().readable_flags();
        write!(f, "PTE {{ ppn: {:#x}, flags: {} }}", ppn, flags)
    }
}

impl PageTableEntry {
    const PPN_MASK: usize = ((1 << PALEN) - 1) << 12;
    pub fn new(ppn: PhysPageNum, flags: PTEFlags) -> Self {
        Self {
            bits: ppn.0 << 12 | flags.bits(),
        }
    }
    pub fn from_pte_cow(pte: PageTableEntry) -> Self {
        let mut flags = pte.flags();
        flags.remove(PTEFlags::W);
        flags.remove(PTEFlags::D);
        flags.insert(PTEFlags::COW);
        Self {
            bits: pte.ppn().0 << 12 | flags.bits(),
        }
    }
    pub fn empty() -> Self {
        Self { bits: 0 }
    }
    pub fn ppn(&self) -> PhysPageNum {
        PhysPageNum((self.bits & Self::PPN_MASK) >> 12)
    }
    pub fn flags(&self) -> PTEFlags {
        PTEFlags::from_bits(self.bits & !Self::PPN_MASK).unwrap()
    }
    /// 检查页表项是否有效
    pub fn is_valid(&self) -> bool {
        self.flags().contains(PTEFlags::V)
    }
    pub fn readable(&self) -> bool {
        !self.flags().contains(PTEFlags::NR)
    }
    pub fn writable(&self) -> bool {
        self.flags().contains(PTEFlags::D)
    }
    pub fn executable(&self) -> bool {
        !self.flags().contains(PTEFlags::NX)
    }
    pub fn is_user(&self) -> bool {
        self.flags().contains(PTEFlags::PLV3)
    }
    pub fn is_cow(&self) -> bool {
        self.flags().contains(PTEFlags::COW)
    }
    pub fn is_shared(&self) -> bool {
        self.flags().contains(PTEFlags::S)
    }
}

impl PTEFlags {
    pub fn readable_flags(&self) -> String {
        let mut ret = String::new();
        if self.contains(PTEFlags::V) {
            ret.push_str("V");
        }
        if self.contains(PTEFlags::W) {
            ret.push_str("W");
        }
        if self.contains(PTEFlags::NR) {
            ret.push_str("NR");
        }
        if self.contains(PTEFlags::NX) {
            ret.push_str("NX");
        }
        if self.contains(PTEFlags::G) {
            ret.push_str("G");
        }
        if self.contains(PTEFlags::P) {
            ret.push_str("P");
        }
        if self.contains(PTEFlags::D) {
            ret.push_str("D");
        }

        if self.contains(PTEFlags::PLV3) {
            ret.push_str("PLV3");
        } else if self.contains(PTEFlags::PLV2) {
            ret.push_str("PLV2");
        } else if self.contains(PTEFlags::PLV1) {
            ret.push_str("PLV1");
        } else {
            ret.push_str("PLV0");
        }

        if self.contains(PTEFlags::MAT_CC) {
            ret.push_str("MAT_CC");
        } else if self.contains(PTEFlags::MAT_WUC) {
            ret.push_str("MAT_WUC");
        } else if self.contains(PTEFlags::MAT_SUC) {
            ret.push_str("MAT_SUC");
        }

        if self.contains(PTEFlags::COW) {
            ret.push_str("COW");
        }
        if self.contains(PTEFlags::S) {
            ret.push_str("S");
        }

        ret
    }
}

pub struct PageTable {
    pub root_ppn: PhysPageNum,
    frames: Vec<FrameTracker>,
}

// 创建页表
// Todo:
impl PageTable {
    pub fn new() -> Self {
        let frame = frame_alloc().expect("failed to alloc frame for root page table");
        Self {
            root_ppn: frame.ppn,
            frames: vec![frame],
        }
    }
    pub fn from_token(token: usize) -> Self {
        Self {
            root_ppn: PhysPageNum::from(token),
            frames: Vec::new(),
        }
    }
    pub fn from_existed_user(parent_pagetbl: &PageTable) -> Self {
        // 注意这行别删, 是loongarch relesae跑起来的神奇咒语
        log::trace!("[PageTable] from_existed_user");
        let cld_root_frame = frame_alloc().unwrap();
        let cld_root_ppn = cld_root_frame.ppn;
        let mut frames: Vec<FrameTracker> = Vec::new();
        let prt_root_ppn = parent_pagetbl.root_ppn;
        // parent and child root page table
        let cld_1_table = cld_root_frame.ppn.get_pte_array();
        let prt_1_table = prt_root_ppn.get_pte_array();

        // // 1. Copy only kernel mapping from parent root page table
        // let kernel_start_vpn = VirtPageNum::from(KERNEL_DIRECT_OFFSET);
        // let kernel_start_idx1 = kernel_start_vpn.indexes()[0];
        // cld_1_table[kernel_start_idx1..].copy_from_slice(&prt_1_table[kernel_start_idx1..]);

        // 2. copy user mapping from parent root page table and 2nd level page table
        // todo: 考虑优化, 将level_1_idx作为常量
        let user_end_vpn = VirtAddr::from(USER_MAX_VA).ceil();
        let user_end_idx1 = user_end_vpn.indexes()[0];
        let prt_1_table_user = &prt_1_table[..user_end_idx1];
        for (idx1, prt_1_entry) in prt_1_table_user.iter().enumerate() {
            if prt_1_entry.is_valid() {
                let cld_1_pte = &mut cld_1_table[idx1];
                let frame = frame_alloc().unwrap();
                // Copy parent's 2nd level page table
                let prt_2_table = prt_1_entry.ppn().get_pte_array();
                let cld_2_table = frame.ppn.get_pte_array();
                cld_2_table.copy_from_slice(&prt_2_table);
                // add mapping to child 1st level page table
                *cld_1_pte = PageTableEntry::new(frame.ppn, PTEFlags::V);
                // add frame to child pagetable(是子进程独有的)
                frames.push(frame);

                for (idx2, prt_2_entry) in prt_2_table.iter_mut().enumerate() {
                    if prt_2_entry.is_valid() {
                        let cld_2_pte = &mut cld_2_table[idx2];
                        let prt_3_table = prt_2_entry.ppn().get_pte_array();
                        // 3. clear PTE_W and set PTE_COW in parent 3rd level pagetable
                        for ptr_3_entry in prt_3_table.iter_mut() {
                            // 如果pte是private, 且可写, 则设置为COW
                            if ptr_3_entry.writable() && !ptr_3_entry.is_shared() {
                                // todo: 优化 modify in place
                                *ptr_3_entry = PageTableEntry::from_pte_cow(*ptr_3_entry);
                            }
                        }
                        // 4. copy parent's 3rd level page table
                        let frame = frame_alloc().unwrap();
                        let cld_3_table = frame.ppn.get_pte_array();
                        cld_3_table.copy_from_slice(&prt_3_table);
                        // add mapping to child 2nd level page table
                        *cld_2_pte = PageTableEntry::new(frame.ppn, PTEFlags::V);
                        // add frame to child pagetable(是子进程独有的)
                        frames.push(frame);
                    }
                }
            }
        }
        frames.push(cld_root_frame);
        // 注意修改了当前用户空间的页表项刷新tlb
        tlb_invalidate();
        // 子进程的页表拥有自己的所有三级页表
        PageTable {
            root_ppn: cld_root_ppn,
            frames,
        }
    }
}

// 操作页表项pte
// complete
impl PageTable {
    /// 由上层调用者保证刷新页表
    pub fn find_pte_create(&mut self, vpn: VirtPageNum) -> Option<&mut PageTableEntry> {
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
                let frame = frame_alloc().expect("failed to alloc frame for page table");
                *pte = PageTableEntry::new(frame.ppn, PTEFlags::V);
                self.frames.push(frame);
            }
            ppn = pte.ppn();
        }
        result
    }
    pub fn find_pte(&self, vpn: VirtPageNum) -> Option<&mut PageTableEntry> {
        let idxs = vpn.indexes();
        let mut ppn = self.root_ppn;
        let mut result: Option<&mut PageTableEntry> = None;
        for (i, idx) in idxs.iter().enumerate() {
            let pte = &mut ppn.get_pte_array()[*idx];
            if !pte.is_valid() {
                return None;
            }
            if i == 2 {
                result = Some(pte);
                break;
            }
            ppn = pte.ppn();
        }
        result
    }
    /// Todo: 对于loongarch, 好像D是可写位
    pub fn map(&mut self, vpn: VirtPageNum, ppn: PhysPageNum, flags: PTEFlags) {
        let pte = self.find_pte_create(vpn).unwrap();
        assert!(!pte.is_valid(), "vpn {:?} is mapped before mapping", vpn);
        *pte = PageTableEntry::new(ppn, flags | PTEFlags::V);
        // *pte = PageTableEntry::new(ppn, flags | PTEFlags::V | PTEFlags::D);
        unsafe {
            sfence_vma_vaddr(vpn.0 << PAGE_SIZE_BITS);
        }
    }
    pub fn remap(&mut self, vpn: VirtPageNum, flags: PTEFlags) {
        let pte = self.find_pte_create(vpn).unwrap();
        assert!(
            pte.is_valid(),
            "vpn {:?} is not mapped before remapping",
            vpn
        );
        *pte = PageTableEntry::new(pte.ppn(), flags | PTEFlags::V | PTEFlags::D);
        unsafe {
            sfence_vma_vaddr(vpn.0 << PAGE_SIZE_BITS);
        }
    }
    pub fn unmap(&mut self, vpn: VirtPageNum) {
        let pte = self.find_pte(vpn).unwrap();
        assert!(
            pte.is_valid(),
            "vpn {:?} is not mapped before unmapping",
            vpn
        );
        *pte = PageTableEntry::empty();
        unsafe {
            sfence_vma_vaddr(vpn.0 << PAGE_SIZE_BITS);
        }
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
        self.root_ppn.0
    }
    pub fn activate(&self) {
        tlb_global_invalidate();
        if self.root_ppn.0 == *KERNEL_SATP {
            PGDH::from(self.token() << PAGE_SIZE_BITS).write();
        } else {
            PGDL::from(self.token() << PAGE_SIZE_BITS).write();
        }
    }
}

#[allow(unused)]
// 用于调试
impl PageTable {
    /// 打印用户空间的映射
    pub fn dump_all_user_mapping(&self) {
        log::error!("pagetable at {:?}", self.root_ppn);
        let pagetable = self.root_ppn.get_pte_array();
        let mut va = 0;
        // 第一级页表(dir3)
        for (index, entry) in pagetable.iter().enumerate() {
            if entry.is_valid() {
                va = va | (index << 30);
                let pagetable = entry.ppn().get_pte_array();

                // 第二级页表（dir1）
                for (index, entry) in pagetable.iter().enumerate() {
                    if entry.is_valid() {
                        va = va | (index << 21);
                        let pagetable = entry.ppn().get_pte_array();

                        // 第三级页表（pt）
                        for (index, entry) in pagetable.iter().enumerate() {
                            if entry.is_valid() && entry.is_user() {
                                va = va | (index << 12);
                                log::error!("--- va: {:#x}: {:?}", va, entry);
                                va = va & !(index << 12);
                            }
                        }
                        va = va & !(index << 21);
                    }
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
        // 打印第一级页表的ppn
        log::error!("- ppn: {:#x}", pte.ppn().0);
        let pagetable = pte.ppn().get_pte_array();
        let pte = pagetable[indexes[1]];
        if !pte.is_valid() {
            log::error!("level2: --- va: {:#x}, pte: None", va);
            return;
        }
        // 打印第二级页表的ppn
        log::error!("--  ppn: {:#x}", pte.ppn().0);
        let pagetable = pte.ppn().get_pte_array();
        let pte = pagetable[indexes[2]];
        if !pte.is_valid() {
            log::error!("level3: --- va: {:#x}, pte: None", va);
            return;
        }
        log::error!("--- va: {:#x}, pte: {:?}", va, pte);
    }
}

// Todo:
pub fn current_token() -> usize {
    todo!()
}

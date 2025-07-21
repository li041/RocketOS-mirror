use crate::arch::mm::sfence_vma_vaddr;
use core::{fmt::Debug, ops::Range};

use alloc::{collections::btree_map::BTreeMap, sync::Arc};
use bitflags::bitflags;

use crate::{
    arch::{
        config::{KERNEL_BASE, PAGE_SIZE, PAGE_SIZE_BITS},
        mm::{PTEFlags, PageTable},
    },
    fs::file::FileOp,
    mm::address::StepByOne,
};

use super::{shm::ShmAtFlags, Page, PhysPageNum, VPNRange, VirtAddr, VirtPageNum};

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub struct MapPermission: u16 {
        // 注意: riscv中将MapPermission转换为PTEFlags是使用的from_bits方法, 所以位要对应
        const R = 1 << 1;
        const W = 1 << 2;
        const X = 1 << 3;
        const U = 1 << 4;
        const G = 1 << 5;
        const A = 1 << 6;
        const D = 1 << 7;
        const COW = 1 << 8;
        const S = 1 << 9;
    }
}

impl From<&ShmAtFlags> for MapPermission {
    fn from(shm_at_flags: &ShmAtFlags) -> Self {
        let mut map_perm = MapPermission::U | MapPermission::S;
        if shm_at_flags.contains(ShmAtFlags::SHM_RDONLY) {
            map_perm.insert(MapPermission::R);
        } else {
            map_perm.insert(MapPermission::R | MapPermission::W);
        }
        if shm_at_flags.contains(ShmAtFlags::SHM_EXEC) {
            map_perm.insert(MapPermission::X);
        }
        map_perm
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum MapType {
    Linear,
    Framed,
    Stack,
    Heap,
    Filebe,
    FilebeRO,
}

impl MapPermission {
    pub fn update_rwx(&mut self, map_perm_from_prot: MapPermission) {
        // 只更新R, W, X
        self.remove(MapPermission::R | MapPermission::W | MapPermission::X | MapPermission::COW);
        self.insert(map_perm_from_prot & (MapPermission::R | MapPermission::X));
        if self.contains(MapPermission::S) && map_perm_from_prot.contains(MapPermission::W) {
            self.insert(MapPermission::W);
        } else {
            self.insert(MapPermission::COW);
        }
    }
}

#[derive(Clone)]
pub struct MapArea {
    pub vpn_range: VPNRange,
    pub map_perm: MapPermission,
    // pub private_frames: BTreeMap<VirtPageNum, Arc<FrameTracker>>,
    pub pages: BTreeMap<VirtPageNum, Arc<Page>>,
    pub map_type: MapType,

    /// 文件映射
    pub backend_file: Option<Arc<dyn FileOp>>,
    pub offset: usize,

    pub locked: bool, // 是否被锁定, 用于文件映射
}

impl Debug for MapArea {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MapArea")
            .field("vpn_range", &self.vpn_range)
            .field("map_perm", &self.map_perm)
            .field("map_type", &self.map_type)
            .finish()
    }
}

impl PartialEq for MapArea {
    fn eq(&self, other: &Self) -> bool {
        self.vpn_range == other.vpn_range
            && self.map_perm == other.map_perm
            && self.map_type == other.map_type
            && self.offset == other.offset
    }
}
impl Eq for MapArea {}

impl MapArea {
    /// Create a empty `MapArea` from va
    pub fn new(
        vpn_range: VPNRange,
        map_type: MapType,
        map_perm: MapPermission,
        backed_file: Option<Arc<dyn FileOp>>,
        offset: usize,
        locked: bool,
    ) -> Self {
        Self {
            vpn_range,
            map_perm,
            pages: BTreeMap::new(),
            map_type,
            backend_file: backed_file,
            offset,
            locked,
        }
    }
}

impl MapArea {
    // used by `Memoryset::from_existed_user`
    pub fn from_another(map_area: &MapArea) -> Self {
        Self {
            vpn_range: map_area.vpn_range.clone(),
            // 物理页会重新分配
            pages: BTreeMap::new(),
            map_type: map_area.map_type,
            map_perm: map_area.map_perm,
            backend_file: map_area.backend_file.clone(),
            offset: map_area.offset,
            locked: false, // 锁定状态不保持
        }
    }
}

impl MapArea {
    // map the area: [start_va, end_va), 左闭右开
    /// 注意对于文件映射, 不应该使用这个函数分配page, 而是在缺页时处理
    pub fn map(&mut self, page_table: &mut PageTable) {
        let mut ppn: PhysPageNum;
        let pte_flags = PTEFlags::from(self.map_perm);
        let start_vpn = self.vpn_range.get_start();
        let end_vpn = self.vpn_range.get_end();
        match self.map_type {
            // 对于riscv是线性偏移, loongarch64是直接映射
            MapType::Linear => {
                // for vpn in self.vpn_range {
                //     ppn = PhysPageNum(vpn.0 - (KERNEL_BASE >> PAGE_SIZE_BITS));
                //     page_table.map(vpn, ppn, pte_flags.clone());
                // }
                let start_ppn = PhysPageNum(start_vpn.0 - (KERNEL_BASE >> PAGE_SIZE_BITS));
                page_table.map_range_continuous(start_vpn, end_vpn, start_ppn, pte_flags.clone());
            }
            MapType::Framed => {
                // for vpn in self.vpn_range {
                //     let page = Page::new_framed(None);
                //     ppn = page.ppn();
                //     self.pages.insert(vpn, Arc::new(page));
                //     page_table.map(vpn, ppn, pte_flags.clone());
                // }
                let page_count = end_vpn.0 - start_vpn.0;
                let pages = Page::new_frameds(page_count);
                page_table.map_range_any(start_vpn, end_vpn, &pages, pte_flags);
                self.pages.extend(
                    pages
                        .into_iter()
                        .enumerate()
                        .map(|(i, page)| (VirtPageNum(start_vpn.0 + i), page)),
                );
            }
            MapType::Filebe => {
                let file = self.backend_file.as_ref().unwrap();
                // for vpn in self.vpn_range {
                //     // 文件映射, 大部分在缺页时处理
                //     // MAP_POPULATE
                //     log::error!("[MapArea::map] unexpected filebe mapping");
                //     let offset = self.offset + (vpn.0 - self.vpn_range.get_start().0) * PAGE_SIZE;
                //     let page = file.get_page(offset).unwrap();
                //     ppn = page.ppn();
                //     self.pages.insert(vpn, page);
                //     page_table.map(vpn, ppn, pte_flags.clone());
                // }
                let offset = self.offset + (start_vpn.0 - self.vpn_range.get_start().0) * PAGE_SIZE;
                let pages = file.get_pages(offset, end_vpn.0 - start_vpn.0);
                page_table.map_range_any(start_vpn, end_vpn, &pages, pte_flags);
                self.pages.extend(
                    pages
                        .into_iter()
                        .enumerate()
                        .map(|(i, page)| (VirtPageNum(start_vpn.0 + i), page)),
                );
            }
            MapType::FilebeRO => {
                // 只读文件映射直接使用页缓存, 在from_elf中已经处理
                panic!("MapType::RO never use this function");
            }
            MapType::Stack => {
                // 栈映射, 懒分配
                panic!("MapType::Stack never use this function");
            }
            MapType::Heap => {
                // 堆映射, 除了初次分配, 后续都是懒分配
                // for vpn in self.vpn_range {
                //     let page = Page::new_framed(None);
                //     ppn = page.ppn();
                //     self.pages.insert(vpn, Arc::new(page));
                //     page_table.map(vpn, ppn, pte_flags.clone());
                // }
                let page_count = end_vpn.0 - start_vpn.0;
                let pages = Page::new_frameds(page_count);
                page_table.map_range_any(start_vpn, end_vpn, &pages, pte_flags);
                self.pages.extend(
                    pages
                        .into_iter()
                        .enumerate()
                        .map(|(i, page)| (VirtPageNum(start_vpn.0 + i), page)),
                );
            }
        }
    }
    /// 在原有的MapArea上增加一个页, 并添加相关映射
    /// used by `sys_brk`
    pub fn alloc_one_page_framed_private(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        let page = Page::new_framed(None);
        let ppn = page.ppn();
        let pte_flags = PTEFlags::from(self.map_perm);
        page_table.map(vpn, ppn, pte_flags);
        self.pages.insert(vpn, Arc::new(page));
    }
    /// 在原有的MapArea上删除一个页, 并删除相关映射
    /// 如果页还没有被映射, 则不需要删除映射
    pub fn dealloc_one_page(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        if let Some(_) = self.pages.remove(&vpn) {
            page_table.unmap(vpn);
        }
    }
}

impl MapArea {
    /// data: with offset and maybe with shorter length, quite flexible
    /// assume that all frames were cleared before
    pub fn copy_data_private(&mut self, page_table: &mut PageTable, data: &[u8], offset: usize) {
        debug_assert!(self.map_type == MapType::Framed);
        let mut start: usize = 0;
        let mut current_vpn = self.vpn_range.get_start();
        let len = data.len();
        // copy the first page with offset
        if offset != 0 {
            let src = &data[0..len.min(0 + PAGE_SIZE - offset)];
            let dst = &mut page_table
                .translate_vpn_to_pte(current_vpn)
                .unwrap()
                .ppn()
                .get_bytes_array()[offset..offset + src.len()];
            dst.copy_from_slice(src);
            start += PAGE_SIZE - offset;
            current_vpn.step();
        }
        // copy the rest pages
        loop {
            if start >= len {
                break;
            }
            let src = &data[start..len.min(start + PAGE_SIZE)];
            let dst = &mut page_table
                .translate_vpn_to_pte(current_vpn)
                .unwrap()
                .ppn()
                .get_bytes_array()[..src.len()];
            dst.copy_from_slice(src);
            start += PAGE_SIZE;
            current_vpn.step();
        }
    }
    /// 由调用者保证split_vpn在原有区域范围内
    /// 将区域分为2个区域, 原有区域[start, split_vpn), 新区域[split_vpn, end)
    /// 划分pages, 如果是文件映射, 需要重新计算偏移量
    pub fn split2(&mut self, split_vpn: VirtPageNum) -> Self {
        debug_assert!(
            self.vpn_range.get_start().0 <= split_vpn.0
                && split_vpn.0 <= self.vpn_range.get_end().0
        );
        let old_vpn_end = self.vpn_range.get_end();
        // 设置原有区域的结束地址: [start, split_vpn)
        self.vpn_range.set_end(split_vpn);
        // 设置新区域的开始地址: [split_vpn, end)
        let new_vpn_range = VPNRange::new(split_vpn, old_vpn_end);
        let new_area_offset = if self.backend_file.is_some() {
            self.offset + (split_vpn.0 - self.vpn_range.get_start().0) * PAGE_SIZE
        } else {
            self.offset
        };
        let mut new_area = Self {
            vpn_range: new_vpn_range,
            pages: BTreeMap::new(),
            map_type: self.map_type,
            map_perm: self.map_perm,
            backend_file: self.backend_file.clone(),
            offset: new_area_offset,
            locked: self.locked, // 锁定状态保持
        };
        // 将原有的frames划分到新区域
        self.pages.retain(|vpn, page| {
            if *vpn >= split_vpn {
                new_area.pages.insert(*vpn, page.clone());
                false
            } else {
                true
            }
        });
        new_area
    }
    /// 由调用者保证`[xmap_start, xmap_end)`在`[start, end)`范围内
    /// 最后self.end被设置为`xmap_start`, 返回一个新的区域: `[xmap_end, end)`
    /// 最后分为3个区域:
    ///     1. [start, xmap_start) : 原有区域
    ///     2. [xmap_start, xmap_end) : remap/unmap区域
    ///     3. [xmap_end, end) : 原有区域
    pub fn split_in3(&mut self, unmap_start: VirtPageNum, unmap_end: VirtPageNum) -> (Self, Self) {
        log::info!(
            "[MapArea::split_in3] unmap_start: {:#x}, unmap_end: {:#x}",
            unmap_start.0,
            unmap_end.0,
        );
        debug_assert!(
            self.vpn_range.get_start().0 <= unmap_start.0
                && unmap_end.0 <= self.vpn_range.get_end().0
        );
        let old_vpn_end = self.vpn_range.get_end();
        // 1. 设置原有区域的结束地址: [start, xmap_start)
        self.vpn_range.set_end(unmap_start);
        // 2. 设置xmap区域
        let xmap_vpn_range = VPNRange::new(unmap_start, unmap_end);
        let xmap_area_offset = if self.backend_file.is_some() {
            self.offset + (unmap_start.0 - self.vpn_range.get_start().0) * PAGE_SIZE
        } else {
            self.offset
        };
        let mut xmap_area = Self {
            vpn_range: xmap_vpn_range,
            pages: BTreeMap::new(),
            map_type: self.map_type,
            map_perm: self.map_perm,
            backend_file: self.backend_file.clone(),
            offset: xmap_area_offset,
            locked: self.locked, // 锁定状态保持
        };
        // 3. 设置新区域的开始地址: [xmap_end, end)
        let new_vpn_range = VPNRange::new(unmap_end, old_vpn_end);
        // 如果是文件映射, 偏移量需要重新计算
        let new_area_offset = if self.backend_file.is_some() {
            self.offset + (unmap_end.0 - self.vpn_range.get_start().0) * PAGE_SIZE
        } else {
            self.offset
        };
        let mut new_area = Self {
            vpn_range: new_vpn_range,
            pages: BTreeMap::new(),
            map_type: self.map_type,
            map_perm: self.map_perm,
            backend_file: self.backend_file.clone(),
            offset: new_area_offset,
            locked: self.locked, // 锁定状态保持
        };
        // 将原有的frames划分到新区域
        self.pages.retain(|vpn, page| {
            if *vpn >= unmap_end && *vpn < old_vpn_end {
                new_area.pages.insert(*vpn, page.clone());
                false
            } else if *vpn >= unmap_start {
                xmap_area.pages.insert(*vpn, page.clone());
                false
            } else {
                true
            }
        });
        (xmap_area, new_area)
    }
    /// used by `sys_mprotect`
    pub fn remap(&mut self, page_table: &mut PageTable) {
        // 对于还未映射的页, 直接设置权限在缺页时会按照self.map_perm设置
        // 对于已经映射的页, 需要重新设置权限
        for &vpn in self.pages.keys() {
            page_table.remap(vpn, PTEFlags::from(self.map_perm));
        }
    }
    pub fn unmap(&mut self, page_table: &mut PageTable) {
        for &vpn in self.pages.keys() {
            page_table.unmap(vpn);
        }
    }
}

impl MapArea {
    pub fn is_shared(&self) -> bool {
        self.map_perm.contains(MapPermission::S)
    }
}

//! MemorySet
//! MapArea
//! MapType
//! MapPermision
use core::arch::asm;

use super::{page_table, VirtAddr};
use crate::{
    config::{PAGE_SIZE_BITS, USER_STACK_SIZE},
    mm::check_va_mapping,
    task::aux::*,
    DEBUG_FLAG,
};
use alloc::{collections::btree_map::BTreeMap, vec::Vec};
use bitflags::bitflags;
use log::info;
use riscv::{addr::Page, register::satp};
use xmas_elf::program::Type;

use super::{
    frame_allocator::{frame_alloc, FrameTracker},
    page_table::{PTEFlags, PageTable},
    PhysPageNum, VPNRange, VirtPageNum,
};
use crate::{
    boards::qemu::{MEMORY_END, MMIO},
    config::{KERNEL_BASE, PAGE_SIZE},
    index_list::IndexList,
    mm::{page_table::PageTableEntry, StepByOne},
    mutex::SpinNoIrqLock,
    task::aux::AuxHeader,
};
use lazy_static::lazy_static;

#[allow(unused)]
extern "C" {
    fn stext();
    fn etext();
    fn srodata();
    fn erodata();
    fn sdata();
    fn edata();
    fn sbss_with_stack();
    fn ebss();
    fn ekernel();
}

use alloc::sync::Arc;

lazy_static! {
    pub static ref KERNEL_SPACE: Arc<SpinNoIrqLock<MemorySet>> =
        Arc::new(SpinNoIrqLock::new(MemorySet::new_kernel()));
    pub static ref KERNEL_SATP: usize = KERNEL_SPACE.lock().page_table.token();
}

// 这个是内核一级页表的最后一项, 部分用于映射内核栈
// 这样用户态浅拷贝内核空间的一级页表后, 也会有内核栈的映射
// 地址从0xffff_ffc0_0000_0000 ~ 0xffff_ffff_ffff_fff
lazy_static! {
    pub static ref kstack_second_level_frame: Arc<FrameTracker> = {
        let frame = frame_alloc().unwrap();
        log::error!(
            "kstack_second_level_frame: {:#x}",
            frame.ppn.0 << PAGE_SIZE_BITS
        );
        Arc::new(frame)
    };
}

pub struct MemorySet {
    pub page_table: PageTable,
    areas: IndexList<MapArea>,
}

// 返回MemroySet的方法
impl MemorySet {
    pub fn new_bare() -> Self {
        Self {
            page_table: PageTable::new(),
            areas: IndexList::new(),
        }
    }

    /// Crate a user `MemorySet` that owns the global kernel mapping
    pub fn from_global() -> Self {
        let page_table = PageTable::from_global();
        Self {
            page_table,
            areas: IndexList::new(),
        }
    }
    pub fn from_existed_user(user_memory_set: &MemorySet) -> Self {
        let mut memory_set = Self::from_global();
        for area in user_memory_set.areas.iter() {
            let new_area = MapArea::from_another(area);
            // 这里只做了分配物理页, 填加页表映射, 没有复制数据
            memory_set.push(new_area, None, 0);
            // 复制数据
            for vpn in area.vpn_range {
                let src_ppn = user_memory_set
                    .page_table
                    .translate_vpn_to_pte(vpn)
                    .unwrap()
                    .ppn();
                let dst_ppn = memory_set
                    .page_table
                    .translate_vpn_to_pte(vpn)
                    .unwrap()
                    .ppn();
                dst_ppn
                    .get_bytes_array()
                    .copy_from_slice(src_ppn.get_bytes_array());
            }
        }
        memory_set
    }
    /// return (user_memory_set, satp, ustack_top, entry_point, aux_vec)
    /// Todo: 动态链接
    pub fn from_elf(elf_data: &[u8]) -> (Self, usize, usize, usize, Vec<AuxHeader>) {
        let mut memory_set = Self::from_global();
        // 创建`TaskContext`时使用
        let satp = memory_set.page_table.token();

        // map program segments of elf, with U flag
        let elf = xmas_elf::ElfFile::new(elf_data).unwrap();
        let elf_header = elf.header;
        let magic = elf_header.pt1.magic;
        assert_eq!(magic, [0x7f, 0x45, 0x4c, 0x46], "invalid elf!");
        let ph_count = elf_header.pt2.ph_count();
        // Todo: 动态链接, entry_point是动态链接器的入口
        let mut entry_point = elf_header.pt2.entry_point() as usize;
        let mut aux_vec: Vec<AuxHeader> = Vec::with_capacity(64);

        // 页大小为4K
        aux_vec.push(AuxHeader {
            aux_type: AT_PAGESZ,
            value: PAGE_SIZE,
        });

        // 程序头表中元素大小
        aux_vec.push(AuxHeader {
            aux_type: AT_PHENT,
            value: elf_header.pt2.ph_entry_size() as usize,
        });

        // 程序头表中元素个数
        aux_vec.push(AuxHeader {
            aux_type: AT_PHNUM,
            value: ph_count as usize,
        });

        /* 映射程序头 */
        // 程序头表在内存中的起始虚拟地址
        // 程序头表一般是从LOAD段(且是代码段)开始
        let mut header_va: Option<usize> = None; // used to build auxv
        let mut max_end_vpn = VirtPageNum(0);

        for i in 0..ph_count {
            // 程序头部的类型是Load, 代码段或数据段
            let ph = elf.program_header(i).unwrap();
            if ph.get_type().unwrap() == Type::Load {
                let start_va: VirtAddr = (ph.virtual_addr() as usize).into();
                let end_va: VirtAddr = (ph.virtual_addr() as usize + ph.mem_size() as usize).into();

                // 注意用户要带U标志
                let mut map_perm = MapPermission::U;
                let ph_flags = ph.flags();
                if ph_flags.is_read() {
                    map_perm |= MapPermission::R;
                }
                if ph_flags.is_write() {
                    map_perm |= MapPermission::W;
                }
                if ph_flags.is_execute() {
                    map_perm |= MapPermission::X;
                }
                let map_area = MapArea::new(start_va, end_va, MapType::Framed, map_perm);
                // 对齐到页
                max_end_vpn = map_area.vpn_range.get_end();

                let map_offset = start_va.0 - start_va.floor().0 * PAGE_SIZE;
                log::info!("map area: [{:#x}, {:#x})", start_va.0, end_va.0);
                memory_set.push(
                    map_area,
                    Some(&elf_data[ph.offset() as usize..(ph.offset() + ph.file_size()) as usize]),
                    map_offset,
                );
            }
        }
        // map user stack with U flags
        let ustack_bottom: usize = (max_end_vpn.0 << PAGE_SIZE_BITS) + PAGE_SIZE; // 一个页用于保护
        let ustack_top: usize = ustack_bottom + USER_STACK_SIZE;
        info!(
            "[MemorySet::from_elf] user stack [{:#x}, {:#x})",
            ustack_bottom, ustack_top
        );
        memory_set.insert_framed_area(
            ustack_bottom.into(),
            ustack_top.into(),
            MapPermission::R | MapPermission::W | MapPermission::U,
            0,
        );
        return (memory_set, satp, ustack_top, entry_point, aux_vec);
    }
    pub fn new_kernel() -> Self {
        let mut memory_set = Self::new_bare();
        // map kernel sections
        info!(".text [{:#x}, {:#x})", stext as usize, etext as usize);
        info!(".rodata [{:#x}, {:#x})", srodata as usize, erodata as usize);
        info!(".data [{:#x}, {:#x})", sdata as usize, edata as usize);
        info!(
            ".bss [{:#x}, {:#x})",
            sbss_with_stack as usize, ebss as usize
        );
        info!("mapping .text section");
        memory_set.push(
            MapArea::new(
                (stext as usize).into(),
                (etext as usize).into(),
                MapType::Linear,
                MapPermission::R | MapPermission::X | MapPermission::G,
            ),
            None,
            0,
        );
        // // add U flag for sigreturn trampoline
        // memory_set.page_table.update_flags(
        //     VirtAddr::from(sigreturn_trampoline as usize).floor(),
        //     PTEFlags::R | PTEFlags::X | PTEFlags::U,
        // );
        info!("mapping .rodata section");
        memory_set.push(
            MapArea::new(
                (srodata as usize).into(),
                (erodata as usize).into(),
                MapType::Linear,
                MapPermission::R | MapPermission::G,
                // MapPermission::R | MapPermission::A | MapPermission::D,
            ),
            None,
            0,
        );
        info!("mapping .data section");
        memory_set.push(
            MapArea::new(
                (sdata as usize).into(),
                (edata as usize).into(),
                MapType::Linear,
                MapPermission::R | MapPermission::W,
                // MapPermission::R | MapPermission::W | MapPermission::A | MapPermission::D,
            ),
            None,
            0,
        );
        info!("mapping .bss section");
        memory_set.push(
            MapArea::new(
                (sbss_with_stack as usize).into(),
                (ebss as usize).into(),
                MapType::Linear,
                MapPermission::R | MapPermission::W,
                // MapPermission::R | MapPermission::W | MapPermission::A | MapPermission::D,
            ),
            None,
            0,
        );
        info!("mapping physical memory");
        memory_set.push(
            MapArea::new(
                (ekernel as usize).into(),
                (KERNEL_BASE + MEMORY_END).into(),
                MapType::Linear,
                MapPermission::R | MapPermission::W,
                // MapPermission::R | MapPermission::W | MapPermission::A | MapPermission::D,
            ),
            None,
            0,
        );
        info!("mapping memory-mapped registers");
        for pair in MMIO {
            memory_set.push(
                MapArea::new(
                    ((*pair).0 + KERNEL_BASE).into(),
                    ((*pair).0 + (*pair).1 + KERNEL_BASE).into(),
                    MapType::Linear,
                    MapPermission::R | MapPermission::W,
                    // MapPermission::R | MapPermission::W | MapPermission::A | MapPermission::D,
                ),
                None,
                0,
            );
        }
        info!("mapping kernel stack area");
        // 注意这里仅在内核的第一级页表加一个映射, 之后的映射由kstack_alloc通过`find_pte_create`完成
        // 这样做只是为了让`user_space`中也有内核栈的映射, user_space通过`from_global`浅拷贝内核的一级页表的后256项
        let kernel_root_page_table = memory_set.page_table.root_ppn.get_pte_array();
        // 511: 对应的是0xffff_ffc0_0000_0000 ~ 0xffff_ffff_ffff_fff, 也就是内核的最后一个页表项
        let pte = &mut kernel_root_page_table[511];
        // log::error!("pte: {:?}", pte); // 这里可以看到511项的pte是0
        // 注意不能让kstack_second_level_frame被drop, 否则frame会被回收, 但是内核栈的映射还在
        *pte = PageTableEntry::new(kstack_second_level_frame.ppn, PTEFlags::V);

        memory_set
    }
}

impl MemorySet {
    /// map_offset: the offset in the first page
    fn push(&mut self, mut map_area: MapArea, data: Option<&[u8]>, map_offset: usize) {
        map_area.map(&mut self.page_table);
        if let Some(data) = data {
            map_area.copy_data(&mut self.page_table, data, map_offset);
        }
        self.areas.insert_last(map_area);
    }
    /// 由caller保证区域没有冲突, 且start_va和end_va是页对齐的
    /// 插入framed的空白区域
    /// used by `kstack_alloc`, `from_elf 用户栈`
    pub fn insert_framed_area(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        map_perm: MapPermission,
        map_offset: usize,
    ) {
        self.push(
            MapArea::new(start_va, end_va, MapType::Framed, map_perm),
            None,
            map_offset,
        );
    }
    /// change the satp register to the new page table, and flush the TLB
    pub fn activate(&self) {
        let satp = self.page_table.token();
        unsafe {
            satp::write(satp);
            asm!("sfence.vma");
        }
    }
}

impl MemorySet {
    pub fn recycle_data_pages(&mut self) {
        self.areas.clear();
    }
    // 这里从尾部开始找, 因为在MemorySet中, 内核栈一般在最后
    pub fn remove_area_with_start_vpn(&mut self, start_vpn: VirtPageNum) {
        let mut index = self.areas.last_index();
        while index.is_some() {
            let area = self.areas.get_mut(index).unwrap();
            if area.vpn_range.get_start() == start_vpn {
                self.areas.remove(index);
                return;
            }
            index = self.areas.prev_index(index);
        }
    }
}

#[derive(Clone)]
pub struct MapArea {
    vpn_range: VPNRange,
    data_frames: BTreeMap<VirtPageNum, Arc<FrameTracker>>,
    map_type: MapType,
    map_perm: MapPermission,
}

// constructor
impl MapArea {
    /// Create a empty `MapArea` from va
    pub fn new(
        start_va: VirtAddr,
        end_va: VirtAddr,
        map_type: MapType,
        map_perm: MapPermission,
    ) -> Self {
        let start_vpn: VirtPageNum = start_va.floor();
        let end_vpn: VirtPageNum = end_va.ceil();
        Self {
            vpn_range: VPNRange::new(start_vpn, end_vpn),
            data_frames: BTreeMap::new(),
            map_type,
            map_perm,
        }
    }
    // used by `Memoryset::from_existed_user`
    pub fn from_another(map_area: &MapArea) -> Self {
        Self {
            vpn_range: VPNRange::new(map_area.vpn_range.get_start(), map_area.vpn_range.get_end()),
            // 物理页会重新分配
            data_frames: BTreeMap::new(),
            map_type: map_area.map_type,
            map_perm: map_area.map_perm,
        }
    }
}

impl MapArea {
    pub fn map(&mut self, page_table: &mut PageTable) {
        for vpn in self.vpn_range {
            self.map_one(page_table, vpn);
        }
    }
    /// map one page
    pub fn map_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        // if DEBUG_FLAG.load(core::sync::atomic::Ordering::Relaxed) != 0 {}
        let ppn: PhysPageNum;
        match self.map_type {
            MapType::Linear => {
                ppn = PhysPageNum(vpn.0 - 0xffffffc000000);
            }
            MapType::Framed => {
                let frame = frame_alloc().unwrap();
                ppn = frame.ppn;
                // log::warn!(
                //     "mapping vpn: {:#x} to ppn: {:#x}",
                //     vpn.0,
                //     ppn.0 << PAGE_SIZE_BITS
                // );
                self.data_frames.insert(vpn, Arc::new(frame));
            }
        }
        let pte_flags = PTEFlags::from_bits(self.map_perm.bits()).unwrap();
        page_table.map(vpn, ppn, pte_flags);
    }
}

impl MapArea {
    /// data: with offset and maybe with shorter length, quite flexible
    /// assume that all frames were cleared before
    pub fn copy_data(&mut self, page_table: &mut PageTable, data: &[u8], offset: usize) {
        assert_eq!(self.map_type, MapType::Framed);
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
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum MapType {
    Linear,
    Framed,
}

bitflags! {
    #[derive(Clone, Copy)]
    pub struct MapPermission: u16 {
        const R = 1 << 1;
        const W = 1 << 2;
        const X = 1 << 3;
        const U = 1 << 4;
        const G = 1 << 5;
        const A = 1 << 6;
        const D = 1 << 7;
    }
}

//! MemorySet
//! MapArea 
//! MapType
//! MapPermision
use core::arch::asm;

use alloc::collections::btree_map::BTreeMap;
use bitflags::bitflags;
use log::info;
use riscv::register::satp;
use super::VirtAddr;

use crate::{boards::qemu::{MEMORY_END, MMIO}, config::{KERNEL_BASE, PAGE_SIZE}, index_list::IndexList, mm::StepByOne, mutex::SpinNoIrqLock};
use lazy_static::lazy_static;
use super::{frame_allocator::{frame_alloc, FrameTracker}, page_table::{PTEFlags, PageTable}, PhysPageNum, VPNRange, VirtPageNum};

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
}

pub struct MemorySet {
    page_table: PageTable, 
    areas: IndexList<MapArea>,
}

impl MemorySet {
    pub fn new_bare() -> Self {
        Self {
            page_table: PageTable::new(),
            areas: IndexList::new(),
        }
    }
    /// map_offset: the offset in the first page
    fn push(&mut self, mut map_area: MapArea, data: Option<&[u8]>, map_offset: usize) {
        map_area.map(&mut self.page_table);
        if let Some(data) = data {
            map_area.copy_data(&mut self.page_table, data, map_offset);
        }
        self.areas.insert_last(map_area);
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
                 MapPermission::R | MapPermission::X | MapPermission::G ,

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
        memory_set
    }
}

impl MemorySet {    
    /// change the satp register to the new page table, and flush the TLB
    pub fn activate(&self) {
        let satp = self.page_table.token();
        unsafe {
            satp::write(satp);
            asm!("sfence.vma");
        }
    }
}

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
}


impl MapArea {
    pub fn map(&mut self, page_table: &mut PageTable) {
        for vpn in self.vpn_range {
            self.map_one(page_table, vpn);
        }
    }
    /// map one page
        pub fn map_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        let ppn: PhysPageNum;
        match self.map_type {
            MapType::Linear => {
                ppn = PhysPageNum(vpn.0 - 0xffffffc000000);
            }
            MapType::Framed => {
                let frame = frame_alloc().unwrap();
                ppn = frame.ppn;
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
                .translate(current_vpn)
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
                .translate(current_vpn)
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


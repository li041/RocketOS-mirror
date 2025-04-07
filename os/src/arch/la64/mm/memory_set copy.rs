use alloc::vec;
use alloc::{
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    sync::{self, Arc},
    vec::Vec,
};
use lazy_static::lazy_static;
use spin::Lazy;
use xmas_elf::program::Type;

use crate::arch::config::{MMAP_MAX_ADDR, MMAP_MIN_ADDR, PAGE_SIZE_BITS, USER_STACK_SIZE};
use crate::arch::mm::{memory_set, PageTableEntry};
use crate::fs::namei::path_openat;
use crate::fs::AT_FDCWD;
use crate::task::aux::AT_BASE;
use crate::utils::ceil_to_page_size;
use crate::{
    arch::{
        boards::qemu::MMIO,
        config::{DL_INTERP_OFFSET, MEMORY_END, PAGE_SIZE},
        mm::StepByOne,
    },
    index_list::IndexList,
    mutex::SpinNoIrqLock,
    task::aux::{AuxHeader, AT_ENTRY, AT_PAGESZ, AT_PHDR, AT_PHENT, AT_PHNUM},
};

use super::{
    frame_allocator::{frame_alloc, FrameTracker},
    page_table::{self, PTEFlags, PageTable},
    PhysPageNum, VPNRange, VirtAddr, VirtPageNum,
};

use bitflags::bitflags;

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
        log::info!(
            "[kstack_second_level_frame] kstack_second_level_frame: {:#x}",
            frame.ppn.0 << PAGE_SIZE_BITS
        );
        Arc::new(frame)
    };
}

pub struct MemorySet {
    // 要访问MemorySet必须先获取Taskinner的锁, 所以这里不需要加锁
    // 注意brk时当前堆顶, 但实际分配给堆的内存是页对齐的
    pub brk: usize,
    pub heap_bottom: usize,
    /// mmap的起始地址, 用于用户态mmap
    /// 仅在`get_unmapped_area`中使用, 可以保证页对齐, 且不会冲突
    pub mmap_start: usize,
    page_table: PageTable,
    // areas: IndexList<MapArea>,
    areas: Vec<MapArea>,
}

pub struct MapArea {
    vpn_range: VPNRange,
    data_frames: BTreeMap<VirtPageNum, Arc<FrameTracker>>,
    map_type: MapType,
    map_perm: MapPermission,
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum MapType {
    Identical,
    Framed,
}

// Todo: Mappermission目前还是参考riscv的, 需要改吗, 还是上层统一
bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct MapPermission: u16 {
        const R = 1 << 1;
        const W = 1 << 2;
        const X = 1 << 3;
        const U = 1 << 4;
        const G = 1 << 5;
        const D = 1 << 7;
    }
}

// 创建一个新的MemorySet, IndexList
// impl MemorySet {
//     pub fn new_bare() -> Self {
//         Self {
//             page_table: PageTable::new(),
//             areas: IndexList::new(),
//         }
//     }
//     /// map_offset: the offset in the first page
//     /// 在data不为None时, map_offset才有意义, 是data在第一个页中的偏移
//     fn push_with_offset(&mut self, mut map_area: MapArea, data: Option<&[u8]>, map_offset: usize) {
//         map_area.map(&mut self.page_table);
//         if let Some(data) = data {
//             map_area.copy_data(&mut self.page_table, data, map_offset);
//         }
//         self.areas.insert_last(map_area);
//     }
//     // 匿名区域映射, 或者内核区域映射
//     fn push_anoymous_area(&mut self, mut map_area: MapArea) {
//         map_area.map(&mut self.page_table);
//         self.areas.insert_last(map_area);
//     }
//     pub fn new_kernel() -> Self {
//         let mut memory_set = Self {
//             page_table: PageTable::new(),
//             areas: IndexList::new(),
//         };
//         // 映射内核
//         log::info!(".text [{:#x}, {:#x})", stext as usize, etext as usize);
//         log::info!(".rodata [{:#x}, {:#x})", srodata as usize, erodata as usize);
//         log::info!(".data [{:#x}, {:#x})", sdata as usize, edata as usize);
//         log::info!(
//             ".bss [{:#x}, {:#x})",
//             sbss_with_stack as usize,
//             ebss as usize
//         );
//         log::trace!("mapping .text section");
//         memory_set.push_anoymous_area(MapArea::from_va(
//             (stext as usize).into(),
//             (etext as usize).into(),
//             MapType::Identical,
//             MapPermission::R | MapPermission::X | MapPermission::G,
//         ));
//         log::trace!("mapping .rodata section");
//         memory_set.push_anoymous_area(MapArea::from_va(
//             (srodata as usize).into(),
//             (erodata as usize).into(),
//             MapType::Identical,
//             MapPermission::R | MapPermission::G,
//         ));
//         log::trace!("mapping .data section");
//         memory_set.push_anoymous_area(MapArea::from_va(
//             (sdata as usize).into(),
//             (edata as usize).into(),
//             MapType::Identical,
//             MapPermission::R | MapPermission::W,
//         ));
//         log::trace!("mapping .bss section");
//         memory_set.push_anoymous_area(MapArea::from_va(
//             (sbss_with_stack as usize).into(),
//             (ebss as usize).into(),
//             MapType::Identical,
//             MapPermission::R | MapPermission::W,
//         ));
//         log::info!(
//             "mapping physical memory, ekernel: {:#x}, Memory_end: {:#x}",
//             ekernel as usize,
//             MEMORY_END
//         );
//         memory_set.push_anoymous_area(MapArea::from_va(
//             (ekernel as usize).into(),
//             (MEMORY_END).into(),
//             MapType::Identical,
//             MapPermission::R | MapPermission::W,
//         ));
//         log::trace!("mapping memory memory-mapped registers");
//         for pair in MMIO {
//             memory_set.push_anoymous_area(MapArea::from_va(
//                 (*pair).0.into(),
//                 ((*pair).0 + (*pair).1).into(),
//                 MapType::Identical,
//                 MapPermission::R | MapPermission::W,
//             ));
//         }
//         memory_set
//     }
// }

// 返回MemorySet的方法
impl MemorySet {
    pub fn new_bare() -> Self {
        Self {
            brk: 0,
            heap_bottom: 0,
            mmap_start: MMAP_MIN_ADDR,
            page_table: PageTable::new(),
            areas: Vec::new(),
        }
    }
    pub fn push_with_offset(
        &mut self,
        mut map_area: MapArea,
        data: Option<&[u8]>,
        map_offset: usize,
    ) {
        map_area.map(&mut self.page_table);
        if let Some(data) = data {
            map_area.copy_data(&mut self.page_table, data, map_offset);
        }
        self.areas.push(map_area);
    }
    pub fn push_anoymous_area(&mut self, mut map_area: MapArea) {
        map_area.map(&mut self.page_table);
        self.areas.push(map_area);
    }
    pub fn new_kernel() -> Self {
        let mut memory_set = Self::new_bare();
        // 映射内核
        log::info!(".text [{:#x}, {:#x})", stext as usize, etext as usize);
        log::info!(".rodata [{:#x}, {:#x})", srodata as usize, erodata as usize);
        log::info!(".data [{:#x}, {:#x})", sdata as usize, edata as usize);
        log::info!(
            ".bss [{:#x}, {:#x})",
            sbss_with_stack as usize,
            ebss as usize
        );
        log::trace!("mapping .text section");
        memory_set.push_anoymous_area(MapArea::from_va(
            (stext as usize).into(),
            (etext as usize).into(),
            MapType::Identical,
            MapPermission::R | MapPermission::X | MapPermission::G,
        ));
        log::trace!("mapping .rodata section");
        memory_set.push_anoymous_area(MapArea::from_va(
            (srodata as usize).into(),
            (erodata as usize).into(),
            MapType::Identical,
            MapPermission::R | MapPermission::G,
        ));
        log::trace!("mapping .data section");
        memory_set.push_anoymous_area(MapArea::from_va(
            (sdata as usize).into(),
            (edata as usize).into(),
            MapType::Identical,
            MapPermission::R | MapPermission::W,
        ));
        log::trace!("mapping .bss section");
        memory_set.push_anoymous_area(MapArea::from_va(
            (sbss_with_stack as usize).into(),
            (ebss as usize).into(),
            MapType::Identical,
            MapPermission::R | MapPermission::W,
        ));
        log::info!(
            "mapping physical memory, ekernel: {:#x}, Memory_end: {:#x}",
            ekernel as usize,
            MEMORY_END
        );
        memory_set.push_anoymous_area(MapArea::from_va(
            (ekernel as usize).into(),
            (MEMORY_END).into(),
            MapType::Identical,
            MapPermission::R | MapPermission::W,
        ));
        log::trace!("mapping memory memory-mapped registers");
        for pair in MMIO {
            memory_set.push_anoymous_area(MapArea::from_va(
                (*pair).0.into(),
                ((*pair).0 + (*pair).1).into(),
                MapType::Identical,
                MapPermission::R | MapPermission::W,
            ));
        }
        log::trace!("mapping kernel stack area");
        // 注意这里仅在内核的第一级页表加一个映射, 之后的映射由kstack_alloc通过`find_pte_create`完成
        // 这样做只是为了让`user_space`中也有内核栈的映射, user_space通过`from_global`浅拷贝内核的一级页表的后256项
        let kernel_root_page_table = memory_set.page_table.root_ppn.get_pte_array();
        // 511: 对应的是0xffff_ffc0_0000_0000 ~ 0xffff_ffff_ffff_fff, 也就是内核的最后一个页表项
        let pte = &mut kernel_root_page_table[511];
        // log::error!("pte: {:?}", pte); // 这里可以看到511项的pte是0
        // 注意不能让kstack_second_level_frame被drop, 否则frame会被回收, 但是内核栈的映射还在
        *pte = PageTableEntry::new(kstack_second_level_frame.ppn, PTEFlags::V);
        log::trace!("mapping complete!");
        memory_set
    }
    /// return (user_memory_set, pagetable_base_ppn, ustack_top, entry_point, aux_vec)
    pub fn from_elf(elf_data: &[u8]) -> (Self, usize, usize, usize, Vec<AuxHeader>) {
        let mut memory_set = Self::new_bare();
        // 创建`TaskContext`是使用
        let pgtbl_ppn = memory_set.page_table.token();
        let elf = xmas_elf::ElfFile::new(elf_data).unwrap();
        let elf_header = elf.header;
        let magic = elf_header.pt1.magic;

        assert_eq!(magic, [0x7f, 0x45, 0x4c, 0x46], "invalid elf!");

        let ph_count = elf_header.pt2.ph_count();
        let ph_entsize = elf_header.pt2.ph_entry_size() as usize;
        let mut entry_point = elf_header.pt2.entry_point() as usize;
        let mut aux_vec: Vec<AuxHeader> = Vec::with_capacity(64);
        let ph_va = elf.program_header(0).unwrap().virtual_addr() as usize;

        /* 映射程序头 */
        // 程序头表在内存中的起始虚拟地址
        // 程序头表一般是从LOAD段(且是代码段)开始
        // let header_va: Option<usize> = None; // used to build auxv
        let mut max_end_vpn = VirtPageNum(0);
        let mut need_dl: bool = false;

        for i in 0..ph_count {
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
                let map_area = MapArea::from_va(start_va, end_va, MapType::Framed, map_perm);
                // 对齐到页
                max_end_vpn = map_area.vpn_range.get_end();

                let map_offset = start_va.0 - start_va.floor().0 * PAGE_SIZE;
                log::info!(
                    "[from_elf] app map area: [{:#x}, {:#x})",
                    start_va.0,
                    end_va.0
                );
                memory_set.push_with_offset(
                    map_area,
                    Some(&elf_data[ph.offset() as usize..(ph.offset() + ph.file_size()) as usize]),
                    map_offset,
                );
            }
            // 判断是否需要动态链接
            if ph.get_type().unwrap() == Type::Interp {
                need_dl = true;
            }
        }

        // 程序头表的虚拟地址
        aux_vec.push(AuxHeader {
            aux_type: AT_PHDR,
            value: ph_va,
        });

        // 页大小为4K
        aux_vec.push(AuxHeader {
            aux_type: AT_PAGESZ,
            value: PAGE_SIZE,
        });

        // 程序头表中元素大小
        aux_vec.push(AuxHeader {
            aux_type: AT_PHENT,
            value: ph_entsize,
        });

        // 程序头表中元素个数
        aux_vec.push(AuxHeader {
            aux_type: AT_PHNUM,
            value: ph_count as usize,
        });

        // 应用程序入口
        aux_vec.push(AuxHeader {
            aux_type: AT_ENTRY,
            value: entry_point,
        });

        log::info!("[from_elf] AT_PHDR: {:#x}", ph_va);
        log::info!("[from_elf] AT_PAGESZ: {}", PAGE_SIZE);
        log::info!("[from_elf] AT_PHENT: {}", ph_entsize);
        log::info!("[from_elf] AT_PHNUM: {}", ph_count);
        log::info!("[from_elf] AT_ENTRY: {:#x}", entry_point);
        log::info!("[from_elf] AT_BASE: {:#x}", DL_INTERP_OFFSET);
        if need_dl {
            log::info!("[from_elf] need dynamic link");
            // 获取动态链接器的路径
            let section = elf.find_section_by_name(".interp").unwrap();
            let mut interpreter = String::from_utf8(section.raw_data(&elf).to_vec()).unwrap();
            interpreter = interpreter
                .strip_suffix("\0")
                .unwrap_or(&interpreter)
                .to_string();
            log::info!("[from_elf] interpreter path: {}", interpreter);

            let interps = vec![interpreter.clone()];

            for interp in interps.iter() {
                // 加载动态链接器
                if let Ok(interpreter) = path_openat(&interp, 0, AT_FDCWD, 0) {
                    log::info!("[from_elf] interpreter open success");
                    let interp_data = interpreter.read_all();
                    let interp_elf = xmas_elf::ElfFile::new(interp_data.as_slice()).unwrap();
                    let interp_head = interp_elf.header;
                    let interp_ph_count = interp_head.pt2.ph_count();
                    entry_point = interp_head.pt2.entry_point() as usize + DL_INTERP_OFFSET;
                    for i in 0..interp_ph_count {
                        // 程序头部的类型是Load, 代码段或数据段
                        let ph = interp_elf.program_header(i).unwrap();
                        if ph.get_type().unwrap() == Type::Load {
                            let start_va: VirtAddr =
                                (ph.virtual_addr() as usize + DL_INTERP_OFFSET).into();
                            let end_va: VirtAddr = (ph.virtual_addr() as usize
                                + DL_INTERP_OFFSET
                                + ph.mem_size() as usize)
                                .into();

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
                            let map_area =
                                MapArea::from_va(start_va, end_va, MapType::Framed, map_perm);

                            let map_offset = start_va.0 - start_va.floor().0 * PAGE_SIZE;
                            log::info!(
                                "[from_elf] interp map area: [{:#x}, {:#x})",
                                start_va.0,
                                end_va.0
                            );
                            memory_set.push_with_offset(
                                map_area,
                                Some(
                                    &interp_data[ph.offset() as usize
                                        ..(ph.offset() + ph.file_size()) as usize],
                                ),
                                map_offset,
                            );
                        }
                    }
                    // 动态链接器的基址
                    aux_vec.push(AuxHeader {
                        aux_type: AT_BASE,
                        value: DL_INTERP_OFFSET,
                    });
                } else {
                    log::error!("[from_elf] interpreter open failed");
                }
            }
        } else {
            log::info!("[from_elf] static link");
        }

        // 映射用户栈
        let ustack_bottom: usize = (max_end_vpn.0 << PAGE_SIZE_BITS) + PAGE_SIZE; // 一个页用于保护
        let ustack_top: usize = ustack_bottom + USER_STACK_SIZE;
        log::info!(
            "[MemorySet::from_elf] user stack [{:#x}, {:#x})",
            ustack_bottom,
            ustack_top
        );
        let vpn_range = VPNRange::new(
            VirtAddr::from(ustack_bottom).floor(),
            VirtAddr::from(ustack_top).ceil(),
        );
        memory_set.insert_framed_area(
            vpn_range,
            MapPermission::R | MapPermission::W | MapPermission::U,
        );

        // 分配用户堆底, 初始不分配堆内存
        let heap_bottom = ustack_top + PAGE_SIZE;
        memory_set.heap_bottom = heap_bottom;
        memory_set.brk = heap_bottom;

        log::error!("[from_elf] entry_point: {:#x}", entry_point);

        return (memory_set, pgtbl_ppn, ustack_top, entry_point, aux_vec);
    }
    pub fn from_existed_user(user_memory_set: &MemorySet) -> Self {
        let mut memory_set = Self::new_bare();

        // 复制堆底和brk, 堆内容会在user_memory_set.areas.iter()中复制
        memory_set.brk = user_memory_set.brk;
        memory_set.heap_bottom = user_memory_set.heap_bottom;
        for area in user_memory_set.areas.iter() {
            let new_area = MapArea::from_another(area);
            // 这里只做了分配物理页, 填加页表映射, 没有复制数据
            memory_set.push_anoymous_area(new_area);
            // 复制数据
            for vpn in area.vpn_range {
                // Debug
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
}

impl MemorySet {
    /// 由caller保证区域没有冲突, 且start_va和end_va是页对齐的
    /// 插入framed的空白区域
    /// used by `kstack_alloc`, `from_elf 用户栈`
    pub fn insert_framed_area(&mut self, vpn_range: VPNRange, map_perm: MapPermission) {
        self.push_anoymous_area(MapArea::from_va(MapType::Framed, map_perm));
    }
    pub fn insert_framed_area_vpn_range(&mut self, vpn_range: VPNRange, map_perm: MapPermission) {
        self.push_anoymous_area(MapArea::from_vpn_range(
            vpn_range,
            MapType::Framed,
            map_perm,
        ));
    }
    // 在memory_set.mmap_start加到MMAP_MAX_ADDR前可以保证没有冲突
    pub fn get_unmapped_area(&mut self, _hint: usize, size: usize) -> VPNRange {
        let aligned_size = ceil_to_page_size(size);
        let start_vpn = VirtPageNum::from(self.mmap_start >> PAGE_SIZE_BITS);
        let end_vpn = VirtPageNum::from((self.mmap_start + aligned_size) >> PAGE_SIZE_BITS);
        self.mmap_start += aligned_size;
        VPNRange::new(start_vpn, end_vpn)
    }
    /// 注意PGDL和PGDH中填的是物理地址, token返回的是页表的ppn
    pub fn token(&self) -> usize {
        self.page_table.token()
    }
    pub fn activate(&self) {
        self.page_table.activate();
    }
}

// 回收资源
impl MemorySet {
    pub fn recycle_data_pages(&mut self) {
        self.areas.clear();
    }
    pub fn remove_area_with_overlap(&mut self, unmap_vpn_range: VPNRange) {
        self.areas.retain_mut(|area| {
        if area.vpn_range.is_intersect_with(&unmap_vpn_range) {
            let old_vpn_start = area.vpn_range.get_start();
            let old_vpn_end = area.vpn_range.get_end();
            let new_vpn_end = old_vpn_end.min(unmap_vpn_range.get_end());
            let new_vpn_start = old_vpn_start.max(unmap_vpn_range.get_start());

            log::error!(
                "[MemorySet::remove_area_with_overlap] old_vpn_start: {:#x}, old_vpn_end: {:#x}, new_vpn_start: {:#x}, new_vpn_end: {:#x}",
                old_vpn_start.0,
                old_vpn_end.0,
                new_vpn_start.0,
                new_vpn_end.0
            );

            // 释放 new_vpn_start 之前的页
            let dealloc_vpn_range1 = VPNRange::new(old_vpn_start, new_vpn_start);
            for vpn in dealloc_vpn_range1 {
                area.dealloc_one_page(&mut self.page_table, vpn);
            }

            // 释放 new_vpn_end 之后的页
            let dealloc_vpn_range2 = VPNRange::new(new_vpn_end, old_vpn_end);
            for vpn in dealloc_vpn_range2 {
                area.dealloc_one_page(&mut self.page_table, vpn);
            }

            // 如果整个范围都被释放，返回 false 从 Vec 中移除该区域
            if new_vpn_start >= new_vpn_end {
                false
            } else {
                area.vpn_range.set_start(new_vpn_start);
                area.vpn_range.set_end(new_vpn_end);
                true
            }
        } else {
            true
        }
    });
    }

    // 这里从尾部开始找, 因为在MemorySet中, 内核栈一般在最后
    // used by `kstack Drop trait`
    pub fn remove_area_with_start_vpn(&mut self, start_vpn: VirtPageNum) {
        if let Some(pos) = self
            .areas
            .iter()
            .position(|area| area.vpn_range.get_start() == start_vpn)
        {
            self.areas.remove(pos);
        }
    }

    /// 从尾部开始找, 因为动态分配的内存一般在最后
    /// 在原有的MapArea上增/删页, 并添加相关映射
    /// used by `sys_brk`
    pub fn remap_area_with_start_vpn(&mut self, start_vpn: VirtPageNum, new_end_vpn: VirtPageNum) {
        if let Some(pos) = self
            .areas
            .iter()
            .position(|area| area.vpn_range.get_start() == start_vpn)
        {
            let area = &mut self.areas[pos];
            let old_end_vpn = area.vpn_range.get_end();

            if old_end_vpn < new_end_vpn {
                let alloc_vpn_range = VPNRange::new(old_end_vpn, new_end_vpn);
                for vpn in alloc_vpn_range {
                    area.alloc_one_page(&mut self.page_table, vpn);
                }
            } else {
                let dealloc_vpn_range = VPNRange::new(new_end_vpn, old_end_vpn);
                for vpn in dealloc_vpn_range {
                    area.dealloc_one_page(&mut self.page_table, vpn);
                }
            }

            area.vpn_range.set_end(new_end_vpn);

            // 如果新的end和start相等, 则删除这个area
            if new_end_vpn == start_vpn {
                self.areas.remove(pos);
            }
        } else {
            log::error!(
                "[MemorySet::remap_area_with_start_vpn] can't find area with start_vpn: {:#x}",
                start_vpn.0
            );
        }
    }
    // 使用`MapArea`做检查, 而不是查页表
    // 要保证MapArea与页表的一致性, 也就是说, 页表中的映射都在MapArea中, MapArea中的映射都在页表中
    // 检查用户传进来的虚拟地址的合法性
    pub fn check_valid_user_vpn_range(
        &self,
        vpn_range: VPNRange,
        wanted_map_perm: MapPermission,
    ) -> Result<(), &'static str> {
        let areas = self.areas.iter().rev();
        for area in areas {
            if area.vpn_range.is_contain(&vpn_range) {
                if area.map_perm.contains(wanted_map_perm) {
                    return Ok(());
                } else {
                    return Err("invalid virtual permission");
                }
            }
        }
        return Err("invalid virtual address");
    }
    pub fn translate_va_to_pa(&self, va: VirtAddr) -> Option<usize> {
        self.page_table.translate_va_to_pa(va)
    }
    pub fn translate_vpn_to_pa(&self, vpn: VirtPageNum) -> Option<PageTableEntry> {
        self.page_table.translate_vpn_to_pte(vpn)
    }
}

impl MapArea {
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
    pub fn from_va(
        start_va: VirtAddr,
        end_va: VirtAddr,
        map_type: MapType,
        map_perm: MapPermission,
    ) -> Self {
        let start_vpn = start_va.floor();
        let end_vpn = end_va.ceil();
        Self {
            vpn_range: VPNRange::new(start_vpn, end_vpn),
            data_frames: BTreeMap::new(),
            map_type,
            map_perm,
        }
    }
    pub fn from_vpn_range(vpn_range: VPNRange, map_type: MapType, map_perm: MapPermission) -> Self {
        Self {
            vpn_range,
            data_frames: BTreeMap::new(),
            map_type,
            map_perm,
        }
    }
}
impl MapArea {
    // Todo:
    pub fn map(&mut self, page_table: &mut PageTable) {
        for vpn in self.vpn_range {
            self.map_one(page_table, vpn);
        }
    }
    pub fn map_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        let ppn: PhysPageNum;
        match self.map_type {
            MapType::Identical => {
                ppn = PhysPageNum(vpn.0);
            }
            MapType::Framed => {
                let frame = frame_alloc().unwrap();
                ppn = frame.ppn;
                self.data_frames.insert(vpn, Arc::new(frame));
            }
        }
        let pte_flags = PTEFlags::from(&self.map_perm);
        page_table.map(vpn, ppn, pte_flags);
    }
}

impl MapArea {
    pub fn copy_data(&mut self, page_table: &PageTable, data: &[u8], offset: usize) {
        assert!(self.map_type == MapType::Framed);
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
    /// 在原有的MapArea上删除一个页, 并删除相关映射
    /// used by `sys_brk`
    pub fn dealloc_one_page(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        let frame = self.data_frames.remove(&vpn).unwrap();
        page_table.unmap(vpn);
        drop(frame);
    }
    /// 在原有的MapArea上增加一个页, 并添加相关映射
    /// used by `sys_brk`
    pub fn alloc_one_page(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        let frame = frame_alloc().unwrap();
        let ppn = frame.ppn;
        let pte_flags = PTEFlags::from(&self.map_perm);
        page_table.map(vpn, ppn, pte_flags);
        self.data_frames.insert(vpn, Arc::new(frame));
    }
}

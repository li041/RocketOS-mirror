//! MemorySet
//! MapArea
//! MapArea
//! MapType
//! MapPermision
use core::{arch::asm, panic};

use super::{PageTable, PageTableEntry, PhysPageNum, StepByOne, VPNRange, VirtAddr, VirtPageNum};

use crate::{
    config::{MMAP_MIN_ADDR, PAGE_SIZE_BITS, USER_STACK_SIZE},
    fs::namei::path_openat,
    task::{aux::*, current_task},
    utils::ceil_to_page_size,
};
use alloc::{
    collections::btree_map::BTreeMap,
    ffi::CString,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use bitflags::bitflags;
use log::info;
use riscv::{interrupt, register::satp};
use xmas_elf::program::Type;

use super::{
    frame_allocator::{frame_alloc, FrameTracker},
    page_table::PTEFlags,
};
use crate::{
    boards::qemu::{MEMORY_END, MMIO},
    config::{DL_INTERP_OFFSET, KERNEL_BASE, PAGE_SIZE},
    fs::AT_FDCWD,
    index_list::IndexList,
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
    pub page_table: PageTable,
    pub areas: IndexList<MapArea>,
}

// 返回MemroySet的方法
impl MemorySet {
    pub fn new_bare() -> Self {
        Self {
            brk: 0,
            heap_bottom: 0,
            mmap_start: MMAP_MIN_ADDR,
            page_table: PageTable::new(),
            areas: IndexList::new(),
        }
    }

    /// 创建一个拥有内核空间一级映射的用户空间
    /// 用于创建用户进程, used by `from_elf, from_existed_user`
    /// 初始用户程序不分配堆内存, 只分配堆底
    pub fn from_global() -> Self {
        let page_table = PageTable::from_global();
        Self {
            // 在caller中分配堆底
            brk: 0,
            heap_bottom: 0,
            mmap_start: MMAP_MIN_ADDR,
            page_table,
            areas: IndexList::new(),
        }
    }

    pub fn from_existed_user(user_memory_set: &MemorySet) -> Self {
        let mut memory_set = Self::from_global();
        // 复制堆底和brk, 堆内容会在user_memory_set.areas.iter()中复制
        memory_set.brk = user_memory_set.brk;
        memory_set.heap_bottom = user_memory_set.heap_bottom;
        for area in user_memory_set.areas.iter() {
            let new_area = MapArea::from_another(area);
            // 这里只做了分配物理页, 填加页表映射, 没有复制数据
            memory_set.push_anoymous_area(new_area);
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
        user_memory_set.page_table.dump_all_user_mapping();
        memory_set
    }
    pub fn from_existed_user_lazily(user_memory_set: &MemorySet) -> Self {
        let page_table = PageTable::from_existed_user(&user_memory_set.page_table);
        MemorySet {
            brk: user_memory_set.brk,
            heap_bottom: user_memory_set.heap_bottom,
            mmap_start: MMAP_MIN_ADDR,
            page_table,
            // areas需要clone, 拿到Arc<FrameTracker>
            areas: user_memory_set.areas.clone(),
        }
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
                let map_area = MapArea::new_from_va(start_va, end_va, MapType::Framed, map_perm);
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

        log::error!("[from_elf] AT_PHDR: {:#x}", ph_va);
        log::error!("[from_elf] AT_PAGESZ: {}", PAGE_SIZE);
        log::error!("[from_elf] AT_PHENT: {}", ph_entsize);
        log::error!("[from_elf] AT_PHNUM: {}", ph_count);
        log::error!("[from_elf] AT_ENTRY: {:#x}", entry_point);
        log::error!("[from_elf] AT_BASE: {:#x}", DL_INTERP_OFFSET);

        // 需要动态链接
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
                                MapArea::new_from_va(start_va, end_va, MapType::Framed, map_perm);

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
        info!(
            "[MemorySet::from_elf] user stack [{:#x}, {:#x})",
            ustack_bottom, ustack_top
        );
        memory_set.insert_framed_area_va(
            ustack_bottom.into(),
            ustack_top.into(),
            MapPermission::R | MapPermission::W | MapPermission::U,
        );

        // 分配用户堆底, 初始不分配堆内存
        let heap_bottom = ustack_top + PAGE_SIZE;
        memory_set.heap_bottom = heap_bottom;
        memory_set.brk = heap_bottom;

        log::error!("[from_elf] entry_point: {:#x}", entry_point);

        return (memory_set, satp, ustack_top, entry_point, aux_vec);
    }

    pub fn new_kernel() -> Self {
        let mut memory_set = Self::new_bare();
        // map kernel sections
        info!(
            "[new_kernel] .text \t[{:#x}, {:#x})",
            stext as usize, etext as usize
        );
        info!(
            "[new_kernel] .rodata \t[{:#x}, {:#x})",
            srodata as usize, erodata as usize
        );
        info!(
            "[new_kernel] .data \t[{:#x}, {:#x})",
            sdata as usize, edata as usize
        );
        info!(
            "[new_kernel] .bss \t[{:#x}, {:#x})",
            sbss_with_stack as usize, ebss as usize
        );
        log::trace!("mapping .text section");
        memory_set.push_with_offset(
            MapArea::new_from_va(
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
        log::trace!("mapping .rodata section");
        memory_set.push_with_offset(
            MapArea::new_from_va(
                (srodata as usize).into(),
                (erodata as usize).into(),
                MapType::Linear,
                MapPermission::R | MapPermission::G,
                // MapPermission::R | MapPermission::A | MapPermission::D,
            ),
            None,
            0,
        );
        log::trace!("mapping .data section");
        memory_set.push_with_offset(
            MapArea::new_from_va(
                (sdata as usize).into(),
                (edata as usize).into(),
                MapType::Linear,
                MapPermission::R | MapPermission::W,
                // MapPermission::R | MapPermission::W | MapPermission::A | MapPermission::D,
            ),
            None,
            0,
        );
        log::trace!("mapping .bss section");
        memory_set.push_with_offset(
            MapArea::new_from_va(
                (sbss_with_stack as usize).into(),
                (ebss as usize).into(),
                MapType::Linear,
                MapPermission::R | MapPermission::W,
                // MapPermission::R | MapPermission::W | MapPermission::A | MapPermission::D,
            ),
            None,
            0,
        );
        log::trace!("mapping physical memory");
        memory_set.push_with_offset(
            MapArea::new_from_va(
                (ekernel as usize).into(),
                (KERNEL_BASE + MEMORY_END).into(),
                MapType::Linear,
                MapPermission::R | MapPermission::W,
                // MapPermission::R | MapPermission::W | MapPermission::A | MapPermission::D,
            ),
            None,
            0,
        );
        log::trace!("mapping memory-mapped registers");
        for pair in MMIO {
            memory_set.push_with_offset(
                MapArea::new_from_va(
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
}

impl MemorySet {
    /// map_offset: the offset in the first page
    /// 在data不为None时, map_offset才有意义, 是data在第一个页中的偏移
    fn push_with_offset(&mut self, mut map_area: MapArea, data: Option<&[u8]>, map_offset: usize) {
        map_area.map(&mut self.page_table);
        if let Some(data) = data {
            map_area.copy_data(&mut self.page_table, data, map_offset);
        }
        self.areas.insert_last(map_area);
    }
    fn push_anoymous_area(&mut self, mut map_area: MapArea) {
        map_area.map(&mut self.page_table);
        self.areas.insert_last(map_area);
    }
    /// 由caller保证区域没有冲突, 且start_va和end_va是页对齐的
    /// 插入framed的空白区域
    /// used by `kstack_alloc`, `from_elf 用户栈`
    pub fn insert_framed_area_va(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        map_perm: MapPermission,
    ) {
        self.push_anoymous_area(MapArea::new_from_va(
            start_va,
            end_va,
            MapType::Framed,
            map_perm,
        ));
    }
    //
    pub fn insert_framed_area_vpn_range(&mut self, vpn_range: VPNRange, map_perm: MapPermission) {
        self.push_anoymous_area(MapArea::new_from_vpn_range(
            vpn_range,
            MapType::Framed,
            map_perm,
        ));
    }
    /// change the satp register to the new page table, and flush the TLB
    #[cfg(target_arch = "riscv64")]
    pub fn activate(&self) {
        let satp = self.page_table.token();
        unsafe {
            satp::write(satp);
            asm!("sfence.vma");
        }
    }
    #[cfg(target_arch = "loongarch64")]
    // Todo
    pub fn activate(&self) {
        unimplemented!();
    }
    // 在memory_set.mmap_start加到MMAP_MAX_ADDR前可以保证没有冲突
    pub fn get_unmapped_area(&mut self, _hint: usize, size: usize) -> VPNRange {
        let aligned_size = ceil_to_page_size(size);
        let start_vpn = VirtPageNum::from(self.mmap_start >> PAGE_SIZE_BITS);
        let end_vpn = VirtPageNum::from((self.mmap_start + aligned_size) >> PAGE_SIZE_BITS);
        self.mmap_start += aligned_size;
        VPNRange::new(start_vpn, end_vpn)
    }
    // 获取当前地址空间token
    pub fn token(&self) -> usize {
        self.page_table.token()
    }
}

impl MemorySet {
    pub fn recycle_data_pages(&mut self) {
        self.areas.clear();
    }
    pub fn remove_area_with_overlap(&mut self, unmap_vpn_range: VPNRange) {
        let mut index = self.areas.last_index();
        while index.is_some() {
            let area = self.areas.get_mut(index).unwrap();
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
                // 对于vpn_start ~ new_vpn_start的页, 释放, 对于new_vpn_end ~ vpn_end的页, 释放
                let dealloc_vpn_range1 = VPNRange::new(old_vpn_start, new_vpn_start);
                for vpn in dealloc_vpn_range1 {
                    area.dealloc_one_page(&mut self.page_table, vpn);
                }
                let dealloc_vpn_range2 = VPNRange::new(old_vpn_end, new_vpn_end);
                for vpn in dealloc_vpn_range2 {
                    area.dealloc_one_page(&mut self.page_table, vpn);
                }
                area.vpn_range.set_start(new_vpn_start);
                area.vpn_range.set_end(new_vpn_end);
                break;
            }
            index = self.areas.prev_index(index);
        }
    }
    // 这里从尾部开始找, 因为在MemorySet中, 内核栈一般在最后
    // used by `sys_brk`, 这是因为heap_bottom是固定的
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

    /// 从尾部开始找, 因为动态分配的内存一般在最后
    /// 在原有的MapArea上增/删页, 并添加相关映射
    /// used by `sys_brk`
    pub fn remap_area_with_start_vpn(&mut self, start_vpn: VirtPageNum, new_end_vpn: VirtPageNum) {
        let mut index = self.areas.last_index();
        let delete_flag = new_end_vpn == start_vpn;
        while index.is_some() {
            let area = self.areas.get_mut(index).unwrap();
            if area.vpn_range.get_start() == start_vpn {
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
                if delete_flag {
                    self.areas.remove(index);
                }
                return;
            }
            index = self.areas.prev_index(index);
        }
        log::error!(
            "[MemorySet::remap_area_with_start_vpn] can't find area with start_vpn: {:#x}",
            start_vpn.0
        );
    }
}

/// MemorySet检查的方法
impl MemorySet {
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
    // 检查是否是COW或者lazy_allocation的区域
    // 逐页处理
    // used by `copy_to_user`, 不仅会检查, 还会提前处理, 避免实际写的时候发生page fault
    // 由调用者保证pte存在
    pub fn pre_handle_page_fault(&mut self, vpn_range: VPNRange) -> Result<(), &'static str> {
        let mut vpn = vpn_range.get_start();
        while vpn < vpn_range.get_end() {
            if let Some(pte) = self.page_table.find_pte(vpn) {
                if vpn == VirtPageNum::from(0) {
                    return Err("[copy_to_user] write to va 0");
                }
                if pte.is_cow() {
                    log::warn!(
                        "[copy_to_user] pre handle cow page fault, vpn {:#x}, pte: {:#x?}",
                        vpn.0,
                        pte
                    );
                    let areas = &mut self.areas;
                    let mut index = areas.last_index();
                    while index.is_some() {
                        let area = areas.get_mut(index).unwrap();
                        if area.vpn_range.contains_vpn(vpn) {
                            let data_frame = area.data_frames.get(&vpn).unwrap();
                            if Arc::strong_count(data_frame) == 1 {
                                let mut flags = pte.flags();
                                flags.remove(PTEFlags::COW);
                                flags.insert(PTEFlags::W);
                                *pte = PageTableEntry::new(pte.ppn(), flags);
                            } else {
                                let frame = frame_alloc().unwrap();
                                let src_frame = pte.ppn().get_bytes_array();
                                let dst_frame = frame.ppn.get_bytes_array();
                                dst_frame.copy_from_slice(src_frame);
                                let mut flags = pte.flags();
                                flags.remove(PTEFlags::COW);
                                flags.insert(PTEFlags::W);
                                *pte = PageTableEntry::new(frame.ppn, flags);
                                area.data_frames.insert(vpn, Arc::new(frame));
                            }
                            unsafe {
                                core::arch::asm!(
                                    "sfence.vma x0, x0",
                                    options(nomem, nostack, preserves_flags)
                                );
                            }
                            break;
                        }
                        index = areas.prev_index(index);
                    }
                } else if pte.ppn() == PhysPageNum::from(0) {
                    let areas = &mut self.areas;
                    let mut index = areas.last_index();
                    while index.is_some() {
                        let area = areas.get_mut(index).unwrap();
                        if area.vpn_range.contains_vpn(vpn) {
                            let frame = frame_alloc().unwrap();
                            let ppn = frame.ppn;
                            *pte = PageTableEntry::new(ppn, pte.flags());
                            area.data_frames.insert(vpn, Arc::new(frame));
                            unsafe {
                                core::arch::asm!(
                                    "sfence.vma x0, x0",
                                    options(nomem, nostack, preserves_flags)
                                );
                            }
                            break;
                        }
                        index = areas.prev_index(index);
                    }
                }
            } else {
                return Err("[copy_to_user] can't find valid pte for vpn");
            }
            // 继续处理下一页
            vpn.step();
        }
        return Ok(());
    }
}

#[derive(Clone)]
pub struct MapArea {
    pub vpn_range: VPNRange,
    pub data_frames: BTreeMap<VirtPageNum, Arc<FrameTracker>>,
    map_type: MapType,
    map_perm: MapPermission,
}

// constructor
impl MapArea {
    /// Create a empty `MapArea` from va
    pub fn new_from_va(
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
    pub fn new_from_vpn_range(
        vpn_range: VPNRange,
        map_type: MapType,
        map_perm: MapPermission,
    ) -> Self {
        Self {
            vpn_range,
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
    // map the area: [start_va, end_va), 左闭右开
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
    /// 在原有的MapArea上增加一个页, 并添加相关映射
    /// used by `sys_brk`
    pub fn alloc_one_page(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        let frame = frame_alloc().unwrap();
        let ppn = frame.ppn;
        let pte_flags = PTEFlags::from_bits(self.map_perm.bits()).unwrap();
        page_table.map(vpn, ppn, pte_flags);
        self.data_frames.insert(vpn, Arc::new(frame));
    }
    /// 在原有的MapArea上删除一个页, 并删除相关映射
    /// used by `sys_brk`
    pub fn dealloc_one_page(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        let frame = self.data_frames.remove(&vpn).unwrap();
        page_table.unmap(vpn);
        drop(frame);
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
    #[derive(Clone, Copy, Debug)]
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

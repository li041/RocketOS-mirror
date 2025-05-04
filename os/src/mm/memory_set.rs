//! MemorySet
use core::{arch::asm, iter::Map, mem, ops::Range, usize};

use super::{address::StepByOne, area::MapArea, shm::ShmSegment, VPNRange};
use crate::{
    arch::mm::{sfence_vma_vaddr, PTEFlags, PageTable, PageTableEntry},
    fs::{fdtable::FdFlags, file::OpenFlags},
    futex::futex::SharedMappingInfo,
    mm::{
        area::{MapPermission, MapType},
        frame_alloc, FrameTracker, PhysAddr, PhysPageNum, VirtAddr, VirtPageNum,
    },
    syscall::errno::{Errno, SyscallRet},
    task::current_task,
};

use crate::{
    arch::{
        config::{MMAP_MIN_ADDR, PAGE_SIZE_BITS, USER_STACK_SIZE},
        trap::PageFaultCause,
    },
    fs::{file::FileOp, namei::path_openat},
    mm::Page,
    task::aux::*,
    utils::ceil_to_page_size,
};
use alloc::{
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use bitflags::bitflags;
use log::info;

use spin::{Mutex, RwLock};
use xmas_elf::program::Type;

use crate::{
    arch::boards::qemu::{MEMORY_END, MMIO},
    arch::config::{DL_INTERP_OFFSET, KERNEL_BASE, PAGE_SIZE},
    fs::AT_FDCWD,
    index_list::IndexList,
    mutex::SpinNoIrqLock,
    task::aux::AuxHeader,
};
use alloc::sync::Arc;
use lazy_static::lazy_static;

#[allow(unused)]
extern "C" {
    fn stext();
    fn strampoline();
    fn etrampoline();
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
    pub static ref KERNEL_SPACE: Arc<Mutex<MemorySet>> =
        Arc::new(Mutex::new(MemorySet::new_kernel()));
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
    /// Elf, Stack, Heap, 匿名私有映射, 匿名共享映射
    /// Todo: 支持areas的lazy allocation
    /// 文件私有/共享映射
    /// key是vpn_range起始虚拟地址
    pub areas: BTreeMap<VirtPageNum, MapArea>,
    /// System V shared memory
    /// shm_start_address -> shmid
    pub addr2shmid: BTreeMap<usize, usize>,
}

#[cfg(target_arch = "riscv64")]
impl MemorySet {
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
            areas: BTreeMap::new(),
            addr2shmid: BTreeMap::new(),
        }
    }
}

// 返回MemroySet的方法
impl MemorySet {
    pub fn new_bare() -> Self {
        Self {
            brk: 0,
            heap_bottom: 0,
            mmap_start: MMAP_MIN_ADDR,
            page_table: PageTable::new(),
            areas: BTreeMap::new(),
            addr2shmid: BTreeMap::new(),
        }
    }

    pub fn new_kernel() -> Self {
        let mut memory_set = Self::new_bare();

        // 映射内核
        log::info!(".text\t[{:#x}, {:#x})", stext as usize, etext as usize);
        log::info!(
            ".rodata\t[{:#x}, {:#x})",
            srodata as usize,
            erodata as usize
        );
        log::info!(".data\t[{:#x}, {:#x})", sdata as usize, edata as usize);
        log::info!(
            ".bss\t[{:#x}, {:#x})",
            sbss_with_stack as usize,
            ebss as usize
        );
        log::trace!("mapping .text section");

        memory_set.push_with_offset(
            MapArea::new(
                VPNRange::new(
                    VirtAddr::from(stext as usize).floor(),
                    VirtAddr::from(strampoline as usize).ceil(),
                ),
                MapType::Linear,
                MapPermission::R | MapPermission::X | MapPermission::G,
                None,
                0,
            ),
            None,
            0,
        );

        memory_set.push_with_offset(
            MapArea::new(
                VPNRange::new(
                    VirtAddr::from(strampoline as usize).floor(),
                    VirtAddr::from(etrampoline as usize).ceil(),
                ),
                MapType::Linear,
                MapPermission::R | MapPermission::X | MapPermission::U,
                None,
                0,
            ),
            None,
            0,
        );

        memory_set.push_with_offset(
            MapArea::new(
                VPNRange::new(
                    VirtAddr::from(etrampoline as usize).floor(),
                    VirtAddr::from(etext as usize).ceil(),
                ),
                MapType::Linear,
                MapPermission::R | MapPermission::X | MapPermission::G,
                None,
                0,
            ),
            None,
            0,
        );

        log::trace!("mapping .rodata section");
        memory_set.push_with_offset(
            MapArea::new(
                VPNRange::new(
                    VirtAddr::from(srodata as usize).floor(),
                    VirtAddr::from(erodata as usize).ceil(),
                ),
                MapType::Linear,
                MapPermission::R | MapPermission::G,
                None,
                0,
            ),
            None,
            0,
        );
        log::trace!("mapping .data section");
        memory_set.push_with_offset(
            MapArea::new(
                VPNRange::new(
                    VirtAddr::from(sdata as usize).floor(),
                    VirtAddr::from(edata as usize).ceil(),
                ),
                MapType::Linear,
                MapPermission::R | MapPermission::W,
                // MapPermission::R | MapPermission::W | MapPermission::A | MapPermission::D,
                None,
                0,
            ),
            None,
            0,
        );
        log::trace!("mapping .bss section");
        memory_set.push_with_offset(
            MapArea::new(
                VPNRange::new(
                    VirtAddr::from(sbss_with_stack as usize).floor(),
                    VirtAddr::from(ebss as usize).ceil(),
                ),
                MapType::Linear,
                MapPermission::R | MapPermission::W,
                // MapPermission::R | MapPermission::W | MapPermission::A | MapPermission::D,
                None,
                0,
            ),
            None,
            0,
        );
        log::trace!("mapping physical memory");
        memory_set.push_with_offset(
            MapArea::new(
                VPNRange::new(
                    VirtAddr::from(ekernel as usize).floor(),
                    VirtAddr::from(KERNEL_BASE + MEMORY_END).ceil(),
                ),
                MapType::Linear,
                MapPermission::R | MapPermission::W,
                // MapPermission::R | MapPermission::W | MapPermission::A | MapPermission::D,
                None,
                0,
            ),
            None,
            0,
        );
        log::trace!("mapping memory-mapped registers");
        for pair in MMIO {
            memory_set.push_with_offset(
                MapArea::new(
                    VPNRange::new(
                        VirtAddr::from((*pair).0 + KERNEL_BASE).floor(),
                        VirtAddr::from((*pair).0 + KERNEL_BASE + (*pair).1).ceil(),
                    ),
                    MapType::Linear,
                    MapPermission::R | MapPermission::W,
                    // MapPermission::R | MapPermission::W | MapPermission::A | MapPermission::D,
                    None,
                    0,
                ),
                None,
                0,
            );
        }
        // #[cfg(target_arch = "riscv64")]
        {
            log::trace!("mapping kernel stack area");
            // 注意这里仅在内核的第一级页表加一个映射, 之后的映射由kstack_alloc通过`find_pte_create`完成
            // 这样做只是为了让`user_space`中也有内核栈的映射, user_space通过`from_global`浅拷贝内核的一级页表的后256项
            let kernel_root_page_table = memory_set.page_table.root_ppn.get_pte_array();
            // 511: 对应的是0xffff_ffc0_0000_0000 ~ 0xffff_ffff_ffff_fff, 也就是内核的最后一个页表项
            let pte = &mut kernel_root_page_table[511];
            // log::error!("pte: {:?}", pte); // 这里可以看到511项的pte是0
            // 注意不能让kstack_second_level_frame被drop, 否则frame会被回收, 但是内核栈的映射还在
            *pte = PageTableEntry::new(kstack_second_level_frame.ppn, PTEFlags::V);
        }
        log::trace!("mapping complete!");
        memory_set
    }

    /// return (user_memory_set, satp, ustack_top, entry_point, aux_vec, Option<tls>)
    /// Todo: elf_data是完整的, 还要lazy_allocation?
    pub fn from_elf(
        mut elf_data: Vec<u8>,
        argv: &mut Vec<String>,
    ) -> (Self, usize, usize, usize, Vec<AuxHeader>, Option<usize>) {
        #[cfg(target_arch = "riscv64")]
        let mut memory_set = Self::from_global();
        #[cfg(target_arch = "loongarch64")]
        let mut memory_set = Self::new_bare();

        let mut tls_ptr = None;

        // 处理 .sh 文件
        if argv.len() > 0 {
            let file_name = &argv[0];
            if file_name.ends_with(".sh") {
                let prepend_args = vec![String::from("./busybox"), String::from("sh")];
                argv.splice(0..0, prepend_args);
                if let Ok(busybox) = path_openat("./busybox", OpenFlags::empty(), AT_FDCWD, 0) {
                    elf_data = busybox.read_all()
                }
            }
        }

        // 创建`TaskContext`时使用
        let pgtbl_ppn = memory_set.page_table.token();
        // map program segments of elf, with U flag
        let elf = xmas_elf::ElfFile::new(&elf_data).unwrap();
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
        let mut max_end_vpn = VirtPageNum(0);
        let mut need_dl: bool = false;

        for i in 0..ph_count {
            // 程序头部的类型是Load, 代码段或数据段
            let ph = elf.program_header(i).unwrap();
            let ph_type = ph.get_type().unwrap();
            if ph_type == Type::Load {
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
                let vpn_range = VPNRange::new(start_va.floor(), end_va.ceil());
                max_end_vpn = vpn_range.get_end();
                let map_area = MapArea::new(vpn_range, MapType::Framed, map_perm, None, 0);
                // 对齐到页

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
            if ph_type == Type::Tls {
                let start_va: VirtAddr = (ph.virtual_addr() as usize).into();
                tls_ptr = Some(start_va.0);
            }
            // 判断是否需要动态链接
            if ph_type == Type::Interp {
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

        log::info!("[from_elf] AT_PHDR:\t{:#x}", ph_va);
        log::info!("[from_elf] AT_PAGESZ:\t{}", PAGE_SIZE);
        log::info!("[from_elf] AT_PHENT:\t{}", ph_entsize);
        log::info!("[from_elf] AT_PHNUM:\t{}", ph_count);
        log::info!("[from_elf] AT_ENTRY:\t{:#x}", entry_point);
        log::info!("[from_elf] AT_BASE:\t{:#x}", DL_INTERP_OFFSET);

        // 需要动态链接
        if need_dl {
            log::warn!("[from_elf] need dynamic link");
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
                if let Ok(interpreter) = path_openat(&interp, OpenFlags::empty(), AT_FDCWD, 0) {
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
                            let vpn_range = VPNRange::new(start_va.floor(), end_va.ceil());
                            let map_area =
                                MapArea::new(vpn_range, MapType::Framed, map_perm, None, 0);

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
            log::warn!("[from_elf] static link");
        }

        // 映射用户栈
        let ustack_bottom: usize = (max_end_vpn.0 << PAGE_SIZE_BITS) + PAGE_SIZE; // 一个页用于保护
        let ustack_top: usize = ustack_bottom + USER_STACK_SIZE;
        info!(
            "[MemorySet::from_elf] user stack [{:#x}, {:#x})",
            ustack_bottom, ustack_top
        );
        let vpn_range = VPNRange::new(
            VirtAddr::from(ustack_bottom).floor(),
            VirtAddr::from(ustack_top).ceil(),
        );
        let ustack_map_area = MapArea::new(
            vpn_range,
            MapType::Framed,
            MapPermission::R | MapPermission::W | MapPermission::U,
            None,
            0,
        );
        memory_set.push_anoymous_area(ustack_map_area);

        // 分配用户堆底, 初始不分配堆内存?
        let heap_bottom = ustack_top + PAGE_SIZE;
        memory_set.heap_bottom = heap_bottom;
        memory_set.brk = heap_bottom;
        // 重置mmap_start
        memory_set.mmap_start = MMAP_MIN_ADDR;

        log::error!("[from_elf] entry_point: {:#x}", entry_point);

        return (
            memory_set,
            pgtbl_ppn,
            ustack_top,
            entry_point,
            aux_vec,
            tls_ptr,
        );
    }

    /// return (user_memory_set, satp, ustack_top, entry_point, aux_vec, Option<tls>)
    /// Todo: elf_data是完整的, 还要lazy_allocation?
    pub fn from_elf_lazily(
        mut elf_file: Arc<dyn FileOp>,
        mut elf_data: Vec<u8>,
        argv: &mut Vec<String>,
    ) -> (Self, usize, usize, usize, Vec<AuxHeader>, Option<usize>) {
        #[cfg(target_arch = "riscv64")]
        let mut memory_set = Self::from_global();
        #[cfg(target_arch = "loongarch64")]
        let mut memory_set = Self::new_bare();

        let mut tls_ptr = None;

        // 处理 .sh 文件
        if argv.len() > 0 {
            let file_name = &argv[0];
            if file_name.ends_with(".sh") {
                let prepend_args = vec![String::from("./busybox"), String::from("sh")];
                argv.splice(0..0, prepend_args);
                if let Ok(busybox) = path_openat("./busybox", OpenFlags::empty(), AT_FDCWD, 0) {
                    elf_data = busybox.read_all();
                    elf_file = busybox;
                }
            }
        }
        // 创建`TaskContext`时使用
        let pgtbl_ppn = memory_set.page_table.token();
        // map program segments of elf, with U flag
        let elf = xmas_elf::ElfFile::new(&elf_data).unwrap();
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
        let mut max_end_vpn = VirtPageNum(0);
        let mut need_dl: bool = false;

        for i in 0..ph_count {
            // 程序头部的类型是Load, 代码段或数据段
            let ph = elf.program_header(i).unwrap();
            let ph_type = ph.get_type().unwrap();
            if ph_type == Type::Load {
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
                let vpn_range = VPNRange::new(start_va.floor(), end_va.ceil());
                max_end_vpn = vpn_range.get_end();
                // 对齐到页

                let map_offset = start_va.0 - start_va.floor().0 * PAGE_SIZE;
                log::info!(
                    "[from_elf] app map area: [{:#x}, {:#x}), map_perm: {:?}",
                    start_va.0,
                    end_va.0,
                    map_perm,
                );
                // 如果只读段, 且file_size与mem_size相等(无需填充), 且直接使用页缓存映射
                if !map_perm.contains(MapPermission::W) && ph.file_size() == ph.mem_size() {
                    let mut map_area =
                        MapArea::new(vpn_range, MapType::FilebeRO, map_perm, None, 0);
                    // 直接使用页缓存映射只读段
                    let vpn_start = vpn_range.get_start().0;
                    for vpn in vpn_range {
                        let offset = ph.offset() as usize + (vpn.0 - vpn_start) * PAGE_SIZE;
                        let page = elf_file.get_page(offset).expect("get page failed");
                        memory_set.page_table.map(vpn, page.ppn(), map_perm.into());
                        map_area.pages.insert(vpn, page);
                    }
                } else {
                    // 采用Framed + 直接拷贝数据到匿名页
                    let map_area = MapArea::new(vpn_range, MapType::Framed, map_perm, None, 0);
                    memory_set.push_with_offset(
                        map_area,
                        Some(
                            &elf_data
                                [ph.offset() as usize..(ph.offset() + ph.file_size()) as usize],
                        ),
                        map_offset,
                    );
                }
            }
            if ph_type == Type::Tls {
                let start_va: VirtAddr = (ph.virtual_addr() as usize).into();
                tls_ptr = Some(start_va.0);
            }
            // 判断是否需要动态链接
            if ph_type == Type::Interp {
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

        log::info!("[from_elf] AT_PHDR:\t{:#x}", ph_va);
        log::info!("[from_elf] AT_PAGESZ:\t{}", PAGE_SIZE);
        log::info!("[from_elf] AT_PHENT:\t{}", ph_entsize);
        log::info!("[from_elf] AT_PHNUM:\t{}", ph_count);
        log::info!("[from_elf] AT_ENTRY:\t{:#x}", entry_point);
        log::info!("[from_elf] AT_BASE:\t{:#x}", DL_INTERP_OFFSET);

        // 需要动态链接
        if need_dl {
            log::warn!("[from_elf] need dynamic link");
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
                if let Ok(interpreter) = path_openat(&interp, OpenFlags::empty(), AT_FDCWD, 0) {
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
                            let vpn_range = VPNRange::new(start_va.floor(), end_va.ceil());
                            let map_area =
                                MapArea::new(vpn_range, MapType::Framed, map_perm, None, 0);

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
            log::warn!("[from_elf] static link");
        }

        // 映射用户栈
        let ustack_bottom: usize = (max_end_vpn.0 << PAGE_SIZE_BITS) + PAGE_SIZE; // 一个页用于保护
        let ustack_top: usize = ustack_bottom + USER_STACK_SIZE;
        info!(
            "[MemorySet::from_elf] user stack [{:#x}, {:#x})",
            ustack_bottom, ustack_top
        );
        let vpn_range = VPNRange::new(
            VirtAddr::from(ustack_bottom).floor(),
            VirtAddr::from(ustack_top).ceil(),
        );
        let ustack_map_area = MapArea::new(
            vpn_range,
            MapType::Framed,
            MapPermission::R | MapPermission::W | MapPermission::U,
            None,
            0,
        );
        memory_set.push_anoymous_area(ustack_map_area);

        // 分配用户堆底, 初始不分配堆内存?
        let heap_bottom = ustack_top + PAGE_SIZE;
        memory_set.heap_bottom = heap_bottom;
        memory_set.brk = heap_bottom;
        // 重置mmap_start
        memory_set.mmap_start = MMAP_MIN_ADDR;

        log::error!("[from_elf] entry_point: {:#x}", entry_point);

        return (
            memory_set,
            pgtbl_ppn,
            ustack_top,
            entry_point,
            aux_vec,
            tls_ptr,
        );
    }

    #[allow(unused)]
    pub fn from_existed_user(user_memory_set: &MemorySet) -> Self {
        #[cfg(target_arch = "riscv64")]
        let mut memory_set = Self::from_global();
        #[cfg(target_arch = "loongarch64")]
        let mut memory_set = Self::new_bare();
        // 复制堆底和brk, 堆内容会在user_memory_set.areas.iter()中复制
        memory_set.brk = user_memory_set.brk;
        memory_set.heap_bottom = user_memory_set.heap_bottom;
        for (_, area) in user_memory_set.areas.iter() {
            let new_area = MapArea::from_another(&area);
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
        memory_set
    }
    pub fn from_existed_user_lazily(user_memory_set: &MemorySet) -> Self {
        let page_table = PageTable::from_existed_user(&user_memory_set.page_table);
        user_memory_set.areas.iter().for_each(|(_, area)| {
            log::error!(
                "[MemorySet::from_existed_user_lazily] area: {:#x} {:#x}",
                area.vpn_range.get_start().0,
                area.vpn_range.get_end().0
            );
        });
        let memory_set = MemorySet {
            brk: user_memory_set.brk,
            heap_bottom: user_memory_set.heap_bottom,
            mmap_start: user_memory_set.mmap_start,
            page_table,
            areas: user_memory_set.areas.clone(),
            addr2shmid: user_memory_set.addr2shmid.clone(),
        };
        memory_set
    }
}

impl MemorySet {
    /// 由caller保证区域没有冲突, 且start_va和end_va是页对齐的
    /// 插入framed的空白区域
    /// used by `kstack_alloc`, `from_elf 用户栈`
    pub fn insert_framed_area(&mut self, vpn_range: VPNRange, map_perm: MapPermission) {
        self.push_anoymous_area(MapArea::new(vpn_range, MapType::Framed, map_perm, None, 0));
    }
    pub fn insert_map_area_lazily(&mut self, map_area: MapArea) {
        // 这里不需要map, 映射在缺页时处理
        self.areas.insert(map_area.vpn_range.get_start(), map_area);
    }
    /// map_offset: the offset in the first page
    /// 在data不为None时, map_offset才有意义, 是data在第一个页中的偏移
    pub fn push_with_offset(
        &mut self,
        mut map_area: MapArea,
        data: Option<&[u8]>,
        map_offset: usize,
    ) {
        map_area.map(&mut self.page_table);
        if let Some(data) = data {
            map_area.copy_data_private(&mut self.page_table, data, map_offset);
        }
        self.areas.insert(map_area.vpn_range.get_start(), map_area);
    }
    fn push_anoymous_area(&mut self, mut map_area: MapArea) {
        map_area.map(&mut self.page_table);
        self.areas.insert(map_area.vpn_range.get_start(), map_area);
    }
    /// change the satp register to the new page table, and flush the TLB
    #[cfg(target_arch = "riscv64")]
    pub fn activate(&self) {
        use riscv::register::satp;
        let satp = self.page_table.token();
        unsafe {
            satp::write(satp);
            asm!("sfence.vma");
        }
    }
    #[cfg(target_arch = "loongarch64")]
    pub fn activate(&self) {
        self.page_table.activate();
    }
    // 在memory_set.mmap_start加到MMAP_MAX_ADDR前可以保证没有冲突
    // 在fixed mmap情况下, 会检查是否有冲突并unmap, 也能保证没有冲突
    pub fn get_unmapped_area(&mut self, size: usize) -> VPNRange {
        let aligned_size = ceil_to_page_size(size);
        let start_vpn = VirtAddr::from(self.mmap_start).floor();
        let end_vpn = VirtAddr::from(self.mmap_start + aligned_size).ceil();
        self.mmap_start += aligned_size;
        VPNRange::new(start_vpn, end_vpn)
    }
    pub fn translate_va_to_pa(&self, va: VirtAddr) -> Option<usize> {
        self.page_table.translate_va_to_pa(va)
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
    // 返回值表示是否有区域被remap
    pub fn remap_area_with_overlap(
        &mut self,
        remap_vpn_range: VPNRange,
        new_perm: MapPermission,
    ) -> bool {
        let mut found = false;
        // 用于存放拆分出来的区域, 最后添加到areas中
        let mut split_new_areas: Vec<MapArea> = Vec::new();
        let remap_vpn_end = remap_vpn_range.get_end();
        // 只检查可能与rnmap_vpn_range重叠的区域
        for (_vpn, area) in self.areas.range_mut(..=remap_vpn_end).rev() {
            if area.vpn_range.is_intersect_with(&remap_vpn_range) {
                let old_vpn_start = area.vpn_range.get_start();
                let old_vpn_end = area.vpn_range.get_end();
                let remap_start = remap_vpn_range.get_start();
                let remap_end: VirtPageNum = remap_vpn_range.get_end();
                log::info!(
                    "[MemorySet::remap_area_with_overlap] old_vpn_start: {:#x}, old_vpn_end: {:#x}, remap_start: {:#x}, remap_end: {:#x}",
                    old_vpn_start.0,
                    old_vpn_end.0,
                    remap_start.0,
                    remap_end.0
                );
                // 调整区域
                if remap_start <= old_vpn_start && remap_end >= old_vpn_end {
                    // `remap_vpn_range` 完全覆盖 `vpn_range`，remap `area`
                    area.map_perm.update_rwx(new_perm);
                    area.remap(&mut self.page_table);
                } else if remap_start <= old_vpn_start {
                    // `remap_vpn_range` 覆盖了前部分
                    let new_area = area.split2(remap_end);
                    area.map_perm.update_rwx(new_perm);
                    area.remap(&mut self.page_table);
                    split_new_areas.push(new_area);
                } else if remap_end >= old_vpn_end {
                    // `remap_vpn_range` 覆盖了后部分，调整 `vpn_end`
                    let mut new_area = area.split2(remap_start);
                    new_area.map_perm.update_rwx(new_perm);
                    new_area.remap(&mut self.page_table);
                    split_new_areas.push(new_area);
                } else {
                    // 区域被 `remap_vpn_range` 拆成两部分，需要拆分 `area`
                    let (mut remap_area, new_area) = area.split_in3(remap_start, remap_end);
                    remap_area.map_perm.update_rwx(new_perm);
                    remap_area.remap(&mut self.page_table);
                    split_new_areas.push(new_area);
                    split_new_areas.push(remap_area);
                }
                found = true;
            } else {
                break;
            }
        }
        // 将拆分出来的区域添加到 `area` 中
        self.areas.extend(
            split_new_areas
                .into_iter()
                .map(|area| (area.vpn_range.get_start(), area)),
        );
        found
    }
    // 返回值表示是否有区域被删除
    pub fn remove_area_with_overlap(&mut self, unmap_vpn_range: VPNRange) -> bool {
        let mut found = false;
        // 用于存放拆分出来的区域, 最后添加到filebe_areas中
        let mut split_new_areas: Vec<MapArea> = Vec::new();
        let mut areas_to_remove = Vec::new();
        let unmap_vpn_end = unmap_vpn_range.get_end();
        // 只检查可能与unmap_vpn_range重叠的区域
        // self.areas.range_mut(..=unmap_vpn_end).rev().for_each(|(vpn, area)| {
        for (vpn, area) in self.areas.range_mut(..=unmap_vpn_end).rev() {
            if area.vpn_range.is_intersect_with(&unmap_vpn_range) {
                let old_vpn_start = area.vpn_range.get_start();
                let old_vpn_end = area.vpn_range.get_end();
                let unmap_start = unmap_vpn_range.get_start();
                let unmap_end: VirtPageNum = unmap_vpn_range.get_end();

                log::info!(
                    "[MemorySet::remove_area_with_overlap] old_vpn_start: {:#x}, old_vpn_end: {:#x}, unmap_start: {:#x}, unmap_end: {:#x}",
                    old_vpn_start.0,
                    old_vpn_end.0,
                    unmap_start.0,
                    unmap_end.0
                );
                // 调整区域
                if unmap_start <= old_vpn_start && unmap_end >= old_vpn_end {
                    // `unmap_vpn_range` 完全覆盖 `vpn_range`，删除 `area`
                    for vpn in area.vpn_range {
                        area.dealloc_one_page(&mut self.page_table, vpn);
                    }
                    // 记录要删除的区域
                    areas_to_remove.push(*vpn);
                } else if unmap_start <= old_vpn_start {
                    // `unmap_vpn_range` 覆盖了前部分
                    // 注意: 这里不能直接设置原来vpn_range, 因为修改了vpn_range的start, 而BTreeMap是根据start排序的
                    // 需要先删除原来的区域, 再插入新的区域
                    let remain_area = area.split2(unmap_end);
                    area.unmap(&mut self.page_table);
                    areas_to_remove.push(*vpn);
                    split_new_areas.push(remain_area);
                } else if unmap_end >= old_vpn_end {
                    // `unmap_vpn_range` 覆盖了后部分，调整 `vpn_end`
                    let mut unmap_area = area.split2(unmap_start);
                    unmap_area.unmap(&mut self.page_table);
                } else {
                    // 区域被 `unmap_vpn_range` 拆成两部分，需要拆分 `area`
                    let (mut umap_area, new_area) = area.split_in3(unmap_start, unmap_end);
                    umap_area.unmap(&mut self.page_table);
                    split_new_areas.push(new_area);
                    area.vpn_range.set_end(unmap_start);
                }
                found = true;
            } else {
                break;
            }
        }
        // 在迭代后删除区域
        for vpn in areas_to_remove {
            self.areas.remove(&vpn);
        }
        // 将拆分出来的区域添加到 `area` 中
        self.areas.extend(
            split_new_areas
                .into_iter()
                .map(|area| (area.vpn_range.get_start(), area)),
        );
        found
    }

    // 这里从尾部开始找, 因为在MemorySet中, 内核栈一般在最后
    // used by `kstack drop trait`
    // 由调用者保证area的存在
    pub fn remove_area_with_start_vpn(&mut self, start_vpn: VirtPageNum) {
        log::error!(
            "[MemorySet::remove_area_with_start_vpn] remove area with start_vpn: {:#x}",
            start_vpn.0
        );
        self.areas.remove(&start_vpn);
    }

    /// 从尾部开始找, 因为动态分配的内存一般在最后
    /// 在原有的MapArea上增/删页, 并添加相关映射
    /// used by `sys_brk`
    pub fn remap_area_with_start_vpn(&mut self, start_vpn: VirtPageNum, new_end_vpn: VirtPageNum) {
        log::trace!("[MemorySet::remap_area_with_start_vpn]",);
        if let Some(area) = self.areas.get_mut(&start_vpn) {
            let old_end_vpn = area.vpn_range.get_end();
            if old_end_vpn < new_end_vpn {
                let alloc_vpn_range = VPNRange::new(old_end_vpn, new_end_vpn);
                for vpn in alloc_vpn_range {
                    area.alloc_one_page_framed_private(&mut self.page_table, vpn);
                }
            } else {
                let dealloc_vpn_range = VPNRange::new(new_end_vpn, old_end_vpn);
                for vpn in dealloc_vpn_range {
                    area.dealloc_one_page(&mut self.page_table, vpn);
                }
            }
            area.vpn_range.set_end(new_end_vpn);
            return;
        }
        // log::error!(
        log::error!(
            "[MemorySet::remap_area_with_start_vpn] can't find area with start_vpn: {:#x}",
            start_vpn.0
        );
    }
}

/// 操纵mmap_area的方法
impl MemorySet {
    // used by Futex
    // 共享区域:
    //    1. 匿名共享区域
    //    2. 文件共享区域
    pub fn get_shared_mmaping_info(&self, vaddr: VirtAddr) -> Option<SharedMappingInfo> {
        let offset = (vaddr.0 % PAGE_SIZE) as u32;
        let vpn = vaddr.floor();
        if let Some((start_vpn, area)) = self.areas.range(..=vpn).next_back() {
            if area.vpn_range.contains_vpn(vpn) {
                // 共享区域
                if area.is_shared() {
                    if area.map_type == MapType::Filebe {
                        // 文件映射
                        let inode_addr =
                            Arc::as_ptr(&area.backend_file.as_ref().unwrap().get_inode())
                                as *const () as u64;
                        let page_index = ((vaddr.0 - start_vpn.0 * PAGE_SIZE) / PAGE_SIZE) as u64;
                        return Some(SharedMappingInfo {
                            inode_addr,
                            page_index,
                            offset,
                        });
                    } else {
                        // 匿名映射
                        let page_index = ((vaddr.0 - start_vpn.0 * PAGE_SIZE) / PAGE_SIZE) as u64;
                        let page_ppn = self.page_table.translate_vpn_to_pte(vpn).unwrap().ppn();
                        log::warn!(
                            "[MemorySet::get_shared_mmaping_info] pages_addr: {:#x}, page_index: {:#x}",
                            page_ppn.0, page_index
                        );
                        return Some(SharedMappingInfo {
                            inode_addr: page_ppn.0 as u64,
                            page_index,
                            offset,
                        });
                    }
                }
                log::error!(
                    "[MemorySet::get_shared_mmaping_info] area is not shared, vpn: {:#x}~{:#x}",
                    area.vpn_range.get_start().0,
                    area.vpn_range.get_end().0
                );
                return None;
            }
        }
        log::error!(
            "[MemorySet::get_shared_mmaping_info] can't find area that contains vpn {:#x}",
            vpn.0
        );
        return None;
    }
    /// 由caller保证区域没有冲突, 且start_va和end_va是页对齐的
    /// 插入mmap的空白区域
    /// used by `sys_mmap`
    /// 文件映射在处理page_fault时才真正被映射
    // pub fn insert_filebe_area_lazily(&mut self, mmap_area: FilebeArea) {
    //     self.filebe_areas.push(mmap_area);
    // }
    /// used by `handle_recoverable_page_fault`
    /// 根据va, 找到对应的内存区域(可能是filebe_area, 也可能是匿名区域)
    /// 目前只有filebe_area是懒分配, 所以只处理filebe_area
    /// Todo: 支持MapAreas的lazy allocation
    pub fn handle_lazy_allocation_area(
        &mut self,
        va: VirtAddr,
        cause: PageFaultCause,
    ) -> Result<(), Errno> {
        log::trace!("[handle_lazy_allocation_area]");
        let vpn = va.floor();
        if let Some((_, area)) = self.areas.range_mut(..=vpn).next_back() {
            if area.vpn_range.contains_vpn(vpn) {
                if area.map_type == MapType::Filebe {
                    // 处理filebe_area的懒分配
                    if cause == PageFaultCause::LOAD
                        || cause == PageFaultCause::EXEC
                        || area.is_shared()
                    {
                        // 读, 执行, 或共享映射的写, 只需要通过backend_file获得对应的页
                        // 注意: 找页的时候需要加上偏移量
                        if cause == PageFaultCause::EXEC {
                            assert!(area.map_perm.contains(MapPermission::X));
                        }
                        let offset = area.offset
                            + (vpn.0 - area.vpn_range.get_start().0) * PAGE_SIZE as usize;
                        log::error!(
                            "[handle_lazy_allocation_area] lazy alloc file_offset {:#x}",
                            offset
                        );
                        let page = area
                            .backend_file
                            .as_ref()
                            .unwrap()
                            .clone()
                            .get_page(offset)
                            .map_err(|_| Errno::EFAULT)?;
                        // 增加页表映射
                        // 注意这里也可以是写时复制(私有映射)
                        let pte_flags = PTEFlags::from(area.map_perm);
                        let ppn = page.ppn();
                        self.page_table.map(vpn, ppn, pte_flags);
                        // 增加页的引用计数
                        area.pages.insert(va.floor(), page);
                        // 刷新tlb
                        return Ok(());
                    } else {
                        // 私有文件映射, 写时复制
                        let offset = area.offset
                            + (vpn.0 - area.vpn_range.get_start().0) * PAGE_SIZE as usize;
                        log::error!(
                            "[handle_lazy_allocation_area] COW file_offset {:#x}",
                            offset
                        );
                        let page = area
                            .backend_file
                            .as_ref()
                            .unwrap()
                            .clone()
                            .get_page(offset)
                            .map_err(|_| Errno::EFAULT)?;
                        let new_page = Page::new_framed(Some(page.get_ref(0)));
                        // 增加页表映射
                        let mut map_perm = area.map_perm;
                        map_perm.remove(MapPermission::COW);
                        map_perm.insert(MapPermission::W);
                        let pte_flags = PTEFlags::from(map_perm);
                        let ppn = new_page.ppn();
                        log::error!("vpn: {:#x}, ppn: {:#x}", vpn.0, ppn.0);
                        self.page_table.map(vpn, ppn, pte_flags);
                        // 增加页的引用计数
                        area.pages.insert(va.floor(), Arc::new(new_page));
                        // 刷新tlb
                        return Ok(());
                    }
                } else {
                    if area.is_shared() {
                        unimplemented!();
                    }
                    {
                        // 处理匿名区域的懒分配
                        // 目前只有mmap匿名区域是懒分配
                        let page = Page::new_framed(None);
                        let mut map_perm = area.map_perm;
                        map_perm.remove(MapPermission::COW);
                        map_perm.insert(MapPermission::W);
                        let pte_flags = PTEFlags::from(map_perm);
                        let ppn = page.ppn();
                        self.page_table.map(vpn, ppn, pte_flags);
                        area.pages.insert(vpn, Arc::new(page));
                        log::error!(
                            "[handle_lazy_allocation_area] lazy alloc area, vpn: {:#x}, ppn: {:#x}",
                            vpn.0,
                            ppn.0
                        );
                        return Ok(());
                    }
                }
            }
            log::error!(
                "[handle_lazy_allocation_area] can't find area with vpn {:#x}",
                vpn.0
            );
            return Err(Errno::EFAULT);
        }
        self.areas.iter().for_each(|(vpn, area)| {
            log::error!("[handle_lazy_allocation_area] area: {:#x?}", area.vpn_range,);
        });
        log::error!(
            "[handle_lazy_allocation_area] can't find area with vpn {:#x}",
            vpn.0
        );
        log::error!("empty areas");
        return Err(Errno::EFAULT);
    }
}

/// MemorySet检查的方法
impl MemorySet {
    pub fn check_writable_vpn_range(&self, vpn_range: VPNRange) -> SyscallRet {
        let mut vpn = vpn_range.get_start();
        let end_vpn = vpn_range.get_end();

        while vpn < end_vpn {
            let mut found = false;

            for (_, area) in self.areas.iter() {
                if area.vpn_range.contains_vpn(vpn) {
                    found = true;
                    if area.map_perm.contains(MapPermission::W)
                        || area.map_perm.contains(MapPermission::COW)
                    {
                        break;
                    }
                    log::warn!(
                        "[check_writable_vpn_range] vpn {:#x} not writable nor COW",
                        vpn.0
                    );
                    return Err(Errno::EACCES);
                }
            }

            if !found {
                log::error!(
                    "[check_writable_vpn_range] vpn {:#x} not mapped in any area",
                    vpn.0
                );
                return Err(Errno::EFAULT);
            }

            vpn.step();
        }

        Ok(0)
    }
    // 使用`MapArea`做检查, 而不是查页表
    // 要保证MapArea与页表的一致性, 也就是说, 页表中的映射都在MapArea中, MapArea中的映射都在页表中
    // 检查用户传进来的虚拟地址的合法性
    pub fn check_valid_user_vpn_range(
        &self,
        vpn_range: VPNRange,
        wanted_map_perm: MapPermission,
    ) -> SyscallRet {
        log::trace!("[check_valid_user_vpn_range]");
        let mut current_vpn = vpn_range.get_start();
        let end_vpn = vpn_range.get_end();

        while current_vpn < end_vpn {
            let mut found = false;

            for (_, area) in self.areas.iter() {
                if area.vpn_range.contains_vpn(current_vpn) {
                    if !area.map_perm.contains(wanted_map_perm) {
                        return Err(Errno::EACCES);
                    }
                    current_vpn = core::cmp::min(area.vpn_range.get_end(), end_vpn);
                    found = true;
                    break;
                }
            }

            if !found {
                log::error!(
                    "[check_valid_user_vpn_range] can't find area with vpn {:#x}",
                    current_vpn.0
                );
                // self.page_table.dump_all_user_mapping();
                return Err(Errno::EFAULT);
            }
        }
        Ok(0)
    }

    // 检查是否是COW或者lazy_allocation的区域
    // 逐页处理
    // used by `copy_to_user`, 不仅会检查, 还会提前处理, 避免实际写的时候发生page fault
    // 由调用者保证pte存在
    pub fn pre_handle_cow(&mut self, vpn_range: VPNRange) -> SyscallRet {
        let mut vpn = vpn_range.get_start();
        while vpn < vpn_range.get_end() {
            if let Some(pte) = self.page_table.find_pte(vpn) {
                if pte.is_cow() {
                    debug_assert!(!pte.is_shared());
                    log::warn!(
                        "[copy_to_user] pre handle cow page fault, vpn {:#x}, pte: {:#x?}",
                        vpn.0,
                        pte
                    );
                    if let Some((_, area)) = self.areas.range_mut(..=vpn).next_back() {
                        if area.vpn_range.contains_vpn(vpn) {
                            let data_frame = area.pages.get(&vpn).unwrap();
                            if Arc::strong_count(data_frame) == 1 {
                                log::warn!("[pre_handle_cow] arc strong count == 1");
                                let mut flags = pte.flags();
                                flags.remove(PTEFlags::COW);
                                flags.insert(PTEFlags::W);
                                #[cfg(target_arch = "loongarch64")]
                                flags.insert(PTEFlags::D);
                                *pte = PageTableEntry::new(pte.ppn(), flags);
                            } else {
                                log::warn!("arc strong count > 1");
                                let page = Page::new_framed(None);
                                let src_frame = pte.ppn().get_bytes_array();
                                let dst_frame = page.ppn().get_bytes_array();
                                log::warn!("dst_frame: {:#x}", page.ppn().0);
                                dst_frame.copy_from_slice(src_frame);
                                let mut flags = pte.flags();
                                flags.remove(PTEFlags::COW);
                                flags.insert(PTEFlags::W);
                                #[cfg(target_arch = "loongarch64")]
                                flags.insert(PTEFlags::D);
                                *pte = PageTableEntry::new(page.ppn(), flags);
                                area.pages.insert(vpn, Arc::new(page));
                            }
                            unsafe {
                                sfence_vma_vaddr(vpn.0 << PAGE_SIZE_BITS);
                            }
                        }
                    }
                }
            }
            // 继续处理下一页
            vpn.step();
        }
        return Ok(0);
    }
    /// 处理可恢复的缺页异常
    /// 1. Cow区域
    /// 2. lazy allocation区域(目前只有file backend mmap area是lazy allocation)
    #[no_mangle]
    pub fn handle_recoverable_page_fault(
        &mut self,
        va: VirtAddr,
        cause: PageFaultCause,
    ) -> Result<(), Errno> {
        log::trace!("[handle_recoverable_page_fault]");
        let vpn = va.floor();
        let page_table = &mut self.page_table;
        if let Some(pte) = page_table.find_pte(vpn) {
            if pte.is_cow() {
                log::error!(
                    "[handle_recoverable_page_fault] COW: {:#x}, pte: {:#x?}, tid: {:#x}",
                    va.0,
                    pte,
                    current_task().tid()
                );
                // 1. fork COW area
                // 如果refcnt == 1, 则直接修改pte, 否则, 分配新的frame, 修改pte, 更新MemorySet
                // debug!("handle cow page fault(cow), vpn {:#x}", vpn.0);
                if let Some((_, area)) = self.areas.range_mut(..=vpn).next_back() {
                    if area.vpn_range.contains_vpn(vpn) {
                        let data_frame = area.pages.get(&vpn).unwrap();
                        // 根据VPN找到对应的data_frame, 并查看Arc的引用计数
                        if Arc::strong_count(data_frame) == 1 {
                            // 直接修改pte
                            log::warn!("[handle_recoverable_page_fault] arc strong count == 1");
                            let mut flags = pte.flags();
                            flags.remove(PTEFlags::COW);
                            flags.insert(PTEFlags::W);
                            #[cfg(target_arch = "loongarch64")]
                            flags.insert(PTEFlags::D);
                            *pte = PageTableEntry::new(pte.ppn(), flags);
                        } else {
                            // 分配新的frame, 修改pte, 更新MemorySet
                            let page = Page::new_framed(None);
                            let src_frame = pte.ppn().get_bytes_array();
                            let dst_frame = page.ppn().get_bytes_array();
                            dst_frame.copy_from_slice(src_frame);
                            let mut flags = pte.flags();
                            flags.remove(PTEFlags::COW);
                            flags.insert(PTEFlags::W);
                            #[cfg(target_arch = "loongarch64")]
                            flags.insert(PTEFlags::D);
                            *pte = PageTableEntry::new(page.ppn(), flags);
                            area.pages.insert(vpn, Arc::new(page));
                        }
                        unsafe {
                            sfence_vma_vaddr(vpn.0 << PAGE_SIZE_BITS);
                        }
                        return Ok(());
                    }
                }
                log::info!("cow page fault recover failed");
                // EFAULT
                return Err(Errno::EFAULT);
                // COW_handle_END
            }
            // 页表中有对应的页表项, 但不是COW
            return Err(Errno::EFAULT);
        }
        self.handle_lazy_allocation_area(va, cause)
        // 页表中没有对应的页表项, 也不是lazy allocation, 返回错误
    }
}

/* System V shared mm */
impl MemorySet {
    // 将现有的的shm segment附加到当前进程的内存空间
    //  1. 如果页面已存在, 则映射
    //  2. 如果页面不存在, 则分配新的页面并映射
    // 返回值是映射的起始地址
    pub fn attach_shm_segment(
        &mut self,
        shmaddr: usize,
        map_perm: MapPermission,
        shm_segment: &mut ShmSegment,
    ) -> usize {
        let shm_size = shm_segment.id.size;
        let vpn_range = if shmaddr == 0 {
            // shmaddr == 0, 则由内核分配地址
            let old_mmap_start = self.mmap_start;
            self.mmap_start = self.mmap_start + shm_size;
            VPNRange::new(
                VirtAddr::from(old_mmap_start).floor(),
                VirtAddr::from(old_mmap_start + shm_size).ceil(),
            )
        } else {
            VPNRange::new(
                VirtAddr::from(shmaddr).floor(),
                VirtAddr::from(shmaddr + shm_size).ceil(),
            )
        };
        let mut map_area = MapArea::new(vpn_range, MapType::Framed, map_perm, None, 0);
        if shm_segment.pages.is_empty() {
            for vpn in vpn_range {
                let page = Arc::new(Page::new_framed(None));
                self.page_table.map(vpn, page.ppn(), map_perm.into());
                shm_segment.pages.push(Arc::downgrade(&page));
                map_area.pages.insert(vpn, page);
            }
        } else {
            debug_assert!(
                shm_segment.pages.len() == vpn_range.get_end().0 - vpn_range.get_start().0
            );
            for vpn in vpn_range {
                let page = shm_segment.pages[vpn.0 - vpn_range.get_start().0]
                    .upgrade()
                    .unwrap();
                self.page_table.map(vpn, page.ppn(), map_perm.into());
                map_area.pages.insert(vpn, page);
            }
        }
        self.areas.insert(vpn_range.get_start(), map_area);
        return vpn_range.get_start().0 * PAGE_SIZE;
    }
    pub fn detach_shm_segment(&mut self, shmaddr: usize) {
        let shm_start_vpn = VirtAddr::from(shmaddr).floor();
        self.remove_area_with_start_vpn(shm_start_vpn);
    }
}

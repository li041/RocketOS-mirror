use core::{fmt::Debug, iter::Map, mem};

use crate::{
    arch::{
        config::{MMAP_MIN_ADDR, PAGE_SIZE, PAGE_SIZE_BITS, USER_MAX_VA},
        mm::copy_to_user,
        trap::context::dump_trap_context,
    },
    fs::file::{File, OpenFlags},
    index_list::{IndexList, ListIndex},
    mm::{
        shm::{
            self, add_shm_segment, attach_shm_segment, check_shm_segment_exist, detach_shm_segment,
            stat_shm_segment, ShmAtFlags, ShmCtlOp, ShmGetFlags, ShmId, ShmSegment, IPC_PRIVATE,
        },
        MapArea, MapPermission, MapType, VPNRange, VirtAddr, VirtPageNum,
    },
    syscall::errno::Errno,
    task::current_task,
    utils::{ceil_to_page_size, floor_to_page_size},
};
use alloc::{string::String, vec::Vec};
use bitflags::bitflags;

use super::errno::SyscallRet;

/// 失败返回的是当前brk, 成功返回新的brk
/// 堆区域: [heap_bottom, brk)
pub fn sys_brk(brk: usize) -> SyscallRet {
    log::info!("sys_brk: brk: {:#x}", brk);
    let task = current_task();
    task.op_memory_set_mut(|memory_set| {
        // sbrk(0)是获取当前program brk(堆顶)
        if brk == 0 {
            return Ok(memory_set.brk);
        }
        let current_brk = memory_set.brk;
        let heap_bottom = memory_set.heap_bottom;
        // (start_vpn, end_vpn)是需要增/删的区间
        let start_vpn = VirtPageNum::from(floor_to_page_size(heap_bottom) >> PAGE_SIZE_BITS);
        let new_end_vpn = VirtPageNum::from(ceil_to_page_size(brk) >> PAGE_SIZE_BITS);
        if brk < heap_bottom {
            // brk小于堆底, 不合法
            log::error!("[sys_brk] brk {:#x} < heap_bottom {:#x}", brk, heap_bottom);
            return Ok(memory_set.brk);
        } else if brk > ceil_to_page_size(current_brk) {
            // 需要分配页
            if current_brk == heap_bottom {
                log::info!(
                    "[sys_brk] init heap space: {:#x} - {:#x}",
                    heap_bottom,
                    new_end_vpn.0 << PAGE_SIZE_BITS
                );
                let vpn_range = VPNRange::new(
                    VirtAddr::from(heap_bottom).floor(),
                    VirtAddr::from(new_end_vpn.0 << PAGE_SIZE_BITS).ceil(),
                );

                let heap_area = MapArea::new(
                    vpn_range,
                    MapType::Heap,
                    MapPermission::R | MapPermission::W | MapPermission::U,
                    None,
                    0,
                );
                memory_set.push_anoymous_area(heap_area);
            } else {
                // 扩展堆空间
                // 懒分配
                #[cfg(target_arch = "riscv64")]
                {
                    memory_set.remap_area_with_start_vpn(start_vpn, new_end_vpn);
                }
                #[cfg(target_arch = "loongarch64")]
                {
                    // loongarch需要检查[heap_bottom, brk)中间是否有其他映射
                    let heap_range = VPNRange::new(start_vpn, new_end_vpn);
                    // 找到最后一个空洞
                    let hole: Option<VPNRange> = memory_set
                        .areas
                        .range(..new_end_vpn)
                        .rev()
                        .find_map(|(_, area)| {
                            if area.vpn_range.is_intersect_with(&heap_range)
                                && area.map_type != MapType::Heap
                            {
                                Some(area.vpn_range.clone())
                            } else {
                                None
                            }
                        });
                    if let Some(hole) = hole {
                        // 如果有空洞, 则将空洞的结束VPN为堆区域开始VPN
                        let start_vpn = hole.get_end();
                        log::warn!("[sys_brk] found hole: {:?} for heap area", hole,);
                        log::info!(
                            "[sys_brk] remap area with start_vpn: {:#x}, new_end_vpn: {:#x}",
                            start_vpn.0,
                            new_end_vpn.0
                        );
                        if let Some(area) = memory_set.areas.get_mut(&start_vpn) {
                            // 调整原有堆区域, 懒分配
                            area.vpn_range.set_end(new_end_vpn);
                        } else {
                            // 插入新的堆区域, 懒分配
                            let heap_area = MapArea::new(
                                VPNRange::new(start_vpn, new_end_vpn),
                                MapType::Heap,
                                MapPermission::R | MapPermission::W | MapPermission::U,
                                None,
                                0,
                            );
                            memory_set.insert_map_area_lazily(heap_area);
                        }
                    } else {
                        // 如果没有空洞, 则直接将堆区域扩展到新的结束VPN
                        memory_set.remap_area_with_start_vpn(start_vpn, new_end_vpn);
                    }
                }
            }
        } else if brk < floor_to_page_size(current_brk) {
            // 需要释放页, 若start_vpn == new_end_vpn, 会将空间删除
            #[cfg(target_arch = "riscv64")]
            {
                memory_set.remap_area_with_start_vpn(start_vpn, new_end_vpn);
            }
            #[cfg(target_arch = "loongarch64")]
            {
                // loongarch需要检查[brk, current_brk)中间是否有其他映射
                let old_end_vpn =
                    VirtPageNum::from(ceil_to_page_size(current_brk) >> PAGE_SIZE_BITS);
                let remove_range = VPNRange::new(new_end_vpn, old_end_vpn);
                // 找出需要删除的堆区域
                let areas_to_remove: Vec<VirtPageNum> = memory_set
                    .areas
                    .range(..old_end_vpn)
                    .filter_map(|(_, area)| {
                        if area.vpn_range.is_intersect_with(&remove_range)
                            && area.map_type == MapType::Heap
                        {
                            // 删除堆区域
                            log::info!(
                                "[sys_brk] remove area: {:?} with vpn_range: {:?}",
                                area.map_type,
                                area.vpn_range
                            );
                            Some(area.vpn_range.get_start())
                        } else {
                            None
                        }
                    })
                    .collect();
                for start_vpn in areas_to_remove {
                    let mut area = memory_set.areas.remove(&start_vpn).expect("area not found");
                    log::warn!(
                        "[sys_brk] complete remove area: {:?} contains in {:?}  ",
                        area.vpn_range,
                        remove_range
                    );
                    // 如果完全覆盖, 则从memory_set中删除
                    if remove_range.is_contain(&area.vpn_range) {
                    } else {
                        // 如果部分覆盖, 则只删除部分, 注意看是覆盖前部分还是后一部分
                        log::warn!(
                            "[sys_brk] partial remove area: {:?} contains in {:?}  ",
                            area.vpn_range,
                            remove_range
                        );
                        if area.vpn_range.get_end() < remove_range.get_end() {
                            // 覆盖后部分
                            for vpn in
                                VPNRange::new(area.vpn_range.get_end(), remove_range.get_start())
                            {
                                area.dealloc_one_page(&mut memory_set.page_table, vpn);
                            }
                            area.vpn_range.set_end(remove_range.get_start());
                            memory_set.areas.insert(area.vpn_range.get_start(), area);
                        } else {
                            // 覆盖前部分
                            for vpn in
                                VPNRange::new(remove_range.get_start(), area.vpn_range.get_end())
                            {
                                area.dealloc_one_page(&mut memory_set.page_table, vpn);
                            }
                            area.vpn_range.set_start(remove_range.get_end());
                            memory_set.areas.insert(area.vpn_range.get_start(), area);
                        }
                    }
                }
            }
        } else {
            // brk在同一页, 不用alloc/dealloc页
            // 页内偏移
        }
        memory_set.brk = brk;
        Ok(brk)
    })
}

bitflags! {
    /// MMAP memeory protection
    /// 注意: PROT_WRITE不直接对应MapPermission的W, 因为对于私有文件映射
    #[derive(Debug)]
    pub struct MmapProt: u32 {
        /// Readable
        const PROT_READ = 0x1;
        /// Writeable
        const PROT_WRITE = 0x2;
        /// Executable
        const PROT_EXEC = 0x4;
    }
}

impl From<MmapProt> for MapPermission {
    /// 注意: 对于其他位prot不应该设置, 只设置R/W/X
    fn from(prot: MmapProt) -> Self {
        let mut map_permission = MapPermission::empty();
        if prot.contains(MmapProt::PROT_READ) {
            map_permission |= MapPermission::R;
        }
        if prot.contains(MmapProt::PROT_WRITE) {
            map_permission |= MapPermission::W;
        }
        if prot.contains(MmapProt::PROT_EXEC) {
            map_permission |= MapPermission::X;
        }
        map_permission
    }
}
bitflags! {
    /// determines whether updates to the mapping are visible to other processes mapping the same region, and whether
    /// updates are carried through to the underlying file.
    #[derive(Clone, Copy)]
    pub struct MmapFlags: u32 {
        /// MAP_SHARED
        const MAP_SHARED = 0x01;
        /// MAP_PRIVATE
        const MAP_PRIVATE = 0x02;
        /// MAP_SHARED_VALIDATE
        const MAP_SHARED_VALIDATE = 0x3;
        /// 以上两种只能选一
        /// MAP_FIXED, 一定要映射到addr, 不是作为hint, 要取消原来位置的映射
        const MAP_FIXED = 0x10;
        /// MAP_ANONYMOUS, 需要fd为-1, offset为0
        const MAP_ANONYMOUS = 0x20;
        /// Todo: 未实现
        const MAP_DENYWRITE = 0x800;
        // MAP_GROWSDOWN, 用于栈的映射, 允许向下增长
        const MAP_GROWSDOWN = 0x100;
        const MAP_NORESERVE = 0x4000;
        // MAP_POPULATE, 预先填充页表, 提高访问速度
        const MAP_POPULATE = 0x8000;
        const MAP_STACK = 0x20000;
        // 一定要映射到hint指向的地址, 如果指定地址范围已经有映射, 则会返回EEXIST, 而不是取消原来的映射
        const MAP_FIXED_NOREPLACE = 0x100000;
    }
}
impl Debug for MmapFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut flags = Vec::new();
        if self.contains(MmapFlags::MAP_SHARED) {
            flags.push("MAP_SHARED");
        }
        if self.contains(MmapFlags::MAP_PRIVATE) {
            flags.push("MAP_PRIVATE");
        }
        if self.contains(MmapFlags::MAP_FIXED) {
            flags.push("MAP_FIXED");
        }
        if self.contains(MmapFlags::MAP_ANONYMOUS) {
            flags.push("MAP_ANONYMOUS");
        }
        if self.contains(MmapFlags::MAP_DENYWRITE) {
            flags.push("MAP_DENYWRITE");
        }
        if self.contains(MmapFlags::MAP_POPULATE) {
            flags.push("MAP_POPULATE");
        }
        write!(f, "{:?}", flags)
    }
}
#[no_mangle]
pub fn sys_mmap(
    hint: usize,
    len: usize,
    prot: usize,
    flags: usize,
    fd: i32,
    offset: usize,
) -> SyscallRet {
    use crate::mm::{MapArea, MapType};

    log::error!(
        "sys_mmap: hint: {:#x}, len: {:#x}, prot: {:#x}, flags: {:#x}, fd: {:#x}, offset: {:#x}",
        hint,
        len,
        prot,
        flags,
        fd,
        offset
    );
    //处理参数
    let prot = MmapProt::from_bits(prot as u32).unwrap();
    let flags = match MmapFlags::from_bits(flags as u32) {
        Some(flags) => flags,
        None => {
            const MAP_SHARED_VALIDATE: usize = 0x3;
            if flags & MAP_SHARED_VALIDATE != 0 {
                return Err(Errno::EOPNOTSUPP);
            } else {
                return Err(Errno::EINVAL);
            }
        }
    };
    let task = current_task();
    // 判断参数合法性, 包括
    // 1. 映射长度不为0 2. MAP_FIXED时指定地址不能为0 3.文件映射时offset页对齐(非文件映射时offset应该为0) 4.既没有指定MAP_SHARED, 也没有MAP_PRIVATE
    if len == 0
        || (hint == 0 && flags.contains(MmapFlags::MAP_FIXED))
        || offset % PAGE_SIZE != 0
        || (!flags.contains(MmapFlags::MAP_SHARED) && !flags.contains(MmapFlags::MAP_PRIVATE))
    {
        return Err(Errno::EINVAL);
    }

    let mut map_perm: MapPermission = prot.into();
    if flags.contains(MmapFlags::MAP_DENYWRITE) {
        log::warn!("[sys_mmap] MAP_DENYWRITE not implemented");
    }
    // 加上U权限
    map_perm |= MapPermission::U;
    if flags.contains(MmapFlags::MAP_SHARED) {
        map_perm |= MapPermission::S;
    }

    // 强制映射到指定地址, 如果该地址范围已经有映射, 则会取消原来的映射, 如果不能在指定地址成功映射, mmap将会失败, 而不会选择其他地址
    if flags.contains(MmapFlags::MAP_FIXED) {
        if hint > USER_MAX_VA {
            // 如果hint大于用户最大虚拟地址, 则不允许映射
            log::error!(
                "[sys_mmap] hint {:#x} > USER_MAX_VA {:#x}",
                hint,
                USER_MAX_VA
            );
            return Err(Errno::EINVAL);
        }
        // 取消原有映射
        log::error!("[sys_mmap] MAP_FIXED: {:#x}", hint);
        task.op_memory_set_mut(|memory_set| {
            let start_vpn = VirtPageNum::from(hint >> PAGE_SIZE_BITS);
            let end_vpn = VirtPageNum::from(ceil_to_page_size(hint + len) >> PAGE_SIZE_BITS);
            let unmap_vpn_range = VPNRange::new(start_vpn, end_vpn);
            let found = memory_set.remove_area_with_overlap(unmap_vpn_range);
            if found == false {
                log::warn!("[sys_mmap] MAP_FIXED : {:#x} not found", hint);
            }
        });
    }

    if flags.contains(MmapFlags::MAP_FIXED_NOREPLACE) {
        // MAP_FIXED_NOREPLACE, 如果指定地址范围已经有映射, 则会失败
        log::error!("[sys_mmap] MAP_FIXED_NOREPLACE: {:#x}", hint);
        task.op_memory_set_mut(|memory_set| {
            let start_vpn = VirtPageNum::from(hint >> PAGE_SIZE_BITS);
            let end_vpn = VirtPageNum::from(ceil_to_page_size(hint + len) >> PAGE_SIZE_BITS);
            let vpn_range = VPNRange::new(start_vpn, end_vpn);
            if let Some((_vpn, area)) = memory_set.areas.range_mut(..end_vpn).next_back() {
                if area.vpn_range.is_intersect_with(&vpn_range) {
                    return Err(Errno::EEXIST);
                }
            }
            Ok(())
        })?;
    }

    if flags.contains(MmapFlags::MAP_ANONYMOUS) {
        // 匿名映射
        // 需要offset为0
        // Todo: 支持lazy_allocation
        if offset != 0 {
            return Err(Errno::EINVAL);
        }
        task.op_memory_set_mut(|memory_set| {
            let mut vpn_range = if flags.contains(MmapFlags::MAP_FIXED) {
                VPNRange::new(
                    VirtAddr::from(hint).floor(),
                    VirtAddr::from(hint + len).ceil(),
                )
            } else {
                memory_set.get_unmapped_area(len)
            };
            if map_perm.contains(MapPermission::S) {
                // 共享映射, 直接分配物理页
                memory_set.insert_framed_area(vpn_range, map_perm);
            } else {
                // 匿名私有映射懒分配
                if flags.contains(MmapFlags::MAP_GROWSDOWN) {
                    // 如果是栈的映射, 则需要将起始虚拟页号减1(保护页包含在vpn_range中, 以便于在访问保护页时, 通过懒分配向下增长)
                    vpn_range.set_start(VirtPageNum(vpn_range.get_start().0 - 1));
                    let mmap_area = MapArea::new(vpn_range, MapType::Stack, map_perm, None, 0);
                    memory_set.insert_map_area_lazily(mmap_area);
                } else {
                    // 懒分配
                    log::info!("[sys_mmap] lazy allocation for anonymous mapping");
                    let mmap_area = MapArea::new(vpn_range, MapType::Framed, map_perm, None, 0);
                    memory_set.insert_map_area_lazily(mmap_area);
                };
            }
            return Ok(vpn_range.get_start().0 << PAGE_SIZE_BITS);
        })
    } else {
        // 文件私有映射, 写时复制, 不会影响页缓存, 共享映射会影响页缓存, 并且可能会写回磁盘(`msync`)
        // 注意文件私有映射在发生写时复制前内容都是与页缓存一致的
        let file = match task.fd_table().get_file(fd as usize) {
            Some(f) => f,
            None => return Err(Errno::EBADF),
        };
        let open_flags = file.get_flags();
        if open_flags.contains(OpenFlags::O_WRONLY) {
            // 如果文件是只写打开的, 则不能进行映射
            return Err(Errno::EACCES);
        }
        // 权限检查
        if map_perm.contains(MapPermission::R) {
            if !file.readable() {
                log::error!("[sys_mmap] file not readable");
                return Err(Errno::EACCES);
            }
        }
        if map_perm.contains(MapPermission::W) {
            if open_flags.contains(OpenFlags::O_APPEND) {
                log::error!("[sys_mmap] file not writable");
                return Err(Errno::EACCES);
            }
        }
        if map_perm.contains(MapPermission::S)
            && map_perm.contains(MapPermission::W)
            && !open_flags.contains(OpenFlags::O_RDWR)
        {
            log::error!("[sys_mmap] file not opened with O_RDWR");
            return Err(Errno::EACCES);
        }

        task.op_memory_set_mut(|memory_set| {
            let vpn_range = if flags.contains(MmapFlags::MAP_FIXED)
                || flags.contains(MmapFlags::MAP_FIXED_NOREPLACE)
            {
                VPNRange::new(
                    VirtAddr::from(hint).floor(),
                    VirtAddr::from(hint + len).ceil(),
                )
            } else {
                memory_set.get_unmapped_area(len)
            };
            // 处理map_perm
            if map_perm.contains(MapPermission::W) && !map_perm.contains(MapPermission::S) {
                map_perm.remove(MapPermission::W);
                map_perm.insert(MapPermission::COW);
            }
            if flags.contains(MmapFlags::MAP_POPULATE) {
                memory_set.insert_framed_area(vpn_range, map_perm);
            } else {
                let mmap_area =
                    MapArea::new(vpn_range, MapType::Filebe, map_perm, Some(file), offset);
                memory_set.insert_map_area_lazily(mmap_area);
            }
            // memory_set.insert_framed_area(vpn_range, map_perm);
            log::error!(
                "[sys_mmap] file return {:#x}",
                vpn_range.get_start().0 << PAGE_SIZE_BITS
            );
            return Ok(vpn_range.get_start().0 << PAGE_SIZE_BITS);
        })
    }
}

pub fn sys_munmap(start: usize, len: usize) -> SyscallRet {
    // start必须页对齐, 且要大于等于MMAP_MIN_ADDR
    if start % PAGE_SIZE != 0 || len == 0 || start < MMAP_MIN_ADDR {
        return Err(Errno::EINVAL);
    }
    let start_vpn = VirtPageNum::from(start >> PAGE_SIZE_BITS);
    let end_vpn = VirtPageNum::from(ceil_to_page_size(start + len) >> PAGE_SIZE_BITS);
    log::error!(
        "sys_munmap: start: {:#x}, len: {:#x}, end: {:#x}, start_vpn: {:#x}, end_vpn: {:#x}, caller: {:?}",
        start,
        len,
        start + len,
        start_vpn.0,
        end_vpn.0,
        current_task().tid()
    );
    let unmap_vpn_range = VPNRange::new(start_vpn, end_vpn);
    let task = current_task();
    task.op_memory_set_mut(|memory_set| {
        if !memory_set.remove_area_with_overlap(unmap_vpn_range) {
            log::warn!("[sys_munmap] {:#x} not found", start);
            // memory_set.page_table.dump_all_user_mapping();
        }
    });
    Ok(0)
}

pub fn sys_mprotect(addr: usize, size: usize, prot: i32) -> SyscallRet {
    log::info!(
        "sys_mprotect: addr: {:#x}, size: {:#x}, prot: {:#x}",
        addr,
        size,
        prot
    );

    if addr % PAGE_SIZE != 0 || size == 0 {
        return Err(Errno::EINVAL);
    }

    let prot = MmapProt::from_bits(prot as u32).ok_or(Errno::EINVAL)?;
    let new_perm: MapPermission = prot.into();

    let start_vpn = VirtPageNum::from(addr >> PAGE_SIZE_BITS);
    let end_vpn = VirtPageNum::from(ceil_to_page_size(addr + size) >> PAGE_SIZE_BITS);
    let remap_range = VPNRange::new(start_vpn, end_vpn);

    current_task().op_memory_set_mut(|memory_set| {
        if !memory_set.remap_area_with_overlap(remap_range, new_perm) {
            log::warn!(
                "[sys_mprotect] no mapped area found for {:#x}-{:#x}",
                addr,
                addr + size
            );
            memory_set.page_table.dump_all_user_mapping();
            return Err(Errno::ENOMEM);
        }
        Ok(0)
    })
}

// pub fn sys_mprotect(addr: usize, size: usize, prot: i32) -> SyscallRet {
//     log::info!(
//         "sys_mprotect: addr: {:#x}, size: {:#x}, prot: {:#x}",
//         addr,
//         size,
//         prot
//     );

//     if addr % PAGE_SIZE != 0 {
//         return Err(Errno::EINVAL);
//     }

//     let prot = MmapProt::from_bits(prot as u32).ok_or(Errno::EINVAL)?;
//     let map_perm_from_prot: MapPermission = prot.into();
//     let remap_start_vpn = VirtPageNum::from(addr >> PAGE_SIZE_BITS);
//     let remap_end_vpn = VirtPageNum::from(ceil_to_page_size(addr + size) >> PAGE_SIZE_BITS);
//     let remap_range = VPNRange::new(remap_start_vpn, remap_end_vpn);

//     current_task().op_memory_set_mut(|memory_set| {
//         let mut remap_vpn = remap_range.get_start();
//         let mut new_areas = Vec::new();

//         while remap_vpn < remap_range.get_end() {
//             let Some((_, area)) = memory_set.areas.range_mut(..=remap_vpn).next_back() else {
//                 return Err(Errno::ENOMEM);
//             };

//             if !area.vpn_range.contains_vpn(remap_vpn) {
//                 return Err(Errno::ENOMEM);
//             }

//             let sub_start = remap_vpn;
//             let sub_end = remap_range.get_end().min(area.vpn_range.get_end());
//             let sub_range = VPNRange::new(sub_start, sub_end);

//             if sub_range == area.vpn_range {
//                 // 全部匹配，直接修改权限
//                 area.map_perm.update_rwx(map_perm_from_prot);
//                 area.remap(&mut memory_set.page_table);
//                 log::info!(
//                     "[sys_mprotect] map_perm from {:?} to {:?}, vpn_range: {:?}, remap_range: {:?}",
//                     area.map_perm,
//                     map_perm_from_prot,
//                     area.vpn_range,
//                     remap_range
//                 );
//             } else {
//                 log::info!(
//                     "[sys_mprotect] map_perm from {:?} to {:?}, vpn_range: {:?}, remap_range: {:?}",
//                     area.map_perm,
//                     map_perm_from_prot,
//                     area.vpn_range,
//                     remap_range
//                 );
//                 // 需要分割原区域
//                 let new_area = area.split_in3(sub_range.get_start(), sub_range.get_end());
//                 let offset = if area.backend_file.is_some() {
//                     area.offset
//                         + (sub_range.get_start().0 - area.vpn_range.get_start().0) * PAGE_SIZE
//                 } else {
//                     area.offset
//                 };
//                 let mut new_perm = area.map_perm;
//                 new_perm.update_rwx(map_perm_from_prot);
//                 let mut remap_area = MapArea::new(
//                     sub_range.clone(),
//                     area.map_type,
//                     new_perm,
//                     area.backend_file.clone(),
//                     offset,
//                 );
//                 area.pages.retain(|vpn, page| {
//                     if *vpn >= sub_range.get_start() && *vpn < sub_range.get_end() {
//                         remap_area.pages.insert(*vpn, page.clone());
//                         false
//                     } else {
//                         true
//                     }
//                 });
//                 remap_area.remap(&mut memory_set.page_table);
//                 new_areas.push((remap_area.vpn_range.get_start(), remap_area));
//                 new_areas.push((new_area.vpn_range.get_start(), new_area));
//             }

//             remap_vpn = sub_end;
//         }

//         memory_set.areas.extend(new_areas.into_iter());
//         Ok(0)
//     })
// }

pub fn sys_mremap(
    old_address: usize,
    old_size: usize,
    new_size: usize,
    flags: i32,
    new_address: usize,
) {
    log::info!(
        "sys_mremap: old_address: {:#x}, old_size: {:#x}, new_size: {:#x}, flags: {:#x}, new_address: {:#x}",
        old_address,
        old_size,
        new_size,
        flags,
        new_address
    );
    // old_address必须页对齐
    if old_address % PAGE_SIZE != 0 {
        return;
    }
}
// Todo:
pub fn sys_madvise(addr: usize, len: usize, advice: i32) -> SyscallRet {
    log::info!(
        "sys_madvise: addr: {:#x}, len: {:#x}, advice: {:#x}",
        addr,
        len,
        advice
    );
    log::warn!("[sys_madvise] Unimplemented");
    // addr必须页对齐
    if addr % PAGE_SIZE != 0 {
        return Err(Errno::EINVAL);
    }
    // Todo:
    Ok(0)
}

/* shm start */
pub fn sys_shmget(key: usize, size: usize, shmflg: i32) -> SyscallRet {
    let shmflg = ShmGetFlags::from_bits_truncate(shmflg);
    log::info!(
        "sys_shmget: key: {:#x}, size: {:#x}, shmflg: {:#x}",
        key,
        size,
        shmflg
    );
    let task = current_task();
    let page_aligned_size = ceil_to_page_size(size);
    if key == IPC_PRIVATE {
        // IPC_PRIVATE是一个特殊的key值, 用于创建一个新的共享内存段
        let shmid = add_shm_segment(page_aligned_size, task.tgid(), None);
        return Ok(shmid);
    }
    // 其他key值, 需要检查是否存在
    let shmid = check_shm_segment_exist(key, page_aligned_size, &shmflg)?;
    if shmid == 0 {
        if shmflg.contains(ShmGetFlags::IPC_CREAT) {
            // 创建新的共享内存段, 同时指定了key(已检查key不存在)
            ShmSegment::new(page_aligned_size, task.tgid());
            let shmid = add_shm_segment(page_aligned_size, task.tgid(), Some(key));
            debug_assert!(shmid == key);
            return Ok(shmid);
        } else {
            // 不存在, 且不创建
            return Err(Errno::ENOENT);
        }
    }
    // 存在, 返回shmid
    Ok(shmid)
}

pub fn sys_shmat(shmid: usize, shmaddr: usize, shmflg: i32) -> SyscallRet {
    let shmflg = ShmAtFlags::from_bits_truncate(shmflg);
    log::info!(
        "sys_shmat: shmid: {:#x}, shmaddr: {:#x}, shmflg: {:#x}",
        shmid,
        shmaddr,
        shmflg
    );
    if shmaddr % PAGE_SIZE != 0 && !shmflg.contains(ShmAtFlags::SHM_RND) {
        return Err(Errno::EINVAL);
    }
    let aligned_shmaddr = floor_to_page_size(shmaddr);
    attach_shm_segment(shmid, aligned_shmaddr, &shmflg)
}

pub fn sys_shmdt(shmaddr: usize) -> SyscallRet {
    log::info!("sys_shmdt: shmaddr: {:#x}", shmaddr);
    if shmaddr % PAGE_SIZE != 0 {
        return Err(Errno::EINVAL);
    }
    detach_shm_segment(shmaddr)
}

pub fn sys_shmctl(shmid: usize, op: i32, buf: *mut ShmId) -> SyscallRet {
    let shmctl_op = ShmCtlOp::from(op);
    log::info!(
        "sys_shmctl: shmid: {:#x}, op: {:?}, buf: {:#x}",
        shmid,
        shmctl_op,
        buf as usize
    );
    match shmctl_op {
        ShmCtlOp::IPC_STAT => {
            // 读取共享内存段信息
            stat_shm_segment(shmid, buf)
        }
        ShmCtlOp::IPC_RMID => {
            // Todo: 标记删除共享内存段
            return Ok(0);
        }
        _ => {
            log::warn!("[sys_shmctl] Unimplemented");
            return Err(Errno::EINVAL);
        }
    }
}

/* shm end */
pub fn sys_membarrier(_cmd: i32, _flags: i32, _cpu_id: u32) -> SyscallRet {
    log::error!("Unimplemented sys_membarrier");
    Ok(0)
}

pub fn sys_get_mempolicy(
    _policy: usize,
    _nodemask: usize,
    _maxnode: usize,
    _addr: usize,
    _flags: usize,
) -> SyscallRet {
    log::error!("Unimplemented sys_get_mempolicy");
    Ok(0)
}

pub fn sys_mlock(_addr: usize, _len: usize) -> SyscallRet {
    log::error!("Unimplemented sys_mlock");
    Ok(0)
}

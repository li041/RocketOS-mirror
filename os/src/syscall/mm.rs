use core::fmt::Debug;

use crate::{
    arch::{
        config::{MMAP_MIN_ADDR, PAGE_SIZE, PAGE_SIZE_BITS},
        mm::copy_to_user,
    },
    fs::file::File,
    index_list::{IndexList, ListIndex},
    mm::{MapArea, MapPermission, VPNRange, VirtAddr, VirtPageNum},
    syscall::errno::Errno,
    task::current_task,
    utils::{ceil_to_page_size, floor_to_page_size},
};
use alloc::{string::String, vec::Vec};
use bitflags::bitflags;

use super::errno::SyscallRet;

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
        let start_vpn = VirtPageNum::from(ceil_to_page_size(current_brk) >> PAGE_SIZE_BITS);
        let new_end_vpn = VirtPageNum::from(ceil_to_page_size(brk) >> PAGE_SIZE_BITS);
        if brk < heap_bottom {
            // brk小于堆底, 不合法
            log::error!("[sys_brk] brk {:#x} < heap_bottom {:#x}", brk, heap_bottom);
            return Err(Errno::EINVAL);
        } else if brk > ceil_to_page_size(current_brk) {
            // 需要分配页
            if current_brk == heap_bottom {
                // 初始分配堆空间
                log::info!(
                    "[sys_brk] init heap space: {:#x} - {:#x}",
                    heap_bottom,
                    new_end_vpn.0 << PAGE_SIZE_BITS
                );
                let vpn_range = VPNRange::new(
                    VirtAddr::from(heap_bottom).floor(),
                    VirtAddr::from(new_end_vpn.0 << PAGE_SIZE_BITS).ceil(),
                );
                memory_set.insert_framed_area(
                    vpn_range,
                    MapPermission::R | MapPermission::W | MapPermission::U,
                );
            } else {
                memory_set.remap_area_with_start_vpn(start_vpn, new_end_vpn);
            }
        } else if brk < floor_to_page_size(current_brk) {
            // 需要释放页, 若start_vpn == new_end_vpn, 会将空间删除
            memory_set.remap_area_with_start_vpn(start_vpn, new_end_vpn);
        } else {
            // brk在同一页, 不用alloc/dealloc页
            // 页内偏移
        }
        memory_set.brk = brk;
        Ok(0)
    })
}

bitflags! {
    /// MMAP memeory protection
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
        /// 以上两种只能选一
        /// MAP_FIXED, 一定要映射到addr, 不是作为hint, 要取消原来位置的映射
        const MAP_FIXED = 0x10;
        /// MAP_ANONYMOUS, 需要fd为-1, offset为0
        const MAP_ANONYMOUS = 0x20;
        /// 拒绝对映射区的写入操作
        /// Todo: 未实现
        const MAP_DENYWRITE = 0x800;
        const MAP_POPULATE = 0x8000;
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

// Todo: 别用unwarp
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
    let flags = MmapFlags::from_bits(flags as u32).unwrap();
    let task = current_task();
    // 判断参数合法性, 包括
    // 1. 映射长度不为0 2. MAP_FIXED时指定地址不能为0 3.文件映射时offset页对齐(非文件映射时offset应该为0) 4.同时指定MAP_SHARED和MAP_PRIVATE
    if len == 0
        || (hint == 0 && flags.contains(MmapFlags::MAP_FIXED))
        || offset % PAGE_SIZE != 0
        || (flags.contains(MmapFlags::MAP_SHARED) && flags.contains(MmapFlags::MAP_PRIVATE))
    {
        return Err(Errno::EINVAL);
    }

    let mut map_perm: MapPermission = prot.into();
    // 加上U权限
    map_perm |= MapPermission::U;
    if flags.contains(MmapFlags::MAP_SHARED) {
        map_perm |= MapPermission::S;
    }

    // 强制映射到指定地址, 如果该地址范围已经有映射, 则会取消原来的映射, 如果不能在指定地址成功映射, mmap将会失败, 而不会选择其他地址
    if flags.contains(MmapFlags::MAP_FIXED) {
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

    if flags.contains(MmapFlags::MAP_ANONYMOUS) {
        // 匿名映射
        // 需要fd为-1, offset为0
        // Todo: 支持lazy_allocation
        if fd != -1 || offset != 0 {
            return Err(Errno::EINVAL);
        }
        task.op_memory_set_mut(|memory_set| {
            let vpn_range = if flags.contains(MmapFlags::MAP_FIXED) {
                VPNRange::new(
                    VirtAddr::from(hint).floor(),
                    VirtAddr::from(hint + len).ceil(),
                )
            } else {
                memory_set.get_unmapped_area(len)
            };
            memory_set.insert_framed_area(vpn_range, map_perm);
            // Debug
            log::error!(
                "[sys_mmap] anonymous return {:#x}",
                vpn_range.get_start().0 << PAGE_SIZE_BITS
            );
            return Ok(vpn_range.get_start().0 << PAGE_SIZE_BITS);
        })
    } else {
        // 文件私有映射, 写时复制, 不会影响页缓存, 共享映射会影响页缓存, 并且可能会写回磁盘(`msync`)
        // 注意文件私有映射在发生写时复制前内容都是与页缓存一致的
        let file = task.fd_table().get_file(fd as usize).unwrap();
        task.op_memory_set_mut(|memory_set| {
            let vpn_range = if flags.contains(MmapFlags::MAP_FIXED) {
                VPNRange::new(
                    VirtAddr::from(hint).floor(),
                    VirtAddr::from(hint + len).ceil(),
                )
            } else {
                memory_set.get_unmapped_area(len)
            };
            let mmap_area = MapArea::new(vpn_range, MapType::Filebe, map_perm, Some(file), offset);
            memory_set.insert_filebe_area_lazily(mmap_area);
            log::error!(
                "[sys_mmap] file return {:#x}",
                vpn_range.get_start().0 << PAGE_SIZE_BITS
            );
            return Ok(vpn_range.get_start().0 << PAGE_SIZE_BITS);
        })
    }
}

// Todo: 目前只支持取消文件映射, 需要支持匿名映射
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
            memory_set.page_table.dump_all_user_mapping();
        }
    });
    Ok(0)
}

///
// pub fn sys_mprotect(addr: usize, size: usize, prot: i32) -> SyscallRet {
//     log::info!(
//         "sys_mprotect: addr: {:#x}, size: {:#x}, prot: {:#x}",
//         addr,
//         size,
//         prot
//     );
//     // addr必须页对齐
//     if addr % PAGE_SIZE != 0 {
//         return Err(Errno::EINVAL);
//     }
//     let prot = MmapProt::from_bits(prot as u32).unwrap();
//     let map_perm_from_prot: MapPermission = prot.into();
//     let remap_start_vpn = VirtPageNum::from(addr >> PAGE_SIZE_BITS);
//     let remap_end_vpn = VirtPageNum::from(ceil_to_page_size(addr + size) >> PAGE_SIZE_BITS);
//     let remap_range = VPNRange::new(remap_start_vpn, remap_end_vpn);
//     let found = current_task().op_memory_set_mut(|memory_set| {
//         // 分裂可能产生新的映射区, 需要先保存, 然后再加入memory_set.areas
//         let mut split_areas = Vec::new();
//         // 先查找指定地址范是否有映射, 如果没有则返回-1, 设置ENOMEM
//         if let Some((_, area)) = memory_set
//             .areas
//             .range_mut(..=remap_range.get_start())
//             .next_back()
//         {
//             if area.vpn_range.contains_vpn(remap_start_vpn) {
//                 if area.vpn_range == remap_range {
//                     log::error!(
//                     "[sys_mprotect] map_perm from {:?} to {:?}, vpn_range: {:?}, remap_range: {:?}",
//                     area.map_perm,
//                     map_perm_from_prot,
//                     area.vpn_range,
//                     remap_range
//                 );
//                     // 对于已经映射的区域, 需要将其权限修改为新的权限(remap)
//                     area.map_perm.update_rwx(map_perm_from_prot);
//                     area.remap(&mut memory_set.page_table);
//                 } else {
//                     // 需要分割
//                     log::error!(
//                     "[sys_mprotect] map_perm from {:?} to {:?}, vpn_range: {:?}, remap_range: {:?}",
//                     area.map_perm,
//                     map_perm_from_prot,
//                     area.vpn_range,
//                     remap_range
//                     );
//                     // remap_map_perm根据area.map_perm和map_perm_from_prot计算出新的权限, 只修改R, W, X
//                     let new_area = area.split_in(remap_range.get_start(), remap_range.get_end());
//                     split_areas.push(new_area);
//                     let offset = if area.backend_file.is_some() {
//                         area.offset
//                             + (remap_range.get_start().0 - area.vpn_range.get_start().0) * PAGE_SIZE
//                     } else {
//                         area.offset
//                     };
//                     let mut remap_map_perm = area.map_perm;
//                     remap_map_perm.update_rwx(map_perm_from_prot);
//                     let mut remap_area = MapArea::new(
//                         remap_range,
//                         area.map_type,
//                         remap_map_perm,
//                         area.backend_file.clone(),
//                         offset,
//                     );
//                     // 划分页
//                     area.pages.retain(|vpn, page| {
//                         if *vpn >= remap_start_vpn && *vpn < remap_end_vpn {
//                             remap_area.pages.insert(*vpn, page.clone());
//                             false
//                         } else {
//                             true
//                         }
//                     });
//                     // 重新映射
//                     remap_area.remap(&mut memory_set.page_table);
//                     // 加入新的映射区
//                     split_areas.push(remap_area);
//                 }

//                 // 把split_areas加入到memory_set.areas中
//                 memory_set.areas.extend(
//                     split_areas
//                         .into_iter()
//                         .map(|area| (area.vpn_range.get_start(), area)),
//                 );
//                 return Ok(0);
//             }
//             // 没有找到指定地址范围的映射
//             return Err(Errno::ENOMEM);
//         }
//         // 没有找到指定地址范围的映射
//         return Err(Errno::ENOMEM);
//     });
//     found
// }

pub fn sys_mprotect(addr: usize, size: usize, prot: i32) -> SyscallRet {
    log::info!(
        "sys_mprotect: addr: {:#x}, size: {:#x}, prot: {:#x}",
        addr,
        size,
        prot
    );

    if addr % PAGE_SIZE != 0 {
        return Err(Errno::EINVAL);
    }

    let prot = MmapProt::from_bits(prot as u32).ok_or(Errno::EINVAL)?;
    let map_perm_from_prot: MapPermission = prot.into();
    let remap_start_vpn = VirtPageNum::from(addr >> PAGE_SIZE_BITS);
    let remap_end_vpn = VirtPageNum::from(ceil_to_page_size(addr + size) >> PAGE_SIZE_BITS);
    let remap_range = VPNRange::new(remap_start_vpn, remap_end_vpn);

    current_task().op_memory_set_mut(|memory_set| {
        let mut remap_vpn = remap_range.get_start();
        let mut new_areas = Vec::new();

        while remap_vpn < remap_range.get_end() {
            let Some((_, area)) = memory_set.areas.range_mut(..=remap_vpn).next_back() else {
                return Err(Errno::ENOMEM);
            };

            if !area.vpn_range.contains_vpn(remap_vpn) {
                return Err(Errno::ENOMEM);
            }

            let sub_start = remap_vpn;
            let sub_end = remap_range.get_end().min(area.vpn_range.get_end());
            let sub_range = VPNRange::new(sub_start, sub_end);

            if sub_range == area.vpn_range {
                // 全部匹配，直接修改权限
                area.map_perm.update_rwx(map_perm_from_prot);
                area.remap(&mut memory_set.page_table);
                log::info!(
                    "[sys_mprotect] map_perm from {:?} to {:?}, vpn_range: {:?}, remap_range: {:?}",
                    area.map_perm,
                    map_perm_from_prot,
                    area.vpn_range,
                    remap_range
                );
            } else {
                log::info!(
                    "[sys_mprotect] map_perm from {:?} to {:?}, vpn_range: {:?}, remap_range: {:?}",
                    area.map_perm,
                    map_perm_from_prot,
                    area.vpn_range,
                    remap_range
                );
                // 需要分割原区域
                let new_area = area.split_in(sub_range.get_start(), sub_range.get_end());
                let offset = if area.backend_file.is_some() {
                    area.offset
                        + (sub_range.get_start().0 - area.vpn_range.get_start().0) * PAGE_SIZE
                } else {
                    area.offset
                };
                let mut new_perm = area.map_perm;
                new_perm.update_rwx(map_perm_from_prot);
                let mut remap_area = MapArea::new(
                    sub_range.clone(),
                    area.map_type,
                    new_perm,
                    area.backend_file.clone(),
                    offset,
                );
                area.pages.retain(|vpn, page| {
                    if *vpn >= sub_range.get_start() && *vpn < sub_range.get_end() {
                        remap_area.pages.insert(*vpn, page.clone());
                        false
                    } else {
                        true
                    }
                });
                remap_area.remap(&mut memory_set.page_table);
                new_areas.push((remap_area.vpn_range.get_start(), remap_area));
                new_areas.push((new_area.vpn_range.get_start(), new_area));
            }

            remap_vpn = sub_end;
        }

        memory_set.areas.extend(new_areas.into_iter());
        Ok(0)
    })
}

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

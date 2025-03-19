use alloc::sync::Arc;

use crate::task::current_task;

use super::{
    frame_allocator::frame_alloc,
    page_table::{PTEFlags, PageTable, PageTableEntry},
    PhysPageNum, VirtAddr, VirtPageNum,
};

// Todo: 增加错误处理
pub const EFAULT: isize = -14;

/// call this function only when scause.cause() == Exception::LoadPageFault || Exception::StorePageFault
/// 1. fork COW area
/// 2. lazy allocation
pub fn handle_recoverable_page_fault(page_table: &PageTable, va: VirtAddr) -> Result<(), isize> {
    // log::error!("handle_recoverable_page_fault: va {:#x}", va.0);
    let vpn = va.floor();
    if let Some(pte) = page_table.find_pte(vpn) {
        if vpn == VirtPageNum::from(0) {
            // // alloc for thread local variable
            // // TODO: temp alloc physical page for vpn: ppn = 0: 0
            // let frame = frame_alloc().unwrap();
            // let ppn = frame.ppn;
            // // let flags = PTEFlags::V | PTEFlags::U | PTEFlags::W | PTEFlags::R;
            // let flags =
            //     PTEFlags::V | PTEFlags::U | PTEFlags::W | PTEFlags::R | PTEFlags::A | PTEFlags::D;
            // *pte = PageTableEntry::new(ppn, flags);
            // return Ok(());
            panic!("handle_recoverable_page_fault: vpn == 0");
        }
        if pte.is_cow() {
            // 1. fork COW area
            // 如果refcnt == 1, 则直接修改pte, 否则, 分配新的frame, 修改pte, 更新MemorySet
            // debug!("handle cow page fault(cow), vpn {:#x}", vpn.0);
            let task = current_task();
            // let memory_set = &mut task.inner_lock().memory_set;
            let memory_set = task.memory_set();
            let areas = &mut memory_set.lock().areas;
            // debug!("get current task");
            // rev是因为一般来说, COW区域都是后续创建的(如mmap)
            let mut index = areas.last_index();
            while index.is_some() {
                let area = areas.get_mut(index).unwrap();
                if area.vpn_range.contains_vpn(vpn) {
                    // 根据VPN找到对应的data_frame, 并查看Arc的引用计数
                    let data_frame = area.data_frames.get(&vpn).unwrap();
                    if Arc::strong_count(data_frame) == 1 {
                        // 直接修改pte
                        // clear COW bit and set valid bit
                        // debug!("ref_cnt = 1");
                        let mut flags = pte.flags();
                        flags.remove(PTEFlags::COW);
                        flags.insert(PTEFlags::W);
                        *pte = PageTableEntry::new(pte.ppn(), flags);
                    } else {
                        // 分配新的frame, 修改pte, 更新MemorySet
                        let frame = frame_alloc().unwrap();
                        let src_frame = pte.ppn().get_bytes_array();
                        let dst_frame = frame.ppn.get_bytes_array();
                        dst_frame.copy_from_slice(src_frame);
                        // clear COW bit and set valid bit, update pte
                        let mut flags = pte.flags();
                        flags.remove(PTEFlags::COW);
                        flags.insert(PTEFlags::W);
                        *pte = PageTableEntry::new(frame.ppn, flags);
                        // update MemorySet -> MapArea -> data_frames
                        area.data_frames.insert(vpn, Arc::new(frame));
                    }
                    unsafe {
                        // core::arch::asm!(
                        //     "sfence.vma x0, x0",
                        //     options(nomem, nostack, preserves_flags)
                        // );
                        core::arch::asm!("sfence.vma {addr}, x0", addr = in(reg) va.0, options(nomem, nostack, preserves_flags));
                    }
                    return Ok(());
                }
                index = areas.prev_index(index);
            }
            log::info!("cow page fault recover failed");
            // EFAULT
            return Err(EFAULT);
            // COW_handle_END
        } else {
            // lazy allocation: mmap region
            log::debug!(
                "[handle_lazy_allocation_page_fault] lazy alloc, vpn: {:#x}",
                vpn.0
            );
            if pte.ppn() == PhysPageNum::from(0) {
                //info!("handle mmap anonamous areas");
                let task = current_task();
                let memory_set = &mut task.memory_set();
                let areas = &mut memory_set.lock().areas;
                // 分配物理页帧, 更新页表, 管理MapArea::data_frames
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
                        return Ok(());
                    }
                    index = areas.prev_index(index);
                }
            }
            log::info!("lazy allocation fault recover failed");
            return Err(EFAULT);
        }
    } else {
        log::error!("page fault but can't find valid pte");
        return Err(EFAULT);
    }
}

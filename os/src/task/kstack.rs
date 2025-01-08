//! 用户的内核栈分配
use crate::config::PAGE_SIZE;
use crate::mm::MapPermission;
use crate::mm::KERNEL_SPACE;

use super::id::kid_alloc;

pub const KSTACK_TOP: usize = 0xffff_ffff_ffff_f000;
pub const KSTACK_SIZE: usize = (PAGE_SIZE << 4) - PAGE_SIZE;
/// 内核栈的底部, 注意每个内核栈下面还有一个页用于保护

// usize记录用户内核栈的sp
pub struct KernelStack(pub usize);

// Todo: 实现懒分配
// 当使用kstack_alloc时, 会给对应页加入映射, 返回栈顶指针
pub fn kstack_alloc() -> usize {
    let kstack_id = kid_alloc();
    let kstack_top = KSTACK_TOP - kstack_id * (KSTACK_SIZE + PAGE_SIZE);
    let kstack_bottom = kstack_top - KSTACK_SIZE;
    log::error!(
        "kstack_top: {:#x}, kstack_bottom: {:#x}",
        kstack_top,
        kstack_bottom
    );

    KERNEL_SPACE.lock().insert_framed_area_va(
        kstack_bottom.into(),
        kstack_top.into(),
        MapPermission::R | MapPermission::W,
    );
    kstack_top
}

// drop KernelStack时, 取消相应内核栈的映射
impl Drop for KernelStack {
    fn drop(&mut self) {
        // let kstack_top = KSTACK_TOP - self.0 * (KSTACK_SIZE + PAGE_SIZE);
        let kstack_top = get_stack_top_by_sp(self.0);
        let kstack_bottom = kstack_top - KSTACK_SIZE;
        KERNEL_SPACE
            .lock()
            .remove_area_with_start_vpn(kstack_bottom.into());
    }
}

pub fn get_kstack_id(kstack_top: usize) -> usize {
    (KSTACK_TOP - kstack_top) / (KSTACK_SIZE + PAGE_SIZE)
}

pub fn get_stack_top_by_sp(sp: usize) -> usize {
    let kstack_id = get_kstack_id(sp);
    let kstack_top = KSTACK_TOP - kstack_id * (KSTACK_SIZE + PAGE_SIZE);
    kstack_top
}

// pub fn check_init_task_kstack_overflow(stval: usize) {
//     if stval == 0 {
//         return;
//     }
//     let kstack_top = KSTACK_TOP;
//     let kstack_bottom = kstack_top - KSTACK_SIZE;
//     if stval < kstack_bottom {
//         panic!("Kernel stack overflow!");
//     }
// }

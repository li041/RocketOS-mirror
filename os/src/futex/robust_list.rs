use crate::{
    arch::mm::{copy_from_user, copy_to_user},
    syscall::errno::{Errno, SyscallRet},
    task::{current_task, get_task},
};

use super::{flags::FLAGS_SHARED, futex::futex_wake};

// futex word构成:
// 31: FUTEX_WAITERS
// 30: FUTEX_OWNER_DIED
// 29: FUTEX_TID

const ROBUST_LIST_LIMIT: usize = 2048;
// 判断该futex上是否有等待的线程
const FUTEX_WAITERS: u32 = 0x80000000;
// 持有该futex的线程已经死亡
const FUTEX_OWNER_DIED: u32 = 0x40000000;
// 持有该futex的线程的tid
const FUTEX_TID_MASK: u32 = 0x3fffffff;

#[repr(C)]
pub struct RobustList {
    next: *mut RobustList,
    // futex字 位于内存中相对于 RobustListHead->futex_offset 的偏移
    // futex_addr = (void *)self + futex_offset
}

#[repr(C)]
#[derive(Copy, Clone)]
/// Todo: 在退出时需要遍历这个链表
pub struct RobustListHead {
    list: *mut RobustList,
    futex_offset: u64,
    list_op_pending: *mut RobustList,
}

impl Default for RobustListHead {
    fn default() -> Self {
        Self {
            list: core::ptr::null_mut(),
            futex_offset: 0,
            list_op_pending: core::ptr::null_mut(),
        }
    }
}

pub fn sys_set_robust_list(head: usize, len: usize) -> SyscallRet {
    if len != core::mem::size_of::<RobustListHead>() {
        return Err(Errno::EINVAL);
    }
    current_task().set_robust_list_head(head);
    Ok(0)
}

pub fn sys_get_robust_list(pid: usize, head_ptr: usize, len_ptr: usize) -> SyscallRet {
    let task = if pid == 0 {
        // 如果pid=0, 则获取当前任务的robust_list
        current_task()
    } else {
        // 否则获取pid对应的任务的robust_list
        match get_task(pid) {
            Some(task) => task,
            None => return Err(Errno::ESRCH),
        }
    };
    // 检查权限
    current_task().compare_permision(&task)?;
    let robust_list_head = task.robust_list_head();
    copy_to_user(head_ptr as *mut usize, &robust_list_head as *const usize, 1)?;
    copy_to_user(
        len_ptr as *mut usize,
        &core::mem::size_of::<RobustListHead>() as *const usize,
        1,
    )?;
    Ok(0)
}

pub fn exit_robust_list() -> Result<(), Errno> {
    let task = current_task();
    let tid = task.tid();
    let head_addr = task.robust_list_head();
    if head_addr != 0 {
        // 释放robust_list
        let mut head: RobustListHead = RobustListHead::default();
        copy_from_user(
            head_addr as *const RobustListHead,
            &mut head as *mut RobustListHead,
            1,
        )?;
        let mut count = 0;
        let mut entry = head.list;
        while !entry.is_null() && (entry as usize != head_addr) && count < ROBUST_LIST_LIMIT {
            handle_futex_death(entry, head.futex_offset, tid as u32);
            entry = unsafe { (*entry).next };
            count += 1;
        }
    }
    return Ok(());
}

fn handle_futex_death(node: *mut RobustList, offset: u64, tid: u32) {
    let futex_addr = (node as usize).wrapping_add(offset as usize) as *mut u32;

    let mut futex_word: u32 = 0;
    copy_from_user(futex_addr, &mut futex_word as *mut u32, 1);

    // 判断futex是否真被当前进程持有
    if (futex_word & FUTEX_TID_MASK) == tid {
        // 设置`OWNER_DIED`
        let new_val = (futex_word & FUTEX_TID_MASK) | FUTEX_OWNER_DIED;
        let _ = copy_to_user(futex_addr, &new_val, 1);
        if futex_word & FUTEX_WAITERS != 0 {
            // 如果有在futex上等待的线程, 唤醒
            let _ = futex_wake(futex_addr as usize, FLAGS_SHARED, 1);
        }
    }
}

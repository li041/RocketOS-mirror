//! 实现与futex相关的系统调用
/*
use axhal::mem::VirtAddr;
use axlog::info;
use core::time::Duration;
use crate::{current_process, current_thread_uncheck, signal::current_have_signals, yield_now_task};
use axfutex::{flags::FLAGS_SHARED, futex::{FutexKey, FutexQ}, queues::{futex_hash, FUTEXQUEUES}};
*/

extern crate alloc;

use core::time::Duration;

use super::{flags::*, queue::FUTEXQUEUES};
use crate::{
    arch::{config::PAGE_SIZE_BITS, mm::copy_from_user, timer::TimeSpec},
    futex::queue::futex_hash,
    syscall::errno::{Errno, SyscallRet},
    task::{current_task, dump_scheduler, yield_current_task, Task},
};
use alloc::{sync::Arc, sync::Weak};

pub(crate) type Futex = u32;

use crate::mm::VirtAddr;
/// Kernel futex
pub struct FutexQ {
    /// The `val` of the futex
    /// the task in the queue waiting for the same futex may have different `val`
    pub key: FutexKey,
    /// the task which is waiting for the futex
    pub task: Weak<Task>,
    /// the bitset of the futex
    pub bitset: u32,
}

impl FutexQ {
    /// Create a new futex queue
    pub fn new(key: FutexKey, task: Arc<Task>, bitset: u32) -> Self {
        Self {
            key,
            task: Arc::downgrade(&task),
            bitset,
        }
    }
    /// check if the futex queues matches the key
    pub fn match_key(&self, key: &FutexKey) -> bool {
        self.key == *key
    }
}

pub struct SharedMappingInfo {
    pub inode_addr: u64, // inode的地址
    pub page_index: u64, // 页偏移
    pub offset: u32,     // 页内偏移
}

// pub enum FutexKey {
//     /// private futex
//     Private {
//         mmset_addr: u64, // 唯一标识虚拟地址空间
//         aligned: u64,    // futex在用户空间的虚拟地址, 对齐到页
//         offset: u32,     // 页内偏移, 在页内的偏移
//     },
//     /// shared futex
//     Shared {
//         inode_addr: u64, // 这里不直接使用inode_num, 是因为inode被删除后系统会回收inode_num并重新使用, 会导致旧引用错误匹配
//         page_index: u64, // 页偏移, futex在文件映射中的位置
//         offset: u32,     // 在页中的偏移
//     },
// }

// 统一结构体, 实际各字段语义参考上面enum FutexKey
#[derive(Copy, Clone, Default, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct FutexKey {
    pub(crate) ptr: u64,     // 可以是inode指针或mm指针, 用于统一表示
    pub(crate) aligned: u64, // 对齐到页的地址
    pub(crate) offset: u32,  // 页偏移, 在页内的偏移
}

impl FutexKey {
    pub fn new(ptr: u64, aligned: u64, offset: u32) -> Self {
        Self {
            ptr,
            aligned,
            offset,
        }
    }
}

#[derive(Default)]
/// 用于存储 robust list 的结构
pub struct FutexRobustList {
    /// The location of the head of the robust list in user space
    pub head: usize,
    /// The length of the robust list
    pub len: usize,
}

impl FutexRobustList {
    /// Create a new robust list
    pub fn new(head: usize, len: usize) -> Self {
        Self { head, len }
    }
}

// pub fn futex_get_value_locked(vaddr: VirtAddr) -> SyscallRet {
//     let uaddr: usize = vaddr.into();
//     let real_futex_val: u32 = unsafe { (uaddr as *const u32).read_volatile() };
//     Ok(real_futex_val as usize)
// }

pub fn futex_get_value_locked(uaddr: *const Futex) -> Result<Futex, Errno> {
    let mut val: Futex = 0;
    match copy_from_user(uaddr, &mut val as *mut Futex, 1) {
        Ok(_) => Ok(val),
        Err(_) => Err(Errno::EFAULT),
    }
}

pub fn get_futex_key(uaddr: usize, flags: i32) -> Result<FutexKey, Errno> {
    if flags & FLAGS_SHARED != 0 {
        let shared_mapping_info = current_task()
            .op_memory_set(|memory_set| memory_set.get_shared_mmaping_info(VirtAddr::from(uaddr)))
            .map_or(Err(Errno::EINVAL), |info| Ok(info))?;
        return Ok(FutexKey::new(
            shared_mapping_info.inode_addr,
            shared_mapping_info.page_index,
            shared_mapping_info.offset,
        ));
    } else {
        let mm_addr = Arc::as_ptr(&current_task().memory_set()) as u64;
        let aligned = uaddr & !((1 << PAGE_SIZE_BITS) - 1);
        let offset = (uaddr & ((1 << PAGE_SIZE_BITS) - 1)) as u32;
        return Ok(FutexKey::new(mm_addr, aligned as u64, offset));
    }
}

/// deadline: None表示无限期等待
pub fn futex_wait(
    uaddr: usize,
    flags: i32,
    expected_val: u32,
    deadline: Option<TimeSpec>,
    bitset: u32,
) -> SyscallRet {
    log::error!(
        "[futex_wait] current task: {:?}, uaddr: {:#x}, flags: {:?}, val: {:?}, deadline: {:?}",
        current_task().tid(),
        uaddr,
        flags,
        expected_val,
        deadline
    );
    let mut is_timeout = false;

    // we may be victim of spurious wakeups, so we need to loop
    let key = get_futex_key(uaddr, flags)?;
    let real_futex_val = futex_get_value_locked(uaddr as *const u32)?;
    if expected_val != real_futex_val as u32 {
        return Err(Errno::EAGAIN);
    }
    // 比较后相等，放入等待队列
    {
        let mut hash_bucket = FUTEXQUEUES.buckets[futex_hash(&key)].lock();
        let cur_futexq = FutexQ::new(key, current_task().clone(), bitset);
        hash_bucket.push_back(cur_futexq);

        // drop lock to avoid deadlock
        drop(hash_bucket);
    }
    loop {
        log::trace!("futex_wait loop");
        if let Some(deadline) = deadline {
            let now = TimeSpec::new_machine_time();
            is_timeout = deadline < now;
        }
        if deadline.is_none() || !is_timeout {
            // Todo: 阻塞
            yield_current_task();
        }

        // If we were woken (and unqueued), we succeeded, whatever.
        // We doesn't care about the reason of wakeup if we were unqueued.
        let mut hash_bucket = FUTEXQUEUES.buckets[futex_hash(&key)].lock();
        let cur_id = current_task().tid();
        // 查看自己是否在队列中
        hash_bucket.retain(|futex_q| futex_q.task.upgrade().is_some());
        if let Some(_idx) = hash_bucket
            .iter()
            .position(|futex_q| futex_q.task.upgrade().unwrap().tid() == cur_id)
        {
            // hash_bucket.remove(idx);
            if is_timeout {
                return Err(Errno::ETIMEDOUT);
            }
            // Todo: 信号中断
            // if current_task().have_signals() {
            //     // we were interrupted by a signal
            //     return Err(EINTR);
            // }
        } else {
            // the task is woken up anyway, and finds itself unqueued
            return Ok(0);
        }
    }
}

/// no need to check the bitset, faster than futex_wake_bitset
pub fn futex_wake(uaddr: usize, flags: i32, nr_waken: u32) -> SyscallRet {
    log::error!(
        "[futex_wake] uaddr: {:#x}, flags: {:?}, nr_waken: {:?}",
        uaddr,
        flags,
        nr_waken
    );
    let mut ret = 0;
    let key = get_futex_key(uaddr, flags)?;
    {
        let mut hash_bucket = FUTEXQUEUES.buckets[futex_hash(&key)].lock();

        if hash_bucket.is_empty() {
            log::info!("hash_bucket is empty");
            return Ok(0);
        } else {
            hash_bucket.retain(|futex_q| {
                if ret < nr_waken && futex_q.key == key {
                    //let wake_up = WAIT_FOR_FUTEX.notify_task(&futex_q.task);
                    log::info!("wake up task {:?}", futex_q.task.upgrade().unwrap().tid());
                    ret += 1;
                    return false;
                }
                true
            })
        }
        // drop hash_bucket to avoid deadlock
    }
    yield_current_task();
    log::info!("[futex_wake] wake up {:?} tasks", ret);
    Ok(ret as usize)
}

pub fn futex_wake_bitset(uaddr: usize, flags: i32, nr_waken: u32, bitset: u32) -> SyscallRet {
    log::info!(
        "[futex_wake_bitset] uaddr: {:?}, flags: {:?}, nr_waken: {:?}, bitset: {:x}",
        uaddr,
        flags,
        nr_waken,
        bitset
    );
    if bitset == 0 {
        return Err(Errno::EINVAL);
    }
    let mut ret = 0;
    let key = get_futex_key(uaddr, flags)?;
    {
        let mut hash_bucket = FUTEXQUEUES.buckets[futex_hash(&key)].lock();
        if hash_bucket.is_empty() {
            return Ok(0);
        } else {
            hash_bucket.retain(|futex_q| {
                if ret == nr_waken {
                    return true;
                }
                if (futex_q.bitset & bitset) != 0 && futex_q.key == key {
                    //WAIT_FOR_FUTEX.notify_task(&futex_q.task);
                    ret += 1;
                    return false;
                }
                return true;
            })
        }
        // drop hash_bucket to avoid deadlock
    }
    yield_current_task();
    Ok(ret as usize)
}

pub fn futex_requeue(
    uaddr: usize,
    flags: i32,
    nr_waken: u32,
    uaddr2: usize,
    nr_requeue: u32,
) -> SyscallRet {
    let mut ret = 0;
    let mut requeued = 0;
    let key = get_futex_key(uaddr, flags)?;
    let req_key = get_futex_key(uaddr2, flags)?;

    if key == req_key {
        return futex_wake(uaddr, flags, nr_waken);
    }

    {
        let mut hash_bucket = FUTEXQUEUES.buckets[futex_hash(&key)].lock();
        if hash_bucket.is_empty() {
            return Ok(0);
        } else {
            while let Some(futex_q) = hash_bucket.pop_front() {
                if futex_q.key == key {
                    //WAIT_FOR_FUTEX.notify_task(&futex_q.task);
                    ret += 1;
                    if ret == nr_waken {
                        break;
                    }
                }
            }
            if hash_bucket.is_empty() {
                return Ok(ret as usize);
            }
            // requeue the rest of the waiters
            let mut req_bucket = FUTEXQUEUES.buckets[futex_hash(&req_key)].lock();
            while let Some(futex_q) = hash_bucket.pop_front() {
                req_bucket.push_back(futex_q);
                requeued += 1;
                if requeued == nr_requeue {
                    break;
                }
            }
        }
    }
    yield_current_task();
    Ok(ret as usize)
}

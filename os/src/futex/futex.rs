//! 实现与futex相关的系统调用
/*
use axhal::mem::VirtAddr;
use axlog::info;
use core::time::Duration;
use crate::{current_process, current_thread_uncheck, signal::current_have_signals, yield_now_task};
use axfutex::{flags::FLAGS_SHARED, futex::{FutexKey, FutexQ}, queues::{futex_hash, FUTEXQUEUES}};
*/

extern crate alloc;

use core::cmp;

use super::{flags::*, queue::FUTEXQUEUES};
use crate::{
    arch::{config::{PAGE_SIZE_BITS, USER_MAX}, mm::copy_from_user},
    futex::{
        self,
        queue::{display_futexqueues, futex_hash},
    },
    syscall::errno::{Errno, SyscallRet},
    task::{
        current_task, dump_scheduler, dump_wait_queue, wait, wait_timeout, wakeup,
        yield_current_task, Task, ITIMER_REAL,
    },
    timer::TimeSpec,
};
use alloc::{
    collections::vec_deque::VecDeque,
    sync::{Arc, Weak},
    task,
};

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
            .map_or(
                // 理应要检查共享权限设置
                {
                    log::error!("[get_futex_key] get_shared_mmaping_info failed");
                    let mm_addr = Arc::as_ptr(&current_task().memory_set()) as u64;
                    let aligned = uaddr & !((1 << PAGE_SIZE_BITS) - 1);
                    let offset = (uaddr & ((1 << PAGE_SIZE_BITS) - 1)) as u32;
                    let info = SharedMappingInfo {
                        inode_addr: mm_addr,
                        page_index: aligned as u64,
                        offset,
                    };
                    Ok(info)
                },
                |info| Ok(info),
            )?;
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
    wait_time: Option<TimeSpec>,
    bitset: u32,
) -> SyscallRet {
    log::error!(
        "[futex_wait] current task: {:?}, uaddr: {:#x}, flags: {:?}, val: {:?}, deadline: {:?}",
        current_task().tid(),
        uaddr,
        flags,
        expected_val,
        wait_time
    );

    // we may be victim of spurious wakeups, so we need to loop
    let key = get_futex_key(uaddr, flags)?;
    let real_futex_val = futex_get_value_locked(uaddr as *const u32)?;
    log::error!(
        "[futex_wait] real futex value: {:?}, expected_val: {}",
        real_futex_val,
        expected_val
    );
    if expected_val != real_futex_val as u32 {
        return Err(Errno::EAGAIN);
    }
    // 比较后相等，放入等待队列
    {
        let mut hash_bucket = FUTEXQUEUES.buckets[futex_hash(&key)].lock();
        //hash_bucket.retain(|futex_q| futex_q.task.upgrade().is_some());
        let cur_futexq = FutexQ::new(key, current_task().clone(), bitset);
        hash_bucket.push_back(cur_futexq);

        // drop lock to avoid deadlock
        drop(hash_bucket);
    }
    loop {
        if let Some(mut wait_time) = wait_time {
            let clock_id = if flags & FLAGS_CLOCKRT != 0 {
                let now = TimeSpec::new_wall_time();
                if wait_time < now {
                    log::error!("[futex_wait] wait_time is in the past, returning ETIMEDOUT");
                    let mut hash_bucket = FUTEXQUEUES.buckets[futex_hash(&key)].lock();
                    hash_bucket.retain(|futex_q| futex_q.task.upgrade().unwrap().tid() != current_task().tid());
                    return Err(Errno::ETIMEDOUT);
                }
                wait_time = wait_time - now;
                ITIMER_REAL
            } else {
                -1
            };
            let ret = wait_timeout(wait_time, clock_id);
            let task = current_task();
            if ret == -1 {
                // 被信号唤醒
                log::error!("[futex_wait] task{} wakeup by signal", task.tid());
                let mut hash_bucket = FUTEXQUEUES.buckets[futex_hash(&key)].lock();
                hash_bucket.retain(|futex_q| futex_q.task.upgrade().unwrap().tid() != task.tid());
                return Err(Errno::EINTR);
            } else if ret == -2 {
                // 超时
                log::error!("[futex_wait] task{} wakeup by timeout", task.tid());
                let mut hash_bucket = FUTEXQUEUES.buckets[futex_hash(&key)].lock();
                hash_bucket.retain(|futex_q| futex_q.task.upgrade().unwrap().tid() != task.tid());
                return Err(Errno::ETIMEDOUT);
            }
            return Ok(0);
        }

        // 无计时情况
        if wait_time.is_none() {
            if wait() == -1 {
                let mut hash_bucket = FUTEXQUEUES.buckets[futex_hash(&key)].lock();
                hash_bucket.retain(|futex_q| {
                    futex_q.task.upgrade().unwrap().tid() != current_task().tid()
                });
                return Err(Errno::EINTR);
            }
            return Ok(0);
        }
    }
}

/// no need to check the bitset, faster than futex_wake_bitset
pub fn futex_wake(uaddr: usize, flags: i32, nr_waken: u32) -> SyscallRet {
    log::error!(
        "[futex_wake] current task: {}, uaddr: {:#x}, flags: {:?}, nr_waken: {:?}",
        current_task().tid(),
        uaddr,
        flags,
        nr_waken
    );
    let mut ret = 0;
    let key = get_futex_key(uaddr, flags)?;
    {
        let mut hash_bucket = FUTEXQUEUES.buckets[futex_hash(&key)].lock();

        if hash_bucket.is_empty() {
            log::info!("[futex_wake] hash_bucket is empty");
            return Ok(0);
        } else {
            log::error!("[futex_wake] hash_bucket is not empty, len: {}", hash_bucket.len());
            hash_bucket.retain(|futex_q| {
                if futex_q.task.upgrade().is_none() {
                    return false;
                }
                if ret < nr_waken && futex_q.key == key {
                    wakeup(futex_q.task.upgrade().unwrap().tid());
                    log::error!(
                        "[futex_wake] wake up task {:?}",
                        futex_q.task.upgrade().unwrap().tid()
                    );
                    ret += 1;
                    return false;
                }
                true
            })
        }
        // drop hash_bucket to avoid deadlock
    }
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
    // 对应的是 val或val2 为-1的情况
    if nr_waken == 4294967295 || nr_requeue == 4294967295 {
        return Err(Errno::EINVAL);
    }

    let mut ret = 0;
    let mut requeued = 0;
    let key = get_futex_key(uaddr, flags)?;
    let req_key = get_futex_key(uaddr2, flags)?;
    let hash_src = futex_hash(&key);
    let hash_req = futex_hash(&req_key);

    if key == req_key {
        return futex_wake(uaddr, flags, nr_waken);
    }

    {
        let mut hash_bucket = FUTEXQUEUES.buckets[futex_hash(&key)].lock();
        if hash_bucket.is_empty() {
            return Ok(0);
        } else {
            // 先唤醒nr_waken个任务
            let mut temp_hash_bucket: VecDeque<FutexQ> = VecDeque::new();
            while ret < nr_waken {
                if let Some(futex_q) = hash_bucket.pop_front() {
                    if futex_q.key == key {
                        log::error!(
                            "[futex_requeue] wake up task {:?} from key {:?}",
                            futex_q.task.upgrade().unwrap().tid(),
                            key
                        );
                        ret += 1;
                        wakeup(futex_q.task.upgrade().unwrap().tid());
                    } else {
                        // 不是要唤醒的futex，放入临时队列
                        temp_hash_bucket.push_back(futex_q);
                    }
                }
            }

            // 把误拿的futex_q放回原来的队列
            while let Some(futex_q) = temp_hash_bucket.pop_front() {
                hash_bucket.push_back(futex_q);
            }

            if hash_src == hash_req {
                // 如果源桶和请求桶是同一个桶，直接返回
                log::error!("[futex_requeue] source bucket and request bucket are the same, returning");
                while let Some(mut futex_q) = hash_bucket.pop_front() {
                    futex_q.key = req_key; // update the key to the new one
                    log::error!("[futex_requeue] requeue task {:?} to key {:?}",
                                futex_q.task.upgrade().unwrap().tid(), req_key);
                    hash_bucket.push_back(futex_q);
                    requeued += 1;
                    ret += 1;
                    if requeued == nr_requeue {
                        break;
                    }
                }
            } else {
                // 将桶中其余的futex_q重新排队到请求的桶中
                let mut req_bucket = FUTEXQUEUES.buckets[futex_hash(&req_key)].lock();
                while let Some(mut futex_q) = hash_bucket.pop_front() {
                    futex_q.key = req_key; // update the key to the new one
                    log::error!("[futex_requeue] requeue task {:?} to key {:?}",
                                futex_q.task.upgrade().unwrap().tid(), req_key);
                    req_bucket.push_back(futex_q);
                    requeued += 1;
                    ret += 1;
                    if requeued == nr_requeue {
                        break;
                    }
                }
                log::error!("[futex_requeue] target bucket len: {:?}", req_bucket.len());
            }
        }
    }
    Ok(ret as usize)
}

pub fn futex_cmp_requeue(
    uaddr: usize,
    flags: i32,
    nr_waken: u32,
    uaddr2: usize,
    nr_requeue: u32,
    val3: u32,
) -> SyscallRet {
    // 对应的是 val或val2 为-1的情况
    if nr_waken >= USER_MAX as u32 || nr_requeue == USER_MAX as u32 {
        return Err(Errno::EINVAL);
    }

    let real_futex_val = futex_get_value_locked(uaddr as *const u32)?;
    if val3 != real_futex_val as u32 {
        return Err(Errno::EAGAIN);
    }

    let mut ret = 0;
    let mut requeued = 0;
    let key = get_futex_key(uaddr, flags)?;
    let req_key = get_futex_key(uaddr2, flags)?;
    let hash_src = futex_hash(&key);
    let hash_req = futex_hash(&req_key);

    if key == req_key {
        return futex_wake(uaddr, flags, nr_waken);
    }

    {
        log::trace!("[futex_requeue] key: {:?}, req_key: {:?}, hash_src: {}, hash_req: {}",
                    key, req_key, hash_src, hash_req);
        let mut hash_bucket = FUTEXQUEUES.buckets[futex_hash(&key)].lock();
        if hash_bucket.is_empty() {
            return Ok(0);
        } else {
            // 先唤醒nr_waken个任务
            let mut temp_hash_bucket: VecDeque<FutexQ> = VecDeque::new();
            while ret < nr_waken {
                if let Some(futex_q) = hash_bucket.pop_front() {
                    if futex_q.key == key {
                        ret += 1;
                        wakeup(futex_q.task.upgrade().unwrap().tid());
                    } else {
                        // 不是要唤醒的futex，放入临时队列
                        temp_hash_bucket.push_back(futex_q);
                    }
                }
            }

            // 把误拿的futex_q放回原来的队列
            while let Some(futex_q) = temp_hash_bucket.pop_front() {
                hash_bucket.push_back(futex_q);
            }

            if hash_src == hash_req {
                // 如果源桶和请求桶是同一个桶，直接返回
                log::error!("[futex_requeue] source bucket and request bucket are the same, returning");
                while let Some(mut futex_q) = hash_bucket.pop_front() {
                    futex_q.key = req_key; // update the key to the new one
                    log::error!("[futex_requeue] requeue task {:?} to key {:?}",
                                futex_q.task.upgrade().unwrap().tid(), req_key);
                    hash_bucket.push_back(futex_q);
                    requeued += 1;
                    ret += 1;
                    if requeued == nr_requeue {
                        break;
                    }
                }
            } else {
                // 将桶中其余的futex_q重新排队到请求的桶中
                let mut req_bucket = FUTEXQUEUES.buckets[futex_hash(&req_key)].lock();
                while let Some(mut futex_q) = hash_bucket.pop_front() {
                    futex_q.key = req_key; // update the key to the new one
                    log::error!("[futex_requeue] requeue task {:?} to key {:?}",
                                futex_q.task.upgrade().unwrap().tid(), req_key);
                    req_bucket.push_back(futex_q);
                    requeued += 1;
                    ret += 1;
                    if requeued == nr_requeue {
                        break;
                    }
                }
                log::error!("[futex_requeue] target bucket len: {:?}", req_bucket.len());
            }
        }
    }
    Ok(ret as usize)
}

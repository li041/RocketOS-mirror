//! System V shared memory

use core::{default, sync::atomic::AtomicUsize};

use alloc::{sync::Weak, vec::Vec};
use bitflags::bitflags;
use hashbrown::HashMap;
use lazy_static::lazy_static;
use spin::{Mutex, RwLock};
use virtio_drivers::PAGE_SIZE;

use crate::{
    arch::{mm::copy_to_user, timer::TimeSpec},
    syscall::errno::{Errno, SyscallRet},
    task::{current_task, IdAllocator},
};

use super::{MapPermission, Page};

lazy_static! {
    /// System V shared memory manager
    static ref SHM_MANAGER: ShmManager = ShmManager::new();
}

pub struct ShmSegment {
    pub id: ShmId, // 共享内存的ID
    // 注意这里使用Weak引用, 因为共享内存的页生命周期是由用户决定的
    pub pages: Vec<Weak<Page>>, //
}

impl ShmSegment {
    /// 由上层调用者保证:
    ///     1. size是页对齐的
    pub fn new(page_aligned_size: usize, tgid: usize) -> Self {
        Self {
            id: ShmId::new(page_aligned_size, tgid),
            pages: Vec::with_capacity(page_aligned_size / PAGE_SIZE),
        }
    }
    fn attach_update_id(&mut self, lprid: usize) {
        self.id.nattch += 1;
        self.id.lprid = lprid;
        self.id.atime = TimeSpec::new_wall_time().sec as usize;
    }
    // detach()方法返回值表示是否需要删除该共享内存段
    fn detach_update_id(&mut self, lprid: usize) -> bool {
        self.id.dtime = TimeSpec::new_wall_time().sec as usize;
        self.id.lprid = lprid;
        if self.id.nattch > 1 {
            self.id.nattch -= 1;
            false
        } else {
            // 如果没有进程attach了, 则删除该共享内存段
            true
        }
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C)]
pub struct IpcPerm {
    pub key: i32,  // 用户提供的用于查找的key值
    pub uid: u32,  // 拥有者的用户ID
    pub gid: u32,  // 拥有者的组ID
    pub cuid: u32, // 创建者的用户ID
    pub cgid: u32, // 创建者的组ID
    pub mode: u16, // 权限模式(九位rwxrwxrwx权限)
    pub seq: u16,
}

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct ShmId {
    pub ipc_perm: IpcPerm, // IPC权限
    pub size: usize,       // 共享内存的大小
    pub atime: usize,      // 上次attach的时间, 自EPOCH以来的秒数
    pub dtime: usize,      // 上次detach的时间, 自EPOCH以来的秒数
    pub ctime: usize,      // 上次创建的时间(或通过shmctl()改变的时间), 自EPOCH以来的秒数
    pub cprid: usize,      // 创建者的进程ID
    pub lprid: usize,      // 最后一次调用`shmat()/shmdt()`的进程ID
    pub nattch: usize,     // 当前attach的进程数
}
impl ShmId {
    pub fn new(size: usize, cprid: usize) -> Self {
        debug_assert!(size % PAGE_SIZE == 0);
        ShmId {
            size,
            ctime: TimeSpec::new_wall_time().sec as usize,
            cprid,
            ..Default::default()
        }
    }
}

pub struct ShmManager {
    pub segments: RwLock<HashMap<usize, ShmSegment>>, // 共享内存段
    shmid_allocator: Mutex<IdAllocator>,              // 共享内存ID分配器
}

pub const IPC_PRIVATE: usize = 0; // IPC_PRIVATE是一个特殊的key值, 用于创建一个新的共享内存段

bitflags! {
    #[derive(Debug)]
    pub struct ShmGetFlags: i32 {
        /// 创建新段。如果不使用此标志，则 shmget() 会查找与 key 关联的段
        /// 并检查用户是否有权限访问该段
        const IPC_CREAT = 0o1000;
        /// 与 IPC_CREAT 一起使用，确保调用会创建新段。
        /// 如果段已存在，则调用失败
        const IPC_EXCL = 0o2000;
    }
}

bitflags! {
    #[derive(Debug)]
    pub struct ShmAtFlags: i32 {
        /// 以只读方式附加段。如果不指定此标志，
        /// 则以读写方式附加段，且进程必须具有对该段的读写权限
        const SHM_RDONLY = 0o10000;
        /// 将附加地址舍入到 SHMLBA 边界
        const SHM_RND = 0o20000;
        /// 附加时接管区域（未实现）
        const SHM_REMAP = 0o40000;
        /// 允许执行段中的内容
        const SHM_EXEC = 0o100000;
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[allow(non_camel_case_types)]
#[repr(i32)]
pub enum ShmCtlOp {
    IPC_PMID = 0, // 获取共享内存段的状态
    IPC_SET = 1,  // 设置共享内存段的权限
    IPC_STAT = 2, // 获取共享内存段的Shmid
    IPC_RMID = 3, // 标志要删除共享内存段(只在最后一个进程分离它是销毁)
}

impl From<i32> for ShmCtlOp {
    fn from(value: i32) -> Self {
        match value {
            0 => ShmCtlOp::IPC_PMID,
            1 => ShmCtlOp::IPC_SET,
            2 => ShmCtlOp::IPC_STAT,
            3 => ShmCtlOp::IPC_RMID,
            _ => panic!("Invalid ShmCtlOp value"),
        }
    }
}

impl ShmManager {
    pub fn new() -> Self {
        ShmManager {
            segments: RwLock::new(HashMap::new()),
            shmid_allocator: Mutex::new(IdAllocator::new()),
        }
    }

    fn add_shmseg(&self, shm_seg: ShmSegment, shmid: Option<usize>) -> usize {
        let mut segments = self.segments.write();
        let shmid = match shmid {
            Some(id) => id,
            None => self.shmid_allocator.lock().alloc(),
        };
        segments.insert(shmid, shm_seg);
        shmid
    }
}

/// 检查对应共享内存段是否存在, 如果不存在则返回Ok(0)
pub fn check_shm_segment_exist(
    key: usize,
    page_aligned_size: usize,
    shmflg: &ShmGetFlags,
) -> Result<usize, Errno> {
    debug_assert!(key != IPC_PRIVATE);
    let shm_manager = SHM_MANAGER.segments.read();
    if let Some(shm) = shm_manager.get(&key) {
        if shmflg.contains(ShmGetFlags::IPC_CREAT | ShmGetFlags::IPC_EXCL) {
            return Err(Errno::EEXIST);
        }
        if shm.id.size < page_aligned_size {
            return Err(Errno::EINVAL);
        }
        return Ok(key);
    }
    return Ok(0);
}

// 返回值是shmid
pub fn add_shm_segment(size: usize, tgid: usize, shmid: Option<usize>) -> usize {
    let shm_seg = ShmSegment::new(size, tgid);
    SHM_MANAGER.add_shmseg(shm_seg, shmid)
}

pub fn attach_shm_segment(shmid: usize, aligned_shmaddr: usize, shmflg: &ShmAtFlags) -> SyscallRet {
    let map_perm = MapPermission::from(shmflg);
    if let Some(shm_seg) = SHM_MANAGER.segments.write().get_mut(&shmid) {
        let task = current_task();
        let shm_start_address = task.op_memory_set_mut(|memory_set| {
            // 将共享内存段映射到进程的地址空间
            let ret = memory_set.attach_shm_segment(aligned_shmaddr, map_perm, shm_seg);
            // 添加shmaddr->shmid映射关系
            memory_set.addr2shmid.insert(ret, shmid);
            return ret;
        });
        shm_seg.attach_update_id(task.tgid());
        return Ok(shm_start_address);
    } else {
        return Err(Errno::EINVAL);
    }
}

pub fn detach_shm_segment(shmaddr: usize) -> SyscallRet {
    let task = current_task();
    task.op_memory_set_mut(|memory_set| {
        let shmid = memory_set
            .addr2shmid
            .remove(&shmaddr)
            .ok_or(Errno::EINVAL)?;
        let mut should_remove: bool = false;
        if let Some(shm_seg) = SHM_MANAGER.segments.write().get_mut(&shmid) {
            // 解除映射
            memory_set.detach_shm_segment(shmaddr);
            // 更新共享内存段的引用计数
            if shm_seg.detach_update_id(task.tgid()) {
                should_remove = true;
            }
            // 删除shmaddr->shmid映射关系
            memory_set.addr2shmid.remove(&shmaddr);
        } else {
            return Err(Errno::EINVAL);
        }
        if should_remove {
            SHM_MANAGER.segments.write().remove(&shmid).unwrap();
        }
        Ok(0)
    })?;
    Ok(0)
}

pub fn stat_shm_segment(shmid: usize, buf: *mut ShmId) -> SyscallRet {
    let shm_manager = SHM_MANAGER.segments.read();
    let shm_seg = shm_manager.get(&shmid).ok_or(Errno::EINVAL)?;
    copy_to_user(buf, &shm_seg.id as *const ShmId, 1)?;
    Ok(0)
}

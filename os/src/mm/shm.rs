//! System V shared memory

use core::{fmt::Debug, sync::atomic::AtomicBool};

use alloc::{collections::btree_map::BTreeMap, sync::Arc, vec::Vec};
use bitflags::bitflags;
use lazy_static::lazy_static;
use spin::{Mutex, RwLock};
use virtio_drivers::PAGE_SIZE;

use crate::{
    arch::mm::{copy_from_user, copy_to_user},
    fs::proc::get_shm_max,
    syscall::errno::{Errno, SyscallRet},
    task::{current_task, IdAllocator},
    timer::TimeSpec,
    utils::ceil_to_page_size,
};

use super::{MapPermission, Page};

lazy_static! {
    /// System V shared memory manager
    static ref SHM_MANAGER: ShmManager = ShmManager::new();
}

pub struct ShmSegment {
    pub id: ShmId, // 共享内存的ID
    // 注意这里使用强引用, 当所有process detach了该共享内存段时, 并且shmctl()标记删除时, 才会删除该共享内存段
    pub pages: Vec<Arc<Page>>,
    pub marked_for_deletion: AtomicBool, // 标记是否被IPC_RMID标记删除
}

impl Debug for ShmSegment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ShmSegment {{ id: {:?}, marked_for_deletion: {} }}",
            self.id,
            self.marked_for_deletion
                .load(core::sync::atomic::Ordering::SeqCst)
        )
    }
}

impl ShmSegment {
    /// 由上层调用者检查是否有权限
    /// 只设置uid, gid, mode, 同时更新shm_ctime
    pub fn set_shmid(&mut self, shmid: &ShmId) {
        self.id.ipc_perm.uid = shmid.ipc_perm.uid;
        self.id.ipc_perm.gid = shmid.ipc_perm.gid;
        self.id.ipc_perm.mode = shmid.ipc_perm.mode;
        self.id.ctime = TimeSpec::new_wall_time().sec as usize;
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ShmInfo {
    pub used_ids: i32,       // 当前系统中正在使用的共享n内段数量
    pub shm_tot: u64,        // 所有已分配共享内存段的总大小（字节数）。
    pub shm_rss: u64,        // 当前所有共享内存段实际驻留在物理内存（RAM）中的总页数。
    pub shm_swp: u64,        // 当前所有共享内存段被交换（swap）出去的总页数。
    pub swap_attempts: u64,  // 内核尝试将共享内存页换出到 swap 的次数。
    pub swap_successes: u64, // 内核成功将共享内存页换出到 swap 的次数。
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IpcInfo {
    shmmax: u64, // 系统允许的最大共享内存段大小
    shmmin: u64, // 系统允许的最小共享内存段大小, 总是1
    shmmni: u64, // 系统允许的最大共享内存段数量
    shmseg: u64, // 系统允许的y一个进程可以attach的最大g内存共享数
    shmall: u64, // 系统允许的总共享内存大小（以页为单位）
}

impl IpcInfo {
    pub fn new() -> Self {
        let shmmax = get_shm_max() as u64;
        IpcInfo {
            shmmax,
            shmmin: 1,
            shmmni: 4096,
            shmseg: 1024,
            shmall: 0xFFFF_FFFF,
        }
    }
}

impl ShmSegment {
    /// 由上层调用者保证:
    ///     1. size是原始参数(可能未对齐)
    pub fn new(shmid: usize, size: usize, tgid: usize, mode: u16) -> Self {
        let page_aligned_size = ceil_to_page_size(size);
        Self {
            id: ShmId::new(shmid, size, tgid as i32, mode),
            pages: Vec::with_capacity(page_aligned_size / PAGE_SIZE),
            marked_for_deletion: AtomicBool::new(false),
        }
    }
    fn attach_update_id(&mut self, lpid: usize) {
        self.id.nattch += 1;
        self.id.lpid = lpid as i32;
        self.id.atime = TimeSpec::new_wall_time().sec as usize;
    }
    // detach()方法返回值表示是否需要删除该共享内存段
    fn detach_update_id(&mut self, lpid: usize) -> bool {
        self.id.dtime = TimeSpec::new_wall_time().sec as usize;
        self.id.lpid = lpid as i32;
        self.id.nattch -= 1;
        self.id.nattch == 0
            && self
                .marked_for_deletion
                .load(core::sync::atomic::Ordering::SeqCst)
    }
}

// mode语义
// 0o400 - 拥有者读权限
// 0o200 - 拥有者写权限
// 0o040 - 组读权限
// 0o020 - 组写权限
// 0o004 - 其他用户读权限
// 0o002 - 其他用户写权限
#[derive(Default, Clone, Copy, Debug)]
#[repr(C)]
pub struct IpcPerm {
    pub key: i32,  // 用户提供的用于查找的key值
    pub uid: u32,  // 拥有者的用户ID
    pub gid: u32,  // 拥有者的组ID
    pub cuid: u32, // 创建者的用户ID
    pub cgid: u32, // 创建者的组ID
    pub mode: u16, // 权限模式
    pub seq: u16,
    pub __pad2: u16,
    pub __glibc_reserved1: u64,
    pub __glibc_reserved2: u64,
}

impl IpcPerm {
    pub fn new(key: i32, mode: u16) -> Self {
        let task = current_task();
        let cuid = task.euid();
        let cgid = task.egid();
        IpcPerm {
            key,
            uid: cuid,
            gid: cgid,
            cuid,
            cgid,
            mode,
            seq: 0,
            __pad2: 0,
            __glibc_reserved1: 0,
            __glibc_reserved2: 0,
        }
    }
}

#[derive(Default, Copy, Clone, Debug)]
#[repr(C)]
pub struct ShmId {
    pub ipc_perm: IpcPerm,  // IPC权限
    pub size: usize,        // 共享内存的大小, 未页对齐
    pub atime: usize,       // 上次attach的时间, 自EPOCH以来的秒数
    pub dtime: usize,       // 上次detach的时间, 自EPOCH以来的秒数
    pub ctime: usize,       // 上次创建的时间(或通过shmctl()改变的时间), 自EPOCH以来的秒数
    pub cpid: i32,          // 创建者的进程ID
    pub lpid: i32,          // 最后一次调用`shmat()/shmdt()`的进程ID
    pub nattch: usize,      // 当前attach的进程数
    __glibc_reserved5: u64, // 保留字段
    __glibc_reserved6: u64, // 保留字段
}
impl ShmId {
    pub fn new(shmid: usize, size: usize, cpid: i32, mode: u16) -> Self {
        ShmId {
            ipc_perm: IpcPerm::new(shmid as i32, mode),
            size,
            ctime: TimeSpec::new_wall_time().sec as usize,
            cpid: cpid,
            ..Default::default()
        }
    }
}

pub struct ShmManager {
    pub segments: RwLock<BTreeMap<usize, ShmSegment>>, // 共享内存段
    shmid_allocator: Mutex<IdAllocator>,               // 共享内存ID分配器
}

pub const IPC_PRIVATE: usize = 0; // IPC_PRIVATE是一个特殊的key值, 用于创建一个新的共享内存段

bitflags! {
    pub struct ShmGetFlags: i32 {
        /// 创建新段。如果不使用此标志，则 shmget() 会查找与 key 关联的段
        /// 并检查用户是否有权限访问该段
        const IPC_CREAT = 0o1000;
        /// 与 IPC_CREAT 一起使用，确保调用会创建新段。
        /// 如果段已存在，则调用失败
        const IPC_EXCL = 0o2000;
        const SHM_HUGETLB = 0o4000; // 使用大页共享内存
    }
}

impl Debug for ShmGetFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 使用位标志的名称进行格式化
        let mut flags = Vec::new();
        if self.contains(ShmGetFlags::IPC_CREAT) {
            flags.push("IPC_CREAT");
        }
        if self.contains(ShmGetFlags::IPC_EXCL) {
            flags.push("IPC_EXCL");
        }
        if self.contains(ShmGetFlags::SHM_HUGETLB) {
            flags.push("SHM_HUGETLB");
        }
        if flags.is_empty() {
            write!(f, "ShmGetFlags::empty()")
        } else {
            write!(f, "ShmGetFlags::{}", flags.join(" | "))
        }
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
    IPC_RMID = 0,    // 标志要删除共享内存段(只在最后一个进程分离它是销毁)
    IPC_SET = 1,     // 设置共享内存段的权限
    IPC_STAT = 2,    // 获取共享内存段的Shmid
    IPC_INFO = 3,    // 查看ipcs
    SHM_LOCK = 11,   // 锁定共享内存段
    SHM_UNLOCK = 12, // 解锁共享内存段
    SHM_STAT = 13,   // 获取共享内存段的状态
    SHM_INFO = 14,   // 获取系统共享内存使用情况
    Unknown = -1,    // 未知操作
}

impl From<i32> for ShmCtlOp {
    fn from(value: i32) -> Self {
        match value {
            0 => ShmCtlOp::IPC_RMID,
            1 => ShmCtlOp::IPC_SET,
            2 => ShmCtlOp::IPC_STAT,
            3 => ShmCtlOp::IPC_INFO,
            11 => ShmCtlOp::SHM_LOCK,
            12 => ShmCtlOp::SHM_UNLOCK,
            13 => ShmCtlOp::SHM_STAT,
            14 => ShmCtlOp::SHM_INFO,
            _ => ShmCtlOp::Unknown,
        }
    }
}

impl ShmManager {
    pub fn new() -> Self {
        ShmManager {
            segments: RwLock::new(BTreeMap::new()),
            shmid_allocator: Mutex::new(IdAllocator::new()),
        }
    }

    fn add_shmseg(&self, shm_seg: ShmSegment, shmid: usize) -> usize {
        let mut segments = self.segments.write();
        segments.insert(shmid, shm_seg);
        shmid
    }
}

/// 检查对应共享内存段是否存在, 如果不存在则返回Ok(0)
/// 如果存在, 则检查权限
pub fn check_shm_segment_exist(
    key: usize,
    page_aligned_size: usize,
    shmflg: &ShmGetFlags,
    mode: u16,
) -> Result<usize, Errno> {
    debug_assert!(key != IPC_PRIVATE);
    let mut shm_manager = SHM_MANAGER.segments.write();
    if let Some(shm) = shm_manager.get(&key) {
        if shm.id.nattch == 0
            && shm
                .marked_for_deletion
                .load(core::sync::atomic::Ordering::SeqCst)
        {
            // 如果该共享内存段nattch为0, 且已经被标记删除, 需要从共享内存段列表中删除
            log::error!(
                "[check_shm_segment_exist] Shared memory segment with key: {:#x} is marked for deletion, and nattch is 0, removing it",
                key
            );
            shm_manager.remove(&key);
            return Ok(0);
        }
        if shmflg.contains(ShmGetFlags::IPC_CREAT | ShmGetFlags::IPC_EXCL) {
            return Err(Errno::EEXIST);
        }
        if shm.id.size < page_aligned_size {
            log::error!(
                "[check_shm_segment_exist] Existing shm segment size: {:#x} is less than requested size: {:#x}",
                shm.id.size,
                page_aligned_size
            );
            return Err(Errno::EINVAL);
        }
        // 检查权限
        check_shm_perm(&shm.id.ipc_perm, mode)?;
        return Ok(key);
    }
    return Ok(0);
}

pub const SHM_R: u16 = 0o400; // 共享内存段的读权限, or S_IRUGO
pub const SHM_W: u16 = 0o200; // 共享内存段的写权限

pub fn check_shm_perm(ipc_perm: &IpcPerm, mode: u16) -> Result<usize, Errno> {
    let task = current_task();
    let euid = task.euid();
    let egid = task.egid();
    let (user_perm, group_perm, other_perm) = (
        (ipc_perm.mode >> 6) & 0o7, // 拥有者权限
        (ipc_perm.mode >> 3) & 0o7, // 组权限
        ipc_perm.mode & 0o7,        // 其他用户权限
    );
    let perm = if euid == ipc_perm.uid {
        user_perm // 拥有者权限
    } else if egid == ipc_perm.gid {
        group_perm // 组权限
    } else {
        other_perm // 其他用户权限
    };
    log::info!(
        "[check_shm_perm] euid: {}, egid: {}, ipc_perm: {:?}, mode: {:#o}, perm: {:#o}",
        euid,
        egid,
        ipc_perm,
        mode,
        perm
    );
    if mode & SHM_R != 0 && perm & 0o4 == 0 || mode & SHM_W != 0 && perm & 0o2 == 0 {
        log::error!(
            "[check_shm_perm] Permission denied: euid: {}, egid: {}, ipc_perm: {:?}, mode: {:#o}",
            euid,
            egid,
            ipc_perm,
            mode
        );
        return Err(Errno::EACCES);
    }
    Ok(0)
}

pub fn check_shm_own(ipc_perm: &IpcPerm) -> Result<usize, Errno> {
    let task = current_task();
    let euid = task.euid();
    if euid == 0 {
        // root用户可以操作任何共享内存段
        return Ok(0);
    }
    if euid != ipc_perm.uid && euid != ipc_perm.cuid {
        log::error!(
            "[check_shm_own] Not creator or owner: euid: {}, ipc_perm: {:?}",
            euid,
            ipc_perm
        );
        return Err(Errno::EPERM);
    }
    Ok(0)
}

// 返回值是shmid
pub fn add_shm_segment(size: usize, tgid: usize, shmid: Option<usize>, mode: u16) -> usize {
    let shmid = match shmid {
        Some(id) => id,
        None => SHM_MANAGER.shmid_allocator.lock().alloc(),
    };
    let shm_seg: ShmSegment = ShmSegment::new(shmid, size, tgid, mode);
    // 8.10 Debug
    log::info!("[sys_shmget] Adding shm segment: {:?}", shm_seg);
    SHM_MANAGER.add_shmseg(shm_seg, shmid)
}

pub fn attach_shm_segment(shmid: usize, aligned_shmaddr: usize, shmflg: &ShmAtFlags) -> SyscallRet {
    let map_perm = MapPermission::from(shmflg);
    if let Some(shm_seg) = SHM_MANAGER.segments.write().get_mut(&shmid) {
        let task = current_task();
        // 检查权限
        let ipc_perm = &shm_seg.id.ipc_perm;
        if shmflg.contains(ShmAtFlags::SHM_RDONLY) {
            // 以只读方式附加段
            check_shm_perm(ipc_perm, SHM_R)?;
        } else {
            // 以读写方式附加段
            check_shm_perm(ipc_perm, SHM_W | SHM_R)?;
        }
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

pub fn increment_shm_segment_nattach(shmid: usize) {
    if let Some(shm_seg) = SHM_MANAGER.segments.write().get_mut(&shmid) {
        shm_seg.id.nattch += 1;
    }
}

pub fn detach_shm_segment(shmaddr: usize) -> SyscallRet {
    let task = current_task();
    task.op_memory_set_mut(|memory_set| {
        let shmid = memory_set
            .addr2shmid
            .remove(&shmaddr)
            .ok_or(Errno::EINVAL)?;
        let should_remove: bool;
        if let Some(shm_seg) = SHM_MANAGER.segments.write().get_mut(&shmid) {
            log::info!(
                "[sys_shmdt] Detaching shm segment: shmid: {:#x}, shm_seg.id: {:?}",
                shmid,
                shm_seg.id
            );
            // 解除映射
            memory_set.detach_shm_segment(shmaddr);
            // 更新共享内存段的引用计数
            should_remove = shm_seg.detach_update_id(task.tgid());
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

pub fn do_shmctl(shmid: usize, shmctl_op: ShmCtlOp, buf: usize) -> SyscallRet {
    const SHM_LOCK: u16 = 0o2000; // SHM_LOCK标志
    match shmctl_op {
        ShmCtlOp::IPC_RMID => {
            // 删除共享内存段
            let mut shm_manager = SHM_MANAGER.segments.write();
            if let Some(shm_seg) = shm_manager.get_mut(&shmid) {
                check_shm_own(&shm_seg.id.ipc_perm)?;
                if shm_seg
                    .marked_for_deletion
                    .load(core::sync::atomic::Ordering::SeqCst)
                {
                    // 如果已经被标记删除, 则直接返回
                    return Ok(0);
                }
                shm_seg
                    .marked_for_deletion
                    .store(true, core::sync::atomic::Ordering::SeqCst);
                log::info!(
                    "[sys_shmctl] shmctl IPC_RMID: shmid: {:#x}, shm_seg.id: {:?}",
                    shmid,
                    shm_seg.id
                );
                // 如果没有进程attach了, 则删除该共享内存段
                if shm_seg.id.nattch == 0 {
                    shm_manager.remove(&shmid);
                }
            } else {
                // 8.9 Debug
                log::warn!("shm_manager size: {}", shm_manager.len());
                for (shmid, shm_seg) in shm_manager.iter() {
                    log::warn!(
                        "[sys_shmctl] shmid: {:#x}, shm_seg.id: {:?}",
                        shmid,
                        shm_seg.id
                    );
                }
                return Err(Errno::EINVAL);
            }
            Ok(0)
        }
        ShmCtlOp::IPC_SET => {
            // 设置共享内存段的权限
            let mut shm_manager = SHM_MANAGER.segments.write();
            let shm_seg = shm_manager.get_mut(&shmid).ok_or(Errno::EINVAL)?;
            let mut shm_id = ShmId::default();
            copy_from_user(buf as *const ShmId, &mut shm_id, 1)?;
            check_shm_own(&shm_seg.id.ipc_perm)?;
            shm_seg.set_shmid(&shm_id);
            Ok(0)
        }
        ShmCtlOp::IPC_STAT => {
            // 读取共享内存段信息
            let shm_manager = SHM_MANAGER.segments.read();
            let shm_seg = shm_manager.get(&shmid).ok_or(Errno::EINVAL)?;
            check_shm_perm(&shm_seg.id.ipc_perm, SHM_R)?;
            log::info!(
                "[sys_shmctl] shmctl IPC_STAT: shmid: {:#x}, shm_seg.id: {:?}",
                shmid,
                shm_seg.id
            );
            copy_to_user(buf as *mut ShmId, &shm_seg.id as *const ShmId, 1)?;
            Ok(0)
        }
        ShmCtlOp::IPC_INFO => {
            let shm_info = IpcInfo::new();
            copy_to_user(buf as *mut IpcInfo, &shm_info as *const IpcInfo, 1)?;
            Ok(0)
        }
        ShmCtlOp::SHM_STAT => {
            // shmid对应的是BTreeMap的索引, 不是实际的shmid
            // 返回对应索引的shmid
            let shm_manager = SHM_MANAGER.segments.read();
            let (shmid, shm_seg) = shm_manager.iter().nth(shmid).ok_or(Errno::EINVAL)?;
            check_shm_perm(&shm_seg.id.ipc_perm, SHM_R)?;
            log::info!(
                "[sys_shmctl] shmctl SHM_STAT: shmid: {:#x}, shm_seg.id: {:?}",
                *shmid,
                shm_seg.id
            );
            copy_to_user(buf as *mut ShmId, &shm_seg.id as *const ShmId, 1)?;
            Ok(*shmid)
        }
        ShmCtlOp::SHM_INFO => {
            // 返回内核共享内存段数组中已使用的最高索引值
            let shm_manager = SHM_MANAGER.segments.read();
            let used_ids = shm_manager.len() as i32;
            let mut shm_info = ShmInfo {
                used_ids: used_ids,
                shm_tot: 0,
                shm_rss: 0,
                shm_swp: 0,
                swap_attempts: 0,
                swap_successes: 0,
            };
            for shm_seg in shm_manager.values() {
                shm_info.shm_tot += shm_seg.id.size as u64;
                shm_info.shm_rss += shm_seg.pages.len() as u64;
            }
            copy_to_user(buf as *mut ShmInfo, &shm_info as *const ShmInfo, 1)?;
            Ok(used_ids as usize)
        }
        ShmCtlOp::SHM_LOCK => {
            // 锁定/解锁共享内存段
            if current_task().euid() != 0 {
                return Err(Errno::EPERM);
            }
            let mut shm_manager = SHM_MANAGER.segments.write();
            let shm_seg = shm_manager.get_mut(&shmid).ok_or(Errno::EINVAL)?;
            shm_seg.id.ipc_perm.mode |= 0o2000; // 设置SHM_LOCK标志
            Ok(0)
        }
        ShmCtlOp::SHM_UNLOCK => {
            // 解锁共享内存段
            if current_task().euid() != 0 {
                return Err(Errno::EPERM);
            }
            let mut shm_manager = SHM_MANAGER.segments.write();
            let shm_seg = shm_manager.get_mut(&shmid).ok_or(Errno::EINVAL)?;
            shm_seg.id.ipc_perm.mode &= !SHM_LOCK; // 清除SHM_LOCK标志
            Ok(0)
        }
        _ => {
            log::warn!("[sys_shmctl] Unimplemented, shmctl_op: {:?}", shmctl_op);
            return Err(Errno::EINVAL);
        }
    }
}

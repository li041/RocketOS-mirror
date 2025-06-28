use core::{default, mem, str};

use lazy_static::lazy_static;
use spin::{lazy, mutex, Mutex, Once, RwLock};

use crate::{
    arch::config::PAGE_SIZE_BITS,
    ext4::inode::Ext4InodeDisk,
    fs::{
        file::{FileOp, OpenFlags},
        inode::InodeOp,
        kstat::Kstat,
        path::Path,
        uapi::Whence,
        FileOld,
    },
    mm::{MapPermission, VPNRange, VirtPageNum},
    syscall::errno::{Errno, SyscallRet},
    task::{current_task, get_task},
    timer::TimeSpec,
};

use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

/*
    为了提高效率，在查询/proc/[PID]/...时，没有为每个任务创建时建立对应文件夹，
    而是统一导向至/proc/pid/...文件
*/

lazy_static! {
    /// 用于记录查询的目标PID
    pub static ref TARGERT_PID: Arc<Mutex<TargetPid>> = Arc::new(Mutex::new(TargetPid::new(0)));
}
pub static PID_STAT: Once<Arc<dyn FileOp>> = Once::new();
pub static SELF_STAT: Once<Arc<dyn FileOp>> = Once::new();

/// 记录当前查询的目标PID，仅用于替换/proc/pid/...中的pid
pub fn record_target_pid(pid: usize) {
    let mut target_pid = TARGERT_PID.lock();
    target_pid.pid = pid;
}

pub struct PidInode {
    pub inner: RwLock<PidInodeInner>,
}
pub struct PidInodeInner {
    pub inode_on_disk: Ext4InodeDisk,
}

impl PidInode {
    pub fn new(inode_on_disk: Ext4InodeDisk) -> Arc<Self> {
        Arc::new(PidInode {
            inner: RwLock::new(PidInodeInner { inode_on_disk }),
        })
    }
}

impl InodeOp for PidInode {
    fn getattr(&self) -> Kstat {
        let mut kstat = Kstat::new();
        let inner_guard = self.inner.read();
        let inode_on_disk = &inner_guard.inode_on_disk;

        kstat.mode = inode_on_disk.get_mode();
        kstat.uid = inode_on_disk.get_uid() as u32;
        kstat.gid = inode_on_disk.get_gid() as u32;
        kstat.nlink = inode_on_disk.get_nlinks() as u32;
        kstat.size = inode_on_disk.get_size();

        // Todo: 目前没有更新时间戳
        kstat.atime = inode_on_disk.get_atime();
        kstat.mtime = inode_on_disk.get_mtime();
        kstat.ctime = inode_on_disk.get_ctime();
        // Todo: 创建时间
        // kstat.btime = TimeSpec {
        //     sec: inode_on_disk.create_time as usize,
        //     nsec: (inode_on_disk.create_time_extra >> 2) as usize,
        // };
        // Todo: Direct I/O 对齐参数
        // inode版本号
        kstat.change_cookie = inode_on_disk.generation as u64;

        kstat
    }
    fn get_resident_page_count(&self) -> usize {
        0
    }

    /* get/set属性方法 */
    // Todo
    fn get_mode(&self) -> u16 {
        self.inner.read().inode_on_disk.get_mode()
    }
    /* 时间戳 */
    fn get_atime(&self) -> TimeSpec {
        self.inner.read().inode_on_disk.get_atime()
    }
    fn set_atime(&self, atime: TimeSpec) {
        self.inner.write().inode_on_disk.set_atime(atime);
    }
    fn get_mtime(&self) -> TimeSpec {
        self.inner.read().inode_on_disk.get_mtime()
    }
    fn set_mtime(&self, mtime: TimeSpec) {
        self.inner.write().inode_on_disk.set_mtime(mtime);
    }
    fn get_ctime(&self) -> TimeSpec {
        self.inner.read().inode_on_disk.get_ctime()
    }
    fn set_ctime(&self, ctime: TimeSpec) {
        self.inner.write().inode_on_disk.set_ctime(ctime);
    }
}

pub struct TargetPid {
    pub pid: usize,
}

impl TargetPid {
    pub fn new(pid: usize) -> Self {
        TargetPid { pid }
    }
}

pub struct PidStatFile {
    pub path: Arc<Path>,
    pub inode: Arc<dyn InodeOp>,
    pub flags: OpenFlags,
    pub inner: RwLock<PidStatFileInner>,
}

pub struct PidStatFileInner {
    pub offset: usize,
}

impl PidStatFile {
    pub fn new(path: Arc<Path>, inode: Arc<dyn InodeOp>, flags: OpenFlags) -> Arc<Self> {
        Arc::new(PidStatFile {
            path,
            inode,
            flags,
            inner: RwLock::new(PidStatFileInner { offset: 0 }),
        })
    }
    pub fn add_offset(&self, offset: usize) {
        self.inner.write().offset += offset;
    }
}

impl FileOp for PidStatFile {
    fn get_inode(&self) -> Arc<dyn InodeOp> {
        self.inode.clone()
    }
    fn read(&self, buf: &mut [u8]) -> SyscallRet {
        let tid = TARGERT_PID.lock().pid;
        if let Some(task) = get_task(tid) {
            let task_stat = task.stat();
            let len = task_stat.len();
            if self.inner.read().offset >= len {
                return Ok(0);
            }
            buf[..len].copy_from_slice(task_stat.as_bytes());
            self.add_offset(len);
            Ok(len)
        } else {
            return Err(Errno::ENOENT);
        }
    }
    fn seek(&self, offset: isize, whence: Whence) -> SyscallRet {
        let mut inner_guard = self.inner.write();
        match whence {
            crate::fs::uapi::Whence::SeekSet => {
                if offset < 0 {
                    panic!("SeekSet offset < 0");
                }
                inner_guard.offset = offset as usize;
            }
            crate::fs::uapi::Whence::SeekCur => {
                inner_guard.offset = inner_guard.offset.checked_add_signed(offset).unwrap();
            }
            crate::fs::uapi::Whence::SeekEnd => {
                let tid = TARGERT_PID.lock().pid;
                if let Some(task) = get_task(tid) {
                    inner_guard.offset = task.stat().len().checked_add_signed(offset).unwrap();
                } else {
                    return Err(Errno::ENOENT);
                }
            }
            _ => {
                log::warn!("Unsupported whence: {:?}", whence);
                return Err(Errno::EINVAL); // Invalid argument
            }
        }
        Ok(inner_guard.offset)
    }
    fn readable(&self) -> bool {
        true
    }
    fn get_flags(&self) -> OpenFlags {
        self.flags
    }
}

pub struct SelfStatFile {
    pub path: Arc<Path>,
    pub inode: Arc<dyn InodeOp>,
    pub flags: OpenFlags,
    pub inner: RwLock<SelfStatFileInner>,
}

pub struct SelfStatFileInner {
    pub offset: usize,
}

impl SelfStatFile {
    pub fn new(path: Arc<Path>, inode: Arc<dyn InodeOp>, flags: OpenFlags) -> Arc<Self> {
        Arc::new(SelfStatFile {
            path,
            inode,
            flags,
            inner: RwLock::new(SelfStatFileInner { offset: 0 }),
        })
    }
    pub fn add_offset(&self, offset: usize) {
        self.inner.write().offset += offset;
    }
}

impl FileOp for SelfStatFile {
    fn get_inode(&self) -> Arc<dyn InodeOp> {
        self.inode.clone()
    }
    fn read(&self, buf: &mut [u8]) -> SyscallRet {
        let task = current_task();
        let task_stat = task.stat();
        let len = task_stat.len();
        if self.inner.read().offset >= len {
            return Ok(0);
        }
        buf[..len].copy_from_slice(task_stat.as_bytes());
        self.add_offset(len);
        Ok(len)
    }
    fn seek(&self, offset: isize, whence: Whence) -> SyscallRet {
        let mut inner_guard = self.inner.write();
        match whence {
            crate::fs::uapi::Whence::SeekSet => {
                if offset < 0 {
                    panic!("SeekSet offset < 0");
                }
                inner_guard.offset = offset as usize;
            }
            crate::fs::uapi::Whence::SeekCur => {
                inner_guard.offset = inner_guard.offset.checked_add_signed(offset).unwrap();
            }
            crate::fs::uapi::Whence::SeekEnd => {
                let tid = TARGERT_PID.lock().pid;
                if let Some(task) = get_task(tid) {
                    inner_guard.offset = task.stat().len().checked_add_signed(offset).unwrap();
                } else {
                    return Err(Errno::ENOENT);
                }
            }
            _ => {
                log::warn!("Unsupported whence: {:?}", whence);
                return Err(Errno::EINVAL); // Invalid argument
            }
        }
        Ok(inner_guard.offset)
    }
    fn readable(&self) -> bool {
        true
    }
    fn get_flags(&self) -> OpenFlags {
        self.flags
    }
}

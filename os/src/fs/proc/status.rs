use core::{default, mem, str};

use lazy_static::lazy_static;
use spin::{lazy, mutex, Once, RwLock};

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
    task::current_task,
    timer::TimeSpec,
};

use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

pub static STATUS: Once<Arc<dyn FileOp>> = Once::new();

pub struct StatusInode {
    pub inner: RwLock<StatusInodeInner>,
}
pub struct StatusInodeInner {
    pub inode_on_disk: Ext4InodeDisk,
}

impl StatusInode {
    pub fn new(inode_on_disk: Ext4InodeDisk) -> Arc<Self> {
        Arc::new(StatusInode {
            inner: RwLock::new(StatusInodeInner { inode_on_disk }),
        })
    }
}

impl InodeOp for StatusInode {
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

pub struct StatusFile {
    pub path: Arc<Path>,
    pub inode: Arc<dyn InodeOp>,
    pub flags: OpenFlags,
    pub inner: RwLock<StatusFileInner>,
}

pub struct StatusFileInner {
    pub offset: usize,
}

impl StatusFile {
    pub fn new(path: Arc<Path>, inode: Arc<dyn InodeOp>, flags: OpenFlags) -> Arc<Self> {
        Arc::new(StatusFile {
            path,
            inode,
            flags,
            inner: RwLock::new(StatusFileInner { offset: 0 }),
        })
    }
    pub fn add_offset(&self, offset: usize) {
        self.inner.write().offset += offset;
    }
}

impl FileOp for StatusFile {
    fn get_inode(&self) -> Arc<dyn InodeOp> {
        self.inode.clone()
    }
    fn read(&self, buf: &mut [u8]) -> SyscallRet {
        let task_info = current_task().info();
        let len = task_info.len();
        if self.inner.read().offset >= len {
            return Ok(0);
        }
        buf[..len].copy_from_slice(task_info.as_bytes());
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
                inner_guard.offset = current_task()
                    .info()
                    .len()
                    .checked_add_signed(offset)
                    .unwrap();
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

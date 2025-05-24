use core::{default, str};

use lazy_static::lazy_static;
use spin::{lazy, mutex, Once, RwLock};

use crate::{
    ext4::inode::Ext4InodeDisk,
    fs::{
        file::{FileOp, OpenFlags},
        inode::InodeOp,
        kstat::Kstat,
        path::Path,
        uapi::Whence,
        FileOld,
    },
    syscall::errno::SyscallRet,
    task::current_task,
    timer::TimeSpec,
};

use alloc::{
    string::{String, ToString},
    sync::Arc,
};

pub static EXE: Once<Arc<dyn FileOp>> = Once::new();

pub struct ExeInode {
    pub inner: RwLock<ExeInodeInner>,
}
pub struct ExeInodeInner {
    pub inode_on_disk: Ext4InodeDisk,
}

impl ExeInode {
    pub fn new(inode_on_disk: Ext4InodeDisk) -> Arc<Self> {
        Arc::new(ExeInode {
            inner: RwLock::new(ExeInodeInner { inode_on_disk }),
        })
    }
}

impl InodeOp for ExeInode {
    fn get_link(&self) -> String {
        current_task().exe_path()
    }
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

pub struct ExeFile {
    pub path: Arc<Path>,
    pub inode: Arc<dyn InodeOp>,
    pub flags: OpenFlags,
}

impl ExeFile {
    pub fn new(path: Arc<Path>, inode: Arc<dyn InodeOp>, flags: OpenFlags) -> Arc<Self> {
        Arc::new(ExeFile { path, inode, flags })
    }
}

impl FileOp for ExeFile {
    fn get_inode(&self) -> Arc<dyn InodeOp> {
        self.inode.clone()
    }
}

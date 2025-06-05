use core::{default, str, sync::atomic::AtomicUsize};

use lazy_static::lazy_static;
use spin::{lazy, mutex, Once, RwLock};

use crate::{
    ext4::{
        dentry,
        inode::{Ext4Inode, Ext4InodeDisk},
    },
    fs::{
        dentry::{Dentry, DentryFlags},
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
    format,
    string::{String, ToString},
    sync::Arc,
};

pub static FD_FILE: Once<Arc<dyn FileOp>> = Once::new();
pub static FD: AtomicUsize = AtomicUsize::new(0);

pub fn record_fd(fd: usize) {
    FD.store(fd, core::sync::atomic::Ordering::SeqCst);
}

// 符号链接
pub struct FdInode {
    link: String,
}
impl FdInode {
    pub fn new(link: String) -> Arc<Self> {
        Arc::new(FdInode { link })
    }
}
impl InodeOp for FdInode {
    fn get_link(&self) -> String {
        self.link.clone()
    }
}

pub struct FdDirInode {
    pub inner: RwLock<FdDirInodeInner>,
}
pub struct FdDirInodeInner {
    pub inode_on_disk: Ext4InodeDisk,
}

impl FdDirInode {
    pub fn new(inode_on_disk: Ext4InodeDisk) -> Arc<Self> {
        Arc::new(FdDirInode {
            inner: RwLock::new(FdDirInodeInner { inode_on_disk }),
        })
    }
}

impl InodeOp for FdDirInode {
    fn can_lookup(&self) -> bool {
        true
    }
    fn lookup<'a>(&'a self, name: &str, parent_entry: Arc<Dentry>) -> Arc<Dentry> {
        let dentry: Arc<Dentry> = Dentry::negative(
            format!("{}/{}", parent_entry.absolute_path, name),
            Some(parent_entry.clone()),
        );
        let fd = match name.parse::<usize>() {
            Ok(fd) => fd,
            Err(_) => {
                // 返回负目录项
                return dentry;
            }
        };
        let task = current_task();
        match task.fd_table().get_file(fd) {
            Some(file) => {
                // 返回符号链接
                let absolute_path = file.get_path().dentry.absolute_path.clone();
                let fd_inode = FdInode::new(absolute_path);
                // 关联到dentry
                dentry.inner.lock().inode = Some(fd_inode.clone());
                // 更新dentry flags, 去掉负目录项标志, 添加符号链接标志
                dentry
                    .flags
                    .write()
                    .update_type_from_negative(DentryFlags::DCACHE_SYMLINK_TYPE);
                return dentry;
            }
            None => {
                // 返回负目录项
                return dentry;
            }
        };
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
    fn set_mode(&self, mode: u16) {
        self.inner.write().inode_on_disk.set_mode(mode);
    }
}

pub struct FdFile {
    pub path: Arc<Path>,
    pub inode: Arc<dyn InodeOp>,
    pub flags: OpenFlags,
}

impl FdFile {
    pub fn new(path: Arc<Path>, inode: Arc<dyn InodeOp>, flags: OpenFlags) -> Arc<Self> {
        Arc::new(FdFile { path, inode, flags })
    }
}

impl FileOp for FdFile {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn get_inode(&self) -> Arc<dyn InodeOp> {
        self.inode.clone()
    }
    fn get_flags(&self) -> OpenFlags {
        self.flags
    }
}

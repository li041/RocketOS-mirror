use alloc::sync::Arc;
use spin::{Once, RwLock};

use crate::{
    arch::mm::copy_to_user,
    ext4::inode::{Ext4InodeDisk, S_IFCHR},
    fs::{
        file::{FileOp, OpenFlags},
        inode::InodeOp,
        kstat::Kstat,
        path::Path,
        uapi::DevT,
    },
    syscall::errno::{Errno, SyscallRet},
    timer::TimeSpec,
    utils::DateTime,
};
pub static ZERO: Once<Arc<ZeroFile>> = Once::new();

pub struct ZeroInode {
    pub inode_num: usize,
    pub inner: RwLock<ZeroInodeInner>,
}

struct ZeroInodeInner {
    pub inode_on_disk: Ext4InodeDisk,
}

impl ZeroInodeInner {
    pub fn new(inode_on_disk: Ext4InodeDisk) -> Self {
        Self { inode_on_disk }
    }
}

impl ZeroInode {
    pub fn new(ino: usize, inode_mode: u16, major: u32, minor: u32) -> Arc<Self> {
        assert!(inode_mode & S_IFCHR == S_IFCHR);
        let inner = ZeroInodeInner::new(Ext4InodeDisk::new_chr(inode_mode, major, minor));
        Arc::new(ZeroInode {
            inode_num: ino,
            inner: RwLock::new(inner),
        })
    }
}
impl InodeOp for ZeroInode {
    fn can_lookup(&self) -> bool {
        // /dev/zero是一个特殊文件, 不是目录
        false
    }
    fn getattr(&self) -> Kstat {
        let mut kstat = Kstat::new();
        let inner_guard = self.inner.read();
        let inode_on_disk = &inner_guard.inode_on_disk;
        kstat.ino = self.inode_num as u64;
        kstat.dev = 0;
        let (major, minor) = inode_on_disk.get_devt();
        let devt = DevT::makedev(major, minor);
        kstat.rdev = u64::from(devt); // 通常特殊文件才会有 rdev

        kstat.mode = inode_on_disk.get_mode();
        kstat.uid = inode_on_disk.get_uid() as u32;
        kstat.gid = inode_on_disk.get_gid() as u32;
        kstat.size = 0;
        kstat.atime = inode_on_disk.get_atime();
        kstat.mtime = inode_on_disk.get_mtime();
        kstat.ctime = inode_on_disk.get_ctime();
        kstat.nlink = 1;
        kstat.blocks = 0;
        kstat
    }
    /* get/set属性方法 */
    // Todo
    fn get_devt(&self) -> (u32, u32) {
        self.inner.read().inode_on_disk.get_devt()
    }
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

pub struct ZeroFile {
    pub path: Arc<Path>,
    pub inode: Arc<dyn InodeOp>,
    pub flags: OpenFlags,
}
// 读时返回无限个 0，写时忽略内容（通常成功返回写入长度但不实际存储）
impl ZeroFile {
    pub fn new(path: Arc<Path>, inode: Arc<dyn InodeOp>, flags: OpenFlags) -> Arc<Self> {
        Arc::new(Self { path, inode, flags })
    }
}

impl FileOp for ZeroFile {
    fn read(&self, buf: &mut [u8]) -> SyscallRet {
        buf.fill(0);
        Ok(buf.len())
    }
    fn write(&self, buf: &[u8]) -> SyscallRet {
        Ok(buf.len())
    }
    fn readable(&self) -> bool {
        true
    }
}

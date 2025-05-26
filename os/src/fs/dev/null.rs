use crate::{
    arch::mm::copy_to_user,
    ext4::inode::{Ext4InodeDisk, S_IFCHR},
    fs::{
        file::{FileOp, OpenFlags},
        inode::InodeOp,
        kstat::Kstat,
        path::Path,
        uapi::{DevT, Whence},
    },
    syscall::errno::{Errno, SyscallRet},
    timer::TimeSpec,
    utils::DateTime,
};

use alloc::sync::Arc;

use spin::{Mutex, Once, RwLock};

pub static NULL: Once<Arc<dyn FileOp>> = Once::new();

pub struct NullInode {
    pub inode_num: usize,
    pub inner: RwLock<NullInodeInner>,
}

struct NullInodeInner {
    pub inode_on_disk: Ext4InodeDisk,
}

impl NullInodeInner {
    pub fn new(inode_on_disk: Ext4InodeDisk) -> Self {
        Self { inode_on_disk }
    }
}
impl NullInode {
    pub fn new(ino: usize, inode_mode: u16, major: u32, minor: u32) -> Arc<Self> {
        assert!(inode_mode & S_IFCHR == S_IFCHR);
        let inner = NullInodeInner::new(Ext4InodeDisk::new_chr(inode_mode, major, minor));
        Arc::new(NullInode {
            inode_num: ino,
            inner: RwLock::new(inner),
        })
    }
}
impl InodeOp for NullInode {
    fn can_lookup(&self) -> bool {
        // /dev/null是一个特殊文件, 不是目录
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
    fn get_resident_page_count(&self) -> usize {
        0
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
    fn set_mode(&self, mode: u16) {
        self.inner.write().inode_on_disk.set_mode(mode);
    }
}

pub struct NullFile {
    pub path: Arc<Path>,
    pub inode: Arc<dyn InodeOp>,
    pub flags: OpenFlags,
    pub inner: Mutex<NullFileInner>,
}

struct NullFileInner {
    offset: usize,
}

impl NullFile {
    pub fn new(path: Arc<Path>, inode: Arc<dyn InodeOp>, flags: OpenFlags) -> Arc<Self> {
        Arc::new(Self {
            path,
            inode,
            flags,
            inner: Mutex::new(NullFileInner { offset: 0 }),
        })
    }
}

impl FileOp for NullFile {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn read(&self, _buf: &mut [u8]) -> SyscallRet {
        // 从/dev/null读取数据, 总是会立刻返回EOF, 表示没有数据可读
        Ok(0)
    }
    fn write(&self, buf: &[u8]) -> SyscallRet {
        Ok(buf.len())
    }
    fn readable(&self) -> bool {
        true
    }
    fn writable(&self) -> bool {
        true
    }
    fn seek(&self, offset: isize, whence: Whence) -> SyscallRet {
        let mut inner = self.inner.lock();
        match whence {
            Whence::SeekSet => inner.offset = offset as usize,
            Whence::SeekCur => inner.offset = (inner.offset as isize + offset) as usize,
            Whence::SeekEnd => inner.offset = 0,
        }
        Ok(inner.offset)
    }
    fn get_inode(&self) -> Arc<dyn InodeOp> {
        self.inode.clone()
    }
    fn get_flags(&self) -> OpenFlags {
        self.flags
    }
}

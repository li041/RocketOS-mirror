use core::{ops::DerefMut, ptr::copy_nonoverlapping};

use alloc::{sync::Arc, vec};
// use riscv::interrupt::Mutex;
use crate::{
    arch::{config::PAGE_SIZE_BITS, mm::copy_to_user},
    ext4::inode::{Ext4InodeDisk, S_IFCHR},
    fs::{
        file::{FileOp, OpenFlags},
        inode::InodeOp,
        kstat::Kstat,
        path::Path,
        uapi::DevT,
    },
    mm::VirtAddr,
    syscall::errno::SyscallRet,
    task::current_task,
    timer::TimeSpec,
};
use rand::RngCore;
use rand::{rngs::SmallRng, Fill, SeedableRng};
use spin::RwLock;
use spin::{Mutex, Once};
pub static URANDOM: Once<Arc<UrandomFile>> = Once::new();
pub struct UrandomInode {
    pub inode_num: usize,
    pub inner: RwLock<UrandomInodeInner>,
}
pub struct UrandomInodeInner {
    pub inode_on_disk: Ext4InodeDisk,
}
impl UrandomInodeInner {
    pub fn new(inode_on_disk: Ext4InodeDisk) -> Self {
        Self { inode_on_disk }
    }
}
impl UrandomInode {
    pub fn new(ino: usize, inode_mode: u16, major: u32, minor: u32) -> Arc<Self> {
        debug_assert!(inode_mode & S_IFCHR == S_IFCHR);
        let inner = UrandomInodeInner::new(Ext4InodeDisk::new_chr(inode_mode, major, minor));
        Arc::new(UrandomInode {
            inode_num: ino,
            inner: RwLock::new(inner),
        })
    }
}

impl InodeOp for UrandomInode {
    fn can_lookup(&self) -> bool {
        // /dev/urandom是一个特殊文件, 不是目录
        false
    }
    fn getattr(&self) -> crate::fs::kstat::Kstat {
        let mut kstat = Kstat::new();
        let inner_guard = self.inner.read();
        let inode_on_disk = &inner_guard.inode_on_disk;
        kstat.ino = self.inode_num as u64;
        kstat.dev = 0;
        let (major, minor) = inode_on_disk.get_devt();
        let devt = DevT::new_encode_dev(major, minor);
        kstat.rdev = u64::from(devt);

        kstat.mode = inode_on_disk.get_mode();
        kstat.uid = inode_on_disk.get_uid() as u32;
        kstat.gid = inode_on_disk.get_gid() as u32;
        kstat.nlink = inode_on_disk.get_nlinks() as u32;
        kstat.size = 0;
        kstat.atime = inode_on_disk.get_atime();
        kstat.mtime = inode_on_disk.get_mtime();
        kstat.ctime = inode_on_disk.get_ctime();
        kstat.change_cookie = inode_on_disk.generation as u64;

        kstat
    }
    fn get_devt(&self) -> (u32, u32) {
        self.inner.read().inode_on_disk.get_devt()
    }
    fn get_resident_page_count(&self) -> usize {
        0
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

pub struct RandomDev(Mutex<SmallRng>);

impl Default for RandomDev {
    fn default() -> Self {
        let rng = SmallRng::from_seed([0; 32]);
        Self(Mutex::new(rng))
    }
}
pub struct UrandomFile {
    pub path: Arc<Path>,
    pub inode: Arc<dyn InodeOp>,
    pub flags: OpenFlags,
    pub random: RandomDev,
}
impl UrandomFile {
    pub fn new(path: Arc<Path>, inode: Arc<dyn InodeOp>, flags: OpenFlags) -> Arc<Self> {
        Arc::new(Self {
            path,
            inode,
            flags,
            random: RandomDev::default(),
        })
    }
}
impl FileOp for UrandomFile {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn readable(&self) -> bool {
        true
    }
    // fn read<'a>(&'a self, buf: &'a mut [u8]) -> usize {
    //     // let randomdev=self.random.0.lock();
    //     // buf.fill(self.0.lock().deref_mut());
    //     use rand_core::RngCore;

    fn read(&self, buf: &mut [u8]) -> SyscallRet {
        let mut rng = self.random.0.lock();
        // let mut kernel_buf= vec![0u8; 32];
        // let task=current_task();
        // let addr
        rng.fill_bytes(buf);
        // log::error!("read buf: {:?}", buf.as_ptr());
        // copy_to_user(buf.as_mut_ptr(), kernel_buf.as_ptr(), kernel_buf.len());
        // log::error!("read buf: {:?},buf len {}", buf,buf.len());
        // kernel_buf.len()
        Ok(buf.len())
    }

    // }
    fn write<'a>(&'a self, buf: &'a [u8]) -> SyscallRet {
        // 这里返回写入的长度
        // println!("2222");
        Ok(buf.len())
    }
    fn writable(&self) -> bool {
        true
    }
    fn get_inode(&self) -> Arc<dyn InodeOp> {
        self.inode.clone()
    }
    fn get_path(&self) -> Arc<Path> {
        self.path.clone()
    }
    fn get_flags(&self) -> OpenFlags {
        self.flags
    }
}

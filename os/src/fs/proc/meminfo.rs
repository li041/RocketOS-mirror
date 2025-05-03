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
    timer::TimeSpec,
};

use alloc::{
    string::{String, ToString},
    sync::Arc,
};

pub static MEMINFO: Once<Arc<dyn FileOp>> = Once::new();

pub struct MemInfoInode {
    pub inner: RwLock<MemInfoInodeInner>,
}

pub struct MemInfoInodeInner {
    pub inode_on_disk: Ext4InodeDisk,
}

impl MemInfoInode {
    pub fn new(inode_on_disk: Ext4InodeDisk) -> Arc<Self> {
        Arc::new(MemInfoInode {
            inner: RwLock::new(MemInfoInodeInner { inode_on_disk }),
        })
    }
}

impl InodeOp for MemInfoInode {
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

pub struct MemInfoFile {
    pub path: Arc<Path>,
    pub inode: Arc<dyn InodeOp>,
    pub flags: OpenFlags,
    pub inner: RwLock<MemInfoFileInner>,
}

#[derive(Default)]
struct MemInfoFileInner {
    pub offset: usize,
}

impl MemInfoFile {
    pub fn new(path: Arc<Path>, inode: Arc<dyn InodeOp>, flags: OpenFlags) -> Arc<Self> {
        Arc::new(MemInfoFile {
            path,
            inode,
            flags,
            inner: RwLock::new(MemInfoFileInner::default()),
        })
    }
    pub fn add_offset(&self, offset: usize) {
        self.inner.write().offset += offset;
    }
}

impl FileOp for MemInfoFile {
    fn read(&self, buf: &mut [u8]) -> usize {
        let info = FAKEMEMINFO.read().serialize();
        let len = info.len();
        if self.inner.read().offset >= len {
            return 0;
        }
        buf[..len].copy_from_slice(info.as_bytes());
        self.add_offset(len);
        len
    }
    fn readable(&self) -> bool {
        true
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
                inner_guard.offset = inner_guard.offset.checked_add_signed(offset).unwrap()
            }
            crate::fs::uapi::Whence::SeekEnd => {
                inner_guard.offset = FAKEMEMINFO
                    .read()
                    .serialize()
                    .len()
                    .checked_add_signed(offset)
                    .unwrap();
            }
        }
        Ok(inner_guard.offset)
    }
    fn get_inode(&self) -> Arc<dyn InodeOp> {
        self.inode.clone()
    }
}

lazy_static! {
    static ref FAKEMEMINFO: RwLock<FakeMemInfo> = RwLock::new(FakeMemInfo::new());
}

const TOTAL_MEM: usize = 16251136;
const FREE_MEM: usize = 327680;
const BUFFER: usize = 373336;
const CACHED: usize = 10391984;
const TOTAL_SWAP: usize = 4194300;
struct FakeMemInfo {
    /// General memory
    pub total_mem: usize,
    pub free_mem: usize,
    pub avail_mem: usize,
    /// Buffer and cache
    pub buffers: usize,
    pub cached: usize,
    /// Swap space
    pub total_swap: usize,
    pub free_swap: usize,
    /// Share memory
    pub shmem: usize,
    pub slab: usize,
}
impl FakeMemInfo {
    pub const fn new() -> Self {
        Self {
            total_mem: TOTAL_MEM,
            free_mem: FREE_MEM,
            avail_mem: TOTAL_MEM - FREE_MEM,
            buffers: BUFFER,
            cached: CACHED,
            total_swap: TOTAL_SWAP,
            free_swap: TOTAL_SWAP,
            shmem: 0,
            slab: 0,
        }
    }
    pub fn serialize(&self) -> String {
        let mut res = "".to_string();
        let end = " KB\n";
        let total_mem = "MemTotal:\t".to_string() + self.total_mem.to_string().as_str() + end;
        let free_mem = "MemFree:\t".to_string() + self.free_mem.to_string().as_str() + end;
        let avail_mem = "MemAvailable:\t".to_string() + self.avail_mem.to_string().as_str() + end;
        let buffers = "Buffers:\t".to_string() + self.buffers.to_string().as_str() + end;
        let cached = "Cached:\t".to_string() + self.cached.to_string().as_str() + end;
        let cached_swap = "SwapCached:\t".to_string() + 0.to_string().as_str() + end;
        let total_swap = "SwapTotal:\t".to_string() + self.total_swap.to_string().as_str() + end;
        let free_swap = "SwapFree:\t".to_string() + self.free_swap.to_string().as_str() + end;
        let shmem = "Shmem:\t".to_string() + self.shmem.to_string().as_str() + end;
        let slab = "Slab:\t".to_string() + self.slab.to_string().as_str() + end;
        res += total_mem.as_str();
        res += free_mem.as_str();
        res += avail_mem.as_str();
        res += buffers.as_str();
        res += cached.as_str();
        res += cached_swap.as_str();
        res += total_swap.as_str();
        res += free_swap.as_str();
        res += shmem.as_str();
        res += slab.as_str();
        res
    }
}

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
    syscall::errno::{Errno, SyscallRet},
    timer::TimeSpec,
};

use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
};

pub static PIDMAX: Once<Arc<dyn FileOp>> = Once::new();

pub struct PidMaxInode {
    pub inner: RwLock<PidMaxInodeInner>,
}

pub struct PidMaxInodeInner {
    pub inode_on_disk: Ext4InodeDisk,
}

impl PidMaxInode {
    pub fn new(inode_on_disk: Ext4InodeDisk) -> Arc<Self> {
        Arc::new(PidMaxInode {
            inner: RwLock::new(PidMaxInodeInner { inode_on_disk }),
        })
    }
}

impl InodeOp for PidMaxInode {
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

pub struct PidMaxFile {
    pub path: Arc<Path>,
    pub inode: Arc<dyn InodeOp>,
    pub flags: OpenFlags,
    pub inner: RwLock<PidMaxFileInner>,
}

#[derive(Default)]
pub struct PidMaxFileInner {
    pub offset: usize,
}

impl PidMaxFile {
    pub fn new(path: Arc<Path>, inode: Arc<dyn InodeOp>, flags: OpenFlags) -> Arc<Self> {
        Arc::new(PidMaxFile {
            path,
            inode,
            flags,
            inner: RwLock::new(PidMaxFileInner::default()),
        })
    }
    pub fn add_offset(&self, offset: usize) {
        self.inner.write().offset += offset;
    }
}

impl FileOp for PidMaxFile {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn read(&self, buf: &mut [u8]) -> SyscallRet {
        let info = FAKEPidMax.read().serialize();
        let len = info.len();
        if self.inner.read().offset >= len {
            return Ok(0);
        }
        buf[..len].copy_from_slice(info.as_bytes());
        self.add_offset(len);
        Ok(len)
    }
    fn readable(&self) -> bool {
        true
    }
    fn write(&self, buf: &[u8]) -> SyscallRet {
        let mut inner_guard = self.inner.write();
        let info = str::from_utf8(buf).map_err(|_| Errno::EINVAL)?;
        if let Ok(pid_max) = info.trim().parse::<usize>() {
            FAKEPidMax.write().pid_max = pid_max;
            inner_guard.offset += buf.len();
            Ok(buf.len())
        } else {
            Err(Errno::EINVAL)
        }
    }
    fn writable(&self) -> bool {
        true
    }
    fn seek(&self, offset: isize, whence: Whence) -> SyscallRet {
        let mut inner_guard = self.inner.write();
        match whence {
            crate::fs::uapi::Whence::SeekSet => {
                if offset < 0 {
                    return Err(Errno::EINVAL);
                }
                inner_guard.offset = offset as usize;
            }
            crate::fs::uapi::Whence::SeekCur => {
                inner_guard.offset = inner_guard.offset.checked_add_signed(offset).unwrap()
            }
            crate::fs::uapi::Whence::SeekEnd => {
                inner_guard.offset = FAKEPidMax
                    .read()
                    .serialize()
                    .len()
                    .checked_add_signed(offset)
                    .unwrap();
            }
            _ => {
                log::warn!("Unsupported whence in PidMaxFile::seek: {:?}", whence);
                return Err(Errno::EINVAL);
            }
        }
        Ok(inner_guard.offset)
    }
    fn get_inode(&self) -> Arc<dyn InodeOp> {
        self.inode.clone()
    }
    fn get_flags(&self) -> OpenFlags {
        self.flags
    }
}

lazy_static! {
    static ref FAKEPidMax: RwLock<FakePidMax> = RwLock::new(FakePidMax::new());
}
struct FakePidMax {
    pub pid_max: usize,
}
impl FakePidMax {
    pub const fn new() -> Self {
        Self {
            pid_max: 32768, // 默认值
        }
    }
    pub fn serialize(&self) -> String {
        format!("{}\n", self.pid_max)
    }
}

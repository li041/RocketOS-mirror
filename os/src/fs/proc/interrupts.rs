use alloc::{
    format,
    string::String,
    sync::Arc,
    vec::Vec,
    vec,
};
use lazy_static::lazy_static;
use spin::{Mutex, Once, RwLock};

use crate::{
    ext4::inode::Ext4InodeDisk, fs::{
        file::{FileOp, OpenFlags},
        inode::InodeOp,
        kstat::Kstat,
        path::Path, uapi::Whence,
    }, syscall::errno::{Errno, SyscallRet}, timer::TimeSpec
};

pub static INTERRUPTS: Once<Arc<dyn FileOp>> = Once::new();

pub struct InterruptsInode {
    pub inner: RwLock<InterruptsInodeInner>,
}

pub struct InterruptsInodeInner {
    pub inode_on_disk: Ext4InodeDisk,
}

impl InterruptsInode {
    pub fn new(inode_on_disk: Ext4InodeDisk) -> Arc<Self> {
        Arc::new(InterruptsInode {
            inner: RwLock::new(InterruptsInodeInner { inode_on_disk }),
        })
    }
}

impl InodeOp for InterruptsInode {
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

pub struct InterruptsFile {
    pub path: Arc<Path>,
    pub inode: Arc<dyn InodeOp>,
    pub flags: OpenFlags,
    pub inner: RwLock<InterruptsFileInner>,
}

#[derive(Default)]
pub struct InterruptsFileInner {
    pub offset: usize,
}

impl InterruptsFile {
    pub fn new(path: Arc<Path>, inode: Arc<dyn InodeOp>, flags: OpenFlags) -> Arc<Self> {
        Arc::new(InterruptsFile {
            path,
            inode,
            flags,
            inner: RwLock::new(InterruptsFileInner::default()),
        })
    }
    pub fn add_offset(&self, offset: usize) {
        self.inner.write().offset += offset;
    }
}

impl FileOp for InterruptsFile {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn read(&self, buf: &mut [u8]) -> SyscallRet {
        let info = INTERRUPTS_RECORD.lock().serialize();
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
                inner_guard.offset = INTERRUPTS_RECORD
                    .lock()
                    .serialize()
                    .len()
                    .checked_add_signed(offset)
                    .unwrap();
            }
            _ => {
                log::warn!("[CPUInfoFile::seek] Unsupported whence: {:?}", whence);
                return Err(Errno::EINVAL); // Invalid argument
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
    fn writable(&self) -> bool {
        false
    }
}

pub fn record_interrupt(interrupt: usize) {
    let mut interrupts_guard = INTERRUPTS_RECORD.lock();
    if interrupt < interrupts_guard.interrupts.len() {
        interrupts_guard.interrupts[interrupt] += 1;
    } else {
        log::warn!("Interrupt {} is out of range", interrupt);
    }
}

lazy_static! {
    static ref INTERRUPTS_RECORD: Mutex<InterruptsInfo> = Mutex::new(InterruptsInfo::new());
}

struct InterruptsInfo {
    pub interrupts: Vec<usize>,
}

impl InterruptsInfo {
    pub fn new() -> Self {
        InterruptsInfo {
            interrupts: vec![0; 32], // 假设最多32个中断，目前riscv只支持11种，loongarch支持13种
        }
    }

    pub fn serialize(&self) -> String {
        let mut info = String::new();
        #[cfg(target_arch = "riscv64")]
        for (i, count) in self.interrupts.iter().enumerate().take(11) {
            info.push_str(&format!("{}:\t{}\n", i, count));
        }
        #[cfg(target_arch = "loongarch64")]
        for (i, count) in self.interrupts.iter().enumerate().take(13) {
            info.push_str(&format!("{}:\t{}\n", i, count));
        }
        info
    }
}

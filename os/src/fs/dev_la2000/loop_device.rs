use alloc::boxed::Box;
use alloc::{sync::Arc, vec::Vec};
use lazy_static::lazy_static;
use spin::{Mutex, Once, RwLock};

use crate::{
    arch::mm::{copy_from_user, copy_to_user},
    ext4::inode::{Ext4InodeDisk, S_IFCHR},
    fs::{
        dentry::Dentry,
        file::{FileOp, OpenFlags},
        inode::InodeOp,
        kstat::Kstat,
        path::Path,
        uapi::DevT,
    },
    syscall::errno::{Errno, SyscallRet},
    task::current_task,
    timer::TimeSpec,
};

// linxu/inclue/uapi/linux/loop.h
pub const LOOP_SET_FD: usize = 0x4C00;
pub const LOOP_CLR_FD: usize = 0x4C01;
pub const LOOP_SET_STATUS: usize = 0x4C02;
pub const LOOP_GET_STATUS: usize = 0x4C03;

lazy_static! {
    static ref LOOP_MANAGER: Mutex<LoopManager> = Mutex::new(LoopManager::new(4));
}
pub static LOOP_CONTROL: Once<Arc<dyn FileOp>> = Once::new();

pub struct LoopManager {
    loops: Vec<Arc<LoopDevice>>,
}

impl LoopManager {
    fn new(num: usize) -> Self {
        Self {
            loops: Vec::with_capacity(num),
        }
    }

    pub fn get_free(&self) -> Option<usize> {
        for dev in &self.loops {
            if dev.backend_file.lock().is_none() {
                return Some(dev.device_id as usize);
            }
        }
        None
    }

    pub fn get(&self, id: usize) -> Option<Arc<LoopDevice>> {
        self.loops.get(id).cloned()
    }
}

pub fn insert_loop_device(loop_device: Arc<LoopDevice>, id: usize) {
    let mut loop_manager = LOOP_MANAGER.lock();
    if id < loop_manager.loops.len() {
        loop_manager.loops[id] = loop_device;
    } else {
        // Extend the vector if necessary
        loop_manager.loops.resize(id + 1, loop_device);
    }
}
pub fn get_loop_device(id: usize) -> Option<Arc<LoopDevice>> {
    LOOP_MANAGER.lock().get(id)
}

const LOOP_CTL_GET_FREE: usize = 0x4c82;

impl FileOp for LoopManager {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn ioctl(&self, op: usize, _arg_ptr: usize) -> SyscallRet {
        match op {
            LOOP_CTL_GET_FREE => {
                if let Some(id) = self.get_free() {
                    Ok(id)
                } else {
                    Err(Errno::ENODEV)
                }
            }
            _ => {
                panic!("Unsupported cmd: {}", op);
            }
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct LoopInfo {
    lo_device: u64,
    lo_inode: u64,
    lo_rdevice: u64,
    lo_offset: u64,
    lo_sizelimit: u64,
    lo_number: u32,
    lo_encrypt_type: u32,
    lo_encrypt_key_size: u32,
    lo_flags: u32,
    lo_encrypt_key: [u8; 32],
    lo_init: [u64; 2],
}

impl LoopInfo {
    pub fn new() -> Self {
        Self {
            lo_device: 0,
            lo_inode: 0,
            lo_rdevice: 0,
            lo_offset: 0,
            lo_sizelimit: 0,
            lo_number: 0,
            lo_encrypt_type: 0,
            lo_encrypt_key_size: 0,
            lo_flags: 0,
            lo_encrypt_key: [0; 32],
            lo_init: [0; 2],
        }
    }
}

pub struct LoopDevice {
    dentry: Arc<Dentry>,
    inode: Arc<dyn InodeOp>,
    flags: OpenFlags,
    device_id: u32,
    loop_info: RwLock<LoopInfo>,
    backend_file: Mutex<Option<Arc<dyn FileOp>>>,
}

impl LoopDevice {
    pub fn new(
        dentry: Arc<Dentry>,
        inode: Arc<dyn InodeOp>,
        flags: OpenFlags,
        id: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            dentry,
            inode,
            flags,
            device_id: id as u32,
            loop_info: RwLock::new(LoopInfo::new()),
            backend_file: Mutex::new(None),
        })
    }

    pub fn id(&self) -> u32 {
        self.device_id
    }
}

impl FileOp for LoopDevice {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn read(&self, buf: &mut [u8]) -> SyscallRet {
        let file = self.backend_file.lock();
        if let Some(f) = file.as_ref() {
            f.read(buf)
        } else {
            Err(Errno::ENODEV)
        }
    }

    fn write(&self, buf: &[u8]) -> SyscallRet {
        let file = self.backend_file.lock();
        if let Some(f) = file.as_ref() {
            match f.write_dio(buf) {
                Ok(len) => {
                    // 更新Loop设备的状态
                    // log::info!(
                    //     "LoopDevice write: {} bytes to device {}",
                    //     len,
                    //     self.device_id
                    // );
                    let mut loop_info = self.loop_info.write();
                    loop_info.lo_offset += len as u64; // 假设每次写入都从偏移量开始
                    Ok(len)
                }
                Err(e) => {
                    log::error!("LoopDevice write error: {:?}", e);
                    Err(e)
                }
            }
        } else {
            Err(Errno::ENODEV)
        }
    }

    fn ioctl(&self, cmd: usize, arg: usize) -> SyscallRet {
        log::info!("LoopDevice ioctl cmd: {:#x}, arg: {:#x}", cmd, arg);
        match cmd {
            LOOP_SET_FD => {
                let file = current_task()
                    .fd_table()
                    .get_file(arg)
                    .ok_or(Errno::EBADF)?;
                // *self.backend_file = Some(file);
                self.backend_file.lock().replace(file);
                Ok(0)
            }
            LOOP_CLR_FD => {
                if self.backend_file.lock().is_some() {
                    self.backend_file.lock().take();
                } else {
                    return Err(Errno::ENXIO);
                }
                Ok(0)
            }
            LOOP_SET_STATUS => {
                let loop_info_ptr = arg as *const LoopInfo;
                if loop_info_ptr.is_null() {
                    return Err(Errno::EINVAL);
                }
                let mut loop_info = self.loop_info.write();
                copy_from_user(loop_info_ptr, &mut *loop_info as *mut LoopInfo, 1)?;
                Ok(0)
            }
            LOOP_GET_STATUS => {
                let loop_info_ptr = arg as *mut LoopInfo;
                if loop_info_ptr.is_null() {
                    return Err(Errno::EINVAL);
                }
                let loop_info = self.loop_info.read();
                copy_to_user(loop_info_ptr, &*loop_info as *const LoopInfo, 1)?;
                Ok(0)
            }

            _ => Err(Errno::EINVAL),
        }
    }
    fn get_inode(&self) -> Arc<dyn InodeOp> {
        self.inode.clone()
    }
    fn get_flags(&self) -> OpenFlags {
        self.flags
    }
    fn writable(&self) -> bool {
        // Loop设备通常是可写的
        true
    }
}
pub struct LoopInode {
    pub inode_num: usize,
    pub inner: RwLock<LoopInodeInner>,
}

impl LoopInode {
    pub fn new(ino: usize, inode_mode: u16, major: u32, minor: u32) -> Arc<Self> {
        debug_assert!(inode_mode & S_IFCHR == S_IFCHR);
        let inner = LoopInodeInner::new(Ext4InodeDisk::new_blk(inode_mode, major, minor));
        Arc::new(LoopInode {
            inode_num: ino,
            inner: RwLock::new(inner),
        })
    }
}

impl InodeOp for LoopInode {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn can_lookup(&self) -> bool {
        // /dev/loop是一个特殊文件, 不是目录
        false
    }
    fn getattr(&self) -> Kstat {
        let mut kstat = Kstat::new();
        let inner_guard = self.inner.read();
        let inode_on_disk = &inner_guard.inode_on_disk;
        kstat.ino = self.inode_num as u64;
        kstat.dev = 0;
        let (major, minor) = inode_on_disk.get_devt();
        let devt = DevT::new_encode_dev(major, minor);
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
    fn getxattr(&self, _key: &str) -> Result<Vec<u8>, Errno> {
        Err(Errno::ENODATA) // Loop设备没有扩展属性
    }
    fn setxattr(
        &self,
        _key: alloc::string::String,
        _value: Vec<u8>,
        _flags: &crate::fs::uapi::SetXattrFlags,
    ) -> SyscallRet {
        Err(Errno::EPERM) // Loop设备不支持设置扩展属性
    }
    fn get_resident_page_count(&self) -> usize {
        0
    }
    fn get_inode_num(&self) -> usize {
        self.inode_num
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

pub struct LoopInodeInner {
    pub inode_on_disk: Box<Ext4InodeDisk>,
}

impl LoopInodeInner {
    pub fn new(inode_on_disk: Box<Ext4InodeDisk>) -> Self {
        Self { inode_on_disk }
    }
}

pub struct LoopControlFile {
    pub path: Arc<Path>,
    pub inode: Arc<dyn InodeOp>,
    pub flags: OpenFlags,
}

impl LoopControlFile {
    pub fn new(path: Arc<Path>, inode: Arc<dyn InodeOp>, flags: OpenFlags) -> Arc<Self> {
        Arc::new(Self { path, inode, flags })
    }
}

impl FileOp for LoopControlFile {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn read(&self, buf: &mut [u8]) -> SyscallRet {
        Err(Errno::ENOSYS) // Loop control file does not support read
    }

    fn write(&self, buf: &[u8]) -> SyscallRet {
        Err(Errno::ENOSYS) // Loop control file does not support write
    }

    fn ioctl(&self, op: usize, arg_ptr: usize) -> SyscallRet {
        LOOP_MANAGER.lock().ioctl(op, arg_ptr)
    }

    fn get_flags(&self) -> OpenFlags {
        self.flags
    }
}

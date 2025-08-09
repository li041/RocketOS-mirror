//! `Arc<Inode>` -> `OSInodeInner`: In order to open files concurrently
//! we need to wrap `Inode` into `Arc`,but `Mutex` in `Inode` prevents
//! file systems from being accessed simultaneously
//!
//! `UPSafeCell<OSInodeInner>` -> `OSInode`: for static `ROOT_INODE`,we
//! need to wrap `OSInodeInner` into `UPSafeCell`
use super::inode_trait::{InodeMeta, InodeMode, InodeTrait};
use super::path_old::PathOld;
use super::{FileMeta, FileOld};
use crate::arch::config::SysResult;
use crate::drivers::BLOCK_DEVICE;
use crate::ext4::fs::Ext4FileSystem;
use crate::fat32::fs::FAT32FileSystem;
use crate::mutex::SpinNoIrqLock;
use crate::task::current_task;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitflags::*;
use lazy_static::*;
/// A wrapper around a filesystem inode
/// to implement File trait atop
pub struct OSInodeOld {
    readable: bool,
    writable: bool,
    inner: SpinNoIrqLock<OSInodeInnerOld>,
}
/// The OS inode inner in 'UPSafeCell'
pub struct OSInodeInnerOld {
    offset: usize,
    inode: Arc<dyn InodeTrait>,
}

impl OSInodeOld {
    fn get_offset(&self) -> usize {
        self.inner.lock().offset
    }

    pub fn set_offset(&self, offset: usize) {
        self.inner.lock().offset = offset;
    }

    pub fn inner_handler<T>(&self, f: impl FnOnce(&mut OSInodeInnerOld) -> T) -> T {
        f(&mut self.inner.lock())
    }

    pub fn get_path(&self) -> PathOld {
        self.inner_handler(|inner| inner.inode.get_meta().path.clone())
    }
}

impl OSInodeOld {
    /// Construct an OS inode from a inode
    pub fn new(readable: bool, writable: bool, inode: Arc<dyn InodeTrait>) -> Self {
        Self {
            readable,
            writable,
            inner: SpinNoIrqLock::new(OSInodeInnerOld { offset: 0, inode }),
        }
    }
    /// Read all data inside a inode into vector
    pub fn read_all(&self) -> Vec<u8> {
        let inode = self.inner_handler(|inner| inner.inode.clone());
        let mut buffer = [0u8; 512];
        let mut v: Vec<u8> = Vec::new();
        loop {
            let offset = self.get_offset();
            let len = inode.read(offset, &mut buffer);
            if len == 0 {
                break;
            }
            self.set_offset(offset + len);
            v.extend_from_slice(&buffer[..len]);
        }
        v
    }
}

// lazy_static! {
//     pub static ref ROOT_INODE: Arc<dyn Inode> = {
//         FAT32FileSystem::open(BLOCK_DEVICE.clone())
//             .lock()
//             .root_inode()
//     };
// }
/// List all files in the filesystems

struct FakeRootInode;

impl InodeTrait for FakeRootInode {
    fn read<'a>(&'a self, _offset: usize, _buf: &'a mut [u8]) -> usize {
        todo!()
    }
    fn write<'a>(&'a self, _offset: usize, _buf: &'a [u8]) -> usize {
        todo!()
    }
    fn mknod(
        &self,
        _this: Arc<dyn InodeTrait>,
        _name: &str,
        _mode: InodeMode,
    ) -> SysResult<Arc<dyn InodeTrait>> {
        todo!()
    }
    fn find(&self, _this: Arc<dyn InodeTrait>, _name: &str) -> SysResult<Arc<dyn InodeTrait>> {
        todo!()
    }
    fn list(&self, _this: Arc<dyn InodeTrait>) -> SysResult<Vec<Arc<dyn InodeTrait>>> {
        todo!()
    }
    fn get_meta(&self) -> Arc<InodeMeta> {
        todo!()
    }
    fn load_children_from_disk(&self, _this: Arc<dyn InodeTrait>) {
        todo!()
    }
    fn clear(&self) {
        todo!()
    }
}

///Open file with flags
// pub fn open_file(name: &str, flags: OpenFlags) -> SysResult<Arc<OSInode>> {
//     let (readable, writable) = flags.read_write();
//     if flags.contains(OpenFlags::CREATE) {
//         if let Ok(inode) = ROOT_INODE.find(ROOT_INODE.clone(), name) {
//             // clear size
//             // inode.clear();
//             Ok(Arc::new(OSInode::new(readable, writable, inode)))
//         } else {
//             // create file
//             ROOT_INODE
//                 .mknod_v(name, InodeMode::FileREG)
//                 .map(|inode| Arc::new(OSInode::new(readable, writable, inode)))
//         }
//     } else {
//         ROOT_INODE.find(ROOT_INODE.clone(), name).map(|inode| {
//             if flags.contains(OpenFlags::TRUNC) {
//                 inode.clear();
//             }
//             Arc::new(OSInode::new(readable, writable, inode))
//         })
//     }
// }

// Todo:
// fn open_cwd(dirfd: isize, path: &PathOld) -> Arc<dyn InodeTrait> {
//     if !path.is_relative() {
//         // absolute path
//         FAT32_ROOT_INODE.clone()
//     } else if dirfd == AT_FDCWD {
//         // relative to cwd
//         let task = current_task();
//         let cwd = &task.inner.lock().cwd_old;
//         FAT32_ROOT_INODE.open_path(cwd, false, false).unwrap()
//     } else {
//         // relative to dirfd
//         let task = current_task();
//         let ret = task.inner.lock().fd_table[dirfd as usize]
//             .clone()
//             .unwrap()
//             .get_meta()
//             .inode
//             .unwrap();
//         ret
//     }
// }

// pub fn open_inode(
//     dirfd: isize,
//     path: &PathOld,
//     flags: OpenFlags,
// ) -> SysResult<Arc<dyn InodeTrait>> {
//     match open_cwd(dirfd, path).open_path(path, flags.contains(OpenFlags::CREATE), false) {
//         Ok(inode) => {
//             if flags.contains(OpenFlags::TRUNC) {
//                 inode.clear();
//             }
//             Ok(inode)
//         }
//         Err(e) => Err(e),
//     }
// }

// pub fn open_file_old(dirfd: isize, path: &PathOld, flags: OpenFlags) -> SysResult<Arc<OSInodeOld>> {
//     let (readable, writable) = flags.read_write();
//     // match open_cwd(dirfd, path).open_path(path, flags.contains(OpenFlags::CREATE), false) {
//     //     Ok(inode) => {
//     //         if flags.contains(OpenFlags::TRUNC) {
//     //             inode.clear();
//     //         }
//     //         Ok(Arc::new(OSInode::new(readable, writable, inode)))
//     //     }
//     //     Err(e) => Err(e),
//     // }
//     match open_inode(dirfd, path, flags) {
//         Ok(inode) => Ok(Arc::new(OSInodeOld::new(readable, writable, inode))),
//         Err(e) => Err(e),
//     }
// }

// pub fn create_dir(dirfd: isize, path: &PathOld) -> usize {
//     match open_cwd(dirfd, path).open_path(path, false, true) {
//         Ok(_) => 0,
//         Err(e) => e,
//     }
// }

impl FileOld for OSInodeOld {
    fn readable(&self) -> bool {
        self.readable
    }
    fn writable(&self) -> bool {
        self.writable
    }
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> usize {
        let inode = self.inner_handler(|inner| inner.inode.clone());
        let offset = self.get_offset();
        let read_size = inode.read(offset, buf);
        self.set_offset(offset + read_size);
        read_size
    }
    fn write<'a>(&'a self, buf: &'a [u8]) -> usize {
        // let mut total_write_size = 0;
        let inode = self.inner_handler(|inner| inner.inode.clone());
        // for slices in buf.buffers.iter() {
        // let mut inner = self.inner.lock();
        let offset = self.get_offset();
        let write_size = inode.write(offset, buf);
        // inner.offset += write_size.unwrap();
        self.set_offset(offset + write_size);
        // total_write_size += write_size.unwrap();
        // inner droped here
        // }
        write_size
    }

    fn get_meta(&self) -> FileMeta {
        let inode = self.inner.lock().inode.clone();
        let offset = self.inner_handler(|inner| inner.offset);
        FileMeta::new(Some(inode), offset)
    }

    fn seek(&self, offset: usize) {
        self.inner_handler(|inner| inner.offset = offset);
    }
}

use super::inode::{Inode, InodeMode};
use super::path::Path;
use super::{File, FileMeta, FileMetaInner};
use crate::config::{AsyncResult, SysResult};
#[allow(unused)]
use crate::drivers::ramfs::virtio_ramfs::VIRTIO_RAMFS;
#[allow(unused)]
use crate::drivers::BLOCK_DEVICE;
#[allow(unused)]
use crate::fs_arona::ext4::block_cache::EXT4_BLOCK_CACHE_MANAGER;
#[allow(unused)]
use crate::fs_arona::ext4::fs::Ext4FileSystem;
#[allow(unused)]
use crate::fs_arona::fat32::fs::FAT32FileSystem;
use crate::fs_arona::AT_FDCWD;
use crate::task::processor::current_process;
use crate::utils::SyscallErr;
use crate::SyscallRet;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use bitflags::*;
use lazy_static::*;
use log::{error, info};

/// A wrapper around a filesystem inode
/// to implement File trait atop
pub struct OSInode {
    meta: FileMeta,
}

impl OSInode {
    fn get_offset(&self) -> usize {
        self.meta.inner.lock().offset
    }

    fn set_offset(&self, offset: usize) {
        self.meta.inner.lock().offset = offset;
    }

    pub fn inner_handler<T>(&self, f: impl FnOnce(&mut FileMetaInner) -> T) -> T {
        f(&mut self.meta.inner.lock())
    }

    pub fn get_path(&self) -> Path {
        self.inner_handler(|inner| inner.inode.as_ref().unwrap().get_meta().path.clone())
    }
}

impl OSInode {
    /// Construct an OS inode from a inode
    pub fn new(readable: bool, writable: bool, inode: Arc<dyn Inode>) -> Option<Self> {
        // recursively follow symlink
        let inode_meta = inode.get_meta();
        if inode_meta.mode == InodeMode::FileLNK {
            let rel_target_path = inode_meta.link_target.as_ref().unwrap();
            let abs_target_path = inode_meta.path.append_to_dir(rel_target_path);
            log::debug!(
                "[OSInode::new] symlink: {} -> {}",
                inode.get_name(),
                abs_target_path
            );
            let target_inode = open_inode(AT_FDCWD, &abs_target_path, OpenFlags::empty()).ok()?;
            return Self::new(readable, writable, target_inode);
        }
        Some(Self {
            meta: FileMeta::new(
                Some(inode),
                0,
                0,
                readable,
                writable,
                super::OSFileType::OSInode,
            ),
        })
    }
    pub async fn read_all(&self) -> Vec<u8> {
        let inode = self.inner_handler(|inner| inner.inode.clone()).unwrap();
        let size = inode.get_meta().inner.lock().data_size;
        let mut v = vec![0u8; size];
        assert!(inode.read(0, v.as_mut_slice()).await.unwrap() == size);
        v
    }
}

impl File for OSInode {
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> AsyncResult<usize> {
        Box::pin(async move {
            if !self.meta.readable {
                return Err(SyscallErr::EBADF.into());
            }
            let inode = self.inner_handler(|inner| inner.inode.clone()).unwrap();
            let offset = self.get_offset();
            log::debug!("[OSInode::read] offset = {}", offset);
            let read_size = inode.read(offset, buf).await?;
            log::debug!("[OSInode::read] read_size = {}", read_size);
            self.set_offset(offset + read_size);
            Ok(read_size)
        })
    }
    fn write<'a>(&'a self, buf: &'a [u8]) -> AsyncResult<usize> {
        Box::pin(async move {
            if !self.meta.writable {
                return Err(SyscallErr::EBADF.into());
            }
            let inode = self.inner_handler(|inner| inner.inode.clone()).unwrap();
            let offset = self.get_offset();
            let write_size = inode.write(offset, buf).await?;
            self.set_offset(offset + write_size);
            Ok(write_size)
        })
    }

    fn get_meta(&self) -> &FileMeta {
        &self.meta
    }

    fn seek(&self, offset: usize) -> Option<usize> {
        self.inner_handler(|inner| {
            let ret = inner.offset;
            inner.offset = offset;
            Some(ret)
        })
    }
    fn ioctl(&self, _request: usize, _argp: usize) -> SyscallRet {
        error!("[OSInode] ioctl not implemented");
        Err(SyscallErr::ENOTTY as usize)
    }
}

// #[cfg(not(feature = "ext4"))]
#[cfg(feature = "fat32")]
lazy_static! {
    pub static ref ROOT_INODE: Arc<dyn Inode> = {
        info!("FS type: fat32");
        FAT32FileSystem::open(BLOCK_DEVICE.clone())
            .unwrap()
            .lock()
            .root_inode()
    };
}

// #[cfg(feature = "ext4")]
#[cfg(all(not(feature = "fat32"), not(feature = "ext4-ramfs")))]
lazy_static! {
    pub static ref ROOT_INODE: Arc<dyn Inode> = {
        info!("FS type: ext4");
        Ext4FileSystem::open(EXT4_BLOCK_CACHE_MANAGER.clone())
            .lock()
            .root_inode()
    };
}

#[cfg(feature = "ext4-ramfs")]
lazy_static! {
    pub static ref ROOT_INODE: Arc<dyn Inode> = {
        info!("FS type: ext4-ramfs");
        Ext4FileSystem::open(VIRTIO_RAMFS.clone())
            .lock()
            .root_inode()
    };
}

/// List all files in the filesystems
pub fn list_apps() {
    println!("[kernel] ROOT FILES >>>");
    for app in ROOT_INODE.list().unwrap() {
        print!("{} \t", app.get_name());
    }
    println!("");
}

bitflags! {
    ///Open file flags
    pub struct OpenFlags: u32 {
        const APPEND = 1 << 10;
        const ASYNC = 1 << 13;
        const DIRECT = 1 << 14;
        const DSYNC = 1 << 12;
        const EXCL = 1 << 7;
        const NOATIME = 1 << 18;
        const NOCTTY = 1 << 8;
        const NOFOLLOW = 1 << 17;
        const PATH = 1 << 21;
        /// TODO: need to find 1 << 15
        const TEMP = 1 << 15;
        /// Read only
        const RDONLY = 0;
        /// Write only
        const WRONLY = 1 << 0;
        /// Read & Write
        const RDWR = 1 << 1;
        /// Allow create
        const CREATE = 1 << 6;
        /// Clear file and return an empty one
        const TRUNC = 1 << 9;
        /// Directory
        const DIRECTORY = 1 << 16;
        /// Enable the close-on-exec flag for the new file descriptor
        const CLOEXEC = 1 << 19;
        /// When possible, the file is opened in nonblocking mode
        const NONBLOCK = 1 << 11;
    }
}

impl OpenFlags {
    /// Do not check validity for simplicity
    /// Return (readable, writable)
    pub fn read_write(&self) -> (bool, bool) {
        if self.is_empty() {
            (true, false)
        } else if self.contains(Self::WRONLY) {
            (false, true)
        } else {
            (true, true)
        }
    }
}

fn open_cwd(dirfd: isize, path: &Path) -> SysResult<Arc<dyn Inode>> {
    if !path.is_relative() {
        // absolute path
        Ok(ROOT_INODE.clone())
    } else if dirfd == AT_FDCWD {
        // relative to cwd
        let process = current_process();
        let cwd = &process.inner_lock().cwd;
        ROOT_INODE.open_path(cwd, false, false)
    } else {
        // relative to dirfd
        let task = current_process();
        let ret = task
            .inner_lock()
            .fd_table
            .get(dirfd as usize)
            .map_or(Err(1), |fdinfo| {
                fdinfo
                    .file
                    .get_meta()
                    .inner
                    .lock()
                    .inode
                    .clone()
                    .map_or(Err(1), |inode| Ok(inode))
            });
        ret
    }
}

/// Open a inode by `dirfd` and `path`
pub fn open_inode(dirfd: isize, path: &Path, flags: OpenFlags) -> SysResult<Arc<dyn Inode>> {
    open_cwd(dirfd, path).and_then(|cwd| {
        cwd.open_path(path, flags.contains(OpenFlags::CREATE), false)
            .and_then(|inode| {
                if flags.contains(OpenFlags::TRUNC) {
                    inode.clear();
                }
                Ok(inode)
            })
    })
}

/// Open a OSInode by `dirfd` and `path`
pub fn open_osinode(dirfd: isize, path: &Path, flags: OpenFlags) -> SysResult<Arc<OSInode>> {
    let (readable, writable) = flags.read_write();
    match open_inode(dirfd, path, flags) {
        Ok(inode) => match OSInode::new(readable, writable, inode) {
            Some(osinode) => Ok(Arc::new(osinode)),
            None => Err(SyscallErr::ENOENT.into()),
        },
        Err(e) => Err(e),
    }
}

/// open a `dyn File` by `fd`
/// as `Err` differs from different syscalls(e.g. `read` and `sendfile`), only return `Option` rather than `Result`.
pub fn open_fd(fd: usize) -> Option<Arc<dyn File>> {
    let fdinfo = current_process().inner_handler(|inner| inner.fd_table.get(fd))?;
    let file = fdinfo.file;
    Some(file)
}

/// Create a directory by `dirfd` and `path`
pub fn create_dir(dirfd: isize, path: &Path) -> SyscallRet {
    let cwd_inode = open_cwd(dirfd, path)?;
    cwd_inode.open_path(path, false, true).map(|_| 0)
}

//! File system in os
// pub mod ctypes;
mod devfs;
mod ext4;
mod fat32;
pub mod fd_table;
pub mod init;
pub mod inode;
mod os_inode;
pub mod path;
pub mod pipe;
mod procfs;
// pub mod socketpair;
// mod stdio;

// pub use ctypes::*;
// mod stdio;
pub mod tty;

use crate::{
    config::AsyncResult,
    mutex::SpinNoIrqLock,
    timer::TimeSpec,
    // utils::SyscallErr,
    SyscallRet, // mm::UserBuffer,
};

pub struct FileMetaInner {
    pub inode: Option<Arc<dyn Inode>>,
    pub offset: usize,
    /// used for sys_getdents, recording the next index of dentry to output
    pub dentry_index: usize,
}

pub struct FileMeta {
    pub readable: bool,
    pub writable: bool,
    pub filetype: OSFileType,
    pub inner: SpinNoIrqLock<FileMetaInner>,
}

impl FileMeta {
    pub fn new(
        inode: Option<Arc<dyn Inode>>,
        offset: usize,
        dentry_index: usize,
        readable: bool,
        writable: bool,
        filetype: OSFileType,
    ) -> Self {
        Self {
            readable,
            writable,
            filetype,
            inner: SpinNoIrqLock::new(FileMetaInner {
                inode,
                offset,
                dentry_index,
            }),
        }
    }

    pub fn new_bare(readable: bool, writable: bool, filetype: OSFileType) -> Self {
        FileMeta::new(None, 0, 0, readable, writable, filetype)
    }
}

/// File trait
pub trait File: Send + Sync {
    /// Read file to `UserBuffer`, return `Err(EBADF)` if not readable
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> AsyncResult<usize>;
    /// Write `UserBuffer` to file, return `Err(EBADF)` if not writable
    fn write<'a>(&'a self, buf: &'a [u8]) -> AsyncResult<usize>;

    fn get_meta(&self) -> &FileMeta;

    /// set offset to `offset`, return the offset **BEFORE SEEK**, which differs from `linux lseek`.
    /// return `None` if the file is not seekable
    fn seek(&self, offset: usize) -> Option<usize>;

    fn ioctl(&self, _request: usize, _argp: usize) -> SyscallRet;
    // fn ioctl(&self, _request: usize, _argp: usize) -> SyscallRet {
    //     error!("ioctl not implemented");
    //     Err(SyscallErr::ENOTTY as usize)
    // }
}

#[derive(Debug, PartialEq)]
pub enum OSFileType {
    OSInode,
    Pipe,
    SocketPair,
    TTY,
}

#[derive(Debug)]
#[repr(C)]
pub struct Fstat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub __pad1: usize,
    pub st_size: u64,
    pub st_blksize: u32,
    pub __pad2: u32,
    pub st_blocks: u64,
    pub st_atim: TimeSpec,
    pub st_mtim: TimeSpec,
    pub st_ctim: TimeSpec,
}

impl Fstat {
    pub fn new(inode: &Arc<dyn Inode>) -> Self {
        let metadata = inode.get_meta();
        // only for FileREG and FileLNK
        let data_lock = metadata.inner.lock();
        let data_size = data_lock.data_size;
        // log::debug!("[Fstat::new] data_size = {}", data_size);
        Self {
            st_dev: 0,
            st_ino: metadata.ino as u64,
            st_mode: metadata.mode as u32,
            st_nlink: 1,
            st_uid: 0,
            st_gid: 0,
            st_rdev: 0,
            __pad1: 0,
            st_size: data_size as u64,
            st_blksize: BLOCK_SIZE as u32,
            __pad2: 0,
            st_blocks: (data_size / BLOCK_SIZE) as u64,
            st_atim: data_lock.st_atim,
            st_mtim: data_lock.st_mtim,
            st_ctim: data_lock.st_ctim,
        }
    }
}

pub const AT_FDCWD: isize = -100;
pub const AT_REMOVEDIR: u32 = 0x200;

use alloc::sync::Arc;
use fat32::BLOCK_SIZE;
use inode::Inode;
// use log::error;
// use alloc::sync::Arc;
// pub use devfs::tty::TtyFile;
pub use os_inode::{create_dir, open_fd, open_inode, open_osinode, OSInode, OpenFlags};
// pub use stdio::{Stdin, Stdout};

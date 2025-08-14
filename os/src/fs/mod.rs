//! File system in os
use alloc::sync::Arc;
use inode::InodeOp;
use spin::RwLock;
// use alloc::sync::Arc;

use lazy_static::lazy_static;

pub use old::{FileMeta, FileOld};

pub mod dentry;
pub mod etc;
pub mod fd_set;
pub mod fdtable;
pub mod file;
pub mod inode;
pub mod inotify;
pub mod kstat;
pub mod manager;
pub mod mount;
pub mod namei;
pub mod old;
pub mod page_cache;
pub mod path;
pub mod pipe;
mod stdio;
pub mod tmp;

#[cfg(not(feature = "la2000"))]
pub mod dev;
#[cfg(feature = "la2000")]
pub mod dev_la2000;
#[cfg(feature = "la2000")]
pub use dev_la2000 as dev;
#[cfg(not(feature = "la2000"))]
pub mod proc;
#[cfg(feature = "la2000")]
pub mod proc_la2000;
#[cfg(feature = "la2000")]
pub use proc_la2000 as proc;

// pub mod tty;
// pub mod fd_set;
pub mod eventfd;
pub mod uapi;
pub type FSMutex<T> = RwLock<T>;
// Todo: 这里动态初始化一个FS_block_size
lazy_static! {
    pub static ref FS_BLOCK_SIZE: usize = 4096;
}
#[allow(unused)]
use crate::drivers::block::VIRTIO_BLOCK_SIZE;
use crate::ext4::inode::S_IFREG;

// 指示在当前工作目录下打开文件
pub const AT_FDCWD: i32 = -100;
pub const AT_REMOVEDIR: i32 = 0x200;

// ext4文件系统的最大文件大小: 16TB
pub const EXT4_MAX_FILE_SIZE: usize = 0x1000000000000;

lazy_static::lazy_static! {
    pub static ref DUMMY_INODE: Arc<dyn InodeOp> = Arc::new(DummyInode {});
}

pub struct DummyInode;

impl DummyInode {
    pub fn new() -> Arc<DummyInode> {
        Arc::new(DummyInode {})
    }
}

impl InodeOp for DummyInode {
    fn get_mode(&self) -> u16 {
        S_IFREG
    }
}

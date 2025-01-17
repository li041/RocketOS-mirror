//! File system in os
use alloc::sync::Arc;
use inode_trait::InodeTrait;
// use alloc::sync::Arc;
pub use os_inode_old::{create_dir, list_apps, open_file, open_inode, OpenFlags};
pub use stdio::{Stdin, Stdout};

use crate::mutex::SpinNoIrqLock;
use lazy_static::lazy_static;

pub mod address_space;
pub mod file;
pub mod inode;
pub mod inode_trait;
mod os_inode_old;
pub mod path;
pub mod pipe;
mod stdio;

// 文件系统的锁先使用SpinNoIrqLock, Todo: 改成RwLock
pub type FSMutex<T> = SpinNoIrqLock<T>;
// Todo: 这里动态初始化一个FS_block_size
lazy_static! {
    pub static ref FS_BLOCK_SIZE: usize = 4096;
}
#[allow(unused)]
use crate::drivers::block::VIRTIO_BLOCK_SIZE;

pub struct FileMeta {
    pub inode: Option<Arc<dyn InodeTrait>>,
    pub offset: usize,
}

impl FileMeta {
    pub fn new(inode: Option<Arc<dyn InodeTrait>>, offset: usize) -> Self {
        Self { inode, offset }
    }
}

/// File trait
pub trait FileOp: Send + Sync {
    /// Read file to `UserBuffer`
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> Result<usize, &'static str>;
    /// Write `UserBuffer` to file
    fn write<'a>(&'a self, buf: &'a [u8]) -> usize;
}

/// File trait
pub trait FileOld: Send + Sync {
    /// If readable
    fn readable(&self) -> bool;
    /// If writable
    fn writable(&self) -> bool;
    /// Read file to `UserBuffer`
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> usize;
    /// Write `UserBuffer` to file
    fn write<'a>(&'a self, buf: &'a [u8]) -> usize;
    fn get_meta(&self) -> FileMeta;
    fn seek(&self, offset: usize);
}

// 指示在当前工作目录下打开文件
pub const AT_FDCWD: isize = -100;
pub const AT_REMOVEDIR: u32 = 0x200;

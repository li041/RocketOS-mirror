//! File system in os
// mod block_cache;
pub mod inode;
mod os_inode;
pub mod path;
pub mod pipe;
mod stdio;

pub struct FileMeta {
    pub inode: Option<Arc<dyn Inode>>,
    pub offset: usize,
}

impl FileMeta {
    pub fn new(inode: Option<Arc<dyn Inode>>, offset: usize) -> Self {
        Self { inode, offset }
    }
}

/// File trait
pub trait File: Send + Sync {
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

pub const AT_FDCWD: isize = -100;
pub const AT_REMOVEDIR: u32 = 0x200;

use alloc::sync::Arc;
use inode::Inode;
// use alloc::sync::Arc;
pub use os_inode::{create_dir, list_apps, open_file, open_inode, OSInode, OpenFlags};
pub use stdio::{Stdin, Stdout};

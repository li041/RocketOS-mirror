//! File system in os
use core::cell::OnceCell;

use alloc::{string::ToString, sync::Arc};
use dentry::{insert_dentry, Dentry, DENTRY_CACHE};
use inode::InodeOp;
use mount::{add_mount, Mount};
use spin::RwLock;
// use alloc::sync::Arc;
pub use stdio::{Stdin, Stdout};

use lazy_static::lazy_static;

pub use old::{FileMeta, FileOld};

pub mod dentry;
pub mod dev;
pub mod etc;
pub mod fd_set;
pub mod fdtable;
pub mod file;
pub mod inode;
pub mod kstat;
pub mod manager;
pub mod mount;
pub mod namei;
pub mod old;
pub mod page_cache;
pub mod path;
pub mod pipe;
pub mod proc;
mod stdio;
pub mod tmp;
// pub mod tty;
// pub mod fd_set;
pub mod uapi;

// 文件系统的锁先使用SpinNoIrqLock, Todo: 改成RwLock
pub type FSMutex<T> = RwLock<T>;
// Todo: 这里动态初始化一个FS_block_size
lazy_static! {
    pub static ref FS_BLOCK_SIZE: usize = 4096;
}
#[allow(unused)]
use crate::drivers::block::VIRTIO_BLOCK_SIZE;

// 指示在当前工作目录下打开文件
pub const AT_FDCWD: i32 = -100;
pub const AT_REMOVEDIR: i32 = 0x200;

// ext4文件系统的最大文件大小: 16TB
pub const EXT4_MAX_FILE_SIZE: usize = 0x1000000000000;

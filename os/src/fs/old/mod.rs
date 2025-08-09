#![allow(unused)]
use alloc::sync::Arc;
use inode_trait::InodeTrait;
use lazy_static::lazy_static;

use crate::{drivers::BLOCK_DEVICE, fat32::fs::FAT32FileSystem};

pub mod inode_trait;
pub mod os_inode_old;
pub mod path_old;

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

lazy_static! {
    pub static ref FAT32_ROOT_INODE: Arc<dyn InodeTrait> = {
        FAT32FileSystem::open(BLOCK_DEVICE.clone())
            .write()
            .root_inode()
    };
}

#[allow(unused)]
pub fn fat32_list_apps() {
    println!("/**** ROOT APPS ****");
    let apps = FAT32_ROOT_INODE.list(FAT32_ROOT_INODE.clone()).unwrap();
    if apps.is_empty() {
        println!("No apps found");
    }
    for app in apps {
        print!("{}\t", app.get_name());
    }
    println!("**************/");
}

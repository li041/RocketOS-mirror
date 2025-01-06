//! fat32 file system

// #![allow(unused)]
// #![allow(dead_code)]

use crate::mutex::SpinNoIrqLock;

mod block_cache;
mod dentry;
mod fat;
mod file;
pub mod fs;
pub mod inode;
mod layout;
mod time;

// 文件系统的锁先使用SpinNoIrqLock, Todo: 改成RwLock
pub type FSMutex<T> = SpinNoIrqLock<T>;

const BLOCK_SIZE: usize = 512;
const SECTOR_SIZE: usize = 512;
const BLOCK_CACHE_SIZE: usize = 16;
const SNAME_LEN: usize = 11;
// FAT32的长文件名最大支持255个字符(UniCode, 一个字符占2字节)
const LNAME_MAXLEN: usize = 255;
// const BOOT_SECTOR_ID: usize = 0;
const FAT_ENTRY_PER_SECTOR: usize = SECTOR_SIZE / 4;
const FATENTRY_MASK: u32 = 0x0FFFFFFF;
// 结束簇的值通常是 0x0FFFFFF8 到 0x0FFFFFFF 之间的值。
const FATENTRY_MIN_EOC: u32 = 0x0FFFFFF8;
const FATENTRY_EOC: u32 = 0x0FFFFFFF;
const FSINFO_LEADSIG: u32 = 0x41615252;
const FSINFO_STRUCSIG: u32 = 0x61417272;
const FSINFO_TRAILSIG: u32 = 0xAA550000;
// const FSI_RESERVED1_SIZE: usize = 480;
// const FSI_RESERVED2_SIZE: usize = 12;
/// 表示FSInfoSector中的Free_Count和Nxt_Free字段不可用
const FSINFO_NOT_AVAILABLE: u32 = 0xFFFFFFFF;

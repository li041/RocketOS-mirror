use alloc::vec;
use core::any::Any;

use alloc::{sync::Arc, vec::Vec};
use log::info;
use spin::RwLock;
use virtio_drivers::PAGE_SIZE;

use crate::{arch::config::PAGE_SIZE_BITS, mm::Page, mutex::SpinNoIrqLock};

use super::{
    dentry::{Dentry, LinuxDirent64},
    inode::InodeOp,
    path::Path,
};

// 普通文件
pub struct File {
    inner: SpinNoIrqLock<FileInner>,
}

pub struct FileInner {
    // pub inode: ,
    /// 单位是字节
    offset: usize,
    // pub dentry: Arc<Dentry>,
    pub path: Arc<Path>,
    pub inode: Arc<dyn InodeOp>,
    pub flags: usize,
}

// 不支持对文件执行ioctl操作
const ENOTTY: isize = 25;
/// File trait
pub trait FileOp: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any {
        unimplemented!();
    }
    // 从文件中读取数据到buf中, 返回读取的字节数, 同时更新文件偏移量
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> usize {
        unimplemented!();
    }
    fn get_page(self: Arc<Self>, page_offset: usize) -> Result<Arc<Page>, &'static str> {
        unimplemented!();
    }
    /// Write `UserBuffer` to file
    fn write<'a>(&'a self, buf: &'a [u8]) -> usize {
        unimplemented!();
    }
    // move the file offset
    fn seek(&self, offset: usize) {
        unimplemented!();
    }
    // Get the file offset
    fn get_offset(&self) -> usize {
        unimplemented!();
    }
    // readable
    fn readable(&self) -> bool {
        unimplemented!();
    }
    // writable
    fn writable(&self) -> bool {
        unimplemented!();
    }
    fn ioctl(&self, _op: usize, _arg_ptr: usize) -> isize {
        -ENOTTY
    }
}

impl File {
    pub fn inner_handler<T>(&self, f: impl FnOnce(&mut FileInner) -> T) -> T {
        f(&mut self.inner.lock())
    }
    pub fn add_offset(&self, offset: usize) {
        self.inner_handler(|inner| inner.offset += offset);
    }
    pub fn get_offset(&self) -> usize {
        self.inner_handler(|inner| inner.offset)
    }
}

impl File {
    pub fn new(path: Arc<Path>, inode: Arc<dyn InodeOp>, flags: usize) -> Self {
        Self {
            inner: SpinNoIrqLock::new(FileInner {
                offset: 0,
                path,
                inode,
                flags,
            }),
        }
    }
    /// Read all data inside a inode into vector
    pub fn read_all(&self) -> Vec<u8> {
        info!("[File::read_all]");
        let inode = self.inner_handler(|inner| inner.inode.clone());
        let size = inode.get_size();
        let mut buffer = vec![0u8; size];
        let offset = self.get_offset();
        let total_read = inode.read(offset, &mut buffer);
        self.add_offset(total_read);
        // loop {
        //     let offset = self.get_offset();
        //     let len = inode.read(offset, &mut buffer);
        //     totol_read += len;
        //     if len == 0 {
        //         break;
        //     }
        //     self.add_offset(len);
        //     v.extend_from_slice(&buffer[..len]);
        //     log::warn!("read one paeg at offset: {}", offset);
        // }
        log::info!("read_all: total_read: {}", total_read);
        buffer
    }
    pub fn is_dir(&self) -> bool {
        self.inner_handler(|inner| inner.inode.can_lookup())
    }

    pub fn readdir(&self) -> Result<Vec<LinuxDirent64>, &'static str> {
        if self.is_dir() {
            let (offset, linux_dirents) =
                self.inner_handler(|inner| inner.inode.getdents(inner.offset));
            self.add_offset(offset);
            return Ok(linux_dirents);
        }
        return Err("not a directory");
    }
}

impl FileOp for File {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> usize {
        let read_size = self.inner_handler(|inner| inner.inode.read(inner.offset, buf));
        self.add_offset(read_size);
        read_size
    }
    /// 共享文件映射和私有文件映射只读时调用
    fn get_page(self: Arc<Self>, page_aligned_offset: usize) -> Result<Arc<Page>, &'static str> {
        debug_assert!(page_aligned_offset % PAGE_SIZE == 0);
        let inode = self.inner_handler(|inner| inner.inode.clone());
        inode.get_page(page_aligned_offset >> PAGE_SIZE_BITS)
    }

    fn write<'a>(&'a self, buf: &'a [u8]) -> usize {
        let write_size = self.inner_handler(|inner| inner.inode.write(inner.offset, buf));
        self.add_offset(write_size);
        write_size
    }
    fn seek(&self, offset: usize) {
        self.inner_handler(|inner| inner.offset = offset);
    }
    fn get_offset(&self) -> usize {
        self.inner_handler(|inner| inner.offset)
    }
    // O_RDONLY = 0, 以只读方式打开文件, 具体的权限检查由VFS层完成
    // Todo:
    fn readable(&self) -> bool {
        // self.inner_handler(|inner| inner.flags & O_RDONLY != 0)
        true
    }
    // Todo:
    fn writable(&self) -> bool {
        true
    }
}

pub const O_RDONLY: usize = 0;
pub const O_WRONLY: usize = 1;
pub const O_RDWR: usize = 2;
pub const O_CREAT: usize = 0x40;
pub const O_DIRECTORY: usize = 0x10000;
pub const O_NOFOLLOW: usize = 0x200000;

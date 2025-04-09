use core::{alloc::Layout, ops::Add};

use alloc::{
    alloc::{alloc, dealloc},
    sync::{Arc, Weak},
};
use virtio_drivers::PAGE_SIZE;

use crate::{
    arch::config::KERNEL_BASE,
    drivers::block::{block_dev::BlockDevice, VIRTIO_BLOCK_SIZE},
    fs::{inode::InodeOp, FS_BLOCK_SIZE},
};

use spin::RwLock;

use crate::arch::config::PAGE_SIZE_BITS;
use crate::mm::PhysPageNum;

pub enum PageKind {
    Private,
    Shared(RwLock<ShreadPageInfo>),
    // Todo: inline_data
    Inline(RwLock<InlinePageInfo>),
}
impl PageKind {
    pub fn is_private(&self) -> bool {
        match self {
            PageKind::Private => true,
            _ => false,
        }
    }
}

pub struct ShreadPageInfo {
    // underlying block id
    start_block_id: usize,
    block_device: Weak<dyn BlockDevice>,
    inode: Weak<dyn InodeOp>,
}

pub struct InlinePageInfo {
    inode: Weak<dyn InodeOp>,
}

// 页缓存中使用的页结构
// Todo: 支持私有的Page
pub struct Page {
    vaddr: usize,
    page_kind: PageKind,
    /// whether the page is dirty
    modified: bool,
}

impl Page {
    pub fn new_shared(
        fs_block_id: usize,
        block_device: Arc<dyn BlockDevice>,
        inode: Weak<dyn InodeOp>,
    ) -> Self {
        let start_block_id = fs_block_id * (*FS_BLOCK_SIZE / VIRTIO_BLOCK_SIZE);
        unsafe {
            let layout = Layout::from_size_align_unchecked(PAGE_SIZE, PAGE_SIZE);
            let vaddr = alloc(layout);
            let buf = core::slice::from_raw_parts_mut(vaddr, PAGE_SIZE);
            // 从块设备中读取数据到缓存中
            if !fs_block_id != 0 {
                block_device.read_blocks(start_block_id, buf);
            } else {
                // 如果fs_block_id为0, 则不需要读取数据, 是稀疏文件的空洞
                // 直接清空页
                buf.fill(0);
            }
            return Self {
                vaddr: vaddr as usize,
                page_kind: PageKind::Shared(RwLock::new(ShreadPageInfo {
                    start_block_id,
                    block_device: Arc::downgrade(&block_device),
                    inode,
                })),
                modified: false,
            };
        };
    }
    // 写时复制
    pub fn new_private(data: Option<&[u8; PAGE_SIZE]>) -> Self {
        unsafe {
            let layout = Layout::from_size_align_unchecked(PAGE_SIZE, PAGE_SIZE);
            let vaddr = alloc(layout);
            let buf = core::slice::from_raw_parts_mut(vaddr, PAGE_SIZE);
            if let Some(data) = data {
                // 复制数据到页中
                buf.copy_from_slice(data);
            } else {
                // 如果没有数据, 则清空页
                buf.fill(0);
            }
            return Self {
                vaddr: vaddr as usize,
                page_kind: PageKind::Private,
                modified: false,
            };
        }
    }
    /// fs_block_id和inner_offset用于回写block cache
    pub fn new_inline(inode: Weak<dyn InodeOp>, inline_data: &[u8]) -> Self {
        unsafe {
            let layout = Layout::from_size_align_unchecked(PAGE_SIZE, PAGE_SIZE);
            let vaddr = alloc(layout);
            let buf = core::slice::from_raw_parts_mut(vaddr, PAGE_SIZE);
            let len_to_copy = inline_data.len();
            buf[..len_to_copy].copy_from_slice(inline_data);
            return Self {
                vaddr: vaddr as usize,
                page_kind: PageKind::Inline(RwLock::new(InlinePageInfo { inode })),
                modified: false,
            };
        }
    }
}

impl Page {
    #[inline(always)]
    pub fn ppn(&self) -> PhysPageNum {
        PhysPageNum((self.vaddr - KERNEL_BASE) >> PAGE_SIZE_BITS)
    }
    // Get the address of an offset inside the cached block data
    #[inline(always)]
    fn addr_of_offset(&self, offset: usize) -> usize {
        self.vaddr + offset
    }
    #[inline(always)]
    pub fn get_ref<T>(&self, offset: usize) -> &T
    where
        T: Sized,
    {
        let type_size = core::mem::size_of::<T>();
        assert!(
            offset + type_size <= PAGE_SIZE,
            "offset: {:#x}, type_size: {:#x}",
            offset,
            type_size
        );
        let addr = self.addr_of_offset(offset);
        unsafe { &*(addr as *const T) }
    }

    pub fn read<T, V>(&self, offset: usize, f: impl FnOnce(&T) -> V) -> V {
        match &self.page_kind {
            PageKind::Private => f(self.get_ref(offset)),
            PageKind::Shared(info) => {
                let _guard = info.read(); // 加读锁
                let ptr = unsafe {
                    let addr = self.addr_of_offset(offset);
                    assert!(offset + core::mem::size_of::<T>() <= PAGE_SIZE);
                    &*(addr as *const T)
                };
                f(ptr)
            }
            PageKind::Inline(info) => {
                let _guard = info.read(); // 加读锁
                let ptr = unsafe {
                    let addr = self.addr_of_offset(offset);
                    assert!(offset + core::mem::size_of::<T>() <= PAGE_SIZE);
                    &*(addr as *const T)
                };
                f(ptr)
            }
        }
    }
    pub fn modify<T, V>(&self, offset: usize, f: impl FnOnce(&mut T) -> V) -> V {
        match &self.page_kind {
            PageKind::Private => self.modify_private(offset, f),
            PageKind::Shared(info) => {
                let _guard = info.write(); // 加写锁
                let ptr = unsafe {
                    let addr = self.addr_of_offset(offset);
                    assert!(offset + core::mem::size_of::<T>() <= PAGE_SIZE);
                    &mut *(addr as *mut T)
                };
                f(ptr)
            }
            PageKind::Inline(info) => {
                let _guard = info.write(); // 加写锁
                let ptr = unsafe {
                    let addr = self.addr_of_offset(offset);
                    assert!(offset + core::mem::size_of::<T>() <= PAGE_SIZE);
                    &mut *(addr as *mut T)
                };
                f(ptr)
            }
        }
    }

    // Modify the cached data through the closure function f
    #[inline(always)]
    pub fn modify_private<T, V>(&self, offset: usize, f: impl FnOnce(&mut T) -> V) -> V {
        let type_size = core::mem::size_of::<T>();
        debug_assert!(offset + type_size <= PAGE_SIZE);
        let addr = self.addr_of_offset(offset);
        f(unsafe { &mut *(addr as *mut T) })
    }

    pub fn sync(&mut self) {
        if self.modified {
            match &self.page_kind {
                PageKind::Shared(info) => {
                    // 判断文件是否已删除, 若已删除, 则不需要回写
                    // 注意ext4可能有稀疏文件, 当第一次读extent_tree时发现空洞, 页缓存直接分配一个全0页面, 并没有对应磁盘的block
                    if let Some(_) = info.read().inode.upgrade() {
                        let cache = unsafe {
                            core::slice::from_raw_parts_mut(self.vaddr as *mut u8, PAGE_SIZE)
                        };
                        // let start_block_id = info.read().start_block_id;
                        // info.write()
                        //     .block_device
                        //     .upgrade()
                        //     .unwrap()
                        //     .write_blocks(start_block_id, cache);
                        info.write().inode.upgrade().unwrap().write(0, cache);
                    }
                }
                PageKind::Inline(info) => {
                    let inline_data = unsafe {
                        core::slice::from_raw_parts_mut(self.vaddr as *mut u8, PAGE_SIZE)
                    };
                    info.write().inode.upgrade().unwrap().write(0, inline_data);
                }
                // Private does not need to sync when dropping
                _ => {}
            }
        }
        // 释放内存
        unsafe {
            let layout = Layout::from_size_align_unchecked(PAGE_SIZE, PAGE_SIZE);
            dealloc(self.vaddr as *mut u8, layout);
        }
        self.modified = false;
    }
}

impl Drop for Page {
    fn drop(&mut self) {
        self.sync()
    }
}

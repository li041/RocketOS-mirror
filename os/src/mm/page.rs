use core::{alloc::Layout, ops::Add};

use alloc::{
    alloc::{alloc, dealloc},
    sync::{Arc, Weak},
};
use virtio_drivers::PAGE_SIZE;

use crate::{
    arch::config::{EXT4_MAX_INLINE_DATA, KERNEL_BASE},
    drivers::block::{block_dev::BlockDevice, VIRTIO_BLOCK_SIZE},
    ext4::{self, extent_tree::Ext4Extent, fs::EXT4_BLOCK_SIZE, inode::Ext4Inode, MAX_FS_BLOCK_ID},
    fs::{inode::InodeOp, FS_BLOCK_SIZE},
};

use spin::RwLock;

use crate::arch::config::PAGE_SIZE_BITS;
use crate::mm::PhysPageNum;

use super::{frame_allocator::frame_alloc_ppn, frame_dealloc};

pub enum PageKind {
    Framed,
    Filebe(RwLock<ShreadPageInfo>),
    // Todo: inline_data
    Inline(RwLock<InlinePageInfo>),
}
impl PageKind {
    pub fn is_private(&self) -> bool {
        match self {
            PageKind::Framed => true,
            _ => false,
        }
    }
}

pub struct ShreadPageInfo {
    // underlying block id
    start_block_id: usize,
    block_device: Weak<dyn BlockDevice>,
    inode: Weak<dyn InodeOp>,
    /// whether the page is dirty
    modified: bool,
}

pub struct InlinePageInfo {
    inode: Weak<dyn InodeOp>,
    /// whether the page is dirty
    modified: bool,
}

// 页缓存中使用的页结构
pub struct Page {
    vaddr: usize,
    page_kind: PageKind,
}

impl Page {
    pub fn new_filebe(
        fs_block_id: usize,
        block_device: Arc<dyn BlockDevice>,
        inode: Weak<dyn InodeOp>,
    ) -> Self {
        let start_block_id = if fs_block_id < MAX_FS_BLOCK_ID {
            fs_block_id * (*FS_BLOCK_SIZE / VIRTIO_BLOCK_SIZE)
        } else {
            fs_block_id
        };
        unsafe {
            let ppn = frame_alloc_ppn();
            let vaddr = (ppn.0 << PAGE_SIZE_BITS) + KERNEL_BASE;
            let buf = core::slice::from_raw_parts_mut(vaddr as *mut u8, PAGE_SIZE);
            // 从块设备中读取数据到缓存中
            if fs_block_id < MAX_FS_BLOCK_ID {
                block_device.read_blocks(start_block_id, buf);
            } else {
                // 如果fs_block_id为usize::MAX, 则不需要读取数据, 是稀疏文件的空洞
                // 直接清空页
                buf.fill(0);
            }
            return Self {
                vaddr: vaddr as usize,
                page_kind: PageKind::Filebe(RwLock::new(ShreadPageInfo {
                    start_block_id,
                    block_device: Arc::downgrade(&block_device),
                    inode,
                    modified: false,
                })),
            };
        };
    }
    /// 用于私有页面, 匿名共享映射和System V shm
    pub fn new_framed(data: Option<&[u8; PAGE_SIZE]>) -> Self {
        unsafe {
            let ppn = frame_alloc_ppn();
            let vaddr = (ppn.0 << PAGE_SIZE_BITS) + KERNEL_BASE;
            let buf = core::slice::from_raw_parts_mut(vaddr as *mut u8, PAGE_SIZE);
            if let Some(data) = data {
                // 复制数据到页中
                // buf.fill(0);
                buf.copy_from_slice(data);
            } else {
                // 如果没有数据, 则清空页
                buf.fill(0);
            }
            return Self {
                vaddr: vaddr as usize,
                page_kind: PageKind::Framed,
            };
        }
    }
    /// fs_block_id和inner_offset用于回写block cache
    pub fn new_inline(inode: Weak<dyn InodeOp>, inline_data: &[u8]) -> Self {
        unsafe {
            // let layout = Layout::from_size_align_unchecked(PAGE_SIZE, PAGE_SIZE);
            // let vaddr = alloc(layout);
            let ppn = frame_alloc_ppn();
            let vaddr = (ppn.0 << PAGE_SIZE_BITS) + KERNEL_BASE;
            let buf = core::slice::from_raw_parts_mut(vaddr as *mut u8, PAGE_SIZE);
            buf.fill(0); // 清空页
            let len_to_copy = inline_data.len();
            buf[..len_to_copy].copy_from_slice(inline_data);
            return Self {
                vaddr: vaddr as usize,
                page_kind: PageKind::Inline(RwLock::new(InlinePageInfo {
                    inode,
                    modified: false,
                })),
            };
        }
    }
}

impl Page {
    #[inline(always)]
    pub fn ppn(&self) -> PhysPageNum {
        PhysPageNum((self.vaddr - KERNEL_BASE) >> PAGE_SIZE_BITS)
    }
    #[inline(always)]
    pub fn vaddr(&self) -> usize {
        self.vaddr
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
            PageKind::Framed => f(self.get_ref(offset)),
            PageKind::Filebe(info) => {
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
            PageKind::Framed => self.modify_private(offset, f),
            PageKind::Filebe(info) => {
                let mut guard = info.write(); // 加写锁
                let ptr = unsafe {
                    let addr = self.addr_of_offset(offset);
                    assert!(offset + core::mem::size_of::<T>() <= PAGE_SIZE);
                    &mut *(addr as *mut T)
                };
                guard.modified = true;
                f(ptr)
            }
            PageKind::Inline(info) => {
                let mut guard = info.write(); // 加写锁
                let ptr = unsafe {
                    let addr = self.addr_of_offset(offset);
                    assert!(offset + core::mem::size_of::<T>() <= PAGE_SIZE);
                    &mut *(addr as *mut T)
                };
                guard.modified = true;
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

    pub fn sync(&self) {
        match &self.page_kind {
            PageKind::Filebe(info) => {
                let guard = info.write(); // 加写锁
                if guard.modified {
                    // println!("[Page::modified]sync page: {:#x}", self.vaddr);
                    if let Some(block_device) = guard.block_device.upgrade() {
                        let cache = unsafe {
                            core::slice::from_raw_parts_mut(self.vaddr as *mut u8, PAGE_SIZE)
                        };
                        if guard.start_block_id >= MAX_FS_BLOCK_ID {
                            log::warn!(
                                "[Page::sync] sparse file, allocating new block and insert extent"
                            );
                            if let Some(inode) = guard.inode.upgrade() {
                                if let Some(ext4_inode) = inode.as_any().downcast_ref::<Ext4Inode>()
                                {
                                    // 稀疏文件的空洞处理
                                    let new_block_num = ext4_inode.alloc_one_block();
                                    let page_index = guard.start_block_id & !MAX_FS_BLOCK_ID;
                                    let new_extent =
                                        Ext4Extent::new(page_index as u32, 1, new_block_num);
                                    let mut inner = ext4_inode.inner.write();
                                    inner
                                        .inode_on_disk
                                        .insert_extent(
                                            page_index as u32,
                                            new_extent.physical_start_block() as u64,
                                            1,
                                            block_device.clone(),
                                            EXT4_BLOCK_SIZE,
                                            ext4_inode.ext4_fs.upgrade().unwrap(),
                                        )
                                        .unwrap();
                                } else {
                                    log::error!(
                                    "[Page::sync] inode is not a Ext4Inode, cannot write back sparse hole"
                                );
                                }
                            } else {
                                log::error!(
                                    "[Page::sync] inode is dropped, cannot write back sparse hole"
                                );
                            }
                        } else {
                            block_device.write_blocks(guard.start_block_id, cache);
                        }
                    }
                }
            }
            PageKind::Inline(info) => {
                log::warn!(
                    "[Page::sync] inline page synced directly, vaddr: {:#x}",
                    self.vaddr
                );
                let guard = info.write(); // 加写锁
                let inode = guard.inode.upgrade();
                if let Some(inode) = inode {
                    if let Some(ext4_inode) = inode.as_any().downcast_ref::<Ext4Inode>() {
                        if guard.modified {
                            // Debug 6.12: 死锁
                            let mut inner = ext4_inode.inner.write();

                            // assert!(inner.inode_on_disk.has_inline_data());
                            if !inner.inode_on_disk.has_inline_data() {
                                log::error!(
                                    "[Page::sync] Inline Page but EXT4_INLINE_DATA_FL is not set"
                                );
                                return;
                            }
                            log::warn!("[page::sync] has inline data, write back to disk");
                            if let Some(inline_page) = ext4_inode.address_space.get_page_cache(0) {
                                // inline data在页缓存中, 写回磁盘
                                let inline_data: &[u8; EXT4_MAX_INLINE_DATA] =
                                    inline_page.get_ref(0);
                                inner.inode_on_disk.block[0..inline_data.len()]
                                    .copy_from_slice(inline_data);
                                // 注意这里不将inode_on_disk写回磁盘, 只更新了内存中的inode_on_disk
                            } else {
                                log::error!(
                                    "[Ext4Inode::drop] inline data not found in page cache"
                                );
                            }
                        }
                    } else {
                        log::error!(
                            "[Page::sync]inode is not a Ext4Inode, cannot write back inline data"
                        );
                    }
                } else {
                    log::error!("[Page::sync]inline page's inode is dropped, cannot write back");
                }
            }
            _ => {}
        }
    }
}

impl Drop for Page {
    fn drop(&mut self) {
        self.sync();
        // 释放内存
        let ppn = (self.vaddr - KERNEL_BASE) >> PAGE_SIZE_BITS;
        frame_dealloc(PhysPageNum(ppn));
    }
}

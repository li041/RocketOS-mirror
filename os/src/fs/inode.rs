//! new
use crate::config::{PAGE_SIZE, PAGE_SIZE_BITS};
use crate::drivers::block::block_dev::BlockDevice;
use crate::drivers::BLOCK_DEVICE;
use crate::ext4::extent_tree::Extent;
use crate::mm::page::Page;
use crate::mutex::SpinNoIrqLock;

use super::address_space::{self, AddressSpace};
use alloc::sync::Arc;
use alloc::vec::Vec;

/// 通过inode是能够访问到文件系统的超级块的
/// 在内存中的inode结构
pub struct Inode {
    /// 页缓存
    pub address_space: SpinNoIrqLock<AddressSpace>,
    pub inode: Arc<dyn InodeOp>,
    pub block_device: Arc<dyn BlockDevice>,
}

impl Inode {
    pub fn new(inode: Arc<dyn InodeOp>) -> Self {
        Self {
            address_space: SpinNoIrqLock::new(AddressSpace::new()),
            inode,
            block_device: BLOCK_DEVICE.clone(),
        }
    }
    // 读取文件内容, offset是字节偏移
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> Result<usize, &'static str> {
        // 需要读取的总长度
        let rbuf_len = buf.len();
        // 先读取页缓存
        let mut current_read = 0;
        let mut page_offset = offset >> PAGE_SIZE_BITS;
        let mut page_offset_in_page = offset & (PAGE_SIZE_BITS - 1);

        let mut current_physical_block_range: Option<PhysicalBlockRange> = None;
        let mut page: Arc<SpinNoIrqLock<Page>>;
        let mut fs_block_id: usize;
        let mut address_space = self.address_space.lock();

        while current_read < rbuf_len {
            if let Some(page_cache) = address_space.get_page_cache(page_offset) {
                // 页缓存命中
                page = page_cache;
            } else {
                // 页缓存未命中, 看是否在查到的PhysicalBlockRange中
                if let Some(physical_block_range) = &current_physical_block_range {
                    if physical_block_range.logical_block_id + physical_block_range.len as usize
                        > page_offset
                    {
                        // 命中extent读取, 知道对应的物理块号
                        fs_block_id = physical_block_range.physical_block_id + page_offset
                            - physical_block_range.logical_block_id;
                    } else {
                        // 未命中, 从inode中读取extent
                        let physical_block_range =
                            self.inode.read(page_offset, self.block_device.clone())?;
                        fs_block_id = physical_block_range.physical_block_id + page_offset
                            - physical_block_range.logical_block_id;
                        current_physical_block_range = Some(physical_block_range);
                    }
                } else {
                    // 未命中, 从inode中读取extent
                    let physical_block_range =
                        self.inode.read(page_offset, self.block_device.clone())?;
                    fs_block_id = physical_block_range.physical_block_id + page_offset
                        - physical_block_range.logical_block_id;
                    current_physical_block_range = Some(physical_block_range);
                }
                page = address_space.new_page_cache(
                    page_offset,
                    fs_block_id,
                    self.block_device.clone(),
                );
            }
            let copy_len = (rbuf_len - current_read).min(PAGE_SIZE - page_offset_in_page);
            page.lock().read(0, |data: &[u8; PAGE_SIZE]| {
                buf[current_read..current_read + copy_len]
                    .copy_from_slice(&data[page_offset_in_page..page_offset_in_page + copy_len]);
            });
            current_read += copy_len;
            page_offset += 1;
            page_offset_in_page = 0;
        }
        Ok(current_read)
    }
    //
    pub fn write(&self, offset: usize, buf: &[u8]) -> usize {
        unimplemented!();
    }
}

// logical_block_id是文件中的逻辑偏移, phsical_block_id是ext4文件系统中的物理块号
pub struct PhysicalBlockRange {
    pub logical_block_id: usize,  // file中的逻辑块号
    pub physical_block_id: usize, // ext4文件系统中的物理块号
    pub len: u32,
}

/// 由页缓存直接和block device交互
/// inode查extent_tree, 返回页号
/// page_offset是页偏移, page_offset * PAGE_SIZE是字节偏移
pub trait InodeOp: Send + Sync {
    // 返回extent
    fn read<'a>(
        &'a self,
        page_offset: usize,
        block_device: Arc<dyn BlockDevice>,
    ) -> Result<PhysicalBlockRange, &'static str>;
    fn write<'a>(&'a self, page_offset: usize, buf: &'a [u8]) -> usize;
}

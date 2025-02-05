//! new
use crate::config::{PAGE_SIZE, PAGE_SIZE_BITS};
use crate::drivers::block::block_dev::BlockDevice;
use crate::drivers::BLOCK_DEVICE;
use crate::mm::page::Page;
use crate::mutex::SpinNoIrqLock;

use super::address_space::AddressSpace;
use super::inode_trait::InodeState;
use super::super_block::SuperBlockOp;
use alloc::collections::btree_map::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

/// 通过inode是能够访问到文件系统的超级块的
/// 在内存中的inode结构
pub struct Inode {
    pub super_block: Weak<dyn SuperBlockOp>,
    /// 页缓存, 不放到inner中, 减小锁粒度
    pub address_space: AddressSpace,
    pub inode: Arc<dyn InodeOp>,
    pub block_device: Arc<dyn BlockDevice>,
    pub inner: SpinNoIrqLock<InodeInner>,
}

/// 用树组织内存中的Inode
pub struct InodeInner {
    pub parent: Option<Weak<Inode>>,
    // 用名字索引子节点
    pub children: BTreeMap<String, Arc<Inode>>,
    pub state: InodeState,
}

impl InodeInner {
    pub fn new() -> Self {
        Self {
            parent: None,
            children: BTreeMap::new(),
            state: InodeState::Init,
        }
    }
}

impl Inode {
    pub fn new(inode: Arc<dyn InodeOp>, super_block: Arc<dyn SuperBlockOp>) -> Self {
        Self {
            address_space: AddressSpace::new(),
            inode,
            block_device: BLOCK_DEVICE.clone(),
            super_block: Arc::downgrade(&super_block),
            inner: SpinNoIrqLock::new(InodeInner::new()),
        }
    }
    // 读取文件内容, offset是字节偏移, hint_physical_blk_range是None
    // 也可以用于目录读取, used by `load_children_from_disk`
    pub fn read(
        &self,
        offset: usize,
        buf: &mut [u8],
        hint_physical_blk_range: Option<PhysicalBlockRange>,
    ) -> Result<usize, &'static str> {
        // 需要读取的总长度
        let rbuf_len = buf.len();
        // 先读取页缓存
        let mut current_read = 0;
        let mut page_offset = offset >> PAGE_SIZE_BITS;
        let mut page_offset_in_page = offset & (PAGE_SIZE_BITS - 1);

        let mut current_physical_block_range: Option<PhysicalBlockRange> = hint_physical_blk_range;
        let mut page: Arc<SpinNoIrqLock<Page>>;
        let mut fs_block_id: usize;

        while current_read < rbuf_len {
            if let Some(page_cache) = self.address_space.get_page_cache(page_offset) {
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
                page = self.address_space.new_page_cache(
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

impl Inode {
    pub fn children_handler<T>(&self, f: impl FnOnce(&mut BTreeMap<String, Arc<Inode>>) -> T) -> T {
        let mut inner = self.inner.lock();
        if inner.state == InodeState::Init {
            inner.state = InodeState::Unmodified;
            self.load_children_from_disk();
            f(&mut self.inner.lock().children)
        } else {
            f(&mut inner.children)
        }
    }
    /// 从磁盘加载子节点
    pub fn load_children_from_disk(&self) {
        let phy_blk_ranges = self.inode.read_all(self.block_device.clone());
        phy_blk_ranges.drain(..).for_each(|phy_blk_range| {
            let mut buf = [0u8; PAGE_SIZE];
            let read_len = self.read(
                phy_blk_range.logical_block_id << PAGE_SIZE_BITS,
                &mut buf,
                Some(phy_blk_range),
            );
            if read_len != PAGE_SIZE {
                panic!("read_len != PAGE_SIZE");
            }
            let dir_content = Ext4DirContent::new(&buf);
            for (name, inode_id) in dir_content.iter() {
                let inode = Inode::new(inode_id, self.super_block.clone());
                self.inner.lock().children.insert(name.clone(), inode);
            }
        });
        // 读取目录内容
        //     for phy_blk_range in phy_blk_ranges {
        //         let mut buf = [0u8; PAGE_SIZE];

        //         let read_len = self.read(phy_blk_range.logical_block_id << PAGE_SIZE_BITS, &mut buf);
        //         if read_len != PAGE_SIZE {
        //             panic!("read_len != PAGE_SIZE");
        //         }
        //         let dir_content = Ext4DirContent::new(&buf);
        //         for (name, inode_id) in dir_content.iter() {
        //             let inode = Inode::new(inode_id, self.super_block.clone());
        //             self.inner.lock().children.insert(name.clone(), inode);
        //         }
        //     }
        // }
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
    // 读取逻辑块好为page_offset页所在返回extent
    // 用于文件读写
    fn read<'a>(
        &'a self,
        page_offset: usize,
        block_device: Arc<dyn BlockDevice>,
    ) -> Result<PhysicalBlockRange, &'static str>;
    // 用于目录, `load_children_from_disk`
    fn read_all(&self, block_device: Arc<dyn BlockDevice>) -> Vec<PhysicalBlockRange>;
    fn write<'a>(&'a self, page_offset: usize, buf: &'a [u8]) -> usize;
}

//! Todo: 还需要搞定extent tree的逻辑
use alloc::{
    collections::btree_map::BTreeMap,
    sync::{Arc, Weak},
};
use spin::RwLock;

use crate::{
    drivers::block::block_dev::{self, BlockDevice},
    mm::{Page, PageKind},
};

use super::inode::InodeOp;
// Todo:
// 管理页缓存, 注意页缓存只存储文件的数据, 不存储元数据
pub struct AddressSpace {
    // Todo: linux使用的是`xarray`, 这里先用`BTreeMap`代替
    // 页缓存, key是页在文件中的页偏移(Page->index), value是页缓存
    // Todo: 这个要换成读写锁
    i_pages: RwLock<BTreeMap<usize, Arc<Page>>>, // 文件对应的页缓存
}

impl AddressSpace {
    pub fn new() -> Self {
        Self {
            i_pages: RwLock::new(BTreeMap::new()),
        }
    }
    /// offset是页在文件中的页偏移(以PAGE_SIZE为单位)
    /// 如果未命中, 不会创建新的页缓存
    pub fn get_page_cache(self: &Self, page_offset: usize) -> Option<Arc<Page>> {
        // 看i_pages中是否有对应的页缓存
        if let Some(page) = self.i_pages.read().get(&page_offset) {
            return Some(page.clone());
        } else {
            None
        }
    }
    pub fn new_page_cache(
        self: &Self,
        page_offset: usize,
        fs_block_id: usize,
        block_device: Arc<dyn BlockDevice>,
        inode: Weak<dyn InodeOp>,
    ) -> Arc<Page> {
        let page = Arc::new(Page::new_shared(
            fs_block_id,
            block_device,
            inode,
        ));
        self.i_pages.write().insert(page_offset, page.clone());
        page
    }
    pub fn new_inline_page_cache(
        self: &Self,
        page_offset: usize,
        inode: Weak<dyn InodeOp>,
        inline_data: &[u8],
    ) -> Arc<Page> {
        // inline data目前最大是60字节, 应该是第一页
        assert!(page_offset == 0);
        let page = Arc::new(Page::new_inline(inode, inline_data));
        self.i_pages.write().insert(page_offset, page.clone());
        page
    }
    // Page有Drop trait, 会写回到磁盘
    pub fn clear(self: &Self) {
        self.i_pages.write().clear();
    }
}

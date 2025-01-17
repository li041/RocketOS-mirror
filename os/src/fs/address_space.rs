//! Todo: 还需要搞定extent tree的逻辑
use alloc::{
    collections::btree_map::BTreeMap,
    sync::{Arc, Weak},
};

use crate::{
    drivers::block::block_dev::{self, BlockDevice},
    mm::page::Page,
    mutex::SpinNoIrqLock,
};

use super::inode_trait::InodeTrait;

// Todo:
// 管理页缓存, 注意页缓存只存储文件的数据, 不存储元数据
pub struct AddressSpace {
    // Todo: linux使用的是`xarray`, 这里先用`BTreeMap`代替
    // 页缓存, key是页在文件中的页偏移(Page->index), value是页缓存
    i_pages: BTreeMap<usize, Arc<SpinNoIrqLock<Page>>>, // 文件对应的页缓存
}

impl AddressSpace {
    pub fn new() -> Self {
        Self {
            i_pages: BTreeMap::new(),
        }
    }
    /// offset是页在文件中的页偏移(以PAGE_SIZE为单位)
    pub fn get_page_cache(self: &Self, page_offset: usize) -> Option<Arc<SpinNoIrqLock<Page>>> {
        // 看i_pages中是否有对应的页缓存
        if let Some(page) = self.i_pages.get(&page_offset) {
            return Some(page.clone());
        } else {
            None
        }
    }
    pub fn new_page_cache(
        self: &mut Self,
        page_offset: usize,
        fs_block_id: usize,
        block_device: Arc<dyn BlockDevice>,
    ) -> Arc<SpinNoIrqLock<Page>> {
        let page = Arc::new(SpinNoIrqLock::new(Page::new(
            page_offset,
            fs_block_id,
            block_device,
        )));
        self.i_pages.insert(page_offset, page.clone());
        page
    }
}

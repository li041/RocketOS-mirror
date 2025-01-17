//! Todo: 还需要搞定extent tree的逻辑
use alloc::{
    collections::btree_map::BTreeMap,
    sync::{Arc, Weak},
};

use crate::{drivers::block::block_dev::BlockDevice, mm::page::Page, mutex::SpinNoIrqLock};

use super::inode_trait::InodeTrait;

// Todo:
// 管理页缓存, 注意页缓存只存储文件的数据, 不存储元数据
pub struct AddressSpace {
    host: Weak<dyn InodeTrait>, // address space所属的inode, 每个inode对应一个address space
    // Todo: linux使用的是`xarray`, 这里先用`BTreeMap`代替
    // 页缓存, key是页在文件中的页偏移(Page->index), value是页缓存
    i_pages: SpinNoIrqLock<BTreeMap<usize, Arc<SpinNoIrqLock<Page>>>>, // 文件对应的页缓存
    // underlying block device
    block_device: Arc<dyn BlockDevice>,
}

impl AddressSpace {
    pub fn new(host: Arc<dyn InodeTrait>, block_device: Arc<dyn BlockDevice>) -> Self {
        Self {
            host: Arc::downgrade(&host),
            i_pages: SpinNoIrqLock::new(BTreeMap::new()),
            block_device,
        }
    }
    /// offset是页在文件中的页偏移(以PAGE_SIZE为单位)
    pub fn get_page_cache(self: &Arc<Self>, offset: usize) -> Arc<SpinNoIrqLock<Page>> {
        // 看i_pages中是否有对应的页缓存
        if let Some(page) = self.i_pages.lock().get(&offset) {
            return page.clone();
        } else {
            // 如果没有, 则创建一个新的页缓存
            let page = Arc::new(SpinNoIrqLock::new(Page::new(Arc::downgrade(self), offset)));
            // 从block_device中读取数据到页缓存中
            // Todo:
            return page.clone();
        }
    }
}

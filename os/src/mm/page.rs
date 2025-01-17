use core::ops::Add;

use alloc::sync::Arc;
use virtio_drivers::PAGE_SIZE;

use crate::{
    drivers::block::{self, block_dev::BlockDevice, VIRTIO_BLOCK_SIZE},
    fs::FS_BLOCK_SIZE,
};

// 页缓存中使用的页结构
pub struct Page {
    cache: [u8; PAGE_SIZE], // 页缓存, 页的大小是4KB
    // frame: FrameTracker,         // 页对应的物理页帧
    // mapping: &'a mut AddressSpace<'a>,
    index: usize, // 页在文件中的页偏移, `index * PAGE_SIZE`就是页在文件中的字节偏移, 在`AddressSpace`中标识页的逻辑位置
    // underlying block id
    start_block_id: usize,
    block_device: Arc<dyn BlockDevice>,
    /// whether the page is dirty
    modified: bool,
}

impl Page {
    pub fn new(index: usize, fs_block_id: usize, block_device: Arc<dyn BlockDevice>) -> Self {
        let mut cache = [0u8; PAGE_SIZE];
        let start_block_id = fs_block_id * (*FS_BLOCK_SIZE / VIRTIO_BLOCK_SIZE);
        // 从块设备中读取数据到缓存中
        block_device.read_blocks(start_block_id, &mut cache);
        Self {
            cache,
            index,
            start_block_id,
            block_device,
            modified: false,
        }
    }
    /// Get the address of an offset inside the cached block data
    fn addr_of_offset(&self, offset: usize) -> usize {
        &self.cache[offset] as *const _ as usize
    }
    pub fn get_ref<T>(&self, offset: usize) -> &T
    where
        T: Sized,
    {
        let type_size = core::mem::size_of::<T>();
        assert!(offset + type_size <= PAGE_SIZE);
        let addr = self.addr_of_offset(offset);
        unsafe { &*(addr as *const T) }
    }

    pub fn get_mut<T>(&mut self, offset: usize) -> &mut T
    where
        T: Sized,
    {
        let type_size = core::mem::size_of::<T>();
        assert!(offset + type_size <= PAGE_SIZE);
        self.modified = true;
        let addr = self.addr_of_offset(offset);
        unsafe { &mut *(addr as *mut T) }
    }
    pub fn read<T, V>(&self, offset: usize, f: impl FnOnce(&T) -> V) -> V {
        f(self.get_ref(offset))
    }

    // Modify the cached data through the closure function f
    pub fn modify<T, V>(&mut self, offset: usize, f: impl FnOnce(&mut T) -> V) -> V {
        f(self.get_mut(offset))
    }

    pub fn sync(&mut self) {
        if self.modified {
            self.modified = false;
            // self.block_device.write_blocks(self.block_id, &self.cache);
        }
    }
}

impl Drop for Page {
    fn drop(&mut self) {
        self.sync()
    }
}

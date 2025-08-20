//! 操作块的基本单位, 管理元数据(读写块组描述符, 超级块等文件系统原信息)
use super::{BLOCK_CACHE_SIZE, VIRTIO_BLOCK_SIZE};
use crate::drivers::block::block_dev::BlockDevice;
use crate::fs::FS_BLOCK_SIZE;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use lazy_static::*;
use spin::Mutex;

/// Cached block inside memory
pub struct BlockCache {
    /// 操作块的基本单位, 管理元数据(读写块组描述符, 超级块等文件系统原信息)
    /// cached block data
    cache: Vec<u8>,
    cache_size: usize,
    /// underlying block id
    block_id: usize,
    /// underlying block device
    block_device: Arc<dyn BlockDevice>,
    /// whether the block is dirty
    modified: bool,
}

impl BlockCache {
    /// Load a new BlockCache from disk.
    /// 从磁盘start_block_id开始连续读取cache_size大小的数据到内存中
    pub fn new(fs_block_id: usize, block_device: Arc<dyn BlockDevice>, cache_size: usize) -> Self {
        debug_assert!(
            cache_size & (VIRTIO_BLOCK_SIZE - 1) == 0,
            "Cache size must be a multiple of VIRTIO_BLOCK_SIZE, which is {}",
            cache_size
        );
        let mut cache = vec![0u8; cache_size];
        // 将FS_block_id转换为VirtIOBlk的block_id
        let start_block_id = fs_block_id * (*FS_BLOCK_SIZE / VIRTIO_BLOCK_SIZE);
        block_device.read_blocks(start_block_id, &mut cache);
        Self {
            cache,
            cache_size,
            block_id: start_block_id,
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
        debug_assert!(
            offset + type_size <= self.cache_size,
            "offset: {}, type_size: {}, cache_size: {}",
            offset,
            type_size,
            self.cache_size
        );
        let addr = self.addr_of_offset(offset);
        unsafe { &*(addr as *const T) }
    }

    pub fn get_mut<T>(&mut self, offset: usize) -> &mut T
    where
        T: Sized,
    {
        let type_size = core::mem::size_of::<T>();
        debug_assert!(offset + type_size <= self.cache_size);
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
            self.block_device.write_blocks(self.block_id, &self.cache);
        }
    }
}

impl Drop for BlockCache {
    fn drop(&mut self) {
        log::info!("[BlockCache] Drop BlockCache: block_id = {}", self.block_id);
        self.sync()
    }
}

pub struct BlockCacheManager {
    pub queue: VecDeque<(usize, Arc<Mutex<BlockCache>>)>,
}

impl BlockCacheManager {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }
    pub fn get_block_cache(
        &mut self,
        fs_block_id: usize,
        block_device: Arc<dyn BlockDevice>,
        cache_size: usize,
    ) -> Arc<Mutex<BlockCache>> {
        if let Some(pair) = self.queue.iter().find(|pair| fs_block_id == pair.0)
        // 这里好像不用判断, 因为FS block_size是VirtIO的倍数, 上层文件系统访问给出的block_id是VirtIO的倍数
        // .find(|pair| block_id >= pair.0 && block_id < pair.0 + cache_size / VIRTIO_BLOCK_SIZE)
        {
            // 找对应的块(大小不定, 512byts的倍数)
            Arc::clone(&pair.1)
        } else {
            if self.queue.len() == BLOCK_CACHE_SIZE {
                if let Some((idx, _)) = self
                    .queue
                    .iter()
                    .enumerate()
                    .find(|(_, pair)| Arc::strong_count(&pair.1) == 1)
                {
                    self.queue.drain(idx..=idx);
                } else {
                    panic!("Run out of BLOCK_CACHE!");
                }
            }
            let block_cache = Arc::new(Mutex::new(BlockCache::new(
                fs_block_id,
                Arc::clone(&block_device),
                cache_size,
            )));
            self.queue
                .push_back((fs_block_id, Arc::clone(&block_cache)));
            block_cache
        }
    }
}

lazy_static! {
    /// The global block cache manager
    pub static ref BLOCK_CACHE_MANAGER: Mutex<BlockCacheManager> =
        Mutex::new(BlockCacheManager::new());
}

/// Get the block cache corresponding to the given block id and block device
pub fn get_block_cache(
    fs_block_id: usize,
    block_device: Arc<dyn BlockDevice>,
    cache_size: usize,
) -> Arc<Mutex<BlockCache>> {
    BLOCK_CACHE_MANAGER
        .lock()
        .get_block_cache(fs_block_id, block_device, cache_size)
}

/// Sync all block cache to block device
#[allow(unused)]
pub fn block_cache_sync_all() {
    let manager = BLOCK_CACHE_MANAGER.lock();
    for (_, cache) in manager.queue.iter() {
        cache.lock().sync();
    }
}

use super::super_block::Ext4SuperBlock;
use alloc::sync::Arc;

use crate::{
    drivers::{
        block::{block_cache::get_block_cache, block_dev::BlockDevice},
        BLOCK_DEVICE,
    },
    ext4::super_block::Ext4Meta,
    fs::FSMutex,
};

pub struct Ext4FileSystem {
    pub block_device: Arc<dyn BlockDevice>,
    pub ext4_meta: Arc<Ext4Meta>,
}

impl Ext4FileSystem {
    /// Opens and loads an Ext4 from the `block_device`
    pub fn open(block_device: Arc<dyn BlockDevice>) -> Arc<FSMutex<Self>> {
        log::info!(
            "sizeof(Ext4SuperBlock): {}",
            core::mem::size_of::<Ext4SuperBlock>()
        );
        log::debug!("[Ext4FileSystem::open()]");
        // 从block_device中读取第2块(0x400)数据，解析出Ext4SuperBlock，然后创建Ext4Meta
        let ext4_meta = get_block_cache(
            2,
            block_device.clone(),
            core::mem::size_of::<Ext4SuperBlock>(),
        )
        .lock()
        .read(0, |super_block: &Ext4SuperBlock| {
            log::debug!("[Ext4FileSystem::open()] super_block: {:?}", super_block);
            assert!(
                super_block.is_valid(),
                "[Ext4FileSystem::open()] Error loading super_block!"
            );
            Arc::new(Ext4Meta::new(super_block))
        });
        Arc::new(FSMutex::new(Self {
            block_device,
            ext4_meta,
        }))
    }
}

use super::super_block::Ext4SuperBlockDisk;
use alloc::{sync::Arc, vec::Vec};

use crate::{
    drivers::block::{block_cache::get_block_cache, block_dev::BlockDevice, VIRTIO_BLOCK_SIZE},
    ext4::{
        block_group::{self, Ext4GroupDescDisk, GroupDesc},
        super_block::Ext4SuperBlock,
    },
    fs::FS_BLOCK_SIZE,
};

// 减小锁粒度
pub struct Ext4FileSystem {
    pub super_block: Arc<Ext4SuperBlock>,
    pub block_groups: Vec<Arc<GroupDesc>>,
    pub block_device: Arc<dyn BlockDevice>,
}

const EXT4_SUPERBLOCK_OFFSET: usize = 1024;
pub const EXT4_BLOCK_SIZE: usize = 4096;

impl Ext4FileSystem {
    /// Opens and loads an Ext4 from the `block_device`
    /// 返回ext4文件系统和根目录inode
    pub fn open(block_device: Arc<dyn BlockDevice>) -> Arc<Self> {
        // 对于Ext4文件系统block_size是4096, 其中superblock在0x400偏移处, 前512bytes是留给引导程序的
        let super_block_cache = get_block_cache(0, block_device.clone(), EXT4_BLOCK_SIZE);

        let super_block = super_block_cache.lock().read(
            EXT4_SUPERBLOCK_OFFSET,
            |ext4_super_block_disk: &Ext4SuperBlockDisk| {
                log::info!(
                    "[Ext4FileSystem::open()] super_block: {:?}",
                    ext4_super_block_disk
                );
                debug_assert!(
                    ext4_super_block_disk.is_valid(),
                    "[Ext4FileSystem::open()] Error loading super_block!"
                );
                Arc::new(Ext4SuperBlock::new(ext4_super_block_disk))
            },
        );

        // 读取块组信息
        // 块组描述符表的位置是紧跟在超级块之后，即从 块 1 开始。
        log::info!(
            "size of GroupDesc: {}",
            core::mem::size_of::<block_group::GroupDesc>()
        );
        let mut block_groups: Vec<Arc<GroupDesc>> = Vec::new();
        let block_group_count = super_block.block_group_count as usize;

        // 注意这里有假设: 假设块组描述符表在第一个块中
        debug_assert!(block_group_count * core::mem::size_of::<GroupDesc>() < EXT4_BLOCK_SIZE);
        let block_groups_block = get_block_cache(1, block_device.clone(), EXT4_BLOCK_SIZE);
        for i in 0..block_group_count as usize {
            block_groups_block.lock().read(
                i * core::mem::size_of::<Ext4GroupDescDisk>(),
                |group_desc: &Ext4GroupDescDisk| {
                    block_groups.push(Arc::new(GroupDesc::new(group_desc)));
                },
            );
        }
        log::info!("Group 0 inode_table: {}", block_groups[0].inode_table());

        let ext4_fs = Arc::new(Self {
            super_block,
            block_groups,
            block_device,
        });
        return ext4_fs;
    }
    // 先使用最简单的first fit算法
    // Todo: 目录分离, 文件与父目录就近分配
    pub fn alloc_inode(&self, block_device: Arc<dyn BlockDevice>, is_dir: bool) -> usize {
        // Todo: 没有考虑灵活块组的支持
        let inode_bitmap_size = self.super_block.inodes_per_group as usize / 8;
        log::info!(
            "[Ext4FileSystem::alloc_inode]inode_bitmap_size: {}, inodes_per_group: {}",
            inode_bitmap_size,
            self.super_block.inodes_per_group
        );
        // 循环遍历块组
        for (i, group) in self.block_groups.iter().enumerate() {
            if let Some(local_inode_num) = group.alloc_inode(
                block_device.clone(),
                self.block_size(),
                inode_bitmap_size,
                is_dir,
            ) {
                // 修改super_block的free_inodes_count
                self.super_block.inner.write().free_inodes_count -= 1;
                let global_inode_num =
                    local_inode_num + self.super_block.inodes_per_group as usize * i;
                return global_inode_num;
            }
        }
        panic!("No available inode!");
    }
    pub fn dealloc_inode(
        &self,
        block_device: Arc<dyn BlockDevice>,
        global_inode_num: usize,
        is_dir: bool,
    ) {
        let group_id = global_inode_num / self.super_block.inodes_per_group as usize;
        let local_inode_num = global_inode_num % self.super_block.inodes_per_group as usize;
        let block_bitmap_size = self.super_block.inodes_per_group as usize / 8;
        self.block_groups[group_id].dealloc_inode(
            block_device.clone(),
            local_inode_num,
            is_dir,
            self.super_block.inode_size as usize,
            self.block_size(),
            block_bitmap_size,
        );
    }

    pub fn add_orphan_inode(&self, inode_num: usize) {
        self.super_block.orphan_inodes.write().push(inode_num);
    }
    // pub fn alloc_block(&self, block_device: Arc<dyn BlockDevice>, block_count: usize) -> usize {
    //     let block_bitmap_size = self.super_block.blocks_per_group as usize / 8;
    //     for (i, group) in self.block_groups.iter().enumerate() {
    //         if let Some(local_block_num) = group.alloc_block(
    //             block_device.clone(),
    //             self.block_size(),
    //             block_bitmap_size,
    //             block_count,
    //         ) {
    //             // 修改super_block的free_blocks_count
    //             self.super_block.inner.write().free_blocks_count -= 1;
    //             let global_block_num =
    //                 local_block_num + self.super_block.blocks_per_group as usize * i;
    //             return global_block_num;
    //         }
    //     }
    //     panic!("No available block!");
    // }
    pub fn alloc_one_block(&self, block_device: Arc<dyn BlockDevice>) -> usize {
        let block_bitmap_size = self.super_block.blocks_per_group as usize / 8;
        for (i, group) in self.block_groups.iter().enumerate() {
            if let Some(local_start) =
                group.alloc_one_block(block_device.clone(), self.block_size(), block_bitmap_size)
            {
                // 修改super_block的free_blocks_count
                self.super_block.inner.write().free_blocks_count -= 1;
                let global_start = local_start + self.super_block.blocks_per_group as usize * i;
                // 清空对应数据块
                let block_id = global_start * (*FS_BLOCK_SIZE / VIRTIO_BLOCK_SIZE);
                self.block_device
                    .write_blocks(block_id, &[0; EXT4_BLOCK_SIZE]);
                return global_start;
            }
        }
        panic!("No available block in any block group!");
    }
    pub fn alloc_block(
        &self,
        block_device: Arc<dyn BlockDevice>,
        block_count: usize,
    ) -> Vec<(usize, u32)> {
        let block_bitmap_size = self.super_block.blocks_per_group as usize / 8;
        let mut result = Vec::new();
        let mut remaining = block_count;

        for (i, group) in self.block_groups.iter().enumerate() {
            if remaining == 0 {
                break;
            }

            let allocated_blocks = group.alloc_block(
                block_device.clone(),
                self.block_size(),
                block_bitmap_size,
                remaining,
            );

            for (local_start, count) in allocated_blocks {
                let global_start = local_start + self.super_block.blocks_per_group as usize * i;

                result.push((global_start, count));

                // 减去已经分配的块数
                remaining -= count as usize;
                self.super_block.inner.write().free_blocks_count -= count as u64;
                // 清空对应数据块
                for _ in 0..count {
                    let block_id = global_start * (*FS_BLOCK_SIZE / VIRTIO_BLOCK_SIZE);
                    self.block_device
                        .write_blocks(block_id, &[0; EXT4_BLOCK_SIZE]);
                }

                if remaining == 0 {
                    break;
                }
            }
        }
        result
    }

    pub fn dealloc_block(
        &self,
        block_device: Arc<dyn BlockDevice>,
        block_num: usize,
        block_count: usize,
    ) {
        let group_id = block_num / self.super_block.blocks_per_group as usize;
        let local_block_num = block_num % self.super_block.blocks_per_group as usize;
        let block_bitmap_size = self.super_block.blocks_per_group as usize / 8;
        self.block_groups[group_id].dealloc_block(
            block_device.clone(),
            local_block_num,
            block_count,
            self.super_block.block_size as usize,
            block_bitmap_size,
        );
        self.super_block.inner.write().free_blocks_count += block_count as u64;
    }
}

impl Ext4FileSystem {
    pub fn block_size(&self) -> usize {
        self.super_block.block_size as usize
    }
}

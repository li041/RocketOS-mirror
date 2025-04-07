use alloc::sync::Arc;
use log::info;

use super::{
    fs::{FAT32Info, FAT32Meta},
    FAT32_SECTOR_SIZE, FATENTRY_EOC, FATENTRY_MASK, FATENTRY_MIN_EOC, FAT_ENTRY_PER_SECTOR,
    FSINFO_NOT_AVAILABLE,
};

use crate::fs::FSMutex;

use crate::drivers::block::{block_cache::get_block_cache, block_dev::BlockDevice};

// 在`read_fat_entry`和`write_fat_entry`中，我们使用了`get_block_cache`函数来获取`BlockCache`的引用。
// 然后使用get_mut<T>和get_ref<T>来将`BlockCache`的引用转换为`FATSector`的引用。
// 之后我们使用`read`和`modify`函数来读取和修改`FATSector`中的数据。
struct FATSector {
    pub data: [u32; FAT_ENTRY_PER_SECTOR],
}

impl FATSector {
    pub fn read(&self, offset: usize) -> Option<u32> {
        if offset < FAT_ENTRY_PER_SECTOR {
            Some(self.data[offset])
        } else {
            None
        }
    }

    pub fn write(&mut self, offset: usize, val: u32) -> Option<()> {
        if offset < FAT_ENTRY_PER_SECTOR {
            self.data[offset] = val;
            Some(())
        } else {
            None
        }
    }
}

pub struct FAT32FileAllocTable {
    /// Block device, 可能要读的块不在BlockCache中, 需要BlockDevice读取
    pub block_device: Arc<dyn BlockDevice>,
    pub info: Arc<FSMutex<FAT32Info>>,
    pub meta: Arc<FAT32Meta>,
}

// 目前采用的分配簇的策略是，先尽量使用`info.last_used_cluster`之后的簇，
// 如果last_used_cluster等于(meta.total_cluster_count + 1) ,则遍历FAT表，找到第一个空闲的cluster
// 注意，这里的cluster_id是从2开始的，因为0和1是保留的, 而totoal_cluster_count是可用的cluster数目(不包括保留的前两个簇)
impl FAT32FileAllocTable {
    pub fn new(
        block_device: Arc<dyn BlockDevice>,
        info: Arc<FSMutex<FAT32Info>>,
        meta: Arc<FAT32Meta>,
    ) -> Self {
        let ret = Self {
            block_device,
            info,
            meta,
        };
        ret.stat_free();
        ret
    }

    // update FAT32Info
    fn stat_free(&self) {
        let mut info = self.info.write();
        if info.free_cluster_count == (FSINFO_NOT_AVAILABLE as usize)
            || info.next_free_cluster == (FSINFO_NOT_AVAILABLE as usize)
        {
            info.free_cluster_count = 0;
            info.next_free_cluster = 0;
            for i in 0..self.meta.total_cluster_count {
                // 前两个cluster是保留的
                // 遍历FAT表，统计空闲cluster数目
                let cluster_id = i + 2;
                let fat_entry = self.read_fat_entry(cluster_id).unwrap() & 0x0FFFFFFF;
                if fat_entry == 0 {
                    info.free_cluster_count += 1;
                } else {
                    info.next_free_cluster = cluster_id;
                }
            }
        }
    }

    /// 读取FAT中对应`cluster_id`的表项
    pub fn read_fat_entry(&self, cluster_id: usize) -> Option<u32> {
        if cluster_id < 2 || cluster_id > self.meta.total_cluster_count + 1 {
            log::info!(
                "[FileAllocTable::read_fat] cluster_id out of range: {}",
                cluster_id
            );
            return None;
        }
        let sector_id = cluster_id / FAT_ENTRY_PER_SECTOR;
        let offset = cluster_id % FAT_ENTRY_PER_SECTOR;
        get_block_cache(
            self.meta.fat_start_sector + sector_id,
            self.block_device.clone(),
            FAT32_SECTOR_SIZE,
        )
        .lock()
        .read(0, |fat_sector: &FATSector| fat_sector.read(offset))
    }

    /// 写入FAT中对应`cluster_id`的表项
    fn write_fat_entry(&self, cluster_id: usize, val: u32) -> Option<()> {
        if cluster_id < 2 || cluster_id > self.meta.total_cluster_count + 1 {
            return None;
        }
        let sector_id = cluster_id / FAT_ENTRY_PER_SECTOR;
        let offset = cluster_id % FAT_ENTRY_PER_SECTOR;
        get_block_cache(
            self.meta.fat_start_sector + sector_id,
            self.block_device.clone(),
            FAT32_SECTOR_SIZE,
        )
        .lock()
        .modify(0, |fat_sector: &mut FATSector| {
            fat_sector.write(offset, val)
        })
    }

    // 分配一个空闲的cluster, 由调用者负责保证这个簇在某个簇链中
    fn alloc_cluster_inner(&self) -> Option<usize> {
        let mut info = self.info.write();
        info!(
            "[FileAllocTable::alloc_cluster_inner] tot_cluster_count: {}, last_used_cluster: {}",
            self.meta.total_cluster_count, info.next_free_cluster
        );
        if info.next_free_cluster != self.meta.total_cluster_count + 1 {
            info.next_free_cluster += 1;
            info.free_cluster_count -= 1;
            Some(info.next_free_cluster)
        } else {
            // 遍历FAT表，找到第一个空闲的cluster
            for i in 0..self.meta.total_cluster_count {
                let cluster_id = i + 2;
                let fatentry = self.read_fat_entry(cluster_id).unwrap() & FATENTRY_MASK;
                if fatentry == 0 {
                    info.free_cluster_count -= 1;
                    return Some(cluster_id);
                }
            }
            None
        }
    }

    pub fn alloc_cluster(&self, prev: Option<usize>) -> Option<usize> {
        if let Some(ret) = self.alloc_cluster_inner() {
            if let Some(pre) = prev {
                // 检查prev是否是簇链的尾部
                if self.read_fat_entry(pre).unwrap() < FATENTRY_MIN_EOC {
                    info!("[FAT::alloc_cluster]write data at non fat link tail!");
                }
                self.write_fat_entry(pre, ret as u32);
            } else {
                // 将新分配的簇设置为结束簇
                self.write_fat_entry(ret, FATENTRY_EOC);
            }
            Some(ret)
        } else {
            None
        }
    }

    pub fn free_cluster(&self, cluster_id: usize, prev: Option<usize>) -> Option<()> {
        if let Some(pre) = prev {
            // 检查prev的下一个簇是否是cluster_id
            if self.read_fat_entry(pre).unwrap() as usize != cluster_id {
                info!("not a right pre!");
                return None;
            }
            self.write_fat_entry(pre, FATENTRY_EOC);
        }
        self.write_fat_entry(cluster_id, 0);
        self.info.write().free_cluster_count += 1;
        Some(())
    }
}

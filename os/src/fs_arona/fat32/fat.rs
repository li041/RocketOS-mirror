use core::sync::atomic::{AtomicUsize, Ordering};

use alloc::sync::Arc;
use log::info;

use crate::drivers::block::block_dev::BlockDevice;

use super::{
    block_cache::get_block_cache,
    // block_dev::BlockDevice,
    fs::{FAT32Info, FAT32Meta},
    SpinNoIrqLock,
    FATENTRY_EOC,
    FATENTRY_MASK,
    FATENTRY_MIN_EOC,
    FATENTRY_PER_SECTOR,
    FSI_NOT_AVAILABLE,
};

struct FATSector {
    pub data: [u32; FATENTRY_PER_SECTOR],
}

impl FATSector {
    pub fn read(&self, offset: usize) -> Option<u32> {
        if offset < FATENTRY_PER_SECTOR {
            Some(self.data[offset])
        } else {
            None
        }
    }

    pub fn write(&mut self, offset: usize, val: u32) -> Option<()> {
        if offset < FATENTRY_PER_SECTOR {
            self.data[offset] = val;
            Some(())
        } else {
            None
        }
    }
}

pub struct FAT32FileAllocTable {
    pub block_device: Arc<dyn BlockDevice>,
    pub info: Arc<SpinNoIrqLock<FAT32Info>>,
    pub meta: Arc<FAT32Meta>,
    pub ino_counter: AtomicUsize,
}

impl FAT32FileAllocTable {
    pub fn new(
        block_device: Arc<dyn BlockDevice>,
        info: Arc<SpinNoIrqLock<FAT32Info>>,
        meta: Arc<FAT32Meta>,
    ) -> Self {
        let ret = Self {
            block_device,
            info,
            meta,
            ino_counter: AtomicUsize::new(0),
        };
        ret.stat_free();
        ret
    }

    // update FAT32Info
    fn stat_free(&self) {
        let mut info = self.info.lock();
        if info.free_cluster_count == (FSI_NOT_AVAILABLE as usize)
            || info.next_free_cluster == (FSI_NOT_AVAILABLE as usize)
        {
            info.free_cluster_count = 0;
            info.next_free_cluster = 0;
            for i in 0..self.meta.total_cluster_count {
                let cluster_id = i + 2;
                let fatentry = self.read_fat(cluster_id).unwrap() & 0x0FFFFFFF;
                if fatentry == 0 {
                    info.free_cluster_count += 1;
                } else {
                    info.next_free_cluster = cluster_id;
                }
            }
        }
    }

    pub fn read_fat(&self, cluster_id: usize) -> Option<u32> {
        if cluster_id < 2 || cluster_id > self.meta.total_cluster_count + 1 {
            return None;
        }
        let sector_id = cluster_id / FATENTRY_PER_SECTOR;
        let offset = cluster_id % FATENTRY_PER_SECTOR;
        get_block_cache(
            self.meta.fat_start_sector + sector_id,
            self.block_device.clone(),
        )
        .lock()
        .read(0, |fat_sector: &FATSector| fat_sector.read(offset))
    }

    fn write_fat(&self, cluster_id: usize, val: u32) -> Option<()> {
        if cluster_id < 2 || cluster_id > self.meta.total_cluster_count + 1 {
            return None;
        }
        let sector_id = cluster_id / FATENTRY_PER_SECTOR;
        let offset = cluster_id % FATENTRY_PER_SECTOR;
        get_block_cache(
            self.meta.fat_start_sector + sector_id,
            self.block_device.clone(),
        )
        .lock()
        .modify(0, |fat_sector: &mut FATSector| {
            fat_sector.write(offset, val)
        })
    }

    fn alloc_cluster_inner(&self) -> Option<usize> {
        let mut info = self.info.lock();
        info!(
            "[FileAllocTable::alloc_cluster_inner] tot_cluster_count: {}, nxt_free: {}",
            self.meta.total_cluster_count, info.next_free_cluster
        );
        if info.next_free_cluster != self.meta.total_cluster_count + 1 {
            info.next_free_cluster += 1;
            info.free_cluster_count -= 1;
            Some(info.next_free_cluster)
        } else {
            for i in 0..self.meta.total_cluster_count {
                let cluster_id = i + 2;
                let fatentry = self.read_fat(cluster_id).unwrap() & FATENTRY_MASK;
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
                if self.read_fat(pre).unwrap() < FATENTRY_MIN_EOC {
                    info!("[FAT::alloc_cluster] write data at non fat link tail!");
                }
                self.write_fat(pre, ret as u32);
            }
            self.write_fat(ret, FATENTRY_EOC);
            Some(ret)
        } else {
            None
        }
    }

    pub fn free_cluster(&self, cluster_id: usize, prev: Option<usize>) -> Option<()> {
        if let Some(pre) = prev {
            if self.read_fat(pre).unwrap() as usize != cluster_id {
                info!("[FAT::free_cluster] not a right pre!");
                return None;
            }
            self.write_fat(pre, 0x0FFFFFFF);
        }
        self.write_fat(cluster_id, 0);
        self.info.lock().free_cluster_count += 1;
        Some(())
    }

    pub fn alloc_ino(&self) -> usize {
        self.ino_counter.fetch_add(1, Ordering::Relaxed)
    }
}

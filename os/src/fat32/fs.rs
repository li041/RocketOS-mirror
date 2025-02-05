use alloc::sync::Arc;

use crate::{
    drivers::block::block_cache::get_block_cache,
    fat32::FAT32_SECTOR_SIZE,
    fs::{
        old::{inode_trait::InodeTrait, path_old::PathOld},
        FSMutex,
    },
};

use super::{
    fat::FAT32FileAllocTable,
    inode::FAT32Inode,
    layout::{FAT32BootSector, FAT32FSInfoSector},
};

use crate::drivers::block::block_dev::BlockDevice;

pub struct FAT32FileSystem {
    pub root_inode: Arc<dyn InodeTrait>,
}

impl FAT32FileSystem {
    pub fn open(block_device: Arc<dyn BlockDevice>) -> Arc<FSMutex<Self>> {
        log::debug!("FAT32FileSystem::open()");
        // 读取引导扇区
        let fs_meta = get_block_cache(0, block_device.clone(), FAT32_SECTOR_SIZE)
            .lock()
            .read(0, |boot_sector: &FAT32BootSector| {
                log::info!("FAT32FileSystem::open(): boot_sector: {:?}", boot_sector);
                assert!(
                    boot_sector.is_valid(),
                    "FAT32FileSystem::open(): Error loading boot_sector!"
                );
                // log::info!("{:?}", boot_sector);
                Arc::new(FAT32Meta::new(boot_sector))
            });
        log::info!(
            "FAT32FileSystem::open(): sector_per_cluster: {:?}, data_start_sector: {:?}",
            fs_meta.sector_per_cluster,
            fs_meta.data_start_sector
        );
        // 读取FSInfoSector
        let fs_info = get_block_cache(
            fs_meta.fs_info_sector_id,
            block_device.clone(),
            FAT32_SECTOR_SIZE,
        )
        .lock()
        .read(0, |fs_info_sector: &FAT32FSInfoSector| {
            assert!(
                fs_info_sector.is_valid(),
                "FAT32FileSystem::open(): Error loading fs_info_sector!"
            );
            Arc::new(FSMutex::new(FAT32Info::new(fs_info_sector)))
        });
        // 读取根目录inode
        let root_inode = Arc::new(FAT32Inode::new_root(
            Arc::new(FAT32FileAllocTable::new(
                block_device.clone(),
                fs_info.clone(),
                fs_meta.clone(),
            )),
            None,
            &PathOld::new_absolute(),
            fs_meta.root_cluster_id,
        ));
        Arc::new(FSMutex::new(Self { root_inode }))
    }

    pub fn root_inode(&self) -> Arc<(dyn InodeTrait + 'static)> {
        self.root_inode.clone()
    }
}

/// immutable struct, initialized at open
/// in-memory struct of FAT32BootSector
#[allow(unused)]
pub struct FAT32Meta {
    // bytes_per_sector: hardwired `512` for simplicity, the same as blocksize
    pub sector_per_cluster: usize,

    pub fat_count: usize,        // count of FAT
    pub fat_sector_count: usize, // sector count of ONE FAT
    pub fat_start_sector: usize,
    pub data_start_sector: usize, // start sector of data region
    pub total_sector_count: usize,
    pub total_cluster_count: usize, // 整个FAT32文件系统中可用的cluster数目(数据区)

    pub root_cluster_id: usize,
    pub fs_info_sector_id: usize,
    pub backup_sector_id: usize,
}

impl FAT32Meta {
    pub fn new(boot_sector: &FAT32BootSector) -> Self {
        let data_start_sector = (boot_sector.BPB_ReservedSectorCount as usize)
            + (boot_sector.BPB_NumFATs as usize) * (boot_sector.BPB_SectorPerFAT32 as usize);
        // total_cluster_count是可用簇的数目(数据区的簇数目)
        let total_cluster_count = (boot_sector.BPB_TotalSector32 as usize - data_start_sector)
            / (boot_sector.BPB_SectorPerCluster as usize);
        Self {
            sector_per_cluster: boot_sector.BPB_SectorPerCluster as usize,

            fat_count: boot_sector.BPB_NumFATs as usize,
            fat_sector_count: boot_sector.BPB_SectorPerFAT as usize,
            fat_start_sector: boot_sector.BPB_ReservedSectorCount as usize,
            data_start_sector,
            total_sector_count: boot_sector.BPB_TotalSector32 as usize,
            total_cluster_count,

            root_cluster_id: boot_sector.BPB_RootClusterNum as usize,
            fs_info_sector_id: boot_sector.BPB_FSInfo as usize,
            backup_sector_id: boot_sector.BPB_BkBootSec as usize,
        }
    }

    /// 将cluster_id转换为对应的sector_id
    pub fn cid_to_sid(&self, cluster_id: usize) -> Option<usize> {
        if cluster_id < 2 {
            log::error!(
                "[FAT32Meta::cid_to_sid] cluster_id out of range: {}",
                cluster_id
            );
            return None;
        }
        // 有两个保留的cluster
        let ret = (cluster_id - 2) * self.sector_per_cluster + self.data_start_sector;
        if ret >= self.total_sector_count {
            log::error!(
                "[FAT32Meta::cid_to_sid] cluster_id out of range: {}",
                cluster_id
            );
            return None;
        }
        Some(ret)
    }
}

/// mutable struct, update along read and write
/// in-memory struct of FAT32FSInfoSector
pub struct FAT32Info {
    pub free_cluster_count: usize,
    /// 目前next_free_cluster的语义是最后一个被分配的cluster(在`stat_free`中设置), 不是下一个空闲的cluster
    /// 且在分配cluster后, 当`next_free_cluster == meta.total_cluster_count + 1`时, 不在具有实际意义, 后续的cluster分配会从头开始查找空闲cluster
    pub next_free_cluster: usize,
}

impl FAT32Info {
    pub fn new(fs_info_sector: &FAT32FSInfoSector) -> Self {
        Self {
            free_cluster_count: fs_info_sector.FSI_Free_Count as usize,
            next_free_cluster: fs_info_sector.FSI_Nxt_Free as usize,
        }
    }
}

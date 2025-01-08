use alloc::sync::Arc;
use log::info;

use crate::{
    drivers::block::block_dev::BlockDevice,
    fs::{inode::Inode, path::Path},
};

use super::{
    block_cache::get_block_cache,
    fat::FAT32FileAllocTable,
    inode::FAT32Inode,
    layout::{FAT32BootSector, FAT32FSInfoSector},
    SpinNoIrqLock,
};

pub struct FAT32FileSystem {
    pub block_device: Arc<dyn BlockDevice>,
    pub root_inode: Arc<dyn Inode>,
}

impl FAT32FileSystem {
    /// Open a FAT32 file system, return Err() if not valid
    pub fn open(block_device: Arc<dyn BlockDevice>) -> Result<Arc<SpinNoIrqLock<Self>>, ()> {
        let fs_meta = get_block_cache(0, block_device.clone()).lock().read(
            0,
            |boot_sector: &FAT32BootSector| {
                info!("[FAT32FileSystem::open] boot_sector: {:?}", boot_sector);
                boot_sector
                    .is_valid()
                    .then(|| Arc::new(FAT32Meta::new(boot_sector)))
                    .ok_or(())
            },
        )?;
        let fs_info = get_block_cache(fs_meta.fs_info_sector_id, block_device.clone())
            .lock()
            .read(0, |fs_info_sector: &FAT32FSInfoSector| {
                // assert!(
                //     fs_info_sector.is_valid(),
                //     "FAT32FileSystem::open(): Error loading fs_info_sector!"
                // );
                fs_info_sector
                    .is_valid()
                    .then(|| Arc::new(SpinNoIrqLock::new(FAT32Info::new(fs_info_sector))))
                    .ok_or(())
                // Arc::new(SpinNoIrqLock::new(FAT32Info::new(fs_info_sector)))
            })?;
        let root_inode = Arc::new(FAT32Inode::new_root(
            Arc::new(FAT32FileAllocTable::new(
                block_device.clone(),
                fs_info.clone(),
                fs_meta.clone(),
            )),
            None,
            &Path::root(),
            fs_meta.root_cluster_id,
        ));
        Ok(Arc::new(SpinNoIrqLock::new(Self {
            block_device,
            root_inode,
        })))
    }

    pub fn root_inode(&self) -> Arc<(dyn Inode + 'static)> {
        self.root_inode.clone()
    }
}

/// immutable struct, initialized at open
/// in-memory struct of FAT32BootSector
pub struct FAT32Meta {
    // bytes_per_sector: hardwired `512` for simplicity, the same as blocksize
    pub sector_per_cluster: usize,

    pub fat_count: usize,        // count of FAT
    pub fat_sector_count: usize, // sector count of ONE FAT
    pub fat_start_sector: usize,
    pub data_start_sector: usize, // start sector of data region
    pub total_sector_count: usize,
    pub total_cluster_count: usize,

    pub root_cluster_id: usize,
    pub fs_info_sector_id: usize,
    pub backup_sector_id: usize,
}

impl FAT32Meta {
    pub fn new(boot_sector: &FAT32BootSector) -> Self {
        let data_start_sector = (boot_sector.BPB_ReservedSectorCount as usize)
            + (boot_sector.BPB_NumFATs as usize) * (boot_sector.BPB_FATsize32 as usize);
        let total_cluster_count = (boot_sector.BPB_TotSector32 as usize - data_start_sector)
            / (boot_sector.BPB_SectorPerCluster as usize);
        Self {
            sector_per_cluster: boot_sector.BPB_SectorPerCluster as usize,

            fat_count: boot_sector.BPB_NumFATs as usize,
            fat_sector_count: boot_sector.BPB_FATsize32 as usize,
            fat_start_sector: boot_sector.BPB_ReservedSectorCount as usize,
            data_start_sector,
            total_sector_count: boot_sector.BPB_TotSector32 as usize,
            total_cluster_count,

            root_cluster_id: boot_sector.BPB_RootCluster as usize,
            fs_info_sector_id: boot_sector.BPB_FSInfo as usize,
            backup_sector_id: boot_sector.BPB_BkBootSec as usize,
        }
    }

    pub fn cid_to_sid(&self, cluster_id: usize) -> Option<usize> {
        if cluster_id < 2 {
            return None;
        }
        let ret = (cluster_id - 2) * self.sector_per_cluster + self.data_start_sector;
        if ret >= self.total_sector_count {
            return None;
        }
        Some(ret)
    }
}

/// mutable struct, update along read and write
/// in-memory struct of FAT32FSInfoSector
pub struct FAT32Info {
    pub free_cluster_count: usize,
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

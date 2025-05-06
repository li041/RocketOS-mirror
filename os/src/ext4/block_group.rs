use alloc::sync::Arc;
use spin::RwLock;

use crate::{
    drivers::block::{self, block_cache::get_block_cache, block_dev::BlockDevice},
    mutex::SpinNoIrqLock,
};

use super::{block_op::Ext4Bitmap, inode::Ext4InodeDisk};

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Ext4GroupDescDisk {
    block_bitmap_lo: u32,      // block位图的起始块号(低32位)
    inode_bitmap_lo: u32,      // inode位图的起始块号(低32位)
    inode_table_lo: u32,       // inode表的起始块号(低32位)
    free_blocks_count_lo: u16, // 空闲的block总数(低16位)
    free_inodes_count_lo: u16, // 空闲的inode总数(低16位)
    used_dirs_count_lo: u16,   // 使用的目录总数(低16位)
    pub flags: u16,            // 块组标志, EXT$_BG_flags(INODE_UNINIT, etc)
    exclude_bitmap_lo: u32,    // 快照排除位图
    block_bitmap_csum_lo: u16, // block位图校验和(低16位, crc32c(s_uuid+grp_num+bitmap)) LE
    inode_bitmap_csum_lo: u16, // inode位图校验和(低16位, crc32c(s_uuid+grp_num+bitmap)) LE
    itable_unused_lo: u16,     // 未使用的inode 数量(低16位)
    checksum: u16,             // crc16(sb_uuid+group_num+desc)
    block_bitmap_hi: u32,      // block位图的起始块号(高32位)
    inode_bitmap_hi: u32,      // inode位图的起始块号(高32位)
    inode_table_hi: u32,       // inode表的起始块号(高32位)
    free_blocks_count_hi: u16, // 空闲的block总数(高16位)
    free_inodes_count_hi: u16, // 空闲的inode总数(高16位)
    used_dirs_count_hi: u16,   // 使用的目录总数(高16位)
    itable_unused_hi: u16,     // (已分配但未被初始化)未使用的inode 数量(高16位)
    exclude_bitmap_hi: u32,    // 快照排除位图
    block_bitmap_csum_hi: u16, // crc32c(s_uuid+grp_num+bitmap)的高16位
    inode_bitmap_csum_hi: u16, // crc32c(s_uuid+grp_num+bitmap)的高16位
    reserved: u32,             // 保留字段, 填充
}

impl Ext4GroupDescDisk {
    pub fn is_inode_uninit(&self) -> bool {
        self.flags & 0x1 == 0x1
    }
    pub fn inode_table(&self) -> u64 {
        (self.inode_table_hi as u64) << 32 | self.inode_table_lo as u64
    }
    pub fn block_bitmap(&self) -> u64 {
        (self.block_bitmap_hi as u64) << 32 | self.block_bitmap_lo as u64
    }
    pub fn inode_bitmap(&self) -> u64 {
        (self.inode_bitmap_hi as u64) << 32 | self.inode_bitmap_lo as u64
    }
    pub fn exclude_bitmap(&self) -> u64 {
        (self.exclude_bitmap_hi as u64) << 32 | self.exclude_bitmap_lo as u64
    }
    pub fn free_blocks_count(&self) -> u32 {
        (self.free_blocks_count_hi as u32) << 16 | self.free_blocks_count_lo as u32
    }
    pub fn free_inodes_count(&self) -> u32 {
        (self.free_inodes_count_hi as u32) << 16 | self.free_inodes_count_lo as u32
    }
    pub fn used_dirs_count(&self) -> u32 {
        (self.used_dirs_count_hi as u32) << 16 | self.used_dirs_count_lo as u32
    }
    pub fn itable_unused(&self) -> u32 {
        (self.itable_unused_hi as u32) << 16 | self.itable_unused_lo as u32
    }
}

pub struct GroupDesc {
    pub inode_table: u64,
    pub block_bitmap: u64,
    pub inode_bitmap: u64,
    pub exclude_bitmap: u64,

    inner: RwLock<GroupDescInner>,
}

impl GroupDesc {
    pub fn inode_table(&self) -> u64 {
        self.inode_table
    }
}

impl GroupDesc {
    pub fn new(group_desc_disk: &Ext4GroupDescDisk) -> Self {
        Self {
            inode_table: group_desc_disk.inode_table(),
            block_bitmap: group_desc_disk.block_bitmap(),
            inode_bitmap: group_desc_disk.inode_bitmap(),
            exclude_bitmap: (group_desc_disk.exclude_bitmap_hi as u64) << 32
                | group_desc_disk.exclude_bitmap_lo as u64,
            inner: RwLock::new(GroupDescInner::new(
                group_desc_disk.free_blocks_count(),
                group_desc_disk.free_inodes_count(),
                group_desc_disk.used_dirs_count(),
                group_desc_disk.itable_unused(),
            )),
        }
    }
    /// 在块组的inode_bitmap中分配一个inode
    /// 注意这个inode_num是相对于块组的inode_table的inode_num
    /// 调用者需要将inode_num转换为全局的inode_num(加上inodes_per_group * group_num)
    /// 认为inode_bitmap的大小不会超过一个块大小, 通过assert检测
    pub fn alloc_inode(
        &self,
        block_device: Arc<dyn BlockDevice>,
        ext4_block_size: usize,
        inode_bitmap_size: usize,
        is_dir: bool,
    ) -> Option<usize> {
        assert!(
            inode_bitmap_size <= ext4_block_size,
            "inode_bitmap_size: {}, ext4_block_size: {}",
            inode_bitmap_size,
            ext4_block_size
        );
        let mut inner = self.inner.write();
        // 检查当前块组是否还有空闲的inode
        if inner.free_inodes_count > 0 {
            // 注意inode_bitmap的size = inodes_per_group / 8 byte
            let num_blocks = (inode_bitmap_size + ext4_block_size - 1) / ext4_block_size;
            for i in 0..num_blocks {
                // 设置inode位图中的inode为已分配
                // 修改bg的used_dirs_count, free_inodes_count, checksum, unused_inodes_count
                let block_id = self.inode_bitmap as usize + i;
                if let Some(inode_num) = Ext4Bitmap::new(
                    get_block_cache(block_id, block_device.clone(), ext4_block_size)
                        .lock()
                        .get_mut(0),
                )
                .alloc(inode_bitmap_size)
                {
                    inner.free_inodes_count -= 1;
                    // TODO: 更新块组的 checksum
                    if is_dir {
                        inner.used_dirs_count += 1;
                    }
                    return Some(inode_num + (i * ext4_block_size * 8));
                }
            }
        }
        return None;
    }
    // 由上层调用者转换为本地(globol_inode_num = local_inode_num + inodes_per_group * group_num)
    // 既要释放inode_bitmap, 也要释放inode_table
    pub fn dealloc_inode(
        &self,
        block_device: Arc<dyn BlockDevice>,
        local_inode_num: usize,
        is_dir: bool,
        inode_size: usize,
        ext4_block_size: usize,
    ) {
        let mut inner = self.inner.write();
        // 释放inode_table
        let block_id = self.inode_table as usize + local_inode_num * inode_size / ext4_block_size;
        let block_offset = local_inode_num * inode_size % ext4_block_size;
        get_block_cache(block_id, block_device.clone(), ext4_block_size)
            .lock()
            .modify(block_offset, |inode_on_disk: &mut Ext4InodeDisk| {
                // assert!(inode_on_disk.get_nlinks() == 0);
                inode_on_disk.set_size(0);
                inode_on_disk.set_dtime(66666666);
                inode_on_disk.set_mode(0);
                inode_on_disk.clear_block();
            });
        // 释放inode_bitmap
        let block_id = self.inode_bitmap as usize + local_inode_num / (ext4_block_size * 8);
        let block_offset = local_inode_num % (ext4_block_size * 8);
        Ext4Bitmap::new(
            get_block_cache(block_id, block_device, ext4_block_size)
                .lock()
                .get_mut(0),
        )
        .dealloc(block_offset);
        inner.free_inodes_count += 1;
        if is_dir {
            inner.used_dirs_count -= 1;
        }
    }
    /// 上层调用者需要转换为文件系统的全局块号(block_num + block_group_num * blocks_per_group)
    pub fn alloc_block(
        &self,
        block_device: Arc<dyn BlockDevice>,
        ext4_block_size: usize,
        block_bitmap_size: usize,
        block_count: usize,
    ) -> Option<usize> {
        let mut inner = self.inner.write();
        let num_blocks = block_bitmap_size / ext4_block_size;
        // 检查是否有足够的空闲块
        if inner.free_blocks_count < block_count as u32 {
            return None;
        }
        for i in 0..num_blocks {
            let block_id = self.block_bitmap as usize + i;
            if let Some(block_num) = Ext4Bitmap::new(
                get_block_cache(block_id, block_device.clone(), ext4_block_size)
                    .lock()
                    .get_mut(0),
            )
            // .alloc(block_bitmap_size)
            .alloc_contiguous(block_bitmap_size, block_count)
            // 修改bg的free_blocks_count, checksum
            {
                inner.free_blocks_count -= block_count as u32;
                return Some(block_num + (i * ext4_block_size * 8));
            }
        }
        return None;
    }
    pub fn dealloc_block(
        &self,
        block_device: Arc<dyn BlockDevice>,
        local_block_num: usize,
        ext4_block_size: usize,
        block_bitmap_size: usize,
    ) {
        let mut inner = self.inner.write();
        let block_id = self.block_bitmap as usize + local_block_num / (ext4_block_size * 8);
        let block_offset = local_block_num % (ext4_block_size * 8);
        Ext4Bitmap::new(
            get_block_cache(block_id, block_device.clone(), ext4_block_size)
                .lock()
                .get_mut(0),
        )
        .dealloc(block_offset);
        inner.free_blocks_count += 1;
    }
}

pub struct GroupDescInner {
    free_blocks_count: u32,
    free_inodes_count: u32,
    used_dirs_count: u32,
    itable_unused: u32,
}

impl GroupDescInner {
    pub fn new(
        free_blocks_count: u32,
        free_inodes_count: u32,
        used_dirs_count: u32,
        itable_unused: u32,
    ) -> Self {
        Self {
            free_blocks_count,
            free_inodes_count,
            used_dirs_count,
            itable_unused,
        }
    }
}

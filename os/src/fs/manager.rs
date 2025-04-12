use alloc::sync::Arc;

use crate::{
    arch::mm::copy_to_user,
    ext4::{fs::Ext4FileSystem, super_block},
};

use super::{dentry::Dentry, uapi::StatFs};

pub struct Fake_FS;

impl FileSystemOp for Fake_FS {
    fn type_name(&self) -> &'static str {
        "fake_fs"
    }
}
pub trait FileSystemOp: Send + Sync {
    fn type_name(&self) -> &'static str;
    fn statfs(&self, buf: *mut StatFs) -> Result<usize, &'static str> {
        unimplemented!();
    }
}

impl FileSystemOp for Ext4FileSystem {
    fn type_name(&self) -> &'static str {
        "ext4"
    }
    fn statfs(&self, buf: *mut StatFs) -> Result<usize, &'static str> {
        let mut statfs = StatFs::default();
        let super_block = &self.super_block;
        let inner_guard = super_block.inner.read();
        // 填充 statfs 结构体
        statfs.f_type = 0xEF53; // EXT4 文件系统的魔数
        statfs.f_bsize = super_block.block_size as i64;

        // 计算总块数（考虑 64 位扩展）
        statfs.f_blocks = super_block.blocks_count;

        // 空闲块数（考虑 64 位扩展）
        statfs.f_bfree = inner_guard.free_blocks_count;

        // 可用块数（通常等于空闲块数减去保留块数）
        let reserved_blocks = super_block.reserved_blocks_count as u64;
        statfs.f_bavail = inner_guard
            .free_blocks_count
            .saturating_sub(reserved_blocks);

        // Inode 信息
        statfs.f_files = super_block.inodes_count as u64;
        statfs.f_ffree = inner_guard.free_inodes_count as u64;

        // 其他字段
        statfs.f_fsid = [0; 2]; // 通常不使用
        statfs.f_frsize = super_block.block_size as i64; // 片段大小（通常等于块大小）
        statfs.f_flags = 0; // 挂载标志（需要根据实际情况设置）
        statfs.f_spare = [0; 4]; // 保留字段
                                 // 写回到用户空间
        copy_to_user(buf, &statfs as *const StatFs, 1)
    }
}

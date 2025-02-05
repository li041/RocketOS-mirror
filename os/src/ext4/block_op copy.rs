//! 用于处理EXT4文件系统的块操作, 如读取目录项, 操作位图等
use crate::ext4::dentry::Ext4DirEntry;

use super::fs::EXT4_BLOCK_SIZE;

/// EXT4中文件名最大长度
pub const EXT4_NAME_LEN: usize = 255;

#[repr(C)]
pub struct Ext4DirContent<'a> {
    content: &'a [u8; EXT4_BLOCK_SIZE],
}

// 用于解析目录项
impl<'a> Ext4DirContent<'a> {
    pub fn new(data: &'a [u8; EXT4_BLOCK_SIZE]) -> Self {
        Self { content: data }
    }
    // 遍历目录项
    // 目录项是连续存储的, 每个目录项的长度不一定相同, 根据目录项的rec_len字段来判断, 到达ext4块尾部即为结束
    pub fn list(&self) {
        let mut rec_len_total = 0;
        while rec_len_total < EXT4_BLOCK_SIZE {
            // rec_len是u16, 2字节
            let rec_len = u16::from_le_bytes([
                self.content[rec_len_total + 4],
                self.content[rec_len_total + 5],
            ]);
            let dentry = Ext4DirEntry::try_from(
                &self.content[rec_len_total..rec_len_total + rec_len as usize],
            )
            .expect("DirEntry::try_from failed");
            log::info!("dentry: {:?}", dentry);
            rec_len_total += rec_len as usize;
            // log::info!("rec_len_total: {}", rec_len_total);
        }
    }
}

pub struct Bitmap<'a> {
    bitmap: &'a [u8; EXT4_BLOCK_SIZE],
}

impl<'a> Bitmap<'a> {
    pub fn new(bitmap: &'a [u8; EXT4_BLOCK_SIZE]) -> Self {
        Self { bitmap }
    }
    pub fn alloc(&self) -> Option<usize> {
        for (i, byte) in self.bitmap.iter().enumerate() {
            if *byte != 0xff {
                for j in 0..8 {
                    if (byte & (1 << j)) == 0 {
                        return Some(i * 8 + j);
                    }
                }
            }
        }
        None
    }
}

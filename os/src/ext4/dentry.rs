use core::fmt::Debug;

use alloc::string::String;
use alloc::vec::Vec;

use super::fs::EXT4_BLOCK_SIZE;

/// EXT4中文件名最大长度
pub const EXT4_NAME_LEN: usize = 255;

#[repr(C)]
pub struct Ext4DirContent<'a> {
    data: &'a [u8; EXT4_BLOCK_SIZE],
}

// 用于解析目录项
impl<'a> Ext4DirContent<'a> {
    pub fn new(data: &'a [u8; EXT4_BLOCK_SIZE]) -> Self {
        Self { data }
    }
    // 遍历目录项
    pub fn list(&self) {
        let mut rec_len_total = 0;
        while rec_len_total < EXT4_BLOCK_SIZE {
            // rec_len是u16, 2字节
            let rec_len =
                u16::from_le_bytes([self.data[rec_len_total + 4], self.data[rec_len_total + 5]]);
            let dentry =
                DirEntry::try_from(&self.data[rec_len_total..rec_len_total + rec_len as usize])
                    .expect("DirEntry::try_from failed");
            log::info!("dentry: {:?}", dentry);
            rec_len_total += rec_len as usize;
            // log::info!("rec_len_total: {}", rec_len_total);
        }
    }
}

/// 注意不能直接用这个结构体从block_cache中读取, 一是因为对齐问题, 二是因为name是变长的
#[repr(C)]
pub struct DirEntry {
    pub inode_num: u32, // 目录项对应的inode号
    pub rec_len: u16,   // 目录项长度, 需要4的整数倍
    pub name_len: u8,   // 文件名长度, 文件名最大长度255
    pub file_type: u8,  // 文件类型
    pub name: Vec<u8>,  // 文件名, 这里只存储有效字符
}

impl TryFrom<&[u8]> for DirEntry {
    type Error = &'static str;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let inode_num = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let rec_len = u16::from_le_bytes([buf[4], buf[5]]);
        let name_len = buf[6];
        let file_type = buf[7];
        let name = buf[8..(8 + name_len as usize)].to_vec();
        Ok(Self {
            inode_num,
            rec_len,
            name_len,
            file_type,
            name,
        })
    }
}

impl Debug for DirEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // let name = c_str_to_string(self.name.as_ptr());
        let name = String::from_utf8(self.name[..].to_vec()).unwrap();
        f.debug_struct("DirEntry")
            .field("inode_num", &self.inode_num)
            .field("rec_len", &self.rec_len)
            .field("name_len", &self.name_len)
            .field("file_type", &self.file_type)
            .field("name", &name)
            .finish()
    }
}

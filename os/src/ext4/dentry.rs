use core::fmt::Debug;

use alloc::string::String;
use alloc::vec::Vec;

pub const EXT4_DT_UNKNOWN: u8 = 0x0;
pub const EXT4_DT_REG: u8 = 0x1;
pub const EXT4_DT_DIR: u8 = 0x2;
pub const EXT4_DT_CHR: u8 = 0x3;
pub const EXT4_DT_BLK: u8 = 0x4;
pub const EXT4_DT_FIFO: u8 = 0x5;
pub const EXT4_DT_SOCK: u8 = 0x6;
pub const EXT4_DT_LNK: u8 = 0x7;

/// 注意不能直接用这个结构体从block_cache中读取, 一是因为对齐问题, 二是因为name是变长的
/// 注意目录项的长度需要是4的整数倍
#[derive(Default)]
#[repr(C)]
pub struct Ext4DirEntry {
    pub inode_num: u32, // 目录项对应的inode号
    pub rec_len: u16,   // 目录项长度, 需要4的整数倍
    pub name_len: u8,   // 文件名长度, 文件名最大长度255
    /*
        File type code, one of:
            0x0	Unknown.
            0x1	Regular file.
            0x2	Directory.
            0x3	Character device file.
            0x4	Block device file.
            0x5	FIFO.
            0x6	Socket.
            0x7	Symbolic link.
    */
    pub file_type: u8, // 文件类型
    pub name: Vec<u8>, // 文件名, 这里只存储有效字符
}

impl Ext4DirEntry {
    pub fn write_to_mem(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&self.inode_num.to_le_bytes());
        buf[4..6].copy_from_slice(&self.rec_len.to_le_bytes());
        buf[6] = self.name_len;
        buf[7] = self.file_type;
        buf[8..(8 + self.name_len as usize)].copy_from_slice(&self.name[..]);
    }
    // Convert the name field to a String
    pub fn get_name(&self) -> String {
        String::from_utf8(self.name.clone()).unwrap()
    }
}

impl TryFrom<&[u8]> for Ext4DirEntry {
    type Error = &'static str;

    // 这个会根据name_len来读取name
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

impl Debug for Ext4DirEntry {
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

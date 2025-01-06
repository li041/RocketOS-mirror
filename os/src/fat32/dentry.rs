use alloc::{
    format,
    string::{String, ToString},
};
use log::info;

use super::{file::FAT32File, time::FAT32Timestamp, LNAME_MAXLEN, SNAME_LEN};

// const ATTR_READ_ONLY: u8 = 0x01;
// const ATTR_HIDDEN: u8 = 0x02;
// const ATTR_SYSTEM: u8 = 0x04;
// const ATTR_VOLUME_ID: u8 = 0x08;
/// 在文件属性(0xB)中, 0x10标识目录
pub const ATTR_DIRECTORY: u8 = 0x10;
// const ATTR_ARCHIVE: u8 = 0x20;
// 当文件属性为0x0F时(只读, 隐藏, 系统, 卷标), 表示这是一个长文件名
const ATTR_LONG_NAME: u8 = 0x0F;
// 目录项大小为32字节
const DENTRY_SIZE: usize = 0x20;

// 长文件名目录项的顺序号掩码
const ORD_MASK: u8 = 0x3F;
/// 每个目录项中Unicode字符数
const CHAR_COUNT_PER_DIRENTRY: usize = 13;
/// 目录项中校验和字段的偏移
const CHKSUM_OFFSET: usize = 13;
/// 是否为最后一个长文件名目录项
const LAST_LONG_ENTRY: u8 = 0x40;

pub struct FAT32DentryContent<'a> {
    // 表示条目所在的文件
    file: &'a mut FAT32File,
    offset: usize,
}

impl<'a> FAT32DentryContent<'a> {
    pub fn new(file: &'a mut FAT32File) -> Self {
        Self { file, offset: 0 }
    }

    #[allow(unused)]
    /// 调整文件指针
    pub fn seek(&mut self, offset: usize) {
        self.offset = offset
    }

    fn read_dentry(&mut self, data: &mut [u8]) -> usize {
        let ret = self.file.read(data, self.offset);
        self.offset += ret;
        ret
    }

    fn write_dentry(&mut self, data: &[u8]) {
        let ret = self.file.write(data, self.offset);
        self.offset += ret;
    }
}

/// 将长文件和短文件合并为一个目录项
pub struct FAT32DirEntry {
    pub lname: [u16; LNAME_MAXLEN], // 长文件名，UTF-16(Unicode) 编码, 最大支持255个字符
    pub sname: [u8; SNAME_LEN], // 短文件名，ASCII 编码, 8.3 格式, 即最多8个字符的文件名和最多3个字符的扩展名
    pub attr: u8,               // 文件属性
    pub crt_time: FAT32Timestamp, // 创建时间戳
    pub wrt_time: FAT32Timestamp, // 修改时间戳
    pub acc_time: FAT32Timestamp, // 访问时间戳
    pub fstcluster: u32,        // 起始簇号
    pub filesize: u32,          // 文件大小
}

impl FAT32DirEntry {
    /// 根据`lname`和`sname`生成文件名
    /// 有长文件名时使用长文件名, 否则使用短文件名
    pub fn fname(&self) -> String {
        let mut lname_len = 0;
        while lname_len < LNAME_MAXLEN && self.lname[lname_len] != 0 {
            lname_len += 1;
        }
        if lname_len > 0 {
            //在遇到无效字符时使用替代字符（通常是 U+FFFD，即 "�"）
            String::from_utf16_lossy(&self.lname[0..lname_len])
        } else {
            let base = &self.sname[0..8];
            let ext = &self.sname[8..11];
            let mut base_len = 8;
            let mut ext_len = 3;
            while base_len > 0 && base[base_len - 1] == b' ' {
                base_len -= 1;
            }
            while ext_len > 0 && ext[ext_len - 1] == b' ' {
                ext_len -= 1;
            }
            if ext_len > 0 {
                String::from_utf8_lossy(&base[0..base_len]).to_string()
                    + "."
                    + &String::from_utf8_lossy(&ext[0..ext_len]).to_string()
            } else {
                String::from_utf8_lossy(&base[0..base_len]).to_string()
            }
        }
    }

    /// 从`FAT32DentryContent`中读取目录项
    /// 注意: 是把一个文件的完整信息读出来, 包括他的长文件名和短文件名
    /// 涉及到读取多个目录项, 长文件名的目录项读取的顺序是倒序的, 读完长文件名的目录项后, 后面紧跟的是短文件名的目录项
    pub fn read_dentry(reader: &mut FAT32DentryContent) -> Option<Self> {
        let mut read_buf: [u8; DENTRY_SIZE] = [0; DENTRY_SIZE];
        // 长文件名的下一个目录项的序号
        let mut next_ord: Option<u8> = None;
        // 根据短文件名计算的校验和
        let mut s_chksum: Option<u8> = None;
        let mut lname: [u16; LNAME_MAXLEN] = [0; LNAME_MAXLEN];

        // 从`read_buf`中读取两个字节, 并组合成一个`u16`
        macro_rules! lsb16 {
            ($data_idx: expr) => {
                (read_buf[$data_idx + 1] as u16) << 8 | (read_buf[$data_idx] as u16)
            };
        }
        // 从`read_buf`中读取一个字符(Unicode, 2字节), 并存入`lname`
        macro_rules! s_lname {
            ($data_idx: expr, $lname_idx: expr) => {
                let data = lsb16!($data_idx);
                if data != 0xFFFF && data != 0 {
                    if $lname_idx >= LNAME_MAXLEN {
                        info!("[Dentry] Too long lname!");
                        return None;
                    }
                    lname[$lname_idx] = lsb16!($data_idx);
                }
            };
        }

        loop {
            let ret = reader.read_dentry(&mut read_buf[..]);
            if ret != DENTRY_SIZE {
                return None;
            }
            // 0xE5 表示已删除的文件
            if read_buf[0] == 0xE5 {
                continue;
            }
            // 0x00 表示目录中没有更多的项
            if read_buf[0] == 0x00 {
                return None;
            }
            // 0x05 表示文件名的冲突或已删除的文件。为了处理这个情况，将其更改为 0xE5 是为了确保一致性和遵循系统的约定。
            if read_buf[0] == 0x05 {
                read_buf[0] = 0xE5;
            }

            // 检查文件属性(0xB)
            let attr = read_buf[11];
            // 是否为0x0F, 表示长文件名
            if attr == ATTR_LONG_NAME {
                let ord = read_buf[0];
                // 长文件格式(0~4bit为序号, 6bit为最后一个长文件名标志)
                let real_ord = ord & ORD_MASK;
                // 长文件名的顺序号从1开始
                let lname_offset = ((real_ord as usize) - 1) * CHAR_COUNT_PER_DIRENTRY;
                let chksum = read_buf[CHKSUM_OFFSET];

                // check ord
                if next_ord.is_some() {
                    if next_ord.unwrap() != real_ord {
                        info!("[Dentry] Long Dir ID not match!");
                        return None;
                    }
                } else {
                    // 长文件名的目录项是倒序存储的, 所以第一个目录项应该是长文件最后一个目录项
                    if (ord & LAST_LONG_ENTRY) != LAST_LONG_ENTRY {
                        info!("[Dentry] Not first dentry!");
                        return None;
                    }
                }

                next_ord = match real_ord {
                    // 确保是读完长文件名的目录项后, 后面紧跟读短文件名的目录项(else中做了检查)
                    1 => None,
                    _ => Some(real_ord - 1),
                };

                // 检查检验和
                if s_chksum.is_some() {
                    if s_chksum.unwrap() != chksum {
                        info!("[Dentry] Chksum not match!");
                        return None;
                    }
                } else {
                    s_chksum = Some(chksum);
                }

                // 读取长文件名在该目录项中的13个Unicode字符
                // 0x1 ~ 0x0A
                s_lname!(1, lname_offset);
                s_lname!(3, lname_offset + 1);
                s_lname!(5, lname_offset + 2);
                s_lname!(7, lname_offset + 3);
                s_lname!(9, lname_offset + 4);
                // 0xE ~ 0x19
                s_lname!(14, lname_offset + 5);
                s_lname!(16, lname_offset + 6);
                s_lname!(18, lname_offset + 7);
                s_lname!(20, lname_offset + 8);
                s_lname!(22, lname_offset + 9);
                s_lname!(24, lname_offset + 10);
                // 0x1C ~ 0x1F
                s_lname!(28, lname_offset + 11);
                s_lname!(30, lname_offset + 12);
            } else {
                // 短文件名
                if next_ord.is_some() {
                    info!("[Dentry] Expect long name but met with short!");
                    return None;
                }

                if s_chksum.is_some() {
                    let calc_chksum = shortname_checksum(&read_buf[0..11]);
                    if calc_chksum != s_chksum.unwrap() {
                        info!("[Dentry] Chksum not match!");
                        return None;
                    }
                }

                let mut sname: [u8; SNAME_LEN] = [0; SNAME_LEN];
                for i in 0..SNAME_LEN {
                    sname[i] = read_buf[i];
                }

                return Some(Self {
                    lname,
                    sname,
                    attr,
                    crt_time: FAT32Timestamp {
                        date: lsb16!(16),
                        time: lsb16!(14),
                        tenms: read_buf[13],
                    },
                    wrt_time: FAT32Timestamp {
                        date: lsb16!(24),
                        time: lsb16!(22),
                        tenms: 0,
                    },
                    acc_time: FAT32Timestamp {
                        date: lsb16!(18),
                        time: 0,
                        tenms: 0,
                    },
                    fstcluster: (lsb16!(20) as u32) << 16 | (lsb16!(26) as u32),
                    filesize: (lsb16!(30) as u32) << 16 | (lsb16!(28) as u32),
                });
            }
        }
    }

    #[allow(unused)]
    fn write_dentry(&self, writer: &mut FAT32DentryContent) {
        let mut lname_len = 0;
        while lname_len < LNAME_MAXLEN && self.lname[lname_len] != 0 {
            lname_len += 1;
        }
        let mut write_buf: [u8; DENTRY_SIZE] = [0; DENTRY_SIZE];
        // 长文件名的目录项数, 每个目录项最多存储13个Unicode字符
        let ldir_count = (lname_len + 12) / 13;
        let chksum = shortname_checksum(&self.sname[..]);

        // 分解`data`(两个字节), 并分别存入`write_buf`的两个字节
        macro_rules! wsb16 {
            ($data_idx: expr, $data: expr) => {
                write_buf[$data_idx] = (($data & 0xFF) as u8);
                write_buf[$data_idx + 1] = ((($data >> 8) & 0xFF) as u8);
            };
        }

        macro_rules! s_lname {
            ($data_idx: expr, $lname_idx: expr) => {
                wsb16!($data_idx, {
                    if $lname_idx == lname_len {
                        // 0x0 表示结束
                        0
                    } else if $lname_idx > lname_len {
                        // 0xFFFF 表示无效或超出范围
                        0xFFFF
                    } else {
                        self.lname[$lname_idx]
                    }
                });
            };
        }

        // 倒序写入长文件名目录项
        for ldir_id in (1..=ldir_count).rev() {
            let lname_offset = (ldir_id - 1) * 13;
            // 写入长文件名的13个Unicode字符
            s_lname!(1, lname_offset);
            s_lname!(3, lname_offset + 1);
            s_lname!(5, lname_offset + 2);
            s_lname!(7, lname_offset + 3);
            s_lname!(9, lname_offset + 4);
            s_lname!(14, lname_offset + 5);
            s_lname!(16, lname_offset + 6);
            s_lname!(18, lname_offset + 7);
            s_lname!(20, lname_offset + 8);
            s_lname!(22, lname_offset + 9);
            s_lname!(24, lname_offset + 10);
            s_lname!(28, lname_offset + 11);
            s_lname!(30, lname_offset + 12);

            write_buf[0] = (ldir_id as u8) | {
                // Todo: 这里原来是`ldir_id == lname_len`, 有问题
                if ldir_id == ldir_count {
                    0x40
                } else {
                    0
                }
            };
            write_buf[11] = ATTR_LONG_NAME;
            write_buf[12] = 0;
            write_buf[13] = chksum;
            // 文件起始簇号(0x1A ~ 0x1B, 目前常置0)
            write_buf[26] = 0;
            write_buf[27] = 0;
            writer.write_dentry(&write_buf[..]);
        }
        // 写完长文件名, 紧跟着写入短文件名
        for i in 0..SNAME_LEN {
            write_buf[i] = self.sname[i];
        }
        write_buf[11] = self.attr;
        write_buf[12] = 0;
        write_buf[13] = self.crt_time.tenms;
        wsb16!(16, self.crt_time.time);
        wsb16!(18, self.acc_time.date);
        wsb16!(20, (((self.fstcluster >> 16) & 0xFFFF) as u16));
        wsb16!(22, self.wrt_time.time);
        wsb16!(24, self.wrt_time.date);
        wsb16!(26, ((self.fstcluster & 0xFFFF) as u16));
        wsb16!(28, ((self.filesize & 0xFFFF) as u16));
        wsb16!(30, (((self.filesize >> 16) & 0xFFFF) as u16));
        writer.write_dentry(&write_buf[..]);
    }
}

fn shortname_checksum(data: &[u8]) -> u8 {
    let mut ret: u16 = 0;
    for i in 0..SNAME_LEN {
        ret = (match ret & 1 {
            1 => 0x80,
            _ => 0,
        } + (ret >> 1)
            + data[i] as u16);
        ret &= 0xFF;
    }
    ret as u8
}

/// return "path/name"
#[allow(unused)]
pub fn append_path(path: &str, name: &str) -> String {
    format!("{}/{}", path, name)
}

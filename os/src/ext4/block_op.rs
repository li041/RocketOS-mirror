//! 用于处理EXT4文件系统的块操作, 如读取目录项, 操作位图等
use alloc::sync::Arc;
use alloc::vec;
use alloc::{string::String, vec::Vec};

use crate::drivers::block::block_cache::get_block_cache;
use crate::drivers::block::block_dev::BlockDevice;
use crate::ext4::dentry::Ext4DirEntry;

use super::extent_tree::{Ext4Extent, Ext4ExtentHeader, Ext4ExtentIdx};
use super::{dentry::EXT4_DT_DIR, fs::EXT4_BLOCK_SIZE};

use crate::arch::config::PAGE_SIZE;
/*
 * 默认情况下，每个目录都以“几乎是线性”数组列出条目。我写“几乎”，因为它不是内存意义上的线性阵列，因为目录条目是跨文件系统块分开。
 * 因此，说目录是一系列数据块，并且每个块包含目录条目的线性阵列。每个块阵列的末端通过到达块的末端来表示；该块中的最后一个条目具有记录长度，将其一直延伸到块的末端。
 * 当然，整个目录的末尾可以通过到达文件的末尾来表示。未使用的目录条目由Inode = 0。
 */
#[repr(C)]
pub struct Ext4DirContentRO<'a> {
    content: &'a [u8],
}

#[repr(C)]
pub struct Ext4DirContentWE<'a> {
    content: &'a mut [u8],
}

// 用于解析目录项
impl<'a> Ext4DirContentRO<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { content: data }
    }
    // 遍历目录项
    // 在文件系统的一个块中, 目录项是连续存储的, 每个目录项的长度不一定相同, 根据目录项的rec_len字段来判断, 到达ext4块尾部即为结束
    // 这个由调用者保证, 传入的buf是目录所有内容
    pub fn getdents(&self) -> Vec<Ext4DirEntry> {
        let mut entries = Vec::new();
        let mut rec_len_total = 0;
        let content_len = self.content.len();
        while rec_len_total < content_len {
            // rec_len是u16, 2字节
            let rec_len = u16::from_le_bytes([
                self.content[rec_len_total + 4],
                self.content[rec_len_total + 5],
            ]);
            let dentry = Ext4DirEntry::try_from(
                &self.content[rec_len_total..rec_len_total + rec_len as usize],
            )
            .expect("DirEntry::try_from failed");
            entries.push(dentry);
            rec_len_total += rec_len as usize;
        }
        entries
    }
    pub fn find(&self, name: &str) -> Option<Ext4DirEntry> {
        let mut rec_len_total = 0;
        let content_len = self.content.len();
        while rec_len_total < content_len {
            let rec_len = u16::from_le_bytes([
                self.content[rec_len_total + 4],
                self.content[rec_len_total + 5],
            ]);
            let dentry = Ext4DirEntry::try_from(
                &self.content[rec_len_total..rec_len_total + rec_len as usize],
            )
            .expect("DirEntry::try_from failed");
            let dentry_name = String::from_utf8(dentry.name[..].to_vec()).unwrap();
            if dentry_name == name {
                return Some(dentry);
            }
            rec_len_total += rec_len as usize;
        }
        None
    }
}

// ToOptimize: 目前这个函数进行了很多不必要的拷贝, 需要优化
impl<'a> Ext4DirContentWE<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { content: data }
    }
    /// 注意目录的size应该是对齐到块大小的, 一个数据块中目录项是根据rec_len找到下一个的, 并且该数据块中目录项的结束是到数据块的末尾(就可能导致最后一个rec_len很大)
    /// 由上层调用者保证name在目录中不存在
    /// Todo: 当块内空间不足时, 需要分配新的块, 并将新的目录项写入新的块(需要extents_tree管理)
    /// ToOptimize: 目前这个函数进行了很多不必要的拷贝, 需要优化
    /// 注意目录项的rec_len要保证对齐到4字节
    pub fn add_entry(
        &mut self,
        name: &str,
        inode_num: u32,
        file_type: u8,
    ) -> Result<(), &'static str> {
        // 新的目录项长度为name长度加上8字节
        let new_entry_name_len = name.len() as u16;
        // rec_len对齐到4字节
        let needed_len = (new_entry_name_len + 8 + 3) & !3;
        let mut rec_len_total = 0;

        let content_len = self.content.len();
        assert!(content_len > 0 && content_len % EXT4_BLOCK_SIZE == 0);
        log::info!(
            "[Ext4DirContentWE::add_entry] content_len: {}, needed_len: {}",
            content_len,
            needed_len
        );

        let mut dentry: Ext4DirEntry = Ext4DirEntry::default();
        let mut rec_len = 0;
        while rec_len_total < content_len {
            rec_len = u16::from_le_bytes([
                self.content[rec_len_total + 4],
                self.content[rec_len_total + 5],
            ]);
            dentry = Ext4DirEntry::try_from(
                &self.content[rec_len_total..rec_len_total + rec_len as usize],
            )
            .expect("DirEntry::try_from failed");

            // 情况1: 找到空闲位置, 已删除的目录项且有足够空间(inode_num为0, 表示已被删除)
            if dentry.inode_num == 0 && rec_len > needed_len {
                log::info!("Using empty dir entry at offset {}", rec_len_total);
                // 更新name_len, inode_num, file_type
                let mut new_dentry = dentry;
                new_dentry.name_len = new_entry_name_len as u8;
                new_dentry.inode_num = inode_num;
                new_dentry.file_type = file_type;
                // 写回
                new_dentry.write_to_mem(
                    &mut self.content[rec_len_total..rec_len_total + needed_len as usize],
                );
                return Ok(());
            }
            // 情况2: 目录项仍在使用, 但rec_len够大
            // 检查当前记录是否有足够的空间容纳新的目录项
            let current_dentry_len = ((dentry.name_len as usize + 8 + 3) & !3) as u16;
            let surplus_len = rec_len - current_dentry_len;
            if surplus_len > needed_len {
                // 有足够的空间容纳新的目录项
                log::info!(
                    "Splitting dir entry at offset {}, surplus_len: {}",
                    rec_len_total,
                    surplus_len
                );
                // 修改原有目录项的rec_len
                let mut updated_dentry = dentry;
                updated_dentry.rec_len = current_dentry_len;
                updated_dentry.write_to_mem(
                    &mut self.content[rec_len_total..rec_len_total + current_dentry_len as usize],
                );
                // 在后续空间写入新的目录项
                let new_dentry = Ext4DirEntry {
                    inode_num,
                    rec_len: surplus_len,
                    name_len: new_entry_name_len as u8,
                    file_type,
                    name: name.as_bytes().to_vec(),
                };
                new_dentry
                    .write_to_mem(&mut self.content[rec_len_total + current_dentry_len as usize..]);
                return Ok(());
            }
            rec_len_total += rec_len as usize;
        }
        // 没有找到unused的目录项, 则看是否最后一个目录项的rec_len可以容纳新的目录项
        // 此时rec_len是最后一个目录项的rec_len, dentry是最后一个目录项
        dentry.rec_len = dentry.name_len as u16 + 8;
        let surplus_len = rec_len - dentry.rec_len;
        assert!(
            surplus_len >= needed_len,
            "No enough space for new entry, surplus_len: {}, needed_len: {}",
            surplus_len,
            needed_len
        );
        dentry.write_to_mem(
            &mut self.content[content_len - rec_len as usize
                ..content_len - rec_len as usize + dentry.rec_len as usize],
        );
        let new_dentry = Ext4DirEntry {
            inode_num,
            rec_len: surplus_len,
            name_len: new_entry_name_len as u8,
            file_type,
            name: name.as_bytes().to_vec(),
        };
        new_dentry.write_to_mem(&mut self.content[content_len - surplus_len as usize..content_len]);
        Ok(())
    }
    /// 基于合并相邻目录项的方式
    ///     1. 如果删除的dentry前面有目录项, 则将`rec_len`合并到前一个目录项
    ///     2. 如果删除的dentry是块中的第一个, 则仅见`inode`设为0
    pub fn delete_entry(&mut self, name: &str, inode_num: u32) -> Result<(), &'static str> {
        let mut rec_len_total = 0;
        let mut prev_len_total = 0;
        let content_len = self.content.len();
        while rec_len_total < content_len {
            let rec_len = u16::from_le_bytes([
                self.content[rec_len_total + 4],
                self.content[rec_len_total + 5],
            ]);
            let mut dentry = Ext4DirEntry::try_from(
                &self.content[rec_len_total..rec_len_total + rec_len as usize],
            )
            .expect("DirEntry::try_from failed");
            let dentry_name = String::from_utf8(dentry.name[..].to_vec()).unwrap();
            if dentry_name == name {
                // 删除目录项
                if rec_len_total == 0 {
                    // 删除的是块中的第一个目录项
                    dentry.inode_num = 0;
                    dentry.write_to_mem(
                        &mut self.content[rec_len_total..rec_len_total + rec_len as usize],
                    );
                    return Ok(());
                } else {
                    // 合并到前一个目录项的rec_len
                    let mut prev_dentry = Ext4DirEntry::try_from(
                        &self.content[prev_len_total..prev_len_total + rec_len as usize],
                    )
                    .expect("DirEntry::try_from failed");
                    prev_dentry.rec_len += rec_len;
                    prev_dentry.write_to_mem(
                        &mut self.content[prev_len_total..prev_len_total + rec_len as usize],
                    );
                }

                return Ok(());
            }
            prev_len_total = rec_len_total;
            rec_len_total += rec_len as usize;
        }
        Err("Entry not found")
    }
    // 在rename的时候如果new_dentry存在, 调用这个函数修改inode_num和file_type
    pub fn set_entry(
        &mut self,
        old_name: &str,
        new_inode_num: u32,
        new_file_type: u8,
    ) -> Result<(), &'static str> {
        let mut rec_len_total = 0;
        let content_len = self.content.len();

        while rec_len_total < content_len {
            let rec_len = u16::from_le_bytes([
                self.content[rec_len_total + 4],
                self.content[rec_len_total + 5],
            ]);
            let mut dentry = Ext4DirEntry::try_from(
                &self.content[rec_len_total..rec_len_total + rec_len as usize],
            )
            .map_err(|_| "DirEntry::try_from failed")?;

            let dentry_name = String::from_utf8(dentry.name[..].to_vec()).unwrap();
            if dentry_name == old_name {
                dentry.inode_num = new_inode_num;
                dentry.file_type = new_file_type;
                dentry.write_to_mem(
                    &mut self.content[rec_len_total..rec_len_total + rec_len as usize],
                );
                return Ok(());
            }

            rec_len_total += rec_len as usize;
        }

        Err("Entry not found")
    }

    pub fn init_dot_dotdot(
        &mut self,
        parent_inode_num: u32,
        self_inode_num: u32,
        ext4_block_size: usize,
    ) {
        let mut dentry = Ext4DirEntry::default();
        // 初始化`.`目录项
        dentry.inode_num = self_inode_num;
        dentry.rec_len = 12;
        dentry.name_len = 1;
        dentry.file_type = EXT4_DT_DIR;
        dentry.name = vec![b'.'];
        dentry.write_to_mem(&mut self.content[0..9]);

        // 初始化`..`目录项
        dentry.inode_num = parent_inode_num;
        dentry.rec_len = ext4_block_size as u16 - 12;
        dentry.name_len = 2;
        dentry.name = vec![b'.', b'.'];
        dentry.write_to_mem(&mut self.content[12..22]);
    }
}

// 注意: ext4的bitmap一般会有多块, inode_bitmap_size = inodes_per_group / 8 (byte), block_bitmap_size = blocks_per_group / 8 (byte)
pub struct Ext4Bitmap<'a> {
    bitmap: &'a mut [u8; EXT4_BLOCK_SIZE],
}

impl<'a> Ext4Bitmap<'a> {
    pub fn new(bitmap: &'a mut [u8; EXT4_BLOCK_SIZE]) -> Self {
        Self { bitmap }
    }
    // 分配一个位
    // 返回分配的位的编号(是一个块内的偏移, 需要转换为inode_bitmap中的编号), 由上层调用者负责转换
    /// 注意: inode_num从1开始, 而bitmap的索引从0开始, bit_index = inode_num - 1
    /// 注意: inode_bitmap_size的单位是byte
    pub fn alloc(&mut self, inode_bitmap_size: usize) -> Option<usize> {
        // log::warn!("self.buffer: {:?}", self.bitmap[4095]);
        // log::warn!("inode_bitmap_size: {}", inode_bitmap_size);
        // 逐字节处理, 加速alloc过程
        for (i, byte) in self.bitmap.iter_mut().enumerate() {
            if *byte != 0xff {
                for j in 0..8 {
                    if (*byte & (1 << j)) == 0 {
                        *byte |= 1 << j;
                        if i <= inode_bitmap_size {
                            // 这里加1是因为inode_num从1开始
                            return Some(i * 8 + j + 1);
                        } else {
                            // 找到第一个未使用的位时, 已经超出了inode_bitmap的大小, 说明inode_bitmap不够用
                            log::error!("i byte, j bit: {}, {}", i, j);
                            return None;
                        }
                    }
                }
            }
        }
        None
    }
    // 注意block_offset只是inode_num % (block_size * 8), 需要上层调用者负责转换
    pub fn dealloc(&mut self, block_offset: usize) {
        assert!(block_offset < PAGE_SIZE);
        let byte_offset = block_offset / 8;
        let bit_offset = block_offset % 8;
        self.bitmap[byte_offset] &= !(1 << bit_offset);
    }
}

// 硬编码, 对于ext4块大小为4096的情况
pub const EXTENT_BLOCK_MAX_ENTRIES: usize = 340; // (ext4_block_size - 12(extent_header)) / 12(ext4_extent_idx)
pub struct Ext4ExtentBlock<'a> {
    block: &'a mut [u8; EXT4_BLOCK_SIZE],
}

impl<'a> Ext4ExtentBlock<'a> {
    pub fn new(block: &'a mut [u8; EXT4_BLOCK_SIZE]) -> Self {
        Self { block }
    }
    fn extent_header(&self) -> &Ext4ExtentHeader {
        unsafe { &*(self.block.as_ptr() as *const Ext4ExtentHeader) }
    }
}

impl<'a> Ext4ExtentBlock<'a> {
    // 递归查找
    pub fn lookup_extent(
        &self,
        logical_block: u32,
        block_device: Arc<dyn BlockDevice>,
        ext4_block_size: usize,
    ) -> Option<Ext4Extent> {
        let header = self.extent_header();
        if header.depth == 0 {
            // 叶子节点
            let extents = unsafe {
                core::slice::from_raw_parts(
                    self.block.as_ptr().add(12) as *const Ext4Extent,
                    header.entries as usize,
                )
            };
            for extent in extents {
                if logical_block >= extent.logical_block
                    && logical_block < extent.logical_block + extent.len as u32
                {
                    return Some(*extent);
                }
            }
            return None;
        } else {
            // 索引节点
            let idxs = unsafe {
                core::slice::from_raw_parts(
                    self.block.as_ptr().add(12) as *const Ext4ExtentIdx,
                    header.entries as usize,
                )
            };
            if let Some(idx) = idxs.iter().find(|idx| logical_block >= idx.block) {
                let block_num = idx.physical_leaf_block();
                return Ext4ExtentBlock::new(
                    get_block_cache(block_num, block_device.clone(), ext4_block_size)
                        .lock()
                        .get_mut(0),
                )
                .lookup_extent(logical_block, block_device, ext4_block_size);
            } else {
                return None;
            }
        }
    }
}

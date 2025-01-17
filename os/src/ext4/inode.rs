use core::ptr;

use alloc::{sync::Arc, vec::Vec};

use crate::{
    drivers::block::{
        block_cache::get_block_cache,
        block_dev::{self, BlockDevice},
    },
    ext4::extent_tree::{self, ExtentIdx},
    fs::inode::{InodeOp, PhysicalBlockRange},
};

use super::{
    block_group::{self, GroupDesc},
    extent_tree::{Extent, ExtentHeader},
    fs::EXT4_BLOCK_SIZE,
    super_block::Ext4Meta,
};

const EXT4_N_BLOCKS: usize = 15;

// File mode
const S_IXOTH: u16 = 0x1; // Others have execute permission
const S_IWOTH: u16 = 0x2; // Others have write permission
const S_IROTH: u16 = 0x4; // Others have read permission
const S_IXGRP: u16 = 0x8; // Group has execute permission
const S_IWGRP: u16 = 0x10; // Group has write permission
const S_IRGRP: u16 = 0x20; // Group has read permission
const S_IXUSR: u16 = 0x40; // Owner has execute permission
const S_IWUSR: u16 = 0x80; // Owner has write permission
const S_IRUSR: u16 = 0x100; // Owner has read permission
const S_ISVTX: u16 = 0x200; // Sticky bit
const S_ISGID: u16 = 0x400; // Set GID
const S_ISUID: u16 = 0x800; // Set UID

// inode flags
// const EXT4_SECRM_FL: u32 = 0x00000001; // Secure deletion
// const EXT4_UNRM_FL: u32 = 0x00000002; // Undelete
// const EXT4_COMPR_FL: u32 = 0x00000004; // Compress file
// const EXT4_SYNC_FL: u32 = 0x00000008; // Synchronous updates
// const EXT4_IMMUTABLE_FL: u32 = 0x00000010; // Immutable file
// const EXT4_APPEND_FL: u32 = 0x00000020; // writes to file may only append
// const EXT4_NODUMP_FL: u32 = 0x00000040; // do not dump file
// const EXT4_NOATIME_FL: u32 = 0x00000080; // do not update atime
// const EXT4_DIRTY_FL: u32 = 0x00000100;
// const EXT4_COMPRBLK_FL: u32 = 0x00000200; // One or more compressed clusters
// const EXT4_NOCOMPR_FL: u32 = 0x00000400; // Don't compress
// const EXT4_ECOMPR_FL: u32 = 0x00000800; // Compression error
const EXT4_INDEX_FL: u32 = 0x00001000; // hash indexed directory
const EXT4_EXTENTS_FL: u32 = 0x000080000; // Inode uses extents
const EXT4_INLINE_DATA_FL: u32 = 0x10000000; // Inode has inline data

#[repr(C)]
#[derive(Debug, Clone, Copy)]
// 注意Ext4Inode字段一共160字节, 但是sb.inode_size是256字节, 在计算偏移量时要注意使用sb的
pub struct Ext4Inode {
    mode: u16,              // 文件类型和访问权限
    uid: u16,               // 文件所有者的用户ID(低16位)
    size_lo: u32,           // 文件大小(字节, 低32位)
    atime: u32,             // 最后访问时间
    change_inode_time: u32, // 最近Inode改变时间
    modify_file_time: u32,  // 最近文件内容修改时间
    dtime: u32,             // 删除时间
    gid: u16,               // 所属组ID(低16位)
    links_count: u16,       // 硬链接数
    blocks_lo: u32,         // 文件大小(块数)
    flags: u32,             // 扩展属性标志
    osd1: u32,              // 操作系统相关
    // 符号链接: 目标字符串长度小于60字节, 直接存储在blocks中
    // ext2/3文件: 存储文件数据块指针, 0-11直接, 12间接, 13二级间接, 14三级间接
    block: [u32; EXT4_N_BLOCKS], // 文件数据块指针
    generation: u32,             // 文件版本(用于NFS)
    file_acl_lo: u32,            // 文件访问控制列表
    size_hi: u32,                // 文件大小(字节, 高32位)
    obso_faddr: u32,             // 已废弃碎片地址
    // 具体可能不是3个u32, 但是这里只是为了占位(大小是12字节)
    osd2: [u32; 3],               // 操作系统相关
    extra_isize: u16,             // Inode扩展大小
    checksum_hi: u16,             // CRC32校验和高16位
    change_inode_time_extra: u32, // 额外的Inode修改时间(nsec << 2 | epoch)
    modify_file_time_extra: u32,  // 额外的内容修改时间(nsec << 2 | epoch)
    atime_extra: u32,             // 额外的访问时间(nsec << 2 | epoch)
    create_time: u32,             // 文件创建时间
    create_time_extra: u32,       // 额外的创建时间(nsec << 2 | epoch)
    version_hi: u32,              // 文件版本(高32位)
    project_id: u32,              // 项目ID
}

// ext4中没有inode0, 根目录的inode number是2
// 定位inode的位置: 块组 + 组内偏移量
// 块组号 = (inode_number - 1) / inodes_per_group
// 组内偏移量 = (inode_number - 1) % inodes_per_group
impl Ext4Inode {
    pub fn new_root(
        block_device: Arc<dyn BlockDevice>,
        ext4_meta: &Ext4Meta,
        group_desc: &GroupDesc,
    ) -> Arc<Self> {
        let root_ino = 2;
        let inode_table_block_id = group_desc.inode_table() as usize;
        let ext4_root_inode = get_block_cache(inode_table_block_id, block_device, EXT4_BLOCK_SIZE)
            .lock()
            .read(
                (root_ino - 1) * ext4_meta.inode_size as usize,
                |inode: &Ext4Inode| inode.clone(),
            );
        Arc::new(ext4_root_inode)
    }
}

/// 辅助函数
impl Ext4Inode {
    /// 是否使用extent tree, 还是传统的12个直接块, 1个间接块, 1个二级间接块, 1个三级间接块
    pub fn use_extent_tree(&self) -> bool {
        self.flags & EXT4_EXTENTS_FL == EXT4_EXTENTS_FL
    }
    /// 是否有inline data
    pub fn has_inline_data(&self) -> bool {
        self.flags & EXT4_INLINE_DATA_FL == EXT4_INLINE_DATA_FL
    }
    pub fn flags(&self) {
        log::info!(
            "\thash indexed directory: {}",
            self.flags & EXT4_INDEX_FL == EXT4_INDEX_FL
        );
        log::info!(
            "\tinode uses extents: {}",
            self.flags & EXT4_EXTENTS_FL == EXT4_EXTENTS_FL
        );
        log::info!(
            "\tinode has inline data: {}",
            self.flags & EXT4_INLINE_DATA_FL == EXT4_INLINE_DATA_FL
        );
    }
}

// Extent tree
impl Ext4Inode {
    pub fn extent_header(&self) -> ExtentHeader {
        assert!(self.use_extent_tree(), "not use extent tree");
        assert!(!self.has_inline_data());
        // extent_header是block的前12字节
        unsafe {
            let extent_header_ptr = self.block.as_ptr() as *const ExtentHeader;
            assert!((*extent_header_ptr).magic == 0xF30A, "magic number error");
            *extent_header_ptr
        }
    }
    pub fn extent_idxs(&self, extent_header: &ExtentHeader) -> Vec<ExtentIdx> {
        assert!(extent_header.depth > 0, "not index node");
        let mut extent_idx = Vec::new();
        // extent_idx是block的后4字节
        unsafe {
            let extent_idx_ptr = self.block.as_ptr().add(3) as *const ExtentIdx;
            for i in 0..extent_header.entries as usize {
                extent_idx.push(ptr::read(extent_idx_ptr.add(i as usize)));
            }
        }
        extent_idx
    }
    pub fn extents(&self, extent_header: &ExtentHeader) -> Vec<Extent> {
        assert!(extent_header.depth == 0, "not leaf node");
        let mut extents = Vec::new();
        unsafe {
            let extent_ptr = self.block.as_ptr().add(3) as *const Extent;
            for i in 0..extent_header.entries as usize {
                extents.push(ptr::read(extent_ptr.add(i as usize)));
            }
        }
        extents
    }

    pub fn find_extent(
        &self,
        logical_start_block: u32,
        block_device: Arc<dyn BlockDevice>,
    ) -> Result<Extent, &'static str> {
        let mut current_block = logical_start_block;

        // 获取根节点的extent_header
        let mut extent_header = self.extent_header();

        // 遍历extent B+树，直到找到所有需要的块范围
        while extent_header.depth > 0 {
            // 当前节点是索引节点
            let extent_idxs = self.extent_idxs(&extent_header);

            // 在索引节点中找到包含目标块的子节点
            if let Some(idx) = extent_idxs.iter().find(|idx| idx.block <= current_block) {
                let next_block = idx.physical_leaf_block();
                extent_header = unsafe {
                    // 加载子节点的ExtentHeader
                    get_block_cache(next_block, block_device.clone(), EXT4_BLOCK_SIZE)
                        .lock()
                        .read(0, |header: &ExtentHeader| header.clone())
                };
            } else {
                // 未找到对应的索引节点
                return Err("not found");
            }
        }
        // 当前节点是叶子节点
        let mut extents = self.extents(&extent_header);

        // 遍历叶子节点的所有extent
        for extent in extents.drain(..) {
            let start_block = extent.block;
            let end_block = start_block + extent.len as u32;
            if logical_start_block >= start_block && logical_start_block < end_block {
                return Ok(extent);
            }
        }
        return Err("not found");
    }
}

impl Ext4Inode {
    // 读取文件内容
    // 现在只支持extent tree
    pub fn read(
        &self,
        page_offset: usize,
        size: usize,
        block_device: Arc<dyn BlockDevice>,
    ) -> Extent {
        assert!(self.use_extent_tree(), "not use extent tree");
        self.read(page_offset, size, block_device)
    }
}

impl InodeOp for Ext4Inode {
    /// 根据在文件中的逻辑块号读取对应的extent
    fn read<'a>(
        &'a self,
        page_offset: usize,
        block_device: Arc<dyn BlockDevice>,
    ) -> Result<PhysicalBlockRange, &'static str> {
        let logical_start_block = page_offset as u32;
        let extent = self.find_extent(logical_start_block, block_device)?;
        Ok(extent.to_physical_block_range())
    }
    fn write<'a>(&'a self, page_offset: usize, buf: &'a [u8]) -> usize {
        unimplemented!();
    }
}

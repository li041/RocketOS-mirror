use core::ptr;

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use spin::RwLock;

use crate::arch::config::EXT4_MAX_INLINE_DATA;
use crate::arch::timer::TimeSpec;
use crate::fat32::inode;
use crate::fs::inode::InodeOp;
use crate::fs::kstat::Kstat;
// use crate::fs::inode::InodeMeta;
use crate::{
    arch::config::{PAGE_SIZE, PAGE_SIZE_BITS},
    drivers::block::{block_cache::get_block_cache, block_dev::BlockDevice},
    ext4::{
        block_op::{Ext4DirContentRO, Ext4DirContentWE},
        extent_tree::Ext4ExtentIdx,
    },
    fs::{dentry::Dentry, page_cache::AddressSpace, FSMutex},
    mm::Page,
    mutex::SpinNoIrqLock,
};

use super::{
    block_group::GroupDesc,
    dentry::Ext4DirEntry,
    extent_tree::{Ext4Extent, Ext4ExtentHeader},
    fs::Ext4FileSystem,
    super_block::Ext4SuperBlock,
};

const EXT4_N_BLOCKS: usize = 15;

/// 权限位掩码（低 12 位）
pub const S_IXOTH: u16 = 0x1; // Others have execute permission
pub const S_IWOTH: u16 = 0x2; // Others have write permission
pub const S_IROTH: u16 = 0x4; // Others have read permission
pub const S_IXGRP: u16 = 0x8; // Group has execute permission
pub const S_IWGRP: u16 = 0x10; // Group has write permission
pub const S_IRGRP: u16 = 0x20; // Group has read permission
pub const S_IXUSR: u16 = 0x40; // Owner has execute permission
pub const S_IWUSR: u16 = 0x80; // Owner has write permission
pub const S_IRUSR: u16 = 0x100; // Owner has read permission
pub const S_ISVTX: u16 = 0x200; // Sticky bit
pub const S_ISGID: u16 = 0x400; // Set GID
pub const S_ISUID: u16 = 0x800; // Set UID

// 文件类型(高4位)
pub const S_IFMT: u16 = 0xF000; // File type mask
pub const S_IFCHR: u16 = 0x2000; // Character device
pub const S_IFDIR: u16 = 0x4000; // Directory
pub const S_IFREG: u16 = 0x8000; // Regular file
pub const S_IFLNK: u16 = 0xA000; // Symbolic link
pub const S_IALLUGO: u16 = 0x1FF; // All permissions

// inode flags
// const EXT4_SECRM_FL: u32 = 0x00000001; // Secure deletion
// const EXT4_UNRM_FL: u32 = 0x00000002; // Undelete
// const EXT4_COMPR_FL: u32 = 0x00000004; // Compress file
// const EXT4_SYNC_FL: u32 = 0x00000008; // Synchronous updates
const EXT4_IMMUTABLE_FL: u32 = 0x00000010; // Immutable file
const EXT4_APPEND_FL: u32 = 0x00000020; // writes to file may only append
                                        // const EXT4_NODUMP_FL: u32 = 0x00000040; // do not dump file
                                        // const EXT4_NOATIME_FL: u32 = 0x00000080; // do not update atime
                                        // const EXT4_DIRTY_FL: u32 = 0x00000100;
                                        // const EXT4_COMPRBLK_FL: u32 = 0x00000200; // One or more compressed clusters
                                        // const EXT4_NOCOMPR_FL: u32 = 0x00000400; // Don't compress
                                        // const EXT4_ECOMPR_FL: u32 = 0x00000800; // Compression error
pub const EXT4_INDEX_FL: u32 = 0x00001000; // hash indexed directory
pub const EXT4_EXTENTS_FL: u32 = 0x00080000; // Inode uses extents
pub const EXT4_INLINE_DATA_FL: u32 = 0x10000000; // Inode has inline data

const STATX_ATTR_APPEND: u64 = 0x00000020; // writes to file may only append

// ext4 inode时间相关字段
//  1. 不带extra的是自Unix时间戳(1970年1月1日)以来的秒数
//  2. 带extra的是自Unix时间戳(1970年1月1日)以来的纳秒数, extra = (nsec << 2 | epoch)
//  低 30 位 (nsec << 2)：存储纳秒部分(纳秒值的左移 2 位), 高 2 位 (epoch)：存储时间时代 (epoch)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
// 注意Ext4Inode字段一共160字节, 但是sb.inode_size是256字节, 在计算偏移量时要注意使用sb的
pub struct Ext4InodeDisk {
    mode: u16,              // 文件类型(高4位)和访问权限(低12位)
    uid: u16,               // 文件所有者的用户ID(低16位)
    size_lo: u32,           // 文件大小(字节, 低32位)
    atime: u32,             // 最后访问时间(秒)
    change_inode_time: u32, // 最近Inode改变时间(秒)
    modify_file_time: u32,  // 最近文件内容修改时间(秒)
    dtime: u32,             // 删除时间
    gid: u16,               // 所属组ID(低16位)
    links_count: u16,       // 硬链接数
    blocks_lo: u32, // 文件大小(块数, 以512字节为逻辑块, 如果设置EXT4_HUGE_FILE_FL, 才是fs_block size)
    flags: u32,     // 扩展属性标志
    osd1: u32,      // 操作系统相关
    // 符号链接: 目标字符串长度小于60字节, 直接存储在blocks中
    // ext2/3文件: 存储文件数据块指针, 0-11直接, 12间接, 13二级间接, 14三级间接
    // block: [u32; EXT4_N_BLOCKS], // 文件数据块指针
    block: [u8; 60],     // 文件数据块指针
    pub generation: u32, // 文件版本(用于NFS)
    file_acl_lo: u32,    // 文件访问控制列表
    obso_faddr: u32,     // 已废弃碎片地址
    size_hi: u32,        // 文件大小(字节, 高32位)
    // 具体可能不是3个u32, 但是这里只是为了占位(大小是12字节)
    osd2: [u32; 3],               // 操作系统相关
    extra_isize: u16,             // Inode扩展大小
    checksum_hi: u16,             // CRC32校验和高16位
    change_inode_time_extra: u32, // 额外的Inode修改时间(nsec << 2 | epoch), epoch对应[1:0]位, 表示翻了多少个2^32秒
    modify_file_time_extra: u32,  // 额外的内容修改时间(nsec << 2 | epoch)
    atime_extra: u32,             // 额外的访问时间(nsec << 2 | epoch)
    create_time: u32,             // 文件创建时间
    create_time_extra: u32,       // 额外的创建时间(nsec << 2 | epoch)
    version_hi: u32,              // 文件版本(高32位)
    project_id: u32,              // 项目ID
}

impl Default for Ext4InodeDisk {
    fn default() -> Self {
        Self {
            mode: 0,
            uid: 0,
            size_lo: 0,
            atime: 0,
            change_inode_time: 0,
            modify_file_time: 0,
            dtime: 0,
            gid: 0,
            links_count: 1,
            blocks_lo: 0,
            flags: 0,
            osd1: 0,
            block: [0; 60],
            generation: 0,
            file_acl_lo: 0,
            size_hi: 0,
            obso_faddr: 0,
            osd2: [0; 3],
            extra_isize: 0,
            checksum_hi: 0,
            change_inode_time_extra: 0,
            modify_file_time_extra: 0,
            atime_extra: 0,
            create_time: 0,
            create_time_extra: 0,
            version_hi: 0,
            project_id: 0,
        }
    }
}

// ext4中没有inode0, 根目录的inode number是2
// 定位inode的位置: 块组 + 组内偏移量
// 块组号 = (inode_number - 1) / inodes_per_group
// 组内偏移量 = (inode_number - 1) % inodes_per_group
impl Ext4InodeDisk {
    // group_desc: 对于root_inode来说, 是块组描述符表的第一个
    fn new_root(
        block_device: Arc<dyn BlockDevice>,
        // ext4_meta: &Ext4Meta,
        super_block: &Arc<Ext4SuperBlock>,
        group_desc: &Arc<GroupDesc>,
    ) -> Self {
        let root_ino = 2;
        let inode_table_block_id = group_desc.inode_table() as usize;
        let ext4_root_inode = get_block_cache(
            inode_table_block_id,
            block_device,
            super_block.block_size as usize,
        )
        .lock()
        .read(
            (root_ino - 1) * super_block.inode_size as usize,
            |inode: &Ext4InodeDisk| inode.clone(),
        );
        ext4_root_inode
    }
    /// 创建一个字符设备, mode字段被设置为S_IFCHR
    /// 字符设备不占用数据块(blocks_lo = 0, size_lo = size_hi = 0), blocks不存储数据块(block前4个字节存主设备号, 4~8字节存次设备号)
    pub fn new_chr(mode: u16, major: u32, minor: u32) -> Self {
        let mut inode = Ext4InodeDisk::default();
        let current_time = TimeSpec::new_wall_time();
        inode.mode = mode | S_IFCHR;
        inode.uid = 0;
        inode.gid = 0;
        inode.size_lo = 0;
        inode.size_hi = 0;
        inode.blocks_lo = 0;
        inode.links_count = 1;
        inode.flags = 0;
        // 设置主设备号和次设备号
        inode.block[0..4].copy_from_slice(&major.to_le_bytes());
        inode.block[4..8].copy_from_slice(&minor.to_le_bytes());
        // 设置时间戳
        inode.set_atime(current_time);
        inode.set_ctime(current_time);
        inode.set_mtime(current_time);
        inode
    }
}

/// 辅助函数
impl Ext4InodeDisk {
    /// 是否使用extent tree, 还是传统的12个直接块, 1个间接块, 1个二级间接块, 1个三级间接块
    pub fn use_extent_tree(&self) -> bool {
        self.flags & EXT4_EXTENTS_FL == EXT4_EXTENTS_FL
    }
    pub fn set_extent_tree_flag(&mut self) {
        self.flags |= EXT4_EXTENTS_FL;
    }
    /// 是否有inline data
    pub fn has_inline_data(&self) -> bool {
        self.flags & EXT4_INLINE_DATA_FL == EXT4_INLINE_DATA_FL
    }
    pub fn set_inline_data_flag(&mut self) {
        self.flags |= EXT4_INLINE_DATA_FL;
    }
    /// 是否是目录
    fn is_dir(&self) -> bool {
        self.mode & S_IFDIR == S_IFDIR
    }
    /// 是否是符号链接
    fn is_symlink(&self) -> bool {
        self.mode & S_IFLNK == S_IFLNK
    }
    fn flags(&self) {
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
    pub fn get_size(&self) -> u64 {
        (self.size_hi as u64) << 32 | self.size_lo as u64
    }
    pub fn set_size(&mut self, size: u64) {
        self.size_lo = size as u32;
        self.size_hi = (size >> 32) as u32;
    }
    pub fn get_devt(&self) -> (u32, u32) {
        let major = u32::from_le_bytes(self.block[0..4].try_into().unwrap());
        let minor = u32::from_le_bytes(self.block[4..8].try_into().unwrap());
        (major, minor)
    }
    pub fn get_uid(&self) -> u32 {
        self.uid as u32
    }
    pub fn get_gid(&self) -> u32 {
        self.gid as u32
    }
    pub fn get_atime(&self) -> TimeSpec {
        TimeSpec {
            sec: (self.atime as u64 + (((self.atime_extra & 0x3) as u64) << 32)) as usize,
            nsec: self.atime_extra as usize,
        }
    }
    pub fn set_atime(&mut self, atime: TimeSpec) {
        self.atime = atime.sec as u32;
        self.atime_extra = (atime.nsec as u32) << 2 | ((atime.sec >> 32) as u32 & 0x3);
    }
    pub fn get_mtime(&self) -> TimeSpec {
        TimeSpec {
            sec: (self.modify_file_time as u64
                + (((self.modify_file_time_extra & 0x3) as u64) << 32)) as usize,
            nsec: self.modify_file_time_extra as usize,
        }
    }
    pub fn set_mtime(&mut self, mtime: TimeSpec) {
        self.modify_file_time = mtime.sec as u32;
        self.modify_file_time_extra = (mtime.nsec as u32) << 2 | ((mtime.sec >> 32) as u32 & 0x3);
    }
    pub fn get_ctime(&self) -> TimeSpec {
        TimeSpec {
            sec: (self.change_inode_time as u64
                + (((self.change_inode_time_extra & 0x3) as u64) << 32)) as usize,
            nsec: self.change_inode_time_extra as usize,
        }
    }
    pub fn set_ctime(&mut self, ctime: TimeSpec) {
        self.change_inode_time = ctime.sec as u32;
        self.change_inode_time_extra = (ctime.nsec as u32) << 2 | ((ctime.sec >> 32) as u32 & 0x3);
    }
    pub fn set_mode(&mut self, mode: u16) {
        self.mode = mode;
    }
    pub fn get_mode(&self) -> u16 {
        self.mode
    }
    pub fn get_type(&self) -> u16 {
        self.mode & S_IFMT
    }
    pub fn get_perm(&self) -> u16 {
        self.mode & S_IALLUGO
    }
    // Todo:
    pub fn set_dtime(&mut self, _dtime: u32) {
        let fake_dtime = 66666666;
        self.dtime = fake_dtime;
    }
    pub fn clear_block(&mut self) {
        self.block = [0; 60];
    }
    pub fn get_nlinks(&self) -> u16 {
        self.links_count
    }
    pub fn add_nlinks(&mut self) {
        self.links_count += 1;
    }
    pub fn sub_nlinks(&mut self) {
        self.links_count -= 1;
    }
}

// Extent tree
impl Ext4InodeDisk {
    pub fn init_extent_tree(&mut self) {
        assert!(self.use_extent_tree(), "not use extent tree");
        // 初始化extent tree
        let header_ptr = self.block.as_mut_ptr() as *mut Ext4ExtentHeader;
        unsafe {
            header_ptr.write(Ext4ExtentHeader::default());
        }
    }
    fn extent_header(&self) -> Ext4ExtentHeader {
        assert!(self.use_extent_tree(), "not use extent tree");
        assert!(!self.has_inline_data());
        // extent_header是block的前12字节
        unsafe {
            let extent_header_ptr = self.block.as_ptr() as *const Ext4ExtentHeader;
            assert!((*extent_header_ptr).magic == 0xF30A, "magic number error");
            *extent_header_ptr
        }
    }
    fn extent_idxs(&self, extent_header: &Ext4ExtentHeader) -> Vec<Ext4ExtentIdx> {
        assert!(extent_header.depth > 0, "not index node");
        let mut extent_idx = Vec::new();
        // extent_idx是block的后4字节
        unsafe {
            let extent_idx_ptr = self.block.as_ptr().add(12) as *const Ext4ExtentIdx;
            for i in 0..extent_header.entries as usize {
                extent_idx.push(ptr::read(extent_idx_ptr.add(i as usize)));
            }
        }
        extent_idx
    }
    fn extents(&self, extent_header: &Ext4ExtentHeader) -> Vec<Ext4Extent> {
        assert!(extent_header.depth == 0, "not leaf node");
        let mut extents = Vec::new();
        unsafe {
            // 偏移量是3个u32, 是extent_header的大小
            let extent_ptr = self.block.as_ptr().add(12) as *const Ext4Extent;
            for i in 0..extent_header.entries as usize {
                extents.push(ptr::read(extent_ptr.add(i as usize)));
            }
        }
        extents
    }
    /// 仅用于文件的读
    /// 由上层调用者保证: 未命中页缓存时才调用
    /// 从内存中的extent tree中找到对应的extent, 如果没有从磁盘加载
    /// logical_start_block: 逻辑块号(例. 文件的前4096字节对于ext4就是逻辑块号0的内容)
    fn lookup_extent(
        &self,
        logical_start_block: u32,
        block_device: Arc<dyn BlockDevice>,
        ext4_block_size: usize,
    ) -> Option<Ext4Extent> {
        let current_block = logical_start_block;

        // 获取根节点的extent_header
        let mut extent_header = self.extent_header();

        // 遍历extent B+树，直到找到所有需要的块范围
        while extent_header.depth > 0 {
            // 当前节点是索引节点
            let extent_idxs = self.extent_idxs(&extent_header);

            // 在索引节点中找到包含目标块的子节点
            if let Some(idx) = extent_idxs.iter().find(|idx| idx.block <= current_block) {
                let next_block = idx.physical_leaf_block();
                // 加载子节点的ExtentHeader
                extent_header = get_block_cache(next_block, block_device.clone(), ext4_block_size)
                    .lock()
                    .read(0, |header: &Ext4ExtentHeader| header.clone());
            } else {
                // 未找到对应的索引节点
                return None;
            }
        }
        // 当前节点是叶子节点
        let extents = self.extents(&extent_header);
        // 遍历叶子节点的所有extent
        for extent in &extents {
            let start_block = extent.logical_block;
            let end_block = start_block + extent.len as u32;
            if logical_start_block >= start_block && logical_start_block < end_block {
                // log::info!(
                //     "[Ext4InodeDisk::find_extent]: hit\nlogical_start_block: {}, start_block: {}, end_block: {}",
                //     logical_start_block,
                //     start_block,
                //     end_block
                // );
                return Some(*extent);
            }
        }
        return None;
    }
    /// 更新 extent 结构，加入新的逻辑块
    /// Todo: 未实现, 没有考虑索引节点分裂
    /// 仅修改在内存中ext4结构体
    /// 上层调用者保证:
    ///     1. 调用modify_inode将inode结构体写回到block_cache
    pub fn insert_extent(
        &mut self,
        logical_block_num: u32,
        physical_block_num: u64, // 物理块号
        blocks_count: u32,
        block_device: Arc<dyn BlockDevice>,
        ext4_block_size: usize,
    ) -> Result<(), &'static str> {
        // 获取当前的 extent 头
        let mut extent_header = self.extent_header();

        // 情况 0: extent entries 超出最大数量, 需要创建索引节点
        // Todo: 未实现节点的分裂
        if extent_header.entries == extent_header.max {
            panic!("[update_extent]Extent entries exceed max, need index node");
        }

        // 1. 遍历找到对应的叶子节点
        while extent_header.depth > 0 {
            let extent_idxs = self.extent_idxs(&extent_header);

            // 在索引节点中找到对应的叶子节点
            if let Some(idx) = extent_idxs
                .iter()
                .find(|idx| idx.block <= logical_block_num)
            {
                let next_block = idx.physical_leaf_block();
                extent_header = get_block_cache(next_block, block_device.clone(), ext4_block_size)
                    .lock()
                    .read(0, |header: &Ext4ExtentHeader| header.clone());
            } else {
                return Err("No valid extent index found");
            }
        }

        // 2. 遍历叶子节点，查找合适的 extent合并
        let mut extents = self.extents(&extent_header);

        for (i, extent) in extents.iter().enumerate() {
            let lend_block = extent.logical_block + extent.len as u32;
            let pend_block = extent.physical_start_block() as u32 + extent.len as u32;

            // 情况 1: 直接合并, 物理块号连续, 且逻辑块号连续
            if logical_block_num == lend_block
                && physical_block_num as u32 == pend_block
                && extent.len < 32768
            {
                unsafe {
                    let extent_ptr = self.block.as_ptr().add(12 + i * 12) as *mut Ext4Extent;
                    (*extent_ptr).len += blocks_count as u16;
                    log::info!("[update_extent] Extend existing extent");
                    return Ok(());
                }
            }
        }

        // 情况 2: 插入新的 extent, 情况0已经保证了有位置可插入
        let new_extent = Ext4Extent::new(
            logical_block_num,
            blocks_count as u16,
            physical_block_num as usize,
        );

        // 没有合并, 插入新extent, 并按logical_block排序
        extents.push(new_extent);
        extents.sort_by_key(|extent| extent.logical_block);

        let extent_header_ptr = self.block.as_ptr() as *mut Ext4ExtentHeader;
        // 写回内存
        unsafe {
            (*extent_header_ptr).entries += 1;
            for (i, extent) in extents.iter().enumerate() {
                let extent_ptr = self.block.as_ptr().add(12 + i * 12) as *mut Ext4Extent;
                extent_ptr.write(*extent);
            }
        }
        Ok(())
    }
    // fn read_all(&self, block_device: Arc<dyn BlockDevice>, ext4_block_size: usize) -> Vec<Ext4Extent> {
    //     assert!(self.is_dir(), "not a directory");
    //     // 使用队列来遍历extent tree
    //     let mut queue= VecDeque::new();
    //     queue.push_back(self.extent_header());
    //     let mut ret = Vec::new();

    //     while let Some(extent_header) = queue.pop_front() {
    //         if extent_header.depth > 0 {
    //             let extent_idxs = self.extent_idxs(&extent_header);
    //             for idx in extent_idxs.iter() {
    //                 let next_block = idx.physical_leaf_block();
    //                 let next_extent_header = get_block_cache(next_block, block_device.clone(), ext4_block_size)
    //                     .lock()
    //                     .read(0, |header: &Ext4ExtentHeader| header.clone());
    //                 queue.push_back(next_extent_header);
    //             }
    //         } else {
    //             let extents = self.extents(&extent_header);
    //             for extent in extents {
    //                 ret.push(extent);
    //             }
    //         }
    //     }
    //     // 由B+树的性质确保了, Extents是有序的(从小到大)
    //     ret
    // }
}

pub struct Ext4Inode {
    pub ext4_fs: Weak<Ext4FileSystem>,
    pub block_device: Arc<dyn BlockDevice>,
    pub address_space: AddressSpace,
    pub inode_num: usize,
    pub link: RwLock<Option<String>>,
    pub inner: FSMutex<Ext4InodeInner>,
    pub self_weak: Weak<Self>,
}

impl Drop for Ext4Inode {
    // 释放页缓存, inode bitmap, block bitmap, inode table
    // Todo: 可能有资源还没有释放
    fn drop(&mut self) {
        // 释放页缓存
        self.address_space.clear();
        // 释放inode bitmap和inode table
        self.ext4_fs.upgrade().unwrap().dealloc_inode(
            self.block_device.clone(),
            self.inode_num,
            self.inner.read().inode_on_disk.is_dir(),
        );
        // Todo: 释放extent_tree
    }
}

pub struct Ext4InodeInner {
    pub inode_on_disk: Ext4InodeDisk,
}

impl Ext4InodeInner {
    pub fn new(inode_on_disk: Ext4InodeDisk) -> Self {
        Self { inode_on_disk }
    }
}

// 所有的读/写都是基于Ext4Inode::read/write, 通过页缓存和extent tree来读写
impl Ext4Inode {
    /// used by `InodeOp ->create`
    pub fn new(
        inode_mode: u16,
        flags: u32,
        ext4_fs: Weak<Ext4FileSystem>,
        ino: usize,
        block_device: Arc<dyn BlockDevice>,
    ) -> Arc<Self> {
        // Todo: 1. init_owner(): 设置mode, uid, gid
        // Todo: 2. 时间戳: atime, mtime, ctime
        // 3. 设置i_size = 0, i_blocks(逻辑块计数) = 0
        // 4. 设置flags, extent tree初始化
        let mut new_inode_disk = Ext4InodeDisk {
            mode: inode_mode,
            flags,
            ..Default::default()
        };
        // 初始化extent tree
        if flags & EXT4_EXTENTS_FL == EXT4_EXTENTS_FL {
            new_inode_disk.init_extent_tree();
        }
        Arc::new_cyclic(|weak| Ext4Inode {
            ext4_fs,
            block_device,
            address_space: AddressSpace::new(),
            inode_num: ino,
            link: RwLock::new(None),
            inner: FSMutex::new(Ext4InodeInner::new(new_inode_disk)),
            self_weak: weak.clone(),
        })
    }
    pub fn new_root(
        block_device: Arc<dyn BlockDevice>,
        ext4_fs: Arc<Ext4FileSystem>,
        group_desc: &Arc<GroupDesc>,
    ) -> Arc<Self> {
        let super_block = &ext4_fs.super_block;
        let root_inode_disk =
            Ext4InodeDisk::new_root(block_device.clone(), super_block, group_desc);
        Arc::new_cyclic(|weak| Ext4Inode {
            ext4_fs: Arc::downgrade(&ext4_fs),
            block_device,
            address_space: AddressSpace::new(),
            inode_num: 2,
            link: RwLock::new(None),
            inner: FSMutex::new(Ext4InodeInner::new(root_inode_disk)),
            self_weak: weak.clone(),
        })
    }
    // 所有的读/写都是基于Ext4Inode::read/write, 通过页缓存和extent tree来读写
    // 先读取页缓存, 若未命中, 看是否是inline_data, 若不是根据extent tree从磁盘中读取
    // 注意:
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> Result<usize, &'static str> {
        // 需要读取的总长度
        let rbuf_len = buf.len();
        let inode_size = self.inner.read().inode_on_disk.size_lo as usize;

        // offset超出文件大小, 直接返回0(EOF)
        if offset >= inode_size {
            return Ok(0);
        }

        let mut current_read = 0;
        let mut page_offset = offset >> PAGE_SIZE_BITS;
        let mut page_offset_in_page = offset & (PAGE_SIZE - 1);

        let mut current_extent: Option<Ext4Extent> = None;
        let mut page: Arc<Page>;
        let mut fs_block_id: usize;

        while current_read < rbuf_len {
            if let Some(page_cache) = self.address_space.get_page_cache(page_offset) {
                // 页缓存命中
                page = page_cache;
            } else if page_offset == 0 && self.inner.read().inode_on_disk.has_inline_data() {
                // 页缓存未命中, 先查看是否是inline_data, 再看是否在查到的PhysicalBlockRange中
                // 第一次读, 且有inline data
                log::warn!("[Ext4Inode::read] has inline data",);
                let inline_data_len = self.inner.read().inode_on_disk.size_lo as usize;
                let copy_len = (rbuf_len).min(inline_data_len - offset);
                //创建inline page cache
                self.address_space.new_inline_page_cache(
                    page_offset,
                    self.self_weak.clone(),
                    &self.inner.write().inode_on_disk.block[offset..offset + copy_len],
                );
                // 复制inline data到buf中
                buf[..copy_len].copy_from_slice(
                    &self.inner.write().inode_on_disk.block[offset..offset + copy_len],
                );
                return Ok(copy_len);
            } else {
                // 不是inline data, 先从页缓存中读取
                if let Some(extent) = &current_extent {
                    // 先查看现有的extent, 是否在查到的PhysicalBlockRange中
                    if (extent.logical_block + extent.len as u32) as usize > page_offset {
                        // 命中extent读取, 知道对应的物理块号
                        fs_block_id = extent.physical_start_block() + page_offset
                            - extent.logical_block as usize;
                    } else {
                        // 未命中, 从inode中读取extent
                        // Todo: 处理空洞, 这里不能是?
                        let extent = self.inner.write().inode_on_disk.lookup_extent(
                            page_offset as u32,
                            self.block_device.clone(),
                            self.ext4_fs.upgrade().unwrap().block_size(),
                        );
                        if let Some(extent) = extent {
                            // 重新计算物理块号
                            fs_block_id = extent.physical_start_block() + page_offset
                                - extent.logical_block as usize;
                            current_extent = Some(extent);
                        } else {
                            fs_block_id = 0;
                            current_extent = None;
                        }
                    }
                } else {
                    // 未命中, 从inode中读取extent
                    // Todo: 处理空洞, 这里不能是?
                    let extent = self.inner.write().inode_on_disk.lookup_extent(
                        page_offset as u32,
                        self.block_device.clone(),
                        self.ext4_fs.upgrade().unwrap().block_size(),
                    );
                    if let Some(extent) = extent {
                        // 重新计算物理块号
                        fs_block_id = extent.physical_start_block() + page_offset
                            - extent.logical_block as usize;
                        current_extent = Some(extent);
                    } else {
                        fs_block_id = 0;
                        current_extent = None;
                    }
                }
                page = self.address_space.new_page_cache(
                    page_offset,
                    fs_block_id,
                    self.block_device.clone(),
                    self.self_weak.clone(),
                );
            }
            // 计算本次能读取的长度, 不能超过文件大小
            let remaining_file_size = inode_size - (current_read + offset);
            let copy_len = (rbuf_len - current_read)
                .min(PAGE_SIZE - page_offset_in_page)
                .min(remaining_file_size);
            // 先读出一整页, 再从页中拷贝需要的部分到buf中
            page.read(0, |data: &[u8; PAGE_SIZE]| {
                buf[current_read..current_read + copy_len]
                    .copy_from_slice(&data[page_offset_in_page..page_offset_in_page + copy_len]);
            });
            current_read += copy_len;
            // 读取到文件末尾
            if remaining_file_size < PAGE_SIZE {
                return Ok(current_read);
            }
            page_offset += 1;
            page_offset_in_page = 0;
        }
        Ok(current_read)
    }
    // Todo: 处理inline_data
    pub fn get_page_cache(&self, offset: usize) -> Option<Arc<Page>> {
        let inode_size = self.inner.read().inode_on_disk.size_lo as usize;

        // offset超出文件大小, 直接返回0(EOF)
        if offset > inode_size {
            panic!("offset out of range");
        }

        // 未命中页缓存, 从磁盘中读取
        self.address_space.get_page_cache(offset).or_else(|| {
            // 先判断是否有inline data
            // 第一次读, 且有inline data
            if offset == 0 && self.inner.read().inode_on_disk.has_inline_data() {
                // 页缓存未命中, 先查看是否是inline_data, 再看是否在查到的PhysicalBlockRange中
                log::warn!("[Ext4Inode::read] has inline data",);
                let inline_data_len = self.inner.read().inode_on_disk.size_lo as usize;
                // 创建inline page cache
                let page = self.address_space.new_inline_page_cache(
                    offset,
                    self.self_weak.clone(),
                    &self.inner.write().inode_on_disk.block[offset..offset + inline_data_len],
                );
                return Some(page);
            }
            // 不是inline data page
            // 从inode中读取extent
            let extent = self.inner.write().inode_on_disk.lookup_extent(
                offset as u32,
                self.block_device.clone(),
                self.ext4_fs.upgrade().unwrap().block_size(),
            );
            if let Some(extent) = extent {
                let fs_block_id =
                    extent.physical_start_block() + offset - extent.logical_block as usize;
                Some(self.address_space.new_page_cache(
                    offset,
                    fs_block_id,
                    self.block_device.clone(),
                    self.self_weak.clone(),
                ))
            } else {
                None
            }
        })
    }
    /// 由上层调用者保证
    ///     1. 确定是inline_data才调用
    ///     2. 对于fast link, 实际inode->i_flags的EXT4_INLINE_DATA_FL位没有设置
    pub fn read_inline_data(&self, offset: usize, buf: &mut [u8]) -> usize {
        let inline_data_len = self.inner.read().inode_on_disk.size_lo as usize;
        assert!(inline_data_len <= 60, "inline data too large");
        let copy_len = (buf.len()).min(inline_data_len - offset);
        buf[..copy_len]
            .copy_from_slice(&self.inner.read().inode_on_disk.block[offset..offset + copy_len]);
        copy_len
    }
    // 注意Fast link, 当文件名可以直接放在inode.block字段中时就不用再申请数据块, 没有设置has_inline_data flag
    pub fn read_link(&self) -> Result<String, &'static str> {
        if self.inner.read().inode_on_disk.is_symlink() {
            if let Some(link) = &*self.link.read() {
                return Ok(link.clone());
            }
            let mut link = String::new();
            let inode_size = self.inner.read().inode_on_disk.size_lo as usize;
            let mut buf = vec![0u8; inode_size];
            // self.read(0, &mut buf)?;
            if inode_size <= EXT4_MAX_INLINE_DATA {
                self.read_inline_data(0, &mut buf);
                log::error!(
                    "[Ext4Inode::read_link]: inline data: {:?}",
                    String::from_utf8_lossy(&buf)
                );
            } else {
                self.read(0, &mut buf)?;
            }
            for &c in buf.iter() {
                if c == 0 {
                    break;
                }
                link.push(c as char);
            }
            self.link.write().replace(link.clone());
            Ok(link)
        } else {
            Err("not a symlink")
        }
    }
    pub fn write_extent_tree(&self, offset: usize, buf: &[u8]) -> usize {
        // 需要写回的总长度
        let wbuf_len = buf.len();
        // 先读取页缓存
        let mut current_write = 0;
        let mut page_offset = offset >> PAGE_SIZE_BITS;
        let mut page_offset_in_page = offset & (PAGE_SIZE - 1);

        let mut current_extent: Option<Ext4Extent> = None;
        let mut page: Arc<Page>;
        let mut fs_block_id: usize;

        while current_write < wbuf_len {
            if let Some(page_cache) = self.address_space.get_page_cache(page_offset) {
                // 页缓存命中
                page = page_cache;
            } else {
                // 页缓存未命中, 看是否在查到的PhysicalBlockRange中
                if let Some(extent) = &current_extent {
                    if (extent.logical_block + extent.len as u32) as usize > page_offset {
                        // 命中extent读取, 知道对应的物理块号
                        fs_block_id = extent.physical_start_block() + page_offset
                            - extent.logical_block as usize;
                    } else {
                        // 未命中, 从inode中读取extent
                        let extent = self.lookup_or_create_extent(
                            page_offset as u32,
                            self.block_device.clone(),
                            self.ext4_fs.upgrade().unwrap().block_size(),
                        );
                        fs_block_id = extent.physical_start_block() + page_offset
                            - extent.logical_block as usize;
                        current_extent = Some(extent);
                    }
                } else {
                    // 未命中, 从inode中读取extent
                    let extent = self.lookup_or_create_extent(
                        page_offset as u32,
                        self.block_device.clone(),
                        self.ext4_fs.upgrade().unwrap().block_size(),
                    );
                    fs_block_id =
                        extent.physical_start_block() + page_offset - extent.logical_block as usize;
                    current_extent = Some(extent);
                }
                page = self.address_space.new_page_cache(
                    page_offset,
                    fs_block_id,
                    self.block_device.clone(),
                    self.self_weak.clone(),
                );
            }
            let copy_len = (wbuf_len - current_write).min(PAGE_SIZE - page_offset_in_page);
            page.modify(0, |data: &mut [u8; PAGE_SIZE]| {
                data[page_offset_in_page..page_offset_in_page + copy_len]
                    .copy_from_slice(&buf[current_write..current_write + copy_len]);
            });
            current_write += copy_len;
            page_offset += 1;
            page_offset_in_page = 0;
        }
        // 如果新写入的数据导致文件增长, 更新inode的size
        let end_offset = offset + current_write;
        let inode_size = self.get_size() as usize;
        if end_offset > inode_size {
            self.set_size(end_offset as u64);
        }

        current_write
    }
    // pub fn lookup_or_create_extent(
    //     &self,
    //     logical_start_block: u32,
    //     block_device: Arc<dyn BlockDevice>,
    //     ext4_block_size: usize,
    // ) -> Ext4Extent {
    //     match self.inner.write().inode_on_disk.lookup_extent(
    //         logical_start_block,
    //         block_device.clone(),
    //         ext4_block_size,
    //     ) {
    //         Some(extent) => extent,
    //         None => {
    //             // 创建新的extent
    //             let new_block_num = self.alloc_block();
    //             let new_extent = Ext4Extent::new(logical_start_block, 1, new_block_num);
    //             self.inner
    //                 .write()
    //                 .inode_on_disk
    //                 .insert_extent(
    //                     logical_start_block,
    //                     new_extent.physical_start_block() as u64,
    //                     1,
    //                     block_device,
    //                     ext4_block_size,
    //                 )
    //                 .unwrap();
    //             new_extent
    //         }
    //     }
    // }

    // 可能会更新inode的内容
    /// 如果extent没有找到, 会创建新的extent
    pub fn lookup_or_create_extent(
        &self,
        logical_start_block: u32,
        block_device: Arc<dyn BlockDevice>,
        ext4_block_size: usize,
    ) -> Ext4Extent {
        let mut inner = self.inner.write();

        if let Some(extent) = inner.inode_on_disk.lookup_extent(
            logical_start_block,
            block_device.clone(),
            ext4_block_size,
        ) {
            extent
        } else {
            let new_block_num = self.alloc_block();
            let new_extent = Ext4Extent::new(logical_start_block, 1, new_block_num);

            inner
                .inode_on_disk
                .insert_extent(
                    logical_start_block,
                    new_extent.physical_start_block() as u64,
                    1,
                    block_device,
                    ext4_block_size,
                )
                .unwrap();

            new_extent
        }
    }

    pub fn write(&self, offset: usize, buf: &[u8]) -> usize {
        let wbuf_len = buf.len();

        // 1. 如果写入后文件大小小于60字节, 且写入的是前60字节, 先写入inline data page
        if offset + wbuf_len <= 60 {
            // Todo
            // let start = offset;
            // let end = offset + wbuf_len;
            // inode_on_disk.block[start..end].copy_from_slice(&buf[..(end - start)]);
            // inode_on_disk.set_size(offset as u64 + wbuf_len as u64);
            // inode_on_disk.set_inline_data_flag();
            // drop(inode_guard);
            // // inode写回block_cache
            // modify_inode(self, self.block_device.clone());
            // return wbuf_len;
            let start = offset;
            let end = offset + wbuf_len;
            let page = self.get_page_cache(0).unwrap();
            page.modify(0, |data: &mut [u8; PAGE_SIZE]| {
                data[start..end].copy_from_slice(&buf[..wbuf_len]);
            });
            self.inner
                .write()
                .inode_on_disk
                .set_size(offset as u64 + wbuf_len as u64);
            return wbuf_len;
        }

        let inode_guard = self.inner.read();
        let inode_on_disk = &inode_guard.inode_on_disk;
        let inode_size_before = self.inner.read().inode_on_disk.get_size();
        // 2. 若写入后文件大小超过60字节, 转换为extent tree
        // 同样会调用write_extent_tree, 但是如果size > 0, 说明有inline_data, 会先将inline_data写入新的block
        if inode_size_before <= 60 {
            // 申请新的block
            let new_block = self.alloc_block();
            // 写入inline_data内容到新的block
            // 注意这里应该写入页缓存(在页缓存drop时写回), 而不是直接写入block_cache
            if inode_size_before > 0 {
                let page = self.get_page_cache(0).unwrap();
                // 复制原来的inline_data, 同时写入新的block
                page.modify(0, |data: &mut [u8; PAGE_SIZE]| {
                    data[0..EXT4_MAX_INLINE_DATA]
                        .copy_from_slice(&inode_on_disk.block[..EXT4_MAX_INLINE_DATA]);
                });
            }
            drop(inode_guard);
            let mut inode_guard = self.inner.write();
            let inode_on_disk = &mut inode_guard.inode_on_disk;
            // 清除原来的inline_data flag, 设置新的extent tree flag
            inode_on_disk.flags &= !EXT4_INLINE_DATA_FL;
            inode_on_disk.flags |= EXT4_EXTENTS_FL;
            // 创建新的extent
            let new_extent = Ext4Extent::new(0, 1, new_block);
            // 初始化extent tree, extent_header + extent
            let header_ptr = inode_on_disk.block.as_mut_ptr() as *mut Ext4ExtentHeader;
            unsafe {
                let mut extent_header = Ext4ExtentHeader::default();
                extent_header.entries = 1;
                header_ptr.write_volatile(extent_header);
                let extent_ptr = inode_on_disk.block.as_mut_ptr().add(12) as *mut Ext4Extent;
                extent_ptr.write(new_extent);
            }
        }
        // 3. 使用extent tree写入
        self.write_extent_tree(offset, buf)
    }
    /// 只读取磁盘上的目录项, 不会加载Inode进入内存
    /// 上层调用者应优先使用DentryCache, 只有未命中时才调用
    pub fn lookup(&self, name: &str) -> Option<Ext4DirEntry> {
        log::info!("[Ext4Inode::lookup] name: {}", name);
        debug_assert!(self.inner.read().inode_on_disk.is_dir(), "not a directory");
        let dir_size = self.inner.read().inode_on_disk.get_size();
        assert!(
            dir_size & (PAGE_SIZE as u64 - 1) == 0,
            "dir_size is not page aligned"
        );
        let mut buf = vec![0u8; dir_size as usize];
        // buf中是目录的所有内容
        self.read(0, &mut buf).expect("read failed");
        let dir_content = Ext4DirContentRO::new(&buf);
        dir_content.find(name)
    }
    // 注意: 这里没有检查目录项是否存在(inode_num != 0), 由上层调用者检查
    pub fn getdents(&self, offset: usize) -> Vec<Ext4DirEntry> {
        assert!(self.inner.read().inode_on_disk.is_dir(), "not a directory");
        let dir_size = self.inner.read().inode_on_disk.get_size();
        assert!(
            dir_size & (PAGE_SIZE as u64 - 1) == 0,
            "dir_size is not page aligned"
        );
        let mut buf = vec![0u8; (dir_size as usize - offset) as usize];
        // buf中是目录的所有内容
        self.read(offset, &mut buf).expect("read failed");
        let dir_content = Ext4DirContentRO::new(&buf);
        dir_content.getdents()
    }
    // Todo: result mask要设置
    pub fn getattr(&self) -> Kstat {
        let mut kstat = Kstat::new();
        let inner_guard = self.inner.read();
        let inode_on_disk = &inner_guard.inode_on_disk;
        kstat.ino = self.inode_num as u64;
        kstat.dev = self.block_device.get_id() as u64;
        kstat.rdev = 0; // 通常特殊文件才会有 rdev

        kstat.mode = inode_on_disk.mode;
        kstat.uid = inode_on_disk.uid as u32;
        kstat.gid = inode_on_disk.gid as u32;
        kstat.nlink = inode_on_disk.links_count as u32;
        kstat.size = inode_on_disk.get_size();

        // Todo: 目前没有更新时间戳
        kstat.atime = self.get_atime();
        kstat.mtime = self.get_mtime();
        kstat.ctime = self.get_ctime();
        kstat.btime = TimeSpec {
            sec: inode_on_disk.create_time as usize,
            nsec: (inode_on_disk.create_time_extra >> 2) as usize,
        };

        kstat.blksize = self.get_block_size() as u32;
        // 处理文件属性标志, unimplemented
        if inode_on_disk.flags & EXT4_APPEND_FL != 0 {
            kstat.attributes |= STATX_ATTR_APPEND;
        }
        // Todo: Direct I/O 对齐参数
        // inode版本号
        kstat.change_cookie = inode_on_disk.generation as u64;

        kstat
    }
    // 检查是否是目录, 且有目录项可以lookup
    pub fn can_lookup(&self) -> bool {
        self.inner.read().inode_on_disk.is_dir() && self.inner.read().inode_on_disk.get_size() > 0
    }
}

// 设计修改inode内容的方法
// 注意对于修改inode的文件内容, 一定要通过`write`方法
// 对于修改inode的元信息的, 一定要由上层调用者通过`write_inode`写回block_cache
// Todo: 更新inode的时间戳
impl Ext4Inode {
    pub fn set_entry(&self, old_name: &str, new_inode_num: u32, new_file_type: u8) {
        assert!(self.inner.read().inode_on_disk.is_dir(), "not a directory");
        log::info!(
            "[Ext4Inode::set_entry] old_name: {}, new_inode_num: {}, new_file_type: {}",
            old_name,
            new_inode_num,
            new_file_type
        );
        let dir_size = self.inner.read().inode_on_disk.get_size();
        assert!(
            dir_size & (PAGE_SIZE as u64 - 1) == 0,
            "dir_size is not page aligned"
        );
        let mut buf = vec![0u8; dir_size as usize];
        // buf中是目录的所有内容
        self.read(0, &mut buf).expect("read failed");
        let mut dir_content = Ext4DirContentWE::new(&mut buf);
        // 更新目录内容, 以及可能目录会扩容, inode_on_disk的size会更新
        dir_content
            .set_entry(old_name, new_inode_num, new_file_type)
            .expect("Ext4Inode::set_dentry failed");
        // 写回page cache
        self.write(0, &buf);
    }
    /// 目录项的插入
    ///     1. 注意可能使用inline_data
    /// Todo: 1. 目前没有考虑目录扩容的情况
    pub fn add_entry(&self, dentry: Arc<Dentry>, inode_num: u32, file_type: u8) {
        assert!(self.inner.read().inode_on_disk.is_dir(), "not a directory");
        log::info!(
            "[Ext4Inode::add_entry] name: {}, inode_num: {}, file_type: {}",
            dentry.get_last_name(),
            inode_num,
            file_type
        );
        let dir_size = self.inner.read().inode_on_disk.get_size();
        assert!(
            dir_size & (PAGE_SIZE as u64 - 1) == 0,
            "dir_size is not page aligned"
        );
        let mut buf = vec![0u8; dir_size as usize];
        // buf中是目录的所有内容
        self.read(0, &mut buf).expect("read failed");
        let mut dir_content = Ext4DirContentWE::new(&mut buf);
        // 更新目录内容, 以及可能目录会扩容, inode_on_disk的size会更新
        dir_content
            .add_entry(&dentry.get_last_name(), inode_num, file_type)
            .expect("Ext4Inode::add_entry failed");
        // 写回page cache
        // Todo: 没有处理目录多页的情况
        self.write(0, &buf);
    }
    pub fn delete_entry(&self, name: &str, inode_num: u32) {
        assert!(self.inner.read().inode_on_disk.is_dir(), "not a directory");
        log::info!("[Ext4Inode::delete_entry] name: {}", name);
        let dir_size = self.inner.read().inode_on_disk.get_size();
        assert!(
            dir_size & (PAGE_SIZE as u64 - 1) == 0,
            "dir_size is not page aligned"
        );
        let mut buf = vec![0u8; dir_size as usize];
        // buf中是目录的所有内容
        self.read(0, &mut buf).expect("read failed");
        let mut dir_content = Ext4DirContentWE::new(&mut buf);
        // 更新目录内容, 以及可能目录会扩容, inode_on_disk的size会更新
        dir_content
            .delete_entry(name, inode_num)
            .expect("Ext4Inode::delete_entry failed");
        // 写回page cache
        // Todo: 没有处理目录多页的情况
        self.write(0, &buf);
    }
    pub fn insert_extent(
        &self,
        logical_block_num: u32,
        physical_block_num: u64,
        blocks_count: u32,
        block_device: Arc<dyn BlockDevice>,
        ext4_block_size: usize,
    ) -> Result<(), &'static str> {
        self.inner.write().inode_on_disk.insert_extent(
            logical_block_num,
            physical_block_num,
            blocks_count,
            block_device,
            ext4_block_size,
        )
    }
    pub fn alloc_block(&self) -> usize {
        self.ext4_fs
            .upgrade()
            .unwrap()
            .alloc_block(self.block_device.clone())
    }
    /// 根据inode_num计算fs_block_id和inner_offset
    pub fn ino_2_blockid_and_offset(&self) -> (usize, usize) {
        let ext4_fs = self.ext4_fs.upgrade().unwrap();
        let inodes_per_group = ext4_fs.super_block.inodes_per_group as usize;
        let bg = (self.inode_num - 1) / inodes_per_group;
        let index = (self.inode_num - 1) % inodes_per_group;
        let inode_table_block_id = ext4_fs.block_groups[bg].inode_table() as usize;
        let outer_offset = index * ext4_fs.super_block.inode_size as usize
            / ext4_fs.super_block.block_size as usize;
        let inner_offset = index * ext4_fs.super_block.inode_size as usize
            % ext4_fs.super_block.block_size as usize;
        let fs_block_id = inode_table_block_id + outer_offset;
        (fs_block_id, inner_offset)
    }
}

// set/get系列方法, 判断标志, 辅助函数
impl Ext4Inode {
    pub fn get_nlinks(&self) -> u16 {
        self.inner.read().inode_on_disk.get_nlinks()
    }
    pub fn add_nlinks(&self) {
        self.inner.write().inode_on_disk.add_nlinks();
    }
    pub fn sub_nlinks(&self) {
        self.inner.write().inode_on_disk.sub_nlinks();
    }
    pub fn get_size(&self) -> u64 {
        self.inner.read().inode_on_disk.get_size()
    }
    pub fn set_size(&self, size: u64) {
        self.inner.write().inode_on_disk.set_size(size);
    }
    pub fn set_mode(&self, mode: u16) {
        self.inner.write().inode_on_disk.mode = mode;
    }
    pub fn set_flags(&self, flags: u32) {
        self.inner.write().inode_on_disk.flags = flags;
    }
    pub fn get_block_size(&self) -> usize {
        self.ext4_fs.upgrade().unwrap().super_block.block_size as usize
    }
    pub fn has_inline_data(&self) -> bool {
        self.inner.read().inode_on_disk.has_inline_data()
    }
    pub fn is_symlink(&self) -> bool {
        self.inner.read().inode_on_disk.is_symlink()
    }
    pub fn is_dir(&self) -> bool {
        self.inner.read().inode_on_disk.is_dir()
    }
}

// Todo: 支持inode_cache
// 上层调用者应保证: 1. inode_num是有效的 2. inode_num对应的inode未加载
pub fn load_inode(
    inode_num: usize,
    block_device: Arc<dyn BlockDevice>,
    ext4_fs: Arc<Ext4FileSystem>,
) -> Arc<Ext4Inode> {
    let inodes_per_group = ext4_fs.super_block.inodes_per_group as usize;
    let bg = (inode_num - 1) / inodes_per_group;
    let index = (inode_num - 1) % inodes_per_group;
    let inode_table_block_id = ext4_fs.block_groups[bg].inode_table() as usize;
    // 注意: inode_table的size = inodes_per_group * inode_size, 一般不只一块
    let outer_offset =
        index * ext4_fs.super_block.inode_size as usize / ext4_fs.super_block.block_size as usize;
    let inner_offset =
        index * ext4_fs.super_block.inode_size as usize % ext4_fs.super_block.block_size as usize;
    let fs_block_id = inode_table_block_id + outer_offset;
    // 计算偏移, 读取inode
    let inode_on_disk = get_block_cache(
        fs_block_id,
        block_device.clone(),
        ext4_fs.super_block.block_size as usize,
    )
    .lock()
    .read(inner_offset, |inode: &Ext4InodeDisk| inode.clone());
    log::warn!(
        "[load_inode] inode_num: {}, size: {}, mode: {}",
        inode_num,
        inode_on_disk.get_size(),
        inode_on_disk.mode
    );
    Arc::new_cyclic(|weak| Ext4Inode {
        ext4_fs: Arc::downgrade(&ext4_fs),
        block_device,
        address_space: AddressSpace::new(),
        inode_num,
        link: RwLock::new(None),
        inner: FSMutex::new(Ext4InodeInner::new(inode_on_disk)),
        self_weak: weak.clone(),
    })
}

// 将inode写回到block_cache
pub fn modify_inode(inode: &Ext4Inode, block_device: Arc<dyn BlockDevice>) {
    let ext4_fs = inode.ext4_fs.upgrade().unwrap();
    let inode_num = inode.inode_num;
    let inodes_per_group = ext4_fs.super_block.inodes_per_group as usize;
    let bg = (inode_num - 1) / inodes_per_group;
    let index = (inode_num - 1) % inodes_per_group;
    let inode_table_block_id = ext4_fs.block_groups[bg].inode_table() as usize;
    let outer_offset =
        index * ext4_fs.super_block.inode_size as usize / ext4_fs.super_block.block_size as usize;
    let inner_offset =
        index * ext4_fs.super_block.inode_size as usize % ext4_fs.super_block.block_size as usize;
    let inode_on_disk = &inode.inner.read().inode_on_disk;
    get_block_cache(
        inode_table_block_id + outer_offset,
        block_device.clone(),
        ext4_fs.super_block.block_size as usize,
    )
    .lock()
    .modify(inner_offset, |inode_disk: &mut Ext4InodeDisk| {
        *inode_disk = *inode_on_disk
    });
}

/// 将新建的inode写回到block_cache
/// 注意对于inode的修改, 不调用这个函数
pub fn write_inode(inode: &Arc<Ext4Inode>, inode_num: usize, block_device: Arc<dyn BlockDevice>) {
    log::warn!(
        "[write_inode] inode_num: {}, size: {}",
        inode_num,
        inode.inner.read().inode_on_disk.get_size()
    );
    let ext4_fs = inode.ext4_fs.upgrade().unwrap();
    let inodes_per_group = ext4_fs.super_block.inodes_per_group as usize;
    let bg = (inode_num - 1) / inodes_per_group;
    let index = (inode_num - 1) % inodes_per_group;
    let inode_table_block_id = ext4_fs.block_groups[bg].inode_table() as usize;
    let outer_offset =
        index * ext4_fs.super_block.inode_size as usize / ext4_fs.super_block.block_size as usize;
    let inner_offset =
        index * ext4_fs.super_block.inode_size as usize % ext4_fs.super_block.block_size as usize;
    let inode_on_disk = &inode.inner.read().inode_on_disk.clone();
    get_block_cache(
        inode_table_block_id + outer_offset,
        block_device.clone(),
        ext4_fs.super_block.block_size as usize,
    )
    .lock()
    .modify(inner_offset, |inode_disk: &mut Ext4InodeDisk| {
        *inode_disk = *inode_on_disk
    });
}

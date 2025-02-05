use core::fmt::Debug;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{
    drivers::block::{
        self,
        block_cache::{self, BlockCache},
    },
    fs::{super_block::FileSystemOp, FSMutex},
    mutex::SpinNoIrqLock,
};

use super::{block_group, inode::Ext4Inode};

pub struct Ext4SuperBlock {
    /* 基本信息 */
    pub inodes_count: u32,             // inode总数
    pub blocks_count_lo: u32,          // block总数(低32位)
    pub reserved_blocks_count_lo: u32, // 保留的block总数(低32位)
    pub first_data_block: u32,         // 第一个数据block的编号(总为1)
    pub block_size: u32,               // block大小(bytes)
    pub cluster_size: u32,             // cluster大小(多少个block)
    /* 块组信息 */
    pub blocks_per_group: u32,   // 每个块组的block数
    pub clusters_per_group: u32, // 每个块组的cluster数
    pub inodes_per_group: u32,   // 每个块组的inode数

    // rev_level为1时, 以下字段有效
    pub inode_size: u16, // inode的大小

    // 推理出的字段
    pub block_group_count: u32, // 块组总数

    // 孤立的inode列表
    pub orphan_inodes: SpinNoIrqLock<Vec<usize>>,

    pub inner: FSMutex<SuperBlockInner>,
}

// 用于存储会发生变化的数据
pub struct SuperBlockInner {
    pub free_inodes_count: u32, // 空闲的inode总数
    pub free_blocks_count: u64, // 空闲的block总数(低32位 + 高32位)
}

impl SuperBlockInner {}

impl SuperBlockInner {
    pub fn new(free_inodes_count: u32, free_blocks_count: u64) -> Self {
        Self {
            free_inodes_count,
            free_blocks_count,
        }
    }
}

impl Ext4SuperBlock {
    pub fn new(
        super_block: &Ext4SuperBlockDisk,
        block_cache: Arc<SpinNoIrqLock<BlockCache>>,
    ) -> Self {
        let block_group_count = (super_block.blocks_count_lo + super_block.blocks_per_group - 1)
            / super_block.blocks_per_group;
        Self {
            inodes_count: super_block.inodes_count,
            blocks_count_lo: super_block.blocks_count_lo,
            reserved_blocks_count_lo: super_block.reserved_blocks_count_lo,
            first_data_block: super_block.first_data_block,
            block_size: 1024 << super_block.log_block_size,
            cluster_size: 1 << super_block.log_cluster_size,
            blocks_per_group: super_block.blocks_per_group,
            clusters_per_group: super_block.clusters_per_group,
            inodes_per_group: super_block.inodes_per_group,
            inode_size: super_block.inode_size,
            block_group_count,
            orphan_inodes: SpinNoIrqLock::new(Vec::new()),
            inner: FSMutex::new(SuperBlockInner::new(
                super_block.free_inodes_count,
                super_block.free_blocks_count(),
            )),
        }
    }
}

impl Debug for Ext4SuperBlockDisk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ext4SuperBlockDisk")
            .field("inodes_per_group", &self.inodes_per_group)
            .field("blocks_per_group", &self.blocks_per_group)
            .field("free_blocks_count", &self.free_blocks_count())
            .finish()
    }
}

#[repr(C)]
/// Ext4SuperBlock是用来操作底层磁盘上的super_block的, 位置偏移是对应的
/// Ext4Meta是在os中使用的, 是Ext4的核心元数据
pub struct Ext4SuperBlockDisk {
    /* 基本信息 */
    pub inodes_count: u32,         // inode总数
    pub blocks_count_lo: u32,      // block总数(低32位)
    reserved_blocks_count_lo: u32, // 保留的block总数(低32位)
    free_blocks_count_lo: u32,     // 空闲的block总数(低32位)
    /* 10 */
    free_inodes_count: u32, // 空闲的inode总数
    first_data_block: u32,  // 第一个数据block的编号(总为1)
    log_block_size: u32, // 块大小, 2的幂次方表示, 1024 << log_block_size, 0表示1024, 1表示2048, 2表示4096字节
    log_cluster_size: u32, // 簇大小, 1 << log_cluster_size个block

    /* 块组信息 */
    /* 20 */
    blocks_per_group: u32,   // 每个块组的block数
    clusters_per_group: u32, // 每个块组的cluster数
    inodes_per_group: u32,   // 每个块组的inode数
    /* 时间和状态信息 */
    mount_time: u32, // 最后一次挂载时间
    /* 30 */
    write_time: u32,      // 最后一次写入时间
    mnt_count: u16,       // 已挂载计数
    max_mnt_count: u16,   // 允许的最大挂载计数, 达到这个值后需要进行`fsck`检查
    pub magic: u16,       // 魔数, 用于识别是否为EXT文件系统, EXT4的值为`0xEF53`
    pub state: u16, // 文件系统的状态, EXT4_VALID_FS(0x0001)表示文件系统正常, EXT4_ERROR_FS(0x0002)表示文件系统有错误, EXT$_ORPHAN_FS(0x0004)表示有孤立的inode
    errors: u16, // 错误处理方式, EXT4_ERRORS_CONTINUE(1)表示遇到错误后继续, EXT4_ERRORS_RO(2)表示遇到错误后只读, EXT4_ERRORS_PANIC(3)表示遇到错误后系统panic
    minor_rev_level: u16, // 次要版本号
    /* 40 */
    lastcheck: u32,     // 最后一次检查(运行`fsck`)时间
    checkinterval: u32, // 两次检查之间的最大间隔时间

    creator_os: u32, // 创建文件系统的操作系统
    rev_level: u32, // 版本号, 0 Original format, 1 v2 format w/ dynamic inode sizes, 2 v3 format w/ dynamic inode sizes
    /* 50 */
    def_reserved_uid: u16, // 保留块的默认用户ID
    def_reserved_gid: u16, // 保留块的默认组ID
    /*
     * 以下字段仅使用与`EXT4_DYNAMIC_REV`超级块
     * Note: the difference between the compatible feature set and
     * the incompatible feature set is that if there is a bit set
     * in the incompatible feature set that the kernel doesn't
     * know about, it should refuse to mount the filesystem.
     *
     * e2fsck's requirements are more strict; if it doesn't know
     * about a feature in either the compatible or incompatible
     * feature set, it must abort and not try to meddle with
     * things it doesn't understand...
     */
    first_nonres_ino: u32, // 第一个非保留inode的编号
    pub inode_size: u16,   // inode的大小
    block_group_nr: u16,   // 本块组的编号
    feature_compat: u32,   // 兼容特性集
    /*  60  */
    feature_incompat: u32,  // 不兼容特性集
    feature_ro_compat: u32, // 只读兼容特性集
    /* 68 */
    uuid: [u8; 16], // 文件系统的唯一标识符
    /* 78 */
    volume_name: [u8; 16], // 卷名
    /* 88 */
    last_mounted: [u8; 64], // 最后一次挂载的路径
    /* C8 */
    algorithm_usage_bitmap: u32, // 用于压缩的算法位图
    /* Perfomanance hints. Directory preallocation should only happen if the
     * EXT4_FEATURE_COMPAT_DIR_PREALLOC flag is on.
     */
    prealloc_blocks: u8,      // 预分配的block数
    prealloc_dir_blocks: u8,  // 预分配的目录block数
    reserved_gdt_blocks: u16, // online growth时保留的GDT块数
    /* Journaling support valid if EXT4_FEATURE_COMPAT_HAS_JOURNAL set */
    /* D0 */
    journal_uuid: [u8; 16], // 日志文件的唯一标识符
    journal_inum: u32,      // 日志文件的inode编号
    journal_dev: u32,       // 日志文件所在的设备号
    last_orphan: u32,       // 待删除节点的链表头
    hash_seed: [u32; 4],    // HTREE hash seed
    def_hash_version: u8,   // 默认的HTREE hash版本
    jnl_backup_type: u8,    // 日志备份类型
    pub desc_size: u16,     // 组描述符大小
    /* 100 */
    default_mount_opts: u32, // 默认挂载选项
    first_meta_bg: u32,      // 第一个元数据块组
    mkfs_time: u32,          // 创建文件系统的时间
    jnl_blocks: [u32; 17],   // 日志文件的备份
    /* 以下字段需设置EXT4_FEATURE_CPMPAT_64BIT, 表示支持64位 */
    /* 150 */
    block_count_hi: u32,           // block总数(高32位)
    reserved_blocks_count_hi: u32, // 保留的block总数(高32位)
    free_blocks_count_hi: u32,     // 空闲的block总数(高32位)
    min_extra_isize: u16,          // 所有inode节点至少有的bytes数
    want_extra_isize: u16,         // 新建inode节点时应保留的bytes数
    /* 160 */
    flags: u32,               // 杂项标志
    raid_stride: u16,         // RAID步长
    mmp_update_interval: u16, // MMP检查的等待秒速
    mmp_block: u64,           // 多重挂载保护块
    /* 170 */
    raid_stripe_width: u32,  // 多有数据磁盘上的块数(N * stride)
    log_groups_per_flex: u8, // FLEX_BG组的大小
    checksum_type: u8,       // 校验和算法类型
    encryption_level: u8,    // 加密算法
    reserved_pad: u8,        // 保留字段
    kbytes_written: u64,     // 文件系统写入的KB数
    /* 180 */
    snapshot_inum: u32,           // active snapshot inode编号
    snapshot_id: u32,             // active snapshot 顺序id
    snapshot_r_blocks_count: u64, // 为活动快照的未来使用保留的块数
    /* 190 */
    snapshot_list: u32, // 磁盘上快照列表的头节点号
    // #define EXT4_S_ERR_START offsetof(struct ext4_super_block, error_count)
    error_count: u32,           // 未修复的错误数
    first_error_time: u32,      // 第一个错误时间
    first_error_ino: u32,       // 第一个错误inode
    first_error_block: u64,     // 第一个错误block
    first_error_func: [u8; 32], // 第一个错误函数
    first_error_line: u32,      // 第一个错误行号
    last_error_time: u32,       // 最后一个错误时间
    last_error_ino: u32,        // 最后一个错误inode
    last_error_line: u32,       // 最后一个错误行号
    last_error_block: u64,      // 最后一个错误block
    last_error_func: [u8; 32],  // 最后一个错误函数
    // #define EXT4_S_ERR_END offsetof(struct ext4_super_block, mount_opts)
    mount_opts: [u8; 64],      // 挂载选项
    usr_quota_inum: u32,       // 用于跟踪用户配额的inode
    grp_quota_inum: u32,       // 用于跟踪组配额inode
    overhead_blocks: u32,      // 文件系统中的开销块/簇
    backup_bgs: [u32; 2],      // 有sparse_super2超级块的组
    encrypt_algos: [u8; 4],    // 加密算法
    encrypt_pw_salt: [u8; 16], //用于string2key算法的salt
    lpf_ino: u32,              // lost+found inode位置
    prj_quota_inum: u32,       // 用于跟踪项目配额的inode
    checksum_seed: u32,        // crc32c(uuid) if csum_seed set
    wirte_time_hi: u8,         // 最后一次写入时间(高8位)
    mount_time_hi: u8,         // 最后一次修改时间(高8位)
    mkfs_time_hi: u8,          // 创建文件系统时间(高8位)
    lastcheck_hi: u8,          // 最后一次检查时间(高8位)
    first_error_time_hi: u8,   // 第一个错误时间(高8位)
    last_error_time_hi: u8,    // 最后一个错误时间(高8位)
    first_error_errcode: u8,   // 第一个错误代码
    last_error_errcode: u8,    // 最后一个错误代码
    encoding: u16,             // 文件名编码
    encoding_flags: u16,       // 文件名编码标志
    orphan_file_ino: u32,      // orphan文件的inode
    reserved: [u32; 94],       // 保留字段
    checksum: u32,             // crc32c(superblock)
}

const EXT4_VALID_FS: u16 = 1;

impl Ext4SuperBlockDisk {
    pub fn is_valid(&self) -> bool {
        // ext4 magic number: 0xEF53
        // Todo: 根据校验和, 检查superblock是否有效
        // 通过raw_pointer的方式, 读取self.state的值
        let raw_pointer = self as *const Self;
        let state = unsafe { (*raw_pointer).state };
        let magic = unsafe { (*raw_pointer).magic };
        log::error!("state: {:x}, magic: {:x}", state, magic);

        self.magic == 0xEF53 && self.state == EXT4_VALID_FS
    }
    // 单位为字节
    pub fn block_size(&self) -> usize {
        1024 << self.log_block_size
    }
    // 单位为块
    pub fn cluster_size(&self) -> usize {
        1 << self.log_cluster_size
    }
    pub fn block_group_count(&self) -> usize {
        (((self.blocks_count_lo as u64 | ((self.block_count_hi as u64) << 32))
            + self.blocks_per_group as u64
            - 1)
            / self.blocks_per_group as u64) as usize
    }
    pub fn free_blocks_count(&self) -> u64 {
        self.free_blocks_count_lo as u64 | ((self.free_blocks_count_hi as u64) << 32)
    }
}

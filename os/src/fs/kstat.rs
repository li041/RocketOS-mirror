use crate::timer::StatxTimeStamp;
use crate::timer::TimeSpec;

use bitflags::bitflags;

bitflags! {
    /// `stx_mask` 的标志位（bitmask），用于 `statx()` 请求和返回的字段掩码
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
    pub struct StatxMask: u32 {
        /// 需要/获取 `stx_mode`（文件类型）
        const TYPE = 0x00000001;
        /// 需要/获取 `stx_mode`（权限）
        const MODE = 0x00000002;
        /// 需要/获取 `stx_nlink`（硬链接数）
        const NLINK = 0x00000004;
        /// 需要/获取 `stx_uid`（所有者用户 ID）
        const UID = 0x00000008;
        /// 需要/获取 `stx_gid`（所有者组 ID）
        const GID = 0x00000010;
        /// 需要/获取 `stx_atime`（最后访问时间）
        const ATIME = 0x00000020;
        /// 需要/获取 `stx_mtime`（最后修改时间）
        const MTIME = 0x00000040;
        /// 需要/获取 `stx_ctime`（最后状态更改时间）
        const CTIME = 0x00000080;
        /// 需要/获取 `stx_ino`（inode 号）
        const INO = 0x00000100;
        /// 需要/获取 `stx_size`（文件大小，单位：字节）
        const SIZE = 0x00000200;
        /// 需要/获取 `stx_blocks`（分配的 512B 块数）
        const BLOCKS = 0x00000400;
        /// 获取 `stat` 结构体中常规的基本字段
        const BASIC_STATS = 0x000007ff;
        /// 需要/获取 `stx_btime`（文件创建时间）
        const BTIME = 0x00000800;
        /// 需要/获取 `stx_mnt_id`（挂载 ID）
        const MNT_ID = 0x00001000;
        /// 需要/获取 `stx_dio_mem_align` 和 `stx_dio_offset_align`（直接 I/O 对齐信息）
        const DIOALIGN = 0x00002000;
        /// 需要/获取 `stx_mnt_id`（扩展的唯一挂载 ID）
        const MNT_ID_UNIQUE = 0x00004000;
        /// 需要/获取 `stx_subvol`（子卷 ID）
        const SUBVOL = 0x00008000;
        /// 预留给未来扩展 `statx` 结构体使用
        const RESERVED = 0x80000000;
    }
}

impl StatxMask {
    /// 获取 `statx` 结构体中常规的基本字段
    pub fn basic_stats() -> Self {
        Self::BASIC_STATS
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct Kstat {
    pub result_mask: StatxMask, // 指示哪些字段被填充
    pub mode: u16,              // 文件权限和类型，如 S_IFREG, S_IFDIR
    pub nlink: u32,             // 硬链接数
    pub blksize: u32,           // I/O 块大小
    pub attributes: u64,        // File attributes
    pub attributes_mask: u64,   // Supported attributes mask
    pub ino: u64,               // inode号(inode->i_ino)
    pub dev: u64,               // 设备号(inode->i_sb->s_dev)
    pub rdev: u64,              // Device ID (if special file)
    pub uid: u32,               // Owner User ID of the file
    pub gid: u32,               // Owner Group ID of the file
    pub size: u64,              // File size (bytes)
    pub atime: TimeSpec,        // Last access time
    pub mtime: TimeSpec,        // Last modification time
    pub ctime: TimeSpec,        // Last status change time
    pub btime: TimeSpec,        // Creation time
    pub blocks: u64,            // Number of 512B blocks allocated(inode->i_blocks)
    pub mnt_id: u64,            // Mount ID
    pub dio_mem_align: u32,     // DIO memory alignment
    pub dio_offset_align: u32,  // DIO offset alignment
    pub change_cookie: u64,     // inode版本号
    pub subvol: u64,            // 子卷ID
}
impl Kstat {
    pub fn new() -> Self {
        Self {
            result_mask: StatxMask::basic_stats(),
            ..Default::default()
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub __pad: u64,
    pub st_size: u64,
    pub st_blksize: u32,
    pub __pad2: u32,
    pub st_blocks: u64,
    pub st_atime: TimeSpec,
    pub st_mtime: TimeSpec,
    pub st_ctime: TimeSpec,
    pub unused: u64,
}

impl From<Kstat> for Stat {
    fn from(kstat: Kstat) -> Self {
        Self {
            st_dev: kstat.dev,
            st_ino: kstat.ino,
            st_mode: kstat.mode as u32,
            st_nlink: kstat.nlink,
            st_uid: kstat.uid,
            st_gid: kstat.gid,
            st_rdev: kstat.rdev,
            __pad: 0,
            st_size: kstat.size,
            st_blksize: kstat.blksize,
            __pad2: 0,
            st_blocks: kstat.blocks,
            st_atime: kstat.atime,
            st_mtime: kstat.mtime,
            st_ctime: kstat.ctime,
            unused: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Statx {
    mask: u32,            // 指示哪些字段被填充
    blksize: u32,         // 文件系统I/O块大小
    attributes: u64,      // 文件属性
    nlink: u32,           // 硬链接数
    uid: u32,             // 文件所有者的用户ID
    gid: u32,             // 文件所有者的组ID
    mode: u16,            // 文件权限和类型
    ino: u64,             // inode号
    size: u64,            // 文件大小（字节）
    blocks: u64,          // 分配的512B块数
    attributes_mask: u64, // stx_attributes字段的支持掩码
    /* 文件时间戳 */
    atime: StatxTimeStamp, // 最后访问时间
    btime: StatxTimeStamp, // 创建时间
    ctime: StatxTimeStamp, // 最后状态更改时间
    mtime: StatxTimeStamp, // 最后修改时间

    // todo: 结构体是statx_timestamp
    /* 当文件是device, 以下两字段表示设备ID*/
    rdev_major: u32,
    rdev_minor: u32,

    /* 设备所在文件系统的主次id */
    dev_major: u32,
    dev_minor: u32,

    mnt_id: u64, // 挂载ID
    /* 直接I/O相关信息  */
    dio_mem_align: u32,    // DIO内存对齐
    dio_offset_align: u32, // DIO偏移对齐
    subvol: u64,           // 子卷ID
    /* 原子写入限制 */
    atomic_write_unit_min: u32,     // 原子写入最小单位
    atomic_write_unit_max: u32,     // 原子写入最大单位
    atomic_write_segments_max: u32, // 原子写入最大段数
    /* 直接I/O读取的文件偏移对齐要求 */
    dio_read_offset_align: u32,
}

impl From<Kstat> for Statx {
    fn from(kstat: Kstat) -> Self {
        Self {
            mask: kstat.result_mask.bits(),
            blksize: kstat.blksize,
            attributes: kstat.attributes,
            nlink: kstat.nlink,
            uid: kstat.uid,
            gid: kstat.gid,
            mode: kstat.mode,
            ino: kstat.ino,
            size: kstat.size,
            blocks: kstat.blocks,
            attributes_mask: kstat.attributes_mask,
            atime: StatxTimeStamp::from(kstat.atime),
            btime: StatxTimeStamp::from(kstat.btime),
            ctime: StatxTimeStamp::from(kstat.ctime),
            mtime: StatxTimeStamp::from(kstat.mtime),
            rdev_major: 0,
            rdev_minor: 0,
            dev_major: 0,
            dev_minor: 0,
            mnt_id: 0,
            dio_mem_align: 0,
            dio_offset_align: 0,
            subvol: 0,
            atomic_write_unit_min: 0,
            atomic_write_unit_max: 0,
            atomic_write_segments_max: 0,
            dio_read_offset_align: 0,
        }
    }
}

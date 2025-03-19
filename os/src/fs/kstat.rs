use crate::arch::timer::TimeSpec;

#[repr(C)]
#[derive(Default)]
pub struct Kstat {
    pub result_mask: u32,      // 指示哪些字段被填充
    pub mode: u16,             // 文件权限和类型，如 S_IFREG, S_IFDIR
    pub nlink: u32,            // 硬链接数
    pub blksize: u32,          // I/O 块大小
    pub attributes: u64,       // File attributes
    pub attributes_mask: u64,  // Supported attributes mask
    pub ino: u64,              // inode号(inode->i_ino)
    pub dev: u64,              // 设备号(inode->i_sb->s_dev)
    pub rdev: u64,             // Device ID (if special file)
    pub uid: u32,              // Owner User ID of the file
    pub gid: u32,              // Owner Group ID of the file
    pub size: u64,             // File size (bytes)
    pub atime: TimeSpec,       // Last access time
    pub mtime: TimeSpec,       // Last modification time
    pub ctime: TimeSpec,       // Last status change time
    pub btime: TimeSpec,       // Creation time
    pub blocks: u64,           // Number of 512B blocks allocated(inode->i_blocks)
    pub mnt_id: u64,           // Mount ID
    pub dio_mem_align: u32,    // DIO memory alignment
    pub dio_offset_align: u32, // DIO offset alignment
    pub change_cookie: u64,    // inode版本号
    pub subvol: u64,           // 子卷ID
}

#[repr(C)]
#[derive(Copy, Clone)]
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

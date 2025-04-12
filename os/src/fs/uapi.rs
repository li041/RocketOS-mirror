/// writev
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct IoVec {
    pub base: usize,
    pub len: usize,
}

bitflags::bitflags! {
    // 定义于 <bits/poll.h>。
    #[derive(Debug, Clone, Copy)]
    pub struct PollEvents: i16 {
        // 可以被监听的事件类型。这些位可以在 `events` 中设置，表示感兴趣的事件类型；
        // 它们会出现在 `revents` 中，表示文件描述符的实际状态。
        /// 有可读的数据
        const IN = 0x001;
        /// 有紧急数据可读
        const PRI = 0x002;
        /// 当前可写，写操作不会阻塞
        const OUT = 0x004;

        // 总是会隐式监听的事件类型。这些位不需要在 `events` 中设置，
        // 但如果发生了，它们会出现在 `revents` 中，表示文件描述符的状态。
        /// Err Condition
        const ERR = 0x008;
        /// Hang up (例如对端关闭了连接)
        const HUP = 0x010;
        /// invalid  poll request (例如文件描述符无效)
        const INVAL = 0x020;
    }
}

/// sys_ppoll
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct PollFd {
    pub fd: i32,
    pub events: PollEvents,
    pub revents: PollEvents,
}

/// sys_utimensat
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct UtimenatFlags: i32 {
        // 如果路径是空字符串, 直接操作dirfd指向的file
        const AT_EMPTY_PATH = 0x1000;
        // 不跟随符号链接, 如果路径是符号链接，则操作会在链接本身上进行，而不是链接指向的目标。
        const AT_SYMLINK_NOFOLLOW = 0x100;
    }
}

/// sys_mknod
pub struct DevT(pub u64);

impl DevT {
    pub fn tty_devt() -> Self {
        Self::makedev(5, 0)
    }
    pub fn rtc_devt() -> Self {
        Self::makedev(10, 0)
    }
}

impl DevT {
    pub fn new(dev: u64) -> Self {
        Self(dev)
    }
    pub fn makedev(major: u32, minor: u32) -> Self {
        Self(((major as u64) << 20) | (minor as u64 & 0xFFFFF))
    }
    /// 从dev_t中获取设备号
    pub fn major(&self) -> u32 {
        ((self.0 >> 20) & 0xfff) as u32
    }
    pub fn minor(&self) -> u32 {
        (self.0 & 0xfffff) as u32
    }
    pub fn unpack(&self) -> (u32, u32) {
        (self.major(), self.minor())
    }
}
impl From<DevT> for u64 {
    fn from(dev: DevT) -> Self {
        dev.0
    }
}

/// sys_fcntl
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct RenameFlags: i32 {
        // 不要覆盖目标路径(newpath), 如果目标路径存在, 返回错误
        const NOREPLACE = 1 << 0;
        /// 原路径（oldpath）和新路径（newpath）进行原子交换。
        const EXCHANGE = 1 << 1;
        /// 仅对 Overlay 或 Union 文件系统实现有意义的操作。
        const WHITEOUT = 1 << 2;
    }
}

#[repr(usize)]
pub enum Whence {
    SeekSet = 0,
    SeekCur = 1,
    SeekEnd = 2,
    // Todo:
    // SeekData = 3,
    // SeekHold = 4,
}

impl TryFrom<usize> for Whence {
    type Error = &'static str;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Whence::SeekSet),
            1 => Ok(Whence::SeekCur),
            2 => Ok(Whence::SeekEnd),
            _ => Err("invalid whence"),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct StatFs {
    pub f_type: i64,       // 文件系统类型（如 EXT4、TMPFS 等）
    pub f_bsize: i64,      // 块大小
    pub f_blocks: u64,     // 总块数
    pub f_bfree: u64,      // 空闲块数
    pub f_bavail: u64,     // 非特权用户可用块数
    pub f_files: u64,      // 总 inode 数
    pub f_ffree: u64,      // 空闲 inode 数
    pub f_fsid: [i32; 2],  // 文件系统 ID（通常不用）
    pub f_namelen: i64,    // 最大文件名长度
    pub f_frsize: i64,     // 片段大小（Linux 2.6+）
    pub f_flags: i64,      // 挂载标志（如 ST_RDONLY）
    pub f_spare: [i64; 4], // 保留字段
}

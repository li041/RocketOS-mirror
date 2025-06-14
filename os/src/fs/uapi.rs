use crate::syscall::errno::Errno;

/// writev
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IoVec {
    pub base: usize,
    pub len: usize,
}

bitflags::bitflags! {
    // 定义于 <bits/poll.h>。
    #[derive(Debug, Clone, Copy, Default)]
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
#[derive(Debug, Copy, Clone, Default)]
#[repr(C)]
pub struct PollFd {
    pub fd: i32,
    pub events: PollEvents,
    pub revents: PollEvents,
}

/// sys_mknod
pub struct DevT(pub u64);

impl DevT {
    pub fn tty_devt() -> Self {
        Self::new_encode_dev(5, 0)
    }
    pub fn rtc_devt() -> Self {
        Self::new_encode_dev(10, 0)
    }
    pub fn null_devt() -> Self {
        Self::new_encode_dev(1, 3)
    }
    pub fn zero_devt() -> Self {
        Self::new_encode_dev(1, 5)
    }
    pub fn urandom_devt() -> Self {
        Self::new_encode_dev(1, 9)
    }
    pub fn loop_control_devt() -> Self {
        Self::new_encode_dev(10, 237)
    }
    pub fn loopx_devt(id: usize) -> Self {
        Self::new_encode_dev(7, id as u32)
    }
}

impl DevT {
    pub fn new(dev: u64) -> Self {
        Self(dev)
    }
    pub fn new_encode_dev(major: u32, minor: u32) -> Self {
        Self(((major as u64) << 20) | (minor as u64 & 0xFFFFF))
    }
    pub fn new_encode_dev_old(major: u32, minor: u32)->Self{
        Self(((major as u64) << 3) | (minor as u64 & 0xFFFFF))
    }
    /// 从dev_t中获取设备号
    // pub fn major(&self) -> u32 {
    //     ((self.0 >> 20) & 0xfff) as u32
    // }
    // pub fn minor(&self) -> u32 {
    //     (self.0 & 0xfffff) as u32
    // }
    pub fn new_decode_dev(&self) -> (u32, u32) {
        let major = ((self.0 >> 20) & 0xfff) as u32;
        let minor = (self.0 & 0xfffff) as u32;
        (major, minor)
    }
    pub fn old_decode_dev(&self) -> (u32, u32) {
        let major = ((self.0 >> 8) & 0xff) as u32;
        let minor = (self.0 & 0xff) as u32;
        (major, minor)
    }
}

pub fn convert_old_dev_to_new(dev: u64) -> DevT {
    // 旧的设备号格式是 8 位主设备号和 8 位次设备号
    let major = (dev >> 8) as u32 & 0xff;
    let minor = (dev & 0xff) as u32;
    DevT::new_encode_dev(major, minor)
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

#[derive(Debug)]
#[repr(usize)]
pub enum Whence {
    SeekSet = 0,
    SeekCur = 1,
    SeekEnd = 2,
    // 将文件偏移量调整到文件中大于或等于offset的下一个包含数据的位置。如果offset本身指向数据，则文件偏移量设置为offset。
    SeekData = 3,
    // 将文件偏移量调整到文件中大于或等于offset的下一个不包含数据的位置。如果offset本身指向空洞，则文件偏移量设置为offset。
    SeekHole = 4,
}

impl TryFrom<usize> for Whence {
    type Error = Errno;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Whence::SeekSet),
            1 => Ok(Whence::SeekCur),
            2 => Ok(Whence::SeekEnd),
            3 => Ok(Whence::SeekData),
            4 => Ok(Whence::SeekHole),
            _ => Err(Errno::EINVAL), // Invalid argument
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

pub const RLIM_INFINITY: usize = usize::MAX;
/// Resource Limit
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RLimit {
    /// Soft limit: the kernel enforces for the corresponding resource
    pub rlim_cur: usize,
    /// Hard limit (ceiling for rlim_cur)
    pub rlim_max: usize,
}

impl RLimit {
    pub fn new(rlim_cur: usize) -> Self {
        Self {
            rlim_cur,
            rlim_max: RLIM_INFINITY,
        }
    }
}
impl Default for RLimit {
    fn default() -> Self {
        Self {
            rlim_cur: RLIM_INFINITY,
            rlim_max: RLIM_INFINITY,
        }
    }
}

/// sys_prlimit
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Resource {
    // 每个进程的 CPU 时间限制，单位为秒。
    CPU = 0,
    // 可以创建的最大文件大小，单位为字节。
    FSIZE = 1,
    // 数据段的最大大小，单位为字节。
    DATA = 2,
    // 栈段的最大大小，单位为字节。
    STACK = 3,
    // 可以创建的最大核心转储文件大小，单位为字节。
    CORE = 4,
    // 最大驻留集大小，单位为字节。
    // 这会影响交换(swapping)；超过其驻留集大小的进程更有可能被剥夺物理内存。
    RSS = 5,
    // 进程数量。
    NPROC = 6,
    // 打开文件的数量。
    NOFILE = 7,
    // 锁在内存中的地址空间。
    MEMLOCK = 8,
    // 地址空间限制。
    AS = 9,
    // 最大文件锁数量。
    LOCKS = 10,
    // 最大挂起信号数量。
    SIGPENDING = 11,
    // POSIX 消息队列的最大字节数。
    MSGQUEUE = 12,
    // 允许提高的最大 nice 优先级。
    // Nice 级别 19 到 -20 对应于此资源限制的 0 到 39 值。
    NICE = 13,
    // 非特权进程允许的最大实时优先级。
    RTPRIO = 14,
    // 在实时调度策略下调度的进程在未进行阻塞系统调用之前可以消耗的最大 CPU 时间，单位为微秒，
    // 超过此时间将被强制取消调度。
    RTTIME = 15,
}

impl TryFrom<i32> for Resource {
    type Error = &'static str;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Resource::CPU),
            1 => Ok(Resource::FSIZE),
            2 => Ok(Resource::DATA),
            3 => Ok(Resource::STACK),
            4 => Ok(Resource::CORE),
            5 => Ok(Resource::RSS),
            6 => Ok(Resource::NPROC),
            7 => Ok(Resource::NOFILE),
            8 => Ok(Resource::MEMLOCK),
            9 => Ok(Resource::AS),
            10 => Ok(Resource::LOCKS),
            11 => Ok(Resource::SIGPENDING),
            12 => Ok(Resource::MSGQUEUE),
            13 => Ok(Resource::NICE),
            14 => Ok(Resource::RTPRIO),
            15 => Ok(Resource::RTTIME),
            _ => Err("invalid resource"),
        }
    }
}

/* linux/include/uapi/linux/falloc.h */
// /// 保持文件大小不变
// pub const FALLOC_FL_KEEP_SIZE: i32 = 0x01;
// /// 打孔操作，释放文件中的空间, 但文件的大小不变, 必须与`FALLOC_FL_KEEP_SIZE`一起使用
// pub const FALLOC_FL_PUNCH_HOLE: i32 = 0x02;
// /// 预留的标志位, 暂未使用
// pub const FALLOC_FL_NO_HIDE_STALE: i32 = 0x04; // 不隐藏旧数据
// /// 折叠文件中的一段区域，相当于将该范围删除，然后将该区域后面的内容往前“搬”，覆盖被删区域，并缩小文件大小。不能跨越文件末尾（EOF），否则操作非法。
// pub const FALLOC_FL_COLLAPSE_RANGE: i32 = 0x08; // 压缩范围，将指定范围内的数据删除并将后面的数据向前移动
// pub const FALLOC_FL_ZERO_RANGE: i32 = 0x10; // 将指定范围内的数据清零
// pub const FALLOC_FL_INSERT_RANGE: i32 = 0x20; // 插入范围，将指定范围内的数据向后移动
// pub const FALLOC_FL_UNSHARE_RANGE: i32 = 0x40; // 取消共享范围，将指定范围内的数据从共享中分离出来

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct FallocFlags: i32 {
        const KEEP_SIZE = 0x1;
        const PUNCH_HOLE = 0x2;
        const NO_HIDE_STALE = 0x4;
        const COLLAPSE_RANGE = 0x8;
        const ZERO_RANGE = 0x10;
        const INSERT_RANGE = 0x20;
        const UNSHARE_RANGE = 0x40;
    }
}

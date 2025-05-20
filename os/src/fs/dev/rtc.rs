use crate::{
    arch::mm::copy_to_user,
    ext4::inode::{Ext4InodeDisk, S_IFCHR},
    fs::{
        file::{FileOp, OpenFlags},
        inode::InodeOp,
        kstat::Kstat,
        path::Path,
        uapi::DevT,
    },
    syscall::errno::{Errno, SyscallRet},
    timer::TimeSpec,
    utils::DateTime,
};

use alloc::sync::Arc;

use spin::{Once, RwLock};

pub static RTC: Once<Arc<dyn FileOp>> = Once::new();

pub struct RtcInode {
    pub inode_num: usize,
    pub inner: RwLock<RtcInodeInner>,
}

struct RtcInodeInner {
    pub inode_on_disk: Ext4InodeDisk,
}

impl RtcInodeInner {
    pub fn new(inode_on_disk: Ext4InodeDisk) -> Self {
        Self { inode_on_disk }
    }
}

impl RtcInode {
    pub fn new(ino: usize, inode_mode: u16, major: u32, minor: u32) -> Arc<Self> {
        assert!(inode_mode & S_IFCHR == S_IFCHR);
        let inner = RtcInodeInner::new(Ext4InodeDisk::new_chr(inode_mode, major, minor));
        Arc::new(RtcInode {
            inode_num: ino,
            inner: RwLock::new(inner),
        })
    }
}

impl InodeOp for RtcInode {
    fn getattr(&self) -> Kstat {
        let mut kstat = Kstat::new();
        let inner_guard = self.inner.read();
        let inode_on_disk = &inner_guard.inode_on_disk;
        kstat.ino = self.inode_num as u64;
        kstat.dev = 0;
        let (major, minor) = inode_on_disk.get_devt();
        let devt = DevT::makedev(major, minor);
        kstat.rdev = u64::from(devt); // 通常特殊文件才会有 rdev

        kstat.mode = inode_on_disk.get_mode();
        kstat.uid = inode_on_disk.get_uid() as u32;
        kstat.gid = inode_on_disk.get_gid() as u32;
        kstat.nlink = inode_on_disk.get_nlinks() as u32;
        kstat.size = inode_on_disk.get_size();

        // Todo: 目前没有更新时间戳
        kstat.atime = inode_on_disk.get_atime();
        kstat.mtime = inode_on_disk.get_mtime();
        kstat.ctime = inode_on_disk.get_ctime();
        // Todo: 创建时间
        // kstat.btime = TimeSpec {
        //     sec: inode_on_disk.create_time as usize,
        //     nsec: (inode_on_disk.create_time_extra >> 2) as usize,
        // };
        // Todo: Direct I/O 对齐参数
        // inode版本号
        kstat.change_cookie = inode_on_disk.generation as u64;

        kstat
    }
    /* get/set属性方法 */
    // Todo
    fn get_devt(&self) -> (u32, u32) {
        self.inner.read().inode_on_disk.get_devt()
    }
    fn get_mode(&self) -> u16 {
        self.inner.read().inode_on_disk.get_mode()
    }
    /* 时间戳 */
    fn get_atime(&self) -> TimeSpec {
        self.inner.read().inode_on_disk.get_atime()
    }
    fn set_atime(&self, atime: TimeSpec) {
        self.inner.write().inode_on_disk.set_atime(atime);
    }
    fn get_mtime(&self) -> TimeSpec {
        self.inner.read().inode_on_disk.get_mtime()
    }
    fn set_mtime(&self, mtime: TimeSpec) {
        self.inner.write().inode_on_disk.set_mtime(mtime);
    }
    fn get_ctime(&self) -> TimeSpec {
        self.inner.read().inode_on_disk.get_ctime()
    }
    fn set_ctime(&self, ctime: TimeSpec) {
        self.inner.write().inode_on_disk.set_ctime(ctime);
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C)]
pub struct RtcTime {
    tm_sec: i32,
    tm_min: i32,
    tm_hour: i32,
    tm_mday: i32,
    tm_mon: i32,
    tm_year: i32,
    tm_wday: i32,  // 周几 [0-6] (0=周日)
    tm_yday: i32,  // 一年中的第几天 [0-365]
    tm_isdst: i32, // 夏令时标志
}

pub struct RtcFile {
    pub path: Arc<Path>,
    pub inode: Arc<dyn InodeOp>,
    pub flags: OpenFlags,
}

impl RtcFile {
    pub fn new(path: Arc<Path>, inode: Arc<dyn InodeOp>, flags: OpenFlags) -> Arc<Self> {
        Arc::new(Self { path, inode, flags })
    }
}

impl FileOp for RtcFile {
    fn read(&self, buf: &mut [u8]) -> SyscallRet {
        let current_time = TimeSpec::new_wall_time();
        let date_time = DateTime::from(&current_time);
        let rtc_time = RtcTime {
            tm_sec: date_time.second as i32,
            tm_min: date_time.minute as i32,
            tm_hour: date_time.hour as i32,
            tm_mday: date_time.day as i32,
            tm_mon: (date_time.month - 1) as i32, // 月份从0开始
            tm_year: (date_time.year - 1900) as i32, // 年份从1900开始
            tm_wday: 0,                           // 周几 [0-6] (0=周日)
            tm_yday: 0,                           // 一年中的第几天 [0-365]
            tm_isdst: 0,                          // 夏令时标志
        };
        // 写入buf
        let size = core::mem::size_of::<RtcTime>();
        let buf_size = buf.len();
        if buf_size < size {
            return Ok(0);
        }
        unimplemented!()
    }
    fn write<'a>(&'a self, buf: &'a [u8]) -> SyscallRet {
        unimplemented!();
    }
    fn ioctl(&self, op: usize, arg_ptr: usize) -> SyscallRet {
        let current_time = TimeSpec::new_wall_time();
        let date_time = DateTime::from(&current_time);
        let rtc_time = RtcTime {
            tm_sec: date_time.second as i32,
            tm_min: date_time.minute as i32,
            tm_hour: date_time.hour as i32,
            tm_mday: date_time.day as i32,
            tm_mon: (date_time.month - 1) as i32, // 月份从0开始
            tm_year: (date_time.year - 1900) as i32, // 年份从1900开始
            tm_wday: 0,                           // 周几 [0-6] (0=周日)
            tm_yday: 0,                           // 一年中的第几天 [0-365]
            tm_isdst: 0,                          // 夏令时标志
        };
        let op = RtcIoctlCmd::try_from(op as u32).unwrap();
        match op {
            RtcIoctlCmd::RTC_RD_TIME => {
                // 读取 RTC 时间
                if arg_ptr == 0 {
                    return Err(Errno::EINVAL);
                }
                let buf_ptr = arg_ptr as *mut RtcTime;
                log::error!("RTC_RD_TIME: buf_ptr = {:#X}", buf_ptr as usize,);
                copy_to_user(buf_ptr, &rtc_time as *const RtcTime, 1)?;
                return Ok(0);
            }
            RtcIoctlCmd::RTC_SET_TIME => {
                unimplemented!("RTC_SET_TIME");
            }
            _ => {
                unimplemented!("RTC ioctl: {:?}", op);
            }
        }
    }
}

/// RTC IOCTL 命令定义，参考 Linux 内核 <linux/rtc.h>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RtcIoctlCmd {
    /// 读取 RTC 时间（返回 struct rtc_time）
    RTC_RD_TIME = 0x8024_7009, // _IOR('p', 0x09, struct rtc_time)

    /// 设置 RTC 时间（输入 struct rtc_time）
    RTC_SET_TIME = 0x4024_700A, // _IOW('p', 0x0A, struct rtc_time)

    /// 读取 RTC 闹钟时间（返回 struct rtc_time）
    RTC_ALM_READ = 0x8024_700B, // _IOR('p', 0x0B, struct rtc_time)

    /// 设置 RTC 闹钟时间（输入 struct rtc_time）
    RTC_ALM_SET = 0x4024_700C, // _IOW('p', 0x0C, struct rtc_time)

    /// 开启闹钟中断
    RTC_AIE_ON = 0x0000_7005, // _IO('p', 0x05)

    /// 关闭闹钟中断
    RTC_AIE_OFF = 0x0000_7006, // _IO('p', 0x06)

    /// 读取周期性中断频率（返回 unsigned long）
    RTC_IRQP_READ = 0x8004_700D, // _IOR('p', 0x0D, unsigned long)

    /// 设置周期性中断频率（输入 unsigned long）
    RTC_IRQP_SET = 0x4004_700E, // _IOW('p', 0x0E, unsigned long)

    /// 开启周期性中断
    RTC_PIE_ON = 0x0000_7003, // _IO('p', 0x03)

    /// 关闭周期性中断
    RTC_PIE_OFF = 0x0000_7004, // _IO('p', 0x04)

    /// 开启更新中断
    RTC_UIE_ON = 0x0000_7001, // _IO('p', 0x01)

    /// 关闭更新中断
    RTC_UIE_OFF = 0x0000_7002, // _IO('p', 0x02)

    /// 读取 RTC 纪元年份（返回 unsigned long）
    RTC_EPOCH_READ = 0x8004_700F, // _IOR('p', 0x0F, unsigned long)

    /// 设置 RTC 纪元年份（输入 unsigned long）
    RTC_EPOCH_SET = 0x4004_7010, // _IOW('p', 0x10, unsigned long)
}
impl From<u32> for RtcIoctlCmd {
    fn from(value: u32) -> Self {
        match value {
            0x8024_7009 => RtcIoctlCmd::RTC_RD_TIME,
            0x4024_700A => RtcIoctlCmd::RTC_SET_TIME,
            0x8024_700B => RtcIoctlCmd::RTC_ALM_READ,
            0x4024_700C => RtcIoctlCmd::RTC_ALM_SET,
            0x0000_7005 => RtcIoctlCmd::RTC_AIE_ON,
            0x0000_7006 => RtcIoctlCmd::RTC_AIE_OFF,
            0x8004_700D => RtcIoctlCmd::RTC_IRQP_READ,
            0x4004_700E => RtcIoctlCmd::RTC_IRQP_SET,
            0x0000_7003 => RtcIoctlCmd::RTC_PIE_ON,
            0x0000_7004 => RtcIoctlCmd::RTC_PIE_OFF,
            0x0000_7001 => RtcIoctlCmd::RTC_UIE_ON,
            0x0000_7002 => RtcIoctlCmd::RTC_UIE_OFF,
            0x8004_700F => RtcIoctlCmd::RTC_EPOCH_READ,
            0x4004_7010 => RtcIoctlCmd::RTC_EPOCH_SET,
            _ => panic!("Invalid RTC IOCTL command: {:#X}", value),
        }
    }
}

use crate::arch::mm::copy_to_user;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Utsname {
    /// 系统名称
    pub sysname: [u8; 65],
    /// 网络上主机名称
    pub nodename: [u8; 65],
    /// 发行编号
    pub release: [u8; 65],
    /// 版本
    pub version: [u8; 65],
    /// 域名
    pub machine: [u8; 65],
}

impl Default for Utsname {
    fn default() -> Self {
        Self {
            sysname: Self::from_str("RocketOS"),
            nodename: Self::from_str("LAPTOP"),
            release: Self::from_str("5.15.146.1-standard"),
            version: Self::from_str("#1 SMP Thu Jan"),
            machine: Self::from_str("RISC-V SiFive Freedom U740 SoC"),
        }
    }
}

impl Utsname {
    fn from_str(info: &str) -> [u8; 65] {
        let mut data: [u8; 65] = [0; 65];
        data[..info.len()].copy_from_slice(info.as_bytes());
        data
    }
}

/// sys_times, 单位都是us
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Tms {
    /// CPU time spent executing instructions of the calling process
    pub utime: usize,
    /// inside the kernel
    pub stime: usize,
    /// the sum of the utime for all waited-for teminated children
    pub cutime: usize,
    /// the sum of stime for all waited-for teminated children
    pub cstime: usize,
}

impl Default for Tms {
    fn default() -> Self {
        Self {
            utime: 1,
            stime: 1,
            cutime: 1,
            cstime: 1,
        }
    }
}

/// fake uname  
///
/// Todo?:
pub fn sys_uname(uts: usize) -> isize {
    log::info!("[sys_uname] uts: {:#x}", uts);
    let uts = uts as *mut Utsname;
    //Todo!: check validarity
    let utsname = Utsname::default();
    // unsafe {
    //     core::ptr::write(uts, utsname);
    // }
    copy_to_user(uts, &utsname as *const Utsname, 1).unwrap();
    0
}

/// fake sys_times
/// Todo?:
#[allow(unused)]
pub fn sys_times(buf: usize) -> isize {
    let buf = buf as *mut Tms;
    let tms = Tms::default();
    // unsafe {
    //     core::ptr::write(buf, tms);
    // }
    copy_to_user(buf, &tms as *const Tms, 1).unwrap();
    0
}

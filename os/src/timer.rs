use core::{
    cmp::Ordering,
    ops::{Add, Sub},
};

pub const TICKS_PER_SEC: usize = 100;
pub const MSEC_PER_SEC: usize = 1000;
pub const USEC_PER_SEC: usize = 1_000_000;

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct TimeSpec {
    // 秒数
    pub sec: usize,
    // 毫秒数中剩余的部分, 使用纳秒表示
    pub nsec: usize,
}

impl PartialEq for TimeSpec {
    fn eq(&self, other: &Self) -> bool {
        self.sec == other.sec && self.nsec == other.nsec
    }
}
impl Eq for TimeSpec {}

impl PartialOrd for TimeSpec {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        if self.sec == other.sec {
            Some(self.nsec.cmp(&other.nsec))
        } else {
            Some(self.sec.cmp(&other.sec))
        }
    }
}

impl Ord for TimeSpec {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.sec.cmp(&other.sec) {
            Ordering::Equal => self.nsec.cmp(&other.nsec),
            other_order => other_order,
        }
    }
}

impl Add for TimeSpec {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        let mut sec = self.sec + rhs.sec;
        let mut nsec = self.nsec + rhs.nsec;
        if nsec >= 1_000_000_000 {
            sec += 1;
            nsec -= 1_000_000_000;
        }
        Self { sec, nsec }
    }
}

impl Sub for TimeSpec {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        let mut sec = self.sec - rhs.sec;
        let mut nsec = self.nsec as isize - rhs.nsec as isize;
        if nsec < 0 {
            sec -= 1;
            nsec += 1_000_000_000;
        }
        Self {
            sec,
            nsec: nsec as usize,
        }
    }
}

impl TimeSpec {
    pub fn is_zero(&self) -> bool {
        self.sec == 0 && self.nsec == 0
    }
    //检查timespec是否符合 UTC/TAI/合理范围约束
    pub fn timespec_valid_settod(&self) -> bool {
        // 纳秒每秒
        const NSEC_PER_SEC: usize = 1_000_000_000;
        // signed 64 位能表示的最大秒数
        const MAX_SEC: usize = (i64::MAX as usize) / NSEC_PER_SEC;

        // 1) nsec 必须小于 1 秒
        if self.nsec >= NSEC_PER_SEC {
            return false;
        }
        // 2) sec 不能超过 i64 能表示的最大秒数
        if self.sec > MAX_SEC {
            return false;
        }
        true
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TimeVal {
    /// 绝对时间, 表示从UNIX time以来的秒数
    pub sec: usize,
    /// 微秒数, 表示秒数后剩余的部分
    pub usec: usize,
}

impl From<TimeSpec> for TimeVal {
    fn from(ts: TimeSpec) -> Self {
        Self {
            sec: ts.sec,
            usec: ts.nsec / 1000,
        }
    }
}

impl From<TimeVal> for TimeSpec {
    fn from(tv: TimeVal) -> Self {
        Self {
            sec: tv.sec,
            nsec: tv.usec * 1000,
        }
    }
}

impl TimeVal {
    pub fn is_zero(&self) -> bool {
        self.sec == 0 && self.usec == 0
    }

    pub fn timespec_to_ticks(&self) -> usize {
        self.sec * TICKS_PER_SEC + self.usec / (1_000 / TICKS_PER_SEC)
    }
}

impl PartialEq for TimeVal {
    fn eq(&self, other: &Self) -> bool {
        self.sec == other.sec && self.usec == other.usec
    }
}

impl PartialOrd for TimeVal {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.sec == other.sec {
            Some(self.usec.cmp(&other.usec))
        } else {
            Some(self.sec.cmp(&other.sec))
        }
    }
}

impl Sub for TimeVal {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        let mut sec = self.sec - rhs.sec;
        let mut usec = self.usec as isize - rhs.usec as isize;
        if usec < 0 {
            sec -= 1;
            usec += 1_000_000;
        }
        Self {
            sec,
            usec: usec as usize,
        }
    }
}

impl Add for TimeVal {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        let mut sec = self.sec + rhs.sec;
        let mut usec = self.usec + rhs.usec;
        if usec >= 1_000_000 {
            sec += 1;
            usec -= 1_000_000;
        }
        Self { sec, usec }
    }
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct ITimerVal {
    /// 每次定时器触发之后, 重新设置的时间间隔
    /// 如果设置为0, 则定时器只触发一次
    pub it_interval: TimeVal,
    /// 相对时间, 表示从现在开始, 多少时间后第一次触发定时器
    /// 当这个值为0, 表示禁用定时器
    pub it_value: TimeVal,
}
impl ITimerVal {
    pub fn is_valid(&self) -> bool {
        self.it_interval.usec < 1_000_000 && self.it_value.usec < 1_000_000
    }
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct StatxTimeStamp {
    /// 自UNIX time以来的秒数
    pub sec: i64,
    /// 纳秒数, 表示秒数后剩余的部分
    pub nsec: u32,
}

impl From<TimeSpec> for StatxTimeStamp {
    fn from(ts: TimeSpec) -> Self {
        Self {
            sec: ts.sec as i64,
            nsec: ts.nsec as u32,
        }
    }
}

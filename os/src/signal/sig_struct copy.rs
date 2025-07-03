use core::fmt::Debug;

use alloc::{collections::btree_map::BTreeMap, vec::Vec};
use bitflags::bitflags;
use log::error;

use super::{ActionType, SigInfo};

pub const MAX_SIGNUM: usize = 64;

// SigPending 负责存储进程收到的待处理信号
pub struct SigPending {
    pub pending: SigSet,            // 接收信号位图
    pub mask: SigSet,               // 信号掩码
    pub info: Vec<Option<SigInfo>>, // 记录信息 key：信号值， value：信号信息
    pub interrupted: bool,          // 是否被信号中断
    pub re_start: bool,             // 是否需要重启
    pub restore_mask: bool,         // 是否需要恢复信号掩码(用于sigsuspend)
}

impl SigPending {
    // 7.10
    pub fn new() -> Self {
        println!("[SigPending::new] enter");
        let pending = SigSet::default();
        println!("[SigPending::new] pending: {:?}", pending);
        // let info = BTreeMap::new();
        // println!("[SigPending::new] info: {:?}", info);
        let info = Vec::with_capacity(64);
        let mask = SigSet::default();
        println!("[SigPending::new] mask: {:?}", mask);
        let sig_pending = Self {
            pending: pending,
            mask: mask,
            info: info,
            interrupted: false,
            re_start: true,     // 默认需要重启
            restore_mask: true, // 默认需要恢复信号掩码
        };
        println!("[SigPending::new] end");
        sig_pending
    }

    pub fn clear(&mut self) {
        self.pending = SigSet::empty();
        self.mask = SigSet::empty();
        self.info.clear();
    }

    // 添加一个新信号
    // 用作任务收到信号
    pub fn add_signal(&mut self, siginfo: SigInfo) {
        let sig = Sig::from(siginfo.signo);
        self.pending.add_signal(sig);
        self.info.insert(siginfo.signo as usize, Some(siginfo));
    }

    // 获得信号信息
    pub fn get_info(&self, sig: Sig) -> Option<&SigInfo> {
        self.info.get(sig.raw() as usize).unwrap_or(&None).as_ref()
    }

    // 从当前待处理集合中选出在wanted_set中且最小的一个信号，但并不修改
    pub fn find_signal(&self, wanted_sigset: SigSet) -> Option<Sig> {
        let mut temp_pending = (self.pending & wanted_sigset).bits();
        loop {
            let pos: u32 = temp_pending.trailing_zeros();
            let sig = Sig::from((pos + 1) as i32);
            // 若全为0，则返回64，代表没有未决信号
            if pos == MAX_SIGNUM as u32 {
                return None;
            } else {
                temp_pending &= !(1 << pos);
                // 没有被屏蔽且无法屏蔽
                if (!self.mask.contain_signal(sig))
                    || pos == Sig::SIGKILL.index() as u32
                    || pos == Sig::SIGSTOP.index() as u32
                {
                    break Some(Sig::from((pos + 1) as i32));
                }
            }
        }
    }

    /// 取出未处理集合中, 在wanted_sigset中最小的一个信号，修改内容
    /// 如果wanted_sigset为满，则表示都可以, 取出pending中最小的一个信号
    pub fn fetch_signal(&mut self, wanted_sigset: SigSet) -> Option<(Sig, SigInfo)> {
        if let Some(sig) = self.find_signal(wanted_sigset) {
            log::info!("[fetch_signal]: {:?}", sig);
            self.pending.remove_signal(sig);
            Some((sig, self.info.remove(sig.raw() as usize).unwrap()))
        } else {
            None
        }
    }

    // 在信号掩码中添加新位
    pub fn add_mask(&mut self, sig: Sig) {
        self.mask.add_signal(sig);
    }

    // 在信号掩码中添加新位
    pub fn add_mask_sigset(&mut self, sigset: SigSet) {
        self.mask |= sigset;
    }

    // 换一个信号掩码
    pub fn change_mask(&mut self, mask: SigSet) -> SigSet {
        let old_mask = self.mask;
        self.mask = mask;
        old_mask
    }

    // 设定当前任务被信号中断
    pub fn set_interrupted(&mut self) {
        self.interrupted = true;
    }

    // 设定当前任务没有被信号中断
    pub fn set_uninterrupted(&mut self) {
        self.interrupted = false;
    }

    // 检查当前任务是否被信号中断
    pub fn is_interrupted(&self) -> bool {
        self.interrupted
    }

    // 阻止当前任务进行重启
    pub fn cancel_restart(&mut self) {
        self.re_start = false; // 设置为取消重启状态
    }

    // 判断当前任务是否需要重启
    pub fn need_restart(&mut self) -> bool {
        if !self.re_start {
            self.re_start = true; // 如果之前是取消重启的状态，则恢复重启
            return false;
        }
        self.re_start
    }

    pub fn cancel_restore_mask(&mut self) {
        self.restore_mask = false; // 设置为不恢复信号掩码状态
    }

    pub fn need_restore_mask(&mut self) -> bool {
        if !self.restore_mask {
            self.restore_mask = true; // 如果之前是不恢复信号掩码的状态，则恢复
            return false;
        }
        self.restore_mask
    }
}

/// 信号实体
/// Sig为0时表示空信号，从1开始才是有含义的信号
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sig(i32);

impl Sig {
    pub const SIGHUP: Sig = Sig(1); // Hangup detected on controlling terminal or death of controlling process
    pub const SIGINT: Sig = Sig(2); // Interrupt from keyboard
    pub const SIGQUIT: Sig = Sig(3); // Quit from keyboard
    pub const SIGILL: Sig = Sig(4); // Illegal Instruction
    pub const SIGTRAP: Sig = Sig(5); // Trace/breakpoint trap
    pub const SIGABRT: Sig = Sig(6); // Abort signal from abort(3)
    pub const SIGBUS: Sig = Sig(7); // Bus error (bad memory access)
    pub const SIGFPE: Sig = Sig(8); // Floating point exception
    pub const SIGKILL: Sig = Sig(9); // Kill signal
    pub const SIGUSR1: Sig = Sig(10); // User-defined signal 1
    pub const SIGSEGV: Sig = Sig(11); // Invalid memory reference
    pub const SIGUSR2: Sig = Sig(12); // User-defined signal 2
    pub const SIGPIPE: Sig = Sig(13); // Broken pipe: write to pipe with no readers
    pub const SIGALRM: Sig = Sig(14); // Timer signal from alarm(2)
    pub const SIGTERM: Sig = Sig(15); // Termination signal
    pub const SIGSTKFLT: Sig = Sig(16); // Stack fault on coprocessor (unused)
    pub const SIGCHLD: Sig = Sig(17); // Child stopped or terminated
    pub const SIGCONT: Sig = Sig(18); // Continue if stopped
    pub const SIGSTOP: Sig = Sig(19); // Stop process
    pub const SIGTSTP: Sig = Sig(20); // Stop typed at terminal
    pub const SIGTTIN: Sig = Sig(21); // Terminal input for background process
    pub const SIGTTOU: Sig = Sig(22); // Terminal output for background process
    pub const SIGURG: Sig = Sig(23); // Urgent condition on socket (4.2BSD)
    pub const SIGXCPU: Sig = Sig(24); // CPU time limit exceeded (4.2BSD)
    pub const SIGXFSZ: Sig = Sig(25); // File size limit exceeded (4.2BSD)
    pub const SIGVTALRM: Sig = Sig(26); // Virtual alarm clock (4.2BSD)
    pub const SIGPROF: Sig = Sig(27); // Profiling alarm clock
    pub const SIGWINCH: Sig = Sig(28); // Window resize signal (4.3BSD, Sun)
    pub const SIGIO: Sig = Sig(29); // I/O now possible (4.2BSD)
    pub const SIGPWR: Sig = Sig(30); // Power failure (System V)
    pub const SIGSYS: Sig = Sig(31); // Bad system call (SVr4); unused on Linux
    pub const SIGLEGACYMAX: Sig = Sig(32); // Legacy maximum signal
    pub const SIGMAX: Sig = Sig(64); // Maximum signal

    pub fn from(signum: i32) -> Sig {
        Sig(signum as i32)
    }

    pub fn is_valid(&self) -> bool {
        self.0 > 0 && self.0 <= MAX_SIGNUM as i32
    }

    pub fn raw(&self) -> i32 {
        self.0 as i32
    }

    pub fn index(&self) -> usize {
        (self.0 - 1) as usize
    }

    pub fn is_kill_or_stop(&self) -> bool {
        self.0 == 9 || self.0 == 19
    }

    // 仅用在handle_signal
    pub fn get_default_type(&self) -> ActionType {
        ActionType::default(*self)
    }

    // 显示信号名称
    pub fn name(&self) -> &'static str {
        match self.0 {
            1 => "SIGHUP",
            2 => "SIGINT",
            3 => "SIGQUIT",
            4 => "SIGILL",
            5 => "SIGTRAP",
            6 => "SIGABRT",
            7 => "SIGBUS",
            8 => "SIGFPE",
            9 => "SIGKILL",
            10 => "SIGUSR1",
            11 => "SIGSEGV",
            12 => "SIGUSR2",
            13 => "SIGPIPE",
            14 => "SIGALRM",
            15 => "SIGTERM",
            16 => "SIGSTKFLT",
            17 => "SIGCHLD",
            18 => "SIGCONT",
            19 => "SIGSTOP",
            20 => "SIGTSTP",
            21 => "SIGTTIN",
            22 => "SIGTTOU",
            23 => "SIGURG",
            24 => "SIGXCPU",
            25 => "SIGXFSZ",
            26 => "SIGVTALRM",
            27 => "SIGPROF",
            28 => "SIGWINCH",
            29 => "SIGIO",
            30 => "SIGPWR",
            31 => "SIGSYS",
            32 => "SIGLEGACYMAX",
            33 => "SIGRT1",
            34 => "SIGRT2",
            35 => "SIGRT3",
            36 => "SIGRT4",
            37 => "SIGRT5",
            38 => "SIGRT6",
            39 => "SIGRT7",
            40 => "SIGRT8",
            41 => "SIGRT9",
            42 => "SIGRT10",
            43 => "SIGRT11",
            44 => "SIGRT12",
            45 => "SIGRT13",
            46 => "SIGRT14",
            47 => "SIGRT15",
            48 => "SIGRT16",
            49 => "SIGRT17",
            50 => "SIGRT18",
            51 => "SIGRT19",
            52 => "SIGRT20",
            53 => "SIGRT21",
            54 => "SIGRT22",
            55 => "SIGRT23",
            56 => "SIGRT24",
            57 => "SIGRT25",
            58 => "SIGRT26",
            59 => "SIGRT27",
            60 => "SIGRT28",
            61 => "SIGRT29",
            62 => "SIGRT30",
            63 => "SIGRT31",
            64 => "SIGMAX",
            _ => "UNKNOWN",
        }
    }
}

impl Debug for Sig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}({})", self.name(), self.raw()) // 显示信号名称和信号值
    }
}

// 这里假设usize到i32的转换是安全的，但要注意溢出的风险
impl From<usize> for Sig {
    fn from(value: usize) -> Self {
        Sig(value as i32)
    }
}

bitflags! {
    #[derive(Copy, Clone, Default, Debug)]
    pub struct SigSet: u64 {
        const SIGHUP    = 1 << 0 ;
        const SIGINT    = 1 << 1 ;
        const SIGQUIT   = 1 << 2 ;
        const SIGILL    = 1 << 3 ;
        const SIGTRAP   = 1 << 4 ;
        const SIGABRT   = 1 << 5 ;
        const SIGBUS    = 1 << 6 ;
        const SIGFPE    = 1 << 7 ;
        const SIGKILL   = 1 << 8 ;
        const SIGUSR1   = 1 << 9 ;
        const SIGSEGV   = 1 << 10;
        const SIGUSR2   = 1 << 11;
        const SIGPIPE   = 1 << 12;
        const SIGALRM   = 1 << 13;
        const SIGTERM   = 1 << 14;
        const SIGSTKFLT = 1 << 15;
        const SIGCHLD   = 1 << 16;
        const SIGCONT   = 1 << 17;
        const SIGSTOP   = 1 << 18;
        const SIGTSTP   = 1 << 19;
        const SIGTTIN   = 1 << 20;
        const SIGTTOU   = 1 << 21;
        const SIGURG    = 1 << 22;
        const SIGXCPU   = 1 << 23;
        const SIGXFSZ   = 1 << 24;
        const SIGVTALRM = 1 << 25;
        const SIGPROF   = 1 << 26;
        const SIGWINCH  = 1 << 27;
        const SIGIO     = 1 << 28;
        const SIGPWR    = 1 << 29;
        const SIGSYS    = 1 << 30;
        const SIGLEGACYMAX  = 1 << 31;

        // TODO: rt signal
        const SIGRT1    = 1 << (33 - 1);   // real time signal min
        const SIGRT2    = 1 << (34 - 1);
        const SIGRT3    = 1 << (35 - 1);
        const SIGRT4    = 1 << (36 - 1);
        const SIGRT5    = 1 << (37 - 1);
        const SIGRT6    = 1 << (38 - 1);
        const SIGRT7    = 1 << (39 - 1);
        const SIGRT8    = 1 << (40 - 1);
        const SIGRT9    = 1 << (41 - 1);
        const SIGRT10    = 1 << (42 - 1);
        const SIGRT11    = 1 << (43 - 1);
        const SIGRT12   = 1 << (44 - 1);
        const SIGRT13   = 1 << (45 - 1);
        const SIGRT14   = 1 << (46 - 1);
        const SIGRT15   = 1 << (47 - 1);
        const SIGRT16   = 1 << (48 - 1);
        const SIGRT17   = 1 << (49 - 1);
        const SIGRT18   = 1 << (50 - 1);
        const SIGRT19   = 1 << (51 - 1);
        const SIGRT20   = 1 << (52 - 1);
        const SIGRT21   = 1 << (53 - 1);
        const SIGRT22   = 1 << (54 - 1);
        const SIGRT23   = 1 << (55 - 1);
        const SIGRT24   = 1 << (56 - 1);
        const SIGRT25   = 1 << (57 - 1);
        const SIGRT26   = 1 << (58 - 1);
        const SIGRT27   = 1 << (59 - 1);
        const SIGRT28   = 1 << (60 - 1);
        const SIGRT29   = 1 << (61 - 1);
        const SIGRT30   = 1 << (62 - 1);
        const SIGRT31   = 1 << (63 - 1);
        const SIGMAX   = 1 << 63;
        // 下面信号通常是由程序中的错误或异常操作触发的，如非法内存访问（导致
        // SIGSEGV）、硬件异常（可能导致
        // SIGBUS）等。同步信号的处理通常需要立即响应，
        // 因为它们指示了程序运行中的严重问题
        // const SYNCHRONOUS_MASK = SigSet::SIGSEGV.bits() | SigSet::SIGBUS.bits()
        // | SigSet::SIGILL.bits() | SigSet::SIGTRAP.bits() | SigSet::SIGFPE.bits() | SigSet::SIGSYS.bits();
        // const SYNCHRONOUS_MASK = (1<<3) | (1<<4) | (1<<6) | (1<<7) | (1<<10) | (1<<30) ;
    }
}

impl SigSet {
    pub fn add_signal(&mut self, sig: Sig) {
        self.insert(SigSet::from_bits(1 << sig.index()).unwrap())
    }

    pub fn contain_signal(&self, sig: Sig) -> bool {
        self.contains(SigSet::from_bits(1 << sig.index()).unwrap())
    }

    pub fn remove_signal(&mut self, sig: Sig) {
        self.remove(SigSet::from_bits(1 << sig.index()).unwrap())
    }
    pub fn revert(&mut self) -> SigSet {
        !*self
    }
}

impl From<Sig> for SigSet {
    fn from(sig: Sig) -> Self {
        Self::from_bits(1 << sig.index()).unwrap()
    }
}

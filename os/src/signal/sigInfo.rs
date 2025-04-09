use crate::task::Tid;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct SigInfo {
    pub signo: i32,              // 信号值
    pub code: i32,               // 信号产生原因  
    pub fields: SiField,         // 额外信息
}

impl SigInfo {
    pub fn new(signo: i32, code: i32, field: SiField) -> Self{
        Self {
            signo, 
            code,
            fields: field
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum SiField {
    None,
    kill {
        tid: Tid,
    },
}

#[allow(unused)]
impl SigInfo {
    /// sent by kill, sigsend, raise
    pub const USER: i32 = 0;
    /// sent by the kernel from somewhere
    pub const KERNEL: i32 = 0x80;
    /// sent by sigqueue
    pub const QUEUE: i32 = -1;
    /// sent by timer expiration
    pub const TIMER: i32 = -2;
    /// sent by real time mesq state change
    pub const MESGQ: i32 = -3;
    /// sent by AIO completion
    pub const ASYNCIO: i32 = -4;
    /// sent by queued SIGIO
    pub const SIGIO: i32 = -5;
    /// sent by tkill system call
    pub const TKILL: i32 = -6;
    /// sent by execve() killing subsidiary threads
    pub const DETHREAD: i32 = -7;
    /// sent by glibc async name lookup completion
    pub const ASYNCNL: i32 = -60;

    // SIGCHLD si_codes
    /// child has exited
    pub const CLD_EXITED: i32 = 1;
    /// child was killed
    pub const CLD_KILLED: i32 = 2;
    /// child terminated abnormally
    pub const CLD_DUMPED: i32 = 3;
    /// traced child has trapped
    pub const CLD_TRAPPED: i32 = 4;
    /// child has stopped
    pub const CLD_STOPPED: i32 = 5;
    /// stopped child has continued
    pub const CLD_CONTINUED: i32 = 6;
    pub const NSIGCHLD: i32 = 6;
}

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct LinuxSigInfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    pub _pad: [i32; 29],
    _align: [u64; 0],
}


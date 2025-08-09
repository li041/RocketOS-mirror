use alloc::vec::Vec;

use crate::{
    arch::trap::TrapContext,
    task::{current_task, Tid},
};

use super::{Sig, SigSet, SigStack};

#[derive(Clone, Copy, Default)]
#[repr(align(16))]
#[repr(C)]
pub struct SigRTFrame {
    pub flag: FrameFlags,      // 标志位
    pub ucontext: UContext,    // 上下文信息
    pub siginfo: LinuxSigInfo, // 信号信息
}

impl SigRTFrame {
    pub fn new(ucontext: UContext, siginfo: LinuxSigInfo) -> Self {
        SigRTFrame {
            flag: FrameFlags::rt_flag(),
            ucontext,
            siginfo,
        }
    }
}
#[derive(Clone, Copy, Default)]
#[repr(align(16))]
#[repr(C)]
pub struct SigFrame {
    pub flag: FrameFlags,       // 标志位
    pub sigcontext: SigContext, // 上下文信息
}

impl SigFrame {
    pub fn new(sigcontext: SigContext) -> Self {
        SigFrame {
            flag: FrameFlags::normal_flag(),
            sigcontext,
        }
    }
}

#[derive(Clone, Copy, Default)]
#[repr(align(16))]
#[repr(C)]
pub struct FrameFlags(usize);

impl FrameFlags {
    pub fn normal_flag() -> Self {
        FrameFlags(0x66666666)
    }

    pub fn rt_flag() -> Self {
        FrameFlags(0x77777777)
    }

    pub fn is_normal(&self) -> bool {
        self.0 == 0x66666666
    }

    pub fn is_rt(&self) -> bool {
        self.0 == 0x77777777
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct SigInfo {
    pub signo: i32,      // 信号值
    pub code: i32,       // 信号产生原因
    pub fields: SiField, // 额外信息
}

impl SigInfo {
    pub fn new(signo: i32, code: i32, field: SiField) -> Self {
        Self {
            signo,
            code,
            fields: field,
        }
    }

    pub fn prepare_kill(sig: Sig) -> Self {
        let task = current_task();
        let tid = task.tid() as i32;
        let uid = task.uid() as u32;
        Self {
            signo: sig.raw(),
            code: SigInfo::USER,
            fields: SiField::Kill { tid, uid },
        }
    }

    pub fn prepare_tgkill(sig: Sig) -> Self {
        let task = current_task();
        let tid = task.tid() as i32;
        let uid = task.uid() as u32;
        Self {
            signo: sig.raw(),
            code: SigInfo::TKILL,
            fields: SiField::Kill { tid, uid },
        }
    }
}

impl From<LinuxSigInfo> for SigInfo {
    fn from(lsi: LinuxSigInfo) -> Self {
        let fields = lsi.field();
        SigInfo {
            signo: lsi.si_signo,
            code: lsi.si_code,
            fields,
        }
    }
}

// Todo Timer child...
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum SiField {
    NULL,
    Kill {
        tid: i32,
        uid: u32,
    },
    Rt {
        tid: i32,
        uid: u32,
        sival_int: i32,
        sival_ptr: usize,
    },
    SIGCHILD {
        tid: i32, // 子进程的 TID
        uid: u32, // 子进程的 UID
        status: i32, // 子进程的退出状态
        // utime: u64, // 用户态 CPU 时间
        // stime: u64, // 内核态 CPU 时间
    }
}

impl SiField {
    pub fn to_array(&self) -> [i32; 29] {
        let mut arr = [0i32; 29];
        match self {
            SiField::NULL {} => {
                // 填充为 0
            }
            SiField::Kill { tid, uid } => {
                arr[1] = *tid;
                arr[2] = *uid as i32;
            }
            SiField::Rt {
                tid,
                uid,
                sival_int,
                sival_ptr,
            } => {
                arr[1] = *tid;
                arr[2] = *uid as i32;
                arr[3] = *sival_int;
                // 将 usize 拆成两个 i32 存储（在 64 位平台）
                let ptr = *sival_ptr as u64;
                arr[4] = (ptr & 0xFFFFFFFF) as i32;
                arr[5] = (ptr >> 32) as i32;
            }
            SiField::SIGCHILD {
                tid,
                uid,
                status,
                // utime,
                // stime,
            } => {
                arr[1] = *tid;
                arr[2] = *uid as i32;
                arr[3] = *status;
                // 将 u64 拆成两个 i32 存储（在 64 位平台）
                // arr[4] = (*utime & 0xFFFFFFFF) as i32;
                // arr[5] = (*utime >> 32) as i32;
                // arr[6] = (*stime & 0xFFFFFFFF) as i32;
                // arr[7] = (*stime >> 32) as i32;
            }
        }
        arr
    }
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

// LinuxSigInfo 是 Linux 内核中用于描述信号信息的结构体（用于符合 Linux ABI 的信号处理）
#[derive(Default, Copy, Clone, Debug)]
#[repr(align(16))]
#[repr(C)]
pub struct LinuxSigInfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    pub field: [i32; 29], // 对应field
}

impl LinuxSigInfo {
    pub fn field(&self) -> SiField {
        // field[0] 对应填充内容
        match self.si_code {
            SigInfo::QUEUE => SiField::Rt {
                tid: self.field[1],
                uid: self.field[2] as u32,
                sival_int: self.field[3],
                sival_ptr: (self.field[4] as usize) | ((self.field[5] as usize) << 32),
            },
            SigInfo::USER | SigInfo::TKILL => SiField::Kill {
                tid: self.field[1],
                uid: self.field[2] as u32,
            },
            _ => SiField::NULL,
        }
    }
}

impl From<SigInfo> for LinuxSigInfo {
    fn from(si: SigInfo) -> Self {
        // 先创建一个填充数组并把 fields 写进去
        let field = si.fields.to_array();
        LinuxSigInfo {
            si_signo: si.signo,
            si_errno: 0, // 如果有 errno 可设置
            si_code: si.code,
            field,
        }
    }
}

#[repr(C)]
#[repr(align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct UContext {
    // 标志位
    pub uc_flags: usize,
    /// 指向上文Ucontext
    pub uc_link: usize,
    // 当前上下文使用的栈信息,包含栈的基址、大小等信息
    pub uc_stack: SigStack,
    // 此上下文中阻塞的信号集
    pub uc_sigmask: SigSet,
    // don't know why, struct need to be exact the same with musl libc
    pub uc_sig: [usize; 16],
    // 保存具体机器状态的上下文信息，这是一个机器相关的表示，包含了处理器的寄存器状态等信息
    pub uc_mcontext: SigContext,
}

impl UContext {
    pub fn new(sig_context: SigContext, sig_mask: SigSet) -> Self {
        UContext {
            uc_flags: 0,
            uc_link: 0,
            uc_stack: SigStack::default(),
            uc_sigmask: sig_mask,
            uc_sig: [0; 16],
            uc_mcontext: sig_context,
        }
    }
}

#[repr(C)]
#[repr(align(16))]
#[derive(Clone, Copy, Debug, Default)]
#[cfg(target_arch = "riscv64")]
pub struct SigContext {
    pub sepc: usize,
    pub x: [usize; 32],
    pub last_a0: usize,
    pub kernel_tp: usize,
    pub mask: SigSet, // 记录原先的mask
}

#[cfg(target_arch = "riscv64")]
impl SigContext {
    pub fn init(trap_cx: &TrapContext, sig_mask: SigSet) -> Self {
        SigContext {
            x: trap_cx.x,
            sepc: trap_cx.sepc,
            last_a0: trap_cx.last_a0,
            kernel_tp: trap_cx.kernel_tp,
            mask: sig_mask,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
#[cfg(target_arch = "loongarch64")]
pub struct SigContext {
    pub r: [usize; 32],
    pub era: usize,
    pub last_a0: usize,
    pub kernel_tp: usize,
    pub mask: SigSet, // 记录原先的mask
}

#[cfg(target_arch = "loongarch64")]
impl SigContext {
    pub fn init(trap_cx: &TrapContext, sig_mask: SigSet) -> Self {
        SigContext {
            r: trap_cx.r,
            era: trap_cx.era,
            last_a0: trap_cx.last_a0,
            kernel_tp: trap_cx.kernel_tp,
            mask: sig_mask,
        }
    }
}

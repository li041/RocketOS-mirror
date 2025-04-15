use super::{Sig, SigSet};

// 用户栈设计如下
//     ----------------------------
//     |     用户栈中原本内容       |
//     ----------------------------
//     |                           |
//     |   sigInfo（当存在SigInfo） |
//     |                           |
//     -----------------------------
//     |                           |
//     |   UContext（当存在SigInfo）|
//     |                           |
//     -----------------------------
//     | SigContext（所有情况下存在）|
//     -----------------------------  <- user_sp
// 
//     注：SigContext是UContext中的一部分


/// 
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct SignalStack {
    pub ss_sp: usize,       // 栈底
    pub ss_flags: usize,    // 是否启用
    pub ss_size: usize,     // 栈大小
}

impl Default for SignalStack {
    fn default() -> Self {
        SignalStack { 
            ss_sp: 0,
            ss_flags: 0, 
            ss_size: 0, 
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UContext {
    // 保存具体机器状态的上下文信息，这是一个机器相关的表示，包含了处理器的寄存器状态等信息
    pub uc_mcontext: SigContext,
    // 标志位
    pub uc_flags: usize,
    /// 指向上文Ucontext
    pub uc_link: usize,
    // 此上下文中阻塞的信号集
    pub uc_sigmask: SigSet,
    // 当前上下文使用的栈信息,包含栈的基址、大小等信息
    pub uc_stack: SignalStack,  
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[cfg(target_arch = "riscv64")]
pub struct SigContext {
    pub x: [usize; 32],
    pub sepc: usize,
    pub last_a0: usize,
    pub kernel_tp: usize,
    pub mask: SigSet,   // 记录原先的mask
    pub info: usize,    // 标志是否存在SIGINFO
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[cfg(target_arch = "loongarch64")]
pub struct SigContext {
    pub r: [usize; 32],
    pub era: usize,
    pub last_a0: usize,
    pub kernel_tp: usize,
    pub mask: SigSet,   // 记录原先的mask
    pub info: usize,    // 标志是否存在SIGINFO
}
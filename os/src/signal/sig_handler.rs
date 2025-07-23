use alloc::vec::Vec;
use bitflags::bitflags;

use super::{Sig, SigSet, MAX_SIGNUM};

#[derive(Copy, Clone)]
// 信号处理器
pub struct SigHandler {
    actions: [SigAction; MAX_SIGNUM],
}

impl SigHandler {
    pub fn new() -> Self {
        use core::mem::MaybeUninit;
        let mut actions: [MaybeUninit<SigAction>; MAX_SIGNUM] = unsafe {
            MaybeUninit::uninit().assume_init()
        };
        for i in 0..MAX_SIGNUM {
            actions[i] = MaybeUninit::new(SigAction::new((i + 1).into()));
        }
        let actions = unsafe { core::mem::transmute::<_, [SigAction; MAX_SIGNUM]>(actions) };
        Self { actions }
    }

    pub fn get(&self, sig: Sig) -> SigAction {
        debug_assert!(sig.is_valid());
        self.actions[sig.index()]
    }

    pub fn update(&mut self, sig: Sig, new: SigAction) {
        debug_assert!(!sig.is_kill_or_stop());
        self.actions[sig.index()] = new;
    }

    pub fn reset(&mut self) {
        for (i, action) in self.actions.iter_mut().enumerate() {
            *action = SigAction::new(Sig::from((i + 1) as i32));
        }
    }
}

/// sa_handler 指定与 signum 关联的操作，可以是以下之一：
/// 1. SIG_DFL 表示默认操作
/// 2. SIG_IGN 表示忽略此信号
/// 3. 指向信号处理函数的指针。此函数接收信号编号作为其唯一参数。

pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;

// 处理操作
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct SigAction {
    pub sa_handler: usize,    // 信号处理函数指针
    pub flags: SigActionFlag, // 额外信息
    pub restorer: usize,      // 废物
    pub mask: SigSet,         // 位掩码，临时阻塞信号
}

impl SigAction {
    pub fn new(sig: Sig) -> Self {
        let sa_handler = SIG_DFL; // 默认处理方式
        let flags = SigActionFlag::default();
        let mask = SigSet::empty(); // 默认不阻塞任何信号
        let sig_action = Self {
            sa_handler,
            flags,
            restorer: 0,
            mask,
        };
        sig_action
    }

    pub fn is_user(&self) -> bool {
        let handler = self.sa_handler;
        (handler != SIG_IGN) && (handler != SIG_DFL)
    }
}

// 信号处理类型
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ActionType {
    Ignore,
    Term,
    Stop,
    Cont,
    Core,
}

impl ActionType {
    // 信号默认处理方式
    pub fn default(sig: Sig) -> Self {
        match sig {
            Sig::SIGABRT
            | Sig::SIGBUS
            | Sig::SIGFPE
            | Sig::SIGILL
            | Sig::SIGTRAP
            | Sig::SIGQUIT
            | Sig::SIGSEGV
            | Sig::SIGXCPU
            | Sig::SIGXFSZ
            | Sig::SIGSYS => ActionType::Core,
            Sig::SIGSTOP | Sig::SIGTSTP | Sig::SIGTTIN | Sig::SIGTTOU => ActionType::Stop,
            Sig::SIGCHLD | Sig::SIGURG | Sig::SIGWINCH => ActionType::Ignore,
            Sig::SIGCONT => ActionType::Cont,
            _ => ActionType::Term,
        }
    }
}

bitflags! {
    #[derive(Default, Copy, Clone, Debug)]
    pub struct SigActionFlag : u32 {
        const SA_NOCLDSTOP = 1;
        const SA_NOCLDWAIT = 2;
        const SA_SIGINFO = 4;
        const SA_ONSTACK = 0x08000000;
        const SA_RESTART = 0x10000000;
        const SA_NODEFER = 0x40000000;
        const SA_RESETHAND = 0x80000000;
        const SA_RESTORER = 0x04000000;
    }
}

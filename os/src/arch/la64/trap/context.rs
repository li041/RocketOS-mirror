use hashbrown::hash_map::Entry;

use crate::arch::PrMd;

#[repr(C)]
pub struct TrapContext {
    /// 通用寄存器, r[1]是ra, r[2]是tp, r[3]是sp, r[4]是a0
    pub r: [usize; 32],
    /// 记录触发例外时的特权级别、全局中断使能和监视点使能位, 用于例外返回时恢复处理器核的现场
    pub prmd: PrMd,
    /// 记录普通例外处理完毕后的返回地址
    pub era: usize,
}

impl TrapContext {
    pub fn get_sp(&self) -> usize {
        self.r[3]
    }
    pub fn set_ra(&mut self, ra: usize) {
        self.r[1] = ra;
    }
    pub fn set_tp(&mut self, tp: usize) {
        self.r[2] = tp;
    }
    pub fn set_sp(&mut self, sp: usize) {
        self.r[3] = sp;
    }
    pub fn set_a0(&mut self, a0: usize) {
        self.r[4] = a0;
    }
    pub fn set_pc(&mut self, pc: usize) {
        self.era = pc;
    }
    /// 初始化app的TrapContext
    /// argc, argv_base, envp_base, auxv_base分别放在r[4](a0), r[5], r[6], r[7]
    /// Todebug:
    pub fn app_init_trap_context(
        entry: usize,
        ustack_top: usize,
        argc: usize,
        argv_base: usize,
        envp_base: usize,
        auxv_base: usize,
    ) -> Self {
        let mut gerneral_regs = [0; 32];
        gerneral_regs[3] = ustack_top;
        gerneral_regs[4] = argc;
        gerneral_regs[5] = argv_base;
        gerneral_regs[6] = envp_base;
        gerneral_regs[7] = auxv_base;
        Self {
            r: gerneral_regs,
            prmd: *PrMd::read().set_pplv(3).set_pie(true),
            era: entry,
        }
    }
}

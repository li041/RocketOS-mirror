use alloc::sync::Arc;
use hashbrown::hash_map::Entry;

use crate::{arch::PrMd, task::{get_stack_top_by_sp, Task}};

#[repr(C)]
pub struct TrapContext {
    /// 通用寄存器, r[1]是ra, r[2]是tp, r[3]是sp, r[4]是a0
    pub r: [usize; 32],
    /// 记录触发例外时的特权级别、全局中断使能和监视点使能位, 用于例外返回时恢复处理器核的现场
    pub prmd: PrMd,
    /// 记录普通例外处理完毕后的返回地址
    pub era: usize,
    pub last_a0: usize,
    pub kernel_tp: usize,  // 将内核tp放在栈顶，也许会有助于debug
}

impl TrapContext {

    /* getter */
    pub fn get_sp(&self) -> usize {
        self.r[3]
    }
    pub fn get_a0(&self) -> usize {
        self.r[4]
    }

    /* setter */
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
    pub fn set_a1(&mut self, a1: usize) {
        self.r[5] = a1;
    }
    pub fn set_a2(&mut self, a2: usize) {
        self.r[6] = a2;
    }
    pub fn set_pc(&mut self, pc: usize) {
        self.era = pc;
    }
    pub fn set_kernel_tp(&mut self, kernel_tp: usize) {
        self.kernel_tp = kernel_tp;
    }
    pub fn restore_a0(&mut self) {
        self.r[4] = self.last_a0;
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
            last_a0: 0,
            kernel_tp: 0,
        }
    }
}

// 获取某一任务的trap_context
// 注: 除非是只想读，否则建议立即成对的调用save_trap_context
pub fn get_trap_context(task: &Arc<Task>) -> TrapContext {
    log::trace!("[get_trap_context] task{} fetch trap_cx", task.tid());
    let task_kstack_top = get_stack_top_by_sp(task.kstack());
    log::trace!("[get_trap_context] kstack top: {:#x}", task_kstack_top);
    let trap_cx_ptr = task_kstack_top - core::mem::size_of::<TrapContext>();
    let trap_cx_ptr = trap_cx_ptr as *mut TrapContext;
    log::trace!("[get_trap_context] trap_cx_ptr: {:x}", trap_cx_ptr as usize);
    unsafe { trap_cx_ptr.read_volatile() }
}

// 保存trap_context到某个任务的内核栈
pub fn save_trap_context(task: &Arc<Task>, cx: TrapContext) {
    log::trace!("[save_trap_context] task{} write trap_cx", task.tid());
    let task_kstack_top = get_stack_top_by_sp(task.kstack());
    log::trace!("[save_trap_context] kstack top: {:#x}", task_kstack_top);
    let trap_cx_ptr = task_kstack_top - core::mem::size_of::<TrapContext>();
    let trap_cx_ptr = trap_cx_ptr as *mut TrapContext;
    log::trace!("[save_trap_context] trap_cx_ptr: {:#x}", trap_cx_ptr as usize);
    unsafe { trap_cx_ptr.write_volatile(cx) }
}

#[allow(unused)]
pub fn dump_trap_context(task: &Arc<Task>) {
    let task_kstack_top = get_stack_top_by_sp(task.kstack());
    let trap_cx_ptr = task_kstack_top - core::mem::size_of::<TrapContext>();
    let trap_cx_ptr = trap_cx_ptr as *mut TrapContext;
    let trap_cx = unsafe { trap_cx_ptr.read_volatile() };
    log::error!("task {} trapcontext dump:", task.tid());
    log::error!("kstack top:\t{:x}", task_kstack_top);
    log::error!("trap_cx_ptr:\t{:x}", trap_cx_ptr as usize);
    log::error!("trap_cx size:\t{:x}", core::mem::size_of::<TrapContext>());
    log::error!("------------- task {} Dump -------------", task.tid());
    for (i, val) in trap_cx.r.iter().enumerate() {
        log::error!("{}:\t\t{:#018x}", reg_name(i), val);
    }
    log::error!("prmd:\t\tPrinting is difficult");
    log::error!("era:\t\t{:#018x}", trap_cx.era);
    log::error!("last_a0:\t{:#018x}", trap_cx.last_a0);
    log::error!("kernel_tp:\t{:#018x}", trap_cx.kernel_tp);
    log::error!("------------- task {} Dump -------------", task.tid());
}

pub fn reg_name(i: usize) -> &'static str {
    match i {
        0  => "zero",
        1  => "ra",
        2  => "tp",
        3  => "sp",
        4  => "a0",
        5  => "a1",
        6  => "a2",
        7  => "a3",
        8  => "a4",
        9  => "a5",
        10 => "a6",
        11 => "a7",
        12 => "t0",
        13 => "t1",
        14 => "t2",
        15 => "t3",
        16 => "t4",
        17 => "t5",
        18 => "t6",
        19 => "t7",
        20 => "t8",
        21 => "fp/s0",
        22 => "s1",
        23 => "s2",
        24 => "s3",
        25 => "s4",
        26 => "s5",
        27 => "s6",
        28 => "s7",
        29 => "s8",
        30 => "s9",
        31 => "s10",
        _ => "invalid",
    }
}

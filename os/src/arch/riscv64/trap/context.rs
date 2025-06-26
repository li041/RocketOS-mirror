use core::arch::asm;

use alloc::sync::Arc;
use alloc::vec::Vec;
use riscv::register::sstatus::{self, Sstatus, SPP};

use crate::mm::frame_alloc;
use crate::task::{get_stack_top_by_sp, Task};
use crate::{arch::config::PAGE_SIZE_BITS, arch::mm::map_temp};

/// Trap Context
/// 内核栈对齐到16字节
/// 2025-04-11 向trap_context中添加了kernel_tp字段, 为保持对齐, 顺便塞了一个last-a0来帮助signal实现SA_RESTART
#[repr(C)]
#[repr(align(16))]
pub struct TrapContext {
    /// 注意riscv和loongarch的通用寄存器不同
    /// 对于riscv, general regs[0..31], x[10]是a0, x[4]是tp, x[1]是ra, x[2]是sp
    /// 对于loongarch, general regs[0..31], r[4]是a0, r[2]是tp, x[1]是ra, r[3]是sp
    pub x: [usize; 32],
    /// CSR sstatus      
    /// 用于保存当前的特权级别, 在la中是PRMD
    pub sstatus: Sstatus,
    /// CSR sepc
    /// 用于保存当前的异常指令地址. 在la中时ERA
    pub sepc: usize,
    pub last_a0: usize,
    pub kernel_tp: usize, // 将内核tp放在栈顶，也许会有助于debug
}

impl TrapContext {
    /* getter */
    pub fn get_sp(&self) -> usize {
        self.x[2]
    }
    pub fn get_a0(&self) -> usize {
        self.x[10]
    }
    pub fn get_sepc(&self) -> usize {
        self.sepc
    }

    /* setter */
    pub fn set_ra(&mut self, ra: usize) {
        self.x[1] = ra;
    }
    /// set stack pointer to x_2 reg (sp)
    pub fn set_sp(&mut self, sp: usize) {
        self.x[2] = sp;
    }
    pub fn set_tp(&mut self, tp: usize) {
        self.x[4] = tp;
    }
    pub fn set_a0(&mut self, a0: usize) {
        self.x[10] = a0;
    }
    pub fn set_a1(&mut self, a1: usize) {
        self.x[11] = a1;
    }
    pub fn set_a2(&mut self, a2: usize) {
        self.x[12] = a2;
    }
    pub fn set_sepc(&mut self, sepc: usize) {
        self.sepc = sepc;
    }
    pub fn set_kernel_tp(&mut self, kernel_tp: usize) {
        self.kernel_tp = kernel_tp;
    }
    pub fn restore_a0(&mut self) {
        self.x[10] = self.last_a0;
    }

    /// init app context
    /// argc, argv_base, envp_base, auxv_base分别放在x[10], x[11], x[12], x[13]
    pub fn app_init_trap_context(
        entry: usize,
        ustack_top: usize,
        argc: usize,
        argv_base: usize,
        envp_base: usize,
        auxv_base: usize,
    ) -> Self {
        let mut sstatus = sstatus::read(); // CSR sstatus
        sstatus.set_spp(SPP::User); //previous privilege mode: user mode
        let mut gerneal_regs = [0; 32];
        gerneal_regs[10] = argc;
        gerneal_regs[11] = argv_base;
        gerneal_regs[12] = envp_base;
        gerneal_regs[13] = auxv_base;
        let mut cx = Self {
            x: gerneal_regs,
            sstatus,
            sepc: entry, // entry point of app
            last_a0: 0,
            kernel_tp: 0,
        };
        cx.set_sp(ustack_top); // app's user stack pointer
        cx // return initial Trap Context of app
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
    log::trace!(
        "[save_trap_context] trap_cx_ptr: {:#x}",
        trap_cx_ptr as usize
    );
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
    for (i, val) in trap_cx.x.iter().enumerate() {
        log::error!("{}:\t\t{:#018x}", reg_name(i), val);
    }
    log::error!("sstatus:\t{:#018x}", trap_cx.sstatus.bits());
    log::error!("sepc:\t\t{:#018x}", trap_cx.sepc);
    log::error!("last_a0:\t{:#018x}", trap_cx.last_a0);
    log::error!("kernel_tp:\t{:#018x}", trap_cx.kernel_tp);
    log::error!("------------- task {} Dump -------------", task.tid());
}

pub fn reg_name(i: usize) -> &'static str {
    match i {
        0 => "zero",
        1 => "ra",
        2 => "sp",
        3 => "gp",
        4 => "tp",
        5 => "t0",
        6 => "t1",
        7 => "t2",
        8 => "s0/fp",
        9 => "s1",
        10 => "a0",
        11 => "a1",
        12 => "a2",
        13 => "a3",
        14 => "a4",
        15 => "a5",
        16 => "a6",
        17 => "a7",
        18 => "s2",
        19 => "s3",
        20 => "s4",
        21 => "s5",
        22 => "s6",
        23 => "s7",
        24 => "s8",
        25 => "s9",
        26 => "s10",
        27 => "s11",
        28 => "t3",
        29 => "t4",
        30 => "t5",
        31 => "t6",
        _ => "invalid",
    }
}

// #[cfg(feature = "test")]
#[allow(unused)]
pub fn trap_cx_test() {
    let va: usize = 0xffff_ffff_ffff_f000;
    let frame = frame_alloc().unwrap().ppn;
    let vpn = (va >> PAGE_SIZE_BITS).into();
    let write_addr = va as *mut TrapContext;
    map_temp(vpn, frame);
    let regs = (0..32).collect::<Vec<usize>>().try_into().unwrap();
    let mut sstatus = sstatus::read();
    sstatus.set_spp(SPP::User);
    let cx = TrapContext {
        x: regs,
        sstatus: sstatus,
        sepc: 0x114,
        last_a0: 0,
        kernel_tp: 0,
    };
    unsafe {
        // write_addr.write(cx);
        *write_addr = cx;
    }
    let read_addr: u64 = 0xffff_ffff_ffff_f000;
    let mut read_cx: TrapContext = TrapContext::app_init_trap_context(0, 0, 0, 0, 0, 0);
    let mut read_cx_sstatus: usize;
    // 在这里使用汇编代码读取内核栈的值
    unsafe {
        // 把read_addr的值加载进t0
        asm!(
            "mv t0, {0}",
            in(reg) read_addr,
            options(nostack)
        );

        for i in 0..32 {
            // 读取x[0..31]的值
            asm!(
                "ld {0}, (t0)",
                "addi t0, t0, 8",
                out(reg) read_cx.x[i],
                options(nostack)
            );
        }
        asm!(
            "ld {0}, (t0)",
            "addi t0, t0, 8",
            out(reg) read_cx_sstatus,
            options(nostack)
        );
        asm!(
            "ld {0}, (t0)",
            "addi t0, t0, 8",
            out(reg) read_cx.sepc,
            options(nostack)
        );
    }
    debug_assert!(read_cx.x == regs);
    debug_assert!(read_cx.sstatus.bits() == read_cx_sstatus);
    debug_assert!(read_cx.sepc == 0x114);
    println!("trap_cx_test pass!");
}

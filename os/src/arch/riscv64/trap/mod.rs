use core::arch::global_asm;

pub use context::TrapContext;
use riscv::register::{
    satp,
    scause::{self, Exception, Interrupt, Trap},
    sepc, sie,
    sstatus::{self, SPP},
    stval, stvec,
    utvec::TrapMode,
};

use crate::{
    arch::mm::{handle_recoverable_page_fault, PageTable, VirtAddr},
    syscall::syscall,
    task::yield_current_task,
};

use super::timer::set_next_trigger;

pub mod context;
mod irq;

global_asm!(include_str!("trap.S"));

extern "C" {
    fn __trap_from_user();
    fn __trap_from_kernel();
    pub fn __return_to_user() -> !;
}

/// initialize CSR `stvec` as the entry of `__alltraps`
/// Tomodify: 先设置为trap_handler, 这样有page fault debug信息
#[cfg(target_arch = "riscv64")]
pub fn init() {
    let mut sstatus = sstatus::read();
    sstatus.set_spp(SPP::Supervisor);
    unsafe {
        stvec::write(__trap_from_kernel as usize, TrapMode::Direct);
    }
}

#[cfg(target_arch = "loongarch64")]
pub fn init() {
    unimplemented!();
}

/// timer interrupt enabled
#[cfg(target_arch = "riscv64")]
pub fn enable_timer_interrupt() {
    unsafe {
        sie::set_stimer();
    }
}
#[cfg(target_arch = "loongarch64")]
pub fn enable_timer_interrupt() {
    unimplemented!();
}

#[no_mangle]
/// handle an interrupt, exception, or system call from user space
pub fn trap_handler(cx: &mut TrapContext) {
    let scause = scause::read(); // get trap cause
    let stval = stval::read(); // get extra value
    match scause.cause() {
        Trap::Exception(Exception::UserEnvCall) => {
            cx.sepc += 4;
            cx.x[10] = syscall(
                cx.x[10], cx.x[11], cx.x[12], cx.x[13], cx.x[14], cx.x[15], cx.x[16], cx.x[17],
            ) as usize;
        }
        Trap::Exception(Exception::InstructionFault)
        | Trap::Exception(Exception::InstructionPageFault) => {
            let satp = satp::read().bits();
            let page_table = PageTable::from_token(satp);
            //page_table.dump_all();
            let pte = page_table.find_pte(VirtAddr::from(stval).floor()).unwrap();
            log::error!("pte: {:?}", pte);
            // page fault exit code
            panic!(
                "Instruction fault in application, bad addr = {:#x}, scause = {:?}, sepc = {:#x}",
                stval,
                scause.cause(),
                sepc::read()
            );
        }
        Trap::Exception(Exception::LoadPageFault)
        | Trap::Exception(Exception::LoadFault)
        | Trap::Exception(Exception::StorePageFault)
        | Trap::Exception(Exception::StoreFault) => {
            // stval is the faulting virtual address
            // recoverable page fault:
            // 1. fork COW area
            // 2. lazy allocation
            let va = VirtAddr::from(stval);
            let satp = satp::read().bits();
            let page_table = PageTable::from_token(satp);
            if handle_recoverable_page_fault(&page_table, va).is_err() {
                page_table.dump_all_user_mapping();
                panic!(
                    "Unrecoverble page fault in application, bad addr = {:#x}, scause = {:?}, sepc = {:#x}",
                    stval,
                    scause.cause(),
                    sepc::read()
                );
            }
            // we should jump back to the faulting instruction after handling the page fault
        }
        Trap::Interrupt(Interrupt::SupervisorTimer) => {
            set_next_trigger();
            yield_current_task();
        }
        _ => {
            let current_task = crate::task::current_task();
            log::error!("task {} trap", current_task.tid());
            panic!(
                "Unsupported trap {:?}, stval = {:#x}, sepc = {:#x}!",
                scause.cause(),
                stval,
                sepc::read()
            );
        }
    }
    return;
}

#[no_mangle]
pub fn kernel_trap_handler(cx: &mut TrapContext) {
    log::warn!("[kernel_trap_handler]");
    let scause = scause::read();
    match scause.cause() {
        Trap::Exception(Exception::Breakpoint) => {
            log::info!("Breakpoint at 0x{:x}", cx.sepc);
            cx.sepc += 2;
        }
        Trap::Exception(Exception::IllegalInstruction) => {
            log::error!("IllegalInstruction at 0x{:x}", cx.sepc);
            panic!("IllegalInstruction");
        }
        Trap::Exception(Exception::LoadPageFault)
        | Trap::Exception(Exception::LoadFault)
        | Trap::Exception(Exception::StorePageFault)
        | Trap::Exception(Exception::StoreFault) => {
            let satp = satp::read().bits();
            let page_table = PageTable::from_token(satp);
            page_table.dump_all_user_mapping();
            panic!(
                "page fault in kernel, bad addr = {:#x}, scause = {:?}, sepc = {:#x}",
                stval::read(),
                scause.cause(),
                sepc::read()
            );
        }
        Trap::Exception(Exception::InstructionPageFault) => {
            panic!(
                "Instruction page fault at 0x{:x}, badaddr = {:#x}",
                cx.sepc,
                stval::read()
            );
        }
        Trap::Exception(Exception::UserEnvCall) => {
            panic!("UserEnvCall from kernel!");
        }
        Trap::Interrupt(Interrupt::SupervisorTimer) => {
            log::warn!("SupervisorTimer in kernel mode")
        }
        _ => {
            panic!(
                "Unsupported trap {:?}, stval = {:#x}, sepc = {:#x}!",
                scause.cause(),
                stval::read(),
                sepc::read()
            );
        }
    }
    // return to the next instruction
}

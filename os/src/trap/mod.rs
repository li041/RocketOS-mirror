use core::arch::global_asm;

pub use context::TrapContext;
use riscv::register::{
    satp,
    scause::Interrupt,
    scause::{self, Exception, Trap},
    sepc, sie,
    sstatus::{self, SPP},
    stval, stvec,
    utvec::TrapMode,
};

use crate::{
    mm::page_table::PageTable, syscall::syscall, task::yield_current_task, timer::set_next_trigger,
};

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
pub fn init() {
    let mut sstatus = sstatus::read();
    sstatus.set_spp(SPP::Supervisor);
    unsafe {
        stvec::write(__trap_from_kernel as usize, TrapMode::Direct);
    }
}

/// timer interrupt enabled
pub fn enable_timer_interrupt() {
    unsafe {
        sie::set_stimer();
    }
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
        Trap::Exception(Exception::LoadPageFault)
        | Trap::Exception(Exception::LoadFault)
        | Trap::Exception(Exception::StorePageFault)
        | Trap::Exception(Exception::StoreFault) => {
            let satp = satp::read().bits();
            let page_table = PageTable::from_token(satp);
            let current_task = crate::task::current_task();
            page_table.dump_all_user_mapping();

            // page_table.dump_with_va(stval);
            let sepc = sepc::read();
            log::error!("task {} page fault", current_task.tid,);

            panic!(
                "page fault in application, bad addr = {:#x}, scause = {:?}, sepc = {:#x}",
                stval,
                scause.cause(),
                sepc
            );
        }
        Trap::Interrupt(Interrupt::SupervisorTimer) => {
            set_next_trigger();
            yield_current_task();
        }
        _ => {
            let current_task = crate::task::current_task();
            log::error!("task {} trap", current_task.tid,);
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

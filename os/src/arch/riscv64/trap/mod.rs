use core::arch::global_asm;

use alloc::sync::Arc;
use bitflags::bitflags;
use context::dump_trap_context;
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
    arch::mm::PageTable,
    fs::dentry::clean_dentry_cache,
    mm::VirtAddr,
    signal::{handle_signal, SiField, Sig, SigInfo},
    syscall::{errno::Errno, syscall},
    task::{current_task, handle_timeout, yield_current_task},
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

/// timer interrupt enabled
#[cfg(target_arch = "riscv64")]
pub fn enable_timer_interrupt() {
    unsafe {
        sie::set_stimer();
    }
}

#[derive(PartialEq)]
pub enum PageFaultCause {
    LOAD,
    STORE,
    EXEC,
}

impl From<scause::Trap> for PageFaultCause {
    fn from(e: scause::Trap) -> Self {
        match e {
            Trap::Exception(Exception::LoadPageFault) => PageFaultCause::LOAD,
            Trap::Exception(Exception::StorePageFault) => PageFaultCause::STORE,
            Trap::Exception(Exception::InstructionPageFault) => PageFaultCause::EXEC,
            _ => unreachable!(),
        }
    }
}

#[no_mangle]
/// handle an interrupt, exception, or system call from user space
pub fn trap_handler(cx: &mut TrapContext) {
    current_task().time_stat().record_ecall();
    let scause = scause::read(); // get trap cause
    let stval = stval::read(); // get extra value
    match scause.cause() {
        Trap::Exception(Exception::UserEnvCall) => {
            cx.sepc += 4;
            // cx.x[10] = syscall(
            //     cx.x[10], cx.x[11], cx.x[12], cx.x[13], cx.x[14], cx.x[15], cx.x[16], cx.x[17],
            // ). as usize;
            cx.x[10] = match syscall(
                cx.x[10], cx.x[11], cx.x[12], cx.x[13], cx.x[14], cx.x[15], cx.x[16], cx.x[17],
            ) {
                Ok(ret) => ret as usize,
                Err(e) => {
                    // 在开发阶段, 如果发生了EFAULT, 直接panic
                    // if e == Errno::EFAULT {
                    //     panic!("EFAULT in syscall");
                    // }
                    log::error!("syscall error: {:?}", e);
                    e as usize
                }
            }
        }
        Trap::Exception(Exception::InstructionFault) => {
            let satp = satp::read().bits();
            let page_table = PageTable::from_token(satp);
            page_table.dump_all_user_mapping();
            log::error!("Instruction fault at {:#x}", stval);
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
        | Trap::Exception(Exception::StorePageFault)
        | Trap::Exception(Exception::InstructionPageFault) => {
            // stval is the faulting virtual address
            // recoverable page fault:
            // 1. fork COW area
            // 2. lazy allocation
            let va = VirtAddr::from(stval);
            let casue = PageFaultCause::from(scause.cause());
            log::error!("page fault cause {:?}", scause.cause());
            let task = current_task();
            task.op_memory_set_mut(|memory_set| {
                if let Err(_e) = memory_set.handle_recoverable_page_fault(va, casue) {
                    // memory_set.page_table.dump_all_user_mapping();
                    // dump_trap_context(&current_task());
                    log::error!(
                        "Unrecoverble page fault in application, bad addr = {:#x}, scause = {:?}, sepc = {:#x}",
                        stval,
                        scause.cause(),
                        sepc::read()
                    );
                    task.receive_siginfo(
                        SigInfo::new(Sig::SIGSEGV.raw(), SigInfo::KERNEL, SiField::None),
                        false,
                    );
                }
            })
            // we should jump back to the faulting instruction after handling the page fault
        }
        Trap::Exception(Exception::LoadFault) | Trap::Exception(Exception::StoreFault) => {
            panic!(
                    "Unrecoverble page fault in application, bad addr = {:#x}, scause = {:?}, sepc = {:#x}",
                    stval,
                    scause.cause(),
                    sepc::read()
                );
        }
        Trap::Exception(Exception::Breakpoint) => {
            // panic!("Breakpoint at 0x{:x}", cx.sepc);
            cx.sepc += 4; // 跳过断点
        }
        Trap::Interrupt(Interrupt::SupervisorTimer) => {
            set_next_trigger();
            handle_timeout();
            clean_dentry_cache();
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
    handle_signal();
    current_task().time_stat().record_sret();
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

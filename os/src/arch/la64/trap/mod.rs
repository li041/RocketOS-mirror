use core::arch::global_asm;

use crate::{
    arch::{
        config::PAGE_SIZE_BITS,
        mm::PageTable,
        tlbrelo::{TLBRELo0, TLBRELo1},
        Interrupt, TLBRBadV, TLBREHi, PGDL, PWCL, TLBRERA,
    }, mm::VirtAddr, signal::{handle_signal, SiField, Sig, SigInfo}, syscall::{errno::Errno, syscall}, task::{current_task, handle_timeout, yield_current_task}
};

use super::{register, Exception, TIClr, Trap, ERA};

pub mod context;
pub mod timer;

use alloc::task;
use context::dump_trap_context;
pub use context::TrapContext;
use timer::set_next_trigger;

global_asm!(include_str!("trap.S"));

extern "C" {
    fn __trap_from_user();
    fn __trap_from_kernel();
    pub fn __return_to_user() -> !;
}

/// Todo: 没有细看
/// trap_handler也需要页对齐
pub fn init() {
    register::EEntry::read()
        .set_exception_entry(__trap_from_user as usize)
        .write();
    // 设置机器错误例外入口地址
    register::MErrEntry::read()
        .set_addr(trap_handler as usize)
        .write();
}

#[derive(PartialEq)]
pub enum PageFaultCause {
    LOAD,
    STORE,
    EXEC,
}

impl From<Trap> for PageFaultCause {
    fn from(e: Trap) -> Self {
        match e {
            Trap::Exception(Exception::PageInvalidLoad) => PageFaultCause::LOAD,
            Trap::Exception(Exception::PageInvalidStore) => PageFaultCause::STORE,
            Trap::Exception(Exception::PageInvalidFetch) => PageFaultCause::EXEC,
            Trap::Exception(Exception::PageModifyFault) => PageFaultCause::STORE,
            _ => unreachable!(),
        }
    }
}

/// 需要页对齐
#[link_section = ".text.trap_handler"]
#[no_mangle]
pub fn trap_handler(cx: &mut TrapContext) {
    let cause = register::EStat::read().cause();
    let badi = register::BadI::read().get_inst();
    match cause {
        Trap::Exception(Exception::Syscall) => {
            cx.era += 4;
            // cx.r[4] = syscall(
            //     cx.r[4], cx.r[5], cx.r[6], cx.r[7], cx.r[8], cx.r[9], cx.r[10], cx.r[11],
            // ) as usize;
            cx.r[4] = match syscall(
                cx.r[4],
                cx.r[5],
                cx.r[6],
                cx.r[7],
                cx.r[8],
                cx.r[9],
                cx.r[10],
                cx.r[11],
            ) {
                Ok(ret) => ret as usize,
                Err(e) => {
                    log::error!("syscall error: {:?}", e);
                    e as usize
                }
            };
        }
        Trap::Exception(Exception::PagePrivilegeIllegal)
        | Trap::Exception(Exception::PageNonReadableFault)
        | Trap::Exception(Exception::PageNonExecutableFault) 
        //     let task = current_task();
        //     let badv = register::BadV::read().get_vaddr();
        //     // let va = VirtAddr::from(badv);
        //     let pgdl_ppn = PGDL::read().get_base() >> PAGE_SIZE_BITS;
        //     let page_table = PageTable::from_token(pgdl_ppn);
        //     page_table.dump_all_user_mapping();
        //     page_table.dump_with_va(badv);

        //     log::error!(
        //         "[page_fault] pid: {}, type: {:?}, badv: {:#x}",
        //         task.tid(),
        //         cause,
        //         badv
        //     );
        //     panic!("page fault");
        // }
        | Trap::Exception(Exception::PageInvalidFetch)
        | Trap::Exception(Exception::PageInvalidStore)
        | Trap::Exception(Exception::PageModifyFault)
        | Trap::Exception(Exception::PageInvalidLoad) => {
            let badv = register::BadV::read().get_vaddr();
            log::error!("{:?} at {:#x}", cause, badv);
            let va = VirtAddr::from(badv);
            let cause = PageFaultCause::from(cause);
            let task = current_task();
            task.op_memory_set_mut(|memory_set| {
                if let Err(e) = memory_set.handle_recoverable_page_fault(va, cause) {
                        // memory_set.page_table.dump_all_user_mapping();
                        // dump_trap_context(&current_task());
                        log::error!(
                            "Unrecoverble page fault in application, bad addr = {:#x}, scause = {:?}, era = {:#x}",
                            badv,
                            register::EStat::read().cause(),
                            ERA::read().get_pc()
                        );
                        task.receive_siginfo(
                            SigInfo::new(Sig::SIGSEGV.raw(), SigInfo::KERNEL, SiField::None),
                            false,
                        );
                }
            });
        }
        // Trap::Exception(Exception::InstructionNonDefined)
        // | Trap::Exception(Exception::InstructionPrivilegeIllegal) => {
        //   todo!()
        // }
        Trap::Interrupt(Interrupt::Timer) => {
            TIClr::read().clear_timer().write();
            set_next_trigger();
            handle_timeout();
            yield_current_task();
        }
        _ => {
            panic!(
                "Unhandled exception: {:?}, era: {:#x}, bad instruction: {:#x}",
                cause,
                register::BadV::read().get_vaddr(),
                badi
            );
        }
    }
    handle_signal();
    return;
}

#[no_mangle]
pub fn kernel_trap_handler(cx: &mut TrapContext) {
    todo!()
}

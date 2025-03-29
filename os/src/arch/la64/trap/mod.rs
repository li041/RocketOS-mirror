use core::arch::global_asm;

use crate::{
    arch::{
        config::PAGE_SIZE_BITS,
        mm::{PageTable, VirtAddr},
        tlbrelo::{TLBRELo0, TLBRELo1},
        Interrupt, TLBRBadV, TLBREHi, PGDL, PWCL, TLBRERA,
    },
    syscall::syscall,
    task::{current_task, yield_current_task},
};

use super::{register, Exception, TIClr, Trap, ERA};

mod context;
pub mod timer;

use alloc::task;
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

/// 需要页对齐
#[link_section = ".text.trap_handler"]
#[no_mangle]
pub fn trap_handler(cx: &mut TrapContext) {
    let cause = register::EStat::read().cause();
    let badi = register::BadI::read().get_inst();
    match cause {
        Trap::Exception(Exception::Syscall) => {
            cx.era += 4;
            cx.r[4] = syscall(
                cx.r[4], cx.r[5], cx.r[6], cx.r[7], cx.r[8], cx.r[9], cx.r[10], cx.r[11],
            ) as usize;
        }
        Trap::Exception(Exception::PagePrivilegeIllegal)
        | Trap::Exception(Exception::PageInvalidFetch)
        | Trap::Exception(Exception::PageInvalidStore)
        | Trap::Exception(Exception::PageInvalidLoad)
        | Trap::Exception(Exception::PageModifyFault)
        | Trap::Exception(Exception::PageNonReadableFault)
        | Trap::Exception(Exception::PageNonExecutableFault) => {
            let task = current_task();
            let badv = register::BadV::read().get_vaddr();
            // let va = VirtAddr::from(badv);
            let pgdl_ppn = PGDL::read().get_base() >> PAGE_SIZE_BITS;
            let page_table = PageTable::from_token(pgdl_ppn);
            page_table.dump_all_user_mapping();
            page_table.dump_with_va(badv);

            // log::error!(
            //     "[page_fault] {:?}, {:?}, {:?}, {:?}, {:?}, {:?}",
            //     TLBRERA::read(),
            //     TLBRBadV::read(),
            //     TLBREHi::read(),
            //     TLBRELo0::read(),
            //     TLBRELo1::read(),
            //     PWCL::read(),
            // );
            log::error!(
                "[page_fault] pid: {}, type: {:?}, badv: {:#x}",
                task.tid(),
                cause,
                badv
            );
            panic!("page fault");
        }
        // Trap::Exception(Exception::InstructionNonDefined)
        // | Trap::Exception(Exception::InstructionPrivilegeIllegal) => {
        //   todo!()
        // }
        Trap::Interrupt(Interrupt::Timer) => {
            TIClr::read().clear_timer().write();
            set_next_trigger();
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
    return;
}

#[no_mangle]
pub fn kernel_trap_handler(cx: &mut TrapContext) {
    todo!()
}

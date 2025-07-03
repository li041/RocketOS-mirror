use core::arch::global_asm;

use crate::{
     arch::{mm::{copy_from_user, copy_to_user}, trap::mem_access::Instruction, BadV, CrMd, EStat, Interrupt, TLBRBadV, TLBRPrMd, PGD, PGDH, PGDL, PWCH, PWCL, TLBRERA}, fs::dentry::clean_dentry_cache, mm::VirtAddr, signal::{handle_signal, SiField, Sig, SigInfo}, syscall::syscall, task::{current_task, handle_timeout, yield_current_task}
};

use super::{register, Exception, TIClr, Trap, ERA};

pub mod context;
pub mod timer;
pub mod mem_access;

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
                if let Err(_e) = memory_set.handle_recoverable_page_fault(va, cause) {
                        memory_set.page_table.dump_all_user_mapping();
                        // dump_trap_context(&current_task());
                        log::error!(
                            "Unrecoverble page fault in application, bad addr = {:#x}, scause = {:?}, era = {:#x}",
                            badv,
                            register::EStat::read().cause(),
                            ERA::read().get_pc()
                        );
                        task.receive_siginfo(
                            SigInfo::new(Sig::SIGSEGV.raw(), SigInfo::KERNEL, SiField::Kill { tid: current_task().tid() }),
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
            clean_dentry_cache();
            yield_current_task();
        }
        Trap::Exception(Exception::AddressNotAligned) => {
            let pc = cx.era;
            let mut ins = 0u32;
            copy_from_user(pc as *const u32 , &mut ins as *mut u32, 1);
            let ins = Instruction::from(ins);
            let op = ins.get_op_code();
            // 解析op_code
            if op.is_err() {
                panic!("Unsupported OpCode! Instruction: {:?} ", ins);
            }
            let op = op.unwrap();
            let addr = BadV::read().get_vaddr();
            let sz = op.get_size();
            let is_aligned: bool = addr % sz == 0;
            if !is_aligned {
                assert!([2, 4, 8].contains(&sz));
                // 手动模拟未对齐的内存访问
                if op.is_store() { // 存储操作
                    let rd_num = ins.get_rd_num();
                    let mut rd = if rd_num != 0 { cx.r[rd_num] } else { 0 };
                    for i in 0..sz {
                        let mut seg = rd as u8;
                        copy_to_user((addr + i) as *mut u8, &mut seg as *mut u8, 1);
                        rd >>= 8;
                    }
                } else { // 读取操作
                    let mut rd = 0usize;
                    for i in (0..sz).rev() {
                        rd <<= 8;
                        let mut read_byte = 0u8;
                        copy_from_user((addr + 1) as *const u8, &mut read_byte as *mut u8, 1);
                        rd |= read_byte as usize;
                        //debug!("{:#x}, {:#x}", rd, read_byte);
                    }
                    if !op.is_unsigned_ld() {
                        match sz {
                            2 => rd = (rd as u16) as i16 as isize as usize,
                            4 => rd = (rd as u32) as i32 as isize as usize,
                            8 => rd = rd,
                            _ => unreachable!(),
                        }
                    }
                }
                cx.era += 4;
            }
            if cx.era == pc {
                panic!(
                    "Failed to execute the command. Bad Instruction: {}, PC:{}",
                    unsafe { *(cx.era as *const u32) },
                    pc
                );
            }
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
    let cause = register::EStat::read().cause();
    let sub_code = EStat::read().exception_sub_code();
    match cause {
        Trap::TLBReFill => {
            println!(
                "[trap_handler] {:?}\n\
                 [trap_handler] {:?}\n\
                 [trap_handler] {:?}\n\
                 [trap_handler] {:?}\n\
                 [trap_handler] {:?}\n\
                 [trap_handler] {:?}\n\
                 [trap_handler] {:?}",
                CrMd::read(),
                TLBRERA::read(),
                TLBRBadV::read(),
                TLBRPrMd::read(),
                PGD::read(),
                PWCL::read(),
                PWCH::read()
            );
        }
        Trap::Exception(Exception::AddressNotAligned) => {
            let pc = cx.era;
            loop {
                let ins = Instruction::from(pc as *const Instruction);
                let op = ins.get_op_code();
                // 解析op_code
                if op.is_err() {
                    break;
                }
                let op = op.unwrap();
                let addr = BadV::read().get_vaddr();
                let sz = op.get_size();
                let is_aligned: bool = addr % sz == 0;
                if is_aligned {
                    break;
                }
                assert!([2, 4, 8].contains(&sz));
                // 手动模拟未对齐的内存访问
                if op.is_store() { // 存储操作
                    let rd_num = ins.get_rd_num();
                    let mut rd = if rd_num != 0 { cx.r[rd_num] } else { 0 };
                    for i in 0..sz {
                        unsafe { ((addr + i) as *mut u8).write_unaligned(rd as u8) };
                        rd >>= 8;
                    }
                } else { // 读取操作
                    let mut rd = 0;
                    for i in (0..sz).rev() {
                        rd <<= 8;
                        let read_byte =
                            (unsafe { ((addr + i) as *mut u8).read_unaligned() } as usize);
                        rd |= read_byte;
                        //debug!("{:#x}, {:#x}", rd, read_byte);
                    }
                    if !op.is_unsigned_ld() {
                        match sz {
                            2 => rd = (rd as u16) as i16 as isize as usize,
                            4 => rd = (rd as u32) as i32 as isize as usize,
                            8 => rd = rd,
                            _ => unreachable!(),
                        }
                    }
                    let rd_num = ins.get_rd_num();
                    if rd_num != 0 {
                        cx.r[rd_num] = rd;
                    }
                }
                cx.era += 4;
                break;
            }
            if cx.era == pc {
                panic!(
                    "Failed to execute the command. Bad Instruction: {}, PC:{}",
                    unsafe { *(cx.era as *const u32) },
                    pc
                );
            }
            return;
        }
        _ => {}
    }
    panic!(
        "a trap {:?} from kernel! bad addr = {:#x}, bad instruction = {:#x}, pc:{:#x}, (subcode:{}), PGDH: {:?}, PGDL: {:?}, {}",
        cause,
        get_bad_addr(),
        get_bad_instruction(),
        get_bad_ins_addr(),
        sub_code,
        PGDH::read(),
        PGDL::read(),
        if let Trap::Exception(ty) = cause {
            match ty {
                Exception::AddressError => match sub_code {
                    0 => "ADdress error Exception for Fetching instructions",
                    1 => "ADdress error Exception for Memory access instructions",
                    _ => "Unknown",
                },
                _ => "",
            }
        } else {
            ""
        }
    );
}

pub fn get_exception_cause() -> Trap {
    register::EStat::read().cause()
}

pub fn get_bad_ins_addr() -> usize {
    match get_exception_cause() {
        Trap::Interrupt(_) | Trap::Exception(_) => register::ERA::read().get_pc(),
        Trap::TLBReFill => register::TLBRERA::read().get_pc(),
        Trap::MachineError(_) => register::MErrEra::read().get_pc(),
        Trap::Unknown => 0,
    }
}
pub fn get_bad_addr() -> usize {
    match get_exception_cause() {
        Trap::Exception(_) => register::BadV::read().get_vaddr(),
        Trap::TLBReFill => register::TLBRBadV::read().get_vaddr(),
        _ => 0,
    }
}
pub fn get_bad_instruction() -> usize {
    register::BadI::read().get_inst()
}
use alloc::vec::Vec;

use super::kstack;
use crate::{
    config::PAGE_SIZE_BITS,
    mm::{frame_allocator::frame_alloc, page_table::map_temp},
    trap::__return_to_user,
};

use core::convert::TryInto;

//要压入内核栈, 对齐到16字节
#[derive(Copy, Clone)]
#[repr(C)]
#[repr(align(16))]
pub struct TaskContext {
    /// return address ( e.g. __return_to_user ) of __switch ASM function
    ra: usize,
    /// tp, thread pointer of current task
    /// tp寄存器指向Task结构体, 进而获取KernelStack, 可以在swtich中修改栈顶指针
    tp: usize,
    /// callee-saved registers: s0 ~ s11
    s: [usize; 12],
    /// satp: page table
    satp: usize,
}

impl TaskContext {
    /// init task context
    pub fn zero_init() -> Self {
        Self {
            ra: 0,
            tp: 0,
            s: [0; 12],
            satp: 0,
        }
    }
    /// Create initial TaskContext
    pub fn app_init_task_context(tp: usize, satp: usize) -> Self {
        Self {
            ra: __return_to_user as usize,
            tp: tp,
            s: [0; 12],
            satp: satp,
        }
    }
    pub fn set_tp(&mut self, tp: usize) {
        self.tp = tp;
    }
}

pub fn check_task_context_in_kernel_stack(sp: usize) {
    log::warn!("[check_task_context_in_kernel_stack]");
    let task_cx_ptr = sp as *const TaskContext;
    let task_cx = unsafe { task_cx_ptr.read() };
    log::warn!("task_kernel_stack: {:#x}", sp);
    log::warn!("task satp: {:#x}", task_cx.satp);
}

// 未完成
pub fn task_cx_test() {
    let va: usize = 0xffff_ffff_ffff_f000;
    let frame = frame_alloc().unwrap().ppn;
    let vpn = (va >> PAGE_SIZE_BITS).into();
    let write_addr = va as *mut TaskContext;
    map_temp(vpn, frame);
    let regs = (0..12).collect::<Vec<usize>>().try_into().unwrap();
    let cx = TaskContext {
        ra: 0x114514,
        tp: 0x1919810,
        s: regs,
        satp: 0x810,
    };
    unsafe {
        // write_addr.write(cx);
        *write_addr = cx;
    }
    let read_addr: u64 = 0xffff_ffff_ffff_f000;
    let mut read_cx: TaskContext = TaskContext::app_init_task_context(0, 0);
    // assert_eq!(read_cx.ra, 0x114);
    // assert_eq!(read_cx.s, regs);
}

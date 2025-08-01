use alloc::sync::Arc;

use crate::arch::{config::PAGE_SIZE_BITS, trap::__return_to_user};

use super::task::Task;

//要压入内核栈, 对齐到16字节
#[cfg(target_arch = "riscv64")]
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

#[cfg(target_arch = "riscv64")]
impl TaskContext {
    /// Create initial TaskContext
    pub fn app_init_task_context(tp: usize, satp: usize) -> Self {
        Self {
            ra: __return_to_user as usize,
            tp: tp,
            s: [0; 12],
            satp: satp,
        }
    }

    pub fn idle_init_task_context(tp: usize) -> Self {
        use crate::{mm::KERNEL_SATP, sched::idle_task};

        Self {
            ra: idle_task as usize,
            tp: tp,
            s: [0; 12],
            satp: *KERNEL_SATP,
        }
    }
}

#[cfg(target_arch = "riscv64")]
#[allow(unused)]
pub fn check_task_context_in_kernel_stack(sp: usize) {
    log::warn!("[check_task_context_in_kernel_stack]");
    let task_cx_ptr = sp as *const TaskContext;
    let task_cx = unsafe { task_cx_ptr.read() };
    log::warn!("task_kernel_stack: {:#x}", sp);
    log::warn!("task satp: {:#x}", task_cx.satp);
}

#[cfg(target_arch = "loongarch64")]
#[derive(Copy, Clone)]
#[repr(C)]
#[repr(align(16))]
pub struct TaskContext {
    /// return address ( e.g. __return_to_user ) of __switch ASM function
    ra: usize,
    /// tp, thread pointer of current task
    /// tp寄存器指向Task结构体, 进而获取KernelStack, 可以在swtich中修改栈顶指针
    tp: usize,
    // 这里为了与riscv64保持一致, 也是s[12], 实际loonarch64是s0 ~ s8, 然后s9保存fp 也是s[1    // 这里为了与riscv64保持一致, 也是s[12], 实际loonarch64是s0 ~ s8, 然后s9保存fp 也是s[1    // 这里为了与riscv64保持一致, 也是s[12], 实际loonarch64是s0 ~ s8, 然后s9保存fp 也是s[1    // 这里为了与riscv64保持一致, 也是s[12], 实际loonarch64是s0 ~ s8, 然后s9保存$fp($r22)
    /// callee-saved registers: s0 ~ s11
    s: [usize; 12],
    // pgdl是页表的物理地址, 不是ppn, 而page_table.token()返回的是ppn
    pgdl: usize,
}

#[cfg(target_arch = "loongarch64")]
impl TaskContext {
    /// Create initial TaskContext
    /// 注意pgdl中存放的是页表的物理地址, 不是ppn, 而page_table.token()返回的是ppn
    pub fn app_init_task_context(tp: usize, pgdl_ppn: usize) -> Self {
        Self {
            ra: __return_to_user as usize,
            tp: tp,
            s: [0; 12],
            pgdl: pgdl_ppn << PAGE_SIZE_BITS,
        }
    }

    pub fn idle_init_task_context(tp: usize) -> Self {
        use crate::{mm::KERNEL_SATP, sched::idle_task};

        Self {
            ra: idle_task as usize,
            tp: tp,
            s: [0; 12],
            pgdl: *KERNEL_SATP << PAGE_SIZE_BITS,
        }
    }
}

// 向指定任务内核栈中保存当前task_cx
pub fn write_task_cx(task: Arc<Task>) {
    let task_tp = Arc::as_ptr(&task) as usize;
    let task_pgtbl_token = task.op_memory_set(|m| m.token());
    let task_cx = TaskContext::app_init_task_context(task_tp, task_pgtbl_token);
    let task_cx_ptr = task.kstack() as *mut TaskContext;
    unsafe {
        task_cx_ptr.write_volatile(task_cx);
    }
}

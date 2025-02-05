use crate::trap::__return_to_user;

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
    /// Create initial TaskContext
    pub fn app_init_task_context(tp: usize, satp: usize) -> Self {
        Self {
            ra: __return_to_user as usize,
            tp: tp,
            s: [0; 12],
            satp: satp,
        }
    }
}

#[allow(unused)]
pub fn check_task_context_in_kernel_stack(sp: usize) {
    log::warn!("[check_task_context_in_kernel_stack]");
    let task_cx_ptr = sp as *const TaskContext;
    let task_cx = unsafe { task_cx_ptr.read() };
    log::warn!("task_kernel_stack: {:#x}", sp);
    log::warn!("task satp: {:#x}", task_cx.satp);
}

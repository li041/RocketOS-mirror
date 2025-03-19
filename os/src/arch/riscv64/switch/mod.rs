use core::arch::global_asm;

global_asm!(include_str!("switch.S"));

extern "C" {
    pub fn __switch(next_task_kernel_stack: usize);
}

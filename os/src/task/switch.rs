use core::arch::{asm, global_asm};

use super::{kstack::KernelStack, Task};
use alloc::sync::Arc;
use lazy_static::lazy_static;

global_asm!(include_str!("switch.S"));

extern "C" {
    pub fn __switch(next_task_kernel_stack: usize);
}

lazy_static! {
    pub static ref IDLE_TASK: Arc<Task> = {
        let idle_task = Arc::new(Task::zero_init());
        // 将tp寄存器指向idle_task
        unsafe {
            // 注意这里需要对Arc指针先解引用再取`IDLE_TASK`地址
            // 两种方法都可以, Arc::as_ptr或者直接解引用然后引用
            asm!("mv tp, {}", in(reg) &(*idle_task) as *const _ as usize);

        }
        idle_task
    };
}

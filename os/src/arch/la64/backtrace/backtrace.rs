use alloc::{string::String, sync::Arc, vec::Vec};

use crate::{
    arch::backtrace::symbol::lookup_symbol,
    task::{current_task, get_stack_top_by_sp, Task, KSTACK_SIZE},
};

// 嵌套深度
const MAX_BACKTRACE_DEPTH: usize = 32;

/// 打印当前任务的调用栈信息
#[allow(unused)]
pub fn dump_backtrace() {
    println!("/************** Backtrace Start **************/");

    let mut fp: usize;
    unsafe {
        core::arch::asm!("move {}, $fp", out(reg) fp);
    }

    let task = current_task();
    let stack_top = get_stack_top_by_sp(task.kstack());
    let stack_base = stack_top - KSTACK_SIZE;

    println!("task{}:", task.tid());
    println!("Stack: ({:#x}, {:#x}]", stack_base, stack_top);

    let mut frame_count = 0;

    while frame_count < MAX_BACKTRACE_DEPTH {
        // fp 中存储的是上一个栈帧的sp所指位置
        let (ra, last_sp) = unsafe { read_frame_info(fp) };
        if let Some(name) = lookup_symbol(ra - 1) {
            // 这里减1是为了防止右侧开区间被计算
            print_frame_info_with_symbol(frame_count, ra, name);
        } else {
            print_frame_info(frame_count, fp, ra);
        }

        if last_sp < stack_base || last_sp >= stack_top {
            break;
        }

        fp = last_sp;
        frame_count += 1;
    }

    if frame_count >= MAX_BACKTRACE_DEPTH {
        println!(
            "Backtrace truncated at maximum depth of {}",
            MAX_BACKTRACE_DEPTH
        );
    }

    println!("/*************** Backtrace End ***************/");
}

// 获取当前任务栈帧数
// return (frame_count, vec<ra>)
pub fn count_frames(task: Arc<Task>) -> (usize, Vec<usize>) {
    let mut fp: usize;
    unsafe {
        core::arch::asm!("move {}, $fp", out(reg) fp);
    }

    let stack_top = get_stack_top_by_sp(task.kstack());
    let stack_base = stack_top - KSTACK_SIZE;

    let mut frame_count = 1; // 从当前帧开始计数
    let mut ra_vec = Vec::new();

    while frame_count < MAX_BACKTRACE_DEPTH {
        // fp 中存储的是上一个栈帧的sp所指位置
        let (ra, last_sp) = unsafe { read_frame_info(fp) };
        ra_vec.push(ra);

        if last_sp < stack_base || last_sp >= stack_top {
            break;
        }

        fp = last_sp;
        frame_count += 1;
    }

    (frame_count, ra_vec)
}

/// 从 fp 指针中提取 ra 和上一个 sp 所在位置
unsafe fn read_frame_info(last_sp: usize) -> (usize, usize) {
    let ra = *((last_sp - 8) as *const usize);
    let last_fp = *((last_sp - 16) as *const usize);
    (ra, last_fp)
}

/// 打印栈帧信息(不带符号解析)
fn print_frame_info(frame_num: usize, fp: usize, ra: usize) {
    println!("  #{}: fp = {:#x}, ra = {:#x}", frame_num, fp, ra);
}

/// 打印栈帧信息(带符号解析)
fn print_frame_info_with_symbol(frame_num: usize, ra: usize, name: String) {
    println!("  #{}: ra:{:#x}, {:?}", frame_num, ra, name);
}

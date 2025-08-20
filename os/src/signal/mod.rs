mod sig_frame;
mod sig_handler;
mod sig_stack;
mod sig_struct;

use core::arch::global_asm;

use alloc::{sync::Arc, task};
pub use sig_frame::*;
pub use sig_handler::*;
pub use sig_stack::*;
pub use sig_struct::*;

#[cfg(target_arch = "riscv64")]
use crate::arch::trap;
use crate::{
    arch::{
        mm::copy_to_user,
        trap::{
            context::{dump_trap_context, get_trap_context, save_trap_context},
            TrapContext,
        },
    },
    mm::VirtAddr,
    syscall::errno::Errno,
    task::{
        continue_task, current_task, get_stack_top_by_sp, kernel_exit, remove_task, schedule,
        stop_task, Task,
    },
};

// 用户栈构造如下
//     ----------------------------
//     |     用户栈中原本内容       |
//     ----------------------------
//     |                           |
//     |   sigInfo（当存在SigInfo） |
//     |                           |
//     -----------------------------
//     |                           |
//     |   UContext（当存在SigInfo）|
//     |                           |
//     -----------------------------
//     | SigContext（所有情况下存在）|
//     -----------------------------  <- user_sp

// 1. 检查是否有信号触发
// 2. 检查是否需要内核处理
// 3. 决定 signal handler 应该运行在哪个栈（SignalStack / 普通栈）
// 4. 决定向用户栈中塞入sigcontext还是ucontext
// 5. 修改内核栈顶trap信息
pub fn handle_signal() {
    log::trace!("[handle_signal]");
    use crate::arch::trampoline::sigreturn_trampoline;
    let task = current_task();
    // 检查是否有信号触发
    while let Some((sig, sig_info)) =
        task.op_sig_pending_mut(|pending| pending.fetch_signal(SigSet::all()))
    {
        let old_mask = task.mask();
        log::info!(
            "[handle_signal] task{} is handling signal {}",
            task.tid(),
            sig.raw()
        );
        let action = task.op_sig_handler(|handler| handler.get(sig));
        let mut trap_cx = get_trap_context(&task);

        // Todo: 中断处理，测试
        #[cfg(target_arch = "riscv64")]
        if task.re_start()   // 优先判断是否可以重启以恢复原有状态
            && action.flags.contains(SigActionFlag::SA_RESTART)
            && task.is_interrupted() && action.sa_handler != SIG_DFL && action.sa_handler != SIG_IGN
        {
            // 回到用户调用ecall的指令
            log::warn!("[handle_signal] handle SA_RESTART");
            trap_cx.set_sepc(trap_cx.sepc - 4);
            trap_cx.restore_a0(); // 从last_a0中恢复a0
        }
        // 处理ERESTARTSYS且含有SA_RESTART
        else if (trap_cx.get_a0() == Errno::ERESTARTSYS as usize)
            && action.flags.contains(SigActionFlag::SA_RESTART)
            && action.sa_handler != SIG_DFL
            && action.sa_handler != SIG_IGN
        {
            log::warn!("[handle_signal] handle ERESTARTSYS");
            trap_cx.set_sepc(trap_cx.sepc - 4);
            trap_cx.restore_a0();
        }
        // 处理ERESTARTSYS时未注册且为默认信号时
        else if (trap_cx.get_a0() == Errno::ERESTARTSYS as usize)
            && !action.is_user()
            && sig.get_default_type() == ActionType::Ignore
        {
            log::warn!("[handle_signal] handle ERESTARTSYS");
            trap_cx.set_sepc(trap_cx.sepc - 4);
            trap_cx.restore_a0();
        }
        // 处理ERESTARTSYS且不含有SA_RESTART
        else if (trap_cx.get_a0() == Errno::ERESTARTSYS as usize) {
            log::warn!("[handle_signal] handle ERESTARTNOINTR");
            trap_cx.set_a0(Errno::EINTR as usize);
        }

        // 回到用户调用ecall的指令
        #[cfg(target_arch = "loongarch64")]
        if task.re_start()   // 优先判断是否可以重启以恢复原有状态
            && action.flags.contains(SigActionFlag::SA_RESTART)
            && task.is_interrupted() && action.sa_handler != SIG_DFL && action.sa_handler != SIG_IGN
        {
            log::warn!("[handle_signal] handle SA_RESTART");
            trap_cx.set_sepc(trap_cx.era - 4);
            trap_cx.restore_a0(); // 从last_a0中恢复a0
        }
        // 处理ERESTARTSYS
        else if (trap_cx.get_a0() == Errno::ERESTARTSYS as usize)
            && action.flags.contains(SigActionFlag::SA_RESTART)
            && action.sa_handler != SIG_DFL
            && action.sa_handler != SIG_IGN
        {
            log::warn!("[handle_signal] handle ERESTARTSYS");
            trap_cx.set_sepc(trap_cx.era - 4); // 恢复到系统调用前
            trap_cx.restore_a0();
        }
        // 处理ERESTARTSYS时未注册且为默认信号时
        else if (trap_cx.get_a0() == Errno::ERESTARTSYS as usize)
            && !action.is_user()
            && sig.get_default_type() == ActionType::Ignore
        {
            log::warn!("[handle_signal] handle ERESTARTSYS");
            trap_cx.set_sepc(trap_cx.era - 4);
            trap_cx.restore_a0();
        }
        // 处理ERESTARTSYS且不含有SA_RESTART
        else if (trap_cx.get_a0() == Errno::ERESTARTSYS as usize) {
            log::warn!("[handle_signal] handle ERESTARTNOINTR");
            trap_cx.set_a0(Errno::EINTR as usize);
        }

        if task.is_interrupted() {
            task.set_uninterrupted();
        }
        //log::info!("[handle_signal] kstack_top: {:x}", kstack);
        // 非用户定义
        if !action.is_user() {
            if action.sa_handler == SIG_IGN {
                log::warn!("[handle_signal] Ignoring signal: {:?}", sig);
                break;
            }
            match sig.get_default_type() {
                ActionType::Ignore => {}
                ActionType::Term => terminate(task, sig),
                ActionType::Stop => stop(task, sig),
                ActionType::Cont => cont(task, sig),
                ActionType::Core => core(task, sig),
            }
        }
        // 用户定义
        else {
            // 不包含SA_NODEFER时需要在信号掩码中防止重复sig
            log::warn!("[handle_signal] Using user {:?} signal handlers", sig);
            log::debug!(
                "[handle_signal] sa_handler: {:#x}, sigActionFlags: {:x}",
                action.sa_handler,
                action.flags
            );

            if !action.flags.contains(SigActionFlag::SA_NODEFER) {
                log::warn!("[handle_signal] no SA_NODEFER");
                task.op_sig_pending_mut(|pending| pending.add_mask(sig));
            }

            // 加上action中的mask
            task.op_sig_pending_mut(|pending| {
                pending.add_mask_sigset(action.mask);
                log::debug!("[handle_signal] current mask = {:?}", pending.mask);
            });

            // 决定 signal handler 应该运行在哪个栈（SignalStack / 普通栈）
            // user_sp：当前用户栈（信号栈）位置
            let mut user_sp = (trap_cx.get_sp() - 15) & !0x0f; // 向下对齐到16字节
            log::debug!("[handle_signal] origin user stack {:#x}", user_sp);
            if action.flags.contains(SigActionFlag::SA_ONSTACK) {
                let mut sig_stack = task.sigstack();
                if sig_stack.ss_flags == 0 || sig_stack.ss_flags == SS_ONSTACK {
                    log::warn!("[handle_signal] handle SA_ONSTACK");
                    user_sp = (sig_stack.ss_sp + sig_stack.ss_size - 15) & !0x0f; // 向下对齐到16字节
                    sig_stack.ss_flags = SS_ONSTACK;
                    task.set_sigstack(sig_stack);
                }
            }

            // 向用户栈中仅塞入SigInfo和UContext
            if action.flags.contains(SigActionFlag::SA_SIGINFO) {
                // 信号处理函数定义方式
                // handler(int sig, siginfo_t *info, void *ucontext)
                log::warn!("[handle_signal] handle SA_SIGINFO");

                // 制作sigcontext
                let sig_context = SigContext::init(&trap_cx, old_mask);

                // 创建siginfo
                user_sp -= core::mem::size_of::<LinuxSigInfo>();
                let siginfo_sp = user_sp; // siginfo_sp：塞入siginfo后的用户栈位置
                trap_cx.set_a1(siginfo_sp);
                log::debug!("[handle_signal] a1 = {:#x}", siginfo_sp);
                let linux_siginfo = sig_info.into();

                // 创建ucontext
                user_sp = user_sp - core::mem::size_of::<UContext>();
                let ucontext_sp = user_sp; // ucontext_sp：塞入ucontext后的用户栈位置
                trap_cx.set_a2(ucontext_sp);
                log::debug!("[handle_signal] a2 = {:#x}", ucontext_sp);
                let ucontext = UContext::new(sig_context, old_mask);

                // 创建sigframe
                user_sp = user_sp - core::mem::size_of::<FrameFlags>();
                let frame_flags_sp = user_sp; // frame_flags_sp：塞入frame_flags后的用户栈位置
                let sig_rt_frame = SigRTFrame::new(ucontext, linux_siginfo);
                log::debug!("[handle_signal] frame_flags_sp = {:#x}", frame_flags_sp);
                if let Err(err) = copy_to_user(frame_flags_sp as *mut SigRTFrame, &sig_rt_frame, 1)
                {
                    panic!("[handle_signal] copy_to_user failed: {:?}", err);
                }
            }
            // 向用户栈中仅塞入sigcontext
            // 信号处理函数定义方式 void (*sa_handler)(int)
            else {
                user_sp = user_sp - core::mem::size_of::<SigFrame>();
                let user_sig_frame_ptr = user_sp as *mut SigFrame;
                let sig_context = SigContext::init(&trap_cx, old_mask);
                let sig_frame = SigFrame::new(sig_context);
                log::debug!("[handle_signal] frame: {:#x}", user_sp);
                if let Err(err) = copy_to_user(user_sig_frame_ptr, &sig_frame, 1) {
                    panic!("[handle_signal] copy_to_user failed: {:?}", err);
                }
            }
            // 修改sepc,ra,sp,a0
            trap_cx.set_ra(sigreturn_trampoline as usize);
            trap_cx.set_sp(user_sp);
            trap_cx.set_sepc(action.sa_handler);
            trap_cx.set_a0(sig.raw() as usize);
            log::debug!("[handle_signal] ra = {:x}", sigreturn_trampoline as usize);
            log::debug!("[handle_signal] user stack = {:x}", user_sp);
            log::debug!("[handle_signal] sa_handler = {:x}", action.sa_handler);
            log::debug!("[handle_signal] a0 = {}", sig.raw() as usize);
            save_trap_context(&task, trap_cx);
        }
        break;
    }
}

fn terminate(task: Arc<Task>, sig: Sig) {
    // 将信号放入低7位 (第8位是core dump标志,在gdb调试崩溃程序中用到)
    kernel_exit(task, sig.raw() as i32 & 0x7F);
    schedule();
}

fn stop(task: Arc<Task>, sig: Sig) {
    task.op_parent(|parent| {
        // 向父进程发送SIGCHLD
        if let Some(parent) = parent {
            log::warn!(
                "[stop] task{} stopped, send SIGCHLD to parent",
                current_task().tid()
            );
            let siginfo = SigInfo::new(
                Sig::SIGCHLD.raw(),
                crate::signal::SigInfo::CLD_STOPPED,
                SiField::SIGCHILD {
                    tid: task.tid() as i32,
                    uid: task.uid(),
                    status: sig.raw() as i32,
                    // utime: task.time_stat().user_time().as_ticks() as u64,
                    // stime: task.time_stat().sys_time().as_ticks() as u64,
                },
            );
            parent.upgrade().unwrap().receive_siginfo(siginfo, false);
        }
    });
    stop_task();
}

fn cont(task: Arc<Task>, sig: Sig) {
    task.op_parent(|parent| {
        // 向父进程发送SIGCHLD
        if let Some(parent) = parent {
            log::warn!(
                "[cont] task{} continued, send SIGCHLD to parent",
                current_task().tid()
            );
            let siginfo = SigInfo::new(
                Sig::SIGCHLD.raw(),
                crate::signal::SigInfo::CLD_CONTINUED,
                SiField::SIGCHILD {
                    tid: task.tid() as i32,
                    uid: task.uid(),
                    status: sig.raw() as i32,
                    // utime: task.time_stat().user_time().as_ticks() as u64,
                    // stime: task.time_stat().sys_time().as_ticks() as u64,
                },
            );
            parent.upgrade().unwrap().receive_siginfo(siginfo, false);
        }
    });
}

// Todo: 转储任务崩溃时的内存快照
// 目前只有page fault恢复失败时, 内核会发送SIGSEGV信号
fn core(task: Arc<Task>, sig: Sig) {
    // task.op_memory_set(|memory_set| {
    //     memory_set.page_table.dump_all_user_mapping();
    // });
    task.close_thread();
    // 将信号放入低7位 (第8位是core dump标志,在gdb调试崩溃程序中用到)
    kernel_exit(task, sig.raw() as i32 & 0x7F | 0x80);
    // panic!("core dump: {:?}", sig); //调试使用
    log::error!("[core] core dump: {:?}", sig);
    schedule();
}

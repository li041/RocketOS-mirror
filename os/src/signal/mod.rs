mod sigHandler;
mod sigInfo;
mod sigStack;
mod sigStruct;

use core::arch::global_asm;

use alloc::sync::Arc;
pub use sigHandler::*;
pub use sigInfo::*;
pub use sigStack::*;
pub use sigStruct::*;

use crate::{
    arch::{mm::copy_to_user, trap::{context::{get_trap_context, save_trap_context}, TrapContext}}, mm::VirtAddr, task::{current_task, get_stack_top_by_sp, kernel_exit, remove_task, switch_to_next_task, Task}
};

// 1. 检查是否有信号触发
// 2. 检查是否需要内核处理
// 3. 决定 signal handler 应该运行在哪个栈（SignalStack / 普通栈）
// 4. 决定向用户栈中塞入sigcontext还是ucontext
// 5. 修改内核栈顶trap信息

pub fn handle_signal() {
    use crate::arch::trampoline::sigreturn_trampoline;

    let task = current_task();
    // 检查是否有信号触发
    while let Some((sig, sigInfo)) = task.op_sig_pending_mut(|pending| pending.fetch_signal()) {
        let old_mask = task.mask();
        log::info!("[handle_signal] task{} is handling signal {}",task.tid(), sig.raw());
        let action = task.op_sig_handler(|handler| handler.get(sig));
        let mut trap_cx = get_trap_context(&task);
        
        // Todo: 中断处理，测试
        #[cfg(target_arch = "riscv64")]
        if action.flags.contains(SigActionFlag::SA_RESTART) {
            // 回到用户调用ecall的指令
            trap_cx.set_pc(trap_cx.sepc - 4);
            trap_cx.restore_a0();   // 从last_a0中恢复a0
            log::warn!("[handle_signal] handle SA_RESTART");
        }

        //log::info!("[handle_signal] kstack_top: {:x}", kstack);
        // 非用户定义
        if !action.is_user() {
            match sig.get_default_type() {
                ActionType::Ignore => {}
                ActionType::Term => terminate(task, sig),
                ActionType::Stop => stop(),
                ActionType::Cont => cont(),
                ActionType::Core => core(),
            }
        }
        // 用户定义
        else {
            // 不包含SA_NODEFER时需要在信号掩码中防止重复sig
            log::warn!("[handle_signal] {:?} Using user signal handlers", sig);
            log::info!(
                "[handle_signal] sa_handler: {:x}, sigActionFlags: {:x}",
                action.sa_handler,
                action.flags
            );
            if !action.flags.contains(SigActionFlag::SA_NODEFER) {
                task.op_sig_pending_mut(|pending| {pending.add_mask(sig)});
            }

            // 加上action中的mask
            task.op_sig_pending_mut(|pending| {
                    pending.add_mask_sigset(action.mask);
                    log::info!("[handle_signal] current mask = {:?}", old_mask);
            });
            
            // 决定 signal handler 应该运行在哪个栈（SignalStack / 普通栈）
            // user_sp：当前用户栈（信号栈）位置
            let sig_stack = task.sigstack();
            let mut user_sp = if action.flags.contains(SigActionFlag::SA_ONSTACK) {
                if let Some(sig_stack) = sig_stack {
                    sig_stack.ss_sp
                } else {
                    trap_cx.get_sp()
                }
            } else {
                trap_cx.get_sp()
            };

            // 向用户栈中仅塞入SigInfo和UContext
            // void (*sa_sigaction)(int, siginfo_t *, void *ucontext);
            if action.flags.contains(SigActionFlag::SA_SIGINFO) {
                // Todo
                // // 信号处理函数定义方式
                // trap_cx.x[12] = ucontext_sp;
                // let mut siginfo = LinuxSigInfo::default();
                // siginfo.si_signo = sig.raw() as _;
                // siginfo.si_code = sigInfo.code;
                // // siginfo_sp：塞入siginfo后的用户栈位置
                // user_sp -= core::mem::size_of::<LinuxSigInfo>();
                // let siginfo_sp = user_sp;
                // let siginfo_ptr = siginfo_sp as *mut LinuxSigInfo;
                // unsafe { siginfo_ptr.write(siginfo) };
                // trap_cx.x[11] = siginfo_sp;
                                // ucontext_sp：塞入ucontext后的用户栈位置
                // user_sp = (user_sp - core::mem::size_of::<UContext>()) & !0xf;
                // let ucontext_sp = user_sp;
                // let ucontext_ptr = ucontext_sp as *mut UContext;
                // // 创建ucontext 保存栈顶trap
                // let ucontext = UContext {
                //     uc_flags: 0,
                //     uc_link: 0,
                //     uc_stack: sig_stack.unwrap_or_default(),
                //     uc_sigmask: old_mask,
                //     uc_mcontext: MContext {
                //         x: trap_cx.x,
                //         fpstate: [0; 66],
                //         sepc: trap_cx.sepc,
                //     },
                // };
                // // 保存当前 ucontext
                // unsafe { ucontext_ptr.write(ucontext) };
                // task.set_sig_ucontext(ucontext_ptr as usize);
            }

            // 向用户栈中仅塞入sigcontext 
            // 信号处理函数定义方式 void (*sa_handler)(int)
            else {
                let sig_context_size = core::mem::size_of::<SigContext>();
                log::info!("[handle_signal] origin user stack {:x}", user_sp);
                user_sp = user_sp - ((sig_context_size + 15) & !0xF);
                log::info!("[handle_signal] SigContext size {:x}", sig_context_size);
                log::info!("[handle_signal] current user stack {:x}", user_sp);
                let user_sig_context_ptr = user_sp as *mut SigContext;
                #[cfg(target_arch = "riscv64")]
                let sig_context = SigContext {
                    x: trap_cx.x,
                    sepc: trap_cx.sepc,
                    mask: old_mask,
                    info: 0,
                };
                #[cfg(target_arch = "loongarch64")]
                let sig_context = SigContext {
                    r: trap_cx.r,
                    era: trap_cx.era,
                    mask: old_mask,
                    info: 0,
                };
                let sig_context_ptr = &sig_context as *const SigContext;
                if let Err(err) = copy_to_user(user_sig_context_ptr, sig_context_ptr,1){
                    panic!("[handle_signal] copy_to_user failed: {}", err);
                }
                // 修改栈顶trap的a0
                trap_cx.set_a0(sig.raw() as usize);
                log::info!("[handle_signal] a0 = {}", sig.raw() as usize);
            }

            // 修改sepc,ra,sp
            trap_cx.set_ra(sigreturn_trampoline as usize);
            trap_cx.set_sp(user_sp);
            trap_cx.set_pc(action.sa_handler);
            log::info!("[handle_signal] ra = {:x}", sigreturn_trampoline as usize);
            log::info!("[handle_signal] user stack = {:x}", user_sp);
            log::info!("[handle_signal] sa_handler = {:x}", action.sa_handler);
            save_trap_context(&task, trap_cx);
        }
        break;
    }
}

fn terminate(task: Arc<Task>, sig: Sig) {
    task.close_thread();
    // 将信号放入低7位 (第8位是core dump标志,在gdb调试崩溃程序中用到)
    kernel_exit(task, sig.raw() as i32 & 0x7F);
    switch_to_next_task();
}
// Todo:
fn stop() {}
fn cont() {}
fn core() {}

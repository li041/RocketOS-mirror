use alloc::sync::Arc;

use crate::{
    signal::{ActionType, Sig, SigAction, SigInfo, SigSet, SIG_IGN},
    task::{add_task, dump_scheduler, dump_wait_queue, manager::delete_wait},
};

use super::task::Task;

impl Task {
    // 接收信号
    pub fn receive_siginfo(self: &Arc<Task>, siginfo: SigInfo, thread_level: bool) {
        log::info!(
            "[receive_siginfo] task{} receive signal:{}",
            self.tid(),
            siginfo.signo
        );
        // 在任务收到信号时，若满足可中断条件，则触发信号中断
        match thread_level {
            // 线程级信号
            true => {
                self.op_sig_pending_mut(|pending| {
                    pending.add_signal(siginfo);
                });
                if self.check_interrupt() {
                    self.op_sig_pending_mut(|pending| {
                        pending.set_interrupted();
                    });
                    delete_wait(self.tid());
                    self.set_ready();
                    add_task(self.clone());
                }
            }
            // 进程级信号
            false => {
                self.op_thread_group_mut(|tg| {
                    // Todo: 线程组线程阻塞问题
                    for task in tg.iter() {
                        task.op_sig_pending_mut(|pending| {
                            pending.add_signal(siginfo);
                        });
                        if task.check_interrupt() {
                            task.op_sig_pending_mut(|pending| {
                                pending.set_interrupted();
                            });
                            delete_wait(task.tid());
                            task.set_ready();
                            add_task(task.clone());
                        }
                    }
                })
            }
        }
    }

    pub fn is_interrupted(&self) -> bool {
        self.op_sig_pending_mut(|sig_pending| sig_pending.is_interrupted())
    }

    pub fn set_uninterrupted(&self) {
        self.op_sig_pending_mut(|sig_pending| sig_pending.set_uninterrupted());
    }
    pub fn have_signals(&self) -> bool {
        !self.op_sig_pending_mut(|sig_pending| sig_pending.pending.is_empty())
    }

    // 可中断条件：
    // 1. 任务处于interruptable
    // 2. 有信号待处理
    // 3. 信号没有被掩码阻塞
    // 4. 信号的处理程序非忽略
    pub fn check_interrupt(&self) -> bool {
        let mut searched_sig = SigSet::all();
        if !self.is_interruptable() {
            return false;
        }
        while let Some(sig) = self.op_sig_pending_mut(|pending| pending.find_signal(searched_sig)) {
            let action = self.op_sig_handler(|handler| handler.get(sig));
            if action.sa_handler == SIG_IGN {
                searched_sig.remove(sig.into());
                continue;
            } else {
                return true;
            }
        }
        false
    }

    pub fn cancel_restart(&self) {
        self.op_sig_pending_mut(|pending| {
            pending.cancel_restart();
        });
    }

    pub fn can_restart(&self) -> bool {
        self.op_sig_pending_mut(|pending| pending.need_restart())
    }
}

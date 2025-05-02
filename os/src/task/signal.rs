use crate::signal::{ActionType, Sig, SigAction, SigInfo, SigSet};

use super::task::Task;

impl Task {
    // 接收信号
    pub fn receive_siginfo(&self, siginfo: SigInfo, thread_level: bool) {
        log::info!(
            "[receive_siginfo] task{} receive signal:{}",
            self.tid(),
            siginfo.signo
        );
        match thread_level {
            // 线程级信号
            true => {
                self.op_sig_pending_mut(|pending| {
                    pending.add_signal(siginfo);
                });
            }
            // 进程级信号
            false => {
                self.op_thread_group_mut(|tg| {
                    // Todo: 线程组线程阻塞问题
                    for task in tg.iter() {
                        task.op_sig_pending_mut(|pending| {
                            pending.add_signal(siginfo);
                        })
                    }
                })
            }
        }
    }
    
    pub fn have_signals(&self) -> bool {
        !self.op_sig_pending_mut(|sig_pending| sig_pending.pending.is_empty())
    }

    pub fn check_interrupt(&self) -> bool {
        let mut searched_sig = SigSet::all();
        while let Some(sig) = self.op_sig_pending_mut(|pending| pending.find_signal(searched_sig)) {
            let action = self.op_sig_handler(|handler| handler.get(sig));
            if action.is_user() {
                return true;
            } else {
                match sig.get_default_type(){
                    ActionType::Ignore => {
                        searched_sig.remove_signal(sig);
                        continue;
                    }
                    _ => {
                        return true;
                    }
                    
                }
            }
        }
        false    
    }
}

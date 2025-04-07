use super::{current_task, kernel_exit, Task, Tid};
use crate::{arch::switch, mutex::SpinNoIrqLock};
use alloc::{collections::vec_deque::VecDeque, sync::Arc};
use bitflags::bitflags;
use core::fmt::Debug;
use lazy_static::lazy_static;

// 初始化调度器
lazy_static! {
    pub static ref SCHEDULER: SpinNoIrqLock<Scheduler> = SpinNoIrqLock::new(Scheduler::new());
}

/// 添加新任务到就绪队列
pub fn add_task(task: Arc<Task>) {
    // log::debug!("[add_task] ready_queue len:{:?}, added task: {:?}",
    // SCHEDULER.lock().ready_queue.len(), task.tid());
    //assert_eq!(2 , Arc::strong_count(&task));
    assert!(task.is_ready());
    SCHEDULER.lock().add(task);
}
/// 从就绪队列中取出队首任务
pub fn fetch_task() -> Option<Arc<Task>> {
    SCHEDULER.lock().fetch()
}

/// 阻塞任务
pub fn block_task(task: Arc<Task>) {
    assert!(task.is_blocked());
    SCHEDULER.lock().block(task);
}

/// 从就绪队列中移除任务
pub fn remove_task(tid: Tid) {
    SCHEDULER.lock().remove(tid);
}

/// 从就绪队列中移除线程组
pub fn remove_thread_group(tgid: Tid) {
    SCHEDULER.lock().remove_thread_group(tgid);
}

/// 解除任务阻塞
// pub fn unblock_task_wait_on_tid(waken_task: Arc<Task>) {
//     SCHEDULER.lock().unblock_tasks_wait_on_tid(waken_task);
// }

// 由caller保证原任务的状态切换
// 不能从自己切换到自己, 否则会死Idle循环
// used by sys_exit
#[no_mangle]
pub fn switch_to_next_task() {
    // 1. 切换内核栈
    // 2. 切换Processor的current
    // 3. 切换tp(在__switch中完成)
    // 4. 切换memory set(在__switch中完成)

    // 获得下一个任务的内核栈
    // 可以保证`Ready`的任务`Task`中的内核栈与实际运行的sp保持一致
    if let Some(next_task) = fetch_task() {
        let next_task_kernel_stack = next_task.kstack();
        log::info!("next_task_kernel_stack: {:#x}", next_task_kernel_stack);
        // check_task_context_in_kernel_stack(next_task_kernel_stack);
        // 切换Processor的current
        crate::task::processor::PROCESSOR
            .lock()
            .switch_to(next_task);
        unsafe {
            switch::__switch(next_task_kernel_stack);
        }
    }
}

// 不能从自己切换到自己
// 注意调用者要释放原任务的锁, 否则会死锁
#[no_mangle]
pub fn yield_current_task() {
    // 注意下面这行日志不要删, 是loongarch64 release跑起来的神奇小咒语
    log::trace!("[yield_current_task] enter");
    let task = current_task();
    if let Some(next_task) = fetch_task() {
        task.set_ready();
        // 将当前任务加入就绪队列
        add_task(task);
        // 获得下一个任务的内核栈
        // 可以保证`Ready`的任务`Task`中的内核栈与实际运行的sp保持一致
        let next_task_kernel_stack = next_task.kstack();
        log::debug!(
            "[yield_current_task] next task {}, next task kstack {:#x}",
            next_task.tid(),
            next_task_kernel_stack
        );
        // check_task_context_in_kernel_stack(next_task_kernel_stack);
        // 切换Processor的current
        crate::task::processor::PROCESSOR
            .lock()
            .switch_to(next_task);
        unsafe {
            switch::__switch(next_task_kernel_stack);
        }
    }
    // 如果没有下一个任务, 则继续执行当前任务
}

// 目前支持由waitpid阻塞的进程
#[no_mangle]
pub fn blocking_and_run_next() {
    let task = current_task();
    if let Some(next_task) = fetch_task() {
        task.set_blocked();
        log::warn!("task {} is blocked", task.tid());
        // 将当前任务加入阻塞队列
        block_task(task);
        // 获得下一个任务的内核栈
        // 可以保证`Ready`的任务`Task`中的内核栈与实际运行的sp保持一致
        let next_task_kernel_stack = next_task.kstack();
        // check_task_context_in_kernel_stack(next_task_kernel_stack);
        // 切换Processor的current
        crate::task::processor::PROCESSOR
            .lock()
            .switch_to(next_task);
        unsafe {
            switch::__switch(next_task_kernel_stack);
        }
    }
}

// FIFO Task scheduler
pub struct Scheduler {
    ready_queue: VecDeque<Arc<Task>>,
    // Todo:阻塞操作
    blocked_queue: VecDeque<Arc<Task>>,
}

impl Scheduler {
    /// 创建一个空调度器
    pub fn new() -> Self {
        Self {
            ready_queue: VecDeque::new(),
            blocked_queue: VecDeque::new(),
        }
    }
    /// 添加任务到调度器就绪队列
    pub fn add(&mut self, task: Arc<Task>) {
        self.ready_queue.push_back(task);
    }
    /// 取出调度器就绪队列队首任务
    pub fn fetch(&mut self) -> Option<Arc<Task>> {
        self.ready_queue.pop_front()
    }
    /// 从调度器就绪队列中移除任务
    pub fn remove(&mut self, tid: Tid) {
        self.ready_queue.retain(|task| task.tid() != tid);
    }
    /// 从调度器就绪队列中移除线程组
    pub fn remove_thread_group(&mut self, tgid: Tid) {
        self.ready_queue.retain(|task| task.tgid() != tgid);
    }
    /// 阻塞任务(暂且没用)
    pub fn block(&mut self, task: Arc<Task>) {
        self.blocked_queue.push_back(task);
    }
    // pub fn unblock_tasks_wait_on_tid(&mut self, waken_task: Arc<Task>) {
    //     for task in self.blocked_queue.iter() {
    //         if Arc::ptr_eq(task, &waken_task) {
    //             task.inner.lock().status = TaskStatus::Ready;
    //             self.ready_queue.push_back(task.clone());
    //             log::warn!("unblock task: {:?}", task.tid);
    //             break;
    //         }
    //     }
    // }
}

bitflags! {
    pub struct WaitOption: i32 {
        /// 这个选项用于非阻塞挂起。当与 wait 或 waitpid 一起使用时，如果没有任何子进程状态改变，
        /// 这些系统调用不会阻塞父进程，而是立即返回。在 Linux 中，如果没有子进程处于可等待的状态，wait 或 waitpid 会返回 0。
        const WNOHANG = 1;
        /// 这个选项告诉 wait 或 waitpid 也报告那些已经停止（stopped），但尚未终止的子进程的状态。默认情况下，
        /// 只有当子进程终止时，它们的结束状态才会被报告。如果子进程被某种信号（如 SIGSTOP 或 SIGTSTP）停止，
        /// 并且父进程没有设置 WUNTRACED 选项，那么父进程将不会感知到子进程的停止状态，直到子进程被继续执行或终止。
        const WUNTRACED = 1 << 1;
        /// 当子进程被停止后又继续执行时，使用这个选项。如果子进程之前被一个停止信号（如SIGSTOP 或 SIGTSTP）暂停，
        /// 然后通过继续信号（如 SIGCONT）被继续执行，那么 wait 或 waitpid 将报告这个子进程的状态，
        /// 即使它还没有终止。这允许父进程知道子进程已经从停止状态恢复。
        const WCONTINUED = 1 << 3;
    }
}
impl Debug for WaitOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        write!(f, "WaitOption {{")?;
        if self.contains(WaitOption::WNOHANG) {
            if first {
                write!(f, "WNOHANG")?;
                first = false;
            } else {
                write!(f, " | WNOHANG")?;
            }
        }
        if self.contains(WaitOption::WUNTRACED) {
            if first {
                write!(f, "WUNTRACED")?;
                first = false;
            } else {
                write!(f, " | WUNTRACED")?;
            }
        }
        if self.contains(WaitOption::WCONTINUED) {
            if first {
                write!(f, "WCONTINUED")?;
            } else {
                write!(f, " | WCONTINUED")?;
            }
        }
        write!(f, "}}")
    }
}

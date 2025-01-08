use core::fmt::Debug;

use alloc::{collections::vec_deque::VecDeque, sync::Arc};

use crate::{mutex::SpinNoIrqLock, task::switch};

use super::{Task, TaskStatus};
use bitflags::bitflags;
use lazy_static::lazy_static;

// FIFO Task scheduler
pub struct Scheduler {
    ready_queue: VecDeque<Arc<Task>>,
    blocked_queue: VecDeque<Arc<Task>>,
}

impl Scheduler {
    ///Creat an empty TaskManager
    pub fn new() -> Self {
        Self {
            ready_queue: VecDeque::new(),
            blocked_queue: VecDeque::new(),
        }
    }
    ///Add a task to `TaskManager`
    pub fn add(&mut self, task: Arc<Task>) {
        self.ready_queue.push_back(task);
    }
    ///Remove the first task and return it,or `None` if `TaskManager` is empty
    pub fn fetch(&mut self) -> Option<Arc<Task>> {
        self.ready_queue.pop_front()
    }
    pub fn block(&mut self, task: Arc<Task>) {
        self.blocked_queue.push_back(task);
    }
    pub fn unblock_tasks_wait_on_tid(&mut self, waken_task: Arc<Task>) {
        for task in self.blocked_queue.iter() {
            if Arc::ptr_eq(task, &waken_task) {
                task.inner.lock().task_status = TaskStatus::Ready;
                self.ready_queue.push_back(task.clone());
                log::warn!("unblock task: {:?}", task.tid);
                break;
            }
        }
    }
}

// every processor
lazy_static! {
    pub static ref SCHEDULER: SpinNoIrqLock<Scheduler> = SpinNoIrqLock::new(Scheduler::new());
}

pub fn add_task(task: Arc<Task>) {
    SCHEDULER.lock().add(task);
}

pub fn fetch_task() -> Option<Arc<Task>> {
    SCHEDULER.lock().fetch()
}

pub fn block_task(task: Arc<Task>) {
    SCHEDULER.lock().block(task);
}

pub fn unblock_task_wait_on_tid(waken_task: Arc<Task>) {
    SCHEDULER.lock().unblock_tasks_wait_on_tid(waken_task);
}

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
    let next_task = fetch_task().unwrap();
    let next_task_kernel_stack = next_task.kstack.0;
    log::info!("next_task_kernel_stack: {:#x}", next_task_kernel_stack);
    // check_task_context_in_kernel_stack(next_task_kernel_stack);
    // 切换Processor的current
    crate::task::processor::PROCESSOR
        .lock()
        .switch_to(next_task);

    unsafe {
        switch::__switch(next_task_kernel_stack);
    }
    log::info!("return from switch");
}

bitflags! {
    /// Open file flags
    pub struct CloneFlags: u32 {
        // SIGCHLD 是一个信号，在UNIX和类UNIX操作系统中，当一个子进程改变了它的状态时，内核会向其父进程发送这个信号。这个信号可以用来通知父进程子进程已经终止或者停止了。父进程可以采取适当的行动，比如清理资源或者等待子进程的状态。
        // 以下是SIGCHLD信号的一些常见用途：
        // 子进程终止：当子进程结束运行时，无论是正常退出还是因为接收到信号而终止，操作系统都会向其父进程发送SIGCHLD信号。
        // 资源清理：父进程可以处理SIGCHLD信号来执行清理工作，例如释放子进程可能已经使用的资源。
        // 状态收集：父进程可以通过调用wait()或waitpid()系统调用来获取子进程的终止状态，了解子进程是如何结束的。
        // 孤儿进程处理：在某些情况下，如果父进程没有适当地处理SIGCHLD信号，子进程可能会变成孤儿进程。孤儿进程最终会被init进程（PID为1的进程）收养，并由init进程来处理其终止。
        // 避免僵尸进程：通过正确响应SIGCHLD信号，父进程可以避免产生僵尸进程（zombie process）。僵尸进程是已经终止但父进程尚未收集其终止状态的进程。
        // 默认情况下，SIGCHLD信号的处理方式是忽略，但是开发者可以根据需要设置自定义的信号处理函数来响应这个信号。在多线程程序中，如果需要，也可以将SIGCHLD信号的传递方式设置为线程安全。
        const SIGCHLD = (1 << 4) | (1 << 0);
        // 如果设置此标志，调用进程和子进程将共享同一内存空间。
        // 在一个进程中的内存写入在另一个进程中可见。
        const CLONE_VM = 1 << 8;
        // 如果设置此标志，子进程将与父进程共享文件系统信息（如当前工作目录）
        const CLONE_FS = 1 << 9;
        // 如果设置此标志，子进程将与父进程共享文件描述符表。
        const CLONE_FILES = 1 << 10;
        const CLONE_SIGHAND = 1 << 11;
        const CLONE_PIDFD = 1 << 12;
        const CLONE_PTRACE = 1 << 13;
        const CLONE_VFORK = 1 << 14;
        const CLONE_PARENT = 1 << 15;
        const CLONE_THREAD = 1 << 16;
        const CLONE_NEWNS = 1 << 17;
        const CLONE_SYSVSEM = 1 << 18;
        const CLONE_SETTLS = 1 << 19;
        const CLONE_PARENT_SETTID = 1 << 20;
        const CLONE_CHILD_CLEARTID = 1 << 21;
        const CLONE_DETACHED = 1 << 22;
        const CLONE_UNTRACED = 1 << 23;
        const CLONE_CHILD_SETTID = 1 << 24;
        const CLONE_NEWCGROUP = 1 << 25;
        const CLONE_NEWUTS = 1 << 26;
        const CLONE_NEWIPC = 1 << 27;
        const CLONE_NEWUSER = 1 << 28;
        const CLONE_NEWPID = 1 << 29;
        const CLONE_NEWNET = 1 << 30;
        const CLONE_IO = 1 << 31;
    }
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

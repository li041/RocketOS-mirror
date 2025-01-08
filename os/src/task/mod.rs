pub mod aux;
pub mod context;
pub mod id;
pub mod kstack;
pub mod processor;
pub mod scheduler;
pub mod switch;

use crate::{
    boards::qemu::CLOCK_FREQ,
    config::PAGE_SIZE,
    loader::get_app_data_by_name,
    mm::KERNEL_SPACE,
    mutex::SpinNoIrqLock,
    sbi::shutdown,
    timer::{get_time, get_time_ms},
    trap::{trap_handler, TrapContext},
    utils::c_str_to_string,
};
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{arch::asm, mem};
use lazy_static::lazy_static;
use riscv::asm;

use context::{check_task_context_in_kernel_stack, TaskContext};
use id::tid_alloc;
pub use id::KID_ALLOCATOR;
use kstack::{get_stack_top_by_sp, kstack_alloc, KernelStack, KSTACK_SIZE};
use scheduler::{add_task, fetch_task, switch_to_next_task};

use crate::mm::MemorySet;

/// tp寄存器指向Task结构体
#[repr(C)]
pub struct Task {
    /// 使用struct KernelStack包装, 实现Drop特性, 实际上就是栈顶指针
    /// 注意在`__switch`中, 会通过tp寄存器的值修改栈顶指针
    /// kstack在Task中要保持在第一个field, 否则在`__switch`中会出错
    /// 只对task_status不为Running的task才有效, 其他的需要读sp寄存器
    pub kstack: KernelStack,
    pub tid: usize,
    pub inner: SpinNoIrqLock<TaskInner>,
}

pub struct TaskInner {
    pub memory_set: MemorySet,
    pub task_status: TaskStatus,
    /// 使用Weak指针, 防止循环引用, 不影响父进程的引用计数
    /// initproc的parent为None
    // pub parent: Option<Weak<Task>>,
    // 使用usize记录父进程的Task指针
    // initproc的parent为0
    pub parent: Option<Weak<Task>>,
    pub children: Vec<Arc<Task>>,
    pub exit_code: i32,
}

// 通过tp寄存器使用裸指针获取当前Task
pub fn current_task_violate() -> Task {
    let tp: usize;
    unsafe {
        asm!("mv {}, tp", out(reg) tp);
    }
    let task_ptr = tp as *const Task;
    unsafe { task_ptr.read() }
}

pub fn current_task() -> Arc<Task> {
    let processor = processor::PROCESSOR.lock();
    processor.current_task()
}

// 返回一个Task或者Arc<Task>
impl Task {
    // used by idle task
    pub fn zero_init() -> Self {
        Task {
            kstack: KernelStack(0),
            tid: 0,
            inner: SpinNoIrqLock::new(TaskInner {
                memory_set: MemorySet::new_bare(),
                task_status: TaskStatus::Running,
                parent: None,
                children: Vec::new(),
                exit_code: 0,
            }),
        }
    }
    /// init task memory space, push `TrapContext` and `TaskContext` to kernel stack
    pub fn new(elf_data: &[u8]) -> Arc<Self> {
        let (memory_set, satp, user_sp, entry_point, aux_vec) = MemorySet::from_elf(elf_data);
        log::info!("Task satp: {:#x}", satp);
        let tid = tid_alloc();
        // alloc kernel stack and map kstack
        let mut kstack = kstack_alloc();
        // Trap_context
        let mut trap_context = TrapContext::app_init_trap_context(entry_point, user_sp);
        kstack -= core::mem::size_of::<TrapContext>();
        let trap_cx_ptr = kstack as *mut TrapContext;
        // Task_context
        kstack -= core::mem::size_of::<TaskContext>();
        let task_cx_ptr = kstack as *mut TaskContext;

        let task = Arc::new(Task {
            kstack: KernelStack(kstack),
            tid: tid,
            inner: SpinNoIrqLock::new(TaskInner {
                memory_set,
                task_status: TaskStatus::Ready,
                parent: None,
                children: Vec::new(),
                exit_code: 0,
            }),
        });
        let task_ptr = Arc::as_ptr(&task) as usize;
        let task_context = context::TaskContext::app_init_task_context(task_ptr, satp);
        log::info!("kstack: {:#x}", kstack);
        // 将TrapContext和TaskContext压入内核栈
        trap_context.set_tp(task_ptr);
        unsafe {
            trap_cx_ptr.write(trap_context);
            task_cx_ptr.write(task_context);
        }
        log::error!(
            "task {} tp: {:#x}, satp: {:#x}, kernel_stack: {:#x}",
            tid,
            task_ptr,
            satp,
            task.kstack.0
        );
        task
    }
    pub fn fork(self: &Arc<Self>) -> Arc<Self> {
        let mut parent_inner = self.inner.lock();
        // 复制内存空间
        let memory_set = MemorySet::from_existed_user(&parent_inner.memory_set);
        // 只复制内核栈中的`TrapContext`, 不复制父进程在内核中函数调用的栈帧
        let dst_kstack_top = kstack_alloc();
        log::info!("self.kstack.0: {:#x}", self.kstack.0);
        let src_kstack_top = get_stack_top_by_sp(self.kstack.0);
        log::info!(
            "[Task::fork] src_kstack_top: {:#x}, dst_kstack_top: {:#x}",
            src_kstack_top,
            dst_kstack_top
        );
        let src_trap_cx_ptr =
            (src_kstack_top - core::mem::size_of::<TrapContext>()) as *const TrapContext;
        let dst_trap_cx_ptr =
            (dst_kstack_top - core::mem::size_of::<TrapContext>()) as *mut TrapContext;
        let task_cx_ptr =
            (dst_trap_cx_ptr as usize - core::mem::size_of::<TaskContext>()) as *mut TaskContext;
        // Debug
        log::error!("src_trap_cx_ptr: {:#x}", src_trap_cx_ptr as usize);
        log::error!("dst_trap_cx_ptr: {:#x}", dst_trap_cx_ptr as usize);
        // 分配新的tid
        let tid = tid_alloc();
        let task = Arc::new(Task {
            // 对于fork出的子进程, 内核栈是新分配的, 其中只有`TrapContext`是父进程的副本, 然后是初始化的`TaskContext`
            kstack: KernelStack(task_cx_ptr as usize),
            tid,
            inner: SpinNoIrqLock::new(TaskInner {
                memory_set,
                task_status: TaskStatus::Ready,
                parent: Some(Arc::downgrade(self)),
                children: Vec::new(),
                exit_code: 0,
            }),
        });

        // 设置子进程的`TrapContext`, 与父进程相比, 1.修改a0为0, 作为fork的返回值 2.设置tp寄存器指向Task结构体, 3.设置satp
        // 设置子进程的`TaskContext`
        let child_tp = Arc::as_ptr(&task) as usize;
        let child_satp = task.inner.lock().memory_set.page_table.token();
        let child_task_cx = context::TaskContext::app_init_task_context(child_tp, child_satp);
        unsafe {
            dst_trap_cx_ptr.write(src_trap_cx_ptr.read());
            task_cx_ptr.write(child_task_cx);
            // 设置a0为0, 作为fork的返回值
            (*dst_trap_cx_ptr).x[10] = 0;
            // 设置tp寄存器指向Task结构体
            (*dst_trap_cx_ptr).x[4] = child_tp;
            log::error!("parent user_sp: {:#x}", (*src_trap_cx_ptr).x[2]);
            log::error!("child user_sp: {:#x}", (*dst_trap_cx_ptr).x[2]);
        }
        log::error!(
            "[Task::fork]task {} tp: {:#x}, satp: {:#x}, kernel_stack: {:#x}",
            tid,
            child_tp,
            child_satp,
            task.kstack.0
        );

        // 将子进程加入父进程的children列表
        parent_inner.children.push(task.clone());
        task
    }
}

impl Task {
    pub fn exec(&self, elf_data: &[u8]) {
        // exec
        // 1. 修改memory set
        // 2. 修改内核栈中的`TrapContext`
        //
        let (memory_set, satp, ustack_top, entry_point, aux_vec) = MemorySet::from_elf(elf_data);
        //修改memory set
        memory_set.activate();
        log::error!(
            "[Task::exec] entry_point: {:x}, user_sp: {:x}, page_table: {:x}",
            entry_point,
            ustack_top,
            memory_set.page_table.token()
        );
        self.inner.lock().memory_set = memory_set;

        // 修改内核栈中的`TrapContext`
        let kstack_top = get_stack_top_by_sp(self.kstack.0);

        let trap_cx_ptr = (kstack_top - core::mem::size_of::<TrapContext>()) as *mut TrapContext;
        // Debug: 打印先前栈中的`TrapContext`
        // let prev_trap_cx = unsafe { trap_cx_ptr.read() };
        // log::info!(
        //     "[Task::exec] prev_trap_cx_sepc: {:x}, prev_trap_cx_sp: {:x}",
        //     prev_trap_cx.sepc,
        //     prev_trap_cx.x[2]
        // );
        let trap_cx = TrapContext::app_init_trap_context(entry_point, ustack_top);
        unsafe {
            *trap_cx_ptr = trap_cx;
        }
        // Todo: 初始化用户栈
    }
    pub fn show_info(self: &Arc<Self>) {
        log::info!("Task tid: {}", self.tid);
        log::info!("Task kstack: {:#x}", self.kstack.0);
        let tp: usize;
        unsafe {
            asm!("mv {}, tp", out(reg) tp);
        }
        assert!(
            tp == Arc::as_ptr(&self) as usize,
            "tp : {:#x}, task_ptr: {:#x}",
            tp,
            Arc::as_ptr(&self) as usize
        );
    }
}

lazy_static! {
    /// Global process that init user shell
    pub static ref INITPROC: Arc<Task> = Task::new(get_app_data_by_name("initproc").unwrap());
}

pub fn add_initproc() {
    add_task(INITPROC.clone());
    // 设置tp寄存器指向INITPROC
    let initproc_tp = Arc::as_ptr(&INITPROC) as usize;
    unsafe {
        asm!("mv tp, {}", in(reg) initproc_tp);
    }
}

#[derive(Copy, Clone, PartialEq)]
pub enum TaskStatus {
    Ready,
    Running,
    Zombie,
}

/// Syscall implement
#[no_mangle]
pub fn sys_fork() -> isize {
    let current_task = current_task();
    current_task.show_info();
    let child_task = current_task.fork();
    let child_tid = child_task.tid as isize;
    add_task(child_task);
    log::info!("fork child tid: {}", child_tid);
    child_tid
}

// Debug
#[no_mangle]
pub fn sys_exec(path: *const u8) -> isize {
    let path = c_str_to_string(path);
    if let Some(elf_data) = get_app_data_by_name(&path) {
        let task = current_task();
        task.exec(elf_data);
        log::info!("current_task_id: {} , exec path: {}", task.tid, path);
        0
    } else {
        -1
    }
}

pub fn sys_getpid() -> isize {
    current_task().tid as isize
}

// 不能从自己切换到自己
#[no_mangle]
pub fn suspend_current_and_run_next() {
    let task = current_task();

    if let Some(next_task) = fetch_task() {
        task.inner.lock().task_status = TaskStatus::Ready;
        // 将当前任务加入就绪队列
        add_task(task);
        // 获得下一个任务的内核栈
        // 可以保证`Ready`的任务`Task`中的内核栈与实际运行的sp保持一致
        let next_task_kernel_stack = next_task.kstack.0;
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

pub fn sys_yield() -> isize {
    // let task = current_task();
    // task.inner.lock().task_status = TaskStatus::Ready;
    // // 将当前任务加入就绪队列
    // add_task(task);
    // // 切换到下一个任务
    // schedule();
    suspend_current_and_run_next();
    0
}

pub const INITPROC_TID: usize = 0;

pub fn sys_exit(exit_code: i32) -> ! {
    let task = current_task();

    let tid = task.tid;
    // 如果是initproc, 则关机
    if tid == INITPROC_TID {
        println!(
            "[kernel] Idle process exit with exit_code {} ...",
            exit_code
        );
        if exit_code != 0 {
            //crate::sbi::shutdown(255); //255 == -1 for err hint
            shutdown(true)
        } else {
            //crate::sbi::shutdown(0); //0 for success hint
            shutdown(false)
        }
    }

    let mut inner = task.inner.lock();
    inner.task_status = TaskStatus::Zombie;
    // 写入exit_code
    inner.exit_code = exit_code;
    // 将当前进程的子进程的parent设置为initproc
    // 使用{}限制initproc_inner的生命周期
    {
        let mut initproc_inner = INITPROC.inner.lock();
        for child in inner.children.iter() {
            let mut child_inner = child.inner.lock();
            child_inner.parent = Some(Arc::downgrade(&INITPROC));
            initproc_inner.children.push(child.clone());
        }
    }

    inner.children.clear();
    inner.memory_set.recycle_data_pages();
    drop(inner);
    drop(task);
    switch_to_next_task();
    panic!("Unreachable in sys_exit");
}

pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    let task = current_task();
    let mut inner = task.inner.lock();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.tid)
    {
        return -1;
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        p.inner.lock().task_status == TaskStatus::Zombie && (pid == -1 || pid as usize == p.tid)
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        assert_eq!(Arc::strong_count(&child), 1);
        let found_tid = child.tid as i32;
        // 写入exit_code
        // Todo: 需要对地址检查
        unsafe {
            *exit_code_ptr = child.inner.lock().exit_code;
        }
        found_tid as isize
    } else {
        -2
    }
}

pub fn sys_get_time() -> isize {
    get_time_ms() as isize
}

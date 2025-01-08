pub mod aux;
pub mod context;
pub mod id;
pub mod kstack;
pub mod processor;
pub mod scheduler;
pub mod switch;

use crate::{
    fs::{open_file, path::Path, File, OpenFlags, Stdin, Stdout, AT_FDCWD},
    loader::get_app_data_by_name,
    mutex::SpinNoIrqLock,
    sbi::shutdown,
    timer::get_time_ms,
    trap::TrapContext,
    utils::{c_str_to_string, extract_cstrings},
};
use alloc::{string::String, vec};
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use aux::{AuxHeader, AT_EXECFN, AT_NULL, AT_RANDOM};
use core::arch::asm;
use lazy_static::lazy_static;

use context::TaskContext;
use id::tid_alloc;
pub use id::TidHandle;
use kstack::{get_stack_top_by_sp, kstack_alloc, KernelStack};
use scheduler::{
    add_task, block_task, fetch_task, switch_to_next_task, unblock_task_wait_on_tid, CloneFlags,
    WaitOption,
};

use crate::mm::MemorySet;

/// tp寄存器指向Task结构体
#[repr(C)]
pub struct Task {
    /// 使用struct KernelStack包装, 实现Drop特性, 实际上就是栈顶指针
    /// 注意在`__switch`中, 会通过tp寄存器的值修改栈顶指针
    /// kstack在Task中要保持在第一个field, 否则在`__switch`中会出错
    /// 只对task_status不为Running的task才有效, 其他的需要读sp寄存器
    pub kstack: KernelStack,
    pub tid: TidHandle,
    pub inner: SpinNoIrqLock<TaskInner>,
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
            tid: TidHandle(0),
            inner: SpinNoIrqLock::new(TaskInner {
                memory_set: MemorySet::new_bare(),
                task_status: TaskStatus::Running,
                parent: None,
                children: Vec::new(),
                exit_code: 0,
                fd_table: Vec::new(),
                cwd: Path::new_absolute(),
            }),
        }
    }
    /// init task memory space, push `TrapContext` and `TaskContext` to kernel stack
    pub fn new_initproc(elf_data: &[u8]) -> Arc<Self> {
        let (memory_set, satp, user_sp, entry_point, _aux_vec) = MemorySet::from_elf(elf_data);
        log::info!("Task satp: {:#x}", satp);
        let tid = tid_alloc();
        // alloc kernel stack and map kstack
        let mut kstack = kstack_alloc();
        // Trap_context
        let mut trap_context = TrapContext::app_init_trap_context(entry_point, user_sp, 0, 0, 0, 0);
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
                fd_table: vec![
                    // 0 -> stdin
                    Some(Arc::new(Stdin)),
                    // 1 -> stdout
                    Some(Arc::new(Stdout)),
                    // Todo: 2 -> stderr, 没有实现, 暂时指向stdout
                    Some(Arc::new(Stdout)),
                ],
                cwd: Path::new_absolute(),
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
        task
    }
    pub fn fork(self: &Arc<Self>, user_stack_top: Option<usize>) -> Arc<Self> {
        // 1. 复制内存空间
        // 2. 复制内核栈中的`TrapContext`, 不复制父进程在内核中函数调用的栈帧
        // 3. 复制fd_table, cwd
        // 4. 创建子进程的`Task`, 并分配新的tid
        // 5. 设置子进程的`TrapContext`, 与父进程相比: 1.修改a0为0, 作为fork的返回值 2.设置tp寄存器指向Task结构体, 3.设置satp 4. `sys_clone`可能会指定新的用户栈
        // 6. 设置子进程的`TaskContext`
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

        // 复制fd_table和cwd
        let mut child_fd_table: Vec<Option<Arc<dyn File + Send + Sync>>> = Vec::new();
        for fd in parent_inner.fd_table.iter() {
            if let Some(file) = fd {
                child_fd_table.push(Some(file.clone()));
            } else {
                child_fd_table.push(None);
            }
        }
        let child_cwd = parent_inner.cwd.clone();
        // 分配新的tid
        let tid = tid_alloc();
        // Debug:
        let debug_tid = tid.0;

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
                fd_table: child_fd_table,
                cwd: child_cwd,
            }),
        });

        // 设置子进程的`TrapContext`,
        // 与父进程相比, 1.修改a0为0, 作为fork的返回值 2.设置tp寄存器指向Task结构体, 3.设置satp 4. `sys_clone`可能会指定新的用户栈
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
            // sys_clone指定设置user_sp
            if let Some(user_stack_top) = user_stack_top {
                (*dst_trap_cx_ptr).x[2] = user_stack_top;
            }
            log::error!("parent user_sp: {:#x}", (*src_trap_cx_ptr).x[2]);
            log::error!("child user_sp: {:#x}", (*dst_trap_cx_ptr).x[2]);
        }
        log::error!(
            "[Task::fork] task {} tp: {:#x}, satp: {:#x}, kernel_stack: {:#x}",
            debug_tid,
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
    pub fn exec(&self, elf_data: &[u8], args_vec: Vec<String>, envs_vec: Vec<String>) {
        // exec
        // 1. 修改memory set
        // 2. 初始化用户栈, 压入args和envs
        // 3. 修改内核栈中的`TrapContext`
        let (memory_set, _satp, ustack_top, entry_point, aux_vec) = MemorySet::from_elf(elf_data);
        //修改memory set
        memory_set.activate();
        log::error!(
            "[Task::exec] entry_point: {:x}, user_sp: {:x}, page_table: {:x}",
            entry_point,
            ustack_top,
            memory_set.page_table.token()
        );
        self.inner.lock().memory_set = memory_set;

        // 初始化用户栈, 压入args和envs
        let argc = args_vec.len();
        let (argv_base, envp_base, auxv_base, ustack_top) =
            init_user_stack(&args_vec, &envs_vec, aux_vec, ustack_top);

        // 修改内核栈中的`TrapContext`
        let kstack_top = get_stack_top_by_sp(self.kstack.0);

        let trap_cx_ptr = (kstack_top - core::mem::size_of::<TrapContext>()) as *mut TrapContext;
        let trap_cx = TrapContext::app_init_trap_context(
            entry_point,
            ustack_top,
            argc,
            argv_base,
            envp_base,
            auxv_base,
        );
        unsafe {
            *trap_cx_ptr = trap_cx;
        }
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
    pub fn inner_handler<F, R>(&self, handler: F) -> R
    where
        F: FnOnce(&mut TaskInner) -> R,
    {
        handler(&mut self.inner.lock())
    }
}

lazy_static! {
    /// Global process that init user shell
    pub static ref INITPROC: Arc<Task> = Task::new_initproc(get_app_data_by_name("initproc").unwrap());
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
    pub fd_table: Vec<Option<Arc<dyn File + Send + Sync>>>,
    pub cwd: Path,
}

impl TaskInner {
    pub fn alloc_fd(&mut self) -> usize {
        if let Some(fd) = (0..self.fd_table.len()).find(|fd| self.fd_table[*fd].is_none()) {
            fd
        } else {
            self.fd_table.push(None);
            self.fd_table.len() - 1
        }
    }
    pub fn reserve_fd(&mut self, fd: usize) {
        if fd >= self.fd_table.len() {
            self.fd_table.resize(fd + 1, None);
        }
    }
}

pub fn add_initproc() {
    add_task(INITPROC.clone());
    // 设置tp寄存器指向INITPROC
    let initproc_tp = Arc::as_ptr(&INITPROC) as usize;
    unsafe {
        asm!("mv tp, {}", in(reg) initproc_tp);
    }
}

// 把参数, 环境变量, 辅助信息压入用户栈
// argv_base, envp_base, auxv_base, user_sp
// 压入顺序从高地址到低地址: envp, argv, platform, random bytes, auxs, envp[], argv[], argc
fn init_user_stack(
    args_vec: &[String],
    envs_vec: &[String],
    mut auxs_vec: Vec<AuxHeader>,
    mut user_sp: usize,
) -> (usize, usize, usize, usize) {
    fn push_strings_to_stack(strings: &[String], stack_ptr: &mut usize) -> Vec<usize> {
        let mut addresses = vec![0; strings.len()];
        for (i, string) in strings.iter().enumerate() {
            *stack_ptr -= string.len() + 1; // Leave space for '\0'
            *stack_ptr -= *stack_ptr % core::mem::size_of::<usize>(); // Align to usize boundary
            let ptr = *stack_ptr as *mut u8;
            unsafe {
                ptr.copy_from(string.as_ptr(), string.len());
                *((ptr as usize + string.len()) as *mut u8) = 0; // Null-terminate
                addresses[i] = *stack_ptr;
            }
        }
        addresses
    }

    fn push_pointers_to_stack(pointers: &[usize], stack_ptr: &mut usize) -> usize {
        let len = (pointers.len() + 1) * core::mem::size_of::<usize>(); // +1 for null terminator
        *stack_ptr -= len;
        let base = *stack_ptr;
        unsafe {
            for (i, &ptr) in pointers.iter().enumerate() {
                *((base + i * core::mem::size_of::<usize>()) as *mut usize) = ptr;
            }
            *((base + pointers.len() * core::mem::size_of::<usize>()) as *mut usize) = 0;
            // Null-terminate
        }
        base
    }

    fn push_aux_headers_to_stack(aux_headers: &[AuxHeader], stack_ptr: &mut usize) -> usize {
        let len = aux_headers.len() * core::mem::size_of::<AuxHeader>();
        *stack_ptr -= len;
        let base = *stack_ptr;
        unsafe {
            for (i, header) in aux_headers.iter().enumerate() {
                *((base + i * core::mem::size_of::<AuxHeader>()) as *mut usize) = header.aux_type;
                *((base + i * core::mem::size_of::<AuxHeader>() + core::mem::size_of::<usize>())
                    as *mut usize) = header.value;
            }
        }
        base
    }

    // Push environment variables to the stack
    let envp = push_strings_to_stack(envs_vec, &mut user_sp);

    // Push arguments to the stack
    let argv = push_strings_to_stack(args_vec, &mut user_sp);

    // Push platform string to the stack
    let platform = "RISC-V64";
    user_sp -= platform.len() + 1;
    user_sp -= user_sp % core::mem::size_of::<usize>();
    unsafe {
        let ptr = user_sp as *mut u8;
        ptr.copy_from(platform.as_ptr(), platform.len());
        *((ptr as usize + platform.len()) as *mut u8) = 0;
    }

    // Push random bytes (16 bytes of 0)
    user_sp -= 16;
    auxs_vec.push(AuxHeader {
        aux_type: AT_RANDOM,
        value: user_sp,
    });

    // Align stack to 16-byte boundary
    user_sp -= user_sp % 16;

    // Push aux headers
    auxs_vec.push(AuxHeader {
        aux_type: AT_EXECFN,
        value: argv[0],
    });
    auxs_vec.push(AuxHeader {
        aux_type: AT_NULL,
        value: 0,
    });
    let auxv_base = push_aux_headers_to_stack(&auxs_vec, &mut user_sp);

    // Push environment pointers to the stack
    let envp_base = push_pointers_to_stack(&envp, &mut user_sp);

    // Push argument pointers to the stack
    let argv_base = push_pointers_to_stack(&argv, &mut user_sp);

    // Push argc (number of arguments)
    user_sp -= core::mem::size_of::<usize>();
    unsafe {
        *(user_sp as *mut usize) = args_vec.len();
    }

    (argv_base, envp_base, auxv_base, user_sp)
}

#[derive(Copy, Clone, PartialEq)]
pub enum TaskStatus {
    Ready,
    Running,
    // 目前用来支持waitpid的阻塞, usize是等待进程的pid
    Blocked,
    Zombie,
}

/// Syscall implement
pub fn sys_fork(user_stack_top: Option<usize>) -> isize {
    let current_task = current_task();
    current_task.show_info();
    // let child_task = current_task.fork(user_stack_top);
    let child_task = current_task.fork(user_stack_top);
    let child_tid = child_task.tid.0 as isize;
    add_task(child_task);
    log::info!("fork child tid: {}", child_tid);
    child_tid
}

// Todo: 完善sys_clone
pub fn sys_clone(
    flags: u32,
    stack_ptr: usize,
    _parent_tid_ptr: usize,
    _tls_ptr: usize,
    _chilren_tid_ptr: usize,
) -> isize {
    let clone_flags = match CloneFlags::from_bits(flags as u32) {
        None => {
            log::error!("clone flags is None: {}", flags);
            return 22;
        }
        Some(flag) => flag,
    };

    if clone_flags.contains(CloneFlags::SIGCHLD) || !clone_flags.contains(CloneFlags::CLONE_VM) {
        // fork
        let stack = match stack_ptr {
            0 => None,
            stack => {
                log::info!("[sys_clone] assign the user stack {:#x}", stack);
                Some(stack)
            }
        };
        let ret = sys_fork(stack);
        // Here is for testcase
        yield_current_task();
        return ret;
    } else if clone_flags.contains(CloneFlags::CLONE_VM) {
        panic!("unimplemented CLONE_VM!")
    } else {
        panic!("unimplemented clone_flags!")
    }
}

pub fn sys_execve(path: *const u8, args: *const usize, envs: *const usize) -> isize {
    // 目前支持在根目录下执行应用程序
    let path = Path::from(c_str_to_string(path));
    // argv[0]是应用程序的名字
    // 后续元素是用户在命令行中输入的参数
    let mut args_vec = extract_cstrings(args);
    let envs_vec = extract_cstrings(envs);
    // 把应用程序的路径放在argv[0]中
    args_vec.insert(0, path.get_name());
    if let Ok(app_inode) = open_file(AT_FDCWD, &path, OpenFlags::RDONLY) {
        let all_data = app_inode.read_all();
        let task = current_task();
        task.exec(all_data.as_slice(), args_vec, envs_vec);
        0
    } else if path.is_relative() && path.len() == 1 {
        // 从内核中加载的应用程序
        if let Some(elf_data) = get_app_data_by_name(&path.get_name()) {
            let task = current_task();
            task.exec(elf_data, args_vec, envs_vec);
            0
        } else {
            -1
        }
    } else {
        -1
    }
}

pub fn sys_getpid() -> isize {
    current_task().tid.0 as isize
}

// 获取父进程的pid
pub fn sys_getppid() -> isize {
    let task = current_task();
    let parent = task
        .inner
        .lock()
        .parent
        .as_ref()
        .unwrap()
        .upgrade()
        .unwrap();
    parent.tid.0 as isize
}

// 不能从自己切换到自己
// 注意调用者要释放原任务的锁, 否则会死锁
#[no_mangle]
pub fn yield_current_task() {
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

// 目前支持由waitpid阻塞的进程
#[no_mangle]
pub fn blocking_current_task_and_run_next() {
    let task = current_task();
    if let Some(next_task) = fetch_task() {
        task.inner.lock().task_status = TaskStatus::Blocked;
        log::warn!("task {} is blocked", task.tid);
        // 将当前任务加入阻塞队列
        block_task(task);
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
}

pub fn sys_yield() -> isize {
    // let task = current_task();
    // task.inner.lock().task_status = TaskStatus::Ready;
    // // 将当前任务加入就绪队列
    // add_task(task);
    // // 切换到下一个任务
    // schedule();
    yield_current_task();
    0
}

pub const INITPROC_TID: usize = 1;

pub fn sys_exit(exit_code: i32) -> ! {
    // 退出当前进程, 清理资源
    // 1. 修改task_status为Zombie
    // 2. 将exit_code写入TaskInner
    // 3. 将当前进程的子进程的parent设置为initproc
    // 4. 将当前进程的fd_table清空, memory_set回收, children清空

    let task = current_task();

    let tid = task.tid.0;
    log::warn!(
        "[sys_exit] task {} exit with exit_code {} ...",
        tid,
        exit_code
    );
    // 如果是initproc, 则关机
    if tid == INITPROC_TID {
        log::info!(
            "[kernel] Initproc process exit with exit_code {} ...",
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
    inner.fd_table.clear();
    unblock_task_wait_on_tid(inner.parent.as_ref().unwrap().upgrade().unwrap());
    drop(inner);
    drop(task);
    switch_to_next_task();
    panic!("Unreachable in sys_exit");
}

// 使用block
#[no_mangle]
pub fn sys_waitpid(pid: isize, exit_code_ptr: usize, option: i32) -> isize {
    let option = WaitOption::from_bits(option).unwrap();
    log::warn!(
        "[sys_waitpid] pid: {}, exit_code_ptr: {:x}, option: {:?}",
        pid,
        exit_code_ptr,
        option
    );
    {
        let task = current_task();
        let inner = task.inner.lock();
        if !inner
            .children
            .iter()
            .any(|p| pid == -1 || pid as usize == p.tid.0)
        {
            // 没有找到子进程
            return -1;
        }
    }
    loop {
        // 有子进程, 进一步看是否有子进程退出
        let task = current_task();
        let mut inner = task.inner.lock();
        let pair = inner.children.iter().enumerate().find(|(_, p)| {
            p.inner.lock().task_status == TaskStatus::Zombie
                && (pid == -1 || pid as usize == p.tid.0)
        });

        // 如果pid > 0, 则等待指定的子进程
        if let Some((idx, _)) = pair {
            let child = inner.children.remove(idx);
            // assert_eq!(Arc::strong_count(&child), 1);
            let found_tid = child.tid.0 as i32;
            // 写入exit_code
            // Todo: 需要对地址检查
            unsafe {
                log::warn!(
                    "[sys_waitpid] child {} exit with code {}, exit_code_ptr: {:x}",
                    found_tid,
                    child.inner.lock().exit_code,
                    exit_code_ptr
                );
                let exit_code_ptr = exit_code_ptr as *mut i32;
                if exit_code_ptr != core::ptr::null_mut() {
                    exit_code_ptr.write_volatile((child.inner.lock().exit_code & 0xff) << 8);
                }
            }
            return found_tid as isize;
        } else {
            if option.contains(WaitOption::WNOHANG) {
                return 0;
            } else {
                // 没有子进程退出, 则挂起当前进程
                drop(inner);
                yield_current_task();
                // blocking_current_task_and_run_next();
            }
        }
    }
}

// pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
//     let task = current_task();
//     let mut inner = task.inner.lock();
//     if !inner
//         .children
//         .iter()
//         .any(|p| pid == -1 || pid as usize == p.tid.0)
//     {
//         return -1;
//     }
//     let pair = inner.children.iter().enumerate().find(|(_, p)| {
//         p.inner.lock().task_status == TaskStatus::Zombie && (pid == -1 || pid as usize == p.tid.0)
//     });
//     if let Some((idx, _)) = pair {
//         let child = inner.children.remove(idx);
//         assert_eq!(Arc::strong_count(&child), 1);
//         let found_tid = child.tid.0 as i32;
//         // 写入exit_code
//         // Todo: 需要对地址检查
//         if exit_code_ptr != core::ptr::null_mut() {
//             unsafe {
//                 *exit_code_ptr = child.inner.lock().exit_code;
//             }
//         }
//         return found_tid as isize;
//     } else {
//         -2
//     }
// }

// /// 成功返回退出子进程的pid, 失败返回-1
// pub fn wait_pid(pid: i32, exit_code_ptr: *mut i32) -> Result<usize, WaitError> {
//     let current_task = current_task();
//     let mut idx_to_remove = None;
//     {
//         let children = current_task.inner.lock().children.clone();
//         if children.is_empty() {
//             return Err(WaitError::NoChild);
//         }
//         for (idx, child) in children.iter().enumerate() {
//             if pid == 0 {
//                 log::error!("[wait_pid] process group wait is not implemented");
//             } else if pid == -1 || pid == child.tid as i32 {
//                 // pid == -1, 等待任意子进程
//                 let child_inner = child.inner.lock();
//                 if child_inner.task_status == TaskStatus::Zombie {
//                     let exit_code = child_inner.exit_code;
//                     let from = &exit_code as *const i32;
//                     // unsafe {
//                     //     *exit_code_ptr = exit_code;
//                     // }
//                     if let Err(err) = copy_to_user(exit_code_ptr, from, 1) {
//                         panic!("[wait_pid]copy exit_code failed: {}", err);
//                     }
//                     log::info!(
//                         "[wait_pid] child {} exit with code {}",
//                         child.tid,
//                         exit_code
//                     );
//                     idx_to_remove = Some(idx);
//                     break;
//                 }
//             }
//         }
//     } // children释放

//     // 移除已经退出的子进程
//     if let Some(idx) = idx_to_remove {
//         let child = current_task.inner.lock().children.remove(idx);
//         assert!(
//             Arc::strong_count(&child) == 1,
//             "child strong count: {}",
//             Arc::strong_count(&child)
//         );
//         return Ok(child.tid);
//     }
//     Err(WaitError::NotFound)
// }

// pub fn sys_wait4(pid: isize, exit_code_ptr: *mut i32, option: i32) -> isize {
//     let options = WaitOption::from_bits(option).unwrap();
//     let task = current_task();
//     loop {
//         match wait_pid(pid as i32, exit_code_ptr) {
//             Ok(tid) => return tid as isize,
//             Err(_) => {
//                 if options.contains(WaitOption::WNOHANG) {
//                     // 返回0, 表示没有子进程退出
//                     return 0;
//                 } else {
//                     // 没有子进程退出, 则挂起当前进程
//                     suspend_current_and_run_next();
//                 }
//             }
//         }
//     }
// }

/// sys_gettimeofday, current time = sec + usec
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TimeVal {
    /// seconds
    pub sec: usize,
    /// microseconds
    pub usec: usize,
}

pub fn sys_get_time(time_val_ptr: usize) -> isize {
    let time_val_ptr = time_val_ptr as *mut TimeVal;
    let current_time_ms = get_time_ms();
    let time_val = TimeVal {
        sec: current_time_ms / 1000,
        usec: current_time_ms % 1000 * 1000,
    };
    unsafe {
        time_val_ptr.write_volatile(time_val);
    }
    0
}

pub fn sys_nanosleep(time_val_ptr: usize) -> isize {
    let time_val_ptr = time_val_ptr as *const TimeVal;
    let time_val = unsafe { time_val_ptr.read() };
    let time_ms = time_val.sec * 1000 + time_val.usec / 1000;
    let start_time = get_time_ms();
    loop {
        let current_time = get_time_ms();
        if current_time - start_time >= time_ms {
            break;
        }
    }
    0
}

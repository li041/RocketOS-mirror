use super::{
    aux::{AuxHeader, AT_EXECFN, AT_NULL, AT_RANDOM},
    context::TaskContext,
    id::{tid_alloc, TidHandle},
    kstack::{get_stack_top_by_sp, kstack_alloc, KernelStack},
    scheduler::switch_to_next_task,
    String, Tid,
};
use crate::{
    fs::{fdtable::FdTable, file::FileOp, path::Path, FileOld, Stdin, Stdout},
    mm::MemorySet,
    mutex::SpinNoIrqLock,
    syscall::CloneFlags,
    task::{
        aux, kstack, scheduler::{add_task, remove_thread_group, SCHEDULER}, INITPROC
    },
    trap::TrapContext,
};
use alloc::{
    collections::btree_map::BTreeMap,
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use core::{assert_ne, sync::atomic::AtomicI32};

const INIT_PROC_PID: usize = 0;

/// tp寄存器指向Task结构体
#[repr(C)]
pub struct Task {
    // 不变量
    // kstack在Thread中要保持在第一个field
    kstack: KernelStack, // 内核栈
    tid: TidHandle,      // 进程/线程标志id

    // 变量
    // 基本变量
    tgid: SpinNoIrqLock<TidHandle>,                         // 线程组id
    status: SpinNoIrqLock<TaskStatus>,                      // 任务状态
    parent: Arc<SpinNoIrqLock<Option<Weak<Task>>>>,         // 父任务
    children: Arc<SpinNoIrqLock<BTreeMap<Tid, Arc<Task>>>>, // 子任务
    thread_group: Arc<SpinNoIrqLock<ThreadGroup>>,          // 线程组
    exit_code: AtomicI32,                                   // 退出码

    // 内存管理
    // ToDo: 共享内存区域
    memory_set: Arc<SpinNoIrqLock<MemorySet>>, // 地址空间

    // 文件系统
    // ToDo: 对接ext4
    fd_table: Arc<FdTable>,
    // #merge Todo: root和pwd
    root: Arc<SpinNoIrqLock<Arc<Path>>>,
    pwd: Arc<SpinNoIrqLock<Arc<Path>>>,
    // ToDo: 信号处理
    // Todo: 进程组
    // ToDo：运行时间(调度相关)
    // ToDo: 多核启动
}

impl core::fmt::Debug for Task {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Task")
            .field("tid", &self.tid())
            .field("tgid", &self.tgid())
            .finish()
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        log::info!("task {} dropped", self.tid());
    }
}

impl Task {
    // used by idle task
    pub fn zero_init() -> Self {
        Self {
            kstack: KernelStack(0),
            tid: TidHandle(0),
            tgid: SpinNoIrqLock::new(TidHandle(0)),
            status: SpinNoIrqLock::new(TaskStatus::Ready),
            parent: Arc::new(SpinNoIrqLock::new(None)),
            children: Arc::new(SpinNoIrqLock::new(BTreeMap::new())),
            thread_group: Arc::new(SpinNoIrqLock::new(ThreadGroup::new())),
            exit_code: AtomicI32::new(0),
            memory_set: Arc::new(SpinNoIrqLock::new(MemorySet::new_bare())),
            fd_table: FdTable::new(),
            root: Arc::new(SpinNoIrqLock::new(Path::zero_init())),
            pwd: Arc::new(SpinNoIrqLock::new(Path::zero_init())),
        }
    }

    /// 初始化地址空间, 将 `TrapContext` 与 `TaskContext` 压入内核栈中
    pub fn initproc(elf_data: &[u8], root_path: Arc<Path>) -> Arc<Self> {
        let (memory_set, satp, user_sp, entry_point, _aux_vec) = MemorySet::from_elf(elf_data);
        let tid = tid_alloc();
        let tgid = SpinNoIrqLock::new(TidHandle(tid.0));
        // 申请内核栈
        let mut kstack = kstack_alloc();
        // Trap_context
        let mut trap_context = TrapContext::app_init_trap_context(entry_point, user_sp, 0, 0, 0, 0);
        kstack -= core::mem::size_of::<TrapContext>();
        let trap_cx_ptr = kstack as *mut TrapContext;
        // Task_context
        kstack -= core::mem::size_of::<TaskContext>();
        let task_cx_ptr = kstack as *mut TaskContext;
        // 创建进程实体
        let task = Arc::new(Task {
            kstack: KernelStack(kstack),
            tid,
            tgid,
            status: SpinNoIrqLock::new(TaskStatus::Ready),
            parent: Arc::new(SpinNoIrqLock::new(None)),
            // 注：children结构中保留了对任务的Arc引用
            children: Arc::new(SpinNoIrqLock::new(BTreeMap::new())),
            thread_group: Arc::new(SpinNoIrqLock::new(ThreadGroup::new())),
            exit_code: AtomicI32::new(0),
            memory_set: Arc::new(SpinNoIrqLock::new(memory_set)),
            fd_table: FdTable::new(),
            // Todo
            root: Arc::new(SpinNoIrqLock::new(root_path.clone())),
            pwd: Arc::new(SpinNoIrqLock::new(root_path)),
        });
        // 向线程组中添加该进程
        task.thread_group.lock().add(task.clone());
        add_task(task.clone());
        // 令tp寄存器指向主线程内核栈顶
        let task_ptr = Arc::as_ptr(&task) as usize;
        let task_context = TaskContext::app_init_task_context(task_ptr, satp);
        // 将TrapContext和TaskContext压入内核栈
        trap_context.set_tp(task_ptr);
        unsafe {
            trap_cx_ptr.write(trap_context);
            task_cx_ptr.write(task_context);
        }
        log::info!("Task: {:p}", &task);
        log::info!("Task kstack: {:p}", &task.kstack);
        log::info!("[Initproc] kstack: {:#x}", kstack);
        log::info!("Initproc complete!");

        task
    }

    pub fn kernel_clone(self: &Arc<Self>, flags: CloneFlags) -> Arc<Self> {
        let tid = tid_alloc();
        let exit_code = AtomicI32::new(0);
        let status = SpinNoIrqLock::new(TaskStatus::Ready);
        let tgid;
        let mut kstack;
        let parent;
        let children;
        let thread_group;
        let memory_set;
        let fd_table;
        let root;
        let pwd;
        log::info!(
            "[kernel_clone] current_task pid: {}, new_task pid: {}",
            self.tid(),
            tid
        );
        if flags.contains(CloneFlags::SIGCHLD) {
            // ToDo:
        }
        // 创建线程
        if flags.contains(CloneFlags::CLONE_THREAD) {
            tgid = SpinNoIrqLock::new(TidHandle(self.tgid()));
            parent = self.parent.clone();
            children = self.children.clone();
            thread_group = self.thread_group.clone();
            root = self.root.clone();
            pwd = self.pwd.clone()
        }
        // 创建进程
        else {
            tgid = SpinNoIrqLock::new(TidHandle(tid.0));
            parent = Arc::new(SpinNoIrqLock::new(Some(Arc::downgrade(self))));
            children = Arc::new(SpinNoIrqLock::new(BTreeMap::new()));
            thread_group = Arc::new(SpinNoIrqLock::new(ThreadGroup::new()));
            // 深拷贝Path, 但共享底层的Dentry和VfsMount
            root = clone_path(&self.root);
            pwd = clone_path(&self.pwd);
        }
        if flags.contains(CloneFlags::CLONE_VM) {
            // Todo: execve可能有问题
            memory_set = self.memory_set.clone()
        } else {
            memory_set = Arc::new(SpinNoIrqLock::new(MemorySet::from_existed_user_lazily(
                // memory_set = Arc::new(SpinNoIrqLock::new(MemorySet::from_existed_user(
                &self.memory_set.lock(),
            )));
        }
        // 申请新的内核栈并写入trap_cx内容
        kstack = self.trap_context_clone();
        // 更新task_cx
        kstack -= core::mem::size_of::<TaskContext>();
        let kstack = KernelStack(kstack);
        if flags.contains(CloneFlags::CLONE_FILES) {
            fd_table = self.fd_table.clone()
        } else {
            fd_table = FdTable::from_existed_user(&self.fd_table);
        }
        let task = Arc::new(Self {
            kstack,
            tid,
            tgid,
            status,
            parent,
            children,
            exit_code,
            thread_group,
            memory_set,
            fd_table,
            root,
            pwd,
        });
        if !flags.contains(CloneFlags::CLONE_THREAD) {
            self.add_child(task.clone());
        }
        task.op_thread_group_mut(|tg| tg.add(task.clone()));
        // 在内核栈中加入task_cx
        write_task_cx(task.clone());
        log::info!(
            "[kernel_clone] task{}, kstack: {:#x}",
            task.tid(),
            task.kstack()
        );
        log::info!(
            "[kernel_clone] task{}, strong_count {}",
            task.tid(),
            Arc::strong_count(&task)
        ); // 未加入调度器理论为 2
        log::info!("[kernel_clone] task{} create sucessfully!", task.tid());

        task
    }

    // ToDo: 两个（多个）线程同时调用execve
    pub fn kernel_execve(
        self: &Arc<Self>,
        elf_data: &[u8],
        args_vec: Vec<String>,
        envs_vec: Vec<String>,
    ) {
        // 创建地址空间
        let (memory_set, _satp, ustack_top, entry_point, aux_vec) = MemorySet::from_elf(elf_data);
        // 更新页表
        memory_set.activate();
        // let pos = 0x30_0000_0000 as usize;
        // unsafe { if need_dl {log::error!("[sys_mmap] pos : {:?}", core::slice::from_raw_parts_mut(pos as *mut u8, 64));} }
        // 初始化用户栈, 压入args和envs
        // ToDo：待完善
        let argc = args_vec.len();
        let (argv_base, envp_base, auxv_base, ustack_top) =
            init_user_stack(&args_vec, &envs_vec, aux_vec, ustack_top);
        log::info!(
            "[kernel_execve] entry_point: {:x}, user_sp: {:x}, page_table: {:x}",
            entry_point,
            ustack_top,
            memory_set.token()
        );
        // 关闭所有线程组其他进程
        self.op_thread_group_mut(|tg| {
            for thread in tg.iter() {
                // 跳过当前线程
                if thread.tid() == self.tid() {
                    continue;
                }
                kernel_exit(thread, 0);
            }
        });
        // 如果当前任务为从线程, 则将线程组中所有任务从调度器中移除
        if !self.is_main_thread() {
            remove_thread_group(self.tgid());
        }
        // 更新地址空间
        self.op_memory_set_mut(|m| *m = memory_set);
        // 更新trap_cx
        let kstack_top = get_stack_top_by_sp(self.kstack());
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
        // 将当前线程升级为主线程
        self.set_tgid(self.tid());
        // 重建线程组
        self.op_thread_group_mut(|tg| {
            *tg = ThreadGroup::new();
            tg.add(self.clone());
        });
        // Todo: FdTable相关
        self.reset_fd_table();

        log::info!(
            "[kernel_execve] current_task ThreadGroup len {}",
            self.op_thread_group_mut(|tg| tg.len())
        );
        log::info!(
            "[kernel_execve] current_task tid:{}, tgid:{}, kstack:{:#x}, strong_count:{}",
            self.tid(),
            self.tgid(),
            self.kstack(),
            Arc::strong_count(&self)
        ); // 理论为3(sys_exec一个，children一个， processor一个)
        log::info!("[kernel_execve] execve complete!");
    }

    pub fn is_main_thread(&self) -> bool {
        self.tid() == self.tgid()
    }

    pub fn alloc_fd(&mut self, file: Arc<dyn FileOp + Send + Sync>) -> usize {
        self.fd_table.alloc_fd(file)
    }

    // 向当前任务中添加新的子任务
    pub fn add_child(&self, task: Arc<Task>) {
        self.children.lock().try_insert(task.tid(), task);
    }

    // 复制当前内核栈trap_context内容到新内核栈中（用于kernel_clone)
    // 返回新内核栈当前指针位置（KernelStack）
    fn trap_context_clone(&self) -> usize {
        let src_kstack_top = get_stack_top_by_sp(self.kstack());
        let dst_kstack_top = kstack_alloc();
        log::info!(
            "[trap_context_clone] src_kstack_top: {:#x}, dst_kstack_top: {:#x}",
            src_kstack_top,
            dst_kstack_top
        );
        let src_trap_cx_ptr =
            (src_kstack_top - core::mem::size_of::<TrapContext>()) as *const TrapContext;
        let dst_trap_cx_ptr =
            (dst_kstack_top - core::mem::size_of::<TrapContext>()) as *mut TrapContext;
        unsafe {
            dst_trap_cx_ptr.write(src_trap_cx_ptr.read());
        }
        dst_trap_cx_ptr as usize
    }

    // 重置文件打开表
    fn reset_fd_table(&self) {
        self.fd_table.reset();
    }

    /*********************************** getter *************************************/

    pub fn kstack(&self) -> usize {
        self.kstack.0
    }
    pub fn tid(&self) -> Tid {
        self.tid.0
    }
    pub fn tgid(&self) -> Tid {
        self.tgid.lock().0
    }
    pub fn status(&self) -> TaskStatus {
        *self.status.lock()
    }
    pub fn root(&self) -> Arc<Path> {
        self.root.lock().clone()
    }
    pub fn pwd(&self) -> Arc<Path> {
        self.pwd.lock().clone()
    }
    pub fn exit_code(&self) -> i32 {
        self.exit_code.load(core::sync::atomic::Ordering::SeqCst)
    }
    pub fn memory_set(&self) -> Arc<SpinNoIrqLock<MemorySet>> {
        self.memory_set.clone()
    }
    pub fn fd_table(&self) -> Arc<FdTable> {
        self.fd_table.clone()
    }

    /*********************************** setter *************************************/
    pub fn set_tgid(&self, tgid: Tid) {
        self.tgid.lock().0 = tgid;
    }
    pub fn set_root(&self, root: Arc<Path>) {
        *self.root.lock() = root;
    }
    pub fn set_pwd(&self, pwd: Arc<Path>) {
        *self.pwd.lock() = pwd;
    }
    pub fn set_exit_code(&self, exit_code: i32) {
        self.exit_code
            .store(exit_code, core::sync::atomic::Ordering::SeqCst);
    }
    pub fn set_parent(&self, parent: Arc<Task>) {
        *self.parent.lock() = Some(Arc::downgrade(&parent));
    }

    /*********************************** operator *************************************/
    pub fn op_parent<T>(&self, f: impl FnOnce(&Option<Weak<Task>>) -> T) -> T {
        f(&self.parent.lock())
    }
    pub fn op_children_mut<T>(&self, f: impl FnOnce(&mut BTreeMap<Tid, Arc<Task>>) -> T) -> T {
        f(&mut self.children.lock())
    }
    pub fn op_memory_set<T>(&self, f: impl FnOnce(&MemorySet) -> T) -> T {
        f(&self.memory_set.lock())
    }
    pub fn op_memory_set_mut<T>(&self, f: impl FnOnce(&mut MemorySet) -> T) -> T {
        f(&mut self.memory_set.lock())
    }
    pub fn op_thread_group<T>(&self, f: impl FnOnce(&ThreadGroup) -> T) -> T {
        f(&self.thread_group.lock())
    }
    pub fn op_thread_group_mut<T>(&self, f: impl FnOnce(&mut ThreadGroup) -> T) -> T {
        f(&mut self.thread_group.lock())
    }
    /******************************** 任务状态判断 **************************************/
    pub fn is_ready(&self) -> bool {
        self.status() == TaskStatus::Ready
    }
    pub fn is_blocked(&self) -> bool {
        self.status() == TaskStatus::Blocked
    }
    pub fn is_zombie(&self) -> bool {
        self.status() == TaskStatus::Zombie
    }
    pub fn set_ready(&self) {
        *self.status.lock() = TaskStatus::Ready;
    }
    pub fn set_running(&self) {
        *self.status.lock() = TaskStatus::Running;
    }
    pub fn set_blocked(&self) {
        *self.status.lock() = TaskStatus::Blocked;
    }
    pub fn set_zombie(&self) {
        *self.status.lock() = TaskStatus::Zombie;
    }
}

/****************************** 辅助函数 ****************************************/

/// 任务退出
/// 参数：task 指定任务，exit_code 退出码
/// 此函数仅负责如下工作，**调度器移除逻辑请自行解决**
/// 1. 从线程组中移除指定任务
/// 2. 修改task_status为Zombie
/// 3. 修改exit_code
/// 4. 托孤给initproc
/// 5. 将当前进程的fd_table清空, memory_set回收, children清空
pub fn kernel_exit(task: Arc<Task>, exit_code: i32) {
    log::error!(
        "[kernel_exit] Task {} exit with exit_code {:?} ...",
        task.tid(),
        exit_code
    );
    assert_ne!(
        task.tid(),
        INIT_PROC_PID,
        "[kernel_exit] Initproc process exit with exit_code {:?} ...",
        task.exit_code()
    );
    // 从线程组中移除
    task.op_thread_group_mut(|tg| tg.remove(task.clone()));
    // 设置当前任务为僵尸态
    task.set_zombie();
    // 设置推出码
    task.set_exit_code(exit_code);
    // 托孤
    task.op_children_mut(|children| {
        for task in children.values() {
            task.set_parent(INITPROC.clone());
            INITPROC.add_child(task.clone())
        }
        children.clear();
    });
    // 回收地址空间
    task.op_memory_set_mut(|mem| {
        mem.recycle_data_pages();
    });
    // 清空文件描述符表
    task.fd_table().clear();
    drop(task);
}

// 向指定任务内核栈中保存当前task_cx
fn write_task_cx(task: Arc<Task>) {
    let task_tp = Arc::as_ptr(&task) as usize;
    let task_satp = task.op_memory_set(|m| m.token());
    let task_cx = TaskContext::app_init_task_context(task_tp, task_satp);
    let task_cx_ptr = task.kstack() as *mut TaskContext;
    unsafe {
        task_cx_ptr.write(task_cx);
    }
}

// 在clone时没有设置`CLONE_THREAD`标志, 为新任务创建新的`Path`结构
// 需要深拷贝`Path`, 但共享底层的`Dentry`和`VfsMount`
fn clone_path(old_path: &Arc<SpinNoIrqLock<Arc<Path>>>) -> Arc<SpinNoIrqLock<Arc<Path>>> {
    let old_path = old_path.lock();
    let new_path = Path::from_existed_user(&old_path);
    Arc::new(SpinNoIrqLock::new(new_path))
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
            *stack_ptr -= string.len() + 1; // '\0'
            *stack_ptr -= *stack_ptr % core::mem::size_of::<usize>(); // 按照usize对齐
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
    log::info!("[init_user_stack] args: {:?}, envs: {:?}", args_vec, envs_vec);

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

/****************************** 辅助结构 ****************************************/

/// 线程组结构
pub struct ThreadGroup {
    member: BTreeMap<Tid, Weak<Task>>,
}

impl ThreadGroup {
    pub fn new() -> Self {
        Self {
            member: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.member.len()
    }

    pub fn add(&mut self, task: Arc<Task>) {
        self.member.insert(task.tid(), Arc::downgrade(&task));
    }

    pub fn remove(&mut self, task: Arc<Task>) {
        self.member.remove(&task.tid());
    }

    pub fn iter(&self) -> impl Iterator<Item = Arc<Task>> + '_ {
        self.member.values().map(|task| task.upgrade().unwrap())
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum TaskStatus {
    Ready,
    Running,
    // 目前用来支持waitpid的阻塞, usize是等待进程的pid
    Blocked,
    Zombie,
}

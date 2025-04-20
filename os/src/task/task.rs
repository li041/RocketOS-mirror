use super::{
    aux::{AuxHeader, AT_EXECFN, AT_NULL, AT_RANDOM},
    context::TaskContext,
    id::{tid_alloc, TidHandle},
    kstack::{get_stack_top_by_sp, kstack_alloc, KernelStack},
    remove_task,
    scheduler::switch_to_next_task,
    String, Tid,
};
use crate::{
    arch::{
        config::USER_STACK_SIZE,
        mm::copy_to_user,
        trap::{
            context::{dump_trap_context, get_trap_context, save_trap_context},
            TrapContext,
        },
    },
    fs::{
        fdtable::FdTable,
        file::FileOp,
        path::Path,
        uapi::{RLimit, Resource},
        FileOld, Stdin, Stdout,
    },
    mm::{MapArea, MapPermission, MapType, MemorySet, VPNRange, VirtAddr},
    mutex::{SpinNoIrq, SpinNoIrqLock},
    signal::{SiField, Sig, SigHandler, SigInfo, SigPending, SigSet, SignalStack, UContext},
    task::{
        aux,
        context::write_task_cx,
        kstack,
        manager::TASK_MANAGER,
        scheduler::{add_task, remove_thread_group, SCHEDULER},
        INITPROC,
    },
};
use alloc::{
    collections::btree_map::BTreeMap,
    sync::{Arc, Weak},
    task, vec,
    vec::Vec,
};
use bitflags::bitflags;
use core::{
    any::Any,
    assert_ne,
    future::{pending, Pending},
    mem,
    sync::atomic::{AtomicI32, AtomicUsize},
};
use xmas_elf::sections::NoteHeader;

pub const INIT_PROC_PID: usize = 0;

extern "C" {
    fn strampoline();
    fn etrampoline();
}

/// tp寄存器指向Task结构体
/// ToDo: 阻塞与唤醒
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
    sig_pending: SpinNoIrqLock<SigPending>,      // 待处理信号
    sig_handler: Arc<SpinNoIrqLock<SigHandler>>, // 信号处理函数
    sig_stack: SpinNoIrqLock<Option<SignalStack>>, // 额外信号栈
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
        log::error!("task {} dropped", self.tid());
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
            sig_pending: SpinNoIrqLock::new(SigPending::new()),
            sig_handler: Arc::new(SpinNoIrqLock::new(SigHandler::new())),
            sig_stack: SpinNoIrqLock::new(None),
        }
    }

    /// 初始化地址空间, 将 `TrapContext` 与 `TaskContext` 压入内核栈中
    pub fn initproc(elf_data: &[u8], root_path: Arc<Path>) -> Arc<Self> {
        let (memory_set, pgdl_ppn, user_sp, entry_point, _aux_vec) =
            MemorySet::from_elf(elf_data.to_vec(), &mut Vec::<String>::new());
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
            root: Arc::new(SpinNoIrqLock::new(root_path.clone())),
            pwd: Arc::new(SpinNoIrqLock::new(root_path)),
            sig_pending: SpinNoIrqLock::new(SigPending::new()),
            sig_handler: Arc::new(SpinNoIrqLock::new(SigHandler::new())),
            sig_stack: SpinNoIrqLock::new(None),
        });
        // 向线程组中添加该进程
        task.thread_group
            .lock()
            .add(task.tid(), Arc::downgrade(&task));
        add_task(task.clone());
        TASK_MANAGER.add(&task);
        // 令tp与kernel_tp指向主线程内核栈顶
        let task_ptr = Arc::as_ptr(&task) as usize;
        trap_context.set_tp(task_ptr);
        trap_context.set_kernel_tp(task_ptr);
        log::info!("[Initproc] Init-tp:\t{:x}", task_ptr);
        let task_context = TaskContext::app_init_task_context(task_ptr, pgdl_ppn);
        // 将TrapContext和TaskContext压入内核栈
        unsafe {
            trap_cx_ptr.write(trap_context);
            task_cx_ptr.write(task_context);
        }
        log::info!("[Initproc] Init-sp:\t{:#x}", kstack);
        log::error!("[Initproc] Initproc complete!");
        task
    }

    // 从父进程复制子进程的核心逻辑实现
    pub fn kernel_clone(self: &Arc<Self>, flags: CloneFlags, ustack_ptr: usize) -> Arc<Self> {
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
        let sig_handler;
        let sig_pending;
        let sig_stack;
        log::info!("[kernel_clone] task{} ready to clone ...", self.tid());

        // 是否与父进程共享信号处理器
        if flags.contains(CloneFlags::CLONE_SIGHAND) {
            log::info!("[kernel_clone] handle CLONE_SIGHAND");
            sig_handler = self.sig_handler.clone();
        } else {
            sig_handler = Arc::new(SpinNoIrqLock::new(
                self.op_sig_handler_mut(|handler| handler.clone()),
            ))
        }

        // 创建线程
        if flags.contains(CloneFlags::CLONE_THREAD) {
            log::info!("[kernel_clone] handle CLONE_THREAD");
            tgid = SpinNoIrqLock::new(TidHandle(self.tgid()));
            parent = self.parent.clone();
            children = self.children.clone();
            thread_group = self.thread_group.clone();
            root = self.root.clone();
            pwd = self.pwd.clone()
        }
        // 创建进程
        else {
            log::info!("[kernel_clone] child task{} is a process", tid);
            tgid = SpinNoIrqLock::new(TidHandle(tid.0));
            parent = Arc::new(SpinNoIrqLock::new(Some(Arc::downgrade(self))));
            children = Arc::new(SpinNoIrqLock::new(BTreeMap::new()));
            thread_group = Arc::new(SpinNoIrqLock::new(ThreadGroup::new()));
            // 深拷贝Path, 但共享底层的Dentry和VfsMount
            root = clone_path(&self.root);
            pwd = clone_path(&self.pwd);
        }

        if flags.contains(CloneFlags::CLONE_VM) {
            log::info!("[kernel_clone] handle CLONE_VM");
            memory_set = self.memory_set.clone()
        } else {
            memory_set = Arc::new(SpinNoIrqLock::new(MemorySet::from_existed_user_lazily(
                &self.memory_set.lock(),
            )));
        }

        // 申请新的内核栈并复制父进程trap_cx内容
        kstack = self.trap_context_clone();
        // 更新task_cx
        kstack -= core::mem::size_of::<TaskContext>();
        let kstack = KernelStack(kstack);

        if flags.contains(CloneFlags::CLONE_FILES) {
            log::warn!("[kernel_clone] handle CLONE_FILES");
            fd_table = self.fd_table.clone()
        } else {
            log::warn!("[kernel_clone] fd_table from_existed_user");
            fd_table = FdTable::from_existed_user(&self.fd_table);
        }

        // 初始化其他未初始化属性
        sig_pending = SpinNoIrqLock::new(SigPending::new());
        sig_stack = SpinNoIrqLock::new(None);
        // 创建新任务
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
            sig_handler,
            sig_pending,
            sig_stack,
        });
        log::info!("[kernel_clone] child task{} created", task.tid());

        // 向任务管理器注册新任务（不是调度器）
        TASK_MANAGER.add(&task);
        // 向父进程添加子进程
        if task.is_process() {
            self.add_child(task.clone());
        }
        // 向线程组添加子进程 （包括当前任务为进程的情况）
        task.op_thread_group_mut(|tg| tg.add(task.tid(), Arc::downgrade(&task)));

        // 更新子进程的trap_cx
        let mut trap_cx = get_trap_context(&task);
        if ustack_ptr != 0 {
            // ToDo: 检验用户栈指针
            trap_cx.set_sp(ustack_ptr);
        }
        // 设定子任务返回值为0，令kernel_tp保存该任务结构
        trap_cx.set_kernel_tp(Arc::as_ptr(&task) as usize);
        trap_cx.set_a0(0);
        save_trap_context(&task, trap_cx);
        log::info!("[kernel_clone] child task{} trap_cx updated", task.tid());

        // 在内核栈中加入task_cx
        write_task_cx(task.clone());
        log::info!("[kernel_clone] child task{} task_cx updated", task.tid());
        log::info!(
            "[kernel_clone] task{}-tp:\t{:x}",
            task.tid(),
            Arc::as_ptr(&task) as usize
        );
        log::info!("[kernel_clone] task{}-sp:\t{:x}", task.tid(), task.kstack());

        let strong_count = Arc::strong_count(&task);
        if strong_count == 2 {
            log::info!("[kernel_clone] strong_count:\t{}", strong_count);
        } else
        // 未加入调度器理论引用计数为 2
        {
            log::error!("[kernel_clone] strong_count:\t{}", strong_count);
        }

        log::info!("[kernel_clone] task{} clone complete!", self.tid());
        task
    }

    // ToDo: 两个（多个）线程同时调用execve
    pub fn kernel_execve(
        self: &Arc<Self>,
        elf_data: &[u8],
        mut args_vec: Vec<String>,
        envs_vec: Vec<String>,
    ) {
        log::info!("[kernel_execve] task{} do execve ...", self.tid());
        // 创建地址空间
        let (mut memory_set, _satp, ustack_top, entry_point, aux_vec) =
            MemorySet::from_elf(elf_data.to_vec(), &mut args_vec);
        // 更新页表
        memory_set.activate();

        #[cfg(target_arch = "loongarch64")]
        memory_set.push_with_offset(
            MapArea::new(
                VPNRange::new(
                    VirtAddr::from(strampoline as usize).floor(),
                    VirtAddr::from(etrampoline as usize).ceil(),
                ),
                MapType::Linear,
                MapPermission::R | MapPermission::X | MapPermission::U,
                None,
                0,
            ),
            None,
            0,
        );

        // 初始化用户栈, 压入args和envs
        let argc = args_vec.len();
        let (argv_base, envp_base, auxv_base, ustack_top) =
            init_user_stack(&memory_set, &args_vec, &envs_vec, aux_vec, ustack_top);
        log::info!(
            "[kernel_execve] entry_point: {:x}, user_sp: {:x}, page_table: {:x}",
            entry_point,
            ustack_top,
            memory_set.token()
        );

        // 关闭所有线程组其他进程
        self.close_thread();
        // 如果当前任务为从线程, 则将线程组中所有任务从调度器中移除
        if !self.is_process() {
            remove_thread_group(self.tgid());
        }
        log::info!("[kernel_execve] task{} close thread_group", self.tid());
        // 将当前线程升级为主线程
        self.set_tgid(self.tid());
        log::info!("[kernel_execve] task{} become a process", self.tid());

        // 更新地址空间
        self.op_memory_set_mut(|m| *m = memory_set);
        // 更新trap_cx
        let mut trap_cx = TrapContext::app_init_trap_context(
            entry_point,
            ustack_top,
            argc,
            argv_base,
            envp_base,
            auxv_base,
        );
        trap_cx.set_tp(Arc::as_ptr(&self) as usize);
        save_trap_context(&self, trap_cx);
        log::info!("[kernel_execve] task{} trap_cx updated", self.tid());
        // 重建线程组
        self.op_thread_group_mut(|tg| {
            *tg = ThreadGroup::new();
            tg.add(self.tid(), Arc::downgrade(&self));
        });
        log::info!("[kernel_execve] task{} thread_group rebuild", self.tid());
        self.fd_table().do_close_on_exec();
        log::info!("[kernel_execve] task{} fd_table reset", self.tid());
        // 重置信号处理器
        self.op_sig_handler_mut(|handler| handler.reset());
        log::info!("[kernel_execve] task{} handler reset", self.tid());

        log::info!(
            "[kernel_execve] task{}-tgid:\t{:x}",
            self.tid(),
            self.tgid()
        );
        log::info!(
            "[kernel_execve] task{}-tp:\t{:x}",
            self.tid(),
            Arc::as_ptr(&self) as usize
        );
        log::info!(
            "[kernel_execve] task{}-sp:\t{:x}",
            self.tid(),
            self.kstack()
        );

        let strong_count = Arc::strong_count(&self);
        if strong_count == 3 {
            log::info!("[kernel_execve] strong_count:\t{}", strong_count);
        } else
        // 理论为3(sys_exec一个，children一个， processor一个)
        {
            log::error!("[kernel_execve] strong_count:\t{}", strong_count)
        }

        log::info!("[kernel_execve] task{} execve complete!", self.tid());
    }

    // 判断当前任务是否为进程
    pub fn is_process(&self) -> bool {
        self.tid() == self.tgid()
    }

    // 向当前任务中添加新的子任务
    pub fn add_child(&self, task: Arc<Task>) {
        self.children.lock().insert(task.tid(), task);
    }
    pub fn remove_child_task(&self, tid: Tid) {
        self.children.lock().remove(&tid);
    }
    // 关闭线程组所有其他线程（保留当前进程）
    pub fn close_thread(&self) {
        self.op_thread_group_mut(|tg| {
            for thread in tg.iter() {
                // 跳过当前线程
                if thread.tid() == self.tid() {
                    continue;
                }
                remove_task(thread.tid());
                kernel_exit(thread, 0);
            }
        });
    }

    // 复制当前内核栈trap_context内容到新内核栈中（用于kernel_clone)
    // 返回新内核栈当前指针位置（KernelStack）
    fn trap_context_clone(self: &Arc<Self>) -> usize {
        let src_kstack_top = get_stack_top_by_sp(self.kstack());
        let dst_kstack_top = kstack_alloc();
        log::info!(
            "[trap_context_clone] src_kstack_top:\t{:#x}",
            src_kstack_top
        );
        log::info!(
            "[trap_context_clone] dst_kstack_top:\t{:#x}",
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
    pub fn get_rlimit(&self, resource: Resource) -> Result<RLimit, &'static str> {
        match resource {
            Resource::STACK => {
                // Todo: 现在是固定配置
                let rlim = RLimit {
                    rlim_cur: USER_STACK_SIZE,
                    rlim_max: USER_STACK_SIZE,
                };
                Ok(rlim)
            }
            Resource::NOFILE => {
                let rlim = self.fd_table().get_rlimit();
                Ok(rlim)
            }
            _ => Err("not supported"),
        }
    }
    pub fn set_rlimit(&self, resource: Resource, rlim: &RLimit) -> Result<(), &'static str> {
        match resource {
            Resource::NOFILE => {
                self.fd_table().set_rlimit(&rlim);
                Ok(())
            }
            _ => Err("not supported"),
        }
    }

    // pub fn alloc_fd(&mut self, file: Arc<dyn FileOp + Send + Sync>) -> usize {
    //     self.fd_table.alloc_fd(file)
    // }

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
    pub fn mask(&self) -> SigSet {
        self.sig_pending.lock().mask
    }
    // 注意：这里将sigstack取出
    pub fn sigstack(&self) -> Option<SignalStack> {
        self.sig_stack.lock().take()
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
    pub fn set_sigstack(&self, sigstack: SignalStack) {
        *self.sig_stack.lock() = Some(sigstack)
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
    pub fn op_sig_pending_mut<T>(&self, f: impl FnOnce(&mut SigPending) -> T) -> T {
        f(&mut self.sig_pending.lock())
    }
    pub fn op_sig_handler<T>(&self, f: impl FnOnce(&SigHandler) -> T) -> T {
        f(&self.sig_handler.lock())
    }
    pub fn op_sig_handler_mut<T>(&self, f: impl FnOnce(&mut SigHandler) -> T) -> T {
        f(&mut self.sig_handler.lock())
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
/// 5. 将当前进程的fd_table清空, memory_set回收, children清空, sigpending清空
/// 6. 向父进程发送SIGCHLD
pub fn kernel_exit(task: Arc<Task>, exit_code: i32) {
    log::error!("[kernel_exit] Task{} ready to exit ...", task.tid(),);
    assert_ne!(
        task.tid(),
        INIT_PROC_PID,
        "[kernel_exit] Initproc process exit with exit_code {:?} ...",
        task.exit_code()
    );
    // 从线程组中移除
    task.op_thread_group_mut(|tg| tg.remove(task.clone()));
    log::info!("[kernel_exit] Task{} removed from thread-group", task.tid(),);
    // 设置当前任务为僵尸态
    task.set_zombie();
    log::warn!("[kernel_exit] Task{} become zombie", task.tid());
    // 设置退出码
    task.set_exit_code(exit_code);
    log::error!(
        "[kernel_exit] Task{} set exit_code to {}",
        task.tid(),
        task.exit_code()
    );
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
    log::info!("[kernel_exit] Task{} memset_area clear", task.tid());
    // 清空文件描述符表
    task.fd_table().clear();
    log::info!("[kernel_exit] Task{} fd_table clear", task.tid());
    // 清空信号
    task.op_sig_pending_mut(|pending| {
        pending.clear();
    });
    log::info!("[kernel_exit] Task{} sig_pending clear", task.tid());
    // 向父进程发送SIGCHID
    task.op_parent(|parent| {
        if let Some(parent) = parent {
            parent.upgrade().unwrap().receive_siginfo(
                SigInfo {
                    signo: Sig::SIGCHLD.raw(),
                    code: SigInfo::CLD_EXITED,
                    fields: SiField::kill { tid: task.tid() },
                },
                false,
            );
        }
    });
    TASK_MANAGER.remove(task.tid());
    log::error!("[kernel_exit] Task{} clear the resource", task.tid(),);
    drop(task);
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
    memory_set: &MemorySet,
    args_vec: &[String],
    envs_vec: &[String],
    mut auxs_vec: Vec<AuxHeader>,
    mut user_sp: usize,
) -> (usize, usize, usize, usize) {
    fn push_strings_to_stack(
        memory_set: &MemorySet,
        strings: &[String],
        stack_ptr: &mut usize,
    ) -> Vec<usize> {
        let mut addresses = vec![0; strings.len()];
        for (i, string) in strings.iter().enumerate() {
            *stack_ptr -= string.len() + 1; // '\0'
            *stack_ptr -= *stack_ptr % core::mem::size_of::<usize>(); // 按照usize对齐
            #[cfg(target_arch = "loongarch64")]
            let ptr = (memory_set
                .translate_va_to_pa(VirtAddr::from(*stack_ptr))
                .unwrap()) as *mut u8;
            #[cfg(target_arch = "riscv64")]
            let ptr = *stack_ptr as *mut u8;
            unsafe {
                ptr.copy_from(string.as_ptr(), string.len());
                *((ptr as usize + string.len()) as *mut u8) = 0; // Null-terminate
                addresses[i] = *stack_ptr;
            }
        }
        addresses
    }

    fn push_pointers_to_stack(
        memory_set: &MemorySet,
        pointers: &[usize],
        stack_ptr: &mut usize,
    ) -> usize {
        let len = (pointers.len() + 1) * core::mem::size_of::<usize>(); // +1 for null terminator
        *stack_ptr -= len;
        #[cfg(target_arch = "loongarch64")]
        let base = memory_set
            .translate_va_to_pa(VirtAddr::from(*stack_ptr))
            .unwrap();
        #[cfg(target_arch = "riscv64")]
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

    fn push_aux_headers_to_stack(
        memory_set: &MemorySet,
        aux_headers: &[AuxHeader],
        stack_ptr: &mut usize,
    ) -> usize {
        let len = aux_headers.len() * core::mem::size_of::<AuxHeader>();
        *stack_ptr -= len;
        #[cfg(target_arch = "loongarch64")]
        let base = memory_set
            .translate_va_to_pa(VirtAddr::from(*stack_ptr))
            .unwrap();
        #[cfg(target_arch = "riscv64")]
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
    log::error!(
        "[init_user_stack] args: {:?}, envs: {:?}",
        args_vec,
        envs_vec
    );

    // Push environment variables to the stack
    let envp = push_strings_to_stack(memory_set, envs_vec, &mut user_sp);

    // Push arguments to the stack
    let argv = push_strings_to_stack(memory_set, args_vec, &mut user_sp);

    // Push platform string to the stack
    #[cfg(target_arch = "riscv64")]
    let platform = "RISC-V64";
    #[cfg(target_arch = "loongarch64")]
    let platform = "loongarch64";

    user_sp -= platform.len() + 1;
    user_sp -= user_sp % core::mem::size_of::<usize>();
    #[cfg(target_arch = "loongarch64")]
    let ptr = (memory_set
        .translate_va_to_pa(VirtAddr::from(user_sp))
        .unwrap()) as *mut u8;
    #[cfg(target_arch = "riscv64")]
    let ptr = user_sp as *mut u8;
    unsafe {
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
    let auxv_base = push_aux_headers_to_stack(&memory_set, &auxs_vec, &mut user_sp);

    // Push environment pointers to the stack
    let envp_base = push_pointers_to_stack(&memory_set, &envp, &mut user_sp);

    // Push argument pointers to the stack
    let argv_base = push_pointers_to_stack(&memory_set, &argv, &mut user_sp);

    // Push argc (number of arguments)
    user_sp -= core::mem::size_of::<usize>();
    #[cfg(target_arch = "loongarch64")]
    let user_sp_pa = (memory_set
        .translate_va_to_pa(VirtAddr::from(user_sp.clone()))
        .unwrap()) as *mut u8;
    #[cfg(target_arch = "riscv64")]
    let user_sp_pa = user_sp as *mut u8;
    unsafe {
        *(user_sp_pa as *mut usize) = args_vec.len();
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

    pub fn add(&mut self, tid: Tid, task: Weak<Task>) {
        self.member.insert(tid, task);
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

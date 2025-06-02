use super::{
    aux::{AuxHeader, AT_EXECFN, AT_NULL, AT_RANDOM},
    context::TaskContext,
    get_task,
    id::{tid_alloc, TidAddress, TidHandle},
    kstack::{get_stack_top_by_sp, kstack_alloc, KernelStack},
    manager::unregister_task,
    remove_task,
    rusage::TimeStat,
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
    ext4::inode::S_IWUSR,
    fs::{
        fdtable::FdTable,
        file::FileOp,
        inode::InodeOp,
        path::Path,
        uapi::{RLimit, Resource},
        FileOld, Stdin, Stdout,
    },
    futex::{
        do_futex,
        flags::{FUTEX_PRIVATE_FLAG, FUTEX_WAKE},
        robust_list::RobustListHead,
    },
    mm::{MapArea, MapPermission, MapType, MemorySet, VPNRange, VirtAddr},
    mutex::{Spin, SpinNoIrq, SpinNoIrqLock},
    net::addr::is_unspecified,
    signal::{SiField, Sig, SigHandler, SigInfo, SigPending, SigSet, SignalStack, UContext},
    syscall::errno::SyscallRet,
    task::{
        self, add_task,
        context::write_task_cx,
        dump_scheduler, dump_wait_queue,
        manager::{add_group, cancel_wait_alarm, delete_wait, new_group, register_task},
        wakeup, INITPROC,
    },
    timer::{ITimerVal, TimeVal},
};
use alloc::{
    collections::btree_map::BTreeMap,
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use bitflags::bitflags;
use core::{
    assert_ne,
    cell::{SyncUnsafeCell, UnsafeCell},
    mem,
    sync::atomic::{AtomicI32, AtomicU32, AtomicUsize},
};
use spin::{Mutex, RwLock};

pub const INIT_PROC_PID: usize = 0;
pub const RLIM_NLIMITS: usize = 16;

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

    // 变量
    // 基本变量
    tid: RwLock<TidHandle>,                                 // 线程id
    tgid: AtomicUsize,                                      // 线程组id
    tid_address: SpinNoIrqLock<TidAddress>,                 // 线程id地址
    status: SpinNoIrqLock<TaskStatus>,                      // 任务状态
    time_stat: SyncUnsafeCell<TimeStat>,                    // 任务时间统计
    parent: Arc<SpinNoIrqLock<Option<Weak<Task>>>>,         // 父任务
    children: Arc<SpinNoIrqLock<BTreeMap<Tid, Arc<Task>>>>, // 子任务
    thread_group: Arc<SpinNoIrqLock<ThreadGroup>>,          // 线程组
    exit_code: AtomicI32,                                   // 退出码
    exe_path: Arc<RwLock<String>>,                          // 执行路径

    // 内存管理
    // 包括System V shm管理
    memory_set: Arc<RwLock<MemorySet>>, // 地址空间
    // futex管理, 线程局部
    robust_list_head: AtomicUsize, // struct robust_list_head* head
    // 文件系统
    fd_table: Arc<FdTable>,
    root: Arc<SpinNoIrqLock<Arc<Path>>>,
    pwd: Arc<SpinNoIrqLock<Arc<Path>>>,
    // 信号处理
    sig_pending: SpinNoIrqLock<SigPending>,      // 待处理信号
    sig_handler: Arc<SpinNoIrqLock<SigHandler>>, // 信号处理函数
    sig_stack: SpinNoIrqLock<Option<SignalStack>>, // 额外信号栈
    itimerval: Arc<RwLock<[ITimerVal; 3]>>,      // 定时器
    rlimit: Arc<RwLock<[RLimit; 16]>>,           // 资源限制
    cpu_mask: SpinNoIrqLock<CpuMask>,            // CPU掩码
    // 权限设置
    pgid: AtomicUsize, // 进程组id
    uid: AtomicU32,    // 用户id
    euid: AtomicU32,   // 有效用户id
    suid: AtomicU32,   // 保存用户id
    gid: AtomicU32,    // 组id
    egid: AtomicU32,   // 有效组id
    sgid: AtomicU32,   // 保存组id
    sup_groups: RwLock<Vec<u32>>, // 附加组列表
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
        // log::error!("task {} dropped", self.tid());
    }
}

impl Task {
    // used by idle task
    pub fn zero_init() -> Self {
        Self {
            kstack: KernelStack(0),
            tid: RwLock::new(TidHandle(0)),
            tgid: AtomicUsize::new(0),
            tid_address: SpinNoIrqLock::new(TidAddress::new()),
            status: SpinNoIrqLock::new(TaskStatus::Ready),
            time_stat: SyncUnsafeCell::new(TimeStat::default()),
            parent: Arc::new(SpinNoIrqLock::new(None)),
            children: Arc::new(SpinNoIrqLock::new(BTreeMap::new())),
            thread_group: Arc::new(SpinNoIrqLock::new(ThreadGroup::new())),
            exit_code: AtomicI32::new(0),
            exe_path: Arc::new(RwLock::new(String::new())),
            memory_set: Arc::new(RwLock::new(MemorySet::new_bare())),
            robust_list_head: AtomicUsize::new(0),
            fd_table: FdTable::new_bare(),
            root: Arc::new(SpinNoIrqLock::new(Path::zero_init())),
            pwd: Arc::new(SpinNoIrqLock::new(Path::zero_init())),
            sig_pending: SpinNoIrqLock::new(SigPending::new()),
            sig_handler: Arc::new(SpinNoIrqLock::new(SigHandler::new())),
            sig_stack: SpinNoIrqLock::new(None),
            itimerval: Arc::new(RwLock::new([ITimerVal::default(); 3])),
            rlimit: Arc::new(RwLock::new([RLimit::default(); RLIM_NLIMITS])),
            cpu_mask: SpinNoIrqLock::new(CpuMask::ALL),
            pgid: AtomicUsize::new(0),
            uid: AtomicU32::new(0),
            euid: AtomicU32::new(0),
            suid: AtomicU32::new(0),
            gid: AtomicU32::new(0),
            egid: AtomicU32::new(0),
            sgid: AtomicU32::new(0),
            sup_groups: RwLock::new(Vec::new()),
        }
    }

    /// 初始化地址空间, 将 `TrapContext` 与 `TaskContext` 压入内核栈中
    pub fn initproc(elf_data: &[u8], root_path: Arc<Path>) -> Arc<Self> {
        let (memory_set, pgdl_ppn, user_sp, entry_point, _aux_vec, _tls_ptr) =
            MemorySet::from_elf(elf_data.to_vec(), &mut Vec::<String>::new());
        let tid = tid_alloc();
        let tgid = AtomicUsize::new(tid.0);
        let pgid = AtomicUsize::new(1);
        let uid = AtomicU32::new(0); // 默认为root(0)用户
        let euid = AtomicU32::new(0);
        let suid = AtomicU32::new(0);
        let gid = AtomicU32::new(0); // 默认为root(0)组
        let egid = AtomicU32::new(0);
        let sgid = AtomicU32::new(0);
        let sup_groups = RwLock::new(Vec::new());
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
            tid: RwLock::new(tid),
            tgid,
            tid_address: SpinNoIrqLock::new(TidAddress::new()),
            status: SpinNoIrqLock::new(TaskStatus::Ready),
            time_stat: SyncUnsafeCell::new(TimeStat::default()),
            parent: Arc::new(SpinNoIrqLock::new(None)),
            // 注：children结构中保留了对任务的Arc引用
            children: Arc::new(SpinNoIrqLock::new(BTreeMap::new())),
            thread_group: Arc::new(SpinNoIrqLock::new(ThreadGroup::new())),
            exit_code: AtomicI32::new(0),
            exe_path: Arc::new(RwLock::new(String::from("/initproc"))),
            memory_set: Arc::new(RwLock::new(memory_set)),
            robust_list_head: AtomicUsize::new(0),
            fd_table: FdTable::new(),
            root: Arc::new(SpinNoIrqLock::new(root_path.clone())),
            pwd: Arc::new(SpinNoIrqLock::new(root_path)),
            sig_pending: SpinNoIrqLock::new(SigPending::new()),
            sig_handler: Arc::new(SpinNoIrqLock::new(SigHandler::new())),
            sig_stack: SpinNoIrqLock::new(None),
            itimerval: Arc::new(RwLock::new([ITimerVal::default(); 3])),
            rlimit: Arc::new(RwLock::new([RLimit::default(); RLIM_NLIMITS])),
            cpu_mask: SpinNoIrqLock::new(CpuMask::ALL),
            pgid,
            uid,
            euid,
            suid,
            gid,
            egid,
            sgid,
            sup_groups,
        });
        // 向线程组中添加该进程
        task.thread_group
            .lock()
            .add(task.tid(), Arc::downgrade(&task));
        add_task(task.clone());
        register_task(&task);
        // 新建进程组
        new_group(&task);
        // 新建进程组
        new_group(&task);
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
    pub fn kernel_clone(self: &Arc<Self>, flags: &CloneFlags, ustack_ptr: usize) -> Arc<Self> {
        let tid = tid_alloc();
        let tid_address = SpinNoIrqLock::new(TidAddress::new());
        let exit_code = AtomicI32::new(0);
        let exe_path;
        let status = SpinNoIrqLock::new(TaskStatus::Ready);
        let tgid;
        let mut kstack;
        let parent;
        let children;
        let thread_group;
        let itimerval;
        let memory_set;
        let fd_table;
        let root;
        let pwd;
        let sig_handler;
        let sig_pending;
        let sig_stack;
        let rlimit;
        let cpu_mask;
        let pgid;
        let uid;
        let euid;
        let suid;
        let gid;
        let egid;
        let sgid;
        let sup_groups;
        log::info!("[kernel_clone] task{} ready to clone ...", self.tid());

        // 是否与父进程共享信号处理器
        if flags.contains(CloneFlags::CLONE_SIGHAND) {
            log::warn!("[kernel_clone] handle CLONE_SIGHAND");
            sig_handler = self.sig_handler.clone();
        } else {
            sig_handler = Arc::new(SpinNoIrqLock::new(
                self.op_sig_handler_mut(|handler| handler.clone()),
            ))
        }

        // 继承父进程
        pgid = AtomicUsize::new(self.pgid());
        uid = AtomicU32::new(self.uid());
        euid = AtomicU32::new(self.euid());
        suid = AtomicU32::new(self.suid());
        gid = AtomicU32::new(self.gid());
        egid = AtomicU32::new(self.egid());
        sgid = AtomicU32::new(self.sgid());
        sup_groups = RwLock::new(self.op_sup_groups(|groups| groups.clone()));

        // 创建线程
        if flags.contains(CloneFlags::CLONE_THREAD) {
            log::warn!("[kernel_clone] child task{} is a thread", tid);
            tgid = AtomicUsize::new(self.tgid());
            log::info!(
                "[kernel_clone] task{}-parent:\t{:x}",
                self.tid(),
                self.parent
                    .lock()
                    .as_ref()
                    .unwrap()
                    .upgrade()
                    .unwrap()
                    .tid()
            );
            parent = self.parent.clone();
            children = self.children.clone();
            thread_group = self.thread_group.clone();
            itimerval = self.itimerval.clone();
            exe_path = self.exe_path.clone();
            rlimit = self.rlimit.clone();
        }
        // 创建进程
        else {
            log::info!("[kernel_clone] child task{} is a process", tid);
            tgid = AtomicUsize::new(tid.0);
            parent = Arc::new(SpinNoIrqLock::new(Some(Arc::downgrade(self))));
            children = Arc::new(SpinNoIrqLock::new(BTreeMap::new()));
            thread_group = Arc::new(SpinNoIrqLock::new(ThreadGroup::new()));
            itimerval = Arc::new(RwLock::new([ITimerVal::default(); 3]));
            exe_path = Arc::new(RwLock::new(String::new()));
            rlimit = Arc::new(RwLock::new([RLimit::default(); RLIM_NLIMITS]));
        }

        if flags.contains(CloneFlags::CLONE_VM) && !flags.contains(CloneFlags::CLONE_VFORK) {
            log::warn!("[kernel_clone] handle CLONE_VM");
            memory_set = self.memory_set.clone()
        } else {
            memory_set = Arc::new(RwLock::new(MemorySet::from_existed_user_lazily(
                &self.memory_set.read(),
            )));
        }

        if flags.contains(CloneFlags::CLONE_FS) {
            log::warn!("[kernel_clone] handle CLONE_FS");
            root = self.root.clone();
            pwd = self.pwd.clone()
        } else {
            root = clone_path(&self.root);
            pwd = clone_path(&self.pwd);
        }

        if flags.contains(CloneFlags::CLONE_FILES) {
            log::warn!("[kernel_clone] handle CLONE_FILES");
            fd_table = self.fd_table.clone()
        } else {
            log::warn!("[kernel_clone] fd_table from_existed_user");
            fd_table = FdTable::from_existed_user(&self.fd_table);
        }

        // 申请新的内核栈并复制父进程trap_cx内容
        kstack = self.trap_context_clone();
        // 更新task_cx
        kstack -= core::mem::size_of::<TaskContext>();
        let kstack = KernelStack(kstack);

        // 初始化其他未初始化属性
        sig_pending = SpinNoIrqLock::new(SigPending::new());
        sig_stack = SpinNoIrqLock::new(None);
        let tid = RwLock::new(tid);
        let robust_list_head = AtomicUsize::new(0);
        let time_stat = SyncUnsafeCell::new(TimeStat::default());
        cpu_mask = SpinNoIrqLock::new(CpuMask::ALL);
        // 创建新任务
        let task = Arc::new(Self {
            kstack,
            tid,
            tgid,
            tid_address,
            status,
            time_stat,
            parent,
            children,
            exit_code,
            exe_path,
            thread_group,
            memory_set,
            robust_list_head,
            fd_table,
            root,
            pwd,
            sig_handler,
            sig_pending,
            sig_stack,
            itimerval,
            rlimit,
            cpu_mask,
            pgid,
            uid,
            euid,
            suid,
            gid,
            egid,
            sgid,
            sup_groups,
        });
        log::trace!("[kernel_clone] child task{} created", task.tid());

        // 向任务管理器注册新任务（不是调度器）
        register_task(&task);
        // 向父进程添加子进程
        if task.is_process() {
            self.add_child(task.clone());
        } else {
            // 线程的父进程为当前任务的父进程
            self.op_parent(|parent| {
                if let Some(parent) = parent {
                    parent.upgrade().unwrap().add_child(task.clone());
                }
            });
        }

        // 向线程组添加子进程 （包括当前任务为进程的情况）
        task.op_thread_group_mut(|tg| tg.add(task.tid(), Arc::downgrade(&task)));
        // 向父进程组添加子进程
        add_group(task.pgid(), &task);

        // 更新子进程的trap_cx
        let mut trap_cx = get_trap_context(&task);
        log::error!("[kernel_clone] user_sp: {:#x}", trap_cx.get_sp());
        if ustack_ptr != 0 {
            // ToDo: 检验用户栈指针
            trap_cx.set_sp(ustack_ptr);
        }

        // 设定子任务返回值为0，令kernel_tp保存该任务结构
        trap_cx.set_kernel_tp(Arc::as_ptr(&task) as usize);
        trap_cx.set_a0(0);
        save_trap_context(&task, trap_cx);

        // 在内核栈中加入task_cx
        write_task_cx(task.clone());

        log::info!(
            "[kernel_clone] task{}-tp:\t{:x}",
            task.tid(),
            Arc::as_ptr(&task) as usize
        );
        log::info!("[kernel_clone] task{}-sp:\t{:x}", task.tid(), task.kstack());
        log::info!("[kernel_clone] task{}-tgid:\t{:x}", task.tid(), task.tgid());
        log::info!("[kernel_clone] task{}-pgid:\t{:x}", task.tid(), task.pgid());

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

    // Todo: sgid 与文件权限检查
    pub fn kernel_execve(
        self: &Arc<Self>,
        elf_data: &[u8],
        mut args_vec: Vec<String>,
        envs_vec: Vec<String>,
    ) {
        log::info!("[kernel_execve] task{} do execve ...", self.tid());
        // 创建地址空间
        let (mut memory_set, _satp, ustack_top, entry_point, aux_vec, tls_ptr) =
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

        if !self.is_process() {
            self.exchange_tid();
        }

        // 关闭线程组中除当前线程外的所有线程
        self.close_thread();
        log::trace!("[kernel_execve] task{} close thread_group", self.tid());

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
        // 设置tls
        if let Some(tls_ptr) = tls_ptr {
            log::error!("[kernel_execve] task{} tls_ptr: {:x}", self.tid(), tls_ptr);
            trap_cx.set_tp(tls_ptr);
        }
        save_trap_context(&self, trap_cx);
        log::trace!("[kernel_execve] task{} trap_cx updated", self.tid());
        // 重建线程组
        self.op_thread_group_mut(|tg| {
            *tg = ThreadGroup::new();
            tg.add(self.tid(), Arc::downgrade(&self));
        });
        log::trace!("[kernel_execve] task{} thread_group rebuild", self.tid());
        self.fd_table().do_close_on_exec();
        log::trace!("[kernel_execve] task{} fd_table reset", self.tid());
        // 重置信号处理器
        self.op_sig_handler_mut(|handler| handler.reset());
        log::trace!("[kernel_execve] task{} handler reset", self.tid());

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
    }

    pub fn kernel_execve_lazily(
        self: &Arc<Self>,
        exe_path: String,
        elf_file: Arc<dyn FileOp>,
        elf_data: &[u8],
        mut args_vec: Vec<String>,
        envs_vec: Vec<String>,
    ) {
        log::info!("[kernel_execve] task{} do execve ...", self.tid());
        // 创建地址空间
        let (mut memory_set, _satp, ustack_top, entry_point, aux_vec) =
            MemorySet::from_elf_lazily(elf_file, elf_data.to_vec(), &mut args_vec);
        // 更新页表
        memory_set.activate();
        // 更新exe_path
        *self.exe_path.write() = exe_path.clone();

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
        if args_vec.is_empty() {
            args_vec.push(String::from(exe_path));
        }
        let (argv_base, envp_base, auxv_base, ustack_top) =
            init_user_stack(&memory_set, &args_vec, &envs_vec, aux_vec, ustack_top);
        log::info!(
            "[kernel_execve] entry_point: {:x}, user_sp: {:x}, page_table: {:x}",
            entry_point,
            ustack_top,
            memory_set.token()
        );

        if !self.is_process() {
            self.exchange_tid();
        }

        // 关闭线程组中除当前线程外的所有线程
        self.close_thread();
        log::trace!("[kernel_execve] task{} close thread_group", self.tid());

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
        save_trap_context(&self, trap_cx);
        log::trace!("[kernel_execve] task{} trap_cx updated", self.tid());
        // 重建线程组
        self.op_thread_group_mut(|tg| {
            *tg = ThreadGroup::new();
            tg.add(self.tid(), Arc::downgrade(&self));
        });
        log::trace!("[kernel_execve] task{} thread_group rebuild", self.tid());
        self.fd_table().do_close_on_exec();
        log::trace!("[kernel_execve] task{} fd_table reset", self.tid());
        // 重置信号处理器
        self.op_sig_handler_mut(|handler| handler.reset());
        log::trace!("[kernel_execve] task{} handler reset", self.tid());

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
    }

    // 判断当前任务是否为进程
    pub fn is_process(&self) -> bool {
        self.tid() == self.tgid()
    }

    // 向当前任务中添加新的子任务
    pub fn add_child(&self, task: Arc<Task>) {
        self.children.lock().insert(task.tid(), task);
    }
    // 移除当前任务中的某子任务
    pub fn remove_child_task(&self, tid: Tid) {
        self.children.lock().remove(&tid);
    }
    // 关闭线程组所有其他线程（保留主进程）
    pub fn close_thread(&self) {
        let mut to_exit = vec![];
        self.op_thread_group_mut(|tg| {
            for thread in tg.iter() {
                // 跳过主线程
                if thread.tid() == thread.tgid() {
                    continue;
                }
                to_exit.push(thread.tid());
            }
        });
        for tid in to_exit {
            if let Some(thread) = get_task(tid) {
                kernel_exit(thread, -1);
            }
        }
    }

    // 抢夺线程组leader交换tid
    // 仅用于在从线程调用kernel_execve的情况
    fn exchange_tid(self: &Arc<Self>) {
        if let Some(leader) = get_task(self.tgid()) {
            // 如果指向同一个task，直接返回
            if Arc::ptr_eq(&self, &leader) {
                return;
            }
            // 确定锁的顺序以避免死锁：比较指针地址
            let (first, second) = if Arc::as_ptr(&self) < Arc::as_ptr(&leader) {
                (self, &leader)
            } else {
                (&leader, self)
            };
            // 获取两个写锁
            let mut handler1 = first.tid.write();
            let mut handler2 = second.tid.write();
            // 交换数据
            mem::swap(&mut *handler1, &mut *handler2);
            drop(handler1);
            drop(handler2);
            // 重新注册任务信息
            unregister_task(self.tid());
            unregister_task(leader.tid());
            register_task(self);
            register_task(&leader);
            // 重新向父进程注册
            self.op_parent(|parent| {
                if let Some(parent) = parent {
                    if let Some(parent) = parent.upgrade() {
                        parent.remove_child_task(self.tid());
                        parent.remove_child_task(leader.tid());
                        parent.add_child(self.clone());
                        parent.add_child(leader);
                    }
                }
            });
        }
    }

    // 复制当前内核栈trap_context内容到新内核栈中（用于kernel_clone)
    // 返回新内核栈当前指针位置（KernelStack）
    fn trap_context_clone(self: &Arc<Self>) -> usize {
        let src_kstack_top = get_stack_top_by_sp(self.kstack());
        let dst_kstack_top = kstack_alloc();
        let src_trap_cx_ptr =
            (src_kstack_top - core::mem::size_of::<TrapContext>()) as *const TrapContext;
        let dst_trap_cx_ptr =
            (dst_kstack_top - core::mem::size_of::<TrapContext>()) as *mut TrapContext;
        unsafe {
            dst_trap_cx_ptr.write(src_trap_cx_ptr.read());
        }
        dst_trap_cx_ptr as usize
    }

    pub fn process_us_time(&self) -> (TimeVal, TimeVal) {
        self.op_thread_group(|tg| {
            tg.iter()
                .map(|thread| thread.time_stat().thread_us_time())
                .reduce(|(acc_utime, acc_stime), (utime, stime)| {
                    (acc_utime + utime, acc_stime + stime)
                })
                .unwrap()
        })
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
            _ => {
                let rlim = self.op_rlimit(|rlimit| rlimit[resource as usize]);
                Ok(rlim)
            }
        }
    }
    pub fn set_rlimit(&self, resource: Resource, rlim: &RLimit) -> SyscallRet {
        match resource {
            Resource::NOFILE => {
                self.fd_table().set_rlimit(&rlim);
                Ok(0)
            }
            Resource::STACK => {
                log::error!("[set_rlimit] Fake stack");
                Ok(0)
            }
            _ => {
                self.op_rlimit_mut(|rlimit| {
                    rlimit[resource as usize].rlim_cur = rlim.rlim_cur;
                    rlimit[resource as usize].rlim_max = rlim.rlim_max;
                });
                Ok(0)
            }
        }
    }

    // pub fn alloc_fd(&mut self, file: Arc<dyn FileOp + Send + Sync>) -> usize {
    //     self.fd_table.alloc_fd(file)
    // }
    /*********************************** 权限检查 *************************************/
    // Todo: 还没有支持uid和euid
    /// 现在检查can_write, 只检查拥有者的写权限
    pub fn can_write(&self, inode: &Arc<dyn InodeOp>) -> bool {
        let mode = inode.get_mode();
        log::warn!("[can_write] Unimplemented, inode mode: {:o}", mode);
        // 现在只检查拥有者的写权限
        if mode & S_IWUSR != 0 {
            return true;
        }
        // 其他情况不允许写
        false
    }

    /*********************************** getter *************************************/

    pub fn kstack(&self) -> usize {
        self.kstack.0
    }
    pub fn tid(&self) -> Tid {
        self.tid.read().0
    }
    pub fn tgid(&self) -> Tid {
        self.tgid.load(core::sync::atomic::Ordering::SeqCst)
    }
    pub fn status(&self) -> TaskStatus {
        *self.status.lock()
    }
    pub fn time_stat(&self) -> &mut TimeStat {
        unsafe { &mut *self.time_stat.get() }
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
    pub fn exe_path(&self) -> String {
        self.exe_path.read().clone()
    }
    pub fn memory_set(&self) -> Arc<RwLock<MemorySet>> {
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
    pub fn TAC(&self) -> Option<usize> {
        self.tid_address.lock().clear_child_tid
    }
    pub fn robust_list_head(&self) -> usize {
        self.robust_list_head
            .load(core::sync::atomic::Ordering::SeqCst)
    }
    pub fn cpu_mask(&self) -> CpuMask {
        *self.cpu_mask.lock()
    }

    pub fn pgid(&self) -> usize {
        self.pgid.load(core::sync::atomic::Ordering::SeqCst)
    }

    pub fn uid(&self) -> u32 {
        self.uid.load(core::sync::atomic::Ordering::SeqCst)
    }

    pub fn euid(&self) -> u32 {
        self.euid.load(core::sync::atomic::Ordering::SeqCst)
    }

    pub fn suid(&self) -> u32 {
        self.suid.load(core::sync::atomic::Ordering::SeqCst)
    }

    pub fn gid(&self) -> u32 {
        self.gid.load(core::sync::atomic::Ordering::SeqCst)
    }

    pub fn egid(&self) -> u32 {
        self.egid.load(core::sync::atomic::Ordering::SeqCst)
    }

    pub fn sgid(&self) -> u32 {
        self.sgid.load(core::sync::atomic::Ordering::SeqCst)
    }

    /*********************************** setter *************************************/
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
    // tid_address 中的 set_child_tid
    pub fn set_TAS(&self, tas: usize) {
        self.tid_address.lock().set_child_tid = Some(tas);
    }
    // tid_address 中的 clear_child_tid
    pub fn set_TAC(&self, tac: usize) {
        self.tid_address.lock().clear_child_tid = Some(tac);
    }
    pub fn set_robust_list_head(&self, head: usize) {
        self.robust_list_head
            .store(head, core::sync::atomic::Ordering::SeqCst);
    }
    pub fn set_pgid(&self, pgid: usize) {
        self.pgid.store(pgid, core::sync::atomic::Ordering::SeqCst);
    }
    pub fn set_uid(&self, uid: u32) {
        self.uid.store(uid, core::sync::atomic::Ordering::SeqCst);
    }
    pub fn set_euid(&self, euid: u32) {
        self.euid.store(euid, core::sync::atomic::Ordering::SeqCst);
    }
    pub fn set_suid(&self, suid: u32) {
        self.suid.store(suid, core::sync::atomic::Ordering::SeqCst);
    }
    pub fn set_gid(&self, gid: u32) {
        self.gid.store(gid, core::sync::atomic::Ordering::SeqCst);
    }
    pub fn set_egid(&self, egid: u32) {
        self.egid.store(egid, core::sync::atomic::Ordering::SeqCst);
    }
    pub fn set_sgid(&self, sgid: u32) {
        self.sgid.store(sgid, core::sync::atomic::Ordering::SeqCst);
    }

    /*********************************** operator *************************************/
    pub fn op_parent<T>(&self, f: impl FnOnce(&Option<Weak<Task>>) -> T) -> T {
        f(&self.parent.lock())
    }
    pub fn op_children_mut<T>(&self, f: impl FnOnce(&mut BTreeMap<Tid, Arc<Task>>) -> T) -> T {
        f(&mut self.children.lock())
    }
    pub fn op_memory_set<T>(&self, f: impl FnOnce(&MemorySet) -> T) -> T {
        f(&self.memory_set.read())
    }
    pub fn op_memory_set_mut<T>(&self, f: impl FnOnce(&mut MemorySet) -> T) -> T {
        f(&mut self.memory_set.write())
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
    pub fn op_itimerval<T>(&self, f: impl FnOnce(&[ITimerVal; 3]) -> T) -> T {
        f(&self.itimerval.read())
    }
    pub fn op_itimerval_mut<T>(&self, f: impl FnOnce(&mut [ITimerVal; 3]) -> T) -> T {
        f(&mut self.itimerval.write())
    }
    pub fn op_rlimit<T>(&self, f: impl FnOnce(&[RLimit; RLIM_NLIMITS]) -> T) -> T {
        f(&self.rlimit.read())
    }
    pub fn op_rlimit_mut<T>(&self, f: impl FnOnce(&mut [RLimit; RLIM_NLIMITS]) -> T) -> T {
        f(&mut self.rlimit.write())
    }
    pub fn op_sup_groups<T>(&self, f: impl FnOnce(&Vec<u32>) -> T) -> T {
        f(&mut self.sup_groups.read())
    }
    pub fn op_sup_groups_mut<T>(&self, f: impl FnOnce(&mut Vec<u32>) -> T) -> T {
        f(&mut self.sup_groups.write())
    }
    /******************************** 任务状态判断 **************************************/
    pub fn is_ready(&self) -> bool {
        self.status() == TaskStatus::Ready
    }
    pub fn is_interruptable(&self) -> bool {
        self.status() == TaskStatus::Interruptable
    }
    pub fn is_uninterruptable(&self) -> bool {
        self.status() == TaskStatus::UnInterruptable
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
    pub fn set_interruptable(&self) {
        *self.status.lock() = TaskStatus::Interruptable;
    }
    pub fn set_uninterruptable(&self) {
        *self.status.lock() = TaskStatus::UnInterruptable;
    }
    pub fn set_zombie(&self) {
        *self.status.lock() = TaskStatus::Zombie;
    }
}

/****************************** 辅助函数 ****************************************/

/// 任务退出
/// 参数：task 指定任务，exit_code 退出码
/// 1. 从线程组中移除指定任务
/// 2. 修改task_status为Zombie
/// 3. 修改exit_code
/// 4. 托孤给initproc
/// 5. 将当前进程的fd_table清空, memory_set回收, children清空, sigpending清空
/// 6. 向父进程发送SIGCHLD
/// 注：现在改为调用者负责提前设置正确退出码（ 如进行操作(exit_code & 0xff)<<8 ）
pub fn kernel_exit(task: Arc<Task>, exit_code: i32) {
    log::error!("[kernel_exit] Task{} ready to exit ...", task.tid(),);
    assert_ne!(
        task.tid(),
        INIT_PROC_PID,
        "[kernel_exit] Initproc process exit with exit_code {:?} ...",
        task.exit_code()
    );

    // 检验tid_address（线程异常退出不清理）（可能语义有问题，需要细确认）
    if !task.is_process() && exit_code != -1 {
        if let Some(tidptr) = task.TAC() {
            // 防止地址不对齐的情况
            let content = [0u8; 8];
            log::info!("[kernel_exit] clear_child_tid: {:#x}", tidptr);
            if let Err(_) = copy_to_user(tidptr as *mut u8, &content as *const u8, 8) {
                panic!();
            }
            // 当 clear_child_tid 不为 NULL 的线程终止时，如果该线程与其他线程共享内存，
            // 则将 0 写入 clear_child_tid 指定的地址，并且内核将执行以下操作：
            //      futex(clear_child_tid, FUTEX_WAKE, 1, NULL, NULL, 0);
            if let Err(_) = do_futex(tidptr, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0, 0, 0) {
                panic!();
            }
        }
    }

    // 从调度队列中移除（包括阻塞队列）
    delete_wait(task.tid());
    remove_task(task.tid());
    cancel_wait_alarm(task.tid());

    // 由于线程不通过waitpid，因此将线程直接从父进程中移除
    if !task.is_process() {
        task.op_parent(|parent| {
            if let Some(parent) = parent {
                log::error!("[kernel_exit] Task{} remove from parent", task.tid());
                if let Some(parent) = parent.upgrade() {
                    parent.remove_child_task(task.tid());
                }
            }
        });
    } else {
        // 如果是主线程退出，从线程直接全部退出
        task.close_thread();
    }

    // 从线程组中移除当前任务
    task.op_thread_group_mut(|tg| tg.remove(task.tid()));

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
        for child in children.values() {
            child.set_parent(INITPROC.clone());
            INITPROC.add_child(child.clone())
        }
        children.clear();
    });
    // 回收地址空间
    if Arc::strong_count(&task.memory_set) == 1 {
        log::warn!("[kernel_exit] Task{} memory_set recycle", task.tid());
        task.op_memory_set_mut(|mem| {
            mem.recycle_data_pages();
        });
    }
    // 清空文件描述符表
    if Arc::strong_count(&task.fd_table) == 1 {
        log::warn!("[kernel_exit] Task{} fd_table recycle", task.tid());
        task.fd_table().clear();
    }
    // 清空信号
    task.op_sig_pending_mut(|pending| {
        pending.clear();
    });
    // 向父进程发送SIGCHID
    if task.thread_group.lock().len() == 0 {
        log::warn!(
            "[kernel_exit] Task{} is the last in thread-group",
            task.tid()
        );
        task.op_parent(|parent| {
            if let Some(parent) = parent {
                log::debug!("[kernel_exit] Task{} send SIGCHILD to parent", task.tid());
                let parent = parent.upgrade().unwrap();
                parent.receive_siginfo(
                    SigInfo {
                        signo: Sig::SIGCHLD.raw(),
                        code: SigInfo::CLD_EXITED,
                        fields: SiField::None,
                    },
                    false,
                );
                log::debug!(
                    "[kernel_exit] Task{} wakeup parent-{}",
                    task.tid(),
                    parent.tid()
                );
                wakeup(parent.tid());
            }
        });
    }
    // 注销任务
    unregister_task(task.tid());
    log::error!("[kernel_exit] Task{} clear the resource", task.tid());
    log::error!(
        "[kernel_exit] Task{} strong count: {}",
        task.tid(),
        Arc::strong_count(&task)
    );
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

    pub fn remove(&mut self, tid: Tid) {
        self.member.remove(&tid);
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
    Interruptable,
    UnInterruptable,
    Zombie,
}

bitflags! {
    /// Open file flags
    #[derive(Debug)]
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
        // 如果设置此标志，子进程将与父进程共享文件系统信息
        //（这包括文件系统的根目录、当前工作目录和umask）
        const CLONE_FS = 1 << 9;
        // 如果设置此标志，子进程将与父进程共享文件描述符表。
        const CLONE_FILES = 1 << 10;
        // 如果设置此标志，子进程将与父进程共享信号处理器。
        const CLONE_SIGHAND = 1 << 11;
        const CLONE_PIDFD = 1 << 12;
        const CLONE_PTRACE = 1 << 13;
        const CLONE_VFORK = 1 << 14;
        const CLONE_PARENT = 1 << 15;
        const CLONE_THREAD = 1 << 16;
        const CLONE_NEWNS = 1 << 17;
        // 如果设置了 CLONE_SYSVSEM，则子进程和调用进程共享一个 System V 信号量调整 (semadj) 值列表
        const CLONE_SYSVSEM = 1 << 18;
        // TLS（线程本地存储）描述符设置为 tls（将tp换成user_tp)
        const CLONE_SETTLS = 1 << 19;
        // 将子线程 ID 存储在父线程内存中 parent_tid
        const CLONE_PARENT_SETTID = 1 << 20;
        // 当子进程退出时，清除（归零）子进程内存中 child_tid
        const CLONE_CHILD_CLEARTID = 1 << 21;
        // 此标志仍然有定义，但在调用 clone() 时通常会被忽略。
        const CLONE_DETACHED = 1 << 22;
        // 如果指定了 CLONE_UNTRACED，则跟踪进程无法强制对该子进程执行 CLONE_PTRACE。
        const CLONE_UNTRACED = 1 << 23;
        // 将子线程 ID 存储在子进程内存中 child_tid
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
    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct CpuMask: usize {
        const CPU0 = 0b00000001;
        // const CPU1 = 0b00000010;
        // const CPU2 = 0b00000100;
        // const CPU3 = 0b00001000;
        // const CPU4 = 0b00010000;
        // const CPU5 = 0b00100000;
        // const CPU6 = 0b01000000;
        // const CPU7 = 0b10000000;
        const ALL = 0b00000001;
    }
}

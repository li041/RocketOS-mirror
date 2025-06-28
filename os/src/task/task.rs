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
        config::USER_STACK_SIZE, mm::copy_to_user, trap::{
            context::{get_trap_context, save_trap_context},
            TrapContext,
        }
    },
    ext4::inode::{S_IWGRP, S_IWOTH, S_IWUSR},
    fs::{
        fdtable::FdTable,
        file::FileOp,
        inode::InodeOp,
        path::Path,
        uapi::{RLimit, Resource},
    },
    futex::{
        do_futex,
        flags::{FUTEX_PRIVATE_FLAG, FUTEX_WAKE},
    },
    mm::{MapArea, MapPermission, MapType, MemorySet, VPNRange, VirtAddr, KERNEL_SPACE},
    net::addr::is_unspecified,
    signal::{SiField, Sig, SigHandler, SigInfo, SigPending, SigSet, SigStack, UContext},
    syscall::errno::{self, Errno, SyscallRet},
    task::{
        self, add_task, context::write_task_cx, current_task, dump_wait_queue, idle_task, manager::{
            add_group, cancel_wait_alarm, delete_wait, new_group, register_task, remove_group,
        }, processor::{current_hart_id, current_tp, preempte}, scheduler::{add_task_init, select_cpu, DEFAULT_PRIO}, wakeup, INITPROC, SCHED_IDLE, SCHED_OTHER
    },
    timer::{ITimerVal, TimeVal},
};
use alloc::{
    collections::btree_map::BTreeMap,
    format,
    string::ToString,
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use bitflags::bitflags;
use core::{
    assert_ne,
    cell::SyncUnsafeCell,
    fmt::Write,
    mem,
    sync::atomic::{AtomicI32, AtomicI8, AtomicU16, AtomicU32, AtomicUsize},
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
    // kstack在Task中要保持在第一个field
    // cpu_id在Task中要保持在第二个field
    kstack: KernelStack, // 内核栈
    cpu_id: usize,       // 当前任务绑定的CPU id

    // 变量
    // 基本变量
    tid: RwLock<TidHandle>,                         // 线程id
    tgid: AtomicUsize,                              // 线程组id
    pgid: AtomicUsize,                              // 进程组id
    status: Mutex<TaskStatus>,                      // 任务状态
    time_stat: SyncUnsafeCell<TimeStat>,            // 任务时间统计
    parent: Arc<Mutex<Option<Weak<Task>>>>,         // 父任务
    children: Arc<Mutex<BTreeMap<Tid, Arc<Task>>>>, // 子任务
    thread_group: Arc<Mutex<ThreadGroup>>,          // 线程组
    exit_code: AtomicI32,                           // 退出码
    exe_path: Arc<RwLock<String>>,                  // 执行路径
    // 内存管理（包括System V shm管理）
    memory_set: RwLock<Arc<RwLock<MemorySet>>>, // 地址空间
    // futex管理, 线程局部
    robust_list_head: AtomicUsize, //  线程局部的robust futex链表头
    // 文件系统
    fd_table: Mutex<Arc<FdTable>>,
    root: Arc<Mutex<Arc<Path>>>,
    pwd: Arc<Mutex<Arc<Path>>>,
    umask: AtomicU16, // 文件权限掩码
    // 信号处理
    sig_pending: Mutex<SigPending>,         // 待处理信号
    sig_handler: Arc<Mutex<SigHandler>>,    // 信号处理函数
    itimerval: Arc<RwLock<[ITimerVal; 3]>>, // 定时器
    // 资源限制
    rlimit: Arc<RwLock<[RLimit; 16]>>,
    // 权限设置
    uid: AtomicU32,               // 用户id
    euid: AtomicU32,              // 有效用户id
    suid: AtomicU32,              // 保存用户id
    fsuid: AtomicU32,             // 文件系统用户id
    gid: AtomicU32,               // 组id
    egid: AtomicU32,              // 有效组id
    sgid: AtomicU32,              // 保存组id
    fsgid: AtomicU32,             // 文件系统组id
    sup_groups: RwLock<Vec<u32>>, // 附加组列表
    // 任务内部结构
    task_inner: Mutex<TaskInner>, // 内部结构
}

// 任务结构中修改频率较低字段（不会发生共享）
// 由于内部字段读写次数均较少，因此在外层统一用一把大锁来管理
pub struct TaskInner {
    priority: u32,           // 任务的优先级 [1-99]为实时优先级，[100-139]为普通优先级 0为空闲任务
    policy: u32,             // 任务的调度策略
    tid_address: TidAddress, // 线程id地址
    sig_stack: SigStack,     // 额外信号栈
    cpu_mask: CpuMask,       // CPU掩码
}

impl TaskInner {
    pub fn new() -> Self {
        Self {
            priority: DEFAULT_PRIO, // 默认优先级
            policy: SCHED_OTHER,
            tid_address: TidAddress::new(),
            sig_stack: SigStack::default(),
            cpu_mask: CpuMask::ALL,
        }
    }

    pub fn idle_init() -> Self {
        Self {
            priority: 0, // 空闲任务优先级
            policy: SCHED_IDLE,
            tid_address: TidAddress::new(),
            sig_stack: SigStack::default(),
            cpu_mask: CpuMask::ALL,
        }
    }
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
    pub fn zero_init() -> Arc<Self> {
        println!("[Task::zero_init] create idle task");
        let sig_handler = Arc::new(Mutex::new(SigHandler::new()));
        println!("after sig_handler init");
        Arc::new(Self {
            kstack: KernelStack(0),
            cpu_id: 0,
            tid: RwLock::new(TidHandle(0)),
            tgid: AtomicUsize::new(0),
            status: Mutex::new(TaskStatus::Ready),
            time_stat: SyncUnsafeCell::new(TimeStat::default()),
            parent: Arc::new(Mutex::new(None)),
            children: Arc::new(Mutex::new(BTreeMap::new())),
            thread_group: Arc::new(Mutex::new(ThreadGroup::new())),
            exit_code: AtomicI32::new(0),
            exe_path: Arc::new(RwLock::new(String::new())),
            memory_set: RwLock::new(Arc::new(RwLock::new(MemorySet::new_bare()))),
            robust_list_head: AtomicUsize::new(0),
            fd_table: Mutex::new(FdTable::new_bare()),
            root: Arc::new(Mutex::new(Path::zero_init())),
            pwd: Arc::new(Mutex::new(Path::zero_init())),
            umask: AtomicU16::new(0),
            sig_pending: Mutex::new(SigPending::new()),
            sig_handler: Arc::new(Mutex::new(SigHandler::new())),
            itimerval: Arc::new(RwLock::new([ITimerVal::default(); 3])),
            rlimit: Arc::new(RwLock::new([RLimit::default(); RLIM_NLIMITS])),
            pgid: AtomicUsize::new(0),
            uid: AtomicU32::new(0),
            euid: AtomicU32::new(0),
            suid: AtomicU32::new(0),
            fsuid: AtomicU32::new(0),
            gid: AtomicU32::new(0),
            egid: AtomicU32::new(0),
            sgid: AtomicU32::new(0),
            fsgid: AtomicU32::new(0),
            sup_groups: RwLock::new(Vec::new()),
            task_inner: Mutex::new(TaskInner::idle_init()),
        })
    }

    /// 初始化地址空间, 将 `TrapContext` 与 `TaskContext` 压入内核栈中
    pub fn initproc(elf_data: &[u8], root_path: Arc<Path>) -> Arc<Self> {
        let (memory_set, pgdl_ppn, user_sp, entry_point, _aux_vec, _tls_ptr) =
            MemorySet::from_elf(elf_data.to_vec(), &mut Vec::<String>::new());
        let tid = tid_alloc();
        let tgid = tid.0;
        let mut kstack = kstack_alloc();
        // Trap_context
        let mut trap_context = TrapContext::app_init_trap_context(entry_point, user_sp, 0, 0, 0, 0);
        kstack -= core::mem::size_of::<TrapContext>();
        let trap_cx_ptr = kstack as *mut TrapContext;
        // Task_context
        kstack -= core::mem::size_of::<TaskContext>();
        let task_cx_ptr = kstack as *mut TaskContext;
        // 创建进程实体
        let memory_set = RwLock::new(Arc::new(RwLock::new(memory_set)));
        let root = Arc::new(Mutex::new(root_path.clone()));
        let pwd = Arc::new(Mutex::new(root_path));
        let exe_path = Arc::new(RwLock::new(String::new()));

        let task = Arc::new(Task {
            kstack: KernelStack(kstack),
            cpu_id: current_hart_id(),
            tid: RwLock::new(tid),
            tgid: AtomicUsize::new(tgid),
            pgid: AtomicUsize::new(1),
            status: Mutex::new(TaskStatus::Ready),
            time_stat: SyncUnsafeCell::new(TimeStat::default()),
            parent: Arc::new(Mutex::new(None)),
            // 注：children结构中保留了对任务的Arc引用
            children: Arc::new(Mutex::new(BTreeMap::new())),
            thread_group: Arc::new(Mutex::new(ThreadGroup::new())),
            exit_code: AtomicI32::new(0),
            exe_path,
            memory_set,
            robust_list_head: AtomicUsize::new(0),
            fd_table: Mutex::new(FdTable::new()),
            root,
            pwd,
            umask: AtomicU16::new(S_IWGRP | S_IWOTH), // 默认umask为022
            sig_pending: Mutex::new(SigPending::new()),
            sig_handler: Arc::new(Mutex::new(SigHandler::new())),
            itimerval: Arc::new(RwLock::new([ITimerVal::default(); 3])),
            rlimit: Arc::new(RwLock::new([RLimit::default(); RLIM_NLIMITS])),
            uid: AtomicU32::new(0), // 默认为root(0)用户
            euid: AtomicU32::new(0),
            suid: AtomicU32::new(0),
            fsuid: AtomicU32::new(0),
            gid: AtomicU32::new(0),
            egid: AtomicU32::new(0),
            sgid: AtomicU32::new(0),
            fsgid: AtomicU32::new(0),
            sup_groups: RwLock::new(Vec::new()),
            task_inner: Mutex::new(TaskInner::new()),
        });
        // 向线程组中添加该进程
        task.thread_group
            .lock()
            .add(task.tid(), Arc::downgrade(&task));
        add_task_init(task.clone());
        register_task(&task);
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
        task
    }

    /// 初始化空闲任务
    /// 用于防止内核无任务，只在内核态空转
    pub fn init_idle_task(hart_id: usize) -> Arc<Self> {
        let tid = tid_alloc();
        let mut kstack = kstack_alloc();
        // Task_context
        kstack -= core::mem::size_of::<TaskContext>();
        let memory_set = MemorySet::new_bare();
        let task_cx_ptr = kstack as *mut TaskContext;
        // 创建进程实体
        let task = Arc::new(Task {
            kstack: KernelStack(kstack),
            cpu_id: hart_id,
            tid: RwLock::new(tid),
            tgid: AtomicUsize::new(0),
            status: Mutex::new(TaskStatus::Ready),
            time_stat: SyncUnsafeCell::new(TimeStat::default()),
            parent: Arc::new(Mutex::new(None)),
            children: Arc::new(Mutex::new(BTreeMap::new())),
            thread_group: Arc::new(Mutex::new(ThreadGroup::new())),
            exit_code: AtomicI32::new(0),
            exe_path: Arc::new(RwLock::new(String::new())),
            memory_set: RwLock::new(Arc::new(RwLock::new(memory_set))),
            robust_list_head: AtomicUsize::new(0),
            fd_table: Mutex::new(FdTable::new_bare()),
            root: Arc::new(Mutex::new(Path::zero_init())),
            pwd: Arc::new(Mutex::new(Path::zero_init())),
            umask: AtomicU16::new(0),
            sig_pending: Mutex::new(SigPending::new()),
            sig_handler: Arc::new(Mutex::new(SigHandler::new())),
            itimerval: Arc::new(RwLock::new([ITimerVal::default(); 3])),
            rlimit: Arc::new(RwLock::new([RLimit::default(); RLIM_NLIMITS])),
            pgid: AtomicUsize::new(0),
            uid: AtomicU32::new(0),
            euid: AtomicU32::new(0),
            suid: AtomicU32::new(0),
            fsuid: AtomicU32::new(0),
            gid: AtomicU32::new(0),
            egid: AtomicU32::new(0),
            sgid: AtomicU32::new(0),
            fsgid: AtomicU32::new(0),
            sup_groups: RwLock::new(Vec::new()),
            task_inner: Mutex::new(TaskInner::idle_init()),
        });
        add_task_init(task.clone());
        // 令tp与kernel_tp指向主线程内核栈顶
        let task_ptr = Arc::as_ptr(&task) as usize;
        let task_context = TaskContext::idle_init_task_context(task_ptr);
        // 将TaskContext压入内核栈
        unsafe {
            task_cx_ptr.write(task_context);
        }
        task
    }

    // 从父进程复制子进程的核心逻辑实现
    pub fn kernel_clone(
        self: &Arc<Self>,
        flags: &CloneFlags,
        ustack_ptr: usize,
        children_tid_ptr: usize,
    ) -> Result<Arc<Self>, Errno> {
        let tid = tid_alloc();
        let exit_code = AtomicI32::new(0);
        let status = Mutex::new(TaskStatus::Ready);
        let tgid;
        let mut kstack;
        let mut parent;
        let children;
        let thread_group;
        let itimerval;
        let memory_set;
        let fd_table;
        let root;
        let pwd;
        let sig_handler;
        let sig_pending;
        let rlimit;
        let pgid;
        let uid;
        let euid;
        let suid;
        let fsuid;
        let gid;
        let egid;
        let sgid;
        let fsgid;
        let sup_groups;
        let cpu_id;
        log::info!("[kernel_clone] task{} ready to clone ...", self.tid());

        // 是否与父进程共享信号处理器
        if flags.contains(CloneFlags::CLONE_SIGHAND) {
            log::warn!("[kernel_clone] handle CLONE_SIGHAND");
            sig_handler = self.sig_handler.clone();
        } else {
            sig_handler = Arc::new(Mutex::new(
                self.op_sig_handler_mut(|handler| handler.clone()),
            ))
        }

        // 为了写到子空间，此处直接写入父空间再复制到子空间
        if flags.contains(CloneFlags::CLONE_CHILD_SETTID) {
            log::warn!("[sys_clone] handle CLONE_CHILD_SETTID");
            let content = (tid.0 as u64).to_le_bytes();
            copy_to_user(children_tid_ptr as *mut u8, &content as *const u8, 8)?;
        }

        // 继承父进程
        pgid = AtomicUsize::new(self.pgid());
        uid = AtomicU32::new(self.uid());
        euid = AtomicU32::new(self.euid());
        suid = AtomicU32::new(self.suid());
        fsuid = AtomicU32::new(self.fsuid());
        gid = AtomicU32::new(self.gid());
        egid = AtomicU32::new(self.egid());
        sgid = AtomicU32::new(self.sgid());
        fsgid = AtomicU32::new(self.fsgid());
        sup_groups = RwLock::new(self.op_sup_groups_mut(|groups| groups.clone()));
        // cpu_id = select_cpu();
        cpu_id = self.cpu_id; // 继承父进程的cpu_id

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
            rlimit = self.rlimit.clone();
        }
        // 创建进程
        else {
            log::info!("[kernel_clone] child task{} is a process", tid);
            tgid = AtomicUsize::new(tid.0);
            parent = Arc::new(Mutex::new(Some(Arc::downgrade(self))));
            children = Arc::new(Mutex::new(BTreeMap::new()));
            thread_group = Arc::new(Mutex::new(ThreadGroup::new()));
            itimerval = Arc::new(RwLock::new([ITimerVal::default(); 3]));
            rlimit = Arc::new(RwLock::new([RLimit::default(); RLIM_NLIMITS]));
        }

        if flags.contains(CloneFlags::CLONE_PARENT) {
            parent = Arc::new(Mutex::new(self.parent.lock().clone()));
        }

        // 对vfork情况做特殊处理
        if flags.contains(CloneFlags::CLONE_VM) {
            log::warn!("[kernel_clone] handle CLONE_VM");
            memory_set = RwLock::new(self.memory_set.read().clone());
        } else {
            memory_set = RwLock::new(Arc::new(RwLock::new(MemorySet::from_existed_user_lazily(
                &self.memory_set.read().read(),
            ))));
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
            fd_table = Mutex::new(self.fd_table());
        } else {
            log::warn!("[kernel_clone] fd_table from_existed_user");
            fd_table = Mutex::new(FdTable::from_existed_user(&self.fd_table()));
        }

        // 申请新的内核栈并复制父进程trap_cx内容
        kstack = self.trap_context_clone();
        // 更新task_cx
        kstack -= core::mem::size_of::<TaskContext>();
        let kstack = KernelStack(kstack);

        // 初始化其他未初始化属性
        sig_pending = Mutex::new(SigPending::new());
        let tid = RwLock::new(tid);
        let robust_list_head = AtomicUsize::new(0);
        let time_stat = SyncUnsafeCell::new(TimeStat::default());
        let umask = AtomicU16::new(self.umask.load(core::sync::atomic::Ordering::Relaxed));
        let exe_path = self.exe_path.clone();
        let task_inner = Mutex::new(TaskInner {
            priority: self.priority(),
            policy: self.policy(),
            tid_address: TidAddress::new(),
            sig_stack: self.sigstack().clone(),
            cpu_mask: CpuMask::ALL,
        });
        // 创建新任务
        let task = Arc::new(Self {
            kstack,
            cpu_id,
            tid,
            tgid,
            pgid,
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
            umask,
            sig_handler,
            sig_pending,
            itimerval,
            rlimit,
            uid,
            euid,
            suid,
            fsuid,
            gid,
            egid,
            sgid,
            fsgid,
            sup_groups,
            task_inner,
        });
        log::trace!("[kernel_clone] child task{} created", task.tid());

        if flags.contains(CloneFlags::CLONE_CHILD_SETTID) {
            task.set_tas(task.tid());
        }

        // 向任务管理器注册新任务（不是调度器）
        register_task(&task);

        if task.is_process() {
            // 向父进程中记录子进程，向父进程组中添加子进程
            self.add_child(task.clone());
            add_group(task.pgid(), &task);
        } else {
            // 线程的父进程为当前任务的父进程，对于线程任务不加入进程组
            self.op_parent(|parent| {
                if let Some(parent) = parent {
                    parent.upgrade().unwrap().add_child(task.clone());
                }
            });
        }

        // 向线程组添加子进程 （包括当前任务为进程的情况）
        task.op_thread_group_mut(|tg| tg.add(task.tid(), Arc::downgrade(&task)));

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
        log::info!(
            "[kernel_clone] task{}-parent:\t{:x}",
            task.tid(),
            task.op_parent(|p| p.as_ref().unwrap().upgrade().unwrap().tid())
        );
        log::info!("[kernel_clone] task{}-sp:\t{:x}", task.tid(), task.kstack());
        log::info!("[kernel_clone] task{}-tgid:\t{:x}", task.tid(), task.tgid());
        log::info!("[kernel_clone] task{}-pgid:\t{:x}", task.tid(), task.pgid());
        log::info!("[kernel_clone] task{}-cpu_id:\t{}", task.tid(), task.cpu_id());
        log::info!("[kernel_clone] task{}-priority:\t{}", task.tid(), task.priority());
        log::info!("[kernel_clone] task{} clone complete!", self.tid());

        Ok(task)
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
                false,
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
        *self.memory_set.write() = Arc::new(RwLock::new(memory_set));

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
    }

    pub fn kernel_execve_lazily(
        self: &Arc<Self>,
        exe_path: String,
        elf_file: Arc<dyn FileOp>,
        mut args_vec: Vec<String>,
        envs_vec: Vec<String>,
    ) -> SyscallRet {
        log::info!("[kernel_execve] task{} do execve ...", self.tid());
        // 创建地址空间
        let (mut memory_set, _satp, ustack_top, entry_point, aux_vec) =
            MemorySet::from_elf_lazily(elf_file, &mut args_vec)?;
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
                false,
            ),
            None,
            0,
        );

        // 初始化用户栈, 压入args和envs
        let argc = args_vec.len();
        log::error!("[kernel_execve_lazily] argc {:?}", argc);
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
        *self.memory_set.write() = Arc::new(RwLock::new(memory_set));

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

        Ok(0)
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

    pub fn get_rlimit(&self, resource: Resource) -> Result<RLimit, Errno> {
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

    pub fn compare_permision(&self, task: &Arc<Task>) -> SyscallRet {
        // 如果是root用户，直接返回
        if self.euid() == 0 {
            return Ok(0);
        }

        // 同一线程组，直接返回
        if self.tgid() == task.tgid() {
            return Ok(0);
        }

        // 非root用户，检查权限
        let uid = self.uid();
        let gid = self.gid();
        if uid == task.uid()
            && uid == task.euid()
            && uid == task.suid()
            && gid == task.gid()
            && gid == task.egid()
            && gid == task.sgid()
        {
            return Ok(0);
        }

        // 权限检查不通过
        return Err(Errno::EPERM);
    }

    pub fn same_thread_group(&self, task: &Arc<Task>) -> bool {
        self.tgid() == task.tgid()
    }

    // 检查task是否为调用任务的子任务
    pub fn is_child(&self, tid: usize) -> bool {
        self.children.lock().contains_key(&tid)
    }

    // 比较两个任务memset是否相同，用于确定子进程是否执行过execve
    pub fn compare_memset(&self, task: &Arc<Task>) -> bool {
        Arc::ptr_eq(&self.memory_set.read(), &task.memory_set.read())
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
    pub fn umask(&self) -> u16 {
        self.umask.load(core::sync::atomic::Ordering::Relaxed)
    }
    pub fn exit_code(&self) -> i32 {
        self.exit_code.load(core::sync::atomic::Ordering::SeqCst)
    }
    pub fn exe_path(&self) -> String {
        self.exe_path.read().clone()
    }
    pub fn memory_set(&self) -> Arc<RwLock<MemorySet>> {
        self.memory_set.read().clone()
    }
    pub fn fd_table(&self) -> Arc<FdTable> {
        self.fd_table.lock().clone()
    }
    pub fn mask(&self) -> SigSet {
        self.sig_pending.lock().mask
    }
    pub fn sigstack(&self) -> SigStack {
        self.task_inner.lock().sig_stack
    }
    pub fn tac(&self) -> Option<usize> {
        self.task_inner.lock().tid_address.clear_child_tid
    }
    pub fn robust_list_head(&self) -> usize {
        self.robust_list_head
            .load(core::sync::atomic::Ordering::SeqCst)
    }
    pub fn cpu_mask(&self) -> CpuMask {
        self.task_inner.lock().cpu_mask
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

    pub fn fsuid(&self) -> u32 {
        self.fsuid.load(core::sync::atomic::Ordering::SeqCst)
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

    pub fn fsgid(&self) -> u32 {
        self.fsgid.load(core::sync::atomic::Ordering::SeqCst)
    }

    pub fn cpu_id(&self) -> usize {
        self.cpu_id
    }

    pub fn priority(&self) -> u32 {
        self.task_inner.lock().priority
    }

    pub fn policy(&self) -> u32 {
        self.task_inner.lock().policy
    }
    /*********************************** setter *************************************/
    pub fn set_root(&self, root: Arc<Path>) {
        *self.root.lock() = root;
    }
    pub fn set_pwd(&self, pwd: Arc<Path>) {
        *self.pwd.lock() = pwd;
    }
    pub fn set_umask(&self, umask: u16) {
        self.umask
            .store(umask, core::sync::atomic::Ordering::Relaxed);
    }
    pub fn set_exit_code(&self, exit_code: i32) {
        self.exit_code
            .store(exit_code, core::sync::atomic::Ordering::SeqCst);
    }
    pub fn set_parent(&self, parent: Arc<Task>) {
        *self.parent.lock() = Some(Arc::downgrade(&parent));
    }
    pub fn set_sigstack(&self, sigstack: SigStack) {
        self.task_inner.lock().sig_stack = sigstack
    }
    // tid_address 中的 set_child_tid
    pub fn set_tas(&self, tas: usize) {
        self.task_inner.lock().tid_address.set_child_tid = Some(tas);
    }
    // tid_address 中的 clear_child_tid
    pub fn set_tac(&self, tac: usize) {
        self.task_inner.lock().tid_address.clear_child_tid = Some(tac);
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
    pub fn set_fsuid(&self, fsuid: u32) {
        self.fsuid
            .store(fsuid, core::sync::atomic::Ordering::SeqCst);
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
    pub fn set_fsgid(&self, fsgid: u32) {
        self.fsgid
            .store(fsgid, core::sync::atomic::Ordering::SeqCst);
    }
    pub fn set_priority(&self, priority: u32) {
        self.task_inner.lock().priority = priority;
    }
    pub fn set_cpu_mask(&self, cpu_mask: CpuMask) {
        self.task_inner.lock().cpu_mask = cpu_mask;
    }
    pub fn set_policy(&self, policy: u32) {
        self.task_inner.lock().policy = policy;
    }
    /*********************************** operator *************************************/
    pub fn op_parent<T>(&self, f: impl FnOnce(&Option<Weak<Task>>) -> T) -> T {
        f(&self.parent.lock())
    }
    pub fn op_children_mut<T>(&self, f: impl FnOnce(&mut BTreeMap<Tid, Arc<Task>>) -> T) -> T {
        f(&mut self.children.lock())
    }
    pub fn op_memory_set<T>(&self, f: impl FnOnce(&MemorySet) -> T) -> T {
        f(&self.memory_set.read().read())
    }
    pub fn op_memory_set_mut<T>(&self, f: impl FnOnce(&mut MemorySet) -> T) -> T {
        f(&mut self.memory_set.read().write())
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
    /******************************** 任务信息提供 **************************************/

    pub fn info(&self) -> String {
        let mut info = String::new();
        // 名称：这里我们用执行路径的文件名部分作为任务名（类似 bash）
        let name = self.exe_path.read();
        let name = name.rsplit('/').next().unwrap_or("unknown");
        let umask = 0o022; // 默认umask为022(fake)
        let status = self.status.lock();
        let state_str = match *status {
            TaskStatus::Running | TaskStatus::Ready => "R (running)",
            TaskStatus::Interruptable => "S (sleeping)",
            TaskStatus::UnInterruptable => "D (Uninterruptible sleep)",
            TaskStatus::Zombie => "Z (zombie)",
        };
        let tgid = self.tgid();
        let ngid = 0; // NUMA 组 ID（如果没有则为 0）
        let pid = self.tid();
        let ppid = self.op_parent(|parent| {
            if let Some(parent) = parent {
                parent.upgrade().map_or(0, |p| p.tid())
            } else {
                0
            }
        });
        let tracerpid = 0; // 跟踪此进程的进程 PID（如果未被跟踪，则为 0）
        let uid = self.uid();
        let euid = self.euid();
        let suid = self.suid();
        let fsuid = self.fsuid();
        let gid = self.gid();
        let egid = self.egid();
        let sgid = self.sgid();
        let fsgid = self.fsgid();
        let fdsize = self.fd_table().get_rlimit().rlim_cur as usize;
        let mut groups = String::new();
        self.op_sup_groups_mut(|sup_groups| {
            for group in sup_groups.iter() {
                groups.push_str(&format!("{} ", group));
            }
        });
        let nstgid = self.tgid(); // pid 所属的每个 PID 命名空间中的线程组 ID
        let nstpid = self.tid(); // pid 所属的每个 PID 命名空间中的线程 ID
        let nspgid = self.pgid(); // pid 所属的每个 PID 命名空间中的进程组 ID
        let nssid = self.tgid(); // pid 所属的每个 PID 命名空间中的会话 ID
        let vmpeak = 3356; // 虚拟内存峰值（fake）需要遍历统计
        let vmsize = 3356; // 虚拟内存大小（fake）
        let vmlck = 0; // 锁定的虚拟内存大小（fake）
        let vmpin = 0; // 锁定的物理内存大小（fake）
        let vmhwm = 1076; // 常驻内存峰值（fake）
        let vmrss = 1076; // 常驻内存大小（fake）请注意，此处的值是 RssAnon、RssFile 和 RssShmem 的总和
        let rssanon = 92; // 匿名内存（fake）
        let rssfile = 984; // 文件映射的常驻内存（fake）
        let rssshmem = 0; // 共享内存的常驻内存（fake）
        let vmdata = 3840; // 数据段大小（fake）
        let vmstk = 2570; // 栈大小（fake）
        let vmexe = 378; // 可执行文件大小（fake）
        let vmlib = 993; // 共享库大小（fake）
        let vmpte = 85; // 页表大小（fake）
        let vmswap = 169; // 交换空间大小（fake）
        let hugetlbpages = 0; // 巨页内存大小（fake）
        let core_dumping = 0; // 核心转储大小（fake）
        let thp_enabled = 1; // 透明大页是否启用（fake）
        let threads = self.op_thread_group(|tg| tg.len());
        let sigq = 1; // 信号队列大小（fake）
        let sigpnd = self.mask(); // 信号掩码
        let shdpnd = 0; // 共享信号掩码（fake）
        let sigblk = 0; // 阻塞的信号掩码（fake）
        let sigign = 0; // 忽略的信号掩码（fake）
        let sigcatch = 0; // 捕获的信号掩码（fake）
        let cap_inheritable = 0; // 可继承的能力（fake）
        let cap_permitted = 0; // 允许的能力（fake）
        let cap_effective = 0; // 有效的能力（fake）
        let cap_bounding = 0x000001ffffffffff as i64; // 边界能力（fake）
        let cap_ambient = 0; // 环境能力（fake）
        let no_new_privs = 0; // 是否设置了 no_new_privs（fake）
        let seccomp = 0; // seccomp 状态（fake）
        let seccomp_filter = 0; // seccomp 过滤器（fake）
        let speculation_store_bypass = "thread vulnerable".to_string();
        let speculation_indirect_branch = "conditional enabled".to_string();
        let cpus_allowed = 1; // 允许的 CPU 掩码（fake）
        let cpus_allowed_list = "0".to_string(); // 允许的 CPU 列表（fake）
        let mems_allowed = 1; // 允许的内存节点掩码（fake）
        let mems_allowed_list = "0".to_string(); // 允许的内存节点列表（fake）
        let voluntary_ctxt_switches = 0; // 自愿上下文切换次数（fake）
        let nonvoluntary_ctxt_switches = 0; // 非自愿上下文切换次数（fake）

        // 构造信息
        write!(
            info,
            "\
            Name:\t{}\n\
            Umask:\t{:04o}\n\
            State:\t{}\n\
            Tgid:\t{}\n\
            Ngid:\t{}\n\
            Pid:\t{}\n\
            PPid:\t{}\n\
            TracerPid:\t{}\n\
            Uid:\t{}\t{}\t{}\t{}\n\
            Gid:\t{}\t{}\t{}\t{}\n\
            FDSize:\t{}\n\
            Groups:\t{}\n\
            NStgid:\t{}\n\
            NSpid:\t{}\n\
            NSpgid:\t{}\n\
            NSsid:\t{}\n\
            VmPeak:\t{:>8} kB\n\
            VmSize:\t{:>8} kB\n\
            VmLck:\t{:>8} kB\n\
            VmPin:\t{:>8} kB\n\
            VmHWM:\t{:>8} kB\n\
            VmRSS:\t{:>8} kB\n\
            RssAnon:\t{:>8} kB\n\
            RssFile:\t{:>8} kB\n\
            RssShmem:\t{:>8} kB\n\
            VmData:\t{:>8} kB\n\
            VmStk:\t{:>8} kB\n\
            VmExe:\t{:>8} kB\n\
            VmLib:\t{:>8} kB\n\
            VmPTE:\t{:>8} kB\n\
            VmSwap:\t{:>8} kB\n\
            HugetlbPages:\t{:>8} kB\n\
            CoreDumping:\t{}\n\
            THP_enabled:\t{}\n\
            Threads:\t{}\n\
            SigQ:\t{}/31760\n\
            SigPnd:\t{:016x}\n\
            ShdPnd:\t{:016x}\n\
            SigBlk:\t{:016x}\n\
            SigIgn:\t{:016x}\n\
            SigCgt:\t{:016x}\n\
            CapInh:\t{:016x}\n\
            CapPrm:\t{:016x}\n\
            CapEff:\t{:016x}\n\
            CapBnd:\t{:016x}\n\
            CapAmb:\t{:016x}\n\
            NoNewPrivs:\t{}\n\
            Seccomp:\t{}\n\
            Seccomp_filters:\t{}\n\
            Speculation_Store_Bypass:\t{}\n\
            SpeculationIndirectBranch:\t{}\n\
            Cpus_allowed:\t{:x}\n\
            Cpus_allowed_list:\t{}\n\
            Mems_allowed:\t{:x}\n\
            Mems_allowed_list:\t{}\n\
            voluntary_ctxt_switches:\t{}\n\
            nonvoluntary_ctxt_switches:\t{}\n",
            name,
            umask,
            state_str,
            tgid,
            ngid,
            pid,
            ppid,
            tracerpid,
            uid,
            euid,
            suid,
            fsuid,
            gid,
            egid,
            sgid,
            fsgid,
            fdsize,
            groups.trim_end(),
            nstgid,
            nstpid,
            nspgid,
            nssid,
            vmpeak,
            vmsize,
            vmlck,
            vmpin,
            vmhwm,
            vmrss,
            rssanon,
            rssfile,
            rssshmem,
            vmdata,
            vmstk,
            vmexe,
            vmlib,
            vmpte,
            vmswap,
            hugetlbpages,
            core_dumping,
            thp_enabled,
            threads,
            sigq,
            sigpnd,
            shdpnd,
            sigblk,
            sigign,
            sigcatch,
            cap_inheritable,
            cap_permitted,
            cap_effective,
            cap_bounding,
            cap_ambient,
            no_new_privs,
            seccomp,
            seccomp_filter,
            speculation_store_bypass,
            speculation_indirect_branch,
            cpus_allowed,
            cpus_allowed_list,
            mems_allowed,
            mems_allowed_list,
            voluntary_ctxt_switches,
            nonvoluntary_ctxt_switches,
        )
        .unwrap();

        info
    }

    // Todo: 记录程序地址等信息，根据需要完善
    pub fn stat(&self) -> String {
        let tid = self.tid();
        let name = self.exe_path.read();
        let name = name.rsplit('/').next().unwrap_or("unknown");
        let comm = format!("({})", name);

        let status = self.status.lock();
        let state_char = match *status {
            TaskStatus::Running | TaskStatus::Ready => 'R',
            TaskStatus::Interruptable => 'S',
            TaskStatus::UnInterruptable => 'D',
            TaskStatus::Zombie => 'Z',
        };

        let ppid = self.op_parent(|parent| {
            if let Some(parent) = parent {
                parent.upgrade().map_or(0, |p| p.tid())
            } else {
                0
            }
        });
        let pgrp = self.pgid(); // 进程组 id
        let session = self.tgid(); // 简化为 session = tgid
        let tty_nr = 0; // 没有终端设备支持
        let tpgid = 0; // 暂无前台进程组
        let flags = 0; // 先设为 0

        // 缺页统计等暂设为 0
        let minflt = 0;
        let cminflt = 0;
        let majflt = 0;
        let cmajflt = 0;

        // CPU 时间统计
        let time_stat = self.time_stat();
        let utime = time_stat.user_time().timespec_to_ticks();
        let stime = time_stat.sys_time().timespec_to_ticks();
        let cutime = time_stat.child_user_system_time().0.timespec_to_ticks();
        let cstime = time_stat.child_user_system_time().1.timespec_to_ticks();

        // 其他字段（fake）
        let priority = 99; // 优先级，暂设为 99
        let nice = 0; // nice 值，暂设为 0（-19-20)
        let num_threads = self.op_thread_group(|tg| tg.len());
        let itrealvalue = 0; // 自 Linux 2.6.17 起，此字段不再维护，并被硬编码为 0。
        let starttime = 0; // 系统启动后进程的启动时间，暂设为 0
        let vsize = 114514; // 虚拟内存（fake）
        let rss = 242; // 驻留集大小：进程在实际内存中拥有的页面数（fake）
        let rsslim = self.rlimit.read()[5].rlim_cur; // 进程 rss 的当前软限制（以字节为单位）
        let startcode = 0; // 程序文本可运行的地址
        let endcode = 0; // 程序文本可运行的地址
        let startstack = 0; // 用户栈的起始地址
        let kstkesp = 0; // 内核栈指针
        let kstkeip = 0; // 内核栈指令指针
        let signal = 0; // 信号掩码，暂设为 0（已过时）
        let blocked = 0; // 阻塞的信号掩码，暂设为 0（已过时）
        let sigignore = 0; // 忽略的信号掩码，暂设为 0（已过时）
        let sigcatch = 0; // 捕获的信号掩码，暂设为 0（已过时）
        let wchan = 0; // 等待的事件，暂设为 0
        let nswap = 0; // 交换次数，暂设为 0（不维护）
        let cnswap = 0; // 子进程交换次数，暂设为 0（不维护）
        let exit_signal = 17; // 退出信号
        let processor = 0; // 假定当前 CPU
        let rt_priority = 0; // 实时优先级，暂设为 0
        let policy = 0; // 调度策略，暂设为 0
        let delayacct_blkio_ticks = 0; // 延迟块 I/O ticks，暂设为 0
        let guest_time = 0; // guest 时间，暂设为 0
        let cguest_time = 0; // 子进程 guest 时间，暂设为 0
        let start_data = 0; // 数据段起始地址
        let end_data = 0; // 数据段结束地址
        let start_brk = 0; // 程序 break 地址
        let arg_start = 0; // 参数起始地址
        let arg_end = 0; // 参数结束地址
        let env_start = 0; // 环境变量起始地址
        let env_end = 0; // 环境变量结束地址
        let exit_code = self.exit_code();

        // 拼接所有字段
        format!(
            "{} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}\n",
            tid, comm, state_char, ppid, pgrp, session, tty_nr, tpgid, flags,
            minflt, cminflt, majflt, cmajflt,
            utime, stime, cutime, cstime,
            priority, nice, num_threads, itrealvalue, starttime,
            vsize, rss,
            rsslim, startcode, endcode, startstack, kstkesp, kstkeip,
            signal, blocked, sigignore, sigcatch, wchan,
            nswap, cnswap, exit_signal, processor, rt_priority,
            policy, delayacct_blkio_ticks, guest_time, cguest_time,
            start_data, end_data, start_brk,
            arg_start, arg_end, env_start, env_end,
            exit_code
        )
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
        if let Some(tidptr) = task.tac() {
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
    // // 回收地址空间
    // if Arc::strong_count(&task.memory_set()) == 1 {
    //     log::warn!("[kernel_exit] Task{} memory_set recycle", task.tid());
    //     task.op_memory_set_mut(|mem| {
    //         mem.recycle_data_pages();
    //     });
    // }
    // 清空文件描述符表
    if Arc::strong_count(&task.fd_table()) == 2 {
        log::warn!("[kernel_exit] Task{} fd_table recycle", task.tid());
        // 6.12 Debug
        task.fd_table().clear();
    } else {
        log::warn!(
            "[kernel_exit] Task{} fd_table strong count: {}",
            task.tid(),
            Arc::strong_count(&task.fd_table())
        );
    }
    // // 清空信号
    // task.op_sig_pending_mut(|pending| {
    //     pending.clear();
    // });

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
                        fields: SiField::Kill {
                            tid: current_task().tid() as i32,
                            uid: current_task().uid(),
                        },
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
        remove_group(&task);
    }
    log::error!("[kernel_exit] Task{} clear the resource", task.tid());
    log::error!(
        "[kernel_exit] Task{} strong count: {}",
        task.tid(),
        Arc::strong_count(&task)
    );
}

/// 比较两个任务的优先级
/// 如果a > b, 返回true, 反之返回false
pub fn compare_task_priority(a: &Arc<Task>, b: &Arc<Task>) -> bool {
    // 先比较优先级
    let a_priority = a.priority();
    let b_priority = b.priority();
    
    // Linux调度系统优先级规则：
    // 0: 特殊情况，无论什么情况都是最低优先级
    // 1-99: 实时优先级（RT priority），数值越大优先级越高
    // 100-139: 静态优先级（nice值），数值越小优先级越高
    // 实时优先级永远比静态优先级高
    
    // 特殊处理优先级为0的情况
    match (a_priority, b_priority) {
        // 如果a是0，无论b是什么，a都是最低优先级
        (0, _) => false,
        // 如果b是0，a不是0，则a优先级更高
        (_, 0) => true,
        // 如果都不是0，按正常规则比较
        _ => {
            // 判断a和b是否为实时优先级
            let a_is_rt = a_priority <= 99;
            let b_is_rt = b_priority <= 99;
            
            match (a_is_rt, b_is_rt) {
                // 如果a是实时优先级，b是静态优先级，则a优先级更高
                (true, false) => true,
                // 如果a是静态优先级，b是实时优先级，则a优先级更低
                (false, true) => false,
                // 如果都是实时优先级，数值越大优先级越高
                (true, true) => a_priority > b_priority,
                // 如果都是静态优先级，数值越小优先级越高
                (false, false) => a_priority < b_priority,
            }
        }
    }
}

// 在clone时没有设置`CLONE_THREAD`标志, 为新任务创建新的`Path`结构
// 需要深拷贝`Path`, 但共享底层的`Dentry`和`VfsMount`
fn clone_path(old_path: &Arc<Mutex<Arc<Path>>>) -> Arc<Mutex<Arc<Path>>> {
    let old_path = old_path.lock();
    let new_path = Path::from_existed_user(&old_path);
    Arc::new(Mutex::new(new_path))
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
        log::debug!("[ThreadGroup:new]");
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
        const CPU0 = 0b0001;
        const CPU1 = 0b0010;
        const CPU2 = 0b0100;
        const CPU3 = 0b1000;
        const ALL = 0b1111;
    }
}

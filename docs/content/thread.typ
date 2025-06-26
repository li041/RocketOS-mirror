#import "../components/cover.typ": *
#import "../components/figure.typ": *

= 进程调度模块

== 内核同步有式模型

=== 异步无栈式设计存在的问题

  在分析往届优秀作品时，我们观察到大部分团队采用了异步无栈协程的调度架构。这种设计通过将async函数编译为状态机，实现了轻量级的任务调度机制。运行时系统仅需根据保存的状态信息推进执行，在代码编写层面具有显著优势。然而，从操作系统设计角度审视，这种架构引入了几个值得深入探讨的关键问题。
 
+ “虚拟栈帧”重建与性能问题

  异步架构从根本上改变了传统的函数执行模型。在传统栈式执行中，函数调用关系通过栈帧自然维护，而异步中的执行上下文则完全依赖堆分配的Future对象。当任务在await点挂起并返回Poll::Pending时，整个调用栈被销毁，所有执行状态必须序列化保存至堆内存中。任务恢复时，调度器通过重新poll相应对象来重建执行环境，这个过程本质上是在堆结构中重构"虚拟栈帧"链。由于async函数间的相互await调用会形成深层嵌套的状态结构，单次任务调度往往涉及十余层的poll函数链式调用。每层调用都需要进行状态检查、分支判断和上下文切换，这些看似微小的开销在高并发场景下会产生可观的性能影响。

+ 内存管理的复杂性

  异步任务缺乏真实栈空间支持，所有局部变量和中间状态都必须在堆上显式分配和管理。这种设计带来两个层面的挑战：首先是内存使用模式的改变，大量并发任务的状态结构同时存在于堆内存中，可能导致内存使用量快速增长；其次是生命周期管理的复杂化，这些堆分配结构的回收时机难以精确控制，在系统负载较高或开发者使用不当的情况下，容易出现悬挂Future对象或内存泄漏问题。

=== 为何选择同步有式设计

  同步栈式设计最重要的优势在于其自然而直观的内存管理模式。所有的局部变量、函数参数和中间状态都自动分配在栈上，这些内存资源的生命周期与函数调用的生命周期完全一致，当函数返回时所有相关内存会被自动回收。这种栈式内存管理完全避免了异步无栈式设计中大量堆分配状态结构带来的内存碎片化问题，也消除了复杂的手动内存生命周期管理需求。更为重要的是，栈内存的分配和释放是常数时间复杂度的简单指针操作，相比异步模式中需要进行的堆内存分配器调用，具有显著的性能优势。
  
  同步栈式架构具有高度可预测的性能特征。每次函数调用的开销是固定的，主要包括栈帧的建立、参数传递和返回值处理，这些操作的时间复杂度都是常数级别的。而异步无栈式设计中的每次状态推进都可能涉及复杂的状态检查、分支判断和多层嵌套的poll调用链，其性能开销随着异步调用的嵌套深度呈现出不可预测的增长趋势。在需要严格性能保证的系统中，有栈式设计的确定性执行时间是一个重要优势。

== 任务调度设计

=== 任务切换设计

  RocketOS的任务切换机制是系统核心组件中的杰出设计，与trap处理中tp寄存器管理构成了紧密集成的架构体系。在任务切换的状态保存阶段，`__switch`函数实现了一种高效的设计策略,即通过直接在当前任务的内核栈上内嵌TaskContext存储空间的方式来保存完整的寄存器状态。TaskContext中涵盖了关键的寄存器组合：返回地址寄存器ra、线程指针寄存器tp，以及s0至s11共计12个调用者保存寄存器，确保了任务切换过程中上下文信息的完整性和一致性。

  #algorithm-figure(
    ```rs
  Input: a0 ← next_task_kernel_stack
  Output: null

  # 保存taskContext到内核栈
  1:  sp ← sp - 16 × 8   
  2:  mem[sp + 0] ← ra         
      mem[sp + 8] ← tp         
  3:  for i ∈ {0..11} do  
        mem[sp + (2 + i) × 8] ← x[Callee[i]]  # Callee ={s0~s11}
  4:  mem[sp + 14 × 8] ← satp/pgdl # loongarch对应csr为pgdl
  5:  tp ← sp

  # 从内核栈恢复taskContext
  6:  ra ← mem[a0 + 0]  
      tp ← mem[a0 + 8]
  7:  for i ∈ {0..11} do  
        x[Callee[i]] ← mem[a0 + (2 + i) × 8]
  8:  satp/pgdl ← mem[a0 + 14 × 8]  
      sfence.vma/invtlb  # 清除TLB      
  9:  a0 ← a0 + 16 × 8  
      sp ← a0  
      return/jr
    ```,
    caption: [任务切换算法],
    label-name: "task-switch",
  )

  #h(2em)在RocketOS任务切换过程中，内核栈的定位机制是通过Task结构体（任务控制块TCB）的首字段kstack实现的。该kstack字段作为记录指针，标记着对应任务内核栈的栈顶位置。
  #h(2em)在RocketOS任务切换过程中，内核栈的定位机制是通过Task结构体（任务控制块TCB）的首字段kstack实现的。该kstack字段作为记录指针，标记着对应任务内核栈的栈顶位置。

  相较于传统的任务切换实现方案，RocketOS通过直接操作内核栈和Task结构中kstack字段的创新设计，实现了任务上下文保存与恢复的显著性能优化。传统方案往往需要在堆上分配复杂的状态结构与加锁来维护任务上下文，这不仅增加了内存分配的开销，还引入了额外的内存管理复杂性。而RocketOS的方案通过将TaskContext直接嵌入到内核栈中，利用栈的天然LIFO特性和局部性原理，不仅消除了动态内存分配的开销，还提高了缓存命中率，从而在任务切换这一高频操作上获得了显著的性能提升。

  #figure(
    image("img/任务切换示意图.png", width: 60%),
    caption: [任务切换示意图]
  ) <task_switch-figure>

  #h(2em) 根据如下lmbench中context-switch测例的测试结果，RocketOS在任务切换性能上表现出色，尤其是在高并发场景下，任务切换的延迟和开销都保持在较低水平。这一性能优势得益于RocketOS在任务切换设计中采用的高效内核栈管理和直接寄存器状态保存机制，使得任务切换操作能够在极短的时间内完成，满足了现代操作系统对高并发和低延迟的严格要求。

  #figure(
    image("img/context-switch成绩1.png", width: 70%),
    caption: [lmbench-context-switch测试结果],
  ) <lmbench-context-switch1>

  #figure(
    image("img/context-switch成绩2.png", width: 70%),
    caption: [lmbench-context-switch测试结果],
  ) <lmbench-context-switch2>

=== 任务调度策略

  RocketOS的任务调度系统采用了简洁而高效的FIFO（First In First Out）调度策略。Scheduler结构使用VecDeque作为就绪队列的底层数据结构，这种选择既保证了队列操作的高效性，又提供了双端队列的灵活性，使得任务的入队和出队操作都能在常数时间内完成。

  #code-figure(
    ```rs
    pub struct Scheduler {
      ready_queue: VecDeque<Arc<Task>>,
    }
    ```,
    caption: [调度队列设计],
    label-name: "scheduler-ready-queue",
  )

 #h(2em)在RocketOS中，任务切换机制通过yield和schedule两个核心函数实现了不同场景下的调度需求，两个函数在功能定位上存在本质区别，主要体现在对当前任务状态的不同处理方式上，这种差异化设计使得系统能够在保证调度效率的同时，准确响应各种任务状态变化。

  yield函数设计用于处理协作式任务切换场景，主要服务于那些主动放弃CPU使用权但仍需要继续执行的任务。当任务调用yield时，系统会将当前任务重新加入到就绪队列的末尾。

  相对而言，schedule函数承担着更为复杂的调度职责，主要处理任务生命周期管理和状态转换的关键时刻。当任务因为等待I/O操作完成、等待锁资源释放、或者因为其他阻塞条件而无法继续执行时，schedule函数会被调用来寻找下一个可执行的任务。在这种情况下，当前任务不会被重新加入到就绪队列中，而是根据具体的阻塞原因被转移到相应的等待队列或直接标记为阻塞状态。同时，当任务正常终止或异常退出时，schedule函数也承担了将任务移除调度队列的工作，从而确保系统资源得到正确释放。

=== 任务阻塞策略

  在RocketOS的阻塞机制设计中，任务阻塞是由一个全局性的阻塞管理器来实现的，其中的底层实现同样是基于VecDeque数据结构。这个设计允许系统在处理任务阻塞时，能够高效地管理和调度等待资源的任务。每当一个任务因为等待某个资源而无法继续执行时，它会被从就绪队列中移除，并加入到全局的阻塞队列中。

  #code-figure(
    ```rs
    pub struct WaitManager {
        pub wait_queue: Mutex<WaitQueue>,
    }
    pub struct WaitQueue {
        queue: VecDeque<Arc<Task>>,
    }
    ```,
    caption: [阻塞队列设计],
    label-name: "scheduler-wait-queue",
  )

  #h(2em)阻塞任务的唤醒机制同样构成了整个任务调度系统的重要组成部分，它确保了被阻塞的任务能够在适当的时机重新获得执行机会。这种唤醒机制根据触发条件的不同可以分为三种主要类型，每种类型都对应着不同的系统事件和应用场景。

  #enum(
  tight: false,
  [正常唤醒

  正常唤醒是最常见的唤醒方式，它发生在任务等待的资源或条件变为可用时。当任务因为等待某个特定资源而进入阻塞状态后，系统会持续监控该资源的状态变化。一旦资源变为可用，系统会立即触发唤醒操作，将对应的任务从阻塞队列中移除并重新加入就绪队列。典型的正常唤醒场景包括文件I/O操作的完成等。这种唤醒方式保证任务只有在真正需要执行时才会被唤醒，同时也减轻了任务调度器的压力，极大地提高了系统的运行效率。],

  [信号中断唤醒

  信号中断唤醒机制则提供了一种异步通信的手段，允许外部事件或其他任务通过发送信号来中断正在等待的任务。这种唤醒方式的特点是具有较高的优先级，能够打断任务的正常等待流程。当任务接收到信号时，无论其等待的原始条件是否满足，都会被强制唤醒并进入信号处理流程。信号唤醒的应用场景非常广泛，包括进程间通信中的自定义信号，定时器到期信号，以及系统异常信号等。这种机制为系统提供了强大的灵活性，使得任务能够响应各种异步事件，实现复杂的控制逻辑和错误处理机制。
  
  #algorithm-figure(
    ```rs
    Input: null  
    Output: If interrupted, returns -1, 
            If wakeup normally returns 0.

    1:  task.state ← INTERRUPTIBLE
    2:  WAIT_MANAGER.add(task)
    3:  schedule() # 执行任务切换
    4:  task.state ← READY
    5:  if task.is_interrupted == true then
          return -1   # 表示阻塞被信号打断
        end if
    6:  return 0  # 表示正常唤醒
    ```,
    caption: [常规阻塞算法],
    label-name: "task-wait",
  )
  ],

  [超时唤醒

  超时唤醒机制则是为了防止任务无限期等待而设计的保护机制。在实际的系统运行中，某些资源可能长时间不可用，或者某些条件可能永远不会满足，如果没有超时机制，任务将会永远阻塞下去，导致系统资源的浪费和潜在的死锁问题。超时唤醒通过设置一个预定的时间限制，当等待时间超过这个限制时，系统会触发超时回调函数，向对应任务发送定时器到期信号来自动唤醒任务，让任务有机会重新评估情况或采取替代措施。

  #algorithm-figure(
    ```rs
    Input: dur, clock_id
    Output: If interrupted by a signal, returns -1,
            If timeout, returns -2,
            If wakeup normally returns 0.

      1:  task.state ← INTERRUPTIBLE
      2:  deadline ← set_wait_alarm(dur, tid, clock_id)
      3:  WAIT_MANAGER.add(task)
      4:  schedule() # 执行任务切换
      5:  task.state ← READY
      6:  clear_wait_alarm(tid)
      7:  if task.interrupted == true then
            return -1  # 表示阻塞被信号打断
          end if
      8:  if current_time() ≥ deadline then
            return -2  # 表示阻塞超时
          end if
      9:  return 0  # 正常唤醒
    ```,
    caption: [超时阻塞算法],
    label-name: "task-waittimeout",
  )
  ])

  #h(2em)无论采用哪种唤醒方式，被唤醒的任务都会经历一个标准的状态转换过程。首先，任务会从阻塞队列中被移除，任务的状态会从阻塞状态转换为就绪状态，这标志着任务已经具备了再次执行的条件。接下来，任务会被重新加入到就绪队列中，等待调度器的下一次调度。当任务再度被执行时，通过检查函数调用的返回值，任务能够准确判断自己究竟是因为正常资源可用、信号中断还是超时而被唤醒的。这种判断机制的存在使得任务能够采取相应的后续行动：如果是正常唤醒，任务可以继续执行原本被阻塞的操作，比如读取已经就绪的文件数据或获取已经释放的锁资源；如果是信号唤醒，任务可能需要先处理信号相关的逻辑，然后决定是否重新尝试之前的操作；如果是超时唤醒，任务则需要评估是否应该放弃当前操作，或者调整策略后重新尝试。

  凭借RocketOS先进的阻塞机制与任务调度算法，系统能够高效管理大规模并发任务，并实现资源的优化分配与利用。cyclictest作为权威的Linux实时性能测试工具，通过创建高优先级线程并定期唤醒的方式来精确测量系统调度延迟，是评估操作系统实时响应性能和延迟抖动的标准基准。
  
  #figure(
    image("img/cyclictest成绩.png", width: 60%),
    caption: [cyclictest测试结果]
  ) <cyclictest-result>

  #h(2em) 如#[@fig:cyclictest-result]所示的RocketOS cyclictest测试结果表明，该系统在实时性能方面表现卓越，延迟控制精准稳定，响应时间抖动极小。这一优异表现充分彰显了同步栈式协程架构的核心优势——不仅具备卓越的实时响应能力和极低的系统延迟，更重要的是在高负载场景下仍能保持稳定的调度延迟分布。
  
  相比传统的异步回调机制，同步栈式协程架构避免了复杂的状态机管理和回调嵌套问题，使得任务调度路径更加直接高效。每个协程拥有独立的执行栈，在任务切换时只需保存和恢复栈指针等少量寄存器状态，大幅减少了上下文切换的开销。这种设计不仅简化了内核调度逻辑，更为高性能并发处理和实时系统应用提供了强有力的技术保障，确保系统在面对大规模并发任务时依然能够维持可预测的低延迟性能表现。


== 任务结构设计

=== 任务控制块设计

  进程作为操作系统中资源管理的基本抽象单元，拥有独立的虚拟地址空间、文件描述符表以及其他系统资源的所有权。线程则代表了处理器调度执行的最小单元，它们在共享宿主进程资源的基础上维护各自独立的执行状态和调用栈。
  
  在关于进程与线程的架构设计上，RocketOS采取了与Linux相类似的先进设计理念。Linux内核通过sys_clone系统调用的灵活标志位机制，实现了对不同类型任务创建的统一管理框架。通过传递不同的flags参数组合（如CLONE_VM、CLONE_FILES、CLONE_SIGHAND等），同一个系统调用既可以创建拥有完全独立虚拟地址空间和系统资源的传统进程，也可以生成与父任务共享特定资源（如内存空间、文件描述符或信号处理器）的轻量级线程。这种统一而灵活的设计充分体现了操作系统设计中"机制与策略分离"的核心思想，为上层应用提供了丰富的进程/线程创建选择。

  基于这一创建方式，RocketOS采用了统一的Task结构体设计模式，通过Rust语言的Arc（原子引用计数）与Mutex（互斥锁）的巧妙组合特性，优雅地解决了线程间的资源共享与同步访问问题。这种设计不仅保证了内存安全性，还通过零拷贝的资源共享机制显著提升了系统性能。Task结构的具体设计如下所示：

  #code-figure(
    ```rs
    pub struct Task {
      kstack: KernelStack, // 内核栈
      tid: RwLock<TidHandle>,                         // 线程id
      tgid: AtomicUsize,                              // 线程组id
      tid_address: Mutex<TidAddress>,                 // 线程id地址
      status: Mutex<TaskStatus>,                      // 任务状态
      time_stat: SyncUnsafeCell<TimeStat>,            // 任务时间统计
      parent: Arc<Mutex<Option<Weak<Task>>>>,         // 父任务
      children: Arc<Mutex<BTreeMap<Tid, Arc<Task>>>>, // 子任务
      thread_group: Arc<Mutex<ThreadGroup>>,          // 线程组
      exit_code: AtomicI32,                           // 退出码
      exe_path: Arc<RwLock<String>>,                  // 执行路径
      memory_set: RwLock<Arc<RwLock<MemorySet>>>,     // 地址空间
      robust_list_head: AtomicUsize,                  // 稳健性链表
      fd_table: Mutex<Arc<FdTable>>,                  // 文件描述符表
      root: Arc<Mutex<Arc<Path>>>,                    // 根路径
      pwd: Arc<Mutex<Arc<Path>>>,                     // 当前路径
      umask: AtomicU16,                               // 文件权限掩码
      sig_pending: Mutex<SigPending>,                 // 待处理信号
      sig_handler: Arc<Mutex<SigHandler>>,            // 信号处理函数
      sig_stack: Mutex<Option<SignalStack>>,          // 额外信号栈
      itimerval: Arc<RwLock<[ITimerVal; 3]>>,         // 定时器
      rlimit: Arc<RwLock<[RLimit; 16]>>,              // 资源限制
      cpu_mask: Mutex<CpuMask>,                       // CPU掩码
      pgid: AtomicUsize,                              // 进程组id
      uid: AtomicU32,                                 // 用户id
      euid: AtomicU32,                                // 有效用户id
      suid: AtomicU32,                                // 保存用户id
      fsuid: AtomicU32,                               // 文件系统用户id
      gid: AtomicU32,                                 // 组id
      egid: AtomicU32,                                // 有效组id
      sgid: AtomicU32,                                // 保存组id
      fsgid: AtomicU32,                               // 文件系统组id
      sup_groups: RwLock<Vec<u32>>,                   // 附加组列表
    }
    ```,
    caption: [任务控制块],
    label-name: "任务控制块",
  )

  #h(2em)在RocketOS的Task结构设计中，身份标识与层次关系通过三层标识体系得以实现，这一体系以tid、tgid和pgid为核心，确保了系统在支持现代多线程编程模型的同时，依然兼容传统的进程间关系。tid作为线程的唯一标识符，能够精确区分系统中每一个独立的线程执行单元；tgid则用于标识线程组，相当于传统意义上的进程概念，将属于同一进程的多个线程关联起来；而pgid则负责进程组的管理，用于协调一组相关进程的行为，例如信号传递或作业控制。此外，thread_group字段被设计用于管理同一进程内的所有线程，通过高效的线程组织方式，支持多线程任务的高效协同。
  
    #code-figure(
      ```rs
        pub struct ThreadGroup {
          member: BTreeMap<Tid, Weak<Task>>,
        }
      ```,
      caption: [线程组结构],
      label-name: "线程组结构"
    )

  #figure(
    image("img/线程组结构图.drawio.png", width: 70%),
    caption: [线程组结构图]
  ) <thread_group_structure>

  #h(2em)在进程间继承关系方面，Task结构通过parent和children字段维护了一棵完整的进程树，其中parent指向父进程，children则记录子进程集合。为了避免循环引用问题，RocketOS采用了Rust语言的Arc（原子引用计数）和Weak智能指针，通过引用计数的动态管理，确保进程树结构的稳定性和内存安全。

  内存管理作为Task结构的核心组成部分，体现了RocketOS在高效性和安全性上的深思熟虑。memory_set字段采用了双重RwLock（读写锁）的嵌套结构，外层RwLock负责控制地址空间的切换，例如在exec系统调用时对整个地址空间的重新配置；内层RwLock则专注于保护具体的内存映射操作，例如页面分配或释放。这种嵌套锁机制允许多个线程在同一地址空间内安全地并发操作，同时支持写时复制（Copy-on-Write）等高级内存管理特性，从而在性能与内存效率之间取得平衡。此外，每个线程通过kstack字段维护独立的内核栈，这一设计确保了线程在内核态执行时的隔离性和安全性，避免了因共享内核栈可能导致的竞争条件或数据损坏问题。

  在用户权限管理方面，RocketOS沿用了Linux的完整权限模型，通过实际用户ID（uid）、有效用户ID（euid）、保存用户ID（suid）以及文件系统用户ID（fsuid）等字段，结合对应的组权限字段（gid、egid、sgid、fsgid），实现了细粒度的权限控制。这种设计支持了复杂的权限提升和降级操作，例如在执行setuid程序时，能够根据上下文动态调整权限以确保安全性。sup_groups字段进一步扩展了权限管理功能，允许任务关联多个附加组，从而支持更灵活的权限分配策略，例如在需要跨多个用户组协作的场景下，提供精确的权限控制。

  在资源管理和任务调度方面，rlimit数组用于管理任务对系统资源的访问限制，例如文件描述符数量、堆栈大小或内存使用量，从而防止资源滥用并保证系统的稳定性。itimerval字段支持定时器功能，允许任务设置周期性或单次触发的定时器，用于实现精确的时间管理或事件触发。cpu_mask字段则提供了对任务CPU亲和性的控制，允许系统将任务绑定到特定的CPU核心上运行，以优化性能或降低调度开销。此外，time_stat字段记录了任务的运行时间统计信息，包括用户态和内核态的执行时间、上下文切换次数等。

=== 任务状态设计

  RocketOS的任务状态设计采用了经典的五状态模型，通过TaskStatus枚举类型精确定义了任务在其生命周期中可能处于的各种状态，系统中的每个任务都必然处于这五种状态中的一种:
  #pad(left: 3em)[
    - *就绪（Ready）*：任务已准备好运行，等待调度器分配CPU时间片。
    - *运行（Running）*：任务正在CPU上执行。
    - *可中断阻塞（Interruptable）*：任务因等待某些资源而阻塞，且可以被信号中断。
    - *不可中断阻塞（UnInterruptable）*：任务因某些资源而阻塞，但不可被信号中断。
    - *僵尸（Zombie）*：任务已终止，但其父进程尚未调用wait系统调用获取其退出状态，仍保留在系统中以供父进程查询。
  ]

  #figure(
    image("img/任务状态切换图.drawio.png", width: 50%),
    caption: [任务状态切换图]
  ) <task_status_transition>

  #h(2em)从Running状态出发存在多种转换路径。当任务主动调用yield让权或时间片耗尽时，会重新回到Ready状态等待下次调度。如果任务因为waitpid、文件I/O等操作需要等待资源时，会根据等待类型进入相应的阻塞状态：对于可以被信号中断的等待操作（如waitpid），任务进入Interruptable状态；对于关键的系统操作（如磁盘写入），任务进入UnInterruptable状态以确保操作的原子性。阻塞状态的唤醒机制体现了不同阻塞类型的特性差异。
  
  Interruptable状态的任务可以通过两种方式返回Ready状态：等待的资源变为可用，或者接收到信号中断。而UnInterruptable状态的任务只能等待特定的资源条件满足才能返回Ready状态，这种设计保证了系统关键操作不会被意外中断。

  当任务执行完毕或异常终止时，会从Running状态直接转换到Zombie状态。Zombie任务已经释放了大部分系统资源，只保留基本的进程控制信息等待父进程收集。当父进程调用wait系列系统调用获取子进程的退出状态后，Zombie任务才会被彻底清理，完成整个生命周期。这种设计确保了父子进程间退出状态信息的可靠传递，同时避免了过早资源回收可能导致的信息丢失。

  #figure(
    image("img/任务流程图.drawio.png", width: 90%),
    caption: [任务流程图]
  ) <task_flow_chart>

== 中断机制设计

  中断机制是操作系统中用于处理硬件或软件事件的响应机制，允许系统在特定事件发生时暂停当前任务，快速切换到中断处理程序以执行紧急或高优先级操作。中断通常分为硬件中断（如I/O设备信号、时钟中断）和软件中断（如系统调用、异常）。

  在RocketOS中，从用户态切换到内核态的场景主要包括三种：
  #pad(left: 3em)[
    - *系统调用*，即用户程序主动请求内核提供的服务；
    - *中断*，由硬件设备触发，需内核进行处理；
    - *异常*，当用户程序执行非法操作时发生。
  ]
    
=== 用户态 → 内核态切换
  每次从用户态陷入内核态，系统会跳转到由`__trap_from_user`标签定义的汇编代码段。这段代码负责保存用户态的运行上下文，并为内核态的执行环境做好准备。随后，trap_handler函数会根据具体的陷阱类型（如系统调用、中断或异常）进行针对性处理，确保系统能够高效、正确地响应不同的事件。

  #algorithm-figure(
    ```rs
    Input: user_context
    Output: processed_context

    1:    sp ← sscratch/CSR_SAVE0  ← sp  # 保存原用户态栈指针
    2:    sp ← sp - 36 × 8
    3:    for i ∈ SaveSet do  
              mem[sp + i × 8] ← x[i]  #SaveSet = {x0~x31(除sp)}
    4:    mem[sp + 32 × 8] ← sstatus/CSR_PRMD  
          mem[sp + 33 × 8] ← sepc/CSR_ERA  
          mem[sp + 2  × 8] ← sscratch/CSR_SAVE0
    5:    mem[sp + 34 × 8] ← a0 # 保存用户a0参数到last_a0
    6:    tp ← mem[sp + 35 × 8] # 加载内核tp
    7:    stvec/CSR_EENTRY ← &__trap_from_user
    8:    call/bl trap_handler(a0)
    9:    jump __return_to_user
    ```,
    caption: [trap_from_user算法],
    label-name: "trap-from-user",
  )

=== TrapContext设计
  在RocketOS的内核态用户态切换中，TrapContext是一个关键的数据结构，用于保存从用户态切换到内核态，以及从内核态切换回用户态时需要恢复的上下文信息。这个结构体的设计保证了用户态和内核态之间的切换能够正确地进行，不会丢失任何重要的状态信息。
  
  在trap机制的核心设计中，我们将trap_context结构始终固定保存在内核栈的顶端位置，这种设计选择带来了显著的架构优势。通过这种固定位置的布局，当系统通过CSR寄存器完成用户栈与内核栈之间的快速切换后，我们能够以确定的偏移量直接访问所有保存的上下文信息。
  
  #figure(
    image("img/内核栈.drawio.png", width: 60%),
    caption: [trap_context结构示意图]
  ) <kernal_stack>

  #h(2em) 如#[@fig:kernal_stack] 所示，trap_context的结构设计，特别是tp寄存器的处理策略，主要是针对前述任务切换机制进行的专门优化。RocketOS在TrapContext结构体中引入了kernel_tp字段这一创新设计，虽然会产生轻微的存储开销，但实现了任务切换流程对传统堆内存分配和锁竞争机制的彻底规避。这一权衡设计的核心优势在于将任务上下文的访问模式从堆访问重构为栈访问，有效消除了动态内存分配、互斥锁获取与释放等高延迟操作，其性能收益远超额外存储开销所带来的成本，实现了整体系统效率的显著提升。

=== 内核态 → 用户态切换

  当内核完成相应的trap处理后，系统需要从内核态安全地返回到用户态，这个过程由`__restore_to_user`标签定义的汇编代码段精确控制。这段代码承担着恢复用户态执行环境的关键职责，它会从之前保存的TrapContext中逐一恢复用户态的寄存器状态，包括通用寄存器、程序计数器以及CSR寄存器。

  #algorithm-figure(
    ```rs
    Input: processed_context
    Output: null

    1: stvec/CSR_EENTRY ← &__trap_from_user  
    2:  t0 ← mem[sp + 32 × 8]     
        t1 ← mem[sp + 33 × 8]      
        t2 ← mem[sp + 2  × 8]     
        sstatus/CSR_PRMD   ← t0  
        sepc/CSR_ERA       ← t1  
        sscratch/CSR_SAVE0 ← t2
    3:  for n ∈ SaveSet do  
          x[n] ← mem[sp + n × 8]  #SaveSet = {x0~x31(除tp)}
    4:  mem[sp + 35 × 8] ← tp # 保存内核tp
    5:  tp ← mem[sp + 4 × 8]
    6:  sp ← sscratch/CSR_SAVE0  ← sp
    7:  sret
    ```,
    caption: [return_to_user算法],
    label-name: "return_to_user",
  )

=== Riscv与LoongArch的中断兼容性设计 <arch_trap>

  为了实现跨架构兼容性，系统针对RISC-V和LoongArch架构分别实现了专门的trap_from_user和return_to_user汇编代码段。在RISC-V架构实现中，trap_from_user段使用csrr指令读取sstatus和sepc等CSR寄存器的值，并通过统一的寄存器编号约定（x0到x31）来保存通用寄存器状态。相对应的return_to_user段则使用csrw指令恢复这些CSR寄存器，最终通过sret指令完成从内核态到用户态的特权级别切换。

  LoongArch架构的实现则采用了该架构特有的指令集和寄存器约定。在LoongArch版本的trap_from_user中，系统使用csrrd指令读取PRMD（替代sstatus的功能）和ERA（替代sepc的功能）寄存器，通用寄存器的保存遵循r0到r31的编号约定。return_to_user的LoongArch实现使用csrwr指令恢复控制寄存器状态，并通过ertn指令执行特权级别的返回操作。

  同时，TrapContext结构的设计也进行了跨架构兼容性的考虑。通用寄存器数组x[32]统一了RISC-V和LoongArch两种架构的寄存器保存方式，尽管两种架构在寄存器编号约定上存在差异（RISC-V中x[4]为tp寄存器，x[10]为a0寄存器，而LoongArch中r[2]为tp寄存器，r[4]为a0寄存器），但通过统一的数组索引机制实现了代码的架构无关性。而针对架构的不同，分别使用了sepc和ERA寄存器（RISC-V）或PRMD寄存器（LoongArch）来保存程序计数器和处理器状态寄存器的值。

  这种架构特定的实现确保了在不同硬件平台上良好的兼容性，同时通过条件编译机制使得同一份内核源代码能够根据目标架构自动选择合适的汇编实现。两种架构实现的共同特点是都严格遵循了TrapContext结构的统一布局，使得上层的trap_handler函数能够以架构无关的方式处理各种trap事件，真正实现了"一次编写，多架构运行"的设计目标。 

#pagebreak()
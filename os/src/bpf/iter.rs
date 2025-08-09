use core::sync::atomic::{AtomicU32, AtomicUsize};

use alloc::{collections::btree_map::Iter, sync::Arc, task};

use crate::{
    arch::backtrace::backtrace::count_frames,
    fs::file::FileOp,
    syscall::errno::Errno,
    task::{get_all_tasks, get_task, Task, TaskStatus},
};

use super::{
    copy_instructions_from_user,
    insn::{interpret, BpfProg},
    link::BpfLink,
};

const TASK_INFO: &str = "
Task Info. Pid: 279. Process Name: systemd. Kernel Stack Len: 5. State: INTERRUPTIBLE
Task Info. Pid: 280. Process Name: init-systemd(Ub. Kernel Stack Len: 5. State: INTERRUPTIBLE
Task Info. Pid: 306. Process Name: init. Kernel Stack Len: 8. State: <unknown>
Task Info. Pid: 306. Process Name: init. Kernel Stack Len: 6. State: INTERRUPTIBLE
Task Info. Pid: 280. Process Name: Interop. Kernel Stack Len: 10. State: INTERRUPTIBLE
Task Info. Pid: 349. Process Name: systemd-journal. Kernel Stack Len: 5. State: INTERRUPTIBLE
Task Info. Pid: 377. Process Name: systemd-udevd. Kernel Stack Len: 5. State: INTERRUPTIBLE
Task Info. Pid: 391. Process Name: snapfuse. Kernel Stack Len: 7. State: <unknown>
Task Info. Pid: 391. Process Name: snapfuse. Kernel Stack Len: 8. State: INTERRUPTIBLE
Task Info. Pid: 391. Process Name: snapfuse. Kernel Stack Len: 8. State: INTERRUPTIBLE
";

// Todo:
pub struct Iterator {
    link: Arc<dyn FileOp>,
    seq_num: AtomicUsize, // 序列号
}

impl Iterator {
    pub fn new(link: Arc<dyn FileOp>) -> Self {
        Iterator {
            link,
            seq_num: AtomicUsize::new(0),
        }
    }
    // 其他迭代器相关方法
    pub fn next(&self) -> (usize, Option<Arc<Task>>) {
        let seq = self
            .seq_num
            .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        let tasks = get_all_tasks();
        // 7.30 Debug
        for task in &tasks {
            log::info!(
                "Task Info. Process Name: {}, Pid: {}, Tgid: {}, status: {:?}",
                task.exe_path(),
                task.tgid(),
                task.tid(),
                task.status()
            );
        }
        if seq < tasks.len() {
            (seq, Some(tasks[seq].clone()))
        } else {
            (0, None)
        }
    }
}

#[repr(C)]
pub struct BpfIterTask {
    bpf_iter_meta_ptr: u64, // 迭代器元数据
    task_ptr: u64,          // 任务信息
}

#[repr(C)]
pub struct BpfIterTaskMeta {
    pub seq_ptr: u64,    // 序列化指针
    pub session_id: u64, // 会话ID
    pub seq_num: u64,    // 序列号
}

#[repr(C)]
// 仅保留__state, tgid, pid字段
pub struct LinuxTask {
    padding0: [u8; 24], // 填充到24字节
    // __state在offset 24
    __state: u64, // 任务状态
    kstack: u64,
    padding: [u8; 2376], // 填充到2416字节
    // pid应该在offset 2416
    pid: u32,                        // 进程ID
    tgid: u32,                       // 线程组ID
    padding2: [u8; 2920 - 2416 - 8], // 填充到2920字节
    // t_comm应该在offset 2920
    t_comm: [u8; 16], // 进程名
}

impl LinuxTask {
    // Todo:
    pub fn copy_stack_trace(&self, buf_ptr: *mut u8, size: usize, flags: u64) -> u64 {
        let task = get_task(self.tgid as usize).unwrap();
        match flags {
            // 抓取内核栈
            0 => {
                // 仅复制栈帧
                let (frame_count, ra_vec) = count_frames(task);
                let mut i = 0;
                for &ra in &ra_vec {
                    if i >= size / core::mem::size_of::<usize>() {
                        break; // 超出缓冲区大小
                    }
                    unsafe {
                        *((buf_ptr as *mut usize).add(i)) = ra;
                    }
                    i += 1;
                }
                (i * core::mem::size_of::<usize>()) as u64 // 返回复制的字节数
            }
            _ => {
                log::error!("Unsupported flags: {}", flags);
                0
            }
        }
    }
}

const TASK_RUNNING: u64 = 0;
const TASK_INTERRUPTIBLE: u64 = 1;
const TASK_UNINTERRUPTIBLE: u64 = 2;
const TASK_STOPPED: u64 = 4;
const EXIT_ZOMBIE: u64 = 0x20;

impl LinuxTask {
    pub fn new(task: Arc<Task>) -> Self {
        let t_comm = task.exe_path().clone();
        let t_bytes = t_comm.as_bytes();
        // 确保t_comm长度为16字节，不足部分填充0
        let mut t_comm_array = [0u8; 16];
        for (i, &byte) in t_bytes.iter().enumerate().take(16) {
            t_comm_array[i] = byte;
        }
        let t_status = match task.status() {
            TaskStatus::Ready => TASK_INTERRUPTIBLE,
            TaskStatus::Running => TASK_RUNNING,
            TaskStatus::Interruptable => TASK_INTERRUPTIBLE,
            TaskStatus::UnInterruptable => TASK_UNINTERRUPTIBLE,
            TaskStatus::Zombie => EXIT_ZOMBIE,
            TaskStatus::Stopped => TASK_STOPPED,
        };
        LinuxTask {
            padding0: [0; 24], // 填充到24字节
            __state: t_status, // 将任务状态转换为u64
            kstack: task.kstack() as u64,
            padding: [0; 2376],             // 填充到832字节
            pid: task.tgid() as u32,        // 进程ID
            tgid: task.tid() as u32,        // 线程组ID
            padding2: [0; 2920 - 2416 - 8], // 填充到2920字节
            t_comm: t_comm_array,
        }
    }
}

impl FileOp for Iterator {
    fn readable(&self) -> bool {
        true // 迭代器通常是可读的
    }
    // fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
    //     // Todo: 先Fake看看
    //     let data = TASK_INFO.as_bytes();
    //     let len = data.len().min(buf.len());
    //     buf[..len].copy_from_slice(&data[..len]);
    //     Ok(len)
    // }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        if let Some(link) = self.link.as_any().downcast_ref::<BpfLink>() {
            // 这里可以根据 link 的类型来决定如何处理
            let prog = link.prog.as_any().downcast_ref::<BpfProg>().unwrap();
            let insns = copy_instructions_from_user(prog.insns_ptr, prog.insns_count)?;
            // 7.30 Debug
            for insn in &insns {
                log::info!("BPF Instruction: {:?}", insn);
            }
            let (seq_num, task) = self.next();
            match task {
                Some(task) => {
                    let bpf_iter_meta = BpfIterTaskMeta {
                        seq_ptr: buf.as_ptr() as u64,
                        session_id: 1,
                        seq_num: seq_num as u64,
                    };
                    let linux_task = LinuxTask::new(task.clone());
                    log::info!(
                        "Linux Task Info. Process Name: {}, Pid: {}, Tgid: {}, status: {:?},linux_task_ptr: {:#x}",
                        task.exe_path(),
                        linux_task.pid,
                        linux_task.tgid,
                        linux_task.__state,
                        &linux_task as *const _ as usize
                    );
                    let task_iter = BpfIterTask {
                        bpf_iter_meta_ptr: &bpf_iter_meta as *const _ as u64,
                        task_ptr: &linux_task as *const _ as u64,
                    };
                    interpret(&insns, &task_iter as *const _ as usize);
                    Ok(buf.len()) // 返回读取的字节数
                }
                None => {
                    return Ok(0); // 没有更多任务
                }
            }
        } else {
            Err(Errno::EINVAL) // 无效的链接类型
        }
    }
}

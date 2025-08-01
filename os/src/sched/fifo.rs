use core::cell::SyncUnsafeCell;

use alloc::{collections::{btree_map::BTreeMap, vec_deque::VecDeque}, sync::Arc, vec::Vec};
use lazy_static::lazy_static;
use crate::{arch::config::MAX_HARTS, task::{get_task, Task, Tid}};

lazy_static! {
    pub static ref RT_SCHEDULER: Vec<SyncUnsafeCell<FIFOScheduler>> = (0..MAX_HARTS)
        .map(|_| SyncUnsafeCell::new(FIFOScheduler::new()))
        .collect();
}

pub fn add_rt_task(task: Arc<Task>, hart_id: usize) {
    let rt_scheduler = unsafe { &mut *RT_SCHEDULER[hart_id].get() };
    rt_scheduler.add(task);
}

pub fn fetch_rt_task(hart_id: usize) -> Option<Arc<Task>> {
    let rt_scheduler = unsafe { &mut *RT_SCHEDULER[hart_id].get() };
    rt_scheduler.fetch()
}

pub fn remove_rt_task(tid: Tid, hart_id: usize) {
    let rt_scheduler = unsafe { &mut *RT_SCHEDULER[hart_id].get() };
    rt_scheduler.remove(tid);
}

// FIFO Task scheduler
pub struct FIFOScheduler {
    // RT队列：索引越大优先级越高，0用来存储空闲任务
    rt_queues: [VecDeque<Arc<Task>>; 100],
    // 普通队列：索引越小优先级越高
    normal_queues: [VecDeque<Arc<Task>>; 40],
    // 分离的bitmap
    rt_bitmap: u128,    // 99位
    normal_bitmap: u64, // 40位
    // 任务索引，快速定位任务在哪个队列
    task_index: BTreeMap<Tid, (QueueType, usize)>, // tid -> (队列类型, 队列索引)
}

#[derive(Debug, Clone, Copy)]
enum QueueType {
    Rt,
    Normal,
}

impl FIFOScheduler {
    /// 创建一个空调度器
    pub fn new() -> Self {
        const EMPTY_QUEUE: VecDeque<Arc<Task>> = VecDeque::new();
        Self {
            rt_queues: [EMPTY_QUEUE; 100],
            normal_queues: [EMPTY_QUEUE; 40],
            rt_bitmap: 0,     // 99位
            normal_bitmap: 0, // 40位
            task_index: BTreeMap::new(),
        }
    }

    /// 添加任务到调度器
    pub fn add(&mut self, task: Arc<Task>) {
        let priority = task.sched_prio();
        let tid = task.tid();
        //task.time_stat().record_wait_start();
        match priority {
            // 空闲任务
            0 => {
                self.rt_queues[0].push_back(task);
                self.task_index.insert(tid, (QueueType::Rt, 0));
            }
            // 实时任务
            1..=99 => {
                let index = priority as usize;
                self.rt_queues[index].push_back(task);
                self.rt_bitmap |= 1u128 << (index - 1);
                self.task_index.insert(tid, (QueueType::Rt, index));
            }
            // 普通任务
            100..=139 => {
                let index = (priority - 100) as usize;
                self.normal_queues[index].push_back(task);
                self.normal_bitmap |= 1u64 << index;
                self.task_index.insert(tid, (QueueType::Normal, index));
            }
            _ => panic!("Invalid task priority: {}", priority),
        }
    }

    /// 取出调度器中任务（不会取出空闲任务）
    pub fn fetch(&mut self) -> Option<Arc<Task>> {
        // 1. 实时任务（高优先级优先）
        if self.rt_bitmap != 0 {
            let highest_bit = 127 - self.rt_bitmap.leading_zeros() as usize;
            if highest_bit < 99 {
                let queue_index = highest_bit + 1;
                if let Some(task) = self.rt_queues[queue_index].pop_front() {
                    if self.rt_queues[queue_index].is_empty() {
                        self.rt_bitmap &= !(1u128 << highest_bit);
                    }
                    return Some(task);
                }
            }
        }

        // 2. 普通任务（低nice值优先）
        if self.normal_bitmap != 0 {
            let highest_normal_idx = self.normal_bitmap.trailing_zeros() as usize;
            if highest_normal_idx < 40 {
                if let Some(task) = self.normal_queues[highest_normal_idx].pop_front() {
                    if self.normal_queues[highest_normal_idx].is_empty() {
                        self.normal_bitmap &= !(1u64 << highest_normal_idx);
                    }
                    return Some(task);
                }
            }
        }
        None
    }

    pub fn fetch_lowest_priority(&mut self) -> Option<Arc<Task>> {
        // 1. 普通任务（高nice值优先，即低优先级）
        if self.normal_bitmap != 0 {
            let lowest_normal_idx = 63 - self.normal_bitmap.leading_zeros() as usize;
            if lowest_normal_idx < 40 {
                if let Some(task) = self.normal_queues[lowest_normal_idx].pop_front() {
                    if self.normal_queues[lowest_normal_idx].is_empty() {
                        self.normal_bitmap &= !(1u64 << lowest_normal_idx);
                    }
                    return Some(task);
                }
            }
        }

        // 2. 实时任务（低优先级优先）
        if self.rt_bitmap != 0 {
            let lowest_rt_bit = self.rt_bitmap.trailing_zeros() as usize;
            if lowest_rt_bit < 99 {
                let queue_index = lowest_rt_bit + 1;
                if let Some(task) = self.rt_queues[queue_index].pop_front() {
                    if self.rt_queues[queue_index].is_empty() {
                        self.rt_bitmap &= !(1u128 << lowest_rt_bit);
                    }
                    return Some(task);
                }
            }
        }

        None
    }

    /// 从调度器中取出空闲任务
    pub fn fetch_idle_task(&mut self) -> Option<Arc<Task>> {
        if !self.rt_queues[0].is_empty() {
            return self.rt_queues[0].pop_front();
        }
        None
    }

    /// 从调度器就绪队列中移除任务
    pub fn remove(&mut self, tid: Tid) {
        if let Some((queue_type, queue_index)) = self.task_index.remove(&tid) {
            let queue = match queue_type {
                QueueType::Rt => &mut self.rt_queues[queue_index],
                QueueType::Normal => &mut self.normal_queues[queue_index],
            };

            // 在队列中找到并移除任务
            if let Some(pos) = queue.iter().position(|task| task.tid() == tid) {
                queue.remove(pos);

                // 如果队列变空，更新bitmap
                if queue.is_empty() {
                    match queue_type {
                        QueueType::Rt if queue_index > 0 => {
                            self.rt_bitmap &= !(1u128 << (queue_index - 1));
                        }
                        QueueType::Normal => {
                            self.normal_bitmap &= !(1u64 << queue_index);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// 从调度器就绪队列中移除线程组
    pub fn remove_thread_group(&mut self, tgid: Tid) {
        if let Some(leader) = get_task(tgid) {
            leader.op_thread_group(|tg| {
                for task in tg.iter() {
                    let tid = task.tid();
                    self.remove(tid);
                }
            });
        }
    }

    pub fn dump(&self) {
        println!("RT Queues:");
        for (i, queue) in self.rt_queues.iter().enumerate() {
            if !queue.is_empty() {
                println!("Queue {}: {:?}", i, queue);
            }
        }
        println!("Normal Queues:");
        for (i, queue) in self.normal_queues.iter().enumerate() {
            if !queue.is_empty() {
                println!("Queue {}: {:?}", i, queue);
            }
        }
        println!("RT Bitmap: {}", self.rt_bitmap);
        println!("Normal Bitmap: {}", self.normal_bitmap);
    }
}

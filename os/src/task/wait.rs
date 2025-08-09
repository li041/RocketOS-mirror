use super::{Task, Tid};
use alloc::{collections::vec_deque::VecDeque, sync::Arc};

// 阻塞队列结构（FIFO）
// Todo: 后期优化
pub struct WaitQueue {
    queue: VecDeque<Arc<Task>>,
}

impl WaitQueue {
    // 创建一个新的阻塞队列
    pub fn new() -> Self {
        WaitQueue {
            queue: VecDeque::new(),
        }
    }

    // 向阻塞队列中添加一个任务
    pub fn add(&mut self, task: Arc<Task>) {
        self.queue.push_back(task);
    }

    // 从阻塞队列中移除特定任务
    pub fn remove(&mut self, tid: Tid) -> Result<Arc<Task>, ()> {
        if let Some(pos) = self.queue.iter().position(|e| e.tid() == tid) {
            log::debug!("[remove] task {} removed from queue", tid);
            Ok(self.queue.remove(pos).unwrap())
        } else {
            Err(())
        }
    }

    // 从阻塞队列中首部取出一个任务
    pub fn fetch(&mut self) -> Option<Arc<Task>> {
        let entry = self.queue.pop_front();
        if let Some(task) = entry {
            Some(task)
        } else {
            None
        }
    }
    // 打印队列中所有内容
    #[allow(unused)]
    pub fn dump_queue(&self) {
        println!("**************************** dump queue ****************************");
        for task in self.queue.iter() {
            println!(
                "task {} in queue\t strong count: {}",
                task.tid(),
                Arc::strong_count(task)
            );
        }
        println!("**************************** dump queue ****************************");
    }
}

use core::sync::atomic::AtomicUsize;

use crate::mutex::SpinNoIrqLock;

use super::{file::FileOp, Stdin, Stdout};
use alloc::{
    collections::{btree_map::BTreeMap, btree_set::BTreeSet},
    sync::Arc,
};

// 进程的文件描述符表
pub struct FdTable {
    table: SpinNoIrqLock<BTreeMap<usize, Arc<dyn FileOp>>>,
    free_fds: SpinNoIrqLock<BTreeSet<usize>>,
    next_fd: AtomicUsize,
}

impl FdTable {
    // 创建一个新的FdTable, 并初始化0(Stdin), 1(Stdout), 2(Stderr)三个文件描述符
    // Todo: stderr, 现在暂时使用stdout
    pub fn new() -> Arc<Self> {
        let mut fd_table: BTreeMap<usize, Arc<dyn FileOp>> = BTreeMap::new();
        fd_table.insert(0, Arc::new(Stdin));
        fd_table.insert(1, Arc::new(Stdout));
        // Todo: stderr, 现在暂时使用stdout
        fd_table.insert(2, Arc::new(Stdout));
        Arc::new(Self {
            table: SpinNoIrqLock::new(fd_table),
            free_fds: SpinNoIrqLock::new(BTreeSet::new()),
            next_fd: AtomicUsize::new(3), // 0, 1, 2 are reserved for stdin, stdout, stderr
        })
    }
    pub fn reset(&self) {
        let mut fd_table: BTreeMap<usize, Arc<dyn FileOp>> = BTreeMap::new();
        fd_table.insert(0, Arc::new(Stdin));
        fd_table.insert(1, Arc::new(Stdout));
        // Todo: stderr, 现在暂时使用stdout
        fd_table.insert(2, Arc::new(Stdout));
        *self.table.lock() = fd_table;
        self.free_fds.lock().clear();
        self.next_fd.store(3, core::sync::atomic::Ordering::SeqCst);
    }
    // 从已有的FdTable中创建一个新的FdTable, 复制已有的文件描述符
    pub fn from_existed_user(parent_table: &FdTable) -> Arc<Self> {
        let mut fd_table: BTreeMap<usize, Arc<dyn FileOp>> = BTreeMap::new();
        for (fd, file) in parent_table.table.lock().iter() {
            fd_table.insert(*fd, file.clone());
        }
        Arc::new(Self {
            table: SpinNoIrqLock::new(fd_table),
            free_fds: SpinNoIrqLock::new(BTreeSet::new()),
            next_fd: AtomicUsize::new(
                parent_table
                    .next_fd
                    .load(core::sync::atomic::Ordering::SeqCst),
            ),
        })
    }
    /// 分配文件描述符, 将文件插入FdTable中
    pub fn alloc_fd(&self, file: Arc<dyn FileOp + Send + Sync>) -> usize {
        let mut free_fds = self.free_fds.lock();
        // 优先使用free_fds中的最小的fd
        let fd = if let Some(&fd) = free_fds.iter().next() {
            free_fds.remove(&fd);
            fd
        } else {
            self.next_fd
                .fetch_add(1, core::sync::atomic::Ordering::SeqCst)
        };
        self.table.lock().insert(fd, file);
        fd
    }
    // 通过fd获取文件
    pub fn get_file(&self, fd: usize) -> Option<Arc<dyn FileOp>> {
        self.table.lock().get(&fd).cloned()
    }
    pub fn close(&self, fd: usize) -> bool {
        if self.table.lock().remove(&fd).is_some() {
            self.free_fds.lock().insert(fd);
            true
        } else {
            log::error!("[FdTable::close] fd not found: {}", fd);
            false
        }
    }
    // 清空FdTable
    pub fn clear(&self) {
        self.table.lock().clear();
        self.free_fds.lock().clear();
        self.next_fd.store(3, core::sync::atomic::Ordering::SeqCst);
    }
    // 给dup2使用, 将new_fd(并不是进程所能分配的最小描述符)指向old_fd的文件
    pub fn insert(&self, new_fd: usize, file: Arc<dyn FileOp>) -> Option<Arc<dyn FileOp>> {
        self.table.lock().insert(new_fd, file)
    }
}

use core::sync::atomic::AtomicUsize;

use crate::{mutex::SpinNoIrqLock, syscall::FcntlOp};

use alloc::vec;
use bitflags::bitflags;
use spin::RwLock;

use super::{
    file::{FileOp, OpenFlags},
    Stdin, Stdout,
};
use alloc::{
    collections::{btree_map::BTreeMap, btree_set::BTreeSet},
    sync::Arc,
};

bitflags! {
    /// 文件描述符的标志位
    /// 在execve成功后需要关闭文件描述符, 在execve失败后不需要关闭文件描述符
    #[derive(Clone, Copy)]
    pub struct FdFlags: usize {
        const FD_CLOEXEC = 1; // close on exec
    }
}
impl From<&OpenFlags> for FdFlags {
    fn from(flags: &OpenFlags) -> Self {
        let mut fd_flags = FdFlags::empty();
        if flags.contains(OpenFlags::O_CLOEXEC) {
            fd_flags |= FdFlags::FD_CLOEXEC;
        }
        fd_flags
    }
}

impl From<&FcntlOp> for FdFlags {
    fn from(flags: &FcntlOp) -> Self {
        let mut fd_flags = FdFlags::empty();
        if flags == &FcntlOp::F_DUPFD_CLOEXEC {
            fd_flags |= FdFlags::FD_CLOEXEC;
        }
        fd_flags
    }
}

// 进程的文件描述符表
pub struct FdTable {
    table: RwLock<BTreeMap<usize, FdEntry>>,
    free_fds: SpinNoIrqLock<BTreeSet<usize>>,
    next_fd: AtomicUsize,
}

#[derive(Clone)]
pub struct FdEntry {
    file: Arc<dyn FileOp>,
    fd_flags: FdFlags,
}

impl FdEntry {
    pub fn new(file: Arc<dyn FileOp>, flags: FdFlags) -> Self {
        Self {
            file,
            fd_flags: flags,
        }
    }
    #[inline(always)]
    pub fn get_file(&self) -> Arc<dyn FileOp> {
        self.file.clone()
    }
    #[inline(always)]
    pub fn get_flags(&self) -> FdFlags {
        self.fd_flags
    }
}

impl FdTable {
    pub fn new() -> Arc<Self> {
        let mut fd_table: BTreeMap<usize, FdEntry> = BTreeMap::new();
        fd_table.insert(
            0,
            FdEntry {
                file: Arc::new(Stdin),
                fd_flags: FdFlags::empty(),
            },
        );
        fd_table.insert(
            1,
            FdEntry {
                file: Arc::new(Stdout),
                fd_flags: FdFlags::empty(),
            },
        );
        fd_table.insert(
            2,
            FdEntry {
                file: Arc::new(Stdout),
                fd_flags: FdFlags::empty(),
            },
        );
        Arc::new(Self {
            table: RwLock::new(fd_table),
            free_fds: SpinNoIrqLock::new(BTreeSet::new()),
            next_fd: AtomicUsize::new(3),
        })
    }

    pub fn reset(&self) {
        let mut fd_table: BTreeMap<usize, FdEntry> = BTreeMap::new();
        fd_table.insert(
            0,
            FdEntry {
                file: Arc::new(Stdin),
                fd_flags: FdFlags::empty(),
            },
        );
        fd_table.insert(
            1,
            FdEntry {
                file: Arc::new(Stdout),
                fd_flags: FdFlags::empty(),
            },
        );
        fd_table.insert(
            2,
            FdEntry {
                file: Arc::new(Stdout),
                fd_flags: FdFlags::empty(),
            },
        );
        *self.table.write() = fd_table;
        self.free_fds.lock().clear();
        self.next_fd.store(3, core::sync::atomic::Ordering::SeqCst);
    }

    pub fn from_existed_user(parent_table: &FdTable) -> Arc<Self> {
        let mut fd_table: BTreeMap<usize, FdEntry> = BTreeMap::new();
        for (&fd, entry) in parent_table.table.read().iter() {
            fd_table.insert(fd, entry.clone());
        }
        Arc::new(Self {
            table: RwLock::new(fd_table),
            free_fds: SpinNoIrqLock::new(BTreeSet::new()),
            next_fd: AtomicUsize::new(
                parent_table
                    .next_fd
                    .load(core::sync::atomic::Ordering::SeqCst),
            ),
        })
    }

    pub fn alloc_fd(&self, file: Arc<dyn FileOp + Send + Sync>, fd_flags: FdFlags) -> usize {
        let mut free_fds = self.free_fds.lock();
        let fd = if let Some(&fd) = free_fds.iter().next() {
            free_fds.remove(&fd);
            fd
        } else {
            self.next_fd
                .fetch_add(1, core::sync::atomic::Ordering::SeqCst)
        };
        self.table.write().insert(fd, FdEntry { file, fd_flags });
        fd
    }

    /// 找到一个大于等于lower_bound的最小可用fd
    pub fn alloc_fd_above_lower_bound(
        &self,
        file: Arc<dyn FileOp + Send + Sync>,
        fd_flags: FdFlags,
        lower_bound: usize,
    ) -> usize {
        let mut free_fds = self.free_fds.lock();
        let fd = if let Some(&fd) = free_fds.range(lower_bound..).next() {
            free_fds.remove(&fd);
            fd
        } else {
            self.next_fd
                .fetch_add(1, core::sync::atomic::Ordering::SeqCst)
        };
        self.table.write().insert(fd, FdEntry { file, fd_flags });
        fd
    }

    /// 给dup2使用, 将new_fd(并不是进程所能分配的最小描述符)指向old_fd的文件
    pub fn insert(
        &self,
        new_fd: usize,
        file: Arc<dyn FileOp>,
        flags: FdFlags,
    ) -> Option<Arc<dyn FileOp>> {
        self.table
            .write()
            .insert(
                new_fd,
                FdEntry {
                    file,
                    fd_flags: flags,
                },
            )
            .map(|entry| entry.file)
    }

    pub fn get_fdentry(&self, fd: usize) -> Option<FdEntry> {
        self.table.read().get(&fd).cloned()
    }

    pub fn get_file(&self, fd: usize) -> Option<Arc<dyn FileOp>> {
        self.table.read().get(&fd).map(|entry| entry.file.clone())
    }

    pub fn close(&self, fd: usize) -> bool {
        if self.table.write().remove(&fd).is_some() {
            self.free_fds.lock().insert(fd);
            true
        } else {
            log::error!("[FdTable::close] fd not found: {}", fd);
            false
        }
    }

    pub fn clear(&self) {
        self.table.write().clear();
        self.free_fds.lock().clear();
        self.next_fd.store(3, core::sync::atomic::Ordering::SeqCst);
    }

    // 设置某个fd的flag（例如 FD_CLOEXEC）
    pub fn set_flag(&self, fd: usize, flags: FdFlags) -> bool {
        if let Some(entry) = self.table.write().get_mut(&fd) {
            entry.fd_flags |= flags;
            true
        } else {
            false
        }
    }

    // 获取某个fd的flags
    pub fn get_flags(&self, fd: usize) -> Option<FdFlags> {
        self.table.read().get(&fd).map(|entry| entry.fd_flags)
    }

    // 清除某个fd的特定位
    pub fn clear_flag(&self, fd: usize, flag: FdFlags) -> bool {
        if let Some(entry) = self.table.write().get_mut(&fd) {
            entry.fd_flags &= !flag;
            true
        } else {
            false
        }
    }

    // execve 成功后，关闭所有 FD_CLOEXEC 的文件描述符
    pub fn do_close_on_exec(&self) {
        let mut to_close = vec![];
        {
            let table = self.table.read();
            for (&fd, entry) in table.iter() {
                if entry.fd_flags.contains(FdFlags::FD_CLOEXEC) {
                    to_close.push(fd);
                }
            }
        }
        let mut table = self.table.write();
        for fd in to_close {
            table.remove(&fd);
            self.free_fds.lock().insert(fd);
        }
    }
}

// impl FdTable {
//     // 创建一个新的FdTable, 并初始化0(Stdin), 1(Stdout), 2(Stderr)三个文件描述符
//     // Todo: stderr, 现在暂时使用stdout
//     pub fn new() -> Arc<Self> {
//         let mut fd_table: BTreeMap<usize, FdEntry> = BTreeMap::new();
//         fd_table.insert(0, Arc::new(Stdin));
//         fd_table.insert(1, Arc::new(Stdout));
//         // Todo: stderr, 现在暂时使用stdout
//         fd_table.insert(2, Arc::new(Stdout));
//         Arc::new(Self {
//             table: SpinNoIrqLock::new(fd_table),
//             free_fds: SpinNoIrqLock::new(BTreeSet::new()),
//             next_fd: AtomicUsize::new(3), // 0, 1, 2 are reserved for stdin, stdout, stderr
//         })
//     }
//     pub fn reset(&self) {
//         let mut fd_table: BTreeMap<usize, Arc<dyn FileOp>> = BTreeMap::new();
//         fd_table.insert(0, Arc::new(Stdin));
//         fd_table.insert(1, Arc::new(Stdout));
//         // Todo: stderr, 现在暂时使用stdout
//         fd_table.insert(2, Arc::new(Stdout));
//         *self.table.lock() = fd_table;
//         self.free_fds.lock().clear();
//         self.next_fd.store(3, core::sync::atomic::Ordering::SeqCst);
//     }
//     // 从已有的FdTable中创建一个新的FdTable, 复制已有的文件描述符
//     pub fn from_existed_user(parent_table: &FdTable) -> Arc<Self> {
//         let mut fd_table: BTreeMap<usize, Arc<dyn FileOp>> = BTreeMap::new();
//         for (fd, file) in parent_table.table.lock().iter() {
//             fd_table.insert(*fd, file.clone());
//         }
//         Arc::new(Self {
//             table: SpinNoIrqLock::new(fd_table),
//             free_fds: SpinNoIrqLock::new(BTreeSet::new()),
//             next_fd: AtomicUsize::new(
//                 parent_table
//                     .next_fd
//                     .load(core::sync::atomic::Ordering::SeqCst),
//             ),
//         })
//     }
//     /// 分配文件描述符, 将文件插入FdTable中
//     pub fn alloc_fd(&self, file: Arc<dyn FileOp + Send + Sync>) -> usize {
//         let mut free_fds = self.free_fds.lock();
//         // 优先使用free_fds中的最小的fd
//         let fd = if let Some(&fd) = free_fds.iter().next() {
//             free_fds.remove(&fd);
//             fd
//         } else {
//             self.next_fd
//                 .fetch_add(1, core::sync::atomic::Ordering::SeqCst)
//         };
//         self.table.lock().insert(fd, file);
//         fd
//     }
//     // 通过fd获取文件
//     pub fn get_file(&self, fd: usize) -> Option<Arc<dyn FileOp>> {
//         self.table.lock().get(&fd).cloned()
//     }
//     pub fn close(&self, fd: usize) -> bool {
//         if self.table.lock().remove(&fd).is_some() {
//             self.free_fds.lock().insert(fd);
//             true
//         } else {
//             log::error!("[FdTable::close] fd not found: {}", fd);
//             false
//         }
//     }
//     // 清空FdTable
//     pub fn clear(&self) {
//         self.table.lock().clear();
//         self.free_fds.lock().clear();
//         self.next_fd.store(3, core::sync::atomic::Ordering::SeqCst);
//     }
//     // 给dup2使用, 将new_fd(并不是进程所能分配的最小描述符)指向old_fd的文件
//     pub fn insert(&self, new_fd: usize, file: Arc<dyn FileOp>) -> Option<Arc<dyn FileOp>> {
//         self.table.lock().insert(new_fd, file)
//     }
// }

use core::sync::atomic::AtomicUsize;

use crate::{mutex::SpinNoIrqLock, syscall::FcntlOp, task::current_task};

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

impl From<FdFlags> for i32 {
    fn from(flags: FdFlags) -> Self {
        flags.bits() as i32
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

/// 进程的文件描述符表
/// 注意free_fds中的fd不一定是最小的fd
pub struct FdTable {
    pub table: RwLock<BTreeMap<usize, FdEntry>>,
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
    #[inline(always)]
    pub fn set_flags(&mut self, flags: FdFlags) {
        self.fd_flags = flags;
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

    pub fn from_existed_user(parent_table: &FdTable) -> Arc<Self> {
        let mut fd_table: BTreeMap<usize, FdEntry> = BTreeMap::new();
        for (&fd, entry) in parent_table.table.read().iter() {
            fd_table.insert(fd, entry.clone());
        }
        Arc::new(Self {
            table: RwLock::new(fd_table),
            free_fds: SpinNoIrqLock::new(
                parent_table
                    .free_fds
                    .lock()
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<usize>>(),
            ),
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
            assert!(!self.is_in(fd));
            free_fds.remove(&fd);
            fd
        } else {
            self.next_fd
                .fetch_add(1, core::sync::atomic::Ordering::SeqCst)
        };
        self.table.write().insert(fd, FdEntry { file, fd_flags });
        log::error!(
            "[FdTable::alloc_fd] fd: {}, tid: {}",
            fd,
            current_task().tid()
        );
        drop(free_fds);
        self.list();
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
        // 从空闲链表中删除fd
        let mut free_fds = self.free_fds.lock();
        if free_fds.contains(&new_fd) {
            free_fds.remove(&new_fd);
        }
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
        let ret = if self.table.write().remove(&fd).is_some() {
            log::error!("[FdTable::close] fd: {}, tid: {}", fd, current_task().tid());
            // 将fd放回空闲链表中
            self.free_fds.lock().insert(fd);
            log::error!("free_fds: {:?}", self.free_fds.lock().iter());
            true
        } else {
            log::error!("[FdTable::close] fd not found: {}", fd);
            false
        };
        // 4.12
        log::error!(
            "[FdTable::close] close fd: {}, tid: {}",
            fd,
            current_task().tid()
        );
        self.list();
        ret
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

// Debug
impl FdTable {
    pub fn list(&self) {
        let table = self.table.read();
        for (fd, _entry) in table.iter() {
            log::error!("[FdTable] fd: {}", fd);
        }
        log::error!("[FdTable] free_fds: {:?}", self.free_fds.lock().iter());
        log::error!(
            "[FdTable] next_fd: {}",
            self.next_fd.load(core::sync::atomic::Ordering::SeqCst)
        );
    }
    pub fn is_in(&self, fd: usize) -> bool {
        self.table.read().contains_key(&fd)
    }
}

use crate::{syscall::FcntlOp, task::current_task};

use alloc::vec;
use alloc::vec::Vec;
use bitflags::bitflags;
use spin::RwLock;

use super::{
    dev::tty::TTY,
    file::{FileOp, OpenFlags},
    Stdin, Stdout,
};
use alloc::sync::Arc;

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

/// Max file descriptors counts
pub const MAX_FDS: usize = 128;
pub const RLIM_INFINITY: usize = usize::MAX;

/// Resource Limit
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RLimit {
    /// Soft limit: the kernel enforces for the corresponding resource
    pub rlim_cur: usize,
    /// Hard limit (ceiling for rlim_cur)
    pub rlim_max: usize,
}

impl RLimit {
    pub fn new(rlim_cur: usize) -> Self {
        Self {
            rlim_cur,
            rlim_max: RLIM_INFINITY,
        }
    }
}

/// 进程的文件描述符表
pub struct FdTable {
    table: RwLock<Vec<Option<FdEntry>>>,
    rlimit: RLimit,
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
        let mut vec = vec![None; MAX_FDS];
        // vec[0] = Some(FdEntry::new(Arc::new(Stdin), FdFlags::empty()));
        // vec[1] = Some(FdEntry::new(Arc::new(Stdout), FdFlags::empty()));
        // vec[2] = Some(FdEntry::new(Arc::new(Stdout), FdFlags::empty()));
        let tty_file = TTY.get().unwrap();
        vec[0] = Some(FdEntry::new(tty_file.clone(), FdFlags::empty()));
        vec[1] = Some(FdEntry::new(tty_file.clone(), FdFlags::empty()));
        vec[2] = Some(FdEntry::new(tty_file.clone(), FdFlags::empty()));
        Arc::new(Self {
            table: RwLock::new(vec),
            rlimit: RLimit::new(MAX_FDS),
        })
    }

    pub fn from_existed_user(parent_table: &FdTable) -> Arc<Self> {
        let mut vec = Vec::with_capacity(MAX_FDS);
        for i in 0..MAX_FDS {
            if let Some(entry) = parent_table.table.read().get(i) {
                vec.push(entry.clone());
            } else {
                vec.push(None);
            }
        }
        Arc::new(Self {
            table: RwLock::new(vec),
            rlimit: parent_table.rlimit,
        })
    }
    pub fn alloc_fd(&self, file: Arc<dyn FileOp>, fd_flags: FdFlags) -> usize {
        let mut table = self.table.write();
        let table_len = table.len();
        for fd in 0..table_len {
            if table[fd].is_none() {
                table[fd] = Some(FdEntry::new(file, fd_flags));
                return fd;
            }
        }
        if table_len < self.rlimit.rlim_cur {
            table.push(Some(FdEntry::new(file, fd_flags)));
            return table_len;
        }
        // 超过限制
        log::error!("[FdTable::alloc_fd] fd table full");
        panic!("fd table full");
    }

    /// 找到一个大于等于lower_bound的最小可用fd
    pub fn alloc_fd_above_lower_bound(
        &self,
        file: Arc<dyn FileOp + Send + Sync>,
        fd_flags: FdFlags,
        lower_bound: usize,
    ) -> usize {
        let mut table = self.table.write();
        let table_len = table.len();
        for fd in lower_bound..table_len {
            if table[fd].is_none() {
                table[fd] = Some(FdEntry::new(file, fd_flags));
                return fd;
            }
        }
        if table_len < self.rlimit.rlim_cur {
            table.push(Some(FdEntry::new(file, fd_flags)));
            return table_len;
        }
        // 超过限制
        log::error!("[FdTable::alloc_fd] fd table full");
        panic!("fd table full");
    }

    /// 给dup2使用, 将new_fd(并不是进程所能分配的最小描述符)指向old_fd的文件
    pub fn insert(
        &self,
        new_fd: usize,
        file: Arc<dyn FileOp>,
        flags: FdFlags,
    ) -> Option<Arc<dyn FileOp>> {
        if new_fd >= self.rlimit.rlim_cur {
            panic!("[FdTable::insert] fd out of range: {}", new_fd);
            // return None;
        }
        let mut table = self.table.write();
        let old = table[new_fd].replace(FdEntry::new(file, flags));
        old.map(|entry| entry.file)
    }

    pub fn get_fdentry(&self, fd: usize) -> Option<FdEntry> {
        self.table
            .read()
            .get(fd)
            .and_then(|entry| entry.as_ref().cloned())
    }

    pub fn get_file(&self, fd: usize) -> Option<Arc<dyn FileOp>> {
        self.table
            .read()
            .get(fd)?
            .as_ref()
            .map(|entry| entry.file.clone())
    }

    /// 返回bool值表示是否成功关闭
    pub fn close(&self, fd: usize) -> bool {
        let mut table = self.table.write();
        if fd < table.len() && table[fd].is_some() {
            table[fd] = None;
            return true;
        } else {
            false
        }
    }

    pub fn clear(&self) {
        self.table.write().clear();
    }

    // 设置某个fd的flag（例如 FD_CLOEXEC）
    pub fn set_flag(&self, fd: usize, flags: FdFlags) -> bool {
        if let Some(Some(entry)) = self.table.write().get_mut(fd) {
            entry.fd_flags |= flags;
            true
        } else {
            false
        }
    }

    // 获取某个fd的flags
    pub fn get_flags(&self, fd: usize) -> Option<FdFlags> {
        self.table
            .read()
            .get(fd)?
            .as_ref()
            .map(|entry| entry.fd_flags)
    }

    // 清除某个fd的特定位
    pub fn clear_flag(&self, fd: usize, flag: FdFlags) -> bool {
        if let Some(Some(entry)) = self.table.write().get_mut(fd) {
            entry.fd_flags &= !flag;
            true
        } else {
            false
        }
    }

    // execve 成功后，关闭所有 FD_CLOEXEC 的文件描述符
    pub fn do_close_on_exec(&self) {
        let mut table = self.table.write();
        for entry in table.iter_mut() {
            if let Some(fd_entry) = entry {
                if fd_entry.fd_flags.contains(FdFlags::FD_CLOEXEC) {
                    *entry = None;
                }
            }
        }
    }
}

// Debug
impl FdTable {
    pub fn list(&self) {
        let table = self.table.read();
        for (fd, entry) in table.iter().enumerate() {
            if let Some(_) = entry {
                log::error!("[FdTable] fd: {}", fd);
            }
        }
    }
}

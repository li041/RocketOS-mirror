use crate::syscall::{
    errno::{Errno, SyscallRet},
    FcntlOp,
};

use alloc::vec;
use alloc::vec::Vec;
use bitflags::bitflags;
use spin::RwLock;
use virtio_drivers::PAGE_SIZE;

use super::{
    dev::tty::TTY,
    file::{FileOp, OpenFlags},
    pipe::Pipe,
    uapi::{CloseRangeFlags, RLimit},
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
/// 需要大于1024
pub const MAX_FDS: usize = 1025;

/// 进程的文件描述符表
pub struct FdTable {
    pub table: RwLock<Vec<Option<FdEntry>>>,
    rlimit: RwLock<RLimit>,
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
    pub fn new_bare() -> Arc<Self> {
        Arc::new(Self {
            table: RwLock::new(Vec::new()),
            rlimit: RwLock::new(RLimit::new(MAX_FDS)),
        })
    }
    pub fn new() -> Arc<Self> {
        let mut vec = vec![None; 3];
        // vec[0] = Some(FdEntry::new(Arc::new(Stdin), FdFlags::empty()));
        // vec[1] = Some(FdEntry::new(Arc::new(Stdout), FdFlags::empty()));
        // vec[2] = Some(FdEntry::new(Arc::new(Stdout), FdFlags::empty()));
        let tty_file = TTY.get().unwrap();
        vec[0] = Some(FdEntry::new(tty_file.clone(), FdFlags::empty()));
        vec[1] = Some(FdEntry::new(tty_file.clone(), FdFlags::empty()));
        vec[2] = Some(FdEntry::new(tty_file.clone(), FdFlags::empty()));
        Arc::new(Self {
            table: RwLock::new(vec),
            rlimit: RwLock::new(RLimit::new(MAX_FDS)),
        })
    }

    pub fn from_existed_user(parent_table: &FdTable) -> Arc<Self> {
        let mut vec = Vec::with_capacity(parent_table.table.read().len());
        for i in 0..MAX_FDS {
            if let Some(entry) = parent_table.table.read().get(i) {
                vec.push(entry.clone());
            } else {
                vec.push(None);
            }
        }
        Arc::new(Self {
            table: RwLock::new(vec),
            rlimit: RwLock::new(parent_table.rlimit.read().clone()),
        })
    }
    pub fn alloc_fd(&self, file: Arc<dyn FileOp>, fd_flags: FdFlags) -> SyscallRet {
        let mut table = self.table.write();
        let table_len = table.len();
        for fd in 0..table_len {
            if table[fd].is_none() {
                table[fd] = Some(FdEntry::new(file, fd_flags));
                log::info!("[FdTable::alloc_fd] alloc fd: {}", fd);
                return Ok(fd);
            }
        }
        if table_len < self.rlimit.read().rlim_cur {
            table.push(Some(FdEntry::new(file, fd_flags)));
            return Ok(table_len);
        }
        // 超过限制
        log::error!("[FdTable::alloc_fd] fd table full");
        // panic!("fd table full");
        return Err(Errno::EMFILE);
    }

    /// 找到一个大于等于lower_bound的最小可用fd
    pub fn alloc_fd_above_lower_bound(
        &self,
        file: Arc<dyn FileOp + Send + Sync>,
        fd_flags: FdFlags,
        lower_bound: usize,
    ) -> SyscallRet {
        let mut table = self.table.write();
        let table_len = table.len();
        for fd in lower_bound..table_len {
            if table[fd].is_none() {
                table[fd] = Some(FdEntry::new(file, fd_flags));
                return Ok(fd);
            }
        }
        if table_len < self.rlimit.read().rlim_cur {
            table.push(Some(FdEntry::new(file, fd_flags)));
            return Ok(table_len);
        }
        // 超过限制
        log::error!("[FdTable::alloc_fd] fd table full");
        return Err(Errno::EMFILE);
    }

    /// 给dup2使用, 将new_fd(并不是进程所能分配的最小描述符)指向old_fd的文件
    /// bool表示是否发生替换
    pub fn insert(
        &self,
        new_fd: usize,
        file: Arc<dyn FileOp>,
        flags: FdFlags,
    ) -> Result<bool, Errno> {
        if new_fd >= self.rlimit.read().rlim_cur {
            log::error!("[FdTable::insert] fd out of range: {}", new_fd);
            return Err(Errno::EBADF);
        }
        let mut table = self.table.write();
        if new_fd >= table.len() {
            table.resize(new_fd + 1, None);
        }
        let old = table[new_fd].replace(FdEntry::new(file, flags));
        if let Some(_entry) = old {
            return Ok(true);
        } else {
            return Ok(false);
        }
    }

    pub fn get_file(&self, fd: usize) -> Option<Arc<dyn FileOp>> {
        log::trace!("[FdTable::get_file]");
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
    pub fn close_range(&self, first: usize, last: usize, flags: CloseRangeFlags) -> SyscallRet {
        if flags.contains(CloseRangeFlags::CLOSE_RANGE_UNSHARE) {
            // Todo:
        }
        return Err(Errno::ENOSYS); // 目前不支持 CLOSE_RANGE_UNSHARE
    }

    pub fn clear(&self) {
        self.table.write().clear();
    }

    pub fn get_rlimit(&self) -> RLimit {
        self.rlimit.read().clone()
    }
    pub fn set_rlimit(&self, rlimit: &RLimit) {
        let mut rlimit_lock = self.rlimit.write();
        rlimit_lock.rlim_cur = rlimit.rlim_cur;
        rlimit_lock.rlim_max = rlimit.rlim_max;
        if self.table.read().len() > rlimit.rlim_cur as usize {
            self.table.write().truncate(rlimit.rlim_cur as usize);
        }
    }

    // 设置某个fd的flag（例如 FD_CLOEXEC）
    pub fn set_flags(&self, fd: usize, flags: FdFlags) -> bool {
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

// 系统调用实现
impl FdTable {
    pub fn dup(&self, fd: usize) -> SyscallRet {
        let file = self
            .table
            .read()
            .get(fd)
            .and_then(|entry| entry.as_ref())
            .ok_or(Errno::EBADF)?
            .get_file();
        self.alloc_fd(file, FdFlags::empty())
    }
    pub fn dup3(&self, fd: usize, new_fd: usize, fd_flags: FdFlags) -> SyscallRet {
        let file = self
            .table
            .read()
            .get(fd)
            .and_then(|entry| entry.as_ref())
            .ok_or(Errno::EBADF)?
            .get_file();
        self.insert(new_fd, file, fd_flags).map(|replaced| {
            if replaced {
                log::warn!("[dup3] fd {} already exists, replaced", new_fd);
            }
            new_fd
        })
    }
    pub fn fcntl(&self, fd: usize, op: i32, arg: usize) -> SyscallRet {
        // let table = self.table.read();
        // let fd_entry = table.get(fd).and_then(|entry| entry.as_ref());
        let op = FcntlOp::try_from(op).map_err(|_| {
            log::error!("[fcntl] Invalid fcntl operation: {}", op);
            Errno::EINVAL
        })?;
        let fd_flags = FdFlags::from(&op);

        // if let Some(entry) = fd_entry {
        match op {
            FcntlOp::F_DUPFD | FcntlOp::F_DUPFD_CLOEXEC => {
                let file = self.get_file(fd).ok_or(Errno::EBADF)?;
                return self.alloc_fd_above_lower_bound(file, fd_flags, arg);
            }
            FcntlOp::F_GETFD => {
                let flags = self
                    .table
                    .read()
                    .get(fd)
                    .and_then(|entry| entry.as_ref())
                    .ok_or(Errno::EBADF)?
                    .get_flags();
                return Ok(i32::from(flags) as usize);
            }
            FcntlOp::F_SETFD => {
                self.table
                    .write()
                    .get_mut(fd)
                    .and_then(|entry| entry.as_mut())
                    .ok_or(Errno::EBADF)?
                    .set_flags(FdFlags::from_bits(arg).unwrap());
                return Ok(0);
            }
            FcntlOp::F_GETFL => {
                let flags = self.get_file(fd).ok_or(Errno::EBADF)?.get_flags();
                log::info!("[fcntl] get OpenFlags: {:?}", flags);
                return Ok(flags.bits() as usize);
            }
            FcntlOp::F_SETFL => {
                let file = self.get_file(fd).ok_or(Errno::EBADF)?;
                let mut flags = OpenFlags::from_bits_truncate(arg as i32);
                flags.remove(OpenFlags::O_ACCMODE);
                flags.remove(OpenFlags::CREATION_FLAGS);
                log::info!("[fcntl] set OpenFlags: {:?}", flags);
                file.set_flags(flags);
                return Ok(0);
            }
            FcntlOp::F_GETPIPE_SZ => {
                let file = self.get_file(fd).ok_or(Errno::EBADF)?;
                if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
                    return Ok(pipe.get_size());
                } else {
                    log::warn!("[fcntl] F_GETPIPE_SZ on non-pipe file");
                    return Err(Errno::EINVAL);
                }
            }
            FcntlOp::F_SETPIPE_SZE => {
                let file = self.get_file(fd).ok_or(Errno::EBADF)?;
                if let Some(pipe) = file.as_any().downcast_ref::<Pipe>() {
                    let pipe_size = if arg < PAGE_SIZE {
                        // 试图将容量设置为低于页面大小的值，会被自动上调到页面大小；
                        PAGE_SIZE
                    } else {
                        // 如果大于等于页面大小，则直接使用arg
                        // Todo: 权限检查
                        arg
                    };
                    pipe.resize(pipe_size);
                    return Ok(pipe_size);
                } else {
                    log::warn!("[fcntl] F_SETPIPE_SZ on non-pipe file");
                    return Err(Errno::EINVAL);
                }
            }
            _ => {
                log::warn!("[fcntl] Unsupported op: {:?}", op);
                return Err(Errno::EINVAL);
            }
        }
        // }
    }
}

impl FdTable {
    pub fn get_fds(&self) -> Vec<usize> {
        let table = self.table.read();
        let mut fds = Vec::new();
        for (fd, entry) in table.iter().enumerate() {
            if let Some(_) = entry {
                fds.push(fd);
            }
        }
        fds
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

use alloc::vec;
use core::any::Any;
use spin::Mutex;

use alloc::{sync::Arc, vec::Vec};
use log::info;
use virtio_drivers::PAGE_SIZE;

use crate::{
    arch::{config::PAGE_SIZE_BITS, mm::copy_to_user},
    fs::dentry::LinuxDirent64,
    mm::Page,
    syscall::errno::{Errno, SyscallRet},
};

use super::{
    inode::InodeOp,
    path::Path,
    uapi::{FallocFlags, Whence},
};

// 普通文件
pub struct File {
    inner: Mutex<FileInner>,
}

pub struct FileInner {
    // pub inode: ,
    /// 单位是字节
    offset: usize,
    // pub dentry: Arc<Dentry>,
    pub path: Arc<Path>,
    pub inode: Arc<dyn InodeOp>,
    pub flags: OpenFlags,
}

/// File trait
pub trait FileOp: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any {
        unimplemented!();
    }
    // 从文件中读取数据到buf中, 返回读取的字节数, 同时更新文件偏移量
    fn read<'a>(&'a self, _buf: &'a mut [u8]) -> SyscallRet {
        unimplemented!();
    }
    // 从文件偏移量为offset处读取数据到buf中, 返回读取的字节数, 不会更新文件偏移量
    fn pread<'a>(&'a self, _buf: &'a mut [u8], _offset: usize) -> SyscallRet {
        unimplemented!();
    }
    // 从文件偏移量为offset处写数据到buf中, 返回写的字节数, 不会更新文件偏移量
    fn pwrite<'a>(&'a self, _buf: &'a [u8], _offset: usize) -> SyscallRet {
        unimplemented!();
    }

    fn read_all(&self) -> Vec<u8> {
        unimplemented!();
    }
    fn get_page<'a>(&'a self, _page_offset: usize) -> Option<Arc<Page>> {
        unimplemented!();
    }
    fn get_pages<'a>(&'a self, _page_offset: usize, _page_count: usize) -> Vec<Arc<Page>> {
        unimplemented!();
    }
    fn get_inode(&self) -> Arc<dyn InodeOp> {
        unimplemented!();
    }
    fn get_path(&self) -> Arc<Path> {
        unimplemented!();
    }
    /// Write `UserBuffer` to file
    fn write<'a>(&'a self, _buf: &'a [u8]) -> SyscallRet {
        unimplemented!();
    }
    fn write_dio<'a>(&'a self, _buf: &'a [u8]) -> SyscallRet {
        unimplemented!();
    }
    // move the file offset
    fn seek(&self, _offset: isize, _whence: Whence) -> SyscallRet {
        unimplemented!();
    }
    // truncate the file to a given length
    fn truncate(&self, _length: usize) -> SyscallRet {
        unimplemented!();
    }
    fn fallocate(&self, _mode: FallocFlags, _offset: usize, _length: usize) -> SyscallRet {
        unimplemented!();
    }
    fn fsync(&self) -> SyscallRet {
        unimplemented!();
    }
    // Get the file offset
    fn get_offset(&self) -> usize {
        unimplemented!();
    }
    // readable
    fn readable(&self) -> bool {
        unimplemented!();
    }
    // writable
    fn writable(&self) -> bool {
        unimplemented!();
    }
    fn add_wait_queue(&self, tid: usize) {
        unimplemented!();
    }
    fn hang_up(&self) -> bool {
        unimplemented!();
    }
    fn r_ready(&self) -> bool {
        unimplemented!();
    }
    fn w_ready(&self) -> bool {
        unimplemented!();
    }
    fn ioctl(&self, _op: usize, _arg_ptr: usize) -> SyscallRet {
        Err(Errno::ENOTTY)
    }
    // 获取文件的OpenFlags(在openat初始化)
    fn get_flags(&self) -> OpenFlags {
        unimplemented!()
    }
    fn set_flags(&self, _flags: OpenFlags) {
        unimplemented!()
    }
}

impl File {
    pub fn inner_handler<T>(&self, f: impl FnOnce(&mut FileInner) -> T) -> T {
        f(&mut self.inner.lock())
    }
    pub fn add_offset(&self, offset: usize) {
        self.inner_handler(|inner| inner.offset += offset);
    }
    pub fn get_offset(&self) -> usize {
        self.inner_handler(|inner| inner.offset)
    }
}

impl File {
    pub fn new(path: Arc<Path>, inode: Arc<dyn InodeOp>, flags: OpenFlags) -> Self {
        let offset = if flags.contains(OpenFlags::O_APPEND) {
            inode.get_size()
        } else {
            0
        };
        Self {
            inner: Mutex::new(FileInner {
                offset,
                path,
                inode,
                flags,
            }),
        }
    }
    /// Read all data inside a inode into vector
    pub fn read_all(&self) -> Vec<u8> {
        info!("[File::read_all]");
        let inode = self.inner_handler(|inner| inner.inode.clone());
        let size = inode.get_size();
        let mut buffer = vec![0u8; size];
        let offset = self.get_offset();
        let total_read = inode.read(offset, &mut buffer);
        self.add_offset(total_read);
        log::info!("read_all: total_read: {}", total_read);
        buffer
    }
    pub fn is_dir(&self) -> bool {
        self.inner_handler(|inner| inner.inode.can_lookup())
    }

    /// dirp是用户空间的指针
    pub fn readdir(&self, dirp: usize, count: usize) -> SyscallRet {
        if self.is_dir() {
            // let mut buf = vec![0u8; count];
            // let buf = copy_from_user_mut(dirp as *mut u8, count)?;
            let mut ker_buf = vec![0u8; count];
            let (file_offset, buf_offset) =
                self.inner_handler(|inner| inner.inode.getdents(&mut ker_buf, inner.offset))?;
            self.add_offset(file_offset);
            log::error!(
                "readdir: file_offset: {}, buf_offset: {}",
                file_offset,
                buf_offset
            );
            // 检查count太小 视为无效
            if count < core::mem::size_of::<LinuxDirent64>() {
                return Err(Errno::EINVAL);
            }
            let n = copy_to_user(dirp as *mut u8, ker_buf[..buf_offset].as_ptr(), buf_offset)?;
            return Ok(n);
        }
        return Err(Errno::ENOTDIR);
    }
}

impl FileOp for File {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> SyscallRet {
        if self.inner.lock().path.dentry.is_dir() {
            return Err(Errno::EISDIR);
        }
        let read_size = self.inner_handler(|inner| inner.inode.read(inner.offset, buf));
        self.add_offset(read_size);
        Ok(read_size)
    }
    fn pread<'a>(&'a self, buf: &'a mut [u8], offset: usize) -> SyscallRet {
        log::info!("File::pread: offset: {}, buf_len: {}", offset, buf.len());
        let read_size = self.inner_handler(|inner| inner.inode.read(offset, buf));
        Ok(read_size)
    }
    // 依照linux的行为, 而非POSIX标准, 如果文件是O_APPEND打开的, 则pwrite时会向文件末尾写, 同时不更新offset
    fn pwrite<'a>(&'a self, buf: &'a [u8], offset: usize) -> SyscallRet {
        let write_size = self.inner_handler(|inner| {
            if inner.flags.contains(OpenFlags::O_APPEND) {
                let size = inner.inode.get_size();
                inner.inode.write(size, buf)
            } else {
                // 如果不是O_APPEND, 则使用指定的offset写入
                inner.inode.write(offset, buf)
            }
        });
        Ok(write_size)
    }
    fn read_all(&self) -> Vec<u8> {
        self.read_all()
    }
    /// 共享文件映射和私有文件映射只读时调用
    fn get_page<'a>(&'a self, page_aligned_offset: usize) -> Option<Arc<Page>> {
        debug_assert!(page_aligned_offset % PAGE_SIZE == 0);
        let inode = self.inner_handler(|inner| inner.inode.clone());
        inode.get_page(page_aligned_offset >> PAGE_SIZE_BITS)
    }
    fn get_pages<'a>(&'a self, page_aligned_offset: usize, page_count: usize) -> Vec<Arc<Page>> {
        debug_assert!(page_aligned_offset % PAGE_SIZE == 0);
        let inode = self.inner_handler(|inner| inner.inode.clone());
        inode.get_pages(page_aligned_offset >> PAGE_SIZE_BITS, page_count)
    }

    fn get_inode(&self) -> Arc<dyn InodeOp> {
        self.inner_handler(|inner| inner.inode.clone())
    }
    fn get_path(&self) -> Arc<Path> {
        self.inner_handler(|inner| inner.path.clone())
    }

    fn write<'a>(&'a self, buf: &'a [u8]) -> SyscallRet {
        let write_size = self.inner_handler(|inner| {
            if inner.flags.contains(OpenFlags::O_APPEND) {
                inner.offset = inner.inode.get_size();
            }
            inner.inode.write(inner.offset, buf)
        });
        self.add_offset(write_size);
        Ok(write_size)
    }
    fn write_dio<'a>(&'a self, buf: &'a [u8]) -> SyscallRet {
        let write_size = self.inner_handler(|inner| {
            if inner.flags.contains(OpenFlags::O_APPEND) {
                inner.offset = inner.inode.get_size();
            }
            // 注意需要直接写入磁盘, 不使用页缓存, 否则会爆
            inner.inode.write_dio(inner.offset, buf)
        });
        self.add_offset(write_size);
        Ok(write_size)
    }
    fn seek(&self, offset: isize, whence: Whence) -> SyscallRet {
        self.inner_handler(|inner| {
            match whence {
                Whence::SeekSet => {
                    if offset < 0 {
                        return Err(Errno::EINVAL);
                    }
                    inner.offset = offset as usize;
                }
                Whence::SeekCur => {
                    inner.offset = inner
                        .offset
                        .checked_add_signed(offset)
                        .ok_or(Errno::EINVAL)?;
                }
                Whence::SeekEnd => {
                    let size = inner.inode.get_size();
                    inner.offset = size.checked_add_signed(offset).ok_or(Errno::EINVAL)?;
                }
                Whence::SeekData => {
                    // 一直get_page直到找到数据
                    let mut page_aligned_offset = offset as usize & !(PAGE_SIZE - 1);
                    log::info!(
                        "SeekData: initial offset: {}, inner.offset: {}",
                        page_aligned_offset,
                        inner.offset
                    );
                    let inode = inner.inode.clone();
                    let file_size = inode.get_size();
                    loop {
                        if page_aligned_offset >= file_size {
                            // whench是SeekData, 且offset在文件末尾的hole中, 返回ENXIO
                            log::error!(
                                "SeekData: offset {} is beyond file size {}",
                                page_aligned_offset,
                                file_size
                            );
                            return Err(Errno::ENXIO);
                        }
                        // if let Some(_page) = inode.get_page(page_aligned_offset >> PAGE_SIZE_BITS) {
                        if let Some(_) = inode.lookup_extent(page_aligned_offset >> PAGE_SIZE_BITS)
                        {
                            // 找到数据, 更新偏移量
                            if offset as usize & !(PAGE_SIZE - 1) == page_aligned_offset {
                                log::warn!("SeekData: data found at offset: {}", inner.offset);
                                inner.offset = offset as usize;
                            } else {
                                inner.offset = page_aligned_offset;
                            }
                            break;
                        }
                        // 没有数据, 继续查找下一个页
                        page_aligned_offset += PAGE_SIZE;
                    }
                    // 6.7 Debug
                    log::warn!("SeekData: found data at offset: {}", inner.offset);
                }
                Whence::SeekHole => {
                    // 一直get_page直到找到hole
                    let mut page_aligned_offset = offset as usize & !(PAGE_SIZE - 1);
                    let inode = inner.inode.clone();
                    let file_size = inode.get_size();
                    if page_aligned_offset >= file_size {
                        // whench是SeekHole, 且offset超过文件末尾, 返回ENXIO
                        log::error!(
                            "SeekHole: offset {} is beyond file size {}",
                            page_aligned_offset,
                            file_size
                        );
                        return Err(Errno::ENXIO);
                    }
                    loop {
                        if inode
                            .lookup_extent(page_aligned_offset >> PAGE_SIZE_BITS)
                            .is_none()
                        {
                            // 找到hole, 更新偏移量
                            inner.offset = page_aligned_offset;
                            break;
                        }
                        // 没有hole, 继续查找下一个页
                        page_aligned_offset += PAGE_SIZE;
                    }
                }
            }
            return Ok(inner.offset);
        })
    }
    fn truncate(&self, length: usize) -> SyscallRet {
        if self.get_flags().contains(OpenFlags::O_APPEND) {
            return Err(Errno::EPERM);
        }
        self.inner_handler(|inner| inner.inode.truncate(length))?;
        Ok(0)
    }
    fn fallocate(&self, _mode: FallocFlags, _offset: usize, _length: usize) -> SyscallRet {
        self.inner_handler(|inner| inner.inode.fallocate(_mode, _offset, _length))
    }
    fn fsync(&self) -> SyscallRet {
        self.inner_handler(|inner| inner.inode.fsync())
    }
    fn get_offset(&self) -> usize {
        self.inner_handler(|inner| inner.offset)
    }
    // O_RDONLY = 0, 以只读方式打开文件, 具体的权限检查由VFS层完成
    fn readable(&self) -> bool {
        let inner_guard = self.inner.lock();
        !inner_guard.flags.contains(OpenFlags::O_WRONLY)
            && !inner_guard.flags.contains(OpenFlags::O_PATH)
    }
    fn writable(&self) -> bool {
        let inner_guard = self.inner.lock();
        (inner_guard.flags.contains(OpenFlags::O_WRONLY)
            || inner_guard.flags.contains(OpenFlags::O_RDWR))
            && !inner_guard.flags.contains(OpenFlags::O_PATH)
    }
    fn r_ready(&self) -> bool {
        true
    }
    fn w_ready(&self) -> bool {
        true
    }
    fn get_flags(&self) -> OpenFlags {
        self.inner_handler(|inner| inner.flags)
    }
    // 保留本身的CREATION_FLAGS, AccessMode, 其余位使用flags设置
    // flags由上层调用者处理, 不设置access mode及creation flags
    fn set_flags(&self, flags: OpenFlags) {
        self.inner_handler(|inner| {
            inner.flags = inner.flags & (OpenFlags::CREATION_FLAGS | OpenFlags::O_ACCMODE) | flags;
        });
    }
}

// pub const O_RDONLY: usize = 0;
// pub const O_WRONLY: usize = 1;
// pub const O_RDWR: usize = 2;
// pub const O_CREAT: usize = 0x40;
// pub const O_DIRECTORY: usize = 0x10000;
// pub const O_NOFOLLOW: usize = 0x200000;

bitflags::bitflags! {
    // Defined in <bits/fcntl-linux.h>.
    // File access mode (O_RDONLY, O_WRONLY, O_RDWR).
    // The file creation flags are O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL,
    // O_NOCTTY, O_NOFOLLOW, O_TMPFILE, and O_TRUNC.
    // O_EXCL在sys_openat中被处理, 文件访问模式在`create_file_from_dentry`中被处理
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct OpenFlags: i32 {
        // reserve 3 bits for the access mode
        // NOTE: bitflags do not encourage zero bit flag, we should not directly check `O_RDONLY`
        // const O_RDONLY      = 0;
        const O_WRONLY      = 1;
        const O_RDWR        = 2;
        const O_ACCMODE     = 3;
        /// If pathname does not exist, create it as a regular file.
        const O_CREAT       = 0o100;
        const O_EXCL        = 0o200;
        const O_NOCTTY      = 0o400;
        // 若文件已存在且为普通文件，并以O_RDWR（读写）或O_WRONLY（只写）方式成功打开时：文件长度将被截断为0（清空内容）
        // 对FIFO特殊文件（命名管道）和终端设备文件无影响。对其他文件类型的影响由具体实现定义。
        const O_TRUNC       = 0o1000;
        const O_APPEND      = 0o2000;
        const O_NONBLOCK    = 0o4000;
        const O_DSYNC       = 0o10000;
        const O_SYNC        = 0o4010000;
        const O_RSYNC       = 0o4010000;
        const O_DIRECTORY   = 0o200000;
        const O_NOFOLLOW    = 0o400000;
        const O_CLOEXEC     = 0o2000000;

        const O_ASYNC       = 0o20000;
        const O_DIRECT      = 0o40000;
        const O_LARGEFILE   = 0o100000;
        // 不更新访问时间, 调用进程需要有`CAP_FOWNER`权限或euid匹配file的Owner id
        const O_NOATIME     = 0o1000000;
        // 打开一个文件但不获取对该文件的读写权限，而是仅获取对文件路径本身的一个引用
        const O_PATH        = 0o10000000;
        const O_TMPFILE     = 0o20200000;
    }
}

impl OpenFlags {
    pub const CREATION_FLAGS: OpenFlags = OpenFlags::O_CREAT
        .union(OpenFlags::O_EXCL)
        .union(OpenFlags::O_TMPFILE)
        .union(OpenFlags::O_NOCTTY)
        .union(OpenFlags::O_NOFOLLOW)
        .union(OpenFlags::O_DIRECTORY)
        .union(OpenFlags::O_CLOEXEC)
        .union(OpenFlags::O_TRUNC);
}

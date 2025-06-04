use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::ptr::copy_nonoverlapping;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize};
use spin::{Mutex, RwLock};

use crate::arch::mm::copy_to_user;
use crate::ext4::inode::{self, Ext4InodeDisk, S_IFIFO};
use crate::signal::{Sig, SigInfo};
use crate::syscall::errno::{Errno, SyscallRet};
use crate::task::{current_task, wait, wakeup, yield_current_task, Tid};
use crate::timer::TimeSpec;

use super::file::{FileOp, OpenFlags};
use super::inode::InodeOp;
use super::kstat::Kstat;

// lazy_static::lazy_static! {
//     static ref PIPEINODE: Arc<dyn InodeOp> =
//      {
//         let mut inode_on_disk = Ext4InodeDisk::default();
//         inode_on_disk.set_mode(S_IFIFO);
//         inode_on_disk.set_size(RING_DEFAULT_BUFFER_SIZE as u64);
//         Arc::new(PipeInode {
//             inode_num: 0,
//             inner: RwLock::new(PipeInodeInner {
//                 inode_on_disk
//             }),
//         })
//     };
// }

pub struct PipeInode {
    inode_num: usize,
    buffer: Arc<Mutex<PipeRingBuffer>>,
    pub inner: RwLock<PipeInodeInner>,
}

impl PipeInode {
    pub fn new(inode_num: usize) -> Arc<Self> {
        let mut inode_on_disk = Ext4InodeDisk::default();
        inode_on_disk.set_mode(S_IFIFO);
        Arc::new(Self {
            inode_num,
            buffer: Arc::new(Mutex::new(PipeRingBuffer::new())),
            inner: RwLock::new(PipeInodeInner { inode_on_disk }),
        })
    }
}

pub struct PipeInodeInner {
    pub inode_on_disk: Ext4InodeDisk,
}

impl InodeOp for PipeInode {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn can_lookup(&self) -> bool {
        false
    }
    fn getattr(&self) -> Kstat {
        let mut kstat = Kstat::new();
        let inner_guard = self.inner.read();
        let inode_on_disk = &inner_guard.inode_on_disk;
        kstat.ino = self.inode_num as u64;
        kstat.dev = 0;

        kstat.mode = inode_on_disk.get_mode();
        kstat.uid = inode_on_disk.get_uid() as u32;
        kstat.gid = inode_on_disk.get_gid() as u32;
        kstat.size = 0;
        kstat.atime = inode_on_disk.get_atime();
        kstat.mtime = inode_on_disk.get_mtime();
        kstat.ctime = inode_on_disk.get_ctime();
        kstat.nlink = 1;
        kstat.blocks = 0;
        kstat
    }
    fn get_resident_page_count(&self) -> usize {
        0
    }
    fn get_inode_num(&self) -> usize {
        self.inode_num
    }
    fn get_mode(&self) -> u16 {
        self.inner.read().inode_on_disk.get_mode()
    }
    /* 时间戳 */
    fn get_atime(&self) -> TimeSpec {
        self.inner.read().inode_on_disk.get_atime()
    }
    fn set_atime(&self, atime: TimeSpec) {
        self.inner.write().inode_on_disk.set_atime(atime);
    }
    fn get_mtime(&self) -> TimeSpec {
        self.inner.read().inode_on_disk.get_mtime()
    }
    fn set_mtime(&self, mtime: TimeSpec) {
        self.inner.write().inode_on_disk.set_mtime(mtime);
    }
    fn get_ctime(&self) -> TimeSpec {
        self.inner.read().inode_on_disk.get_ctime()
    }
    fn set_ctime(&self, ctime: TimeSpec) {
        self.inner.write().inode_on_disk.set_ctime(ctime);
    }
    fn set_mode(&self, mode: u16) {
        self.inner.write().inode_on_disk.set_mode(mode);
    }
}

/// 匿名管道不占用磁盘inode, 其元数据仅存在于内核内存中
pub struct Pipe {
    readable: bool,
    writable: bool,
    inode: Arc<PipeInode>,
    flags: AtomicI32,
    is_named_pipe: bool,
}

impl Pipe {
    pub fn read_end(
        inode: Arc<PipeInode>,
        flags: OpenFlags,
        is_named_pipe: bool,
    ) -> Result<Arc<Self>, Errno> {
        let read_end = Arc::new(Self {
            readable: true,
            writable: false,
            inode: inode.clone(),
            flags: AtomicI32::new(flags.bits()),
            is_named_pipe,
        });
        let mut buffer = inode.buffer.lock();
        buffer.set_read_end(&read_end);
        if is_named_pipe {
            if buffer.get_one_waiter() != 0 {
                // wake up writer
                let waiter = buffer.get_one_waiter();
                wakeup(waiter);
            } else {
                if flags.contains(OpenFlags::O_NONBLOCK) {
                    log::error!(
                        "[Pipe::read_end] named pipe write end not ready, non-blocking mode, block"
                    );
                    buffer.add_waiter(current_task().tid());
                    drop(buffer);
                    wait();
                }
            }
        }
        Ok(read_end)
    }
    pub fn write_end(
        inode: Arc<PipeInode>,
        flags: OpenFlags,
        is_named_pipe: bool,
    ) -> Result<Arc<Self>, Errno> {
        let write_end = Arc::new(Self {
            readable: false,
            writable: true,
            inode: inode.clone(),
            flags: AtomicI32::new(flags.bits()),
            is_named_pipe,
        });
        let mut buffer = inode.buffer.lock();
        buffer.set_write_end(&write_end);
        if is_named_pipe {
            if buffer.get_one_waiter() != 0 {
                // wake up reader
                log::info!("[Pipe::write_end] wake up reader");
                let waiter = buffer.get_one_waiter();
                wakeup(waiter);
            } else {
                if flags.contains(OpenFlags::O_NONBLOCK) {
                    log::error!(
                        "[Pipe::write_end] named pipe read end not ready, non-blocking mode, return ENXIO"
                    );
                    return Err(Errno::ENXIO);
                }
            }
        }
        Ok(write_end)
    }
    /// 创建匿名管道的读写端
    pub fn read_write_end(inode: Arc<PipeInode>, flags: OpenFlags) -> (Arc<Self>, Arc<Self>) {
        let read_end = Arc::new(Self {
            readable: true,
            writable: false,
            inode: inode.clone(),
            flags: AtomicI32::new(flags.bits()),
            is_named_pipe: false,
        });
        let write_end = Arc::new(Self {
            readable: false,
            writable: true,
            inode: inode.clone(),
            flags: AtomicI32::new(flags.bits()),
            is_named_pipe: false,
        });
        let mut buffer = inode.buffer.lock();
        buffer.set_read_end(&read_end);
        buffer.set_write_end(&write_end);
        (read_end, write_end)
    }
    pub fn get_size(&self) -> usize {
        self.inode.buffer.lock().size
    }
    /// 调整管道大小, 成功返回新大小, 失败返回Errno
    pub fn resize(&self, new_size: usize) -> Result<usize, Errno> {
        assert!(new_size > 0);
        let mut buffer = self.inode.buffer.lock();
        buffer.resize(new_size)
    }
}

pub const RING_DEFAULT_BUFFER_SIZE: usize = 65536;

#[derive(Copy, Clone, PartialEq, Debug)]
enum RingBufferStatus {
    FULL,
    EMPTY,
    NORMAL,
}

pub struct PipeRingBuffer {
    // arr: Box<[u8; RING_DEFAULT_BUFFER_SIZE]>,
    arr: Vec<u8>,
    head: usize,
    tail: usize,
    status: RingBufferStatus,
    write_end: Option<Weak<Pipe>>,
    read_end: Option<Weak<Pipe>>,
    pub(crate) waiter: Vec<Tid>,
    size: usize, // 用于记录管道的大小
}

impl PipeRingBuffer {
    fn new() -> Self {
        Self {
            arr: vec![0u8; RING_DEFAULT_BUFFER_SIZE],
            head: 0,
            tail: 0,
            status: RingBufferStatus::EMPTY,
            write_end: None,
            read_end: None,
            waiter: Vec::new(),
            size: RING_DEFAULT_BUFFER_SIZE,
        }
    }
    #[allow(unused)]
    fn get_used_size(&self) -> usize {
        if self.status == RingBufferStatus::FULL {
            self.arr.len()
        } else if self.status == RingBufferStatus::EMPTY {
            0
        } else {
            assert!(self.head != self.tail);
            if self.head < self.tail {
                self.tail - self.head
            } else {
                self.tail + self.arr.len() - self.head
            }
        }
    }
    #[inline]
    fn buffer_read(&mut self, buf: &mut [u8]) -> usize {
        // get range
        let begin = self.head;
        let end = if self.tail <= self.head {
            self.size
        } else {
            self.tail
        };
        // copy
        let read_bytes = buf.len().min(end - begin);
        unsafe {
            copy_nonoverlapping(self.arr.as_ptr().add(begin), buf.as_mut_ptr(), read_bytes);
        };
        // update head
        self.head = if begin + read_bytes == self.size {
            0
        } else {
            begin + read_bytes
        };
        read_bytes
    }
    #[inline]
    fn buffer_write(&mut self, buf: &[u8]) -> usize {
        // get range
        let begin = self.tail;
        let end = if self.tail < self.head {
            self.head
        } else {
            self.size
        };
        // write
        let write_bytes = buf.len().min(end - begin);
        unsafe {
            copy_nonoverlapping(buf.as_ptr(), self.arr.as_mut_ptr().add(begin), write_bytes);
        };
        // update tail
        self.tail = if begin + write_bytes == self.size {
            0
        } else {
            begin + write_bytes
        };
        write_bytes
    }
    fn set_write_end(&mut self, write_end: &Arc<Pipe>) {
        self.write_end = Some(Arc::downgrade(write_end));
    }
    fn set_read_end(&mut self, read_end: &Arc<Pipe>) {
        self.read_end = Some(Arc::downgrade(read_end));
    }
    fn all_write_ends_closed(&self) -> bool {
        log::trace!("[all_write_ends_closed]");
        self.write_end.as_ref().unwrap().upgrade().is_none()
    }
    fn all_read_ends_closed(&self) -> bool {
        log::trace!("[all_read_ends_closed]");
        self.read_end.as_ref().unwrap().upgrade().is_none()
    }
    fn get_one_waiter(&mut self) -> Tid {
        log::warn!("[PipeRingBuffer::get_one_waiter] get one waiter");
        self.waiter.pop().unwrap_or(0) // 如果没有等待者，返回0
    }
    fn add_waiter(&mut self, waiter: Tid) {
        // 6.7 Debug
        log::warn!("[PipeRingBuffer::add_waiter] add waiter: {}", waiter);
        log::warn!("[PipeRingBuffer::get_one_waiter] get one waiter");
        self.waiter.push(waiter);
    }
    // 成功返回新大小, 失败返回Errno
    fn resize(&mut self, new_size: usize) -> Result<usize, Errno> {
        log::warn!("[PipeRingBuffer::resize] resize to {}", new_size);
        let used = self.get_used_size();
        if used > new_size {
            log::error!(
                "[PipeRingBuffer::resize] new size is smaller than used size, resizing failed"
            );
            return Err(Errno::EBUSY); // 不允许缩小
        }
        let mut new_arr = vec![0u8; new_size];
        if self.status != RingBufferStatus::EMPTY {
            if self.head < self.tail {
                // 正常情况
                new_arr[..used].copy_from_slice(&self.arr[self.head..self.tail]);
            } else {
                // 环形情况
                let first_part = &self.arr[self.head..self.size];
                let second_part = &self.arr[..self.tail];
                let first_part_len = first_part.len();
                new_arr[..first_part_len].copy_from_slice(first_part);
                new_arr[first_part_len..used].copy_from_slice(second_part);
            }
        }
        self.arr = new_arr;
        self.head = 0;
        self.tail = used;
        self.size = new_size;
        // 更新状态
        self.status = if used == 0 {
            RingBufferStatus::EMPTY
        } else if used == new_size {
            RingBufferStatus::FULL
        } else {
            RingBufferStatus::NORMAL
        };
        return Ok(new_size);
    }
}

/// Return (read_end, write_end)
pub fn make_pipe(flags: OpenFlags) -> (Arc<Pipe>, Arc<Pipe>) {
    log::trace!("[make_pipe]");
    // let buffer = Arc::new(Mutex::new(PipeRingBuffer::new()));
    let inode = PipeInode::new(0);
    // buffer仅剩两个强引用，这样读写端关闭后就会被释放
    let (read_end, write_end) = Pipe::read_write_end(inode.clone(), flags);
    (read_end, write_end)
}

/// Pipe IOCTL 命令
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum PipeIoctlCmd {
    FIONREAD = 0x541B, // 获取管道中可读字节数
}

impl FileOp for Pipe {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> SyscallRet {
        debug_assert!(self.readable);
        let mut read_size = 0usize;
        let nonblock = self.flags.load(core::sync::atomic::Ordering::Relaxed)
            & OpenFlags::O_NONBLOCK.bits()
            != 0;
        if self.is_named_pipe {
            let mut guard = self.inode.buffer.lock();
            // 命名管道对端还没打开, 需阻塞
            if guard.write_end.is_none() {
                if nonblock {
                    log::error!("[Pipe::read] named pipe read end not ready, non-blocking mode");
                    return Err(Errno::EAGAIN);
                }
                guard.add_waiter(current_task().tid());
                drop(guard);
                if wait() == -1 {
                    // log::error!("[Pipe::read] wait failed");
                    return Err(Errno::ERESTARTSYS);
                }
            } else {
                drop(guard);
            }
        }
        let mut buffer;
        loop {
            buffer = self.inode.buffer.lock();
            core::hint::black_box(&buffer);
            if buffer.status == RingBufferStatus::EMPTY {
                if buffer.all_write_ends_closed() {
                    log::error!("all write ends closed");
                    return Ok(read_size);
                }
                if nonblock {
                    log::error!("[Pipe::read] pipe read end not ready, non-blocking mode");
                    return Err(Errno::EAGAIN);
                }
                // wait for data, 注意释放锁
                buffer.add_waiter(current_task().tid());
                drop(buffer);
                // log::error!("[Pipe::read] set waiter: {}", current_task().tid());
                if wait() == -1 {
                    // log::error!("[Pipe::read] wait failed");
                    return Err(Errno::ERESTARTSYS);
                }
                continue;
            }
            while read_size < buf.len() {
                let read_bytes = buffer.buffer_read(&mut buf[read_size..]);
                let waiter = buffer.get_one_waiter();
                if waiter != 0 {
                    // log::info!("[Pipe::read] wake up waiter");
                    // wake up writer
                    wakeup(waiter);
                }
                // log::error!("[Pipe::read] read_bytes: {}", read_bytes);
                read_size += read_bytes;
                if buffer.head == buffer.tail {
                    buffer.status = RingBufferStatus::EMPTY;
                    return Ok(read_size);
                }
            }
            buffer.status = RingBufferStatus::NORMAL;
            return Ok(read_size);
        }
    }
    fn write<'a>(&'a self, buf: &'a [u8]) -> SyscallRet {
        assert!(self.writable);
        let mut write_size = 0;
        let nonblock = self.flags.load(core::sync::atomic::Ordering::Relaxed)
            & OpenFlags::O_NONBLOCK.bits()
            != 0;
        if self.is_named_pipe {
            let mut guard = self.inode.buffer.lock();
            // 命名管道对端还没打开, 需阻塞
            if guard.read_end.is_none() {
                if nonblock {
                    log::error!("[Pipe::write] named pipe read end not ready, non-blocking mode");
                    return Err(Errno::EAGAIN);
                }
                guard.add_waiter(current_task().tid());
                drop(guard);
                if wait() == -1 {
                    // log::error!("[Pipe::read] wait failed");
                    return Err(Errno::ERESTARTSYS);
                }
            } else {
                drop(guard);
            }
        }
        let mut buffer;
        loop {
            buffer = self.inode.buffer.lock();
            core::hint::black_box(&buffer);
            // 检查读端是否关闭
            if buffer.all_read_ends_closed() {
                log::error!("[Pipe::write] all read ends closed");
                current_task().receive_siginfo(
                    SigInfo::new(
                        Sig::SIGPIPE.raw(),
                        SigInfo::KERNEL,
                        crate::signal::SiField::Kill { tid: current_task().tid() },
                    ),
                    false,
                );
                return Err(Errno::EPIPE);
            }
            if buffer.status == RingBufferStatus::FULL {
                if nonblock {
                    log::error!("[Pipe::write] buffer is full, non-blocking mode, return EAGAIN");
                    return Err(Errno::EAGAIN);
                }
                // wait for space, 注意释放锁
                buffer.add_waiter(current_task().tid());
                drop(buffer);
                // yield_current_task();
                if wait() == -1 {
                    // log::error!("[Pipe::write] wait failed");
                    return Err(Errno::ERESTARTSYS);
                }
                continue;
            }
            while write_size < buf.len() {
                let write_bytes = buffer.buffer_write(&buf[write_size..]);
                let waiter = buffer.get_one_waiter();
                if waiter != 0 {
                    // log::info!("[Pipe::write] wake up waiter");
                    // wake up reader
                    wakeup(waiter);
                }
                // log::error!("[Pipe::write] write_bytes: {}", write_bytes);
                write_size += write_bytes;
                log::info!(
                    "buffer.head: {}, buffer.tail: {}, write_size: {}",
                    buffer.head,
                    buffer.tail,
                    write_size
                );
                if buffer.head == buffer.tail {
                    buffer.status = RingBufferStatus::FULL;
                    log::warn!("[Pipe::write] buffer is full, byte_written: {}", write_size);
                    return Ok(write_size);
                }
            }
            buffer.status = RingBufferStatus::NORMAL;
            return Ok(write_size);
        }
    }
    fn ioctl(&self, op: usize, arg_ptr: usize) -> SyscallRet {
        log::info!("[Pipe::ioctl] op: {:#x}, arg_ptr: {:#x}", op, arg_ptr);
        let op = unsafe { core::mem::transmute::<usize, PipeIoctlCmd>(op) };
        match op {
            PipeIoctlCmd::FIONREAD => {
                // 获取管道中可读字节数
                let buffer = self.inode.buffer.lock();
                let used_size = buffer.get_used_size();
                copy_to_user(arg_ptr as *mut usize, &used_size, 1)?;
                Ok(0)
            }
            _ => {
                log::error!("[Pipe::ioctl] unsupported ioctl command: {:?}", op);
                Err(Errno::ENOTTY)
            }
        }
    }
    // 管道不支持 fsync
    fn fsync(&self) -> SyscallRet {
        return Err(Errno::EINVAL);
    }
    fn readable(&self) -> bool {
        self.readable
    }
    fn writable(&self) -> bool {
        self.writable
    }
    fn seek(&self, offset: isize, whence: super::uapi::Whence) -> SyscallRet {
        return Err(Errno::ESPIPE);
    }
    fn r_ready(&self) -> bool {
        if self.readable {
            let buffer = self.inode.buffer.lock();
            buffer.status != RingBufferStatus::EMPTY
        } else {
            false
        }
    }
    fn w_ready(&self) -> bool {
        if self.writable {
            let buffer = self.inode.buffer.lock();
            buffer.status != RingBufferStatus::FULL
        } else {
            false
        }
    }
    /// 表示另一端已关闭
    fn hang_up(&self) -> bool {
        if self.readable {
            self.inode.buffer.lock().all_write_ends_closed()
        } else {
            self.inode.buffer.lock().all_read_ends_closed()
        }
    }
    fn get_inode(&self) -> Arc<dyn InodeOp> {
        self.inode.clone() as Arc<dyn InodeOp>
    }
    fn get_flags(&self) -> OpenFlags {
        OpenFlags::from_bits(self.flags.load(core::sync::atomic::Ordering::Relaxed)).unwrap()
    }
    fn set_flags(&self, flags: OpenFlags) {
        self.flags
            .store(flags.bits(), core::sync::atomic::Ordering::Relaxed);
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        log::trace!("[Pipe::drop]");
        let buffer = self.inode.buffer.lock();
        let waiter = &buffer.waiter;
        // 唤醒所有等待者
        for &tid in waiter {
            log::warn!("[Pipe::drop] wake up waiter: {}", tid);
            wakeup(tid);
        }
    }
}

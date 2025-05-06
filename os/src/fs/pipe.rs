use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::ptr::copy_nonoverlapping;
use core::sync::atomic::AtomicUsize;
use spin::{Mutex, RwLock};

use crate::ext4::inode::{Ext4InodeDisk, S_IFIFO};
use crate::syscall::errno::{Errno, SyscallRet};
use crate::task::{current_task, wait, wakeup, yield_current_task, Tid};
use crate::timer::TimeSpec;

use super::file::{FileOp, OpenFlags};
use super::inode::InodeOp;
use super::kstat::Kstat;

lazy_static::lazy_static! {
    static ref PIPEINODE: Arc<dyn InodeOp> =
     {
        let mut inode_on_disk = Ext4InodeDisk::default();
        inode_on_disk.set_mode(S_IFIFO);
        inode_on_disk.set_size(RING_DEFAULT_BUFFER_SIZE as u64);
        Arc::new(PipeInode {
            inode_num: 0,
            inner: RwLock::new(PipeInodeInner {
                inode_on_disk
            }),
        })
    };
}

struct PipeInode {
    inode_num: usize,
    inner: RwLock<PipeInodeInner>,
}

struct PipeInodeInner {
    pub inode_on_disk: Ext4InodeDisk,
}

impl InodeOp for PipeInode {
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
}

/// 匿名管道不占用磁盘inode, 其元数据仅存在于内核内存中
pub struct Pipe {
    readable: bool,
    writable: bool,
    buffer: Arc<Mutex<PipeRingBuffer>>,
    flags: OpenFlags,
}

impl Pipe {
    pub fn read_end_with_buffer(buffer: Arc<Mutex<PipeRingBuffer>>, flags: OpenFlags) -> Self {
        Self {
            readable: true,
            writable: false,
            buffer,
            flags,
        }
    }
    pub fn write_end_with_buffer(buffer: Arc<Mutex<PipeRingBuffer>>, flags: OpenFlags) -> Self {
        Self {
            readable: false,
            writable: true,
            buffer,
            flags,
        }
    }
}

pub const RING_DEFAULT_BUFFER_SIZE: usize = 4096;

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
    waiter: Tid,
}

impl PipeRingBuffer {
    fn new() -> Self {
        // let mut vec = Vec::<u8>::with_capacity(RING_DEFAULT_BUFFER_SIZE);
        // unsafe {
        //     vec.set_len(RING_DEFAULT_BUFFER_SIZE);
        // }
        Self {
            arr: vec![0u8; RING_DEFAULT_BUFFER_SIZE],
            head: 0,
            tail: 0,
            status: RingBufferStatus::EMPTY,
            write_end: None,
            read_end: None,
            waiter: 0,
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
            RING_DEFAULT_BUFFER_SIZE
        } else {
            self.tail
        };
        // copy
        let read_bytes = buf.len().min(end - begin);
        unsafe {
            copy_nonoverlapping(self.arr.as_ptr().add(begin), buf.as_mut_ptr(), read_bytes);
        };
        // update head
        self.head = if begin + read_bytes == RING_DEFAULT_BUFFER_SIZE {
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
            RING_DEFAULT_BUFFER_SIZE
        };
        // write
        let write_bytes = buf.len().min(end - begin);
        unsafe {
            copy_nonoverlapping(buf.as_ptr(), self.arr.as_mut_ptr().add(begin), write_bytes);
        };
        // update tail
        self.tail = if begin + write_bytes == RING_DEFAULT_BUFFER_SIZE {
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
    fn get_waiter(&self) -> Tid {
        self.waiter
    }
    fn set_waiter(&mut self, waiter: Tid) {
        self.waiter = waiter;
    }
}

/// Return (read_end, write_end)
pub fn make_pipe(flags: OpenFlags) -> (Arc<Pipe>, Arc<Pipe>) {
    log::trace!("[make_pipe]");
    let buffer = Arc::new(Mutex::new(PipeRingBuffer::new()));
    // buffer仅剩两个强引用，这样读写端关闭后就会被释放
    let read_end = Arc::new(Pipe::read_end_with_buffer(buffer.clone(), flags));
    let write_end = Arc::new(Pipe::write_end_with_buffer(buffer.clone(), flags));
    buffer.lock().set_write_end(&write_end);
    buffer.lock().set_read_end(&read_end);
    (read_end, write_end)
}

impl FileOp for Pipe {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> usize {
        debug_assert!(self.readable);
        let mut read_size = 0usize;
        let mut buffer;
        loop {
            buffer = self.buffer.lock();
            core::hint::black_box(&buffer);
            if buffer.status == RingBufferStatus::EMPTY {
                if buffer.all_write_ends_closed() {
                    log::error!("all write ends closed");
                    return read_size;
                }
                // wait for data, 注意释放锁
                buffer.set_waiter(current_task().tid());
                drop(buffer);
                // log::error!("[Pipe::read] set waiter: {}", current_task().tid());
                wait();
                continue;
            }
            while read_size < buf.len() {
                let read_bytes = buffer.buffer_read(&mut buf[read_size..]);
                if buffer.get_waiter() != 0 {
                    // log::info!("[Pipe::read] wake up waiter");
                    // wake up writer
                    let waiter = buffer.get_waiter();
                    buffer.set_waiter(0);
                    wakeup(waiter);
                }
                // log::error!("[Pipe::read] read_bytes: {}", read_bytes);
                read_size += read_bytes;
                if buffer.head == buffer.tail {
                    buffer.status = RingBufferStatus::EMPTY;
                    return read_size;
                }
            }
            buffer.status = RingBufferStatus::NORMAL;
            return read_size;
        }
    }
    fn write<'a>(&'a self, buf: &'a [u8]) -> usize {
        assert!(self.writable);
        let mut write_size = 0;
        let mut buffer;
        loop {
            buffer = self.buffer.lock();
            core::hint::black_box(&buffer);
            if buffer.status == RingBufferStatus::FULL {
                if buffer.all_read_ends_closed() {
                    return write_size;
                }
                // wait for space, 注意释放锁
                buffer.set_waiter(current_task().tid());
                drop(buffer);
                // yield_current_task();
                wait();
                continue;
            }
            while write_size < buf.len() {
                let write_bytes = buffer.buffer_write(&buf[write_size..]);
                if buffer.get_waiter() != 0 {
                    // log::info!("[Pipe::write] wake up waiter");
                    // wake up reader
                    let waiter = buffer.get_waiter();
                    buffer.set_waiter(0);
                    wakeup(waiter);
                }
                // log::error!("[Pipe::write] write_bytes: {}", write_bytes);
                write_size += write_bytes;
                if buffer.head == buffer.tail {
                    buffer.status = RingBufferStatus::FULL;
                    return write_size;
                }
            }
            buffer.status = RingBufferStatus::NORMAL;
            return write_size;
        }
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
            let buffer = self.buffer.lock();
            buffer.status != RingBufferStatus::EMPTY
        } else {
            false
        }
    }
    fn w_ready(&self) -> bool {
        if self.writable {
            let buffer = self.buffer.lock();
            buffer.status != RingBufferStatus::FULL
        } else {
            false
        }
    }
    /// 表示另一端已关闭
    fn hang_up(&self) -> bool {
        if self.readable {
            self.buffer.lock().all_write_ends_closed()
        } else {
            self.buffer.lock().all_read_ends_closed()
        }
    }
    fn get_inode(&self) -> Arc<dyn InodeOp> {
        PIPEINODE.clone()
    }
    fn get_flags(&self) -> OpenFlags {
        self.flags
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        log::trace!("[Pipe::drop]");
        let buffer = self.buffer.lock();
        let waiter = buffer.get_waiter();
        if waiter != 0 {
            // wake up reader or writer
            wakeup(waiter);
        }
    }
}

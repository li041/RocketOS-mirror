use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};
use spin::Mutex;

use crate::fs::file::{FileOp, OpenFlags};
use crate::fs::pipe::{PipeRingBuffer, RingBufferStatus};
use crate::syscall::errno::{Errno, SyscallRet};
use crate::task::{current_task, wait, wakeup, Tid};

/// 全双工 SocketPairBuffer 使用两个 PipeRingBuffer
pub struct SocketPairBuffer {
    /// A -> B 方向缓冲区
    pub a_to_b: Arc<Mutex<PipeRingBuffer>>,
    /// B -> A 方向缓冲区
    pub b_to_a: Arc<Mutex<PipeRingBuffer>>,
}

impl SocketPairBuffer {
    pub fn new() -> Self {
        Self {
            a_to_b: Arc::new(Mutex::new(PipeRingBuffer::new(128))),
            b_to_a: Arc::new(Mutex::new(PipeRingBuffer::new(128))),
        }
    }
}

/// BufferEnd 代表 SocketPair 的一端
pub struct BufferEnd {
    /// 用于读操作的缓冲区
    read_buf: Arc<Mutex<PipeRingBuffer>>,
    /// 用于写操作的缓冲区
    write_buf: Arc<Mutex<PipeRingBuffer>>,
    //判断拥有的是写端还是读端
    flags: AtomicI32,
    /// 是否有读权限
    pub readable: bool,
    /// 是否有写权限
    pub writable: bool,
}

impl BufferEnd {
    fn new(
        read_buf: Arc<Mutex<PipeRingBuffer>>,
        write_buf: Arc<Mutex<PipeRingBuffer>>,
        flags: OpenFlags,
    ) -> Self {
        Self {
            read_buf,
            write_buf,
            flags: AtomicI32::new(flags.bits()),
            //全双工
            readable: true,
            writable: true,
        }
    }

    /// 根据 endpoint 0/1 生成对应的 BufferEnd
    pub fn from_pair(buf: &SocketPairBuffer, endpoint: usize, flags: OpenFlags) -> Self {
        if endpoint == 0 {
            BufferEnd::new(buf.b_to_a.clone(), buf.a_to_b.clone(), flags)
        } else {
            BufferEnd::new(buf.a_to_b.clone(), buf.b_to_a.clone(), flags)
        }
    }
}

impl FileOp for BufferEnd {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    /// 判断是否有读权限
    fn readable(&self) -> bool {
        self.readable
    }

    /// 判断是否有写权限
    fn writable(&self) -> bool {
        self.writable
    }

    /// 判断是否有数据可读
    fn r_ready(&self) -> bool {
        if self.readable {
            let ring = self.read_buf.lock();
            ring.status != RingBufferStatus::EMPTY
        } else {
            false
        }
    }

    /// 判断是否有空间可写
    fn w_ready(&self) -> bool {
        if self.readable {
            let ring = self.write_buf.lock();
            ring.status != RingBufferStatus::FULL
        } else {
            false
        }
    }

    fn read<'a>(&'a self, buf: &'a mut [u8]) -> SyscallRet {
        debug_assert!(self.readable());
        //检查对端是否打开
        let mut guard = self.read_buf.lock();
        let nonblock = self.flags.load(Ordering::Relaxed) & OpenFlags::O_NONBLOCK.bits() != 0;
        if guard.write_end.is_none() {
            //如果没有
            if nonblock {
                return Err(Errno::EAGAIN);
            }
            guard.add_waiter(current_task().tid());
            drop(guard);
            if wait() == -1 {
                return Err(Errno::ERESTARTSYS);
            }
        } else {
            drop(guard);
        }

        loop {
            let mut ring = self.read_buf.lock();
            if ring.status == RingBufferStatus::EMPTY {
                if nonblock {
                    return Err(Errno::EAGAIN);
                }
                ring.add_waiter(current_task().tid());
                drop(ring);
                if wait() == -1 {
                    return Err(Errno::ERESTARTSYS);
                }
                continue;
            }
            let n = ring.buffer_read(buf);
            let waiter = ring.get_one_waiter();
            drop(ring);
            if waiter != 0 {
                wakeup(waiter);
            }
            return Ok(n);
        }
    }

    fn write<'a>(&'a self, buf: &'a [u8]) -> SyscallRet {
        debug_assert!(self.writable());
        let nonblock = self.flags.load(Ordering::Relaxed) & OpenFlags::O_NONBLOCK.bits() != 0;
        let mut guard = self.write_buf.lock();
        let nonblock = self.flags.load(Ordering::Relaxed) & OpenFlags::O_NONBLOCK.bits() != 0;
        if guard.read_end.is_none() {
            //如果没有
            if nonblock {
                return Err(Errno::EAGAIN);
            }
            guard.add_waiter(current_task().tid());
            drop(guard);
            if wait() == -1 {
                return Err(Errno::ERESTARTSYS);
            }
        } else {
            drop(guard);
        }
        loop {
            let mut ring = self.write_buf.lock();
            // 对端关闭检查，触发 SIGPIPE
            if ring.all_read_ends_closed() {
                current_task().receive_siginfo(
                    crate::signal::SigInfo::new(
                        crate::signal::Sig::SIGPIPE.raw(),
                        crate::signal::SigInfo::KERNEL,
                        crate::signal::SiField::Kill {
                            tid: current_task().tid(),
                        },
                    ),
                    false,
                );
                return Err(Errno::EPIPE);
            }
            if ring.status == RingBufferStatus::FULL {
                if nonblock {
                    return Err(Errno::EAGAIN);
                }
                ring.add_waiter(current_task().tid());
                drop(ring);
                if wait() == -1 {
                    return Err(Errno::ERESTARTSYS);
                }
                continue;
            }
            let n = ring.buffer_write(buf);
            let waiter = ring.get_one_waiter();
            drop(ring);
            if waiter != 0 {
                wakeup(waiter);
            }
            return Ok(n);
        }
    }

    fn ioctl(&self, _: usize, _: usize) -> SyscallRet {
        Err(Errno::ENOTTY)
    }

    fn fsync(&self) -> SyscallRet {
        Err(Errno::EINVAL)
    }
    fn hang_up(&self) -> bool {
        if self.readable {
            //如果读权限，判断对端的写是否都被关闭了
            self.read_buf.lock().all_write_ends_closed()
        } else {
            //如果写权限，判断对端的读是否都被关闭了
            self.write_buf.lock().all_read_ends_closed()
        }
    }
    fn add_wait_queue(&self, tid: Tid) {
        // 读端等待写缓冲区可写，写端等待读缓冲区可读
        let mut ring = if self.readable {
            self.write_buf.lock()
        } else {
            self.read_buf.lock()
        };
        ring.add_waiter(tid);
    }
    fn seek(&self, _: isize, _: crate::fs::uapi::Whence) -> SyscallRet {
        Err(Errno::ESPIPE)
    }
}

/// 创建 SocketPair 的两个 BufferEnd
pub fn create_buffer_ends(flags: OpenFlags) -> (BufferEnd, BufferEnd) {
    let buf = SocketPairBuffer::new();
    (
        BufferEnd::from_pair(&buf, 0, flags),
        BufferEnd::from_pair(&buf, 1, flags),
    )
}

impl Drop for BufferEnd {
    fn drop(&mut self) {
        for tid in &self.read_buf.lock().waiter {
            wakeup(*tid);
        }
        for tid in &self.write_buf.lock().waiter {
            wakeup(*tid);
        }
    }
}

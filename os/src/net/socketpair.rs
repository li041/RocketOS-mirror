use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};
use spin::Mutex;

use crate::fs::file::{FileOp, OpenFlags};
use crate::fs::pipe::{PipeRingBuffer, RingBufferStatus};
use crate::syscall::errno::{Errno, SyscallRet};
use crate::task::{current_task, wait, wakeup, Tid};

// /// 全双工 SocketPairBuffer 使用两个 PipeRingBuffer
// pub struct SocketPairBuffer {
//     /// A -> B 方向缓冲区
//     pub a_to_b: Arc<Mutex<PipeRingBuffer>>,
//     /// B -> A 方向缓冲区
//     pub b_to_a: Arc<Mutex<PipeRingBuffer>>,
// }

// impl SocketPairBuffer {
//     pub fn new() -> Self {
//         Self {
//             a_to_b: Arc::new(Mutex::new(PipeRingBuffer::new(128))),
//             b_to_a: Arc::new(Mutex::new(PipeRingBuffer::new(128))),
//         }
//     }
// }

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

impl Drop for BufferEnd {
    fn drop(&mut self) {
        log::trace!("[BufferEnd] drop",);
        // Todo: 应该read_buf和write_buf取一个用来唤醒对端就行j
        let buffer = self.write_buf.lock();
        let waiter = &buffer.waiter;
        for &tid in &buffer.waiter {
            log::warn!("[BufferEnd] drop: wakeup tid: {}", tid);
            wakeup(tid);
        }
    }
}

impl BufferEnd {
    fn new(
        read_buf: Arc<Mutex<PipeRingBuffer>>,
        write_buf: Arc<Mutex<PipeRingBuffer>>,
        flags: OpenFlags,
    ) -> Arc<Self> {
        Arc::new(Self {
            read_buf,
            write_buf,
            flags: AtomicI32::new(flags.bits()),
            //全双工
            readable: true,
            writable: true,
        })
    }

    // /// 根据 endpoint 0/1 生成对应的 BufferEnd
    // pub fn from_pair(buf: &SocketPairBuffer, endpoint: usize, flags: OpenFlags) -> Self {
    //     if endpoint == 0 {
    //         BufferEnd::new(buf.b_to_a.clone(), buf.a_to_b.clone(), flags)
    //     } else {
    //         BufferEnd::new(buf.a_to_b.clone(), buf.b_to_a.clone(), flags)
    //     }
    // }
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
        let nonblock = self.flags.load(Ordering::Relaxed) & OpenFlags::O_NONBLOCK.bits() != 0;

        loop {
            log::trace!("BufferEnd::read: nonblock: {}, buf: {:?}", nonblock, buf);
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
            if ring.head == ring.tail {
                ring.status = RingBufferStatus::EMPTY;
            } else {
                ring.status = RingBufferStatus::NORMAL;
            }
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

        loop {
            log::trace!("BufferEnd::write: nonblock: {}, buf: {:?}", nonblock, buf);
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
            if ring.head == ring.tail {
                ring.status = RingBufferStatus::FULL;
            } else {
                ring.status = RingBufferStatus::NORMAL;
            }
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
    // Todo: 有问题, buffer_end应该是即可写, 又可读的
    fn hang_up(&self) -> bool {
        // 应该只检查对端是否关闭就行
        self.write_buf.lock().all_read_ends_closed()
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
pub fn create_buffer_ends(flags: OpenFlags) -> (Arc<BufferEnd>, Arc<BufferEnd>) {
    // let buf = SocketPairBuffer::new();
    let end0_buf = Arc::new(Mutex::new(PipeRingBuffer::new(128)));
    let end1_buf = Arc::new(Mutex::new(PipeRingBuffer::new(128)));
    let end0 = BufferEnd::new(end0_buf.clone(), end1_buf.clone(), flags);
    let end1 = BufferEnd::new(end1_buf.clone(), end0_buf.clone(), flags);
    // 设置读, 写端
    end0_buf.lock().set_read_end(end0.clone());
    end0_buf.lock().set_write_end(end1.clone());
    end1_buf.lock().set_read_end(end1.clone());
    end1_buf.lock().set_write_end(end0.clone());
    // let end0 = BufferEnd::from_pair(&buf, 0, flags);
    // let end1 = BufferEnd::from_pair(&buf, 1, flags);
    // (
    //     BufferEnd::from_pair(&buf, 0, flags),
    //     BufferEnd::from_pair(&buf, 1, flags),
    // )
    (end0, end1)
}

/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-06-11 22:45:33
 * @LastEditTime: 2025-06-12 00:14:14
 * @FilePath: /RocketOS_netperfright/os/src/net/socketpair.rs
 * @Description: 全双工 SocketPairBuffer 及 BufferEnd FileOp 实现
 */

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};
use spin::Mutex;
use alloc::vec;
use crate::syscall::errno::{Errno, SyscallRet};
use crate::task::{current_task, wait, wakeup, Tid};
use crate::fs::file::{FileOp, OpenFlags};
use crate::fs::inode::InodeOp;

const RING_DEFAULT_BUFFER_SIZE: usize = 65536;

struct RingBuf {
    buf: Vec<u8>, head: usize, tail: usize, full: bool, size: usize,
}

impl RingBuf {
    fn new() -> Self {
        Self { buf: vec![0; RING_DEFAULT_BUFFER_SIZE], head: 0, tail: 0, full: false, size: RING_DEFAULT_BUFFER_SIZE }
    }
    fn used(&self) -> usize {
        if self.full { self.size }
        else if self.tail >= self.head { self.tail - self.head }
        else { self.size + self.tail - self.head }
    }
    fn avail(&self) -> usize { self.size - self.used() }
    fn read(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.used());
        for i in 0..n { out[i] = self.buf[self.head]; self.head = (self.head + 1) % self.size; }
        self.full = false;
        n
    }
    fn write(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.avail());
        for i in 0..n { self.buf[self.tail] = data[i]; self.tail = (self.tail + 1) % self.size; }
        if n > 0 && self.tail == self.head { self.full = true; }
        n
    }
}

pub struct SocketPairBuffer {
    pub a_to_b: RingBuf,
    pub b_to_a: RingBuf,
    pub a_waiters: Vec<Tid>,
    pub b_waiters: Vec<Tid>,
}

impl SocketPairBuffer {
    pub fn new() -> Self {
        Self { a_to_b: RingBuf::new(), b_to_a: RingBuf::new(), a_waiters: Vec::new(), b_waiters: Vec::new() }
    }
}

pub struct BufferEnd {
    buffer: Arc<Mutex<SocketPairBuffer>>,
    endpoint: usize,
    flags: AtomicI32,
}

impl BufferEnd {
    pub fn new(buffer: Arc<Mutex<SocketPairBuffer>>, endpoint: usize, flags: OpenFlags) -> Self {
        Self { buffer, endpoint, flags: AtomicI32::new(flags.bits()) }
    }
}

impl FileOp for BufferEnd {
    fn as_any(&self) -> &dyn core::any::Any { self }

    fn read<'a>(&'a self, buf: &'a mut [u8]) -> SyscallRet {
        let nonblock = self.flags.load(Ordering::Relaxed) & OpenFlags::O_NONBLOCK.bits() != 0;
        loop {
            let mut guard = self.buffer.lock();
            if self.endpoint == 0 {
                // A端 reads from b_to_a
                let used = guard.b_to_a.used();
                if used == 0 {
                    if nonblock 
                    { 
                        return Err(Errno::EAGAIN); 
                    }
                    guard.a_waiters.push(current_task().tid());
                    drop(guard);
                    if wait() == -1 
                    { 
                        return Err(Errno::ERESTARTSYS); 
                    }
                    continue;
                }
                let tid = guard.a_waiters.pop().unwrap_or(0);
                let n = guard.b_to_a.read(buf);
                log::error!("[BufferEnd read A] read buf is {:?} len is {:?}",buf,buf.len());
                drop(guard);
                if tid != 0 
                { 
                    wakeup(tid); 
                }
                return Ok(n);
            } else {
                // B端 reads from a_to_b
                let used = guard.a_to_b.used();
                if used == 0 {
                    if nonblock 
                    { 
                        return Err(Errno::EAGAIN); 
                    }
                    guard.b_waiters.push(current_task().tid());
                    drop(guard);
                    if wait() == -1 
                    { 
                        return Err(Errno::ERESTARTSYS); 
                    }
                    continue;
                }
                let tid = guard.b_waiters.pop().unwrap_or(0);
                let n = guard.a_to_b.read(buf);
                log::error!("[BufferEnd read B] read buf is {:?} len is {:?}",buf,buf.len());
                drop(guard);
                if tid != 0 
                { 
                    wakeup(tid); 
                }
                return Ok(n);
            }
        }
    }

    fn write<'a>(&'a self, buf: &'a [u8]) -> SyscallRet {
        log::error!("[BufferEnd] write buffer is {:?}",buf);
        let nonblock = self.flags.load(Ordering::Relaxed) & OpenFlags::O_NONBLOCK.bits() != 0;
        loop {
            let mut guard = self.buffer.lock();
            if self.endpoint == 0 {
                // A端 writes to a_to_b
                let avail = guard.a_to_b.avail();
                if avail == 0 {
                    if nonblock 
                    { 
                        return Err(Errno::EAGAIN); 
                    }
                    guard.b_waiters.push(current_task().tid());
                    drop(guard);
                    if wait() == -1 
                    { 
                        return Err(Errno::ERESTARTSYS); 
                    }
                    continue;
                }
                let tid = guard.b_waiters.pop().unwrap_or(0);
                let n = guard.a_to_b.write(buf);
                log::error!("[BufferEnd] write A buffer is {:?}",buf);
                drop(guard);
                if tid != 0 
                { 
                    wakeup(tid); 
                }
                return Ok(n);
            } else {
                // B端 writes to b_to_a
                let avail = guard.b_to_a.avail();
                if avail == 0 {
                    if nonblock 
                    { 
                        return Err(Errno::EAGAIN); 
                    }
                    guard.a_waiters.push(current_task().tid());
                    drop(guard);
                    if wait() == -1 
                    { 
                        return Err(Errno::ERESTARTSYS); 
                    }
                    continue;
                }
                let tid = guard.a_waiters.pop().unwrap_or(0);
                let n = guard.b_to_a.write(buf);
                log::error!("[BufferEnd] write B buffer is {:?}",buf);
                drop(guard);
                if tid != 0 
                { 
                    wakeup(tid); 
                }
                return Ok(n);
            }
        }
    }

    fn ioctl(&self, _: usize, _: usize) -> SyscallRet 
    { 
        Err(Errno::ENOTTY) 
    }
    fn fsync(&self) -> SyscallRet 
    { 
        Err(Errno::EINVAL) 
    }
    fn readable(&self) -> bool {
        let guard = self.buffer.lock();
        if self.endpoint == 0 
        { 
            log::error!("[Bufferend_readable] endpoint=0 b_to_a {:?}",guard.b_to_a.used());
            guard.b_to_a.used() > 0 
        } else 
        { 
            log::error!("[Bufferend_readable] endpoint=0 b_to_a {:?}",guard.a_to_b.used());
            guard.a_to_b.used() > 0 
        }
    }
    fn writable(&self) -> bool {
        let guard = self.buffer.lock();
        if self.endpoint == 0 
        { 
            guard.a_to_b.avail() > 0 
        } else 
        { 
            guard.b_to_a.avail() > 0 
        }
    }
    fn seek(&self, _: isize, _: crate::fs::uapi::Whence) -> SyscallRet 
    {
         Err(Errno::ESPIPE) 
    }
    fn r_ready(&self) -> bool 
    { 
        self.readable() 
    }
    fn w_ready(&self) -> bool 
    { 
        self.writable() 
    }
    fn hang_up(&self) -> bool 
    { 
        false 
    }
    fn get_flags(&self) -> OpenFlags 
    { 
        OpenFlags::from_bits(self.flags.load(Ordering::Relaxed)).unwrap() 
    }
    fn set_flags(&self, f: OpenFlags) 
    { 
        self.flags.store(f.bits(), Ordering::Relaxed); 
    }
}

pub fn create_buffer_ends(flags: OpenFlags) -> (BufferEnd, BufferEnd) {
    let buf = Arc::new(Mutex::new(SocketPairBuffer::new()));
    (BufferEnd::new(buf.clone(), 0, flags), BufferEnd::new(buf, 1, flags))
}

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use core::ptr::copy_nonoverlapping;
use spin::Mutex;

use crate::task::yield_current_task;

use super::file::FileOp;

pub struct Pipe {
    readable: bool,
    writable: bool,
    buffer: Arc<Mutex<PipeRingBuffer>>,
}

impl Pipe {
    pub fn read_end_with_buffer(buffer: Arc<Mutex<PipeRingBuffer>>) -> Self {
        Self {
            readable: true,
            writable: false,
            buffer,
        }
    }
    pub fn write_end_with_buffer(buffer: Arc<Mutex<PipeRingBuffer>>) -> Self {
        Self {
            readable: false,
            writable: true,
            buffer,
        }
    }
}

const RING_DEFAULT_BUFFER_SIZE: usize = 4096;

#[derive(Copy, Clone, PartialEq, Debug)]
enum RingBufferStatus {
    FULL,
    EMPTY,
    NORMAL,
}

pub struct PipeRingBuffer {
    arr: Box<[u8; RING_DEFAULT_BUFFER_SIZE]>,
    head: usize,
    tail: usize,
    status: RingBufferStatus,
    write_end: Option<Weak<Pipe>>,
    read_end: Option<Weak<Pipe>>,
}

impl PipeRingBuffer {
    fn new() -> Self {
        // let mut vec = Vec::<u8>::with_capacity(RING_DEFAULT_BUFFER_SIZE);
        // unsafe {
        //     vec.set_len(RING_DEFAULT_BUFFER_SIZE);
        // }
        Self {
            arr: Box::new([0u8; RING_DEFAULT_BUFFER_SIZE]),
            head: 0,
            tail: 0,
            status: RingBufferStatus::EMPTY,
            write_end: None,
            read_end: None,
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
        self.write_end.as_ref().unwrap().upgrade().is_none()
    }
    fn all_read_ends_closed(&self) -> bool {
        self.read_end.as_ref().unwrap().upgrade().is_none()
    }
}

/// Return (read_end, write_end)
pub fn make_pipe() -> (Arc<Pipe>, Arc<Pipe>) {
    let buffer = Arc::new(Mutex::new(PipeRingBuffer::new()));
    // buffer仅剩两个强引用，这样读写端关闭后就会被释放
    let read_end = Arc::new(Pipe::read_end_with_buffer(buffer.clone()));
    let write_end = Arc::new(Pipe::write_end_with_buffer(buffer.clone()));
    buffer.lock().set_write_end(&write_end);
    buffer.lock().set_read_end(&read_end);
    (read_end, write_end)
}

pub const ESPIPE: usize = 29; // Invalid seek on a pipe

impl FileOp for Pipe {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> usize {
        debug_assert!(self.readable);
        let mut read_size = 0usize;
        loop {
            let mut buffer = self.buffer.lock();
            if buffer.status == RingBufferStatus::EMPTY {
                if buffer.all_write_ends_closed() {
                    log::error!("all write ends closed");
                    return read_size;
                }
                // wait for data, 注意释放锁
                drop(buffer);
                yield_current_task();
                continue;
            }
            while read_size < buf.len() {
                let read_bytes = buffer.buffer_read(&mut buf[read_size..]);
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
        loop {
            let mut buffer = self.buffer.lock();
            if buffer.status == RingBufferStatus::FULL {
                if buffer.all_read_ends_closed() {
                    return write_size;
                }
                // wait for space, 注意释放锁
                drop(buffer);
                yield_current_task();
                continue;
            }
            while write_size < buf.len() {
                let write_bytes = buffer.buffer_write(&buf[write_size..]);
                log::error!("write_bytes: {}", write_bytes);
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
    fn seek(&self, offset: isize, whence: super::uapi::Whence) -> usize {
        return ESPIPE;
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
}

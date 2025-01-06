use alloc::{boxed::Box, sync::Arc};
use log::error;

use crate::{mutex::SpinNoIrqLock, task::yield_task, utils::SyscallErr, AsyncResult, SyscallRet};

use super::{File, FileMeta};

// pub const PIPE_BUFFER_SIZE: usize = 101000;
// pub const PIPE_BUFFER_SIZE: usize = 1024 * 16;
pub const PIPE_BUFFER_SIZE: usize = 1024 * 4;

pub struct Pipe {
    buffer: Arc<SpinNoIrqLock<PipeRingBuffer>>,
    meta: FileMeta,
}

impl Pipe {
    /// return (pipe_read, pipe_write)
    pub fn new_pair() -> (Arc<Self>, Arc<Self>) {
        let buffer = Arc::new(SpinNoIrqLock::new(PipeRingBuffer {
            buffer: [0; PIPE_BUFFER_SIZE],
            read_pos: 0,
            write_pos: 0,
            // eof: false,
            writer_count: 1,
        }));
        (
            Arc::new(Self {
                buffer: buffer.clone(),
                meta: FileMeta::new_bare(true, false, super::OSFileType::Pipe),
            }),
            Arc::new(Self {
                buffer: buffer.clone(),
                meta: FileMeta::new_bare(false, true, super::OSFileType::Pipe),
            }),
        )
    }

    /// the only difference from `pipe` is, both fds are readable and writable
    pub fn new_socketpair() -> (Arc<Self>, Arc<Self>) {
        let buffer = Arc::new(SpinNoIrqLock::new(PipeRingBuffer {
            buffer: [0; PIPE_BUFFER_SIZE],
            read_pos: 0,
            write_pos: 0,
            // eof: false,
            writer_count: 2,
        }));
        (
            Arc::new(Self {
                buffer: buffer.clone(),
                meta: FileMeta::new_bare(true, true, super::OSFileType::SocketPair),
            }),
            Arc::new(Self {
                buffer: buffer.clone(),
                meta: FileMeta::new_bare(true, true, super::OSFileType::SocketPair),
            }),
        )
    }

    pub fn read_inner(&self, buf: &mut [u8]) -> usize {
        let mut read_size = 0;
        let mut buffer = self.buffer.lock();
        for char in buf {
            if let Some(c) = buffer.read_char() {
                *char = c;
                read_size += 1;
            } else {
                break;
            }
        }
        log::debug!("[Pipe::read_inner] read_size = {}", read_size);
        read_size
    }

    pub fn write_inner(&self, buf: &[u8]) -> usize {
        let mut write_size = 0;
        let mut buffer = self.buffer.lock();
        for char in buf {
            if !buffer.write_char(*char) {
                break;
            }
            write_size += 1;
        }
        log::debug!("[Pipe::write_inner] write_size = {}", write_size);
        write_size
    }
}

impl File for Pipe {
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> AsyncResult<usize> {
        Box::pin(async move {
            if !self.meta.readable {
                return Err(SyscallErr::EBADF.into());
            }
            loop {
                let ret = self.read_inner(buf);
                if ret != 0 {
                    return Ok(ret);
                } else if self.buffer.lock().eof() {
                    // empty buffer and no writer, EOF
                    log::debug!("[Pipe::read] EOF");
                    return Ok(0);
                } else {
                    // empty buffer but writer exists, wait
                    yield_task().await;
                    continue;
                }
            }
        })
    }

    fn write<'a>(&'a self, buf: &'a [u8]) -> AsyncResult<usize> {
        Box::pin(async move {
            if !self.meta.writable {
                return Err(SyscallErr::EBADF.into());
            }
            // block on full buffer by default
            while self.buffer.lock().full() {
                yield_task().await;
            }
            Ok(self.write_inner(buf))
        })
    }

    fn get_meta(&self) -> &FileMeta {
        &self.meta
    }

    fn seek(&self, _offset: usize) -> Option<usize> {
        None
    }

    fn ioctl(&self, _request: usize, _argp: usize) -> SyscallRet {
        error!("[Pipe] ioctl not implemented");
        Err(SyscallErr::ENOTTY as usize)
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        if self.meta.writable {
            let mut buffer = self.buffer.lock();
            // buffer.eof = true;
            buffer.writer_count -= 1;
        }
    }
}

struct PipeRingBuffer {
    buffer: [u8; PIPE_BUFFER_SIZE],
    read_pos: usize,
    write_pos: usize,
    // // whether writer exists
    // eof: bool,
    // number of writers, if writer_count == 0, then eof
    writer_count: usize,
}

impl PipeRingBuffer {
    fn read_char(&mut self) -> Option<u8> {
        if self.read_pos == self.write_pos {
            None
        } else {
            let c = self.buffer[self.read_pos];
            self.read_pos = (self.read_pos + 1) % PIPE_BUFFER_SIZE;
            Some(c)
        }
    }
    fn write_char(&mut self, c: u8) -> bool {
        if (self.write_pos + 1) % PIPE_BUFFER_SIZE == self.read_pos {
            false
        } else {
            self.buffer[self.write_pos] = c;
            self.write_pos = (self.write_pos + 1) % PIPE_BUFFER_SIZE;
            true
        }
    }
    fn eof(&self) -> bool {
        self.writer_count == 0
        // self.eof
    }
    fn full(&self) -> bool {
        (self.write_pos + 1) % PIPE_BUFFER_SIZE == self.read_pos
    }
}

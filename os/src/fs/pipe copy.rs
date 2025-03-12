use alloc::sync::Arc;
use log::debug;

use crate::{mutex::SpinNoIrqLock, task::yield_current_task};

use super::{file::FileOp, FileMeta, FileOld};

const PIPE_BUFFER_SIZE: usize = 4096;

pub struct Pipe {
    buffer: Arc<SpinNoIrqLock<PipeRingBuffer>>,
    readable: bool,
    writeable: bool,
}

impl Pipe {
    /// return (pipe_read, pipe_write)
    pub fn new_pair() -> (Arc<Self>, Arc<Self>) {
        let buffer = Arc::new(SpinNoIrqLock::new(PipeRingBuffer {
            buffer: [0; PIPE_BUFFER_SIZE],
            read_pos: 0,
            write_pos: 0,
            eof: false,
        }));
        (
            Arc::new(Self {
                buffer: buffer.clone(),
                readable: true,
                writeable: false,
            }),
            Arc::new(Self {
                buffer: buffer.clone(),
                readable: false,
                writeable: true,
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
        write_size
    }
}

impl FileOp for Pipe {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> usize {
        // if self.buffer.lock().eof() {
        //     return Ok(0);
        // }
        loop {
            let ret = self.read_inner(buf);
            if ret != 0 {
                return ret;
            } else if self.buffer.lock().eof() {
                // empty buffer and no writer, EOF
                return 0;
            } else {
                // empty buffer but writer exists, wait
                yield_current_task();
                continue;
            }
            // yield_task().await;
            // continue;
        }
    }
    fn write<'a>(&'a self, buf: &'a [u8]) -> usize {
        debug!("[Pipe::write] entered");
        self.write_inner(buf)
    }
    fn readable(&self) -> bool {
        self.readable
    }

    fn writable(&self) -> bool {
        self.writeable
    }
    fn get_offset(&self) -> usize {
        panic!("Pipe does not support get_offset")
    }
    fn seek(&self, _offset: usize) {
        panic!("Pipe does not support seek")
    }
}

impl FileOld for Pipe {
    fn readable(&self) -> bool {
        self.readable
    }

    fn writable(&self) -> bool {
        self.writeable
    }
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> usize {
        // if self.buffer.lock().eof() {
        //     return Ok(0);
        // }
        loop {
            let ret = self.read_inner(buf);
            if ret != 0 {
                return ret;
            } else if self.buffer.lock().eof() {
                // empty buffer and no writer, EOF
                return 0;
            } else {
                // empty buffer but writer exists, wait
                yield_current_task();
                continue;
            }
            // yield_task().await;
            // continue;
        }
    }

    fn write<'a>(&'a self, buf: &'a [u8]) -> usize {
        debug!("[Pipe::write] entered");
        self.write_inner(buf)
    }

    fn get_meta(&self) -> FileMeta {
        FileMeta::new(None, 0)
    }

    fn seek(&self, _offset: usize) {
        panic!("Pipe does not support seek")
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        if self.writeable {
            let mut buffer = self.buffer.lock();
            buffer.eof = true;
        }
    }
}

struct PipeRingBuffer {
    buffer: [u8; PIPE_BUFFER_SIZE],
    read_pos: usize,
    write_pos: usize,
    // whether writer exists
    eof: bool,
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
        self.eof
    }
}

//!Stdin & Stdout
use super::{file::FileOp, uapi::Whence, FileMeta, FileOld};
// use crate::mm::UserBuffer;
use crate::{arch::sbi::console_getchar, syscall::errno::SyscallRet, task::yield_current_task};
// use crate::task::yield_task;
///Standard input
pub struct Stdin;
///Standard output
pub struct Stdout;

impl FileOp for Stdin {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> usize {
        // assert_eq!(buf.len(), 1);
        // busy loop
        let mut c: usize;
        loop {
            c = console_getchar();
            // opensbi returns usize::MAX if no char available
            if c == usize::MAX {
                // 此处对ioctl要读取的参数进行了fake
                // if buf.len() != 1 {
                //     break;
                // }
                yield_current_task();
                continue;
            } else {
                break;
            }
        }
        let ch = c as u8;
        unsafe {
            // buf.buffers[0].as_mut_ptr().write_volatile(ch);
            buf.as_mut_ptr().write_volatile(ch);
        }
        1
    }
    fn write(&self, _buf: &[u8]) -> usize {
        panic!("Cannot write to stdin!");
    }
    fn seek(&self, _offset: isize, _whence: Whence) -> SyscallRet {
        panic!("Cannot seek stdin!");
    }
    fn get_offset(&self) -> usize {
        panic!("Cannot get offset from stdin!");
    }
    fn readable(&self) -> bool {
        true
    }
    fn writable(&self) -> bool {
        false
    }
}

impl FileOp for Stdout {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn read(&self, _buf: &mut [u8]) -> usize {
        panic!("Cannot read from stdout!");
    }
    fn write<'a>(&'a self, buf: &'a [u8]) -> usize {
        // for buffer in user_buf.buffers.iter() {
        //     print!("{}", core::str::from_utf8(*buffer).unwrap());
        // }
        unsafe {
            print!("{}", core::str::from_utf8_unchecked(buf));
        }
        buf.len()
    }
    fn seek(&self, _offset: isize, _whence: Whence) -> SyscallRet {
        panic!("Cannot seek stdin!");
    }
    fn get_offset(&self) -> usize {
        panic!("Cannot get offset from stdout!");
    }
    fn readable(&self) -> bool {
        false
    }
    fn writable(&self) -> bool {
        true
    }
}

impl FileOld for Stdin {
    fn readable(&self) -> bool {
        true
    }
    fn writable(&self) -> bool {
        false
    }
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> usize {
        assert_eq!(buf.len(), 1);
        // busy loop
        let mut c: usize;
        loop {
            c = console_getchar();
            // opensbi returns usize::MAX if no char available
            if c == usize::MAX {
                yield_current_task();
                continue;
            } else {
                break;
            }
        }
        let ch = c as u8;
        unsafe {
            // buf.buffers[0].as_mut_ptr().write_volatile(ch);
            buf.as_mut_ptr().write_volatile(ch);
        }
        1
    }
    fn write(&self, _buf: &[u8]) -> usize {
        panic!("Cannot write to stdin!");
    }
    fn get_meta(&self) -> FileMeta {
        FileMeta::new(None, 0)
    }
    fn seek(&self, _offset: usize) {
        panic!("Cannot seek stdin!");
    }
}

impl FileOld for Stdout {
    fn readable(&self) -> bool {
        false
    }
    fn writable(&self) -> bool {
        true
    }
    fn read(&self, _buf: &mut [u8]) -> usize {
        panic!("Cannot read from stdout!");
    }
    fn write<'a>(&'a self, buf: &'a [u8]) -> usize {
        // for buffer in user_buf.buffers.iter() {
        //     print!("{}", core::str::from_utf8(*buffer).unwrap());
        // }
        print!("{}", core::str::from_utf8(buf).unwrap());
        buf.len()
    }
    fn get_meta(&self) -> FileMeta {
        FileMeta::new(None, 0)
    }
    fn seek(&self, _offset: usize) {
        panic!("Cannot seek stdout!");
    }
}

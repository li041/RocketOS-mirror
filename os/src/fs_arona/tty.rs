use alloc::{boxed::Box, sync::Arc};
// use core::str::Utf8Error;
use lazy_static::lazy_static;
// use log::trace;
// use log::debug;

use crate::{
    mutex::SpinNoIrqLock, sbi::console_getchar, task::yield_task, utils::SyscallErr, AsyncResult,
    SyscallRet,
};

use super::{File, FileMeta};

lazy_static! {
    // pub static ref TTY: Arc<SpinNoIrqLock<TtyFile>> = Arc::new(SpinNoIrqLock::new(TtyFile::new()));
    pub static ref TTY: Arc<TtyFile> = Arc::new(TtyFile::new(true, true));
}

pub struct TtyFile {
    // tty_inode: Arc<dyn Inode>,
    meta: FileMeta,
    inner: SpinNoIrqLock<TtyInner>,
}

struct TtyInner {
    fg_pgid: u32,
    win_size: WinSize,
    termios: Termios,
}

impl TtyFile {
    // pub fn new(tty_inode: Arc<dyn Inode>) -> Self {
    pub fn new(readable: bool, writable: bool) -> Self {
        Self {
            // tty_inode,
            meta: FileMeta::new_bare(readable, writable, super::OSFileType::TTY),
            inner: SpinNoIrqLock::new(TtyInner {
                fg_pgid: 0,
                win_size: WinSize::new(),
                termios: Termios::new(),
            }),
        }
    }
}

impl File for TtyFile {
    /// Read file to `UserBuffer`, return `Err(EBADF)` if not readable
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> AsyncResult<usize> {
        Box::pin(async move {
            if !self.meta.readable {
                return Err(SyscallErr::EBADF.into());
            }
            // assert_eq!(buf.len(), 1);
            // busy loop
            let mut c: usize;
            loop {
                c = console_getchar();
                // opensbi returns usize::MAX if no char available
                if c == usize::MAX {
                    yield_task().await;
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
            Ok(1)
        })
    }
    /// Write `UserBuffer` to file, return `Err(EBADF)` if not writable
    fn write<'a>(&'a self, buf: &'a [u8]) -> AsyncResult<usize> {
        Box::pin(async move {
            if !self.meta.writable {
                return Err(SyscallErr::EBADF.into());
            }
            print!("{}", core::str::from_utf8(buf).unwrap_or("<invalid utf8>"));
            Ok(buf.len())
        })
    }

    fn get_meta(&self) -> &FileMeta {
        &self.meta
    }

    /// set offset to `offset`, return the offset **BEFORE SEEK**, which differs from `linux lseek`.
    /// return `None` if the file is not seekable
    fn seek(&self, _offset: usize) -> Option<usize> {
        None
    }

    fn ioctl(&self, request: usize, argp: usize) -> SyscallRet {
        log::info!("[TtyFile::ioctl] request {:#x}, argp {:#x}", request, argp);
        match request {
            TCGETS | TCGETA => {
                // let _sum_guard = SumGuard::new();
                // UserCheck::new()
                //     .check_writable_slice(value as *mut u8, core::mem::size_of::<Termios>())?;
                unsafe {
                    // (value as *mut Termios).copy_from(&self.inner.lock().termios as *const Termios, 1);
                    *(argp as *mut Termios) = self.inner.lock().termios;
                }
                Ok(0)
            }
            TCSETS | TCSETSW | TCSETSF => {
                // let _sum_guard = SumGuard::new();
                // UserCheck::new()
                //     .check_readable_slice(value as *const u8, core::mem::size_of::<Termios>())?;
                unsafe {
                    self.inner.lock().termios = *(argp as *const Termios);
                }
                Ok(0)
            }
            TIOCGPGRP => {
                // let _sum_guard = SumGuard::new();
                // UserCheck::new()
                //     .check_writable_slice(value as *mut u8, core::mem::size_of::<Pid>())?;
                unsafe {
                    *(argp as *mut u32) = self.inner.lock().fg_pgid;
                    log::info!("[TtyFile::ioctl] get fg pgid {}", *(argp as *const u32));
                }
                Ok(0)
            }
            TIOCSPGRP => {
                // let _sum_guard = SumGuard::new();
                // UserCheck::new()
                //     .check_readable_slice(value as *const u8, core::mem::size_of::<Pid>())?;
                unsafe {
                    log::info!("[TtyFile::ioctl] set fg pgid {}", *(argp as *const u32));
                    self.inner.lock().fg_pgid = *(argp as *const u32);
                }
                Ok(0)
            }
            TIOCGWINSZ => {
                // let _sum_guard = SumGuard::new();
                // UserCheck::new()
                //     .check_writable_slice(value as *mut u8, core::mem::size_of::<WinSize>())?;
                unsafe {
                    *(argp as *mut WinSize) = self.inner.lock().win_size;
                }
                Ok(0)
            }
            TIOCSWINSZ => {
                // let _sum_guard = SumGuard::new();
                // UserCheck::new()
                //     .check_readable_slice(value as *const u8, core::mem::size_of::<WinSize>())?;
                unsafe {
                    self.inner.lock().win_size = *(argp as *const WinSize);
                }
                Ok(0)
            }
            TCSBRK => Ok(0),
            _ => unimplemented!(),
        }
    }
}

/// Gets the current serial port settings.
const TCGETS: usize = 0x5401;
/// Sets the serial port settings immediately.
const TCSETS: usize = 0x5402;
/// Get the process group ID of the foreground process group on this terminal.
/// Sets the serial port settings after allowing the input and output buffers to drain/empty.
const TCSETSW: usize = 0x5403;
/// Sets the serial port settings after flushing the input and output buffers.
const TCSETSF: usize = 0x5404;
/// For struct termio
/// Gets the current serial port settings.
const TCGETA: usize = 0x5405;
/// Sets the serial port settings immediately.
// #[allow(unused)]
// const TCSETA: usize = 0x5406;
/// Sets the serial port settings after allowing the input and output buffers to drain/empty.
// #[allow(unused)]
// const TCSETAW: usize = 0x5407;
/// Sets the serial port settings after flushing the input and output buffers.
// #[allow(unused)]
// const TCSETAF: usize = 0x5408;
/// If the terminal is using asynchronous serial data transmission, and arg is zero, then send a break (a stream of zero bits) for between 0.25 and 0.5 seconds.
const TCSBRK: usize = 0x5409;
/// Get the process group ID of the foreground process group on this terminal.
const TIOCGPGRP: usize = 0x540F;
/// Set the foreground process group ID of this terminal.
const TIOCSPGRP: usize = 0x5410;
/// Get window size.
const TIOCGWINSZ: usize = 0x5413;
/// Set window size.
const TIOCSWINSZ: usize = 0x5414;

#[repr(C)]
#[derive(Clone, Copy)]
struct WinSize {
    ws_row: u16,
    ws_col: u16,
    xpixel: u16,
    ypixel: u16,
}

impl WinSize {
    fn new() -> Self {
        // stack_trace!();
        Self {
            // ws_row: 67,
            // ws_col: 270,
            ws_row: 67,
            ws_col: 120,
            xpixel: 0,
            ypixel: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Termios {
    /// Input modes
    pub iflag: u32,
    /// Ouput modes
    pub oflag: u32,
    /// Control modes
    pub cflag: u32,
    /// Local modes
    pub lflag: u32,
    pub line: u8,
    /// Terminal special characters.
    pub cc: [u8; 19],
    // pub cc: [u8; 32],
    // pub ispeed: u32,
    // pub ospeed: u32,
}

impl Termios {
    fn new() -> Self {
        // stack_trace!();
        Self {
            // IMAXBEL | IUTF8 | IXON | IXANY | ICRNL | BRKINT
            iflag: 0o66402,
            // OPOST | ONLCR
            oflag: 0o5,
            // HUPCL | CREAD | CSIZE | EXTB
            cflag: 0o2277,
            // IEXTEN | ECHOTCL | ECHOKE ECHO | ECHOE | ECHOK | ISIG | ICANON
            lflag: 0o105073,
            line: 0,
            cc: [
                3,   // VINTR Ctrl-C
                28,  // VQUIT
                127, // VERASE
                21,  // VKILL
                4,   // VEOF Ctrl-D
                0,   // VTIME
                1,   // VMIN
                0,   // VSWTC
                17,  // VSTART
                19,  // VSTOP
                26,  // VSUSP Ctrl-Z
                255, // VEOL
                18,  // VREPAINT
                15,  // VDISCARD
                23,  // VWERASE
                22,  // VLNEXT
                255, // VEOL2
                0, 0,
            ],
            // ispeed: 0,
            // ospeed: 0,
        }
    }
}

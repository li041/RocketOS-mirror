use core::{any::Any, u8};
use spin::Once;

use alloc::{sync::Arc, sync::Weak};
use bitflags::Flag;
use spin::RwLock;

use crate::{
    arch::{
        mm::{copy_from_user, copy_to_user},
        sbi::console_getchar,
    },
    drivers::block::block_dev::BlockDevice,
    ext4::{
        dentry,
        fs::Ext4FileSystem,
        inode::{Ext4InodeDisk, S_IFCHR},
    },
    fs::{
        dentry::Dentry,
        file::{FileOp, OpenFlags},
        inode::InodeOp,
        kstat::Kstat,
        path::Path,
        uapi::DevT,
    },
    syscall::errno::{Errno, SyscallRet},
    task::{yield_current_task, Tid},
    timer::TimeSpec,
};

pub static TTY: Once<Arc<dyn FileOp>> = Once::new();

pub struct TtyInode {
    pub inode_num: usize,
    pub inner: RwLock<TTyInodeInner>,
}
pub struct TTyInodeInner {
    pub inode_on_disk: Ext4InodeDisk,
}

impl TTyInodeInner {
    pub fn new(inode_on_disk: Ext4InodeDisk) -> Self {
        TTyInodeInner { inode_on_disk }
    }
}

impl TtyInode {
    pub fn new(ino: usize, inode_mode: u16, major: u32, minor: u32) -> Arc<Self> {
        assert!(inode_mode & S_IFCHR == S_IFCHR);
        let inner = TTyInodeInner::new(Ext4InodeDisk::new_chr(inode_mode, major, minor));
        Arc::new(TtyInode {
            inode_num: ino,
            inner: RwLock::new(inner),
        })
    }
}

impl InodeOp for TtyInode {
    fn getattr(&self) -> Kstat {
        let mut kstat = Kstat::new();
        let inner_guard = self.inner.read();
        let inode_on_disk = &inner_guard.inode_on_disk;
        kstat.ino = self.inode_num as u64;
        kstat.dev = 0;
        let (major, minor) = inode_on_disk.get_devt();
        let devt = DevT::makedev(major, minor);
        kstat.rdev = u64::from(devt); // 通常特殊文件才会有 rdev

        kstat.mode = inode_on_disk.get_mode();
        kstat.uid = inode_on_disk.get_uid() as u32;
        kstat.gid = inode_on_disk.get_gid() as u32;
        kstat.nlink = inode_on_disk.get_nlinks() as u32;
        kstat.size = inode_on_disk.get_size();

        // Todo: 目前没有更新时间戳
        kstat.atime = inode_on_disk.get_atime();
        kstat.mtime = inode_on_disk.get_mtime();
        kstat.ctime = inode_on_disk.get_ctime();
        // Todo: 创建时间
        // kstat.btime = TimeSpec {
        //     sec: inode_on_disk.create_time as usize,
        //     nsec: (inode_on_disk.create_time_extra >> 2) as usize,
        // };
        // Todo: Direct I/O 对齐参数
        // inode版本号
        kstat.change_cookie = inode_on_disk.generation as u64;

        kstat
    }
    /* get/set属性方法 */
    // Todo
    fn get_devt(&self) -> (u32, u32) {
        self.inner.read().inode_on_disk.get_devt()
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

#[repr(usize)]
#[derive(Debug, Clone, Copy)]
enum TtyIoctlCmd {
    // For struct termios
    /// Gets the current serial port settings.
    TCGETS = 0x5401,
    /// Sets the serial port settings immediately.
    TCSETS = 0x5402,
    /// Sets the serial port settings after allowing the input and output
    /// buffers to drain/empty.
    TCSETSW = 0x5403,
    /// Sets the serial port settings after flushing the input and output
    /// buffers.
    TCSETSF = 0x5404,
    /// For struct termio
    /// Gets the current serial port settings.
    TCGETA = 0x5405,
    /// Sets the serial port settings immediately.
    #[allow(unused)]
    TCSETA = 0x5406,
    /// Sets the serial port settings after allowing the input and output
    /// buffers to drain/empty.
    #[allow(unused)]
    TCSETAW = 0x5407,
    /// Sets the serial port settings after flushing the input and output
    /// buffers.
    #[allow(unused)]
    TCSETAF = 0x5408,
    /// If the terminal is using asynchronous serial data transmission, and arg
    /// is zero, then send a break (a stream of zero bits) for between 0.25
    /// and 0.5 seconds.
    TCSBRK = 0x5409,
    /// Get the process group ID of the foreground process group on this
    /// terminal.
    TIOCGPGRP = 0x540F,
    /// Set the foreground process group ID of this terminal.
    TIOCSPGRP = 0x5410,
    /// Get window size.
    TIOCGWINSZ = 0x5413,
    /// Set window size.
    TIOCSWINSZ = 0x5414,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct WinSize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16, // Unused
    ws_ypixel: u16, // Unused
}

impl WinSize {
    fn new() -> Self {
        Self {
            ws_row: 67,
            ws_col: 120,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }
    }
}

/// Defined in <asm-generic/termbits.h>
#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct Termios {
    /// Input mode flags.
    pub iflag: u32,
    /// Output mode flags.
    pub oflag: u32,
    /// Control mode flags.
    pub cflag: u32,
    /// Local mode flags.
    pub lflag: u32,
    /// Line discipline.
    pub line: u8,
    /// control characters.
    pub cc: [u8; 19],
}

impl Termios {
    fn new() -> Self {
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
        }
    }

    fn is_icrnl(&self) -> bool {
        const ICRNL: u32 = 0o0000400;
        self.iflag & ICRNL != 0
    }

    fn is_echo(&self) -> bool {
        const ECHO: u32 = 0o0000010;
        self.lflag & ECHO != 0
    }
}

pub struct TtyFile {
    pub path: Arc<Path>,
    pub inode: Arc<dyn InodeOp>,
    pub flags: OpenFlags,
    pub inner: RwLock<TtyFileInner>,
}

struct TtyFileInner {
    fg_pgid: Tid,
    win_size: WinSize,
    termios: Termios,
    last_char: u8,
}

impl TtyFile {
    pub fn new(path: Arc<Path>, inode: Arc<dyn InodeOp>, flags: OpenFlags) -> Arc<Self> {
        Arc::new(Self {
            path,
            inode,
            flags,
            inner: RwLock::new(TtyFileInner {
                fg_pgid: 1,
                win_size: WinSize::new(),
                termios: Termios::new(),
                last_char: u8::MAX,
            }),
        })
    }
}

impl FileOp for TtyFile {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> SyscallRet {
        // let mut c: usize;
        let mut inner = self.inner.write();
        loop {
            inner.last_char = console_getchar() as u8;
            // opensbi returns usize::MAX if no char available
            if inner.last_char == u8::MAX {
                yield_current_task();
                continue;
            } else {
                break;
            }
        }
        let ch = inner.last_char as u8;
        drop(inner);
        unsafe {
            buf.as_mut_ptr().write_volatile(ch);
        }
        Ok(1)
    }
    // #[cfg(target_arch = "riscv64")]
    fn write<'a>(&'a self, buf: &'a [u8]) -> SyscallRet {
        let mut _inner = self.inner.write();
        // print!("{}", core::str::from_utf8(buf).unwrap());
        print!("{}", core::str::from_utf8(buf).unwrap());
        Ok(buf.len())
    }
    fn seek(&self, _offset: isize, _whence: crate::fs::uapi::Whence) -> SyscallRet {
        Err(Errno::ESPIPE)
    }
    fn ioctl(&self, op: usize, arg_ptr: usize) -> SyscallRet {
        log::info!("[TtyFile::ioctl] op: {:#x}, arg_ptr: {:#x}", op, arg_ptr);
        let op: TtyIoctlCmd = unsafe { core::mem::transmute(op) };
        match op {
            TtyIoctlCmd::TCGETS | TtyIoctlCmd::TCGETA => {
                match copy_to_user(arg_ptr as *mut Termios, &(self.inner.read().termios), 1) {
                    Ok(_) => Ok(0),
                    Err(_) => {
                        log::error!("[TtyFile::ioctl] copy_to_user failed");
                        return Err(Errno::EINVAL);
                    }
                }
            }
            TtyIoctlCmd::TCSETS | TtyIoctlCmd::TCSETSW | TtyIoctlCmd::TCSETSF => {
                let mut termios = Termios::new();
                match copy_from_user(arg_ptr as *const Termios, &mut termios as *mut Termios, 1) {
                    Ok(_) => {
                        self.inner.write().termios = termios;
                        Ok(0)
                    }
                    Err(_) => {
                        log::error!("[TtyFile::ioctl] copy_from_user failed");
                        return Err(Errno::EINVAL);
                    }
                }
            }
            TtyIoctlCmd::TIOCGPGRP => {
                let fd_pgid = self.inner.read().fg_pgid;
                match copy_to_user(arg_ptr as *mut Tid, &fd_pgid, 1) {
                    Ok(_) => Ok(0),
                    Err(_) => {
                        log::error!("[TtyFile::ioctl] copy_to_user failed");
                        return Err(Errno::EINVAL);
                    }
                }
            }
            TtyIoctlCmd::TIOCSPGRP => {
                let mut pgid: Tid = 0;
                copy_from_user(arg_ptr as *const Tid, &mut pgid as *mut Tid, 1)?;
                self.inner.write().fg_pgid = pgid;
                Ok(0)
            }
            TtyIoctlCmd::TIOCGWINSZ => {
                let win_size = self.inner.read().win_size;
                copy_to_user(arg_ptr as *mut WinSize, &win_size, 1)?;
                Ok(0)
            }
            TtyIoctlCmd::TIOCSWINSZ => {
                let mut win_size = WinSize::new();
                copy_from_user(arg_ptr as *const WinSize, &mut win_size as *mut WinSize, 1)?;
                self.inner.write().win_size = win_size;
                Ok(0)
            }
            TtyIoctlCmd::TCSBRK => Ok(0),
            _ => {
                panic!("[TtyFile::ioctl] Unsupported ioctl cmd: {:?}", op);
            }
        }
    }
    fn get_inode(&self) -> Arc<dyn InodeOp> {
        self.inode.clone()
    }
    fn readable(&self) -> bool {
        // 终端设备总是可读的
        true
    }
    fn writable(&self) -> bool {
        // 终端设备总是可写的
        true
    }
    fn hang_up(&self) -> bool {
        false
    }
    fn r_ready(&self) -> bool {
        let mut inner = self.inner.write();
        if inner.last_char != u8::MAX {
            return true;
        } else {
            // 尝试读取下一个字符
            inner.last_char = console_getchar() as u8;
            inner.last_char != u8::MAX
        }
    }
    fn w_ready(&self) -> bool {
        true
    }
    fn get_flags(&self) -> OpenFlags {
        self.flags
    }
}

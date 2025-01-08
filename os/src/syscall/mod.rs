//! Implementation of syscalls
//!
//! The single entry point to all system calls, [`syscall()`], is called
//! whenever userspace wishes to perform a system call using the `ecall`
//! instruction. In this case, the processor raises an 'Environment call from
//! U-mode' exception, which is handled as one of the cases in
//! [`crate::trap::trap_handler`].
//!
//! For clarity, each single syscall is implemented as its own function, named
//! `sys_` then the name of the syscall. You can find functions like this in
//! submodules, and you should also implement syscalls this way.

use fs::{
    sys_chdir, sys_close, sys_dup, sys_dup3, sys_fstat, sys_getcwd, sys_getdents64, sys_mkdirat,
    sys_mount, sys_openat, sys_pipe2, sys_read, sys_umount2, sys_unlinkat, sys_write,
};
use mm::{sys_brk, sys_mmap, sys_munmap};
use util::{sys_times, sys_uname};

use crate::task::{
    sys_clone, sys_execve, sys_exit, sys_get_time, sys_getpid, sys_getppid, sys_nanosleep,
    sys_waitpid, sys_yield,
};

mod fs;
mod mm;
mod util;

const SYSCALL_GETCWD: usize = 17;
const SYSCALL_DUP: usize = 23;
const SYSCALL_DUP3: usize = 24;
const SYSCALL_MKDIRAT: usize = 34;
const SYSCALL_UNLINKAT: usize = 35;
const SYSCALL_UMOUNT2: usize = 39;
const SYSCALL_MOUNT: usize = 40;
const SYSCALL_CHDIR: usize = 49;
const SYSCALL_OPENAT: usize = 56;
const SYSCALL_CLOSE: usize = 57;
const SYSCALL_PIPE2: usize = 59;
const SYSCALL_GETDENTS64: usize = 61;
const SYSCALL_READ: usize = 63;
const SYSCALL_WRITE: usize = 64;
const SYS_FSTAT: usize = 80;
const SYSCALL_EXIT: usize = 93;
const SYSCALL_NANOSLEEP: usize = 101;
const SYSCALL_YIELD: usize = 124;
const SYSCALL_TIMES: usize = 153;
const SYSCALL_UNAME: usize = 160;
const SYSCALL_GET_TIME: usize = 169;
const SYSCALL_GITPID: usize = 172;
const SYSCALL_GETPPID: usize = 173;
const SYSCALL_BRK: usize = 214;
const SYSCALL_MUNMAP: usize = 215;
const SYSCALL_FORK: usize = 220;
const SYSCALL_EXEC: usize = 221;
const SYSCALL_MMAP: usize = 222;
const SYSCALL_WAIT4: usize = 260;

const CARELESS_SYSCALLS: [usize; 4] = [63, 64, 124, 260];

#[no_mangle]
pub fn syscall(
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    _a6: usize,
    syscall_id: usize,
) -> isize {
    if !CARELESS_SYSCALLS.contains(&syscall_id) {
        log::info!("syscall_id: {}", syscall_id);
    }
    // if syscall_id == SYSCALL_WAIT4 {
    // log::warn!("syscall_id: {}", syscall_id);
    // }
    match syscall_id {
        SYSCALL_GETCWD => sys_getcwd(a0 as *mut u8, a1),
        SYSCALL_DUP => sys_dup(a0),
        SYSCALL_DUP3 => sys_dup3(a0, a1),
        SYSCALL_MKDIRAT => sys_mkdirat(a0 as isize, a1 as *const u8, a2),
        SYSCALL_UNLINKAT => sys_unlinkat(a0 as isize, a1 as *const u8, a2 as u32),
        SYSCALL_UMOUNT2 => sys_umount2(),
        SYSCALL_MOUNT => sys_mount(),
        SYSCALL_CHDIR => sys_chdir(a0 as *const u8),
        SYSCALL_OPENAT => sys_openat(a0 as isize, a1 as *const u8, a2 as u32, a3),
        SYSCALL_CLOSE => sys_close(a0),
        SYSCALL_PIPE2 => sys_pipe2(a0 as *mut u8),
        SYSCALL_GETDENTS64 => sys_getdents64(a0, a1 as *mut u8, a2),
        SYSCALL_READ => sys_read(a0, a1 as *mut u8, a2),
        SYSCALL_WRITE => sys_write(a0, a1 as *const u8, a2),
        SYS_FSTAT => sys_fstat(a0, a1 as *mut u8),
        SYSCALL_EXIT => sys_exit(a0 as i32),
        SYSCALL_NANOSLEEP => sys_nanosleep(a0),
        SYSCALL_YIELD => sys_yield(),
        SYSCALL_TIMES => sys_times(a0),
        SYSCALL_UNAME => sys_uname(a0),
        SYSCALL_GET_TIME => sys_get_time(a0),
        SYSCALL_GITPID => sys_getpid(),
        SYSCALL_GETPPID => sys_getppid(),
        SYSCALL_BRK => sys_brk(a0),
        SYSCALL_MUNMAP => sys_munmap(a0, a1),
        SYSCALL_FORK => sys_clone(a0 as u32, a1, a2, a3, a4),
        SYSCALL_EXEC => sys_execve(a0 as *mut u8, a1 as *const usize, a2 as *const usize),
        SYSCALL_MMAP => sys_mmap(a0, a1, a2, a3, a4 as i32, a5),
        // SYSCALL_WAIT4 => sys_waitpid(a0 as isize, a1 as *mut i32),
        SYSCALL_WAIT4 => sys_waitpid(a0 as isize, a1, a2 as i32),
        _ => panic!("Unsupported syscall_id: {}", syscall_id),
    }
}

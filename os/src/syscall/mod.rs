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

use errno::{Errno, SyscallRet};
use fs::{
    sys_chdir, sys_close, sys_dup, sys_dup3, sys_faccessat, sys_fchmodat, sys_fchownat, sys_fcntl,
    sys_fstat, sys_fstatat, sys_fsync, sys_ftruncate, sys_getcwd, sys_getdents64, sys_ioctl,
    sys_linkat, sys_lseek, sys_mkdirat, sys_mknodat, sys_mount, sys_openat, sys_pipe2, sys_ppoll,
    sys_pread, sys_pwrite, sys_read, sys_readv, sys_renameat2, sys_sendfile, sys_statfs, sys_statx,
    sys_sync, sys_umount2, sys_unlinkat, sys_utimensat, sys_write, sys_writev,
};
use mm::{
    sys_brk, sys_madvise, sys_mmap, sys_mprotect, sys_munmap, sys_shmat, sys_shmctl, sys_shmdt,
    sys_shmget,
};
use signal::{
    sys_kill, sys_rt_sigaction, sys_rt_sigpending, sys_rt_sigprocmask, sys_rt_sigreturn,
    sys_rt_sigsuspend, sys_rt_sigtimedwait, sys_tgkill, sys_tkill,
};
use task::{
    sys_clock_nansleep, sys_clone, sys_execve, sys_exit_group, sys_futex, sys_get_time,
    sys_getegid, sys_geteuid, sys_getgid, sys_getpid, sys_getppid, sys_gettid, sys_getuid,
    sys_nanosleep, sys_set_tid_address, sys_setpgid, sys_waitpid, sys_yield,
};
use util::{sys_clock_gettime, sys_prlimit64, sys_setitimer, sys_syslog, sys_times, sys_uname};

use crate::{
    fs::{
        kstat::{Stat, Statx},
        uapi::{IoVec, PollFd, RLimit, StatFs},
    },
    futex::robust_list::{sys_get_robust_list, sys_set_robust_list},
    mm::shm::ShmId,
    signal::{SigInfo, SigSet},
    timer::{ITimerVal, TimeSpec},
};
pub use fs::FcntlOp;
pub use task::sys_exit;
pub mod errno;
mod fs;
mod mm;
mod signal;
mod task;
mod util;

const SYSCALL_GETCWD: usize = 17;
const SYSCALL_DUP: usize = 23;
const SYSCALL_DUP3: usize = 24;
const SYSCALL_FCNTL: usize = 25;
const SYSCALL_IOCTL: usize = 29;
const SYSCALL_MKNODAT: usize = 33;
const SYSCALL_MKDIRAT: usize = 34;
const SYSCALL_UNLINKAT: usize = 35;
const SYSCALL_LINKAT: usize = 37;
const SYSCALL_UMOUNT2: usize = 39;
const SYSCALL_MOUNT: usize = 40;
const SYSCALL_STATFS: usize = 43;
const SYSCALL_FTRUNCATE: usize = 46;
const SYSCALL_FACCESSAT: usize = 48;
const SYSCALL_CHDIR: usize = 49;
const SYSCALL_FCHMODAT: usize = 53;
const SYSCALL_FCHOWNAT: usize = 54;
const SYSCALL_OPENAT: usize = 56;
const SYSCALL_CLOSE: usize = 57;
const SYSCALL_PIPE2: usize = 59;
const SYSCALL_GETDENTS64: usize = 61;
const SYSCALL_LSEEK: usize = 62;
const SYSCALL_READ: usize = 63;
const SYSCALL_WRITE: usize = 64;
const SYSCALL_READV: usize = 65;
const SYSCALL_WRITEV: usize = 66;
const SYSCALL_PREAD: usize = 67;
const SYSCALL_PWRITE: usize = 68;
const SYSCALL_SENDFILE: usize = 71;
const SYSCALL_PSELECT6: usize = 72;
const SYSCALL_PPOLL: usize = 73;
const SYSCALL_FSTATAT: usize = 79;
const SYSCALL_FSTAT: usize = 80;
const SYSCALL_SYNC: usize = 81;
const SYSCALL_FSYNC: usize = 82;
const SYSCALL_UTIMENSAT: usize = 88;
const SYSCALL_EXIT: usize = 93;
const SYSCALL_EXIT_GROUP: usize = 94;
const SYSCALL_SET_TID_ADDRESS: usize = 96;
const SYSCALL_FUTEX: usize = 98;
const SYSCALL_SET_ROBUST_LIST: usize = 99;
const SYSCALL_GET_ROBUST_LIST: usize = 100;
const SYSCALL_NANOSLEEP: usize = 101;
const SYSCALL_SETITIMER: usize = 103;
const SYSCALL_CLOCK_GETTIME: usize = 113;
const SYSCALL_CLOCK_NANOSLEEP: usize = 115;
const SYSCALL_SYSLOG: usize = 116;
const SYSCALL_YIELD: usize = 124;
const SYSCALL_KILL: usize = 129;
const SYSCALL_TKILL: usize = 130;
const SYSCALL_TGKILL: usize = 131;
const SYSCALL_SIGALTSTACK: usize = 132;
const SYSCALL_RT_SIGSUSPEND: usize = 133;
const SYSCALL_RT_SIGACTION: usize = 134;
const SYSCALL_RT_SIGPROCMASK: usize = 135;
const SYSCALL_RT_SIGPENDING: usize = 136;
const SYSCALL_RT_SIGTIMEDWAIT: usize = 137;
const SYSCALL_RT_SIGQUEUEINFO: usize = 138;
const SYSCALL_RT_SIGRETURN: usize = 139;
const SYSCALL_SETGID: usize = 144;
const SYSCALL_SETUID: usize = 146;
const SYSCALL_TIMES: usize = 153;
const SYSCALL_SETPGID: usize = 154;
const SYSCALL_UNAME: usize = 160;
const SYSCALL_GETRUSAGE: usize = 165;
const SYSCALL_GET_TIME: usize = 169;
const SYSCALL_GITPID: usize = 172;
const SYSCALL_GETPPID: usize = 173;
const SYSCALL_GETUID: usize = 174;
const SYSCALL_GETEUID: usize = 175;
const SYSCALL_GETGID: usize = 176;
const SYSCALL_GETEGID: usize = 177;
const SYSCALL_GETTID: usize = 178;
const SYCALL_SHMGET: usize = 194;
const SYSCALL_SHMCTL: usize = 195;
const SYSCALL_SHMAT: usize = 196;
const SYSCALL_SHMDT: usize = 197;
const SYSCALL_BRK: usize = 214;
const SYSCALL_MUNMAP: usize = 215;
const SYSCALL_FORK: usize = 220;
const SYSCALL_EXEC: usize = 221;
const SYSCALL_MMAP: usize = 222;
const SYSCALL_MADVISE: usize = 233;
const SYSCALL_MPROTECT: usize = 226;
const SYSCALL_WAIT4: usize = 260;
const SYSCALL_PRLIMIT: usize = 261;
const SYSCALL_RENAMEAT2: usize = 276;
const SYSCALL_GETRANDOM: usize = 278;
const SYSCALL_MEMBARRIER: usize = 283;
const SYSCALL_STATX: usize = 291;

const CARELESS_SYSCALLS: [usize; 5] = [62, 63, 64, 124, 260];
// const SYSCALL_NUM_2_NAME: [(&str, usize); 4] = [
const SYSCALL_NUM_2_NAME: [(usize, &str); 6] = [
    (SYSCALL_SETGID, "SYS_SETGID"),
    (SYSCALL_SETUID, "SYS_SETUID"),
    (SYSCALL_GETTID, "SYS_GETTID"),
    (SYSCALL_EXIT_GROUP, "SYS_EXIT_GROUP"),
    (SYSCALL_SIGALTSTACK, "SYS_SIGALTSTACK"),
    (SYSCALL_GETRANDOM, "SYS_GETRANDOM"),
];

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
) -> SyscallRet {
    // 神奇小咒语
    log::trace!("[syscall]");
    if !CARELESS_SYSCALLS.contains(&syscall_id) {
        if syscall_id != 98 {
            log::warn!("syscall_id: {}", syscall_id);
        }
    }
    // if syscall_id == SYSCALL_WAIT4 {
    // log::warn!("syscall_id: {}", syscall_id);
    // }
    match syscall_id {
        SYSCALL_GETCWD => sys_getcwd(a0 as *mut u8, a1),
        SYSCALL_DUP => sys_dup(a0),
        SYSCALL_DUP3 => sys_dup3(a0, a1, a2 as i32),
        SYSCALL_FCNTL => sys_fcntl(a0 as i32, a1 as i32, a2),
        SYSCALL_IOCTL => sys_ioctl(a0, a1, a2),
        SYSCALL_MKNODAT => sys_mknodat(a0 as i32, a1 as *const u8, a2, a3 as u64),
        SYSCALL_MKDIRAT => sys_mkdirat(a0 as isize, a1 as *const u8, a2),
        SYSCALL_UNLINKAT => sys_unlinkat(a0 as i32, a1 as *const u8, a2 as i32),
        SYSCALL_LINKAT => sys_linkat(
            a0 as i32,
            a1 as *const u8,
            a2 as i32,
            a3 as *const u8,
            a4 as i32,
        ),
        SYSCALL_UMOUNT2 => sys_umount2(a1 as *const u8, a2 as i32),
        SYSCALL_MOUNT => sys_mount(
            a0 as *const u8,
            a1 as *const u8,
            a2 as *const u8,
            a3,
            a4 as *const u8,
        ),
        SYSCALL_STATFS => sys_statfs(a0 as *const u8, a1 as *mut StatFs),
        SYSCALL_FTRUNCATE => sys_ftruncate(a0, a1),
        SYSCALL_FACCESSAT => sys_faccessat(a0 as usize, a1 as *const u8, a2 as i32, a3 as i32),
        SYSCALL_CHDIR => sys_chdir(a0 as *const u8),
        SYSCALL_FCHMODAT => sys_fchmodat(a0, a1),
        SYSCALL_FCHOWNAT => sys_fchownat(a0, a1 as *const u8, a2, a3),
        SYSCALL_OPENAT => sys_openat(a0 as i32, a1 as *const u8, a2 as i32, a3),
        SYSCALL_CLOSE => sys_close(a0),
        SYSCALL_PIPE2 => sys_pipe2(a0 as *mut i32, a1 as i32),
        SYSCALL_GETDENTS64 => sys_getdents64(a0, a1, a2),
        SYSCALL_LSEEK => sys_lseek(a0, a1 as isize, a2),
        SYSCALL_READ => sys_read(a0, a1 as *mut u8, a2),
        SYSCALL_WRITE => sys_write(a0, a1 as *const u8, a2),
        SYSCALL_READV => sys_readv(a0, a1 as *const IoVec, a2),
        SYSCALL_WRITEV => sys_writev(a0, a1 as *const IoVec, a2),
        SYSCALL_PREAD => sys_pread(a0, a1 as *mut u8, a2, a3),
        SYSCALL_PWRITE => sys_pwrite(a0, a1 as *const u8, a2, a3),
        SYSCALL_SENDFILE => sys_sendfile(a0, a1, a2 as *mut usize, a3),
        // SYSCALL_PSELECT6 => sys_pselect6(a0, a1, a2, a3, a4 as *const TimeSpec, a5),
        SYSCALL_PPOLL => sys_ppoll(a0 as *mut PollFd, a1, a2 as *const TimeSpec, a3),
        SYSCALL_FSTATAT => sys_fstatat(a0 as i32, a1 as *const u8, a2 as *mut Stat, a3 as i32),
        SYSCALL_FSTAT => sys_fstat(a0 as i32, a1 as *mut Stat),
        SYSCALL_SYNC => sys_sync(a0),
        SYSCALL_FSYNC => sys_fsync(a0),
        SYSCALL_UTIMENSAT => {
            sys_utimensat(a0 as i32, a1 as *const u8, a2 as *const TimeSpec, a3 as i32)
        }
        SYSCALL_EXIT => sys_exit(a0 as i32),
        SYSCALL_EXIT_GROUP => sys_exit_group(a0 as i32),
        SYSCALL_SET_TID_ADDRESS => sys_set_tid_address(a0),
        SYSCALL_FUTEX => sys_futex(a0, a1 as i32, a2 as u32, a3, a4, a5 as u32),
        SYSCALL_SET_ROBUST_LIST => sys_set_robust_list(a0, a1),
        SYSCALL_GET_ROBUST_LIST => sys_get_robust_list(a0, a1, a2),
        SYSCALL_NANOSLEEP => sys_nanosleep(a0),
        SYSCALL_SETITIMER => sys_setitimer(a0 as i32, a1 as *const ITimerVal, a2 as *mut ITimerVal),
        SYSCALL_CLOCK_GETTIME => sys_clock_gettime(a0, a1 as *mut TimeSpec),
        SYSCALL_CLOCK_NANOSLEEP => sys_clock_nansleep(a0, a1 as i32, a2, a3),
        SYSCALL_SYSLOG => sys_syslog(a0, a1 as *mut u8, a3),
        SYSCALL_YIELD => sys_yield(),
        SYSCALL_KILL => sys_kill(a0 as isize, a1 as i32),
        SYSCALL_TKILL => sys_tkill(a0 as isize, a1 as i32),
        SYSCALL_TGKILL => sys_tgkill(a0 as isize, a1 as isize, a2 as i32),
        // SYSCALL_SIGALTSTACK => sys_sigaltstack()
        SYSCALL_RT_SIGSUSPEND => sys_rt_sigsuspend(a0),
        SYSCALL_RT_SIGACTION => sys_rt_sigaction(a0 as i32, a1, a2),
        SYSCALL_RT_SIGPROCMASK => sys_rt_sigprocmask(a0, a1, a2),
        SYSCALL_RT_SIGPENDING => sys_rt_sigpending(a0),
        SYSCALL_RT_SIGTIMEDWAIT => sys_rt_sigtimedwait(
            a0 as *const SigSet,
            a1 as *const SigInfo,
            a2 as *const TimeSpec,
        ),
        //SYSCALL_RT_SIGQUEUEINFO => sys_rt_sigqueueinfo(),
        SYSCALL_RT_SIGRETURN => sys_rt_sigreturn(),
        SYSCALL_TIMES => sys_times(a0),
        SYSCALL_SETPGID => sys_setpgid(a0, a1),
        SYSCALL_UNAME => sys_uname(a0),
        SYSCALL_GET_TIME => sys_get_time(a0),
        SYSCALL_GITPID => sys_getpid(),
        SYSCALL_GETPPID => sys_getppid(),
        SYSCALL_GETUID => sys_getuid(),
        SYSCALL_GETEUID => sys_geteuid(),
        SYSCALL_GETGID => sys_getgid(),
        SYSCALL_GETEGID => sys_getegid(),
        SYSCALL_GETTID => sys_gettid(),
        SYCALL_SHMGET => sys_shmget(a0, a1, a2 as i32),
        SYSCALL_SHMCTL => sys_shmctl(a0, a1 as i32, a3 as *mut ShmId),
        SYSCALL_SHMAT => sys_shmat(a0, a1, a2 as i32),
        SYSCALL_SHMDT => sys_shmdt(a0),
        SYSCALL_BRK => sys_brk(a0),
        SYSCALL_MUNMAP => sys_munmap(a0, a1),
        SYSCALL_MADVISE => sys_madvise(a0, a1, a2 as i32),
        SYSCALL_MPROTECT => sys_mprotect(a0, a1, a2 as i32),
        SYSCALL_FORK => sys_clone(a0 as u32, a1, a2, a3, a4),
        SYSCALL_EXEC => sys_execve(a0 as *mut u8, a1 as *const usize, a2 as *const usize),
        SYSCALL_MMAP => sys_mmap(a0, a1, a2, a3, a4 as i32, a5),
        SYSCALL_WAIT4 => sys_waitpid(a0 as isize, a1, a2 as i32),
        SYSCALL_PRLIMIT => sys_prlimit64(a0, a1 as i32, a2 as *const RLimit, a3 as *mut RLimit),
        SYSCALL_RENAMEAT2 => sys_renameat2(
            a0 as i32,
            a1 as *const u8,
            a2 as i32,
            a3 as *const u8,
            a4 as i32,
        ),
        SYSCALL_MEMBARRIER => Ok(0),
        SYSCALL_STATX => sys_statx(
            a0 as i32,
            a1 as *const u8,
            a2 as i32,
            a3 as u32,
            a4 as *mut Statx,
        ),
        _ => {
            log::warn!(
                "Unsupported syscall_id: {}, {}",
                syscall_id,
                SYSCALL_NUM_2_NAME
                    .iter()
                    .find(|x| x.0 == syscall_id)
                    .map(|x| x.1)
                    .unwrap_or("Unknown")
            );
            Err(Errno::ENOSYS)
        }
    }
}

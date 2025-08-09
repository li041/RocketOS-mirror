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
use fs::sys_faccessat2;
pub use fs::{
    sys_chdir, sys_chroot, sys_close, sys_close_range, sys_copy_file_range, sys_dup, sys_dup3,
    sys_faccessat, sys_fadvise64, sys_fallocate, sys_fchdir, sys_fchmod, sys_fchmodat, sys_fchown,
    sys_fchownat, sys_fcntl, sys_fdatasync, sys_fgetxattr, sys_flistxattr, sys_flock,
    sys_fremovexattr, sys_fsetxattr, sys_fstat, sys_fstatat, sys_fstatfs, sys_fsync, sys_ftruncate,
    sys_getcwd, sys_getdents64, sys_getxattr, sys_ioctl, sys_lgetxattr, sys_linkat, sys_listxattr,
    sys_llistxattr, sys_lremovexattr, sys_lseek, sys_lsetxattr, sys_memfd_create, sys_mkdirat,
    sys_mknodat, sys_mount, sys_msync, sys_openat, sys_openat2, sys_pipe2, sys_ppoll, sys_pread,
    sys_preadv, sys_preadv2, sys_pselect6, sys_pwrite, sys_pwritev, sys_pwritev2, sys_read,
    sys_readlinkat, sys_readv, sys_removexattr, sys_renameat2, sys_sendfile, sys_setxattr,
    sys_splice, sys_statfs, sys_statx, sys_symlinkat, sys_sync, sys_sync_file_range, sys_tee,
    sys_truncate, sys_umask, sys_umount2, sys_unlinkat, sys_utimensat, sys_vmsplice, sys_write,
    sys_writev,
};
use mm::{
    sys_brk, sys_get_mempolicy, sys_madvise, sys_membarrier, sys_mlock, sys_mmap, sys_mprotect,
    sys_mremap, sys_munmap, sys_shmat, sys_shmctl, sys_shmdt, sys_shmget,
};
use net::{
    syscall_accept, syscall_accept4, syscall_bind, syscall_connect, syscall_getpeername,
    syscall_getsocketopt, syscall_getsockname, syscall_listen, syscall_recvfrom, syscall_recvmsg,
    syscall_send, syscall_sendmsg, syscall_setdomainname, syscall_sethostname,
    syscall_setsocketopt, syscall_shutdown, syscall_socket, syscall_socketpair,
};
use sched::{
    sys_sched_getaffinity, sys_sched_getparam, sys_sched_getscheduler, sys_sched_setaffinity,
    sys_sched_setscheduler,
};
use signal::{
    sys_kill, sys_rt_sigaction, sys_rt_sigpending, sys_rt_sigprocmask, sys_rt_sigreturn,
    sys_rt_sigsuspend, sys_rt_sigtimedwait, sys_tgkill, sys_tkill,
};
use task::{
    sys_acct, sys_clock_nanosleep, sys_clone, sys_execve, sys_exit_group, sys_futex, sys_get_time,
    sys_getegid, sys_geteuid, sys_getgid, sys_getgroups, sys_getpgid, sys_getpid, sys_getppid,
    sys_getresgid, sys_getresuid, sys_gettid, sys_getuid, sys_nanosleep, sys_set_tid_address,
    sys_setfsgid, sys_setfsuid, sys_setgid, sys_setgroups, sys_setpgid, sys_setregid,
    sys_setresgid, sys_setresuid, sys_setreuid, sys_setsid, sys_setuid, sys_waitpid, sys_yield,
};
use util::{
    sys_adjtimex, sys_bpf, sys_clock_adjtime, sys_clock_getres, sys_clock_gettime,
    sys_clock_settime, sys_getitimer, sys_getrlimit, sys_getrusage, sys_prlimit64, sys_setitimer,
    sys_setrlimit, sys_shutdown, sys_sysinfo, sys_syslog, sys_timer_create, sys_timer_delete,
    sys_timer_getoverrun, sys_timer_gettimer, sys_timer_settimer, sys_timerfd_create,
    sys_timerfd_gettime, sys_timerfd_settime, sys_times, sys_uname, SysInfo,
};

use crate::{
    fs::{
        kstat::{Stat, Statx},
        uapi::{IoVec, OpenHow, PollFd, RLimit, StatFs},
    },
    futex::robust_list::{sys_get_robust_list, sys_set_robust_list},
    mm::shm::{ShmGetFlags, ShmId},
    signal::{SigInfo, SigSet},
    syscall::{
        fs::{sys_inotify_add_watch, sys_inotify_init, sys_inotify_rm_watch}, sched::{
            sys_getpriority, sys_sched_get_priority_max, sys_sched_get_priority_min,
            sys_sched_getattr, sys_sched_rr_get_interval, sys_sched_setattr, sys_sched_setparam,
            sys_setpriority,
        }, signal::{sys_rt_sigqueueinfo, sys_sigaltstack}, task::{sys_execveat, sys_getcpu, sys_waitid}
    },
    task::rusage::RUsage,
    time::KernelTimex,
    timer::{ITimerSpec, ITimerVal, TimeSpec},
};
pub use fs::FcntlOp;
pub use fs::{AT_SYMLINK_NOFOLLOW, NAME_MAX};
pub use task::sys_exit;
pub mod errno;
mod fs;
mod mm;
mod net;
mod sched;
mod signal;
mod task;
mod util;
// mod time;

// io_*一族
const SYSCALL_SETXATTR: usize = 5;
const SYSCALL_LSETXATTR: usize = 6;
const SYSCALL_FSETXATTR: usize = 7;
const SYSCALL_GETXATTR: usize = 8;
const SYSCALL_LGETXATTR: usize = 9;
const SYSCALL_FGETXATTR: usize = 10;
const SYSCALL_LISTATTR: usize = 11;
const SYSCALL_LLISTATTR: usize = 12;
const SYSCALL_FLISTXATTR: usize = 13;
const SYSCALL_REMOVEXATTR: usize = 14;
const SYSCALL_LREMOVEXATTR: usize = 15;
const SYSCALL_FREMOVEXATTR: usize = 16;
const SYSCALL_GETCWD: usize = 17;
// epoll一族
const SYSCALL_DUP: usize = 23;
const SYSCALL_DUP3: usize = 24;
const SYSCALL_FCNTL: usize = 25;
// inotify一族
const SYSCALL_INOTIFY_INIT: usize = 26;
const SYSCALL_INOTIFY_ADD_WATCH: usize = 27;
const SYSCALL_INOTIFY_REMOVE_WATCH: usize = 28;
const SYSCALL_IOCTL: usize = 29;
// ioprio一族
const SYSCALL_FLOCK: usize = 32;
const SYSCALL_MKNODAT: usize = 33;
const SYSCALL_MKDIRAT: usize = 34;
const SYSCALL_UNLINKAT: usize = 35;
const SYSCALL_SYMLINKAT: usize = 36;
const SYSCALL_LINKAT: usize = 37;
const SYSCALL_UMOUNT2: usize = 39;
const SYSCALL_MOUNT: usize = 40;
#[allow(unused)]
const SYSCALL_PIVOT_ROOT: usize = 41;
#[allow(unused)]
const SYSCALL_NI_SYSCALL: usize = 42;
const SYSCALL_STATFS: usize = 43;
const SYSCALL_FSTATFS: usize = 44;
const SYSCALL_TRUNCATE: usize = 45;
const SYSCALL_FTRUNCATE: usize = 46;
const SYSCALL_FALLOCATE: usize = 47;
const SYSCALL_FACCESSAT: usize = 48;
const SYSCALL_CHDIR: usize = 49;
const SYSCALL_FCHDIR: usize = 50;
const SYSCALL_CHROOT: usize = 51;
const SYSCALL_FCHMOD: usize = 52;
const SYSCALL_FCHMODAT: usize = 53;
const SYSCALL_FCHOWNAT: usize = 54;
const SYSCALL_FCHOWN: usize = 55;
const SYSCALL_OPENAT: usize = 56;
const SYSCALL_CLOSE: usize = 57;
#[allow(unused)]
const SYSCALL_VHANGUP: usize = 58;
const SYSCALL_PIPE2: usize = 59;
#[allow(unused)]
const SYSCALL_QUOTACTL: usize = 60;
const SYSCALL_GETDENTS64: usize = 61;
const SYSCALL_LSEEK: usize = 62;
const SYSCALL_READ: usize = 63;
const SYSCALL_WRITE: usize = 64;
const SYSCALL_READV: usize = 65;
const SYSCALL_WRITEV: usize = 66;
const SYSCALL_PREAD: usize = 67;
const SYSCALL_PWRITE: usize = 68;
const SYSCALL_PREADV: usize = 69;
const SYSCALL_PWRITEV: usize = 70;
const SYSCALL_SENDFILE: usize = 71;
const SYSCALL_PSELECT6: usize = 72;
const SYSCALL_PPOLL: usize = 73;
#[allow(unused)]
const SYSCALL_SIGNALFD: usize = 74;
const SYSCALL_VMSPLICE: usize = 75;
const SYSCALL_SPLICE: usize = 76;
const SYSCALL_TEE: usize = 77;
const SYSCALL_READLINKAT: usize = 78;
const SYSCALL_FSTATAT: usize = 79;
const SYSCALL_FSTAT: usize = 80;
const SYSCALL_SYNC: usize = 81;
const SYSCALL_FSYNC: usize = 82;
const SYSCALL_FDATASYNC: usize = 83;
const SYSCALL_SYNC_FILE_RANGE: usize = 84;
const SYSCALL_TIMERFD_CREATE: usize = 85;
const SYSCALL_TIMERFD_SETTIME: usize = 86;
const SYSCALL_TIMERFD_GETTIME: usize = 87;
const SYSCALL_UTIMENSAT: usize = 88;
const SYSCALL_ACCT: usize = 89;
const SYSCALL_CAPGET: usize = 90;
const SYSCALL_CAPSET: usize = 91;
const SYSCALL_PERSONALITY: usize = 92;
const SYSCALL_EXIT: usize = 93;
const SYSCALL_EXIT_GROUP: usize = 94;
const SYSCALL_WAITID: usize = 95;
const SYSCALL_SET_TID_ADDRESS: usize = 96;
const SYSCALL_UNSHARE: usize = 97;
const SYSCALL_FUTEX: usize = 98;
const SYSCALL_SET_ROBUST_LIST: usize = 99;
const SYSCALL_GET_ROBUST_LIST: usize = 100;
const SYSCALL_NANOSLEEP: usize = 101;
const SYSCALL_GETITIMER: usize = 102;
const SYSCALL_SETITIMER: usize = 103;
const SYSCALL_KEXEC_LOAD: usize = 104;
const SYSCALL_INIT_MODULE: usize = 105;
const SYSCALL_DELETE_MODULE: usize = 106;
const SYSCALL_TIMER_CREATE: usize = 107;
const SYSCALL_TIMER_GETTIME: usize = 108;
const SYSCALL_TIMER_GETOVERRUN: usize = 109;
const SYSCALL_TIMER_SETTIME: usize = 110;
const SYSCALL_TIMER_DELETE: usize = 111;
const SYSCALL_CLOCK_SETTIME: usize = 112;
const SYSCALL_CLOCK_GETTIME: usize = 113;
const SYSCALL_CLOCK_GETRES: usize = 114;
const SYSCALL_CLOCK_NANOSLEEP: usize = 115;
const SYSCALL_SYSLOG: usize = 116;
const SYSCALL_PTRACE: usize = 117;
const SYSCALL_SCHED_SETPARAM: usize = 118;
const SYSCALL_SCHED_SETSCHEDULER: usize = 119;
const SYSCALL_SCHED_GETSCHEDULER: usize = 120;
const SYSCALL_SCHED_GETPARAM: usize = 121;
const SYSCALL_SCHED_SETAFFINITY: usize = 122;
const SYSCALL_SCHED_GETAFFINITY: usize = 123;
const SYSCALL_YIELD: usize = 124;
const SYSCALL_SCHED_GET_PRIORITY_MAX: usize = 125;
const SYSCALL_SCHED_GET_PRIORITY_MIN: usize = 126;
const SYSCALL_SCHED_RR_GET_INTERVAL: usize = 127;
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
const SYSCALL_SETPRIORITY: usize = 140;
const SYSCALL_GETPRIORITY: usize = 141;
const SYSCALL_REROOT: usize = 142;
const SYACALL_SETREGRID: usize = 143;
const SYSCALL_SETGID: usize = 144;
const SYSCALL_SETREUID: usize = 145;
const SYSCALL_SETUID: usize = 146;
const SYSCALL_SETRESUID: usize = 147;
const SYSCALL_GETRESUID: usize = 148;
const SYSCALL_SETRESGID: usize = 149;
const SYSCALL_GETRESGID: usize = 150;
const SYSCALL_SETFSUID: usize = 151;
const SYSCALL_SETFSGID: usize = 152;
const SYSCALL_TIMES: usize = 153;
const SYSCALL_SETPGID: usize = 154;
const SYSCALL_GETPGID: usize = 155;
const SYSCALL_GETSID: usize = 156;
const SYSCALL_SETSID: usize = 157;
const SYSCALL_GETGROUPS: usize = 158;
const SYSCALL_SETGROUPS: usize = 159;
const SYSCALL_UNAME: usize = 160;
const SYSCALL_SETHOSTNAME: usize = 161;
const SYSCALL_SETDOMAINNAME: usize = 162;
const SYSCALL_GETRLIMIT: usize = 163;
const SYSCALL_SETRLIMIT: usize = 164;
const SYSCALL_GETRUSAGE: usize = 165;
const SYSCALL_UMASK: usize = 166;
const SYSCALL_GETCPU: usize = 168;
const SYSCALL_GET_TIME: usize = 169;
const SYSCALL_SETTIMEOFDAY: usize = 170;
const SYSCALL_ADJTIMEX: usize = 171;
const SYSCALL_GITPID: usize = 172;
const SYSCALL_GETPPID: usize = 173;
const SYSCALL_GETUID: usize = 174;
const SYSCALL_GETEUID: usize = 175;
const SYSCALL_GETGID: usize = 176;
const SYSCALL_GETEGID: usize = 177;
const SYSCALL_GETTID: usize = 178;
const SYSCALL_SYSINFO: usize = 179;
// mq_*一族, ms*一族
const SYSCALL_SEMGET: usize = 190;
const SYSCALL_SEMCTL: usize = 191;
const SYSCALL_SEMTIMEDOP: usize = 192;
const SYSCALL_SEMOP: usize = 193;
const SYCALL_SHMGET: usize = 194;
const SYSCALL_SHMCTL: usize = 195;
const SYSCALL_SHMAT: usize = 196;
const SYSCALL_SHMDT: usize = 197;
const SYSCALL_SOCKET: usize = 198;
const SYSCALL_SOCKETPAIR: usize = 199;
const SYSCALL_BIND: usize = 200;
const SYSCALL_LISTEN: usize = 201;
const SYSCALL_ACCEPT: usize = 202;
const SYSCALL_CONNECT: usize = 203;
const SYSCALL_GETSOCKNAME: usize = 204;
const SYSCALL_GETPEERNAME: usize = 205;
const SYSCALL_SENDTO: usize = 206;
const SYSCALL_RECVFROM: usize = 207;
const SYSCALL_SETSOCKOPT: usize = 208;
const SYSCALL_GETSOCKOPT: usize = 209;
const SYSCALL_SHUTDOWN: usize = 210;
const SYSCALL_SENDMSG: usize = 211;
const SYSCALL_RECVMSG: usize = 212;
const SYSCALL_READAHEAD: usize = 213;
const SYSCALL_BRK: usize = 214;
const SYSCALL_MUNMAP: usize = 215;
const SYSCALL_MREMAP: usize = 216;
// key一族
const SYSCALL_FORK: usize = 220;
const SYSCALL_EXEC: usize = 221;
const SYSCALL_MMAP: usize = 222;
const SYSCALL_FADVISE64: usize = 223;
// swap一族
const SYSCALL_MPROTECT: usize = 226;
const SYSCALL_MSYNC: usize = 227;
const SYSCALL_MLOCK: usize = 228;
const SYSCALL_MUNLOCK: usize = 229;
const SYSCALL_MLOCKALL: usize = 230;
const SYSCALL_MUNLOCKALL: usize = 231;
const SYSCALL_MINCORE: usize = 232;
const SYSCALL_MADVISE: usize = 233;
const SYSCALL_REMAP_FILE_PAGES: usize = 234;
const SYSCALL_MBIND: usize = 235;
const SYSCALL_GET_MEMPOLICY: usize = 236;
const SYSCALL_ACCEPT4: usize = 242;
const SYSCALL_WAIT4: usize = 260;
const SYSCALL_PRLIMIT: usize = 261;
const SYSCALL_FANOTIFY: usize = 262;
const SYSCALL_SCHED_SETATTR: usize = 274;
const SYSCALL_SCHED_GETATTR: usize = 275;
const SYSCALL_RENAMEAT2: usize = 276;
const SYSCALL_GETRANDOM: usize = 278;
const SYSCALL_MEMFD_CREATE: usize = 279;
const SYSCALL_BPF: usize = 280;
const SYSCALL_EXECVEAT: usize = 281;
const SYSCALL_MEMBARRIER: usize = 283;
const SYSCALL_COPY_FILE_RANGE: usize = 285;
const SYSCALL_PREADV2: usize = 286;
const SYSCALL_PWRITEV2: usize = 287;
const SYSCALL_STATX: usize = 291;
const SYSCALL_STRERROR: usize = 300;
const SYSCALL_PERROR: usize = 301;
const SYSCALL_CLOCKADJTIME: usize = 266;
const SYSCALL_FSOPEN: usize = 430;
const SYSCALL_CLOSE_RANGE: usize = 436;
const SYSCALL_OPENAT2: usize = 437;
const SYSCALL_FACCESSAT2: usize = 439;
const SYSCALL_SHUTDOMN: usize = 666;

const CARELESS_SYSCALLS: [usize; 9] = [62, 63, 64, 72, 113, 124, 129, 165, 260];
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
        log::warn!("syscall_id: {}", syscall_id);
    }
    // if syscall_id == SYSCALL_WAIT4 {
    // log::warn!("syscall_id: {}", syscall_id);
    // }
    // log::error!("syscall_id: {}", syscall_id);
    match syscall_id {
        SYSCALL_SETXATTR => sys_setxattr(
            a0 as *const u8,
            a1 as *const u8,
            a2 as *const u8,
            a3,
            a4 as i32,
        ),
        SYSCALL_LSETXATTR => sys_lsetxattr(
            a0 as *const u8,
            a1 as *const u8,
            a2 as *const u8,
            a3,
            a4 as i32,
        ),
        SYSCALL_FSETXATTR => sys_fsetxattr(a0, a1 as *const u8, a2 as *const u8, a3, a4 as i32),
        SYSCALL_GETXATTR => sys_getxattr(a0 as *const u8, a1 as *const u8, a2 as *mut u8, a3),
        SYSCALL_LGETXATTR => sys_lgetxattr(a0 as *const u8, a1 as *const u8, a2 as *mut u8, a3),
        SYSCALL_FGETXATTR => sys_fgetxattr(a0, a1 as *const u8, a2 as *mut u8, a3),
        SYSCALL_LISTATTR => sys_listxattr(a0 as *const u8, a1 as *mut u8, a2),
        SYSCALL_LLISTATTR => sys_llistxattr(a0 as *const u8, a1 as *mut u8, a2),
        SYSCALL_FLISTXATTR => sys_flistxattr(a0, a1 as *mut u8, a2),
        SYSCALL_REMOVEXATTR => sys_removexattr(a0 as *const u8, a1 as *const u8),
        SYSCALL_LREMOVEXATTR => sys_lremovexattr(a0 as *const u8, a1 as *const u8),
        SYSCALL_FREMOVEXATTR => sys_fremovexattr(a0, a1 as *const u8),
        SYSCALL_GETCWD => sys_getcwd(a0 as *mut u8, a1),
        SYSCALL_DUP => sys_dup(a0),
        SYSCALL_DUP3 => sys_dup3(a0, a1, a2 as i32),
        SYSCALL_FCNTL => sys_fcntl(a0 as i32, a1 as i32, a2),
        SYSCALL_INOTIFY_INIT => sys_inotify_init(a0 as i32),
        SYSCALL_INOTIFY_ADD_WATCH => sys_inotify_add_watch(a0, a1 as *const u8, a2 as u32),
        SYSCALL_INOTIFY_REMOVE_WATCH => sys_inotify_rm_watch(a0, a1 as i32),
        SYSCALL_IOCTL => sys_ioctl(a0, a1, a2),
        SYSCALL_FLOCK => sys_flock(a0, a1 as i32),
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
        SYSCALL_SYMLINKAT => sys_symlinkat(a0 as *const u8, a1 as i32, a2 as *const u8),
        SYSCALL_UMOUNT2 => sys_umount2(a1 as *const u8, a2 as i32),
        SYSCALL_MOUNT => sys_mount(
            a0 as *const u8,
            a1 as *const u8,
            a2 as *const u8,
            a3,
            a4 as *const u8,
        ),
        SYSCALL_SETSID => sys_setsid(),
        SYSCALL_STATFS => sys_statfs(a0 as *const u8, a1 as *mut StatFs),
        SYSCALL_FSTATFS => sys_fstatfs(a0, a1 as *mut StatFs),
        SYSCALL_TRUNCATE => sys_truncate(a0 as *const u8, a1 as isize),
        SYSCALL_FTRUNCATE => sys_ftruncate(a0, a1 as isize),
        SYSCALL_FALLOCATE => sys_fallocate(a0, a1 as i32, a2 as isize, a3 as isize),
        SYSCALL_FACCESSAT => sys_faccessat(a0 as usize, a1 as *const u8, a2 as i32, a3 as i32),
        SYSCALL_CHDIR => sys_chdir(a0 as *const u8),
        SYSCALL_FCHDIR => sys_fchdir(a0),
        SYSCALL_CHROOT => sys_chroot(a0 as *const u8),
        SYSCALL_FCHMOD => sys_fchmod(a0, a1),
        SYSCALL_FCHMODAT => sys_fchmodat(a0, a1 as *const u8, a2, a3 as i32),
        SYSCALL_FCHOWN => sys_fchown(a0, a1 as u32, a2 as u32),
        SYSCALL_FCHOWNAT => sys_fchownat(a0, a1 as *const u8, a2 as u32, a3 as u32, a4 as i32),
        SYSCALL_OPENAT => sys_openat(a0 as i32, a1 as *const u8, a2 as i32, a3 as i32),
        SYSCALL_CLOSE => sys_close(a0),
        SYSCALL_PIPE2 => sys_pipe2(a0 as *mut i32, a1 as i32),
        SYSCALL_GETDENTS64 => sys_getdents64(a0, a1, a2),
        SYSCALL_LSEEK => sys_lseek(a0, a1 as isize, a2),
        SYSCALL_READ => sys_read(a0, a1 as *mut u8, a2),
        SYSCALL_WRITE => sys_write(a0, a1 as *const u8, a2),
        SYSCALL_READV => sys_readv(a0, a1 as *const IoVec, a2),
        SYSCALL_WRITEV => sys_writev(a0, a1 as *const IoVec, a2),
        SYSCALL_PREAD => sys_pread(a0, a1 as *mut u8, a2, a3 as isize),
        SYSCALL_PWRITE => sys_pwrite(a0, a1 as *const u8, a2, a3 as isize),
        SYSCALL_PREADV => sys_preadv(a0, a1 as *const IoVec, a2, a3 as isize),
        SYSCALL_PWRITEV => sys_pwritev(a0, a1 as *const IoVec, a2, a3 as isize),
        SYSCALL_SENDFILE => sys_sendfile(a0, a1, a2 as *mut usize, a3),
        SYSCALL_PSELECT6 => sys_pselect6(a0, a1, a2, a3, a4 as *const TimeSpec, a5),
        SYSCALL_PPOLL => sys_ppoll(a0 as *mut PollFd, a1, a2 as *const TimeSpec, a3),
        SYSCALL_VMSPLICE => sys_vmsplice(a0, a1 as *const IoVec, a2, a3 as i32),
        SYSCALL_SPLICE => sys_splice(a0, a1, a2, a3, a4, a5 as i32),
        SYSCALL_TEE => sys_tee(a0, a1, a2, a3 as i32),
        SYSCALL_READLINKAT => {
            sys_readlinkat(a0 as i32, a1 as *const u8, a2 as *mut u8, a3 as isize)
        }
        SYSCALL_FSTATAT => sys_fstatat(a0 as i32, a1 as *const u8, a2 as *mut Stat, a3 as i32),
        SYSCALL_FSTAT => sys_fstat(a0 as i32, a1 as *mut Stat),
        SYSCALL_SYNC => sys_sync(),
        SYSCALL_FSYNC => sys_fsync(a0),
        SYSCALL_FDATASYNC => sys_fdatasync(a0),
        SYSCALL_SYNC_FILE_RANGE => sys_sync_file_range(a0, a1 as isize, a2 as isize, a3 as i32),
        SYSCALL_TIMERFD_CREATE => sys_timerfd_create(a0, a1 as i32),
        SYSCALL_TIMERFD_SETTIME => sys_timerfd_settime(
            a0,
            a1 as i32,
            a2 as *const ITimerSpec,
            a3 as *mut ITimerSpec,
        ),
        SYSCALL_TIMERFD_GETTIME => sys_timerfd_gettime(a0, a1 as *mut ITimerSpec),
        SYSCALL_UTIMENSAT => {
            sys_utimensat(a0 as i32, a1 as *const u8, a2 as *const TimeSpec, a3 as i32)
        }
        SYSCALL_ACCT => sys_acct(a0 as *const u8),
        // SYSCALL_CAPGET => sys_capget(a0, a1),
        // SYSCALL_CAPSET => sys_capset(a0, a1),
        SYSCALL_EXIT => sys_exit(a0 as i32),
        SYSCALL_EXIT_GROUP => sys_exit_group(a0 as i32),
        SYSCALL_WAITID => sys_waitid(a0 as i32, a1 as isize, a2, a3 as i32),
        SYSCALL_SET_TID_ADDRESS => sys_set_tid_address(a0),
        SYSCALL_SET_ROBUST_LIST => sys_set_robust_list(a0, a1),
        SYSCALL_FUTEX => sys_futex(a0, a1 as i32, a2 as u32, a3, a4, a5 as u32),
        SYSCALL_GET_ROBUST_LIST => sys_get_robust_list(a0, a1, a2),
        SYSCALL_NANOSLEEP => sys_nanosleep(a0, a1),
        SYSCALL_GETITIMER => sys_getitimer(a0 as i32, a1 as *mut ITimerVal),
        SYSCALL_SETITIMER => sys_setitimer(a0 as i32, a1 as *const ITimerVal, a2 as *mut ITimerVal),
        SYSCALL_TIMER_CREATE => sys_timer_create(a0, a1, a2),
        SYSCALL_TIMER_GETTIME => sys_timer_gettimer(a0, a1 as *mut ITimerSpec),
        SYSCALL_TIMER_GETOVERRUN => sys_timer_getoverrun(a0),
        SYSCALL_TIMER_SETTIME => sys_timer_settimer(
            a0,
            a1 as i32,
            a2 as *const ITimerSpec,
            a3 as *mut ITimerSpec,
        ),
        SYSCALL_TIMER_DELETE => sys_timer_delete(a0),
        SYSCALL_CLOCK_SETTIME => sys_clock_settime(a0, a1 as *const TimeSpec),
        SYSCALL_CLOCK_GETTIME => sys_clock_gettime(a0, a1 as *mut TimeSpec),
        SYSCALL_CLOCK_GETRES => sys_clock_getres(a0, a1),
        SYSCALL_CLOCK_NANOSLEEP => sys_clock_nanosleep(a0, a1 as i32, a2, a3),
        SYSCALL_SYSLOG => sys_syslog(a0, a1 as *mut u8, a3 as isize),
        SYSCALL_SCHED_SETPARAM => sys_sched_setparam(a0 as isize, a1),
        SYSCALL_SCHED_SETSCHEDULER => sys_sched_setscheduler(a0 as isize, a1 as u32, a2),
        SYSCALL_SCHED_GETSCHEDULER => sys_sched_getscheduler(a0 as isize),
        SYSCALL_SCHED_GETPARAM => sys_sched_getparam(a0 as isize, a1),
        SYSCALL_SCHED_SETAFFINITY => sys_sched_setaffinity(a0 as isize, a1, a2),
        SYSCALL_SCHED_GETAFFINITY => sys_sched_getaffinity(a0 as isize, a1, a2),
        SYSCALL_YIELD => sys_yield(),
        SYSCALL_SCHED_GET_PRIORITY_MAX => sys_sched_get_priority_max(a0 as i32),
        SYSCALL_SCHED_GET_PRIORITY_MIN => sys_sched_get_priority_min(a0 as i32),
        SYSCALL_SCHED_RR_GET_INTERVAL => sys_sched_rr_get_interval(a0 as isize, a1),
        SYSCALL_KILL => sys_kill(a0 as isize, a1 as i32),
        SYSCALL_TKILL => sys_tkill(a0 as isize, a1 as i32),
        SYSCALL_TGKILL => sys_tgkill(a0 as isize, a1 as isize, a2 as i32),
        SYSCALL_SIGALTSTACK => sys_sigaltstack(a0, a1),
        SYSCALL_RT_SIGSUSPEND => sys_rt_sigsuspend(a0),
        SYSCALL_RT_SIGACTION => sys_rt_sigaction(a0 as i32, a1, a2, a3),
        SYSCALL_RT_SIGPROCMASK => sys_rt_sigprocmask(a0, a1, a2, a3),
        SYSCALL_RT_SIGPENDING => sys_rt_sigpending(a0),
        SYSCALL_RT_SIGTIMEDWAIT => sys_rt_sigtimedwait(a0, a1, a2),
        SYSCALL_RT_SIGQUEUEINFO => sys_rt_sigqueueinfo(a0 as isize, a1 as i32, a2),
        SYSCALL_RT_SIGRETURN => sys_rt_sigreturn(),
        SYSCALL_SETPRIORITY => sys_setpriority(a0 as i32, a1 as i32, a2 as i32),
        SYSCALL_GETPRIORITY => sys_getpriority(a0 as i32, a1 as i32),
        SYACALL_SETREGRID => sys_setregid(a0 as i32, a1 as i32),
        SYSCALL_SETGID => sys_setgid(a0 as u32),
        SYSCALL_SETREUID => sys_setreuid(a0 as i32, a1 as i32),
        SYSCALL_SETUID => sys_setuid(a0 as u32),
        SYSCALL_SETRESUID => sys_setresuid(a0 as i32, a1 as i32, a2 as i32),
        SYSCALL_GETRESUID => sys_getresuid(a0 as u32, a1 as u32, a2 as u32),
        SYSCALL_SETRESGID => sys_setresgid(a0 as i32, a1 as i32, a2 as i32),
        SYSCALL_GETRESGID => sys_getresgid(a0 as u32, a1 as u32, a2 as u32),
        SYSCALL_SETFSUID => sys_setfsuid(a0 as i32),
        SYSCALL_SETFSGID => sys_setfsgid(a0 as i32),
        SYSCALL_TIMES => sys_times(a0),
        SYSCALL_SETPGID => sys_setpgid(a0, a1),
        SYSCALL_GETPGID => sys_getpgid(a0),
        SYSCALL_SETGROUPS => sys_setgroups(a0, a1),
        SYSCALL_GETGROUPS => sys_getgroups(a0, a1),
        SYSCALL_UNAME => sys_uname(a0),
        SYSCALL_GETRUSAGE => sys_getrusage(a0 as i32, a1 as *mut RUsage),
        SYSCALL_UMASK => sys_umask(a0),
        SYSCALL_GETCPU => sys_getcpu(a0, a1),
        SYSCALL_GET_TIME => sys_get_time(a0),
        SYSCALL_GITPID => sys_getpid(),
        SYSCALL_GETPPID => sys_getppid(),
        SYSCALL_GETUID => sys_getuid(),
        SYSCALL_GETEUID => sys_geteuid(),
        SYSCALL_GETGID => sys_getgid(),
        SYSCALL_GETEGID => sys_getegid(),
        SYSCALL_GETTID => sys_gettid(),
        SYSCALL_SYSINFO => sys_sysinfo(a0 as *mut SysInfo),
        SYCALL_SHMGET => sys_shmget(a0, a1, a2 as i32),
        // SYSCALL_SHMCTL => sys_shmctl(a0, a1 as i32, a2),
        SYSCALL_SHMCTL => sys_shmctl(a0, a1 as i32, a2 as *mut ShmId),
        SYSCALL_SHMAT => sys_shmat(a0, a1, a2 as i32),
        SYSCALL_SHMDT => sys_shmdt(a0),
        SYSCALL_BRK => sys_brk(a0),
        SYSCALL_MUNMAP => sys_munmap(a0, a1),
        SYSCALL_MREMAP => sys_mremap(a0, a1, a2, a3 as i32, a4),
        SYSCALL_MADVISE => sys_madvise(a0, a1, a2 as i32),
        SYSCALL_MPROTECT => sys_mprotect(a0, a1, a2 as i32),
        SYSCALL_MLOCK => sys_mlock(a0, a1),
        SYSCALL_GET_MEMPOLICY => sys_get_mempolicy(a0, a1, a2, a3, a4),
        SYSCALL_MSYNC => sys_msync(a0, a1, a2 as i32),
        SYSCALL_FORK => sys_clone(a0 as u32, a1, a2, a3, a4),
        SYSCALL_EXEC => sys_execve(a0 as *mut u8, a1 as *const usize, a2 as *const usize),
        SYSCALL_MMAP => sys_mmap(a0, a1, a2, a3, a4 as i32, a5),
        SYSCALL_FADVISE64 => sys_fadvise64(a0, a1, a2 as usize, a3 as i32),
        SYSCALL_WAIT4 => sys_waitpid(a0 as isize, a1, a2 as i32),
        SYSCALL_SOCKET => syscall_socket(a0, a1, a2),
        SYSCALL_BIND => syscall_bind(a0, a1, a2),
        SYSCALL_LISTEN => syscall_listen(a0, a1),
        SYSCALL_CONNECT => syscall_connect(a0, a1, a2),
        SYSCALL_ACCEPT => syscall_accept(a0, a1, a2),
        SYSCALL_ACCEPT4 => syscall_accept4(a0, a1, a2, a3),
        SYSCALL_SENDTO => syscall_send(a0, a1 as *const u8, a2, a3, a4, a5),
        SYSCALL_RECVFROM => syscall_recvfrom(a0, a1 as *mut u8, a2, a3, a4, a5),
        SYSCALL_SHUTDOWN => syscall_shutdown(a0, a1),
        SYSCALL_PRLIMIT => sys_prlimit64(a0, a1 as i32, a2 as *const RLimit, a3 as *mut RLimit),
        SYSCALL_SCHED_SETATTR => sys_sched_setattr(a0 as isize, a1, a2 as u32),
        SYSCALL_SCHED_GETATTR => sys_sched_getattr(a0 as isize, a1, a2 as u32, a3 as u32),
        SYSCALL_GETSOCKNAME => syscall_getsockname(a0, a1, a2),
        SYSCALL_GETPEERNAME => syscall_getpeername(a0, a1, a2),
        SYSCALL_RENAMEAT2 => sys_renameat2(
            a0 as i32,
            a1 as *const u8,
            a2 as i32,
            a3 as *const u8,
            a4 as i32,
        ),
        SYSCALL_GETRANDOM => Ok(1), // python3.10 需要这个系统调用
        SYSCALL_MEMFD_CREATE => sys_memfd_create(a0 as *const u8, a1 as i32),
        SYSCALL_BPF => sys_bpf(a0 as i32, a1, a2),
        SYSCALL_EXECVEAT => sys_execveat(
            a0 as i32,
            a1 as *mut u8,
            a2 as *const usize,
            a3 as *const usize,
            a4 as i32,
        ),
        SYSCALL_MEMBARRIER => sys_membarrier(a0 as i32, a1 as i32, a2 as u32),
        SYSCALL_COPY_FILE_RANGE => sys_copy_file_range(a0, a1, a2, a3, a4, a5 as i32),
        SYSCALL_PREADV2 => sys_preadv2(a0, a1 as *const IoVec, a2, a3 as i32, a4 as i32, a5 as i32),
        SYSCALL_PWRITEV2 => sys_pwritev2(a0, a1 as *const IoVec, a2, a3 as isize, a4 as i32),
        SYSCALL_STATX => sys_statx(
            a0 as i32,
            a1 as *const u8,
            a2 as i32,
            a3 as u32,
            a4 as *mut Statx,
        ),
        // SYSCALL_SELECT=>sys_select(a0 , a1, a2,a3 ,a4 as *const TimeSpec , a5),
        SYSCALL_SETSOCKOPT => syscall_setsocketopt(a0, a1, a2, a3 as *const u8, a4),
        SYSCALL_GETSOCKOPT => syscall_getsocketopt(a0, a1, a2, a3 as *mut u8, a4),
        SYSCALL_ADJTIMEX => sys_adjtimex(a0 as *mut KernelTimex),
        // SYSCALL_FSOPEN => sys_fsopen(a0 as  ),
        SYSCALL_CLOCKADJTIME => sys_clock_adjtime(a0 as i32, a1 as *mut KernelTimex),
        SYSCALL_SOCKETPAIR => syscall_socketpair(a0, a1, a2, a3 as *mut i32),
        SYSCALL_SENDMSG => syscall_sendmsg(a0, a1, a2),
        SYSCALL_RECVMSG => syscall_recvmsg(a0, a1, a2),
        SYSCALL_CLOSE_RANGE => sys_close_range(a0, a1, a2 as i32),
        SYSCALL_OPENAT2 => sys_openat2(a0 as i32, a1 as *const u8, a2 as *const u8, a3 as usize),
        SYSCALL_FACCESSAT2 => sys_faccessat2(a0 as usize, a1 as *const u8, a2 as i32, a3 as i32),
        SYSCALL_SETDOMAINNAME => syscall_setdomainname(a0 as *const u8, a1),
        SYSCALL_GETRLIMIT => sys_getrlimit(a0 as i32, a1 as *mut RLimit),
        SYSCALL_SETRLIMIT => sys_setrlimit(a0 as i32, a1 as *const RLimit),
        SYSCALL_SETHOSTNAME => syscall_sethostname(a0 as *const u8, a1),
        SYSCALL_SHUTDOMN => sys_shutdown(),
        _ => {
            log::warn!("Unsupported syscall_id: {}", syscall_id,);
            Err(Errno::ENOSYS)
        }
    }
    // println!("[syscall_id]:{}",&syscall_id);
}

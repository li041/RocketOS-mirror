use core::arch::asm;

use alloc::ffi::CString;

const SYSCALL_OPEN: usize = 56;
const SYSCALL_CLOSE: usize = 57;
const SYSCALL_READ: usize = 63;
const SYSCALL_WRITE: usize = 64;
const SYSCALL_DUP3: usize = 24;
const SYSCALL_EXIT: usize = 93;
const SYSCALL_YIELD: usize = 124;
const SYSCALL_GET_TIME: usize = 169;
const SYSCALL_GETPID: usize = 172;
const SYSCALL_FORK: usize = 220;
const SYSCALL_EXECVE: usize = 221;
const SYSCALL_WAITPID: usize = 260;
const SYSCALL_PIPE2: usize = 59;
const SYSCALL_CHDIR: usize = 49;
const SYSCALL_GETCWD: usize = 17;
const SYSCALL_SOCKETPAIR: usize = 199;
#[cfg(target_arch = "riscv64")]
fn syscall(id: usize, args: [usize; 6]) -> isize {
    let mut ret: isize;
    unsafe {
        asm!(
            "ecall",
            inlateout("x10") args[0] => ret,
            in("x11") args[1],
            in("x12") args[2],
            in("x13") args[3],
            in("x14") args[4],
            in("x15") args[5],
            in("x17") id
        );
    }
    ret
}
#[cfg(target_arch = "loongarch64")]
pub fn syscall(id: usize, args: [usize; 6]) -> isize {
    let mut ret: isize;
    unsafe {
        asm!(
            "syscall 0",
            inlateout("$r4") args[0] => ret,
            in("$r5") args[1],
            in("$r6") args[2],
            in("$r7") args[3],
            in("$r8") args[4],
            in("$r9") args[5],
            in("$r11") id
        )
    }
    ret
}

pub fn sys_open(dirfd: i32, path: &CString, flags: u32) -> isize {
    syscall(
        SYSCALL_OPEN,
        [
            dirfd as usize,
            path.as_ptr() as usize,
            flags as usize,
            0,
            0,
            0,
        ],
    )
}

pub fn sys_close(fd: usize) -> isize {
    syscall(SYSCALL_CLOSE, [fd, 0, 0, 0, 0, 0])
}

pub fn sys_read(fd: usize, buffer: &mut [u8]) -> isize {
    syscall(
        SYSCALL_READ,
        [fd, buffer.as_mut_ptr() as usize, buffer.len(), 0, 0, 0],
    )
}

pub fn sys_write(fd: usize, buffer: &[u8]) -> isize {
    syscall(
        SYSCALL_WRITE,
        [fd, buffer.as_ptr() as usize, buffer.len(), 0, 0, 0],
    )
}

pub fn sys_dup3(oldfd: usize, newfd: usize, flags: i32) -> isize {
    syscall(SYSCALL_DUP3, [oldfd, newfd, flags as usize, 0, 0, 0])
}

pub fn sys_exit(exit_code: i32) -> ! {
    syscall(SYSCALL_EXIT, [exit_code as usize, 0, 0, 0, 0, 0]);
    panic!("sys_exit never returns!");
}

pub fn sys_yield() -> isize {
    syscall(SYSCALL_YIELD, [0, 0, 0, 0, 0, 0])
}

pub fn sys_get_time() -> isize {
    syscall(SYSCALL_GET_TIME, [0, 0, 0, 0, 0, 0])
}

pub fn sys_socketpair(
    domain: usize,
    sockettype: usize,
    protocol: usize,
    socketfds: *mut i32,
) -> isize {
    syscall(
        SYSCALL_SOCKETPAIR,
        [domain, sockettype, protocol, socketfds as usize, 0, 0],
    )
}

pub fn sys_getpid() -> isize {
    syscall(SYSCALL_GETPID, [0, 0, 0, 0, 0, 0])
}

pub fn sys_fork() -> isize {
    syscall(SYSCALL_FORK, [0, 0, 0, 0, 0, 0])
}
pub fn sys_pipe2(pipe: *mut i32, flags: i32) -> isize {
    syscall(SYSCALL_PIPE2, [pipe as usize, flags as usize, 0, 0, 0, 0])
}

pub fn sys_chdir(path: &str) -> isize {
    syscall(SYSCALL_CHDIR, [path.as_ptr() as usize, 0, 0, 0, 0, 0])
}

pub fn sys_getcwd(buf: *mut u8, size: usize) -> isize {
    syscall(SYSCALL_GETCWD, [buf as usize, size, 0, 0, 0, 0])
}

// pub fn sys_exec(path: &str) -> isize {
//     syscall(SYSCALL_EXEC, [path.as_ptr() as usize, 0, 0, 0, 0, 0])
// }

pub fn sys_execve(path: &str, argv: &[*const u8], envp: &[*const u8]) -> isize {
    syscall(
        SYSCALL_EXECVE,
        [
            path.as_ptr() as usize,
            argv.as_ptr() as usize,
            envp.as_ptr() as usize,
            0,
            0,
            0,
        ],
    )
}

pub fn sys_waitpid(pid: isize, exit_code: *mut i32) -> isize {
    syscall(
        SYSCALL_WAITPID,
        [pid as usize, exit_code as usize, 0, 0, 0, 0],
    )
}

pub fn sys_shutdown() -> isize {
    syscall(666, [0, 0, 0, 0, 0, 0])
}

pub fn sys_flush() -> isize {
    syscall(667, [0, 0, 0, 0, 0, 0])
}

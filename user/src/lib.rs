#![no_std]
#![feature(linkage)]
#![feature(alloc_error_handler)]

#[macro_use]
pub mod console;
mod lang_items;
mod syscall;

extern crate alloc;
#[macro_use]
extern crate bitflags;

use core::ptr::null;

use alloc::{
    ffi::CString,
    string::{String, ToString},
    vec::Vec,
};
use buddy_system_allocator::LockedHeap;
use syscall::*;

const USER_HEAP_SIZE: usize = 32768;

static mut HEAP_SPACE: [u8; USER_HEAP_SIZE] = [0; USER_HEAP_SIZE];

#[global_allocator]
static HEAP: LockedHeap<16> = LockedHeap::empty();

#[alloc_error_handler]
pub fn handle_alloc_error(layout: core::alloc::Layout) -> ! {
    panic!("Heap allocation error, layout = {:?}", layout);
}

#[no_mangle]
#[link_section = ".text.entry"]
pub extern "C" fn _start() -> ! {
    #[allow(static_mut_refs)]
    unsafe {
        HEAP.lock()
            .init(HEAP_SPACE.as_ptr() as usize, USER_HEAP_SIZE);
    }
    exit(main());
}

#[linkage = "weak"]
#[no_mangle]
fn main() -> i32 {
    panic!("Cannot find main!");
}

bitflags! {
    pub struct OpenFlags: u32 {
        const RDONLY = 0;
        const WRONLY = 1 << 0;
        const RDWR = 1 << 1;
        const CREATE = 1 << 9;
        const TRUNC = 1 << 10;
        const APPEND =  1 << 11;
    }
}

pub const AT_FDCWD: i32 = -100; // Current working directory

pub fn open(path: &CString, flags: OpenFlags) -> isize {
    sys_open(AT_FDCWD, path, flags.bits)
}
pub fn close(fd: usize) -> isize {
    sys_close(fd)
}
pub fn read(fd: usize, buf: &mut [u8]) -> isize {
    sys_read(fd, buf)
}
pub fn write(fd: usize, buf: &[u8]) -> isize {
    sys_write(fd, buf)
}
pub fn dup3(oldfd: usize, newfd: usize, flags: i32) -> isize {
    sys_dup3(oldfd, newfd, flags)
}
pub fn exit(exit_code: i32) -> ! {
    sys_exit(exit_code);
}
pub fn yield_() -> isize {
    sys_yield()
}
pub fn get_time() -> isize {
    sys_get_time()
}
pub fn getpid() -> isize {
    sys_getpid()
}
pub fn fork() -> isize {
    sys_fork()
}
pub fn pipe(pipe: *mut i32, flags: i32) -> isize {
    sys_pipe2(pipe, flags)
}
pub fn chdir(path: &str) -> isize {
    sys_chdir(path)
}
pub fn socketpair(domain: usize, sockettype: usize, protocol: usize, socketfds: *mut i32) -> isize {
    sys_socketpair(domain, sockettype, protocol, socketfds)
}

// pub fn exec(path: &str) -> isize {
//     sys_exec(path)
// }

/// Replaces the current process image with a new process image.
///
/// # Arguments
///
/// * `path` - A NULL-TERMINATED string slice that holds the path of the new program.
/// * `argv` - An array of string slices that represent the argument list to the new program. TRAILING NULL IS NOT NEEDED.
/// * `envp` - An array of string slices that represent the environment for the new program. TRAILING NULL IS NOT NEEDED.
///
/// # Errors
///
/// on error, return POSIX errno
pub fn execve(path: &str, argv: &[&str], envp: &[&str]) -> isize {
    let mut argv: Vec<*const u8> = argv.iter().map(|s| s.as_ptr() as *const u8).collect();
    argv.push(null());
    let mut envp: Vec<*const u8> = envp.iter().map(|s| s.as_ptr() as *const u8).collect();
    envp.push(null());
    sys_execve(path, &argv, &envp)
}

pub fn wait(exit_code: &mut i32) -> isize {
    loop {
        match sys_waitpid(-1, exit_code as *mut _) {
            -2 => {
                yield_();
            }
            // -1 or a real pid
            exit_pid => return exit_pid,
        }
    }
}

pub fn waitpid(pid: isize, exit_code: &mut i32) -> isize {
    loop {
        match sys_waitpid(pid as isize, exit_code as *mut _) {
            -2 => {
                yield_();
            }
            // -1 or a real pid
            exit_pid => return exit_pid,
        }
    }
}
pub fn sleep(period_ms: usize) {
    let start = sys_get_time();
    while sys_get_time() < start + period_ms as isize {
        sys_yield();
    }
}

pub fn getcwd() -> String {
    let mut buf = [0u8; 256];
    sys_getcwd(buf.as_mut_ptr(), buf.len());
    String::from_utf8_lossy(&buf)
        .trim_end_matches('\0')
        .to_string()
}

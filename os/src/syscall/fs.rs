use core::arch::asm;

use crate::{
    sbi::console_getchar,
    task::{suspend_current_and_run_next, sys_yield},
};

const FD_STDOUT: usize = 1;
const FD_STDIN: usize = 0;

pub fn sys_read(fd: usize, buf: *mut u8, len: usize) -> isize {
    match fd {
        FD_STDIN => {
            assert_eq!(len, 1, "Only support len = 1 in sys_read!");
            let mut c: usize;
            loop {
                c = console_getchar();
                if c == usize::MAX {
                    suspend_current_and_run_next();
                    continue;
                } else {
                    break;
                }
            }
            let ch = c as u8;
            log::info!("read from console: {}", ch as char);
            let buffer = unsafe { core::slice::from_raw_parts_mut(buf, len) };
            buffer[0] = ch;
            1
        }
        _ => {
            panic!("Unsupported fd in sys_read!");
        }
    }
}

/// write buf of length `len`  to a file with `fd`
pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    match fd {
        FD_STDOUT => {
            let slice = unsafe { core::slice::from_raw_parts(buf, len) };
            let str = core::str::from_utf8(slice).unwrap();
            print!("{}", str);
            len as isize
        }
        _ => {
            panic!("Unsupported fd in sys_write!");
        }
    }
}

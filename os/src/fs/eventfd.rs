/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-07-18 11:02:38
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-07-19 16:34:17
 * @FilePath: /RocketOS_netperfright/os/src/fs/eventfd.rs
 * @Description: 
 * 
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved. 
 */

use alloc::sync::Arc;
use bitflags::bitflags;
use spin::Mutex;

use crate::{fs::file::{FileOp, OpenFlags}, syscall::errno::{Errno, SyscallRet}, task::yield_current_task};

bitflags! {
    // https://sites.uclouvain.be/SystInfo/usr/include/sys/eventfd.h.html
    #[derive(Clone, Copy, Debug)]
    pub struct EventFdFlag: u32 {
        const EFD_SEMAPHORE = 0x1;
        const EFD_NONBLOCK = 0x800;
        const EFD_CLOEXEC = 0x80000;
    }
}
// https://man7.org/linux/man-pages/man2/eventfd2.2.html
pub struct EventFd {
    value: Arc<Mutex<u64>>,
    flags: u32,
}
impl EventFd {
    pub fn new(initval: u64, flags: u32) -> EventFd {
        EventFd {
            value: Arc::new(Mutex::new(initval)),
            flags,
        }
    }

    fn should_block(&self) -> bool {
        self.flags & EventFdFlag::EFD_NONBLOCK.bits() == 0
    }

    fn has_semaphore_set(&self) -> bool {
        self.flags & EventFdFlag::EFD_SEMAPHORE.bits() != 0
    }
}

impl FileOp for EventFd {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> SyscallRet {
        let len: usize = core::mem::size_of::<u64>();
        if buf.len() < len {
            return Err(Errno::EINVAL);
        }

        loop {
            let mut value_guard = self.value.lock();
            // If EFD_SEMAPHORE was not specified and the eventfd counter has a nonzero value, then a read returns 8 bytes containing that value,
            // and the counter's value is reset to zero.
            if !self.has_semaphore_set() && *value_guard != 0 {
                buf[0..len].copy_from_slice(&value_guard.to_ne_bytes());
                *value_guard = 0;
                return Ok(len);
            }

            // If EFD_SEMAPHORE was specified and the eventfd counter has a nonzero value, then a read returns 8 bytes containing the value 1,
            // and the counter's value is decremented by 1.
            if self.has_semaphore_set() && *value_guard != 0 {
                let result: u64 = 1;
                buf[0..len].copy_from_slice(&result.to_ne_bytes());
                let _ = value_guard.checked_add_signed(-1);
                return Ok(len);
            }

            // If the eventfd counter is zero at the time of the call to read,
            // then the call either blocks until the counter becomes nonzero (at which time, the read proceeds as described above)
            // or fails with the error EAGAIN if the file descriptor has been made nonblocking.
            if *value_guard != 0 {
                buf[0..len].copy_from_slice(&value_guard.to_ne_bytes());
                return Ok(len);
            }

            if self.should_block() {
                drop(value_guard);
                yield_current_task();
            } else {
                return Err(Errno::EAGAIN);
            }
        }
    }

    fn write<'a>(&'a self, buf: &'a [u8]) -> SyscallRet {
        let len: usize = core::mem::size_of::<u64>();

        // A write fails with the error EINVAL if the size of the supplied buffer is less than 8 bytes,
        // or if an attempt is made to write the value 0xffffffffffffffff.
        let val = u64::from_ne_bytes(buf[0..len].try_into().unwrap());
        if buf.len() < 8 || val == u64::MAX {
            return Err(Errno::EINVAL);
        }

        loop {
            let mut value_guard = self.value.lock();
            // The maximum value that may be stored in the counter is the largest unsigned 64-bit value minus 1 (i.e., 0xfffffffffffffffe).
            match value_guard.checked_add(val + 1) {
                // no overflow
                Some(_) => {
                    *value_guard += val;
                    return Ok(len);
                }
                // overflow
                None => {
                    if self.should_block() {
                        drop(value_guard);
                        yield_current_task();
                    } else {
                        return Err(Errno::EAGAIN);
                    }
                }
            }
        }
    }
    fn writable(&self) -> bool {
        true
    }
    fn readable(&self) -> bool {
        true
    }
    fn r_ready(&self) -> bool {
        *self.value.lock() > 0
    }
    fn w_ready(&self) -> bool {
        *self.value.lock() < u64::MAX - 1
    }
    fn get_flags(&self) -> OpenFlags {
        let mut status = OpenFlags::O_RDWR;
        if self.flags & EventFdFlag::EFD_NONBLOCK.bits() != 0 {
            status |= OpenFlags::O_NONBLOCK;
        }
        if self.flags & EventFdFlag::EFD_CLOEXEC.bits() != 0 {
            status |= OpenFlags::O_CLOEXEC;
        }

        status
    }
    fn hang_up(&self) -> bool {
        true
    }

}
extern crate alloc;

use core::time::Duration;
use log::error;

use flags::*;
use futex::{futex_cmp_requeue, futex_requeue, futex_wait, futex_wake, futex_wake_bitset};

use crate::{
    arch::mm::copy_from_user,
    syscall::errno::{Errno, SyscallRet},
    timer::TimeSpec,
};

/*
use axprocess::{
    current_process, current_task, futex::FutexRobustList
}
;

use crate::{RobustList, SyscallError, SyscallResult, TimeSecs};
*/

pub mod flags;
pub mod futex;
mod jhash;
mod queue;
pub mod robust_list;

pub fn do_futex(
    uaddr: usize,
    futex_op: i32,
    val: u32,
    val2: usize,
    uaddr2: usize,
    val3: u32,
) -> SyscallRet {
    let flags: i32 = futex_op_to_flag(futex_op);
    // cmd determines the operation of futex
    let cmd: i32 = futex_op & FUTEX_CMD_MASK;

    match cmd {
        FUTEX_WAIT => {
            let val3 = FUTEX_BITSET_MATCH_ANY;
            let mut timeout_buf = TimeSpec::default();
            // convert relative timeout to absolute timeout
            let timeout: Option<TimeSpec> = if val2 != 0 {
                copy_from_user(
                    val2 as *const TimeSpec,
                    &mut timeout_buf as *mut TimeSpec,
                    1,
                )?;
                Some(timeout_buf)
            } else {
                None
            };
            let deadline: Option<TimeSpec> = if timeout.is_some() {
                if flags & FLAGS_CLOCKRT != 0 {
                    // convert relative timeout to absolute timeout
                    Some(timeout.unwrap() + TimeSpec::new_machine_time())
                } else {
                    // convert relative timeout to absolute timeout
                    Some(timeout.unwrap() + TimeSpec::new_machine_time())
                }
            } else {
                None
            };
            futex_wait(uaddr.into(), flags, val, deadline, val3)
        }
        FUTEX_WAIT_BITSET => {
            let mut timeout_buf = TimeSpec::default();
            let timeout: Option<TimeSpec> = if val2 != 0 {
                copy_from_user(
                    val2 as *const TimeSpec,
                    &mut timeout_buf as *mut TimeSpec,
                    1,
                )?;
                Some(timeout_buf)
            } else {
                None
            };
            futex_wait(uaddr.into(), flags, val, timeout, val3)
        }
        FUTEX_WAKE => futex_wake(uaddr.into(), flags, val),
        FUTEX_WAKE_BITSET => futex_wake_bitset(uaddr.into(), flags, val, val3),
        FUTEX_REQUEUE => futex_requeue(uaddr.into(), flags, val, uaddr2.into(), val2 as u32),
        FUTEX_CMP_REQUEUE => futex_cmp_requeue(
            uaddr.into(),
            flags,
            val,
            uaddr2.into(),
            val2 as u32,
            val3 as u32,
        ),
        FUTEX_WAKE_OP => {
            // futex_wake(uaddr, flags, uaddr2, val, val2, val3)
            panic!("[linux_syscall_api] futex: unsupported futex operation: FUTEX_WAKE_OP");
        }
        // TODO: priority-inheritance futex
        _ => {
            panic!(
                "[linux_syscall_api] futex: unsupported futex operation: {}",
                cmd
            );
        }
    }
    // success anyway and reach here
}

/*
/// 内核只发挥存储的作用
/// 但要保证head对应的地址已经被分配
/// # Arguments
/// * head: usize
/// * len: usize
pub fn syscall_set_robust_list(args: [usize; 6]) -> SyscallResult {
    let head = args[0];
    let len = args[1];
    let process = current_process();
    if len != core::mem::size_of::<RobustList>() {
        return Err(SyscallError::EINVAL);
    }
    let curr_id = current_task().id().as_u64();
    if process.manual_alloc_for_lazy(head.into()).is_ok() {
        let mut robust_list = process.robust_list.lock();
        robust_list.insert(curr_id, FutexRobustList::new(head, len));
        Ok(0)
    } else {
        Err(SyscallError::EINVAL)
    }
}

/// 取出对应线程的robust list
/// # Arguments
/// * pid: i32
/// * head: *mut usize
/// * len: *mut usize
pub fn syscall_get_robust_list(args: [usize; 6]) -> SyscallResult {
    let pid = args[0] as i32;
    let head = args[1] as *mut usize;
    let len = args[2] as *mut usize;

    if pid == 0 {
        let process = current_process();
        let curr_id = current_task().id().as_u64();
        if process
            .manual_alloc_for_lazy((head as usize).into())
            .is_ok()
        {
            let robust_list = process.robust_list.lock();
            if robust_list.contains_key(&curr_id) {
                let list = robust_list.get(&curr_id).unwrap();
                unsafe {
                    *head = list.head;
                    *len = list.len;
                }
            } else {
                return Err(SyscallError::EPERM);
            }
            return Ok(0);
        }
        return Err(SyscallError::EPERM);
    }
    Err(SyscallError::EPERM)
}
    */

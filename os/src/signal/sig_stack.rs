use crate::arch::trap::TrapContext;

use super::{Sig, SigSet};

pub const SS_ONSTACK: i32 = 1;
pub const SS_DISABLE: i32 = 2;
pub const SS_AUTODISARM: i32 = 1 << 31; // tode
pub const MINSIGSTKSZ: usize = 2048; // 最小信号栈大小

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct SigStack {
    pub ss_sp: usize,   // 栈底
    pub ss_flags: i32,  // 是否启用
    pub ss_size: usize, // 栈大小
}

impl Default for SigStack {
    fn default() -> Self {
        Self {
            ss_sp: 0,
            ss_flags: SS_DISABLE,
            ss_size: 0,
        }
    }
}
use crate::arch::trap::TrapContext;

use super::{Sig, SigSet};

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct SignalStack {
    pub ss_sp: usize,   // 栈底
    pub ss_flags: i32,  // 是否启用
    pub ss_size: usize, // 栈大小
}

impl SignalStack {
    pub fn new() -> Self {
        SignalStack {
            ss_sp: 0,
            ss_flags: 0,
            ss_size: 0,
        }
    }
}

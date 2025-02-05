#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct IoVec {
    pub base: usize,
    pub len: usize,
}

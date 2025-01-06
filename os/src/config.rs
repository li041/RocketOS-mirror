pub const KERNEL_HEAP_SIZE: usize = 0x300_0000; // 48MB
pub const PAGE_SIZE: usize = 0x1000; // 4KB
pub const KERNEL_BASE: usize = 0xffff_ffc0_0000_0000;
/// KERNEL_BASE >> 12
pub const KERNEL_DIRECT_OFFSET: usize = KERNEL_BASE >> 12;
pub const PAGE_SIZE_BITS: usize = 0xc;
/// 用户栈大小: 两页
pub const USER_STACK_SIZE: usize = PAGE_SIZE << 4;

pub type SysResult<T> = Result<T, usize>;

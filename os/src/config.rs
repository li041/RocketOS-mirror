/* 内存布局 */
pub const KERNEL_HEAP_SIZE: usize = 0x300_0000; // 48MB
pub const PAGE_SIZE: usize = 0x1000; // 4KB
pub const KERNEL_BASE: usize = 0xffff_ffc0_0000_0000;
pub const USER_MAX: usize = 0x0000_003f_ffff_ffff;
/// KERNEL_BASE >> 12
pub const KERNEL_DIRECT_OFFSET: usize = KERNEL_BASE >> 12;
pub const PAGE_SIZE_BITS: usize = 0xc;
/// 用户栈大小: 两页
pub const USER_STACK_SIZE: usize = PAGE_SIZE << 4;

// 文件映射和匿名映射区域, 大小为1GB
pub const MMAP_MIN_ADDR: usize = 0x0000_0020_0000_0000;
pub const MMAP_MAX_ADDR: usize = 0x0000_002f_ffff_ffff;
pub const MMAP_AREA_SIZE: usize = MMAP_MAX_ADDR - MMAP_MIN_ADDR;
// 动态连接器加载偏移量
pub const DL_INTERP_OFFSET: usize = 0x30_0000_0000;

/* 系统调用 */
pub type SysResult<T> = Result<T, usize>;
pub const USER_MAX_VA: usize = 0x0000_003f_ffff_ffff; // 256GB

/* Ext4文件系统 */
pub const EXT4_MAX_INLINE_DATA: usize = 60;

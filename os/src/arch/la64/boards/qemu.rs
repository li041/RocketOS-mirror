pub const MEMORY_START: usize = 0x0000_0000_9000_0000;
#[cfg(feature = "virt")]
pub const MEMORY_SIZE: usize = 0x3000_0000;
#[cfg(feature = "board")]
pub const MEMORY_SIZE: usize = 0x3000_0000;
pub const MEMORY_END: usize = MEMORY_SIZE + MEMORY_START;

pub const DISK_IMAGE_BASE: usize = 0x800_0000 + MEMORY_START;
/// I/O
/// 0x800000001fe20000
/// 0x1fe0_01eo

#[cfg(feature = "board")]
pub const UART_BASE: usize = 0x800000001fe20000;
#[cfg(feature = "virt")]
pub const UART_BASE: usize = 0x1fe0_01e0;

pub const MMIO: &[(usize, usize)] = &[
    (0x0010_0000, 0x00_2000), // VIRT_TEST/RTC  in virt machin
    (0x1000_1000, 0x00_1000), // Virtio Block in virt machine
];

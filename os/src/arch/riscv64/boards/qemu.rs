pub const CLOCK_FREQ: usize = 12500000;
#[cfg(feature = "virt")]
pub const MEMORY_START: usize = 0x0000_0000_9000_0000;
#[cfg(feature = "virt")]
pub const MEMORY_SIZE: usize = 0x3000_0000;
#[cfg(feature = "board")]
pub const MEMORY_START: usize = 0x0000_0000_4000_0000;
#[cfg(feature = "board")]
pub const MEMORY_SIZE: usize = 0x2000_0000;
pub const MEMORY_END: usize = MEMORY_SIZE + MEMORY_START;
// pub const MEMORY_END: usize = 0xB000_0000;

pub const MMIO: &[(usize, usize)] = &[
    (0x0010_0000, 0x00_2000), // VIRT_TEST/RTC in virt machine
    (0x1000_2000, 0x00_1000), // Virtio Block in virt machine
    (0x1010_0000, 0x00_0024), // Goldfish RTC
];
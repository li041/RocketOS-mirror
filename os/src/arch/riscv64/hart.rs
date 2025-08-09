#[cfg(feature = "smp")]
pub fn start_other_harts(hart_id: usize) {
    use crate::arch::{config::MAX_HARTS, sbi::hart_start};
    const KERNEL_START_ADDR: usize = 0x80200000;
    for i in 0..MAX_HARTS {
        if i == hart_id {
            continue;
        }
        println!("Starting hart {}", i);
        hart_start(i, KERNEL_START_ADDR);
    }
}

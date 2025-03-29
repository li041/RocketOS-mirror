use core::arch::asm;


/// 无效所有G=0的页表项(保留G=1的页表项)
pub fn tlb_invalidate() {
    unsafe {
        asm!("invtlb 0x3, $r0, $r0");
    }
}

pub fn tlb_global_invalidate() {
    unsafe {
        asm!("invtlb 0x1, $r0, $r0");
    }
}

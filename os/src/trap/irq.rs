#![allow(unused)]
pub fn close_interrupt() {
    unsafe { riscv::register::sstatus::clear_sie() }
}
pub fn open_interrupt() {
    // info!("open interrupt");
    unsafe {
        riscv::register::sstatus::set_sie();
    }
}

use core::arch::global_asm;

global_asm!(include_str!("trampoline.S"));

extern "C" {
    pub fn sigreturn_trampoline();
}
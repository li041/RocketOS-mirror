use core::arch::global_asm;

pub mod lang_items;
pub mod mm;
pub mod sbi;
pub mod switch;
pub mod timer;
pub mod trap;

global_asm!(include_str!("entry.S"));

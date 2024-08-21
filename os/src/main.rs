#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

#[macro_use]
mod console;
mod sbi;
mod lang_items;
mod trap;
mod loader;
mod mm;

pub mod config;


use core::{arch::global_asm, ffi::c_void, ptr};


global_asm!(include_str!("entry.S"));

/// clear BSS segment
fn clear_bss() {
    extern "C" {
        fn sbss();
        fn ebss();
    }
    unsafe {
        ptr::write_bytes(sbss as *mut c_void, 0, ebss as usize - sbss as usize);
    }
}


#[no_mangle]
pub fn rust_main() -> ! {
    println!("hello world");
    //loader::list_apps();
    mm::init();
    clear_bss();
    panic!("shutdown machine");
}


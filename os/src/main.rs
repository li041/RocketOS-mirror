#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![feature(negative_impls)]
#![feature(panic_info_message)]

extern crate alloc;

#[macro_use]
mod console;
mod boards;
pub mod index_list;
mod lang_items;
mod loader;
mod logging;
mod mm;
pub mod mutex;
mod sbi;
// mod sched;
mod drivers;
mod ext4;
mod fat32;
mod fs;
mod syscall;
mod task;
mod timer;
mod trap;

pub mod config;
pub mod utils;

use drivers::BLOCK_DEVICE;
use ext4::fs::Ext4FileSystem;
use riscv::register::sstatus;
use task::{add_initproc, processor::run_tasks};

use crate::config::KERNEL_BASE;
use core::{
    arch::{asm, global_asm},
    ffi::c_void,
    panic, ptr,
    sync::atomic::AtomicU8,
};

global_asm!(include_str!("entry.S"));
global_asm!(include_str!("link_app.S"));

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
pub extern "C" fn jump_to_app() {
    unsafe {
        asm!("la t0, app_1_start");
        asm!("jalr zero, 0(t0)");
    }
}

#[no_mangle]
pub fn fake_main(hart_id: usize) {
    unsafe {
        asm!("add sp, sp, {}", in(reg) KERNEL_BASE);
        asm!("la t0, rust_main");
        asm!("add t0, t0, {}", in(reg) KERNEL_BASE);
        asm!("mv a0, {}", in(reg) hart_id);
        asm!("jalr zero, 0(t0)");
    }
}

#[allow(unused)]
static DEBUG_FLAG: AtomicU8 = AtomicU8::new(0);

#[no_mangle]
pub fn rust_main(_hart_id: usize) -> ! {
    clear_bss();
    println!("hello world");
    logging::init();
    mm::init();
    trap::init();
    // 允许S mode访问U mode的页面
    //  S mode下会访问User的堆
    unsafe {
        sstatus::set_sum();
    }
    #[cfg(feature = "test")]
    {
        logging::test();
        trap::context::trap_cx_test();
    }
    // Task::new(loader::get_app_data(0));
    // trap_return();
    // task::add_initproc();
    // let elf_data = get_app_data_by_name("forktest_simple").unwrap();
    // let init_proc = Arc::new(Task::new(elf_data));
    show_context_size();
    add_initproc();
    trap::enable_timer_interrupt();
    timer::set_next_trigger();
    let fs = Ext4FileSystem::open(BLOCK_DEVICE.clone());
    panic!("shutdown machine");
    fs::list_apps();
    loader::list_apps();
    // pass block_device_test, 注意实际运行时别调用这个函数, 会覆盖Block内容
    DEBUG_FLAG.store(1, core::sync::atomic::Ordering::SeqCst);
    run_tasks();
    panic!("shutdown machine");
}

pub fn show_context_size() {
    log::info!(
        "size of trap context: {}",
        core::mem::size_of::<trap::context::TrapContext>()
    );
    log::info!(
        "size of task context: {}",
        core::mem::size_of::<task::context::TaskContext>()
    )
}

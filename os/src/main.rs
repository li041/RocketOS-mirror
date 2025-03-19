#![no_std]
#![no_main]
#![feature(map_try_insert)]
#![feature(alloc_error_handler)]
#![feature(negative_impls)]

extern crate alloc;

#[macro_use]
mod console;
#[cfg(target_arch = "riscv64")]
mod boards;
pub mod index_list;
#[cfg(target_arch = "riscv64")]
mod loader;
mod logging;
mod mm;
pub mod mutex;
// mod sched;
mod arch;

#[cfg(target_arch = "riscv64")]
mod drivers;

#[cfg(target_arch = "riscv64")]
mod ext4;

#[cfg(target_arch = "riscv64")]
mod fat32;

#[cfg(target_arch = "riscv64")]
mod fs;

#[cfg(target_arch = "riscv64")]
// 目前只支持riscv64
mod syscall;

#[cfg(target_arch = "riscv64")]
mod task;

pub mod config;
pub mod utils;

use core::{
    arch::{asm, global_asm},
    ffi::c_void,
    panic, ptr,
    sync::atomic::AtomicU8,
};

#[cfg(target_arch = "riscv64")]
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
#[cfg(target_arch = "riscv64")]
pub fn fake_main(hart_id: usize) {
    use config::KERNEL_BASE;
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
#[cfg(target_arch = "riscv64")]
pub fn rust_main(_hart_id: usize) -> ! {
    use arch::trap::{self, TrapContext};
    use riscv::register::sstatus;
    use task::{add_initproc, run_tasks, TaskContext};
    pub fn show_context_size() {
        log::info!(
            "size of trap context: {}",
            core::mem::size_of::<TrapContext>()
        );
        log::info!(
            "size of task context: {}",
            core::mem::size_of::<TaskContext>()
        )
    }

    clear_bss();
    println!("hello world!");
    logging::init();
    arch::mm::init();
    trap::init();
    // 允许S mode访问U mode的页面
    //  S mode下会访问User的堆
    #[cfg(target_arch = "riscv64")]
    unsafe {
        sstatus::set_sum();
    }
    #[cfg(feature = "test")]
    {
        logging::test();
        trap::context::trap_cx_test();
    }
    show_context_size();
    trap::enable_timer_interrupt();
    arch::timer::set_next_trigger();
    add_initproc();
    loader::list_apps();
    DEBUG_FLAG.store(1, core::sync::atomic::Ordering::SeqCst);
    run_tasks();
    panic!("shutdown machine");
}

#[cfg(target_arch = "loongarch64")]
#[no_mangle]
pub fn rust_main() -> ! {
    use arch::{sbi::shutdown, CrMd};
    clear_bss();
    println!("Hello, world!");
    logging::init();
    arch::mm::init();
    // 默认是直接地址映射模式
    log::error!("CRMD: {:?}", CrMd::read());
    shutdown();
}

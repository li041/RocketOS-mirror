#![no_std]
#![no_main]
#![feature(map_try_insert)]
#![feature(alloc_error_handler)]
#![feature(negative_impls)]
#![feature(sync_unsafe_cell)]
#![feature(trait_upcasting)]
#![feature(ip_from)]

extern crate alloc;

#[macro_use]
mod console;
pub mod futex;
pub mod index_list;
mod loader;
mod logging;
mod mm;
pub mod mutex;
pub mod timer;
// mod sched;
mod arch;
mod net;
mod signal;

mod drivers;

mod ext4;

mod fat32;

mod time;
mod fs;

// 目前只支持riscv64
mod syscall;

mod task;

pub mod utils;

use core::{
    arch::{asm, global_asm},
    ffi::c_void,
    panic, ptr,
    sync::atomic::AtomicU8,
};

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
#[link_section = ".text.main"]
pub fn fake_main(hart_id: usize, dtb_address: usize) {
    use arch::config::KERNEL_BASE;
    unsafe {
        asm!("add sp, sp, {}", in(reg) KERNEL_BASE);
        asm!("la t0, rust_main");
        asm!("add t0, t0, {}", in(reg) KERNEL_BASE);
        asm!("mv a0, {}", in(reg) hart_id);
        asm!("mv a1, {}", in(reg) dtb_address);
        asm!("jalr zero, 0(t0)");
    }
}

#[allow(unused)]
static DEBUG_FLAG: AtomicU8 = AtomicU8::new(0);

#[no_mangle]
#[cfg(target_arch = "riscv64")]
pub fn rust_main(_hart_id: usize, dtb_address: usize) -> ! {
    use crate::utils::seconds_to_beijing_datetime;
    use arch::{
        timer::{read_rtc, NANOS_PER_SEC},
        trap::{self, TrapContext},
    };
    use riscv::register::sstatus;
    use task::{add_initproc, run_tasks, TaskContext};
    use xmas_elf::sections;
    pub fn show_context_size() {
        log::error!(
            "size of trap context: {}",
            core::mem::size_of::<TrapContext>()
        );
        log::error!(
            "size of task context: {}",
            core::mem::size_of::<TaskContext>()
        )
    }

    clear_bss();
    logging::init();
    mm::init();
    trap::init();
    let seconds = read_rtc() / NANOS_PER_SEC;
    println!("rtc time: {:?}", seconds);
    println!("data time: {:?}", seconds_to_beijing_datetime(seconds));
    drivers::net::init_net_device(dtb_address);
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
    use arch::{
        bootstrap_init,
        drivers::pci,
        trap::{
            self,
            timer::{enable_timer_interrupt, set_next_trigger},
        },
    };
    use task::{add_initproc, run_tasks};

    clear_bss();
    logging::init();
    bootstrap_init();
    mm::init();
    pci::init();
    trap::init();
    // let time = unsafe { read_ls7a_rtc(LS7A_RTC_BASE as *mut u32) };
    // println!("{:?}", time);
    // time_test();
    enable_timer_interrupt();
    add_initproc();
    loader::list_apps();
    set_next_trigger();
    run_tasks();
    panic!("shutdown machine");
    // shutdown();
}

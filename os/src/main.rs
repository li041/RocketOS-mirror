#![no_std]
#![no_main]
#![feature(map_try_insert)]
#![feature(alloc_error_handler)]
#![feature(negative_impls)]
#![feature(sync_unsafe_cell)]
#![feature(trait_upcasting)]
#![feature(ip_from)]
#![feature(allocator_api)]
#![allow(static_mut_refs)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(unused)]

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
mod drivers;
mod net;
mod signal;

mod ext4;

mod fat32;

mod fs;
mod time;

// 目前只支持riscv64
mod syscall;

mod task;

pub mod utils;

use core::{
    arch::{asm, global_asm},
    ffi::c_void,
    panic, ptr,
    sync::atomic::{AtomicBool, AtomicU8},
};

use fs::dentry::dump_dentry_cache;
use mm::FRAME_ALLOCATOR;
use task::info_allocator;

global_asm!(include_str!("link_app.S"));

/// clear BSS segment
fn clear_bss() {
    extern "C" {
        fn sbss();
        fn ebss();
    }
    // unsafe {
    //     ptr::write_bytes(sbss as *mut c_void, 0, ebss as usize - sbss as usize);
    // }
    unsafe {
        core::slice::from_raw_parts_mut(sbss as usize as *mut u8, ebss as usize - sbss as usize)
            .fill(0);
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

static IS_BOOT: AtomicBool = AtomicBool::new(true);

#[no_mangle]
#[cfg(target_arch = "riscv64")]
pub fn rust_main(hart_id: usize, dtb_address: usize) -> ! {
    use core::sync::atomic::Ordering;

    #[cfg(feature = "smp")]
    use crate::arch::hart::start_other_harts;
    use crate::task::other_initproc;
    use crate::utils::seconds_to_beijing_datetime;
    use arch::{
        config::DTB_BASE,
        timer::{read_rtc, NANOS_PER_SEC},
        trap::{self, TrapContext},
    };
    use drivers::init_device;
    use riscv::register::sstatus;
    use task::{boot_initproc, run_tasks, TaskContext};

    if IS_BOOT
        .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        clear_bss();
        DTB_BASE.lock().replace(dtb_address);
        logging::init();
        mm::init();
        trap::init();
        init_device(dtb_address);

        // let seconds = read_rtc() / NANOS_PER_SEC;
        // println!("rtc time: {:?}", seconds);
        // println!("data time: {:?}", seconds_to_beijing_datetime(seconds));
        // drivers::net::init_net_device(dtb_address);
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
        #[cfg(feature = "smp")]
        start_other_harts(hart_id);
        trap::enable_timer_interrupt();
        arch::timer::set_next_trigger();
        loader::list_apps();
        boot_initproc(hart_id);
        run_tasks(hart_id);
    } else {
        mm::kernel_init();
        trap::init();
        trap::enable_timer_interrupt();
        arch::timer::set_next_trigger();
        other_initproc(hart_id);
        run_tasks(hart_id);
    }
    panic!("shutdown machine");
}

#[cfg(target_arch = "loongarch64")]
#[no_mangle]
pub fn rust_main(hart_id: usize) -> ! {
    #[cfg(feature = "smp")]
    use crate::arch::hart::start_other_harts;
    use core::sync::atomic::Ordering;

    use arch::{
        bootstrap_init,
        config::{PAGE_SIZE, SUC_DMW_VESG},
        drivers::pci,
        sbi::shutdown,
        timer::ls7a_rtc_init,
        trap::{
            self,
            timer::{enable_timer_interrupt, set_next_trigger},
            TrapContext,
        },
        DMW, DMW2, DMW3,
    };
    use task::run_tasks;

    if IS_BOOT
        .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        use crate::task::add_initproc;

        clear_bss();
        logging::init();
        bootstrap_init();
        mm::init();
        #[cfg(feature = "virt")]
        pci::init();
        trap::init();
        #[cfg(feature = "virt")]
        ls7a_rtc_init();
        println!("[kernel] boot hart {}", hart_id);
        #[cfg(feature = "smp")]
        start_other_harts(hart_id);
        enable_timer_interrupt();
        add_initproc(hart_id);
        loader::list_apps();
        set_next_trigger();
        run_tasks(hart_id);
    } else {
        use crate::task::other_initproc;
        bootstrap_init();
        mm::kernel_init();
        trap::init();
        enable_timer_interrupt();
        set_next_trigger();
        other_initproc(hart_id);
        run_tasks(hart_id);
    }
    panic!("shutdown machine");
    // shutdown();
}

pub fn dump_system_info() {
    // frame_allocator位置
    FRAME_ALLOCATOR.lock().info();
    // 栈位置
    // pid分配
    info_allocator();
    // 打印dentry缓存信息
    dump_dentry_cache();
}

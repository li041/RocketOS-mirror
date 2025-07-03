#![allow(unused)]

use embedded_hal::serial::nb::{Read, Write};

use core::{arch::asm, mem::MaybeUninit};

use super::{boards::qemu::UART_BASE, serial::ns16550a::Ns16550a};

pub static mut UART: Ns16550a = Ns16550a { base: UART_BASE };

pub fn console_putchar(c: usize) {
    let mut retry = 0;
    unsafe {
        UART.write(c as u8);
    }
}

pub fn console_flush() {
    unsafe { while UART.flush().is_err() {} }
}

pub fn console_getchar() -> usize {
    unsafe {
        if let Ok(i) = UART.read() {
            return i as usize;
        } else {
            return 1usize.wrapping_neg();
        }
    }
}

pub fn shutdown(fauilure: bool) -> ! {
    println!("Shutdown...");
    // // 电源管理模块设置为s5状态，软关机
    unsafe {
        // (0x100e_001c as *mut u8).write_volatile(0x34);
        ((0x1fe27000+0x14) as *mut u32 ).write_volatile(0b1111<<10);

    }
    panic!("Unreachable in shutdown");
}

//! SBI console driver, for text output
use core::fmt::{self, Write};

use crate::arch::sbi::console_putchar;

struct Stdout;

#[cfg(target_arch = "riscv64")]
impl Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() {
            console_putchar(c as usize);
        }
        Ok(())
    }
}
#[cfg(target_arch = "loongarch64")]
impl Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        use crate::arch::sbi::console_flush;
        let mut i = 0;
        for c in s.chars() {
            console_putchar(c as usize);
            i += 1;
            if i >= 4 {
                console_flush();
                i = 0;
            }
        }
        if i != 0 {
            console_flush();
        }
        Ok(())
    }
}

pub fn print(args: fmt::Arguments) {
    Stdout.write_fmt(args).unwrap();
}

#[macro_export]
/// print string macro
macro_rules! print {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::print(format_args!($fmt $(, $($arg)+)?));
    }
}

#[macro_export]
/// println string macro
macro_rules! println {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::print(format_args!(concat!($fmt, "\n") $(, $($arg)+)?));
    }
}

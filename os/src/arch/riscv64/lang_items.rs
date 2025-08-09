use core::panic::PanicInfo;

use crate::arch::backtrace::backtrace::dump_backtrace;

use super::sbi::shutdown;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    if let Some(location) = info.location() {
        println!(
            "Panicked at {}:{} {:?}",
            location.file(),
            location.line(),
            info.message()
        );
    } else {
        println!("Panicked: {:?}", info.message());
    }
    dump_backtrace();
    shutdown(true);
}

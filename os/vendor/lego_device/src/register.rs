#[macro_export]
macro_rules! reg_map {
    ($( $name:ident $addr:expr ),*) => {
        $(
            pub const $name: usize = $addr;
        )*
    };
}

#[inline(always)]
pub fn read_reg<T>(io_base: usize, reg: usize) -> T {
    let ptr = (io_base + reg) as *mut usize as *const T;
    unsafe { ptr.read_volatile() }
}
#[inline(always)]
pub fn write_reg<T>(io_base: usize, reg: usize, val: T) {
    let ptr = (io_base + reg) as *mut usize as *mut T;
    unsafe {
        ptr.write_volatile(val);
    }
}

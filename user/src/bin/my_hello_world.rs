#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

use user_lib::getpid;

const N: usize = 10;
type Arr = [[i32; N]; N];

#[no_mangle]
pub fn main() -> i32 {
    println!("Hello world from user mode program!");
    let mut arr: Arr = Default::default();
    arr[0][0] = getpid() as i32;
    println!("pid: {}", arr[0][0]);
    0
}

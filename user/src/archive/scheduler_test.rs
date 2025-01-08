#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;
use user_lib::{exit, fork, waitpid, yield_};

macro_rules! color_text {
    ($text:expr, $color:expr) => {{
        format_args!("\x1b[{}m{}\x1b[0m", $color, $text)
    }};
}

const CHILD_NUM: usize = 3;

pub fn child_work(child_num: usize) {
    for j in 0..10 {
        println!(
            "{}",
            color_text!(format_args!("Child {} iteration {}", child_num, j), 33 + child_num as u8)
        );
        yield_();
    }
    exit(0);
}

// You should see output interleaving of different colors
#[no_mangle]
pub fn main() -> i32 {
    let mut child_num = usize::MAX;
    for i in 0..CHILD_NUM {
        let pid = fork();
        if pid == 0 {
            child_num = i;
            break;
        }
    }

    if child_num != usize::MAX {
        child_work(child_num);
    }

    let mut exit_code: i32 = 0;
    for _ in 0..CHILD_NUM {
        waitpid(usize::MAX, &mut exit_code);
    }

    println!("scheduler_test pass.");
    0
}

#![no_std]
#![no_main]
#![allow(clippy::println_empty_string)]

extern crate alloc;

#[macro_use]
extern crate user_lib;

mod shell;

const LF: u8 = 0x0au8;
const CR: u8 = 0x0du8;
const DL: u8 = 0x7fu8;
const BS: u8 = 0x08u8;

const THEME_COLOR: &str = "\u{1B}[38;5;14m";
const RESET_COLOR: &str = "\u{1B}[0m";

use alloc::string::String;
use alloc::vec::Vec;
use shell::command::Command;
use user_lib::console::getchar;
use user_lib::{execve, fork, waitpid};

fn print_prompt() {
    print!("{}RROS>> {}", THEME_COLOR, RESET_COLOR);
}

#[no_mangle]
pub fn main() -> i32 {
    let mut line: String = String::new();
    print_prompt();
    loop {
        let c = getchar();
        match c {
            LF | CR => {
                println!("");
                if !line.is_empty() {
                    let mut cmd = Command::from(line.as_str());
                    let pid = fork();
                    if pid == 0 {
                        cmd.exec();
                    } else {
                        let mut exit_code: i32 = 0;
                        let exit_pid = waitpid(pid as usize, &mut exit_code);
                        println!("pid: {}, exit_pid: {}", pid, exit_pid);
                        assert_eq!(pid, exit_pid);
                        println!("Shell: Process {} exited with code {}", pid, exit_code);
                    }
                    line.clear();
                }
                print_prompt();
            }
            BS | DL => {
                if !line.is_empty() {
                    print!("{}", BS as char);
                    print!(" ");
                    print!("{}", BS as char);
                    line.pop();
                }
            }
            _ => {
                print!("{}", c as char);
                line.push(c as char);
            }
        }
    }
}

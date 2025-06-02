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
use shell::command::parse_pipeline;
use user_lib::console::getchar;
use user_lib::{chdir, close, dup3, fork, pipe, waitpid};

fn print_prompt() {
    let cwd = user_lib::getcwd(); // 假设你有这个系统调用
    print!("{}RROS:{}$ {}", THEME_COLOR, cwd, RESET_COLOR);
}

#[no_mangle]
pub fn main() -> i32 {
    let mut line: String = String::new();
    let mut history: Vec<String> = Vec::new(); // 存储历史命令
    let mut history_index: usize = 0; // 当前显示的历史命令索引
    print_prompt();

    loop {
        let c = getchar();
        match c {
            LF | CR => {
                println!("");
                if !line.is_empty() {
                    // 存入历史
                    history.push(line.clone());
                    history_index = history.len(); // 重置索引到最新

                    // 执行命令
                    if line.starts_with("cd") {
                        let cmds = parse_pipeline(line.as_str());
                        let cmd = &cmds[0];
                        // 如果command是cd的话
                        let args = cmd.get_args();
                        if args.is_empty() {
                            let home_dir = "/\0";
                            if chdir(home_dir) != 0 {
                                println!("cd: failed to change directory to '{}'", home_dir);
                            }
                        } else {
                            // Change to the specified directory
                            let target_dir = &args[0];
                            if chdir(target_dir) != 0 {
                                println!("cd: failed to change directory to '{}'", target_dir);
                            }
                        }
                        line.clear();
                    } else {
                        let cmds = parse_pipeline(line.as_str());
                        if cmds.len() == 1 {
                            let cmd = &cmds[0];
                            let pid = fork();
                            if pid == 0 {
                                cmd.exec();
                            } else {
                                let mut exit_code: i32 = 0;
                                let exit_pid = waitpid(pid, &mut exit_code);
                                println!("pid: {}, exit_pid: {}", pid, exit_pid);
                                assert_eq!(pid, exit_pid);
                                println!("Shell: Process {} exited with code {}", pid, exit_code);
                            }
                        } else {
                            // 多个命令的pipeline情况
                            let mut fds: [i32; 2] = [0; 2];
                            let mut prev_fd_read: Option<usize> = None;

                            for (i, cmd) in cmds.iter().enumerate() {
                                if i != cmds.len() - 1 {
                                    pipe(&mut fds as *mut i32, 0); // 创建一个 pipe
                                }

                                let pid = fork();
                                if pid == 0 {
                                    // 子进程

                                    // 如果有前一个 pipe 的 read 端，就作为 stdin
                                    if let Some(fd_in) = prev_fd_read {
                                        dup3(fd_in, 0, 0);
                                        close(fd_in);
                                    }

                                    // 如果不是最后一个命令，就设置 stdout 为 pipe 的写端
                                    if i != cmds.len() - 1 {
                                        close(fds[0] as usize); // 关闭读端
                                        dup3(fds[1] as usize, 1, 0); // 设置 stdout
                                        close(fds[1] as usize);
                                    }

                                    cmd.exec(); // exec 会自动 exit
                                }

                                // 父进程：关闭已用的 pipe 文件描述符
                                if let Some(fd_in) = prev_fd_read {
                                    close(fd_in);
                                }
                                if i != cmds.len() - 1 {
                                    prev_fd_read = Some(fds[0] as usize);
                                    close(fds[1] as usize);
                                }
                            }

                            // 等待所有子进程
                            for _ in 0..cmds.len() {
                                let mut exit_code: i32 = 0;
                                let pid = waitpid(-1, &mut exit_code);
                                println!("Shell: Process {} exited with code {}", pid, exit_code);
                            }
                        }
                        line.clear();
                    }
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
            // 处理方向键（上键 `ESC [ A`，下键 `ESC [ B`）
            0x1B => {
                // 检查是否是方向键（`ESC [ A` 或 `ESC [ B`）
                let next_c = getchar();
                if next_c == 0x5B {
                    // '['
                    match getchar() {
                        0x41 => {
                            // 上键 'A'
                            if history_index > 0 {
                                history_index -= 1;
                                // 清除当前行并替换为历史命令
                                print!("\x1B[2K\r"); // ANSI 清行
                                print_prompt();
                                line = history[history_index].clone();
                                print!("{}", line);
                            }
                        }
                        0x42 => {
                            // 下键 'B'
                            if history_index < history.len() {
                                history_index += 1;
                                print!("\x1B[2K\r"); // ANSI 清行
                                print_prompt();
                                if history_index < history.len() {
                                    line = history[history_index].clone();
                                } else {
                                    line.clear();
                                }
                                print!("{}", line);
                            }
                        }
                        _ => {} // 其他键忽略
                    }
                }
            }
            _ => {
                print!("{}", c as char);
                line.push(c as char);
            }
        }
    }
}

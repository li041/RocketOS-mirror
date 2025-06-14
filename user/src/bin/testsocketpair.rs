/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-06-11 21:48:02
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-06-11 21:51:53
 * @FilePath: /RocketOS_netperfright/user/src/bin/testsocketpair.rs
 * @Description: 
 * 
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved. 
 */
#![no_std]
#![no_main]

extern crate user_lib;

use core::str;
use user_lib::{fork, wait, socketpair, read, write, close, println, exit};

#[no_mangle]
pub fn main() -> i32 {
    // 创建 UNIX 域套接字对
    let mut fds = [0i32; 2];
    if socketpair(1, 1, 0, fds.as_mut_ptr()) < 0 {
        println!("socketpair() failed");
        exit(-1);
    }

    // 分叉进程
    let pid = fork();
    if pid == 0 {
        // 子进程：使用 fds[1]
        close(fds[0] as usize);
        // 同时发送和接收
        let msg_c2p = b"ping from child";
        if write(fds[1] as usize, msg_c2p) < 0 {
            println!("child write failed");
            exit(-1);
        }
        let mut buf = [0u8; 64];
        let n = read(fds[1] as usize, &mut buf) as usize;
        let s = str::from_utf8(&buf[..n]).unwrap_or("<invalid utf8>");
        println!("child received: {}", s);
        close(fds[1] as usize);
        exit(0);
    } else {
        // 父进程：使用 fds[0]
        close(fds[1] as usize);
        let msg_p2c = b"pong from parent";
        if write(fds[0] as usize, msg_p2c) < 0 {
            println!("parent write failed");
            exit(-1);
        }
        let mut buf = [0u8; 64];
        let n = read(fds[0] as usize, &mut buf) as usize;
        let s = str::from_utf8(&buf[..n]).unwrap_or("<invalid utf8>");
        println!("parent received: {}", s);
        let mut status = 0;
        let _ = wait(&mut status);
        close(fds[0] as usize);
        exit(0);
    }
}

#![no_std]
#![no_main]

extern crate user_lib;

// ltp 暂且没塞
static TEST_LIST: &[&str] = &[
    "basic_testcode.sh\0",
    "busybox_testcode.sh\0",
    // "cyclictest_testcode.sh\0",
    "iozone_testcode.sh\0",
    // "iperf_testcode.sh\0",
    "libcbench_testcode.sh\0",
    "libctest_testcode.sh\0",
    //"lmbench_testcode.sh\0",
    "lua_testcode.sh\0",
    // "netperf_testcode.sh\0",
    // "ltp_testcode.sh\0",
];

mod shell;
use user_lib::{chdir, execve, exit, fork, waitpid};

#[no_mangle]
pub fn main() -> i32 {
    chdir("/glibc\0");
    for app_name in TEST_LIST {
        let pid = fork();
        if pid == 0 {
            execve(&app_name, &[&app_name, "\0"], &["\0"]);
            panic!("unreachable!");
        } else {
            let mut exit_code = 0;
            let _wait_pid = waitpid(pid, &mut exit_code);
        }
    }
    chdir("/musl\0");
    for app_name in TEST_LIST {
        let pid = fork();
        if pid == 0 {
            execve(&app_name, &[&app_name, "\0"], &["\0"]);
            panic!("unreachable!");
        } else {
            let mut exit_code = 0;
            let _wait_pid = waitpid(pid, &mut exit_code);
        }
    }
    return 0;
}

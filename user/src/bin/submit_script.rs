#![no_std]
#![no_main]

extern crate user_lib;

// ltp 暂且没塞
static MUSL_TEST_LIST: &[&str] = &[
    "basic_testcode.sh\0",
    "iozone_testcode.sh\0",
    "busybox_testcode.sh\0",
    "netperf_testcode.sh\0",
    "lua_testcode.sh\0",
    "libcbench_testcode.sh\0",
    "libctest_testcode.sh\0",
    "cyclictest_testcode.sh\0",
    // "ltp_testcode.sh\0",
];

static GLIBC_TEST_LIST: &[&str] = &[
    "basic_testcode.sh\0",
    "iozone_testcode.sh\0",
    "busybox_testcode.sh\0",
    "netperf_testcode.sh\0",
    "lua_testcode.sh\0",
    "libcbench_testcode.sh\0",
    // "libctest_testcode.sh\0",
    "cyclictest_testcode.sh\0",
    // "ltp_testcode.sh\0",
];

static OTHER_TEST_LIST: &[&str] = &[
    "lmbench_testcode.sh\0",
    // "ltp_testcode.sh\0",
];

static LTP_TEST_LIST: &[&str] = &["ltp_testcode.sh\0"];

static LAST_TEST_LIST: &[&str] = &["iperf_testcode.sh\0"];

static FINAL_TEST_LIST: &[&str] = &[
    "interrupts_testcode.sh\0",
    "copy-file-range_testcode.sh\0",
    "splice_testcode.sh\0",
];

mod shell;
use user_lib::{chdir, execve, fork, shutdown, waitpid};

#[no_mangle]
pub fn main() -> i32 {
    chdir("/musl\0");
    for app_name in FINAL_TEST_LIST {
        let pid = fork();
        if pid == 0 {
            execve(&app_name, &[&app_name, "\0"], &["\0"]);
            panic!("unreachable!");
        } else {
            let mut exit_code = 0;
            let _wait_pid = waitpid(pid, &mut exit_code);
        }
    }
    chdir("/glibc\0");
    for app_name in FINAL_TEST_LIST {
        let pid = fork();
        if pid == 0 {
            execve(&app_name, &[&app_name, "\0"], &["\0"]);
            panic!("unreachable!");
        } else {
            let mut exit_code = 0;
            let _wait_pid = waitpid(pid, &mut exit_code);
        }
    }
    // chdir("/musl\0");
    // for app_name in MUSL_TEST_LIST {
    //     let pid = fork();
    //     if pid == 0 {
    //         execve(&app_name, &[&app_name, "\0"], &["\0"]);
    //         panic!("unreachable!");
    //     } else {
    //         let mut exit_code = 0;
    //         let _wait_pid = waitpid(pid, &mut exit_code);
    //     }
    // }
    // chdir("/glibc\0");
    // for app_name in GLIBC_TEST_LIST {
    //     let pid = fork();
    //     if pid == 0 {
    //         execve(&app_name, &[&app_name, "\0"], &["\0"]);
    //         panic!("unreachable!");
    //     } else {
    //         let mut exit_code = 0;
    //         let _wait_pid = waitpid(pid, &mut exit_code);
    //     }
    // }
    // chdir("/musl\0");
    // for app_name in OTHER_TEST_LIST {
    //     let pid = fork();
    //     if pid == 0 {
    //         execve(&app_name, &[&app_name, "\0"], &["\0"]);
    //         panic!("unreachable!");
    //     } else {
    //         let mut exit_code = 0;
    //         let _wait_pid = waitpid(pid, &mut exit_code);
    //     }
    // }
    // chdir("/glibc\0");
    // for app_name in OTHER_TEST_LIST {
    //     let pid = fork();
    //     if pid == 0 {
    //         execve(&app_name, &[&app_name, "\0"], &["\0"]);
    //         panic!("unreachable!");
    //     } else {
    //         let mut exit_code = 0;
    //         let _wait_pid = waitpid(pid, &mut exit_code);
    //     }
    // }
    // chdir("/musl\0");
    // for app_name in LTP_TEST_LIST {
    //     let pid = fork();
    //     if pid == 0 {
    //         execve(&app_name, &[&app_name, "\0"], &["\0"]);
    //         panic!("unreachable!");
    //     } else {
    //         let mut exit_code = 0;
    //         let _wait_pid = waitpid(pid, &mut exit_code);
    //     }
    // }
    // chdir("/glibc\0");
    // for app_name in LTP_TEST_LIST {
    //     let pid = fork();
    //     if pid == 0 {
    //         execve(&app_name, &[&app_name, "\0"], &["\0"]);
    //         panic!("unreachable!");
    //     } else {
    //         let mut exit_code = 0;
    //         let _wait_pid = waitpid(pid, &mut exit_code);
    //     }
    // }
    // chdir("/musl\0");
    // for app_name in LAST_TEST_LIST {
    //     let pid = fork();
    //     if pid == 0 {
    //         execve(&app_name, &[&app_name, "\0"], &["\0"]);
    //         panic!("unreachable!");
    //     } else {
    //         let mut exit_code = 0;
    //         let _wait_pid = waitpid(pid, &mut exit_code);
    //     }
    // }
    // chdir("/glibc\0");
    // for app_name in LAST_TEST_LIST {
    //     let pid = fork();
    //     if pid == 0 {
    //         execve(&app_name, &[&app_name, "\0"], &["\0"]);
    //         panic!("unreachable!");
    //     } else {
    //         let mut exit_code = 0;
    //         let _wait_pid = waitpid(pid, &mut exit_code);
    //     }
    // }
    shutdown();
}

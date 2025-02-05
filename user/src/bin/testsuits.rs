#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

// not in SUCC_TESTS & FAIL_TESTS
// count_lines, infloop, user_shell, usertests

// item of TESTS : app_name(argv_0), argv_1, argv_2, argv_3, exit_code
static SUCC_TESTS: &[(&str, &str, &str, &str, i32)] = &[
    ("brk\0", "\0", "\0", "\0", 0),
    ("chdir\0", "\0", "\0", "\0", 0),
    ("clone\0", "\0", "\0", "\0", 0),
    ("close\0", "\0", "\0", "\0", 0),
    ("dup2\0", "\0", "\0", "\0", 0),
    ("dup\0", "\0", "\0", "\0", 0),
    ("execve\0", "\0", "\0", "\0", 0),
    ("exit\0", "\0", "\0", "\0", 0),
    ("fork\0", "\0", "\0", "\0", 0),
    ("fstat\0", "\0", "\0", "\0", 0),
    ("getcwd\0", "\0", "\0", "\0", 0),
    ("getdents\0", "\0", "\0", "\0", 0),
    ("getpid\0", "\0", "\0", "\0", 0),
    ("getppid\0", "\0", "\0", "\0", 0),
    ("gettimeofday\0", "\0", "\0", "\0", 0),
    ("mkdir_\0", "\0", "\0", "\0", 0),
    ("mmap\0", "\0", "\0", "\0", 0),
    ("mount\0", "\0", "\0", "\0", 0),
    ("munmap\0", "\0", "\0", "\0", 0),
    ("openat\0", "\0", "\0", "\0", 0),
    ("open\0", "\0", "\0", "\0", 0),
    ("pipe\0", "\0", "\0", "\0", 0),
    ("read\0", "\0", "\0", "\0", 0),
    ("times\0", "\0", "\0", "\0", 0),
    ("umount\0", "\0", "\0", "\0", 0),
    ("uname\0", "\0", "\0", "\0", 0),
    ("unlink\0", "\0", "\0", "\0", 0),
    ("wait\0", "\0", "\0", "\0", 0),
    ("waitpid\0", "\0", "\0", "\0", 0),
    ("write\0", "\0", "\0", "\0", 0),
    ("yield\0", "\0", "\0", "\0", 0),
];

static FAIL_TESTS: &[(&str, &str, &str, &str, i32)] = &[];

use user_lib::{execve, fork, waitpid};

fn run_tests(tests: &[(&str, &str, &str, &str, i32)]) -> i32 {
    let mut pass_num = 0;
    let mut arr: [*const u8; 4] = [
        core::ptr::null::<u8>(),
        core::ptr::null::<u8>(),
        core::ptr::null::<u8>(),
        core::ptr::null::<u8>(),
    ];

    for test in tests {
        println!("Usertests: Running {}", test.0);
        arr[0] = test.0.as_ptr();
        if test.1 != "\0" {
            arr[1] = test.1.as_ptr();
            arr[2] = core::ptr::null::<u8>();
            arr[3] = core::ptr::null::<u8>();
            if test.2 != "\0" {
                arr[2] = test.2.as_ptr();
                arr[3] = core::ptr::null::<u8>();
                if test.3 != "\0" {
                    arr[3] = test.3.as_ptr();
                } else {
                    arr[3] = core::ptr::null::<u8>();
                }
            } else {
                arr[2] = core::ptr::null::<u8>();
                arr[3] = core::ptr::null::<u8>();
            }
        } else {
            arr[1] = core::ptr::null::<u8>();
            arr[2] = core::ptr::null::<u8>();
            arr[3] = core::ptr::null::<u8>();
        }

        let pid = fork();
        if pid == 0 {
            // execve(test.0, &[arr.as_str()], &["\0"]);
            execve(test.0, &["\0"], &["\0"]);
            panic!("unreachable!");
        } else {
            let mut exit_code: i32 = Default::default();
            let wait_pid = waitpid(pid as usize, &mut exit_code);
            assert_eq!(pid, wait_pid);
            if exit_code == test.4 {
                // summary apps with  exit_code
                pass_num = pass_num + 1;
            }
            println!(
                "\x1b[32mUsertests: Test {} in Process {} exited with code {}\x1b[0m",
                test.0, pid, exit_code
            );
        }
    }
    pass_num
}

#[no_mangle]
pub fn main() -> i32 {
    let succ_num = run_tests(SUCC_TESTS);
    let err_num = run_tests(FAIL_TESTS);
    if succ_num == SUCC_TESTS.len() as i32 && err_num == FAIL_TESTS.len() as i32 {
        println!(
            "{} of sueecssed apps, {} of failed apps run correctly. \nUsertests passed!",
            SUCC_TESTS.len(),
            FAIL_TESTS.len()
        );
        return 0;
    }
    if succ_num != SUCC_TESTS.len() as i32 {
        println!(
            "all successed app_num is  {} , but only  passed {}",
            SUCC_TESTS.len(),
            succ_num
        );
    }
    if err_num != FAIL_TESTS.len() as i32 {
        println!(
            "all failed app_num is  {} , but only  passed {}",
            FAIL_TESTS.len(),
            err_num
        );
    }
    println!(" Usertests failed!");
    return -1;
}

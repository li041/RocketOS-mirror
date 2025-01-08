use alloc::string::ToString;

use crate::{
    fs::{
        create_dir, inode::InodeMode, open_file, open_inode, path::Path, pipe::Pipe, OpenFlags,
        AT_FDCWD, AT_REMOVEDIR,
    },
    mm::copy_to_user,
    task::current_task,
    timer::TimeSpec,
    utils::c_str_to_string,
};

pub fn sys_read(fd: usize, buf: *mut u8, len: usize) -> isize {
    let task = current_task();
    /* cannot use `inner` as MutexGuard will cross `await` that way */
    let fd_table_len = task.inner_handler(|inner| inner.fd_table.len());
    if fd >= fd_table_len {
        return -1;
    }
    let file = task.inner_handler(|inner| inner.fd_table[fd].clone());
    if let Some(file) = file {
        let file = file.clone();
        if !file.readable() {
            return -1;
        }
        let ret = file.read(unsafe { core::slice::from_raw_parts_mut(buf, len) });
        ret as isize
    } else {
        -1
    }
}

pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    let task = current_task();
    let fd_table_len = task.inner_handler(|inner| inner.fd_table.len());
    if fd >= fd_table_len {
        return -1;
    }
    let file = task.inner_handler(|inner| inner.fd_table[fd].clone());
    if let Some(file) = file {
        if !file.writable() {
            return -1;
        }
        let file = file.clone();
        let ret = file.write(unsafe { core::slice::from_raw_parts(buf as *const u8, len) });
        ret as isize
    } else {
        -1
    }
}

/// 由copy_to_user保证用户指针的合法性
pub fn sys_getcwd(buf: *mut u8, buf_size: usize) -> isize {
    // glibc getcwd(3) says that if buf is NULL, it will allocate a buffer
    let cwd = current_task().inner.lock().cwd.clone();
    let cwd_str = cwd.to_string();
    let copy_len = cwd_str.len() + 1;
    if copy_len > buf_size {
        log::error!("getcwd: buffer is too small");
        // buf太小返回NULL
        return 0;
    }
    let from: *const u8 = cwd_str.as_bytes().as_ptr();
    // 若出错, 打印错误信息
    // if copy_to_user(buf, from, copy_len).is_err() {
    //     log::error!("getcwd: copy_to_user failed");
    //     return 0;
    // }
    if let Err(err) = copy_to_user(buf, from, copy_len) {
        log::error!("getcwd: copy_to_user failed: {}", err);
        return 0;
    }
    // 成功返回buf指针
    buf as isize
}

pub fn sys_mkdirat(dirfd: isize, pathname: *const u8, _mode: usize) -> isize {
    let path = Path::from(c_str_to_string(pathname));
    create_dir(dirfd, &path) as isize
}

pub fn sys_chdir(pathname: *const u8) -> isize {
    let path = Path::from(c_str_to_string(pathname));
    // simply examine validity of the path
    match open_file(AT_FDCWD, &path, OpenFlags::empty()) {
        Ok(inode) => {
            current_task().inner.lock().cwd = inode.get_path();
            0
        }
        Err(_) => -1,
    }
}

pub fn sys_close(fd: usize) -> isize {
    let task = current_task();
    log::trace!("[sys_close] pid: {}, fd: {}", task.tid, fd);
    let mut inner = task.inner.lock();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if inner.fd_table[fd].is_none() {
        return -1;
    }
    inner.fd_table[fd].take();
    0
}

pub fn sys_openat(dirfd: isize, pathname: *const u8, flags: u32, _mode: usize) -> isize {
    log::info!(
        "[sys_openat] pid {} open file: {:?} with flags: {:?}",
        current_task().tid,
        c_str_to_string(pathname),
        flags
    );
    let task = current_task();
    let path = Path::from(c_str_to_string(pathname));
    if let Ok(inode) = open_file(dirfd, &path, OpenFlags::from_bits(flags).unwrap()) {
        let mut inner = task.inner.lock();
        let fd = inner.alloc_fd();
        inner.fd_table[fd] = Some(inode);
        log::info!(
            "[sys_openat] pid {} succeed to open file: {} -> fd: {}",
            task.tid,
            path,
            fd
        );
        fd as isize
    } else {
        log::info!("[sys_openat] pid {} fail to open file: {}", task.tid, path);
        -1
    }
}
#[derive(Debug)]
#[repr(C)]
pub struct Kstat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub __pad1: usize,
    pub st_size: u64,
    pub st_blksize: u32,
    pub __pad2: u32,
    pub st_blocks: u64,
    pub st_atim: TimeSpec,
    pub st_mtim: TimeSpec,
    pub st_ctim: TimeSpec,
}

/// fake
pub fn sys_fstat(_fd: usize, buf: *const u8) -> isize {
    let stat = Kstat {
        st_dev: 0,
        st_ino: 0,
        st_mode: 0,
        st_nlink: 1,
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        __pad1: 0,
        st_size: 28,
        st_blksize: 0,
        __pad2: 0,
        st_blocks: 0,
        st_atim: TimeSpec::new(),
        st_mtim: TimeSpec::new(),
        st_ctim: TimeSpec::new(),
    };
    let kstat_ptr = buf as *mut Kstat;
    unsafe {
        core::ptr::write(kstat_ptr, stat);
    }
    0
}

/// fake
pub fn sys_getdents64(_fd: usize, buf: *const u8, len: usize) -> isize {
    let slice = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len) };
    let dent = "12345678123456781211";
    slice[..20].copy_from_slice(dent.as_bytes());
    2
}

pub fn sys_dup(fd: usize) -> isize {
    let task = current_task();
    task.inner_handler(|inner| {
        if inner.fd_table.len() <= fd {
            return -1;
        }
        inner.fd_table[fd]
            .clone()
            .map(|file| {
                let new_fd = inner.alloc_fd();
                inner.fd_table[new_fd] = Some(file);
                new_fd as isize
            })
            .unwrap_or(-1)
    })
}

pub fn sys_dup3(oldfd: usize, newfd: usize) -> isize {
    let task = current_task();
    task.inner_handler(|inner| {
        if inner.fd_table.len() <= oldfd {
            return -1;
        }
        inner.fd_table[oldfd]
            .clone()
            .map(|file| {
                inner.reserve_fd(newfd);
                inner.fd_table[newfd] = Some(file);
                newfd as isize
            })
            .unwrap_or(-1)
    })
}

pub fn sys_unlinkat(dirfd: isize, pathname: *const u8, flags: u32) -> isize {
    let path = Path::from(c_str_to_string(pathname));
    match open_inode(dirfd, &path, OpenFlags::empty()) {
        Ok(inode) => {
            let mode = inode.get_meta().mode;
            if mode == InodeMode::FileREG || (mode == InodeMode::FileDIR && flags == AT_REMOVEDIR) {
                inode.delete();
                0
            } else {
                -1
            }
        }
        Err(_) => -1,
    }
}

pub fn sys_pipe2(fdset: *const u8) -> isize {
    let task = current_task();
    let pipe_pair = Pipe::new_pair();
    let fdret = task.inner_handler(|inner| {
        let fd1 = inner.alloc_fd();
        inner.fd_table[fd1] = Some(pipe_pair.0.clone());
        let fd2 = inner.alloc_fd();
        inner.fd_table[fd2] = Some(pipe_pair.1.clone());
        (fd1, fd2)
    });
    /* the FUCKING user fd is `i32` type! */
    let fdret: [i32; 2] = [fdret.0 as i32, fdret.1 as i32];
    let fdset_ptr = fdset as *mut [i32; 2];
    unsafe {
        core::ptr::write(fdset_ptr, fdret);
    }
    0
}
/// fake
pub fn sys_mount() -> isize {
    0
}
/// fake
pub fn sys_umount2() -> isize {
    0
}

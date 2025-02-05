use alloc::{string::String, vec};

use alloc::string::ToString;
use xmas_elf::header::parse_header;

use crate::{
    ext4::{self, inode::S_IFDIR},
    fs::{
        dentry::{delete_dentry, LinuxDirent64},
        file::File,
        kstat::Stat,
        mount::{do_mount, ext4_list_apps},
        namei::{filename_create, filename_lookup, path_openat, Nameidata},
        path::Path,
        pipe::Pipe,
        uio::IoVec,
        AT_FDCWD,
    },
    mm::copy_to_user,
    task::current_task,
    utils::c_str_to_string,
};

pub fn sys_read(fd: usize, buf: *mut u8, len: usize) -> isize {
    let task = current_task();
    let file = task.fd_table().get_file(fd);
    if let Some(file) = file {
        let file = file.clone();
        if !file.readable() {
            return -1;
        }
        let ret = file.read(unsafe { core::slice::from_raw_parts_mut(buf, len) });
        if fd >= 3 {
            log::info!("sys_read: fd: {}, len: {}, ret: {}", fd, len, ret);
        }
        ret as isize
    } else {
        -1
    }
}

pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    if fd > 3 {
        log::info!("sys_write: fd: {}, len: {}", fd, len);
    }
    let task = current_task();
    let file = task.fd_table().get_file(fd);
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

pub fn sys_writev(fd: usize, iov: *const IoVec, iovcnt: usize) -> isize {
    if fd > 3 {
        log::info!("sys_writev: fd: {}, iovcnt: {}", fd, iovcnt);
    }
    let task = current_task();
    let file = task.fd_table().get_file(fd);
    if file.is_none() {
        return -1;
    }
    let file = file.unwrap();
    if !file.writable() {
        return -1;
    }
    let mut total_written = 0isize;
    for i in 0..iovcnt {
        let iovec = unsafe { &*iov.add(i) };
        let buf = unsafe { core::slice::from_raw_parts(iovec.base as *const u8, iovec.len) };
        let written = file.write(buf);
        // 如果写入失败, 则返回已经写入的字节数, 或错误码
        if written == 0 {
            return if total_written > 0 {
                total_written
            } else {
                written as isize
            };
        }
        total_written += written as isize;
    }
    total_written
}

pub fn sys_dup(oldfd: usize) -> isize {
    let task = current_task();
    let file = task.fd_table().get_file(oldfd);
    if let Some(file) = file {
        let file = file.clone();
        let newfd = task.fd_table().alloc_fd(file);
        newfd as isize
    } else {
        -1
    }
}

/// 如果`oldfd == newfd`, 则不进行任何操作, 返回`newfd`
/// 如果`newfd`已经打开, 则关闭`newfd`, 再分配, 关闭newfd中出现的错误不会影响sys_dup2
pub fn sys_dup2(oldfd: usize, newfd: usize) -> isize {
    let task = current_task();
    if oldfd == newfd {
        return newfd as isize;
    }
    let file = task.fd_table().get_file(oldfd);
    if let Some(file) = file {
        let file = file.clone();
        let fd_table = task.fd_table();
        fd_table.close(newfd);
        if fd_table.insert(newfd, file).is_some() {
            log::warn!("sys_dup2: newfd {} already opened", newfd);
        }
        newfd as isize
    } else {
        -1
    }
}

pub fn sys_unlinkat(dirfd: i32, pathname: *const u8, flag: i32) -> isize {
    let path = c_str_to_string(pathname);
    log::info!(
        "[sys_unlinkat] dirfd: {}, pathname: {:?}, flag: {}",
        dirfd,
        path,
        flag
    );
    let mut nd = Nameidata::new(&path, dirfd);
    let fake_lookup_flags = 0;
    match filename_lookup(&mut nd, fake_lookup_flags) {
        Ok(dentry) => {
            assert!(!dentry.is_negative());
            let parent_inode = nd.dentry.get_inode();
            parent_inode.unlink(dentry.clone());
            // 从dentry cache中删除
            delete_dentry(dentry);
            // Debug Ok
            // ext4_list_apps(parent_inode);
            return 0;
        }
        Err(e) => {
            log::info!("[sys_unlinkat] fail to unlink: {}, {}", path, e);
            return -1;
        }
    }
}

pub fn sys_linkat(
    olddirfd: i32,
    oldpath: *const u8,
    newdirfd: i32,
    newpath: *const u8,
    flags: i32,
) -> isize {
    let oldpath = c_str_to_string(oldpath);
    let newpath = c_str_to_string(newpath);
    log::info!(
        "[sys_linkat] olddirfd: {}, oldpath: {:?}, newdirfd: {}, newpath: {:?}, flags: {}",
        olddirfd,
        oldpath,
        newdirfd,
        newpath,
        flags
    );
    let mut old_nd = Nameidata::new(&oldpath, olddirfd);
    let old_fake_lookup_flags = 0;
    match filename_lookup(&mut old_nd, old_fake_lookup_flags) {
        Ok(old_dentry) => {
            let mut new_nd = Nameidata::new(&newpath, newdirfd);
            let new_fake_lookup_flags = 0;
            match filename_create(&mut new_nd, new_fake_lookup_flags) {
                Ok(new_dentry) => {
                    let parent_inode = new_nd.dentry.get_inode();
                    parent_inode.link(old_dentry, new_dentry);
                    // Debug Ok
                    // ext4_list_apps();
                    return 0;
                }
                Err(e) => {
                    log::info!("[sys_linkat] fail to create link: {}, {}", newpath, e);
                    -1
                }
            }
        }
        Err(e) => {
            log::info!("[sys_linkat] fail to lookup link: {}, {}", oldpath, e);
            -1
        }
    }
}

/// mode是直接传递给ext4_create, 由其处理(仅当O_CREAT设置时有效, 指定inode的权限)
/// flags影响文件的打开, 在flags中指定O_CREAT, 则创建文件
pub fn sys_openat(dirfd: i32, pathname: *const u8, flags: usize, mode: usize) -> isize {
    log::info!(
        "[sys_openat] dirfd: {}, pathname: {:?}, flags: {}, mode: {}",
        dirfd,
        pathname,
        flags,
        mode
    );
    let task = current_task();
    let path = c_str_to_string(pathname);
    if let Ok(file) = path_openat(&path, flags, dirfd, mode) {
        let fd = task.fd_table().alloc_fd(file);
        log::info!("[sys_openat] success to open file: {}, fd: {}", path, fd);
        // Debug Ok
        // ext4_list_apps(current_task().get_root().dentry.get_inode());
        return fd as isize;
    } else {
        log::info!("[sys_openat] fail to open file: {}", path);
        -1
    }
}

pub fn sys_mkdirat(dirfd: isize, pathname: *const u8, mode: usize) -> isize {
    log::info!(
        "[sys_mkdirat] dirfd: {}, pathname: {:?}, mode: {}",
        dirfd,
        pathname,
        mode
    );
    let path = c_str_to_string(pathname);
    let mut nd = Nameidata::new(&path, dirfd as i32);
    let fake_lookup_flags = 0;
    match filename_create(&mut nd, fake_lookup_flags) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.mkdir(dentry, mode as u16 | S_IFDIR);
            // Debug Ok
            // ext4_list_apps();
            return 0;
        }
        Err(e) => {
            log::info!("[sys_mkdirat] fail to create dir: {}, {}", path, e);
            -1
        }
    }
}

/// 由copy_to_user保证用户指针的合法性
/// 返回的是绝对路径
pub fn sys_getcwd(buf: *mut u8, buf_size: usize) -> isize {
    // glibc getcwd(3) says that if buf is NULL, it will allocate a buffer
    // let cwd = current_task().inner.lock().cwd.clone();
    let mut cwd = current_task().pwd().dentry.absolute_path.clone();
    // 特殊处理根目录, 因为根目录的路径是空字符串
    if cwd.is_empty() {
        cwd = "/".to_string();
    }
    let copy_len = cwd.len();
    if copy_len > buf_size {
        log::error!("getcwd: buffer is too small");
        // buf太小返回NULL
        return 0;
    }
    let from: *const u8 = cwd.as_bytes().as_ptr();
    if let Err(err) = copy_to_user(buf, from, copy_len) {
        log::error!("getcwd: copy_to_user failed: {}", err);
        return 0;
    }
    // 成功返回buf指针
    buf as isize
}

// 仅仅是根据初赛的文档要求, 后续需要根据man7修改
pub fn sys_fstat(dirfd: i32, statbuf: *mut Stat) -> isize {
    if let Some(file_dyn) = current_task().fd_table().get_file(dirfd as usize) {
        // let file = file_dyn.as_any().downcast_ref::<File>().unwrap();
        match file_dyn.as_any().downcast_ref::<File>() {
            Some(file) => {
                let inode = file.inner_handler(|inner| inner.inode.clone());
                let stat = Stat::from(inode.getattr());
                if let Err(e) = copy_to_user(statbuf, &stat as *const Stat, 1) {
                    log::error!("fstat: copy_to_user failed: {}", e);
                    return -1;
                }
                return 0;
            }
            None => {
                log::error!("fstat: downcast_ref failed");
                return -1;
            }
        }
    }
    // 根据fd获取文件失败
    return -1;
}

pub const AT_EMPTY_PATH: i32 = 0x1000;

pub fn sys_fstatat(dirfd: i32, pathname: *const u8, statbuf: *mut Stat, flags: i32) -> isize {
    if flags & AT_EMPTY_PATH != 0 {
        return sys_fstat(dirfd, statbuf);
    }
    let path = c_str_to_string(pathname);
    if path.is_empty() {
        log::error!("[sys_fstatat] pathname is empty");
        let slice = unsafe { core::slice::from_raw_parts(pathname, 100) };
        log::error!("{:?}", String::from_utf8_lossy(slice));
        return -1;
    }
    log::info!(
        "[sys_fstatat] dirfd: {}, pathname: {:?}, flags: {}",
        dirfd,
        path,
        flags
    );
    let mut nd = Nameidata::new(&path, dirfd);
    let fake_lookup_flags = 0;
    match filename_lookup(&mut nd, fake_lookup_flags) {
        Ok(dentry) => {
            let inode = dentry.get_inode();
            let stat = Stat::from(inode.getattr());
            if let Err(e) = copy_to_user(statbuf, &stat as *const Stat, 1) {
                log::error!("fstatat: copy_to_user failed: {}", e);
                return -1;
            }
            return 0;
        }
        Err(e) => {
            log::info!("[sys_fstatat] fail to fstatat: {}, {}", path, e);
            return -1;
        }
    }
}

pub fn sys_getdents64(fd: usize, dirp: *mut u8, count: usize) -> isize {
    log::info!(
        "[sys_getdents64] fd: {}, dirp: {:?}, count: {}",
        fd,
        dirp,
        count
    );
    let task = current_task();
    if let Some(file_dyn) = task.fd_table().get_file(fd as usize) {
        if let Some(file) = file_dyn.as_any().downcast_ref::<File>() {
            let mut buf = vec![0u8; count];
            match file.readdir() {
                Ok(dirents) => {
                    let mut offset = 0;
                    for dirent in dirents {
                        // log::error!("dirent_name: {}", String::from_utf8_lossy(&dirent.d_name));
                        let dirent_size = dirent.d_reclen as usize;
                        log::warn!("dirent_size: {}", dirent_size);
                        if offset + dirent_size > count {
                            break;
                        }
                        dirent.write_to_mem(&mut buf[offset..offset + dirent_size]);
                        offset += dirent_size;
                    }

                    if let Err(e) = copy_to_user(dirp, buf.as_ptr(), offset) {
                        log::error!("getdents64: copy_to_user failed: {}", e);
                        return -1;
                    }
                    return offset as isize;
                }
                Err(e) => {
                    log::error!("getdents64: readdir failed: {}", e);
                    return -1;
                }
            }
        }
    }
    -1
}

pub fn sys_chdir(pathname: *const u8) -> isize {
    let path = c_str_to_string(pathname);
    let mut nd = Nameidata::new(&path, AT_FDCWD);
    let fake_lookup_flags = 0;
    match filename_lookup(&mut nd, fake_lookup_flags) {
        Ok(dentry) => {
            current_task().set_pwd(Path::new(nd.mnt, dentry));
            0
        }
        Err(e) => {
            log::info!("[sys_chdir] fail to chdir: {}, {}", path, e);
            -1
        }
    }
}

// Todo: 直接往用户地址空间写入, 没有检查
pub fn sys_pipe2(fdset: *const u8) -> isize {
    let task = current_task();
    let pipe_pair = Pipe::new_pair();
    let fd_table = task.fd_table();
    let fd1 = fd_table.alloc_fd(pipe_pair.0.clone());
    let fd2 = fd_table.alloc_fd(pipe_pair.1.clone());
    let pipe = [fd1 as i32, fd2 as i32];
    let fdset_ptr = fdset as *mut [i32; 2];
    // unsafe {
    //     core::ptr::write(fdset_ptr, pipe);
    // }
    copy_to_user(
        fdset_ptr as *mut u8,
        pipe.as_ptr() as *const u8,
        2 * core::mem::size_of::<i32>(),
    )
    .unwrap();
    0
}

pub fn sys_close(fd: usize) -> isize {
    log::info!("[sys_close] fd: {}", fd);
    let task = current_task();
    let fd_table = task.fd_table();
    if fd_table.close(fd) {
        0
    } else {
        -1
    }
}

/* Todo: fake  */
pub fn sys_mount(
    source: *const u8,
    target: *const u8,
    fs_type: *const u8,
    flags: usize,
    _data: *const u8,
) -> isize {
    let source = c_str_to_string(source);
    let target = c_str_to_string(target);
    let fs_type = c_str_to_string(fs_type);
    log::info!(
        "[sys_mount] source: {:?}, target: {:?}, fs: {:?}, flags: {}",
        source,
        target,
        fs_type,
        flags
    );
    do_mount(source, target, fs_type, flags, _data)
}

// 用户程序target传的参数是0?
pub fn sys_umount2(target: *const u8, flags: i32) -> isize {
    // let target = c_str_to_string(target);
    // log::info!("[sys_unmount] target: {:?}, flags: {}", target, flags);
    log::info!("[sys_unmount] target: {:?}, flags: {}", target, flags);
    0
}

// 表示无效的文件描述符, Bad file descriptor
const EBADF: isize = 9;
/// op是与设备相关的操作码, arg_ptr是指向参数的指针(untyped pointer, 由设备决定)
pub fn sys_ioctl(fd: usize, op: usize, arg_ptr: usize) -> isize {
    log::error!("[sys_ioctl] fd: {}, op: {}, arg_ptr: {}", fd, op, arg_ptr);
    let task = current_task();
    let file = task.fd_table().get_file(fd);
    if let Some(file) = file {
        return file.ioctl(op, arg_ptr);
    }
    return -EBADF;
}

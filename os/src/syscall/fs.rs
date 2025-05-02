use core::{mem, panic, time};

use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{string::String, vec};

use alloc::string::ToString;
use xmas_elf::header::parse_header;

use crate::arch::timer::{get_time_ms, TimeSpec};
use crate::fs::fdtable::FdFlags;
use crate::fs::file::OpenFlags;
use crate::fs::kstat::Statx;
use crate::fs::mount::get_mount_by_dentry;
use crate::fs::namei::lookup_dentry;
use crate::fs::pipe::make_pipe;
use crate::fs::uapi::{DevT, PollEvents, PollFd, RenameFlags, StatFs, UtimenatFlags, Whence};
use crate::signal::{Sig, SigSet};
use crate::syscall::errno::Errno;
use crate::task::yield_current_task;
use crate::{
    ext4::{self, inode::S_IFDIR},
    fs::{
        dentry::{delete_dentry, LinuxDirent64},
        file::File,
        kstat::Stat,
        mount::do_mount,
        namei::{filename_create, filename_lookup, path_openat, Nameidata},
        path::Path,
        pipe::Pipe,
        uapi::IoVec,
        AT_FDCWD,
    },
    task::current_task,
    utils::c_str_to_string,
};

use crate::arch::mm::{copy_from_user, copy_to_user};

use super::errno::SyscallRet;

pub fn sys_lseek(fd: usize, offset: isize, whence: usize) -> SyscallRet {
    // log::info!(
    //     "[sys_lseek] fd: {}, offset: {}, whence: {}",
    //     fd,
    //     offset,
    //     whence
    // );
    let task = current_task();
    let file = task.fd_table().get_file(fd);
    let whence = Whence::try_from(whence).unwrap_or(Whence::SeekSet);
    if let Some(file) = file {
        let file = file.clone();
        file.seek(offset, whence)
    } else {
        log::error!("[sys_lseek] fd {} not opened", fd);
        Err(Errno::EBADF)
    }
}

// #[cfg(target_arch = "riscv64")]
pub fn sys_read(fd: usize, buf: *mut u8, len: usize) -> SyscallRet {
    // if fd >= 3 {
    //     log::info!("sys_read: fd: {}, len: {}", fd, len);
    // }
    let task = current_task();
    let file = task.fd_table().get_file(fd);
    if let Some(file) = file {
        let file = file.clone();
        if !file.readable() {
            return Err(Errno::EBADF);
        }
        // let ret = file.read(unsafe { core::slice::from_raw_parts_mut(buf, len) });
        let mut ker_buf = vec![0u8; len];
        let read_len = file.read(&mut ker_buf);
        let ker_buf_ptr = ker_buf.as_ptr();
        // assert!(ker_buf_ptr != core::ptr::null());
        // 写回用户空间
        copy_to_user(buf, ker_buf_ptr, read_len as usize)
    } else {
        log::error!("[sys_read] fd {} not opened", fd);
        Err(Errno::EBADF)
    }
}

// #[cfg(target_arch = "loongarch64")]
// pub fn sys_read(fd: usize, buf: *mut u8, len: usize) -> SyscallRet {
//     use crate::mm::VirtAddr;
//     log::trace!("[sys_read]");
//     let task = current_task();
//     let file = task.fd_table().get_file(fd);
//     if let Some(file) = file {
//         let file = file.clone();
//         if !file.readable() {
//             return Err(Errno::EBADF);
//         }
//         let buf = current_task().op_memory_set(|memory_set| {
//             memory_set
//                 .translate_va_to_pa(VirtAddr::from(buf as usize))
//                 .unwrap()
//         });
//         let ret = file.read(unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len) });
//         // ToOptimize:
//         // if fd >= 3 {
//         //     log::info!("sys_read: fd: {}, len: {}, ret: {}", fd, len, ret);
//         // }
//         Ok(ret)
//     } else {
//         log::error!("[sys_read] fd {} not opened", fd);
//         Err(Errno::EBADF)
//     }
// }

#[no_mangle]
pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> SyscallRet {
    if len == 0 {
        return Ok(0);
    }
    // if fd >= 3 {
    //     log::info!("sys_write: fd: {}, len: {}", fd, len);
    // }
    let task = current_task();
    let file = task.fd_table().get_file(fd);
    if let Some(file) = file {
        if !file.writable() {
            return Err(Errno::EBADF);
        }
        let file = file.clone();
        let mut ker_buf = vec![0u8; len];
        copy_from_user(buf, ker_buf.as_mut_ptr(), len).unwrap();
        let ret = file.write(&ker_buf);
        Ok(ret)
    } else {
        log::error!("[sys_write] fd {} not opened", fd);
        Err(Errno::EBADF)
    }
}

pub fn sys_readv(fd: usize, iov_ptr: *const IoVec, iovcnt: usize) -> SyscallRet {
    if fd > 3 {
        log::info!("sys_readv: fd: {}, iovcnt: {}", fd, iovcnt);
    }
    let task = current_task();
    let file = task.fd_table().get_file(fd);
    if file.is_none() {
        return Err(Errno::EBADF);
    }
    let file = file.unwrap();
    if !file.readable() {
        return Err(Errno::EBADF);
    }
    let mut total_read = 0;
    let mut iov: Vec<IoVec> = vec![IoVec::default(); iovcnt];
    copy_from_user(iov_ptr, iov.as_mut_ptr(), iovcnt).unwrap();
    for iovec in iov.iter() {
        if iovec.len == 0 {
            continue;
        }
        // let buf = copy_from_user_mut(iovec.base as *mut u8, iovec.len).unwrap();
        let mut ker_buf = vec![0u8; iovec.len];
        let read = file.read(&mut ker_buf);
        copy_to_user(iovec.base as *mut u8, ker_buf.as_ptr(), read).unwrap();
        // 如果读取失败, 则返回已经读取的字节数, 或错误码
        if read == 0 {
            return if total_read > 0 {
                Ok(total_read)
            } else {
                Ok(read)
            };
        }
        total_read += read;
    }
    Ok(total_read)
}

pub fn sys_writev(fd: usize, iov_ptr: *const IoVec, iovcnt: usize) -> SyscallRet {
    // log::trace!("[sys_writev]");
    // if fd >= 3 {
    log::info!("sys_writev: fd: {}, iovcnt: {}", fd, iovcnt);
    // }
    let task = current_task();
    let file = task.fd_table().get_file(fd);
    if file.is_none() {
        return Err(Errno::EBADF);
    }
    let file = file.unwrap();
    if !file.writable() {
        return Err(Errno::EBADF);
    }
    let mut total_written = 0;
    let mut iov: Vec<IoVec> = vec![IoVec::default(); iovcnt];
    copy_from_user(iov_ptr, iov.as_mut_ptr(), iovcnt).unwrap();
    for iovec in iov.iter() {
        if iovec.len == 0 {
            continue;
        }
        let mut ker_buf = vec![0u8; iovec.len];
        copy_from_user(iovec.base as *const u8, ker_buf.as_mut_ptr(), iovec.len)?;
        let written = file.write(&ker_buf);
        // 如果写入失败, 则返回已经写入的字节数, 或错误码
        if written == 0 {
            return if total_written > 0 {
                Ok(total_written)
            } else {
                Ok(written)
            };
        }
        total_written += written;
    }
    Ok(total_written)
}

pub fn sys_pread(fd: usize, buf: *mut u8, count: usize, offest: usize) -> SyscallRet {
    log::info!(
        "[sys_pread] fd: {}, buf: {:?}, count: {}, offset: {}",
        fd,
        buf,
        count,
        offest
    );
    let task = current_task();
    let file = task.fd_table().get_file(fd as usize);
    if let Some(file) = file {
        let file = file.clone();
        if !file.readable() {
            return Err(Errno::EBADF);
        }
        let mut ker_buf = vec![0u8; count];
        let read_len = file.pread(&mut ker_buf, offest);
        let ker_buf_ptr = ker_buf.as_ptr();
        // 写回用户空间
        copy_to_user(buf, ker_buf_ptr, read_len as usize)
    } else {
        log::error!("[sys_pread] fd {} not opened", fd);
        Err(Errno::EBADF)
    }
}

pub fn sys_pwrite(fd: usize, buf: *const u8, count: usize, offest: usize) -> SyscallRet {
    log::info!(
        "[sys_pwrite] fd: {}, buf: {:?}, count: {}, offset: {}",
        fd,
        buf,
        count,
        offest
    );
    let task = current_task();
    let file = task.fd_table().get_file(fd as usize);
    if let Some(file) = file {
        if !file.writable() {
            return Err(Errno::EBADF);
        }
        let mut ker_buf = vec![0u8; count];
        copy_from_user(buf, ker_buf.as_mut_ptr(), count).unwrap();
        Ok(file.pwrite(&ker_buf, offest))
    } else {
        log::error!("[sys_pwrite] fd {} not opened", fd);
        Err(Errno::EBADF)
    }
}

/// 注意Fd_flags并不会在dup中继承
pub fn sys_dup(oldfd: usize) -> SyscallRet {
    log::info!("[sys_dup] oldfd: {}", oldfd);
    let task = current_task();
    // let file = task.fd_table().get_file(oldfd);
    let fd_entry = task.fd_table().get_fdentry(oldfd);
    if let Some(fd_entry) = fd_entry {
        task.fd_table()
            .alloc_fd(fd_entry.get_file(), FdFlags::empty())
    } else {
        return Err(Errno::EBADF);
    }
}

/// 如果`oldfd == newfd`, 则不进行任何操作, 返回`newfd`
/// 如果`newfd`已经打开, 则关闭`newfd`, 再分配, 关闭newfd中出现的错误不会影响sys_dup2
///
pub fn sys_dup3(oldfd: usize, newfd: usize, flags: i32) -> SyscallRet {
    log::info!(
        "[sys_dup3] oldfd: {}, newfd: {}, flags: {}",
        oldfd,
        newfd,
        flags
    );
    let task = current_task();
    let flags = OpenFlags::from_bits(flags).unwrap();
    if oldfd == newfd {
        return Ok(newfd);
    }
    let fd_entry = task.fd_table().get_fdentry(oldfd);
    if let Some(fd_entry) = fd_entry {
        let fd_table = task.fd_table();
        fd_table.close(newfd);
        if fd_table
            .insert(newfd, fd_entry.get_file(), FdFlags::from(&flags))
            .is_some()
        {
            log::warn!("sys_dup2: newfd {} already opened", newfd);
        }
        return Ok(newfd);
    } else {
        log::error!("sys_dup2: oldfd {} not opened", oldfd);
        return Err(Errno::EBADF);
    }
}

pub fn sys_unlinkat(dirfd: i32, pathname: *const u8, flag: i32) -> SyscallRet {
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
            return Ok(0);
        }
        Err(e) => {
            return Err(e);
        }
    }
}

/// 创建硬链接
pub fn sys_linkat(
    olddirfd: i32,
    oldpath: *const u8,
    newdirfd: i32,
    newpath: *const u8,
    flags: i32,
) -> SyscallRet {
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
                    return Ok(0);
                }
                Err(e) => {
                    log::info!("[sys_linkat] fail to create link: {}, {:?}", newpath, e);
                    return Err(e);
                }
            }
        }
        Err(e) => {
            log::info!("[sys_linkat] fail to lookup link: {}, {:?}", oldpath, e);
            return Err(e);
        }
    }
}

/// mode是直接传递给ext4_create, 由其处理(仅当O_CREAT设置时有效, 指定inode的权限)
/// flags影响文件的打开, 在flags中指定O_CREAT, 则创建文件
pub fn sys_openat(dirfd: i32, pathname: *const u8, flags: i32, mode: usize) -> SyscallRet {
    log::info!(
        "[sys_openat] dirfd: {}, pathname: {:?}, flags: {:?}, mode: {}",
        dirfd,
        pathname,
        flags,
        mode
    );
    let flags = OpenFlags::from_bits(flags).unwrap();
    let task = current_task();
    let path = c_str_to_string(pathname);
    if let Ok(file) = path_openat(&path, flags, dirfd, mode) {
        let fd_flags = FdFlags::from(&flags);
        task.fd_table().alloc_fd(file, fd_flags)
    } else {
        log::info!("[sys_openat] fail to open file: {}", path);
        return Err(Errno::ENOENT);
    }
}

/// mode是inode类型+文件权限
pub fn sys_mknodat(dirfd: i32, pathname: *const u8, mode: usize, dev: u64) -> SyscallRet {
    log::info!(
        "[sys_mknodat] dirfd: {}, pathname: {:?}, mode: {}, dev: {}",
        dirfd,
        pathname,
        mode,
        dev
    );
    let path = c_str_to_string(pathname);
    let mut nd = Nameidata::new(&path, dirfd);
    let fake_lookup_flags = 0;
    match filename_create(&mut nd, fake_lookup_flags) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.mknod(dentry, mode as u16, DevT::new(dev));
            return Ok(0);
        }
        Err(e) => {
            log::info!("[sys_mknodat] fail to create file: {}, {:?}", path, e);
            return Err(e);
        }
    }
}

pub fn sys_mkdirat(dirfd: isize, pathname: *const u8, mode: usize) -> SyscallRet {
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
            return Ok(0);
        }
        Err(e) => {
            log::info!("[sys_mkdirat] fail to create dir: {}, {:?}", path, e);
            return Err(e);
        }
    }
}

/// 由copy_to_user保证用户指针的合法性
/// 返回的是绝对路径
pub fn sys_getcwd(buf: *mut u8, buf_size: usize) -> SyscallRet {
    // glibc getcwd(3) says that if buf is NULL, it will allocate a buffer
    log::info!("[sys_getcwd] buf: {:?}, buf_size: {}", buf, buf_size);
    let mut cwd = current_task().pwd().dentry.absolute_path.clone();
    // 特殊处理根目录, 因为根目录的路径是空字符串
    if cwd.is_empty() {
        cwd = "/".to_string();
    }
    let copy_len = cwd.len();
    if copy_len > buf_size {
        log::error!("getcwd: buffer is too small");
        // buf太小返回NULL
        return Err(Errno::ENAMETOOLONG);
    }
    let from: *const u8 = cwd.as_bytes().as_ptr();
    if let Err(err) = copy_to_user(buf, from, copy_len) {
        log::error!("getcwd: copy_to_user failed: {:?}", err);
        return Err(err);
    }
    // 成功返回buf指针
    Ok(buf as usize)
}

// 仅仅是根据初赛的文档要求, 后续需要根据man7修改
pub fn sys_fstat(dirfd: i32, statbuf: *mut Stat) -> SyscallRet {
    if let Some(file) = current_task().fd_table().get_file(dirfd as usize) {
        let inode = file.get_inode();
        let stat = Stat::from(inode.getattr());
        if let Err(e) = copy_to_user(statbuf, &stat as *const Stat, 1) {
            log::error!("fstat: copy_to_user failed: {:?}", e);
            return Err(e);
        }
        return Ok(0);
    }
    // 根据fd获取文件失败
    return Err(Errno::EBADF);
}

pub const AT_EMPTY_PATH: i32 = 0x1000;

pub fn sys_fstatat(dirfd: i32, pathname: *const u8, statbuf: *mut Stat, flags: i32) -> SyscallRet {
    if flags & AT_EMPTY_PATH != 0 {
        return sys_fstat(dirfd, statbuf);
    }
    let path = c_str_to_string(pathname);
    if path.is_empty() {
        log::error!("[sys_fstatat] pathname is empty");
        return Err(Errno::ENOENT);
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
                log::error!("fstatat: copy_to_user failed: {:?}", e);
                return Err(e);
            }
            return Ok(0);
        }
        Err(e) => {
            log::info!("[sys_fstatat] fail to fstatat: {}, {:?}", path, e);
            return Err(e);
        }
    }
}

pub fn sys_getdents64(fd: usize, dirp: usize, count: usize) -> SyscallRet {
    log::info!(
        "[sys_getdents64] fd: {}, dirp: {:#x}, count: {}",
        fd,
        dirp,
        count
    );
    let task = current_task();
    if let Some(file_dyn) = task.fd_table().get_file(fd as usize) {
        if let Some(file) = file_dyn.as_any().downcast_ref::<File>() {
            return file.readdir(dirp, count);
        }
    }
    Err(Errno::EBADF)
}

pub fn sys_chdir(pathname: *const u8) -> SyscallRet {
    let path = c_str_to_string(pathname);
    let mut nd = Nameidata::new(&path, AT_FDCWD);
    let fake_lookup_flags = 0;
    match filename_lookup(&mut nd, fake_lookup_flags) {
        Ok(dentry) => {
            current_task().set_pwd(Path::new(nd.mnt, dentry));
            Ok(0)
        }
        Err(e) => {
            log::info!("[sys_chdir] fail to chdir: {}, {:?}", path, e);
            Err(e)
        }
    }
}

// Todo: 直接往用户地址空间写入, 没有检查
pub fn sys_pipe2(fdset_ptr: *mut i32, flags: i32) -> SyscallRet {
    log::trace!("[sys_pipe2]");
    let flags = OpenFlags::from_bits(flags).unwrap();
    let task = current_task();
    let pipe_pair = make_pipe();
    let fd_table = task.fd_table();
    let fd_flags = FdFlags::from(&flags);
    let fd1 = fd_table.alloc_fd(pipe_pair.0.clone(), fd_flags)?;
    let fd2 = fd_table.alloc_fd(pipe_pair.1.clone(), fd_flags)?;
    log::info!(
        "[sys_pipe2] fdset: {:?}, flags: {:?}, fds: [{}, {}]",
        fdset_ptr,
        flags,
        fd1,
        fd2
    );
    let pipe = [fd1 as i32, fd2 as i32];
    copy_to_user(fdset_ptr, pipe.as_ptr(), 2).unwrap();
    Ok(0)
}

pub fn sys_close(fd: usize) -> SyscallRet {
    // 4.17
    log::error!("[sys_close] fd: {}", fd);
    let task = current_task();
    let fd_table = task.fd_table();
    if fd_table.close(fd) {
        Ok(0)
    } else {
        Err(Errno::EBADF)
    }
}

/// 更改文件的名称(必要的时候会改变位置), 文件的其他硬链接(由link创建)不受影响, 对oldpth打开的文件描述符不受影响
/// Todo: 实现oldpath是符号链接的情况
pub fn sys_renameat2(
    olddirfd: i32,
    oldpath: *const u8,
    newdirfd: i32,
    newpath: *const u8,
    flags: i32,
) -> SyscallRet {
    log::info!(
        "[sys_renameat2] olddirfd: {}, oldpath: {:?}, newdirfd: {}, newpath: {:?}, flags: {}",
        olddirfd,
        oldpath,
        newdirfd,
        newpath,
        flags
    );
    let oldpath = c_str_to_string(oldpath);
    let newpath = c_str_to_string(newpath);
    let flags = RenameFlags::from_bits(flags).unwrap();
    // 检查flags
    if (flags.contains(RenameFlags::NOREPLACE) || flags.contains(RenameFlags::WHITEOUT))
        && flags.contains(RenameFlags::EXCHANGE)
    {
        log::error!("[sys_renameat2] NOREPLACE and RENAME_EXCHANGE cannot be used together");
        return Err(Errno::EINVAL);
    }
    if flags.contains(RenameFlags::WHITEOUT) {
        unimplemented!();
    }
    let mut old_nd = Nameidata::new(&oldpath, olddirfd);
    let fake_lookup_flags = 0;
    match filename_lookup(&mut old_nd, fake_lookup_flags) {
        Ok(old_dentry) => {
            let mut new_nd = Nameidata::new(&newpath, newdirfd);
            // 检查newpath是否存在, 并进行相关的类型检查
            let new_dentry = lookup_dentry(&mut new_nd);
            if new_dentry.is_negative() {
                // new_path不存在
                if flags.contains(RenameFlags::EXCHANGE) {
                    log::error!("[sys_renameat2] newpath must exist with EXCHANGE flag");
                    return Err(Errno::EINVAL);
                }
            } else {
                // new_path存在
                if flags.contains(RenameFlags::NOREPLACE) {
                    // 如果newpath存在, 则返回错误
                    log::error!("[sys_renameat2] newpath already exists with NOREPLACE flag");
                    return Err(Errno::EINVAL);
                }
                if flags.contains(RenameFlags::EXCHANGE) {
                    // 进行ancestor检查
                    if new_dentry.is_ancestor(&old_dentry) {
                        log::error!(
                            "[sys_renameat2] newpath is ancestor of oldpath with EXCHANGE flag"
                        );
                        return Err(Errno::EINVAL);
                    }
                }
                // 先进行类型检查
                if old_dentry.is_symlink() {
                    // Todo: 处理符号链接
                    unimplemented!();
                }
                if old_dentry.is_dir() && !new_dentry.get_inode().can_lookup() {
                    // 如果old_dentry是目录, 则newpath必须不存在, 或者是空目录
                    log::error!(
                        "[sys_renameat2] oldpath is dir, newpath must not exist or be an empty dir"
                    );
                    return Err(Errno::ENOTEMPTY);
                }
                if old_dentry.is_regular()
                    && Arc::ptr_eq(&old_dentry.get_inode(), &new_dentry.get_inode())
                {
                    // 如果old_dentry和new_dentry是同一个file的两个硬链接, 则直接返回
                    log::warn!(
                        "[rename] old_dentry and new_dentry are the hard links of the same file"
                    );
                    return Ok(0);
                }
            }
            // 进行ancestor检查
            if old_dentry.is_ancestor(&new_dentry) {
                log::error!("[sys_renameat2] oldpath is ancestor of newpath");
                return Err(Errno::EINVAL);
            }
            // 执行renameat操作
            let old_dir_entry = old_dentry.get_parent();
            let new_dir_entry = new_dentry.get_parent();
            let old_dir_inode = old_dir_entry.get_inode();
            let new_dir_inode = new_dir_entry.get_inode();
            let should_mv = !Arc::ptr_eq(&old_dir_inode, &new_dir_inode);
            // inode层次的操作 + dentry层次的操作
            match old_dir_inode.rename(
                new_dir_inode,
                old_dentry.clone(),
                new_dentry.clone(),
                flags,
                should_mv,
            ) {
                Ok(_) => {
                    delete_dentry(old_dentry);
                    // new_dentry在lookup时已insert到dentry cache中
                    return Ok(0);
                }
                Err(e) => {
                    log::error!("[sys_renameat2] rename failed: {:?}", e);
                    return Err(e);
                }
            }
        }
        Err(e) => {
            // old_path不存在
            log::info!(
                "[sys_renameat2] fail to lookup oldpath: {}, {:?}",
                oldpath,
                e
            );
            return Err(e);
        }
    }
}

// Defined in <bits/fcntl-linux.h>
#[derive(Debug, Eq, PartialEq, Clone, Copy, Default)]
#[allow(non_camel_case_types)]
pub enum FcntlOp {
    F_DUPFD = 0,
    F_DUPFD_CLOEXEC = 1030,
    F_GETFD = 1,
    F_SETFD = 2,
    F_GETFL = 3,
    F_SETFL = 4,
    #[default]
    F_UNIMPL,
}

impl TryFrom<i32> for FcntlOp {
    type Error = ();
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(FcntlOp::F_DUPFD),
            1030 => Ok(FcntlOp::F_DUPFD_CLOEXEC),
            1 => Ok(FcntlOp::F_GETFD),
            2 => Ok(FcntlOp::F_SETFD),
            3 => Ok(FcntlOp::F_GETFL),
            4 => Ok(FcntlOp::F_SETFL),
            _ => Err(()),
        }
    }
}

// Todo: 还有Op没有实现
pub fn sys_fcntl(fd: i32, op: i32, arg: usize) -> SyscallRet {
    log::info!("[sys_fcntl] fd: {}, op: {}, arg: {}", fd, op, arg);
    let task = current_task();
    // let file = task.fd_table().get_file(fd as usize);
    let fd_entry = task.fd_table().get_fdentry(fd as usize);
    let op = FcntlOp::try_from(op).unwrap_or(FcntlOp::F_UNIMPL);
    let fd_flags = FdFlags::from(&op);
    if let Some(entry) = fd_entry {
        match op {
            FcntlOp::F_DUPFD => {
                // let newfd = task.fd_table().alloc_fd(file.clone(), FdFlags::empty());
                return task.fd_table().alloc_fd_above_lower_bound(
                    entry.get_file().clone(),
                    fd_flags,
                    arg,
                );
            }
            FcntlOp::F_DUPFD_CLOEXEC => {
                return task.fd_table().alloc_fd_above_lower_bound(
                    entry.get_file().clone(),
                    fd_flags,
                    arg,
                );
            }
            FcntlOp::F_GETFD => {
                // 获取fd entry的flags
                // 这里的flags是FdFlags, 不是OpenFlags
                return Ok(i32::from(entry.get_flags()) as usize);
            }
            FcntlOp::F_SETFD => {
                // 仅仅是设置fd的flags, 不会影响fd_table中的fd
                let mut fd_entry = entry.clone();
                fd_entry.set_flags(FdFlags::from_bits(arg).unwrap());
                return Ok(0);
            }
            FcntlOp::F_GETFL => {
                // 获取文件的状态标志(OpenFlags)
                let flags = entry.get_file().get_flags();
                log::error!("[sys_fcntl] get flags: {:?}", flags);
                return Ok(flags.bits() as usize);
            }
            FcntlOp::F_SETFL => {
                // 设置flags
                let mut flags = OpenFlags::from_bits_truncate(arg as i32);
                // 忽略访问模式和文件创建标志
                flags.remove(OpenFlags::O_ACCMODE);
                flags.remove(OpenFlags::CREATION_FLAGS);
                log::error!("[sys_fcntl] set flags: {:?}", flags);
                entry.get_file().set_flags(flags);
                return Ok(0);
            }
            _ => {
                panic!("[sys_fcntl] Unimplemented");
            }
        }
    }
    Err(Errno::EBADF)
}

// pub fn sys_select(
//     nfds: usize,
//     readfds: usize,
//     writefds: usize,
//     exceptfds: usize,
//     timeout: *const TimeSpec,
//     sigmask: usize,
// ) -> SyscallRet {
//     assert!(sigmask == 0);
//     log::error!("[sys_select]:begin select");
//     sys_pselect6(nfds, readfds, writefds, exceptfds, timeout, sigmask)
// }

// /// pselect用于检查多个文件描述符的状态
// /// 函数会在3中情况退出：1.存在文件可读可写 2. timeout 3.存在信号
// /// nfds:文件描述符范围，会检查0-nfds-1的所有文件描述符
// /// readfds:可读文件描述符地址
// /// writefds:可写文件描述符地址
// /// exceptfds:异常文件描述符地址
// /// timeout:超时时间,如果timeout为null,会阻塞
// /// mask:信号掩码
// /// 基本步骤如下：
// /// 1.根据nfds和readfds构造对应的掩码数组，read,write,except3中
// /// 2.一个loop来不断判断file[i]的状态，并更新read,write,except的掩码
// /// 3.处理timeout和signal结果
// pub fn sys_pselect6(
//     nfds: usize,
//     readfds: usize,
//     writefds: usize,
//     exceptfds: usize,
//     timeout: *const TimeSpec,
//     sigmask: usize,
// ) -> SyscallRet {
//     //log::error!("[sys_pselecct6] nfds: {}, readfds: {:?}, writefds: {:?}, exceptfds: {:?}, timeout: {:?}, mask: {}",nfds,readfds,writefds,exceptfds,timeout,mask);
//     log::error!("[sys_pselect6]:begin pselect6");
//     log::error!(
//         "nfds: {}, readfds: {}, writefds: {}, exceptfds: {}, timeout: {:?}, sigmask: {}",
//         nfds,
//         readfds,
//         writefds,
//         exceptfds,
//         timeout,
//         sigmask
//     );
//     let mut readfditer = match init_fdset(readfds, nfds) {
//         Ok(rfditer) => rfditer,
//         Err(e) => return Err(e),
//     };
//     let mut writeiter = match init_fdset(writefds, nfds) {
//         Ok(wfditer) => wfditer,
//         Err(e) => return Err(e),
//     };
//     //to
//     // if exceptfds != 0 {
//     //     // exceptfds不为0, 需要初始化exceptfds
//     //     init_fdset(exceptfds, nfds);

//     // }
//     // let exceptiter=init_fdset(exceptfds, nfds);
//     let task = current_task();
//     let timeout = if timeout.is_null() {
//         // timeout为负数对于poll来说是无限等待
//         -1
//     } else {
//         let mut tmo: TimeSpec = TimeSpec::default();
//         copy_from_user(timeout, &mut tmo as *mut TimeSpec, 1)?;
//         (tmo.sec * 1000 + tmo.nsec / 1000000) as isize
//     };
//     let origin_sigset = task.op_sig_pending_mut(|sig_pending| sig_pending.mask.clone());
//     if sigmask != 0 {
//         let mut sigset: SigSet = SigSet::default();
//         copy_from_user(sigmask as *const SigSet, &mut sigset as *mut SigSet, 1)?;
//         task.op_sig_pending_mut(|sig_pending| sig_pending.mask = sigset);
//     }
//     drop(task);
//     loop {
//         yield_current_task();
//         let mut set: usize = 0;
//         if readfditer.fdset.valid() {
//             for fd in 0..readfditer.fds.len() {
//                 log::error!("[sys_pselect6] read fd: {}", readfditer.fds[fd]);
//                 if readfditer.files[fd].r_ready() {
//                     yield_current_task();
//                     //e内核会根据嗅探的结果设置fdset的对应位为1
//                     readfditer.fdset.set(readfditer.fds[fd]);
//                     set += 1;
//                 }
//             }
//         }
//         if writeiter.fdset.valid() {
//             for i in 0..writeiter.fds.len() {
//                 if writeiter.files[i].w_ready() {
//                     writeiter.fdset.set(writeiter.fds[i]);
//                     set += 1;
//                 }
//             }
//         }
//         //todo exception condition
//         // if exceptiter.fdset.valid(){
//         //     for i in 0..exceptiter.fds.len() {
//         //         if exceptiter.files[i].{
//         //             set+=1;
//         //         }
//         //     }
//         // }
//         if set > 0 {
//             log::error!("[sys_pselect6]: set is {:?}", set);
//             //将设置好的返回给用户
//             if readfds != 0 {
//                 copy_to_user(
//                     readfds as *mut usize,
//                     readfditer.fdset.get_addr(),
//                     readfditer.fdset.get_len(),
//                 )?;
//             }
//             if writefds != 0 {
//                 copy_to_user(
//                     writefds as *mut usize,
//                     writeiter.fdset.get_addr(),
//                     writeiter.fdset.get_len(),
//                 )?;
//             }
//             return Ok(set);
//         }
//         if timeout == 0 {
//             // timeout为0表示立即返回, 即使没有fd准备好
//             break;
//         } else if timeout > 0 {
//             if get_time_ms() > timeout as usize {
//                 // 超时了, 返回
//                 break;
//             }
//         }
//         let task = current_task();
//         if task.op_sig_pending_mut(|sig_pending| sig_pending.pending.contain_signal(Sig::SIGKILL)) {
//             return Err(Errno::EINTR);
//         }
//         drop(task);
//     }
//     if sigmask != 0 {
//         let task = current_task();
//         task.op_sig_pending_mut(|sig_pending| sig_pending.mask = origin_sigset);
//     }
//     return Ok(0);
// }

// #[cfg(target_arch = "riscv64")]
pub fn sys_ppoll(
    fds: *mut PollFd,
    nfds: usize,
    timeout: *const TimeSpec,
    sigmask: usize,
) -> SyscallRet {
    log::error!(
        "[sys_ppoll] fds: {:?}, nfds: {}, timeout: {:?}, sigmask: {}",
        fds,
        nfds,
        timeout,
        sigmask
    );
    let task = current_task();
    // 处理参数
    let timeout = if timeout.is_null() {
        // timeout为负数对于poll来说是无限等待
        -1
    } else {
        let mut tmo: TimeSpec = TimeSpec::default();
        copy_from_user(timeout, &mut tmo as *mut TimeSpec, 1).unwrap();
        (tmo.sec * 1000 + tmo.nsec / 1000000) as isize
    };
    // Todo: 设置sigmaskconst
    // 用于保存原来的sigmask, 后续需要恢复
    let origin_sigset = task.op_sig_pending_mut(|sig_pending| sig_pending.mask.clone());
    if sigmask != 0 {
        let mut sigset: SigSet = SigSet::default();
        copy_from_user(sigmask as *const SigSet, &mut sigset as *mut SigSet, 1)?;
        task.op_sig_pending_mut(|sig_pending| sig_pending.mask = sigset);
    }
    drop(task);

    let mut poll_fds: Vec<PollFd> = vec![PollFd::default(); nfds];
    copy_from_user(fds, poll_fds.as_mut_ptr(), nfds).unwrap();
    for poll_fd in poll_fds.iter_mut() {
        poll_fd.revents = PollEvents::empty();
    }
    let mut done;
    loop {
        done = 0;
        let task = current_task();
        for i in 0..nfds {
            let poll_fd = &mut poll_fds[i];
            if poll_fd.fd < 0 {
                continue;
            } else {
                if let Some(file) = task.fd_table().get_file(poll_fd.fd as usize) {
                    let mut trigger = 0;
                    if file.hang_up() {
                        poll_fd.revents |= PollEvents::HUP;
                        trigger = 1;
                    }
                    if poll_fd.events.contains(PollEvents::IN) && file.r_ready() {
                        poll_fd.revents |= PollEvents::IN;
                        trigger = 1;
                    }
                    if poll_fd.events.contains(PollEvents::OUT) && file.w_ready() {
                        poll_fd.revents |= PollEvents::OUT;
                        trigger = 1;
                    }
                    done += trigger;
                } else {
                    // pollfd的fd字段大于0, 但是对应文件描述符并没有打开, 设置pollfd.revents为POLLNVAL
                    poll_fd.revents |= PollEvents::INVAL;
                    log::error!("[sys_ppoll] invalid fd: {}", poll_fd.fd);
                }
            }
        }
        // for poll_fd in poll_fds.iter_mut() {
        //     if poll_fd.fd < 0 {
        //         continue;
        //     } else {
        //         if let Some(file) = task.fd_table().get_file(poll_fd.fd as usize) {
        //             let mut trigger = 0;
        //             if file.hang_up() {
        //                 poll_fd.revents |= PollEvents::HUP;
        //                 trigger = 1;
        //             }
        //             // Todo: 如果文件描述符是pipe写端, 且没有读端打开, 则设置POLLERR
        //             if poll_fd.events.contains(PollEvents::IN) && file.r_ready() {
        //                 poll_fd.revents |= PollEvents::IN;
        //                 trigger = 1;
        //             }
        //             if poll_fd.events.contains(PollEvents::OUT) && file.w_ready() {
        //                 poll_fd.revents |= PollEvents::OUT;
        //                 trigger = 1;
        //             }
        //             done += trigger;
        //         } else {
        //             // pollfd的fd字段大于0, 但是对应文件描述符并没有打开, 设置pollfd.revents为POLLNVAL
        //             poll_fd.revents |= PollEvents::INVAL;
        //             log::error!("[sys_ppoll] invalid fd: {}", poll_fd.fd);
        //         }
        //     }
        // }
        if done > 0 {
            break;
        }
        if timeout == 0 {
            // timeout为0表示立即返回, 即使没有fd准备好
            break;
        } else if timeout > 0 {
            if get_time_ms() > timeout as usize {
                // 超时了, 返回
                break;
            }
        }
        drop(task);
        yield_current_task();
    }
    // 写回用户空间
    copy_to_user(fds, poll_fds.as_ptr(), nfds).unwrap();
    // 恢复origin sigmask
    if sigmask != 0 {
        let task = current_task();
        task.op_sig_pending_mut(|sig_pending| sig_pending.mask = origin_sigset);
    }
    Ok(done)
}

/// Todo: 目前只支持了Pipe的hang_up, r_ready, w_ready
// #[cfg(target_arch = "loongarch64")]
// pub fn sys_ppoll(
//     fds: *mut PollFd,
//     nfds: usize,
//     timeout: *const TimeSpec,
//     sigmask: usize,
// ) -> SyscallRet {
//     log::info!(
//         "[sys_ppoll] fds: {:?}, nfds: {}, timeout: {:?}, sigmask: {}",
//         fds,
//         nfds,
//         timeout,
//         sigmask
//     );
//     let task = current_task();
//     // 处理参数
//     let timeout = if timeout.is_null() {
//         // timeout为负数对于poll来说是无限等待
//         -1
//     } else {
//         let mut tmo: TimeSpec = TimeSpec::default();
//         copy_from_user(timeout, &mut tmo as *mut TimeSpec, 1).unwrap();
//         (tmo.sec * 1000 + tmo.nsec / 1000000) as isize
//     };
//     // Todo: 设置sigmaskconst
//     // 用于保存原来的sigmask, 后续需要恢复
//     let origin_sigset = task.op_sig_pending_mut(|sig_pending| sig_pending.mask.clone());
//     if sigmask != 0 {
//         let mut sigset: SigSet = SigSet::default();
//         copy_from_user(sigmask as *const SigSet, &mut sigset as *mut SigSet, 1)?;
//         task.op_sig_pending_mut(|sig_pending| sig_pending.mask = sigset);
//     }
//     drop(task);

//     let mut poll_fds: Vec<PollFd> = vec![PollFd::default(); nfds];
//     copy_from_user(fds, poll_fds.as_mut_ptr(), nfds).unwrap();
//     // core::hint::black_box(&poll_fds);
//     for poll_fd in poll_fds.iter_mut() {
//         poll_fd.revents = PollEvents::empty();
//     }
//     let mut done;
//     loop {
//         done = 0;
//         let task = current_task();
//         for i in 0..nfds {
//             let poll_fd = &mut poll_fds[i];
//             if poll_fd.fd < 0 {
//                 continue;
//             } else {
//                 if let Some(file) = task.fd_table().get_file(poll_fd.fd as usize) {
//                     let mut trigger = 0;
//                     if file.hang_up() {
//                         poll_fd.revents |= PollEvents::HUP;
//                         trigger = 1;
//                     }
//                     // Todo: 如果文件描述符是pipe写端, 且没有读端打开, 则设置POLLERR
//                     if poll_fd.events.contains(PollEvents::IN) && file.r_ready() {
//                         poll_fd.revents |= PollEvents::IN;
//                         trigger = 1;
//                     }
//                     if poll_fd.events.contains(PollEvents::OUT) && file.w_ready() {
//                         poll_fd.revents |= PollEvents::OUT;
//                         trigger = 1;
//                     }
//                     done += trigger;
//                 } else {
//                     // pollfd的fd字段大于0, 但是对应文件描述符并没有打开, 设置pollfd.revents为POLLNVAL
//                     poll_fd.revents |= PollEvents::INVAL;
//                     log::error!("[sys_ppoll] invalid fd: {}", poll_fd.fd);
//                 }
//             }
//         }
//         if done > 0 {
//             break;
//         }
//         if timeout == 0 {
//             // timeout为0表示立即返回, 即使没有fd准备好
//             break;
//         } else if timeout > 0 {
//             if get_time_ms() > timeout as usize {
//                 // 超时了, 返回
//                 break;
//             }
//         }
//         drop(task);
//         yield_current_task();
//     }
//     // 写回用户空间
//     copy_to_user(fds, poll_fds.as_ptr(), nfds).unwrap();
//     // 恢复origin sigmask
//     if sigmask != 0 {
//         let task = current_task();
//         task.op_sig_pending_mut(|sig_pending| sig_pending.mask = origin_sigset);
//     }
//     Ok(done)
// }

// 如果对应timespec.sec为UTIME_NOE, 时间戳设置为当前时间(墙上时间)
pub const UTIME_NOW: usize = 0x3fffffff;
// 如果对应timespec.sec为UTIME_OMIT, 则不修改对应的时间戳
pub const UTIME_OMIT: usize = 0x3ffffffe;

/*
   C library/kernel ABI differences
       On Linux, futimens() is a library function implemented on top of
       the utimensat() system call.  To support this, the Linux
       utimensat() system call implements a nonstandard feature: if
       pathname is NULL, then the call modifies the timestamps of the
       file referred to by the file descriptor dirfd (which may refer to
       any type of file).  Using this feature, the call
       futimens(fd, times) is implemented as:

           utimensat(fd, NULL, times, 0);

       Note, however, that the glibc wrapper for utimensat() disallows
       passing NULL as the value for pathname: the wrapper function
       returns the error EINVAL in this case.
*/
// 当pathname为NULL时, 不检查flags是否设置了AT_EMPTY_PATH, 而是直接使用dirfd
pub fn sys_utimensat(
    dirfd: i32,
    pathname: *const u8,
    time_spec2: *const TimeSpec,
    flags: i32,
) -> SyscallRet {
    log::info!(
        "[sys_utimensat] dirfd: {}, pathname: {:?}, times: {:?}, flags: {:?}",
        dirfd,
        pathname,
        time_spec2,
        flags
    );
    let flags = UtimenatFlags::from_bits(flags).unwrap();
    let path = if pathname.is_null() {
        if !flags.contains(UtimenatFlags::AT_EMPTY_PATH) {
            log::warn!("[sys_utimensat] pathname is NULL, but AT_EMPTY_PATH is not set");
            // 因为linux kernel abi, 这里不返回EINVAL
        }
        None
    } else {
        Some(c_str_to_string(pathname))
    };
    let mut time_spec2_buf: [TimeSpec; 2] = [TimeSpec::default(); 2];
    let time_specs = if time_spec2.is_null() {
        None
    } else {
        copy_from_user(time_spec2, &mut time_spec2_buf as *mut TimeSpec, 2).unwrap();
        Some(&time_spec2_buf)
    };
    let inode = if let Some(path) = path {
        let mut nd = Nameidata::new(&path, dirfd);
        let fake_lookup_flags = 0;
        match filename_lookup(&mut nd, fake_lookup_flags) {
            Ok(dentry) => dentry.get_inode(),
            Err(e) => {
                log::info!("[sys_utimensat] fail to lookup: {}, {:?}", path, e);
                return Err(e);
            }
        }
    } else {
        // 直接操作dirfd
        match dirfd {
            AT_FDCWD => current_task().pwd().dentry.get_inode(),
            _ => {
                let file = current_task().fd_table().get_file(dirfd as usize);
                if let Some(file) = file {
                    file.get_inode()
                } else {
                    log::error!("[sys_utimensat] invalid dirfd: {}", dirfd);
                    return Err(Errno::EBADF);
                }
            }
        }
    };
    let current_time = TimeSpec::new_wall_time();
    match time_specs {
        Some(time_specs) => {
            match time_specs[0].nsec {
                UTIME_NOW => {
                    log::info!("[sys_utimensat] set atime to now");
                    inode.set_atime(current_time);
                }
                UTIME_OMIT => {
                    log::info!("[sys_utimensat] omit atime");
                }
                _ => {
                    inode.set_atime(time_specs[0]);
                }
            }
            match time_specs[1].nsec {
                UTIME_NOW => {
                    log::info!("[sys_utimensat] set mtime to now");
                    inode.set_mtime(current_time);
                }
                UTIME_OMIT => {
                    log::info!("[sys_utimensat] omit mtime");
                }
                _ => {
                    inode.set_mtime(time_specs[1]);
                }
            }
        }
        None => {
            log::info!("[sys_utimensat] times is null, use current time to set atime and mtime");
            inode.set_atime(current_time);
            inode.set_mtime(current_time);
            inode.set_ctime(current_time);
        }
    }
    Ok(0)
}

pub fn sys_sendfile(
    out_fd: usize,
    in_fd: usize,
    offset_ptr: *mut usize,
    count: usize,
) -> SyscallRet {
    log::info!(
        "[sys_sendfile] out_fd: {}, in_fd: {}, offset: {:?}, count: {}",
        out_fd,
        in_fd,
        offset_ptr,
        count
    );
    let fd_table = current_task().fd_table();
    let (in_file, out_file) = match (fd_table.get_file(in_fd), fd_table.get_file(out_fd)) {
        (Some(in_file), Some(out_file)) => (in_file, out_file),
        _ => {
            log::error!("[sys_sendfile] invalid fd");
            return Err(Errno::EBADF);
        }
    };
    if !in_file.readable() || !out_file.writable() {
        log::error!("[sys_sendfile] invalid fd");
        return Err(Errno::EBADF);
    }
    let mut buf = vec![0u8; count];
    let len;
    if offset_ptr.is_null() {
        len = in_file.read(&mut buf);
    } else {
        // offset不为NULL, 则sendfile不会修改`in_fd`的文件偏移量
        let mut offset = 0;
        copy_from_user(offset_ptr, &mut offset, 1).unwrap();
        let origin_offset = in_file.get_offset();
        in_file.seek(offset as isize, Whence::SeekSet)?;
        len = in_file.read(&mut buf);
        in_file.seek(origin_offset as isize, Whence::SeekSet)?;
        // 将新的偏移量写回用户空间
        copy_to_user(offset_ptr, &(offset + len + 1), 1).unwrap();
    }
    let ret = out_file.write(&buf[..len]) as isize;
    log::info!("[sys_sendfile] ret: {}", ret);
    Ok(ret as usize)
}

pub fn sys_ftruncate(fildes: usize, length: usize) -> SyscallRet {
    log::info!("[sys_ftruncate] fd: {}, length: {}", fildes, length);
    let task = current_task();
    if let Some(file) = task.fd_table().get_file(fildes) {
        if file.get_inode().get_mode() & S_IFDIR != 0 {
            log::error!("[sys_ftruncate] ftruncate on a directory");
            return Err(Errno::EISDIR);
        }
        file.truncate(length)
    } else {
        Err(Errno::EBADF)
    }
}

/* loongarch */
// Todo: 使用mask指示内核需要返回哪些信息
pub fn sys_statx(
    dirfd: i32,
    pathname: *const u8,
    flags: i32,
    _mask: u32,
    statxbuf: *mut Statx,
    // statbuf: *mut Stat,
) -> SyscallRet {
    log::info!(
        "[sys_statx] dirfd: {}, pathname: {:?}, flags: {}, mask: {}",
        dirfd,
        pathname,
        flags,
        _mask
    );
    if flags & AT_EMPTY_PATH != 0 {
        if let Some(file) = current_task().fd_table().get_file(dirfd as usize) {
            match file.as_any().downcast_ref::<File>() {
                Some(file) => {
                    let inode = file.inner_handler(|inner| inner.inode.clone());
                    let statx = Statx::from(inode.getattr());
                    log::error!("statx: statx: {:?}", statx);
                    copy_to_user(statxbuf, &statx as *const Statx, 1)?;
                    return Ok(0);
                }
                None => {
                    log::error!("statx: downcast_ref failed");
                    return Err(Errno::EBADF);
                }
            }
        }
        // 根据fd获取文件失败
        return Err(Errno::EBADF);
    }
    let path = c_str_to_string(pathname);
    if path.is_empty() {
        log::error!("[sys_statx] pathname is empty");
        return Err(Errno::EINVAL);
    }
    let mut nd = Nameidata::new(&path, dirfd);
    let fake_lookup_flags = 0;
    match filename_lookup(&mut nd, fake_lookup_flags) {
        Ok(dentry) => {
            let inode = dentry.get_inode();
            let statx = Statx::from(inode.getattr());
            // log::error!("statx: statx: {:?}", statx);
            if let Err(e) = copy_to_user(statxbuf, &statx as *const Statx, 1) {
                // let stat = Stat::from(inode.getattr());
                // if let Err(e) = copy_to_user(statbuf, &stat as *const Stat, 1) {
                log::error!("statx: copy_to_user failed: {:?}", e);
                return Err(e);
            }
            return Ok(0);
        }
        Err(e) => {
            log::info!("[sys_statx] fail to statx: {}, {:?}", path, e);
            return Err(e);
        }
    }
}

/* loongarch end */

// Todo: 需要支持除根目录以外的vfs挂载
pub fn sys_statfs(path: *const u8, buf: *mut StatFs) -> SyscallRet {
    let path = c_str_to_string(path);
    if path.is_empty() {
        log::error!("[sys_statfs] pathname is empty");
        return Err(Errno::EINVAL);
    }
    log::info!("[sys_statfs] path: {:?}, buf: {:?}", path, buf);
    // 特殊处理根目录, 因为根目录的dentry是空字符串, path传入的是"/"
    // if path == "/" {
    let root_dentry = current_task().root().dentry.clone();
    let mount = get_mount_by_dentry(root_dentry).unwrap();
    match mount.statfs(buf) {
        Ok(_) => {
            log::info!("[sys_statfs] success to statfs");
            return Ok(0);
        }
        Err(e) => {
            log::info!("[sys_statfs] fail to statfs: {}, {:?}", path, e);
            return Err(e);
        }
    }
    // } else {
    // Todo: 需要支持/tmp的tmpfs
    // let mut nd = Nameidata::new(&path, AT_FDCWD);
    // let target_dentry = lookup_dentry(&mut nd);
    // let mount = get_mount_by_dentry(target_dentry).unwrap();
    // match mount.statfs(buf) {
    //     Ok(_) => {
    //         log::info!("[sys_statfs] success to statfs");
    //         return Ok(0);
    //     }
    //     Err(e) => {
    //         log::info!("[sys_statfs] fail to statfs: {}, {:?}", path, e);
    //         return Err(e);
    //     }
    // }
    // }
}

/* Todo: fake  */
pub fn sys_mount(
    source: *const u8,
    target: *const u8,
    fs_type: *const u8,
    flags: usize,
    _data: *const u8,
) -> SyscallRet {
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
pub fn sys_umount2(target: *const u8, flags: i32) -> SyscallRet {
    // let target = c_str_to_string(target);
    // log::info!("[sys_unmount] target: {:?}, flags: {}", target, flags);
    log::info!("[sys_unmount] target: {:?}, flags: {}", target, flags);
    Ok(0)
}

/// op是与设备相关的操作码, arg_ptr是指向参数的指针(untyped pointer, 由设备决定)
pub fn sys_ioctl(fd: usize, op: usize, _arg_ptr: usize) -> SyscallRet {
    log::error!(
        "[sys_ioctl] fd: {}, op: {:x}, arg_ptr: {:x}",
        fd,
        op,
        _arg_ptr
    );
    let task = current_task();
    let file = task.fd_table().get_file(fd);
    if let Some(file) = file {
        return file.ioctl(op, _arg_ptr);
    }
    log::error!("sys_ioctl: invalid fd: {}", fd);
    return Err(Errno::EBADF);
}

/// 检查进程是否可以访问指定的文件
/// Todo: 目前只检查pathname指定的文件是否存在, 没有检查权限
pub fn sys_faccessat(fd: usize, pathname: *const u8, mode: i32, flags: i32) -> SyscallRet {
    log::info!(
        "[sys_faccessat] fd: {}, pathname: {:?}, mode: {}, flags: {}",
        fd,
        pathname,
        mode,
        flags
    );
    log::warn!("[sys_faccessat] Unimplemented");
    let path = c_str_to_string(pathname);
    if path.is_empty() {
        log::error!("[sys_faccessat] pathname is empty");
        return Err(Errno::EINVAL);
    }
    let mut nd = Nameidata::new(&path, fd as i32);
    let fake_lookup_flags = 0;
    match filename_lookup(&mut nd, fake_lookup_flags) {
        Ok(_) => {
            // let inode = dentry.get_inode();
            // if inode.mode() & mode as u16 == 0 {
            //     log::error!("[sys_faccessat] permission denied");
            //     return;
            // }
            return Ok(0);
        }
        Err(e) => {
            log::info!("[sys_faccessat] fail to faccessat: {}, {:?}", path, e);
            return Err(e);
        }
    }
}

pub fn sys_sync(fd: usize) -> SyscallRet {
    log::info!("[sys_sync] fd: {} Unimplemented", fd);
    Ok(0)
}

pub fn sys_fsync(fd: usize) -> SyscallRet {
    log::info!("[sys_fsync] fd: {} Unimplemented", fd);
    Ok(0)
}

pub fn sys_fchmodat(fd: usize, mode: usize) -> SyscallRet {
    Ok(0)
}

pub fn sys_fchownat(fd: usize, path: *const u8, owner: usize, group: usize) -> SyscallRet {
    Ok(0)
}
/* fake end */

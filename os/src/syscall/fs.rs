use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use alloc::string::{String, ToString};
use virtio_drivers::PAGE_SIZE;

use crate::arch::config::USER_MAX_VA;
use crate::arch::timer::{get_time_ms, get_time_ns, get_time_us};
use crate::ext4::dentry;
use crate::ext4::inode::{S_IFMT, S_IFREG, S_IFSOCK, S_ISGID};
use crate::fs::dentry::{chown, dentry_check_access, LinuxDirent64, F_OK, R_OK, W_OK, X_OK};
use crate::fs::fd_set::init_fdset;
use crate::fs::fdtable::FdFlags;
use crate::fs::file::OpenFlags;
use crate::fs::kstat::Statx;
use crate::fs::mount::get_mount_by_dentry;
use crate::fs::namei::{
    link_path_walk, link_path_walk2, lookup_dentry, open_last_lookups, open_last_lookups2,
};
use crate::fs::pipe::make_pipe;
use crate::fs::uapi::{
    convert_old_dev_to_new, CloseRangeFlags, DevT, FallocFlags, OpenHow, PollEvents, PollFd,
    RenameFlags, ResolveFlags, SetXattrFlags, StatFs, Whence, MAX_OPEN_HOW, XATTR_SIZE_MAX,
};
use crate::fs::{old, path, AT_REMOVEDIR, EXT4_MAX_FILE_SIZE};
use crate::futex::flags;
use crate::mm::{MapType, VPNRange, VirtAddr, VirtPageNum};
use crate::signal::{Sig, SigSet};
use crate::syscall::errno::Errno;
use crate::task::{wait, wait_timeout, yield_current_task};
use crate::timer::TimeSpec;
use crate::{
    ext4::inode::S_IFDIR,
    fs::{
        dentry::delete_dentry,
        file::File,
        kstat::Stat,
        mount::do_mount,
        namei::{filename_create, filename_lookup, path_openat, Nameidata},
        path::Path,
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
    let whence = Whence::try_from(whence)?;
    if let Some(file) = file {
        let file = file.clone();
        file.seek(offset, whence)
    } else {
        log::error!("[sys_lseek] fd {} not opened", fd);
        Err(Errno::EBADF)
    }
}

pub fn sys_read(fd: usize, buf: *mut u8, len: usize) -> SyscallRet {
    let task = current_task();
    let file = task.fd_table().get_file(fd);
    if let Some(file) = file {
        let file = file.clone();
        if !file.readable() {
            log::error!("[sys_read] fd {} not readable", fd);
            return Err(Errno::EBADF);
        }
        // Todo: Socket没有实现get_inode会寄, 改在Impl FileOp for File中检查
        // if file.get_inode().can_lookup() {
        //     log::error!("[sys_read] fd {} is dir", fd);
        //     return Err(Errno::EISDIR);
        // }
        // let ret = file.read(unsafe { core::slice::from_raw_parts_mut(buf, len) });
        let mut ker_buf = vec![0u8; len];
        let read_len = file.read(&mut ker_buf)?;
        // if fd >= 3 {
        //     log::info!("sys_read: fd: {}, len: {}", fd, len);
        // }
        let ker_buf_ptr = ker_buf.as_ptr();
        // assert!(ker_buf_ptr != core::ptr::null());
        // 写回用户空间
        copy_to_user(buf, ker_buf_ptr, read_len as usize)
    } else {
        log::error!("[sys_read] fd {} not opened", fd);
        Err(Errno::EBADF)
    }
}

#[no_mangle]
pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> SyscallRet {
    if len == 0 {
        return Ok(0);
    }
    let task = current_task();
    let file = task.fd_table().get_file(fd);
    if let Some(file) = file {
        if !file.writable() {
            return Err(Errno::EBADF);
        }
        let file = file.clone();
        let mut ker_buf = vec![0u8; len];
        copy_from_user(buf, ker_buf.as_mut_ptr(), len)?;
        // if fd >= 3 {
        //     // log::info!("sys_write: fd: {}, len: {}, buf: {:?}", fd, len, ker_buf);
        //     log::info!("sys_write: fd: {}, len: {}", fd, len);
        // }
        let ret = file.write(&ker_buf)?;
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
    if file.get_path().dentry.is_dir() {
        log::error!("[sys_readv] fd {} is a directory", fd);
        return Err(Errno::EISDIR);
    }
    let mut total_read = 0;
    if iovcnt == 0 {
        log::warn!("[sys_readv] iovcnt is 0, returning 0");
        return Ok(0);
    }
    if iovcnt > i32::MAX as usize {
        log::error!(
            "[sys_readv] iovcnt is less than zero or greater than
              the permitted maximum"
        );
        return Err(Errno::EINVAL);
    }
    let mut iov: Vec<IoVec> = vec![IoVec::default(); iovcnt];

    copy_from_user(iov_ptr, iov.as_mut_ptr(), iovcnt)?;
    log::info!("sys_readv: iov: {:?}", iov);
    let mut iovec_total_len = 0;
    for iovec in iov.iter() {
        iovec_total_len += iovec.len;
        if iovec.len == 0 {
            continue;
        }
        if iovec_total_len > isize::MAX as usize {
            log::error!("[sys_readv] total length of iovec exceeds ssize_t max");
            return Err(Errno::EINVAL);
        }
        // let buf = copy_from_user_mut(iovec.base as *mut u8, iovec.len).unwrap();
        let mut ker_buf = vec![0u8; iovec.len];
        let read = file.read(&mut ker_buf)?;
        log::info!(
            "[sys_readv] read: {}, iovec.base: {:#x}, iovec.len: {}",
            read,
            iovec.base,
            iovec.len
        );
        log::error!(
            "[copy_to_user]iovec.base {:#x},ker_buf: {:?}",
            iovec.base,
            ker_buf.as_ptr()
        );
        copy_to_user(iovec.base as *mut u8, ker_buf.as_ptr(), read)?;
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
    log::info!("[sys_readv] total_read: {}", total_read);
    Ok(total_read)
}

pub fn sys_writev(fd: usize, iov_ptr: *const IoVec, iovcnt: usize) -> SyscallRet {
    // log::trace!("[sys_writev]");
    // if fd >= 3 {
    // }
    let task = current_task();
    log::info!(
        "sys_writev: tid: {}, fd: {}, iovcnt: {}",
        task.tid(),
        fd,
        iovcnt
    );
    let file = task.fd_table().get_file(fd);
    if file.is_none() {
        return Err(Errno::EBADF);
    }
    let file = file.unwrap();
    if !file.writable() {
        return Err(Errno::EBADF);
    }
    if file.get_inode().can_lookup() {
        log::error!("[sys_writev] fd {} is a directory", fd);
        return Err(Errno::EISDIR);
    }
    let mut total_written = 0;
    if iovcnt == 0 {
        log::warn!("[sys_readv] iovcnt is 0, returning 0");
        return Ok(0);
    }
    if iovcnt > i32::MAX as usize {
        log::error!(
            "[sys_writev] iovcnt is less than zero or greater than
              the permitted maximum"
        );
        return Err(Errno::EINVAL);
    }
    let mut iov: Vec<IoVec> = vec![IoVec::default(); iovcnt];
    copy_from_user(iov_ptr, iov.as_mut_ptr(), iovcnt)?;
    let mut iovec_total_len = 0;
    for iovec in iov.iter() {
        iovec_total_len += iovec.len;
        if iovec.len == 0 {
            continue;
        }
        if iovec_total_len > isize::MAX as usize {
            log::error!("[sys_writev] total length of iovec exceeds ssize_t max");
            return Err(Errno::EINVAL);
        }
        let mut ker_buf = vec![0u8; iovec.len];
        match copy_from_user(iovec.base as *const u8, ker_buf.as_mut_ptr(), iovec.len) {
            Ok(_) => {}
            Err(e) => {
                log::error!("[sys_writev] copy_from_user failed: {:?}", e);
                // 如果部分写入成功, 则返回已经写入的字节数
                if total_written > 0 {
                    return Ok(total_written);
                }
                return Err(e);
            }
        }
        // log::warn!(
        //     "[sys_writev] iovec.base: {:#x}, iovec.len: {}, ker_buf: {:?}",
        //     iovec.base,
        //     iovec.len,
        //     ker_buf
        // );
        let written = file.write(&ker_buf)?;
        total_written += written;
    }
    Ok(total_written)
}

pub fn sys_pread(fd: usize, buf: *mut u8, count: usize, offset: isize) -> SyscallRet {
    // log::info!(
    //     "[sys_pread] fd: {}, buf: {:?}, count: {}, offset: {}",
    //     fd,
    //     buf,
    //     count,
    //     offset
    // );
    if fd > isize::MAX as usize {
        log::error!("[sys_pread] fd is negative: {}", fd);
        return Err(Errno::EBADF);
    }
    if offset < 0 {
        log::error!("[sys_pread] offset is negative or too large: {}", offset);
        return Err(Errno::EINVAL);
    }
    if count == 0 {
        log::warn!("[sys_pread] count is 0, returning 0");
        return Ok(0);
    }
    let task = current_task();
    let file = task.fd_table().get_file(fd as usize);
    if let Some(file) = file {
        let file = file.clone();
        if !file.readable() {
            return Err(Errno::EBADF);
        }
        if file.get_inode().can_lookup() {
            log::error!("[sys_pread] fd {} is dir", fd);
            return Err(Errno::EISDIR);
        }
        let mut ker_buf = vec![0u8; count];
        let read_len = file.pread(&mut ker_buf, offset as usize)?;
        let ker_buf_ptr = ker_buf.as_ptr();
        // 写回用户空间
        copy_to_user(buf, ker_buf_ptr, read_len as usize)
    } else {
        log::error!("[sys_pread] fd {} not opened", fd);
        Err(Errno::EBADF)
    }
}

pub fn sys_preadv(fd: usize, iov_ptr: *const IoVec, iovcnt: usize, offset: isize) -> SyscallRet {
    if offset < 0 {
        return Err(Errno::EINVAL);
    }
    if iovcnt == 0 {
        return Ok(0);
    }
    if iovcnt > i32::MAX as usize {
        return Err(Errno::EINVAL);
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
    if file.get_inode().can_lookup() {
        return Err(Errno::EISDIR);
    }

    let mut iovecs = vec![IoVec::default(); iovcnt];
    copy_from_user(iov_ptr, iovecs.as_mut_ptr(), iovcnt)?;

    let mut total_read = 0;
    let mut current_offset = offset as usize;
    let mut iovec_total_len = 0;

    for iovec in iovecs.iter() {
        iovec_total_len += iovec.len;
        if iovec.len == 0 {
            continue;
        }
        if iovec_total_len > isize::MAX as usize {
            log::error!("[sys_preadv] total length of iovec exceeds ssize_t max");
            return Err(Errno::EINVAL);
        }
        if current_offset.checked_add(iovec.len).is_none() {
            return Err(Errno::EINVAL);
        }

        let mut ker_buf = vec![0u8; iovec.len];
        let read_len = file.pread(&mut ker_buf, current_offset)?;
        if read_len == 0 {
            break;
        }

        copy_to_user(iovec.base as *mut u8, ker_buf.as_ptr(), read_len)?;

        total_read += read_len;
        current_offset += read_len;
    }

    Ok(total_read)
}

pub fn sys_pwrite(fd: usize, buf: *const u8, count: usize, offset: isize) -> SyscallRet {
    // log::info!(
    //     "[sys_pwrite] fd: {}, buf: {:?}, count: {}, offset: {}",
    //     fd,
    //     buf,
    //     count,
    //     offset
    // );
    if fd > isize::MAX as usize {
        log::error!("[sys_pwrite] fd is negative: {}", fd);
        return Err(Errno::EBADF);
    }
    if offset < 0 {
        log::error!("[sys_pwrite] offset is negative or too large: {}", offset);
        return Err(Errno::EINVAL);
    }
    if count == 0 {
        log::warn!("[sys_pwrite] count is 0, returning 0");
        return Ok(0);
    }
    let task = current_task();
    let file = task.fd_table().get_file(fd as usize);
    if let Some(file) = file {
        if !file.writable() {
            return Err(Errno::EBADF);
        }
        let mut ker_buf = vec![0u8; count];
        copy_from_user(buf, ker_buf.as_mut_ptr(), count)?;
        // log::warn!(
        //     "[sys_pwrite] ker_buf: {:?}",
        //     String::from_utf8(ker_buf.clone())
        // );
        file.pwrite(&ker_buf, offset as usize)
    } else {
        log::error!("[sys_pwrite] fd {} not opened", fd);
        Err(Errno::EBADF)
    }
}

pub fn sys_pwritev(fd: usize, iov_ptr: *const IoVec, iovcnt: usize, offset: isize) -> SyscallRet {
    log::info!(
        "[sys_pwritev] fd: {}, iov_ptr: {:?}, iovcnt: {}, offset: {}",
        fd,
        iov_ptr,
        iovcnt,
        offset
    );
    if offset < 0 {
        return Err(Errno::EINVAL);
    }
    if iovcnt == 0 {
        return Ok(0);
    }
    if iovcnt > i32::MAX as usize {
        return Err(Errno::EINVAL);
    }
    let task = current_task();
    let file = task.fd_table().get_file(fd);
    if file.is_none() {
        return Err(Errno::EBADF);
    }
    let file = file.unwrap();
    // 先检查是否支持随机访问， 再检查权限
    file.can_seek()?;
    if !file.writable() {
        return Err(Errno::EBADF);
    }
    if file.get_inode().can_lookup() {
        return Err(Errno::EISDIR);
    }

    let mut iovecs = vec![IoVec::default(); iovcnt];
    copy_from_user(iov_ptr, iovecs.as_mut_ptr(), iovcnt)?;

    let mut total_written = 0;
    let mut current_offset = offset as usize;
    let mut iovec_total_len = 0;

    for iovec in iovecs.iter() {
        iovec_total_len += iovec.len;
        if iovec.len == 0 {
            continue;
        }
        if iovec_total_len > isize::MAX as usize {
            log::error!("[sys_pwritev] total length of iovec exceeds ssize_t max");
            return Err(Errno::EINVAL);
        }
        if current_offset.checked_add(iovec.len).is_none() {
            return Err(Errno::EINVAL);
        }

        let mut ker_buf = vec![0u8; iovec.len];
        copy_from_user(iovec.base as *const u8, ker_buf.as_mut_ptr(), iovec.len)?;
        let written = file.pwrite(&ker_buf, current_offset)?;
        total_written += written;
        current_offset += written;
    }

    Ok(total_written)
}

/*
    `sysdeps/unix/sysv/linux/preadv2.c`
    ssize_t result = SYSCALL_CANCEL (preadv2, fd, vector, count,
                     LO_HI_LONG (offset), flags);
    `sysdeps/unix/sysv/linux/x86_64/sysdep.h`
    #define LO_HI_LONG(val) (val), 0`
*/
pub fn sys_preadv2(
    fd: usize,
    iov_ptr: *const IoVec,
    iovcnt: usize,
    offset_low: i32,
    offset_hign: i32,
    flags: i32,
) -> SyscallRet {
    log::info!(
        "[sys_preadv2] fd: {}, iov_ptr: {:?}, iovcnt: {}, offset_low: {}, offset_hign: {}, flags: {}",
        fd,
        iov_ptr,
        iovcnt,
        offset_low,
        offset_hign,
        flags,
    );
    // Todo: 需要实现flags
    if flags != 0 {
        log::warn!("[sys_pwritev2] flags is not 0, Unimplemented: {}", flags);
    }
    if flags < 0 {
        log::error!("[sys_pwritev2] flags is negative: {}", flags);
        return Err(Errno::EOPNOTSUPP);
    }
    let offset = ((offset_hign as isize) << 32) | (offset_low as isize);
    if offset < 0 && offset != -1 {
        log::error!("[sys_pwritev2] offset is negative or too large: {}", offset);
        return Err(Errno::EINVAL);
    }
    if offset == -1 {
        log::warn!("[sys_pwritev2] offset is -1, using current file offset");
        sys_readv(fd, iov_ptr, iovcnt)
    } else {
        sys_preadv(fd, iov_ptr, iovcnt, offset)
    }
}

/// offset != -1显示指定偏移写入，不影响文件当前偏移
/// offest == -1则使用文件当前偏移写入, 写完后更新
pub fn sys_pwritev2(
    fd: usize,
    iov_ptr: *const IoVec,
    iovcnt: usize,
    offset: isize,
    flags: i32,
) -> SyscallRet {
    log::info!(
        "[sys_pwritev2] fd: {}, iov_ptr: {:?}, iovcnt: {}, offset: {}, flags: {}",
        fd,
        iov_ptr,
        iovcnt,
        offset,
        flags
    );
    // Todo: 需要实现flags
    if flags != 0 {
        log::warn!("[sys_pwritev2] flags is not 0, Unimplemented: {}", flags);
    }
    if offset < 0 && offset != -1 {
        log::error!("[sys_pwritev2] offset is negative or too large: {}", offset);
        return Err(Errno::EINVAL);
    }
    if offset == -1 {
        log::warn!("[sys_pwritev2] offset is -1, using current file offset");
        sys_writev(fd, iov_ptr, iovcnt)
    } else {
        sys_pwritev(fd, iov_ptr, iovcnt, offset)
    }
}

/// 注意Fd_flags并不会在dup中继承
pub fn sys_dup(oldfd: usize) -> SyscallRet {
    log::info!("[sys_dup] oldfd: {}", oldfd);
    let task = current_task();
    task.fd_table().dup(oldfd)
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
    if (flags & !(OpenFlags::O_CLOEXEC.bits())) != 0 {
        return Err(Errno::EINVAL);
    }
    if newfd == oldfd {
        log::info!("[sys_dup3] oldfd and newfd are the same, return EINVAL");
        return Err(Errno::EINVAL);
    }
    let fd_flags = if flags & OpenFlags::O_CLOEXEC.bits() != 0 {
        // 设置FD_CLOEXEC标志
        FdFlags::FD_CLOEXEC
    } else {
        // 不设置FD_CLOEXEC标志
        FdFlags::empty()
    };
    task.fd_table().dup3(oldfd, newfd, fd_flags)
}

/// 如果最后一个路径组件是符号链接, 则删除符号链接不跟随
pub fn sys_unlinkat(dirfd: i32, pathname: *const u8, flag: i32) -> SyscallRet {
    let path = c_str_to_string(pathname)?;
    log::info!(
        "[sys_unlinkat] dirfd: {}, pathname: {:?}, flag: {}",
        dirfd,
        path,
        flag
    );
    if path.len() > PATH_MAX {
        log::error!("[sys_unlinkat] pathname is too long: {}", path.len());
        return Err(Errno::ENAMETOOLONG);
    }
    if flag & !AT_REMOVEDIR != 0 {
        log::error!("[sys_unlinkat] invalid flag: {}", flag);
        return Err(Errno::EINVAL);
    }
    let mut nd = Nameidata::new(&path, dirfd)?;
    match filename_lookup(&mut nd, false) {
        Ok(dentry) => {
            debug_assert!(!dentry.is_negative());
            let dir_dentry = nd.dentry.clone();
            // 检查父目录是否有写权限
            dentry_check_access(&dir_dentry, W_OK, true)?;
            // 检查是否是目录
            if dentry.is_dir() && (flag & AT_REMOVEDIR) == 0 {
                log::error!("[sys_unlinkat] cannot unlink a directory without AT_REMOVEDIR");
                return Err(Errno::EISDIR);
            }
            let parent_inode = dir_dentry.get_inode();
            parent_inode.unlink(dentry.clone())?;
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
    let oldpath = c_str_to_string(oldpath)?;
    let newpath = c_str_to_string(newpath)?;
    log::info!(
        "[sys_linkat] olddirfd: {}, oldpath: {:?}, newdirfd: {}, newpath: {:?}, flags: {}",
        olddirfd,
        oldpath,
        newdirfd,
        newpath,
        flags
    );
    if oldpath.len() > NAME_MAX || newpath.len() > NAME_MAX {
        log::error!(
            "[sys_linkat] oldpath or newpath is too long: {}, {}",
            oldpath.len(),
            newpath.len()
        );
        return Err(Errno::ENAMETOOLONG);
    }
    // Todo: fake, 需要支持mount
    if oldpath == "/proc/meminfo" || oldpath == "/proc/cpuinfo" {
        return Err(Errno::EXDEV);
    }
    if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
        log::error!("[sys_linkat] invalid flags: {}", flags);
        return Err(Errno::EINVAL);
    }
    let follow_symlink = flags & AT_SYMLINK_FOLLOW != 0;
    let mut old_nd = Nameidata::new(&oldpath, olddirfd)?;
    match filename_lookup(&mut old_nd, follow_symlink) {
        Ok(old_dentry) => {
            let mut new_nd = Nameidata::new(&newpath, newdirfd)?;
            if old_dentry.is_dir() {
                log::error!("[sys_linkat] old_dentry is dir");
                return Err(Errno::EPERM);
            }
            let new_fake_lookup_flags = 0;
            match filename_create(&mut new_nd, new_fake_lookup_flags) {
                Ok(new_dentry) => {
                    // 父目录要有写权限
                    dentry_check_access(&new_nd.dentry, W_OK, true)?;
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

/// 创建符号链接
/// 如果 linkpath 已存在，则不会被覆盖。
pub fn sys_symlinkat(target: *const u8, newdirfd: i32, linkpath: *const u8) -> SyscallRet {
    let target = c_str_to_string(target)?;
    let linkpath = c_str_to_string(linkpath)?;
    if linkpath.len() > PATH_MAX {
        log::error!("[sys_symlinkat] target is too long: {}", target.len());
        return Err(Errno::ENAMETOOLONG);
    }
    log::info!(
        "[sys_symlinkat] target: {:?}, newdirfd: {}, linkpath: {:?}",
        target,
        newdirfd,
        linkpath
    );
    let mut nd = Nameidata::new(&linkpath, newdirfd)?;
    let fake_lookup_flags = 0;
    match filename_create(&mut nd, fake_lookup_flags) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.symlink(dentry, target);
            return Ok(0);
        }
        Err(e) => {
            log::info!(
                "[sys_symlinkat] fail to create symlink: {}, {:?}",
                linkpath,
                e
            );
            return Err(e);
        }
    }
}

/// mode是直接传递给ext4_create, 由其处理(仅当O_CREAT设置时有效, 指定inode的权限)
/// flags影响文件的打开, 在flags中指定O_CREAT, 则创建文件
pub fn sys_openat(dirfd: i32, pathname: *const u8, flags: i32, mode: i32) -> SyscallRet {
    let flags = OpenFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
    let task = current_task();
    let path = c_str_to_string(pathname)?;
    if path.len() > PATH_MAX {
        log::error!("[sys_openat] pathname is too long: {}", path.len());
        return Err(Errno::ENAMETOOLONG);
    }
    log::info!(
        "[sys_openat] dirfd: {}, pathname: {:?}, flags: {:?}, mode: 0o{:o}",
        dirfd,
        path,
        flags,
        mode
    );
    let file = path_openat(&path, flags, dirfd, mode)?;
    let fd_flags = FdFlags::from(&flags);
    task.fd_table().alloc_fd(file, fd_flags)
}

/// Todo: RESOLVE_IN_ROOT没有作用于路径解析中的符号链接, 可能需要Nameidata保存root
pub fn sys_openat2(dirfd: i32, pathname: *const u8, how_ptr: *const u8, size: usize) -> SyscallRet {
    let path = c_str_to_string(pathname)?;
    if path.len() > PATH_MAX {
        log::error!("[sys_openat2] pathname is too long: {}", path.len());
        return Err(Errno::ENAMETOOLONG);
    }

    if size < core::mem::size_of::<OpenHow>() {
        log::error!(
            "[sys_openat2] size mismatch: expected {}, got {}",
            core::mem::size_of::<OpenHow>(),
            size
        );
        return Err(Errno::EINVAL);
    }
    log::info!("[sys_openat2] how_ptr: {:?}, size: {}", how_ptr, size);
    let mut openhow_buf = vec![0u8; size];
    copy_from_user(how_ptr, openhow_buf.as_mut_ptr(), size)?;
    // 如果超出 OpenHow 的大小的buf不是全零的话, 返回E2big
    if size > core::mem::size_of::<OpenHow>()
        && !openhow_buf[core::mem::size_of::<OpenHow>()..]
            .iter()
            .all(|&b| b == 0)
    {
        log::error!("[sys_openat2] buffer is too big or not zero-padded");
        return Err(Errno::E2BIG);
    }
    let how = unsafe {
        // 安全地将指针转换为 OpenHow 结构体
        &*(openhow_buf.as_ptr() as *const OpenHow)
    };
    // 检查mode
    if how.mode > 0o777 {
        log::error!("[sys_openat2] mode is invalid: {}", how.mode);
        return Err(Errno::EINVAL);
    }
    let open_flags = OpenFlags::from_bits(how.flags as i32).ok_or(Errno::EINVAL)?;
    let has_create =
        open_flags.contains(OpenFlags::O_CREAT) || open_flags.contains(OpenFlags::O_TMPFILE);
    // 若没有设置 O_CREAT 或 O_TMPFILE，mode 必须为 0（防止无效模式）
    if !has_create && how.mode != 0 {
        log::error!("[sys_openat2] mode must be zero when O_CREAT or O_TMPFILE is non set");
        return Err(Errno::EINVAL);
    }
    log::info!(
        "[sys_openat2] dirfd: {}, pathname: {:?}, flags: {:?}, mode: 0o{:o}, resolve: 0x{:x}",
        dirfd,
        path,
        open_flags,
        how.mode,
        how.resolve,
    );
    let resolve_flags = ResolveFlags::from_bits(how.resolve).ok_or(Errno::EINVAL)?;
    // Todo: fake, 需要支持mount
    if (resolve_flags.contains(ResolveFlags::RESOLVE_NO_XDEV)
        || resolve_flags.contains(ResolveFlags::RESOLVE_BENEATH))
        && path == "/proc/version"
    {
        return Err(Errno::EXDEV);
    }
    if resolve_flags.contains(ResolveFlags::RESOLVE_NO_MAGICLINKS) {
        if path.starts_with("/proc/") {
            return Err(Errno::ELOOP);
        }
    }
    let task = current_task();
    let in_root = resolve_flags.contains(ResolveFlags::RESOLVE_IN_ROOT);
    // let file = path_openat(&path, open_flags, dirfd, how.mode as i32)?;
    // 解析路径的目录部分，遇到最后一个组件时停止
    let mut nd = Nameidata::new2(&path, dirfd, in_root)?;
    let mut file;
    loop {
        link_path_walk2(&mut nd, &resolve_flags)?;
        // 到达最后一个组件
        match open_last_lookups2(&mut nd, open_flags, how.mode as i32, &resolve_flags) {
            Ok(f) => {
                file = f;
                break;
            }
            Err(e) => return Err(e),
        }
    }
    let fd_flags = FdFlags::from(&open_flags);
    task.fd_table().alloc_fd(file, fd_flags)
}

/// mode是inode类型+文件权限
pub fn sys_mknodat(dirfd: i32, pathname: *const u8, mode: usize, dev: u64) -> SyscallRet {
    let path = c_str_to_string(pathname)?;
    // 7.2 Debug
    if path.ends_with("sock") {
        log::warn!("[sys_mknodat] creating a socket file: {}", path);
    }
    log::info!(
        "[sys_mknodat] dirfd: {}, pathname: {:?}, mode: {:#o}, dev: {}",
        dirfd,
        path,
        mode,
        dev
    );
    if path.len() > PATH_MAX {
        log::error!("[sys_mknodat] pathname is too long: {}", path.len());
        return Err(Errno::ENAMETOOLONG);
    }
    let mut nd = Nameidata::new(&path, dirfd)?;
    let fake_lookup_flags = 0;
    // 兼容旧的设备号格式(16位)
    let dev_t = if dev < 0xffff {
        convert_old_dev_to_new(dev)
    } else {
        DevT::new(dev)
    };
    match filename_create(&mut nd, fake_lookup_flags) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            if (mode as u16 & S_IFMT) == S_IFREG {
                parent_inode.create(dentry, mode as u16);
            } else {
                parent_inode.mknod(dentry, mode as u16, dev_t);
            }
            return Ok(0);
        }
        Err(e) => {
            log::info!("[sys_mknodat] fail to create file: {}, {:?}", path, e);
            return Err(e);
        }
    }
}

pub fn sys_mkdirat(dirfd: isize, pathname: *const u8, mode: usize) -> SyscallRet {
    let path = c_str_to_string(pathname)?;
    log::info!(
        "[sys_mkdirat] dirfd: {}, pathname: {:?}, mode: {:#o}",
        dirfd,
        path,
        mode
    );
    let mut nd = Nameidata::new(&path, dirfd as i32)?;
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
    cwd.push('\0'); // 添加字符串结束符
    let copy_len = cwd.len();
    if copy_len > PATH_MAX {
        log::error!("[sys_getcwd]: path is too long: {}", copy_len);
    }
    if copy_len > buf_size {
        log::error!("[sys_getcwd]: buffer is too small");
        // buf太小返回NULL
        return Err(Errno::ERANGE);
    }
    let from: *const u8 = cwd.as_bytes().as_ptr();
    if let Err(err) = copy_to_user(buf, from, copy_len) {
        log::error!("[sys_getcwd]: copy_to_user failed: {:?}", err);
        return Err(err);
    }
    // 成功返回buf指针
    Ok(buf as usize)
}

// 仅仅是根据初赛的文档要求, 后续需要根据man7修改
pub fn sys_fstat(dirfd: i32, statbuf: *mut Stat) -> SyscallRet {
    log::info!("[sys_fstat] dirfd: {}, statbuf: {:?}", dirfd, statbuf);
    if let Some(file) = current_task().fd_table().get_file(dirfd as usize) {
        let inode = file.get_inode();
        let stat = Stat::from(inode.getattr());
        log::error!("[sys_fstat] stat is {:?}", stat);
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
/// 中间路径部分始终会跟随符号链接, 只有最后一部分受AT_SYMLINK_NOFOLLOW影响
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
pub const AT_SYMLINK_FOLLOW: i32 = 0x400;
pub const AT_NO_AUTOMOUNT: i32 = 0x800;
pub const AT_STATX_SYNC_TYPE: i32 = 0x6000;

pub fn sys_fstatat(dirfd: i32, pathname: *const u8, statbuf: *mut Stat, flags: i32) -> SyscallRet {
    if flags & AT_EMPTY_PATH != 0 {
        return sys_fstat(dirfd, statbuf);
    }
    if flags & !(AT_SYMLINK_NOFOLLOW) != 0 {
        log::error!("[sys_fstatat] invalid flags: {}", flags);
        return Err(Errno::EINVAL);
    }
    let path = c_str_to_string(pathname)?;
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
    let mut nd = Nameidata::new(&path, dirfd)?;
    let follow_symlink = flags & AT_SYMLINK_NOFOLLOW == 0;
    match filename_lookup(&mut nd, follow_symlink) {
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

/// 默认跟随符号链接
pub fn sys_chdir(pathname: *const u8) -> SyscallRet {
    let path = c_str_to_string(pathname)?;
    if path.len() > NAME_MAX {
        log::error!("[sys_chdir] pathname is too long: {}", path.len());
        return Err(Errno::ENAMETOOLONG);
    }
    log::info!("[sys_chdir] pathname: {:?}", path);
    let mut nd = Nameidata::new(&path, AT_FDCWD)?;
    match filename_lookup(&mut nd, true) {
        Ok(dentry) => {
            if !dentry.is_dir() {
                log::error!("[sys_chdir] chdir path must be a directory");
                return Err(Errno::ENOTDIR);
            }
            if !dentry.can_search() {
                log::error!("[sys_chdir] chdir path must be searchable");
                return Err(Errno::EACCES);
            }
            current_task().set_pwd(Path::new(nd.mnt, dentry));
            Ok(0)
        }
        Err(e) => {
            log::info!("[sys_chdir] fail to chdir: {}, {:?}", path, e);
            Err(e)
        }
    }
}

pub fn sys_fchdir(fd: usize) -> SyscallRet {
    log::info!("[sys_fchdir] fd: {}", fd);
    let task = current_task();
    if let Some(file) = task.fd_table().get_file(fd as usize) {
        let path = file.get_path();
        dentry_check_access(&path.dentry, X_OK, true)?;
        current_task().set_pwd(path);
        Ok(0)
    } else {
        log::error!("[sys_fchdir] fd {} not opened", fd);
        Err(Errno::EBADF)
    }
}

/// 默认跟随符号链接
pub fn sys_chroot(pathname: *const u8) -> SyscallRet {
    let path = c_str_to_string(pathname)?;
    log::info!("[sys_chroot] pathname: {:?}", path);
    if path.len() > NAME_MAX {
        log::error!("[sys_chroot] pathname is too long: {}", path.len());
        return Err(Errno::ENAMETOOLONG);
    }
    let task = current_task();
    let mut nd = Nameidata::new(&path, AT_FDCWD)?;
    match filename_lookup(&mut nd, true) {
        Ok(dentry) => {
            if !dentry.is_dir() {
                log::error!("[sys_chroot] chroot path must be a directory");
                return Err(Errno::ENOTDIR);
            }
            // Todo: 权限检查, 目前仅允许root用户执行chroot
            if !dentry.can_search() {
                log::error!("[sys_chroot] chroot path must be searchable");
                return Err(Errno::EACCES);
            }
            if task.fsuid() != 0 {
                log::error!("[sys_chroot] only root can chroot");
                return Err(Errno::EPERM);
            }
            current_task().set_root(Path::new(nd.mnt, dentry));
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
    let pipe_pair = make_pipe(flags);
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
    copy_to_user(fdset_ptr, pipe.as_ptr(), 2)?;
    Ok(0)
}

pub fn sys_close(fd: usize) -> SyscallRet {
    let task = current_task();
    let fd_table = task.fd_table();
    log::error!("[sys_close] fd: {}, task: {}", fd, task.tid());
    if fd_table.close(fd) {
        Ok(0)
    } else {
        log::warn!("[sys_close] fd {} not opened", fd);
        Err(Errno::EBADF)
    }
}

pub fn sys_close_range(first: usize, last: usize, flags: i32) -> SyscallRet {
    log::info!(
        "[sys_close_range] first: {}, last: {}, flags: {}",
        first,
        last,
        flags
    );
    if first > last {
        log::error!("[sys_close_range] first is greater than last");
        return Err(Errno::EINVAL);
    }
    let flags = CloseRangeFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
    let task = current_task();
    let fd_table = task.fd_table();
    fd_table.close_range(first, last, flags)
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
    let oldpath = c_str_to_string(oldpath)?;
    let newpath = c_str_to_string(newpath)?;
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
    let mut old_nd = Nameidata::new(&oldpath, olddirfd)?;
    match filename_lookup(&mut old_nd, true) {
        Ok(old_dentry) => {
            let mut new_nd = Nameidata::new(&newpath, newdirfd)?;
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
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum FcntlOp {
    F_DUPFD = 0,
    F_GETFD = 1,
    F_SETFD = 2,
    F_GETFL = 3,
    F_SETFL = 4,
    F_DUPFD_CLOEXEC = 1030,
    F_SETPIPE_SZE = 1031, // 设置管道大小
    F_GETPIPE_SZ = 1032,  // 获取管道大小
}

impl TryFrom<i32> for FcntlOp {
    type Error = ();
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(FcntlOp::F_DUPFD),
            1 => Ok(FcntlOp::F_GETFD),
            2 => Ok(FcntlOp::F_SETFD),
            3 => Ok(FcntlOp::F_GETFL),
            4 => Ok(FcntlOp::F_SETFL),
            1030 => Ok(FcntlOp::F_DUPFD_CLOEXEC),
            1031 => Ok(FcntlOp::F_SETPIPE_SZE),
            1032 => Ok(FcntlOp::F_GETPIPE_SZ),
            _ => Err(()),
        }
    }
}

// Todo: 还有Op没有实现
pub fn sys_fcntl(fd: i32, op: i32, arg: usize) -> SyscallRet {
    log::info!("[sys_fcntl] fd: {}, op: {}, arg: {}", fd, op, arg);
    let task = current_task();
    task.fd_table().fcntl(fd as usize, op, arg)
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

/// pselect用于检查多个文件描述符的状态
/// 函数会在3中情况退出：1.存在文件可读可写 2. timeout 3.存在信号
/// nfds:文件描述符范围，会检查0-nfds-1的所有文件描述符
/// readfds:可读文件描述符地址
/// writefds:可写文件描述符地址
/// exceptfds:异常文件描述符地址
/// timeout:超时时间,如果timeout为null,会阻塞
/// mask:信号掩码
/// 基本步骤如下：
/// 1.根据nfds和readfds构造对应的掩码数组，read,write,except3中
/// 2.一个loop来不断判断file[i]的状态，并更新read,write,except的掩码
/// 3.处理timeout和signal结果
pub fn sys_pselect6(
    nfds: usize,
    readfds: usize,
    writefds: usize,
    exceptfds: usize,
    timeout: *const TimeSpec,
    sigmask: usize,
) -> SyscallRet {
    // log::error!("[sys_pselecct6] nfds: {}, readfds: {:?}, writefds: {:?}, exceptfds: {:?}, timeout: {:?}, mask: {}",nfds,readfds,writefds,exceptfds,timeout,mask);
    log::error!("[sys_pselect6]:begin pselect6,nfds {:?},readfds {:?},writefds {:?},exceptfds {:?},timeout {:?},sigmask {:?}",nfds,readfds,writefds,exceptfds,timeout,sigmask);
    let starttime = get_time_us();
    let timeout = if timeout.is_null() {
        //timeout为空则是阻塞
        -1
    } else {
        let mut tmo: TimeSpec = TimeSpec::default();
        copy_from_user(timeout, &mut tmo as *mut TimeSpec, 1)?;
        log::error!(
            "[sys_pselect6] tmo sec is {:?},tmo nsec is {:?}",
            tmo.sec,
            tmo.nsec
        );
        let sec_signed = tmo.sec as isize;
        if sec_signed < 0 {
            return Err(Errno::EINVAL);
        }
        (tmo.sec * 1000000 + tmo.nsec / 1000) as isize
    };
    log::error!("[sys_pselect6] timeout is {:?}", timeout);
    let mut readfditer = match init_fdset(readfds, nfds) {
        Ok(rfditer) => rfditer,
        Err(e) => return Err(e),
    };
    let mut writeiter = match init_fdset(writefds, nfds) {
        Ok(wfditer) => wfditer,
        Err(e) => return Err(e),
    };
    let mut exceptiter = match init_fdset(exceptfds, nfds) {
        Ok(exceptiter) => exceptiter,
        Err(e) => return Err(e),
    };
    let task = current_task();
    let origin_sigset = task.op_sig_pending_mut(|sig_pending| sig_pending.mask.clone());
    if sigmask != 0 {
        let mut sigset: SigSet = SigSet::default();
        copy_from_user(sigmask as *const SigSet, &mut sigset as *mut SigSet, 1)?;
        task.op_sig_pending_mut(|sig_pending| sig_pending.mask = sigset);
    }
    drop(task);
    let mut set = 0;

    loop {
        log::trace!("[sys_pselect6]:loop");
        //这里必须要yield否则会死机
        yield_current_task();
        set = 0;
        if readfditer.fdset.valid() {
            for fd in 0..readfditer.fds.len() {
                log::trace!("[sys_pselect6] read fd: {}", readfditer.fds[fd]);
                if readfditer.files[fd].r_ready() {
                    //e内核会根据嗅探的结果设置fdset的对应位为1
                    log::trace!("[sys_pselect6] set read fd is {:?}", readfditer.fds[fd]);
                    readfditer.fdset.set(readfditer.fds[fd]);
                    set += 1;
                }
            }
        }
        // log::error!("[sys_pselect6] after read set is: {}", set);
        if writeiter.fdset.valid() {
            for i in 0..writeiter.fds.len() {
                if writeiter.files[i].w_ready() {
                    writeiter.fdset.set(writeiter.fds[i]);
                    set += 1;
                }
            }
        }
        if set > 0 {
            break;
        }
        if timeout == 0 {
            // timeout为0表示立即返回, 即使没有fd准备好
            log::trace!("[sys_pselect] timeout is 0");
            break;
        } else if timeout > 0 {
            if get_time_us() - starttime > timeout as usize {
                // 超时了, 返回
                // println!("[sys_pselect] get_time_ms {:?},timeout {:?}",get_time_ms(),timeout);
                log::error!("[sys_pselect6]:timeout");
                log::trace!("[sys_pselect]:timeout");
                break;
            }
        }
        let task = current_task();
        if task.op_sig_pending_mut(|sig_pending| sig_pending.pending.contain_signal(Sig::SIGKILL)) {
            return Err(Errno::EINTR);
        }
        drop(task);
        log::trace!("[loop]");
        yield_current_task();
    }
    //无论set是否为0,均需要将内核的readfds和writefds写回去
    if readfds != 0 {
        // log::error!("[sys_pselect6] readfds fdset addr is {:?}",readfditer.fdset.get_addr());
        copy_to_user(
            readfds as *mut usize,
            readfditer.fdset.get_addr() as *const usize,
            readfditer.fdset.get_len(),
        )?;
    }
    if writefds != 0 {
        copy_to_user(
            writefds as *mut usize,
            writeiter.fdset.get_addr() as *const usize,
            nfds,
        )?;
    }
    if exceptfds != 0 {
        copy_to_user(
            exceptfds as *mut usize,
            exceptiter.fdset.get_addr() as *const usize,
            nfds,
        )
        .unwrap();
    }
    //恢复信号
    if sigmask != 0 {
        let task = current_task();
        task.op_sig_pending_mut(|sig_pending| sig_pending.mask = origin_sigset);
    }
    if set > 0 {
        return Ok(set);
    }
    return Ok(0);
}
// pub fn sys_pselect6(
//     nfds: usize,
//     readfds: usize,
//     writefds: usize,
//     exceptfds: usize,
//     timeout: *const TimeSpec,
//     sigmask: usize,
// )->SyscallRet {
//     log::error!("[sys_pselect6]:begin pselect6,nfds {:?},readfds {:?},writefds {:?},exceptfds {:?},timeout {:?},sigmask {:?}",nfds,readfds,writefds,exceptfds,timeout,sigmask);
//     let mut tmo=TimeSpec::default();
//     if !timeout.is_null() {
//         //timeout地址不为空则需要设置时钟
//         copy_from_user(timeout, &mut tmo as *mut TimeSpec, 1)?;
//         log::error!(
//             "[sys_pselect6] tmo sec is {:?},tmo nsec is {:?}",
//             tmo.sec,
//             tmo.nsec
//         );
//     }
//     let has_deadline=!timeout.is_null();
//     //届时根据tmo是否为default判断是否需要设置
//     let mut readfditer = match init_fdset(readfds, nfds) {
//         Ok(rfditer) => rfditer,
//         Err(e) => return Err(e),
//     };
//     let mut writeiter = match init_fdset(writefds, nfds) {
//         Ok(wfditer) => wfditer,
//         Err(e) => return Err(e),
//     };
//     let mut exceptiter = match init_fdset(exceptfds, nfds) {
//         Ok(exceptiter) => exceptiter,
//         Err(e) => return Err(e),
//     };
//     let task = current_task();
//     let origin_sigset = task.op_sig_pending_mut(|sig_pending| sig_pending.mask.clone());
//     if sigmask != 0 {
//         let mut sigset: SigSet = SigSet::default();
//         copy_from_user(sigmask as *const SigSet, &mut sigset as *mut SigSet, 1)?;
//         task.op_sig_pending_mut(|sig_pending| sig_pending.mask = sigset);
//     }
//     drop(task);
//     let mut set = 0;
//     loop {
//         log::trace!("[sys_pselect6]:loop");
//         //这里必须要yield否则会死机
//         // yield_current_task();
//         set = 0;
//         let task = current_task();
//         let mut file_vec = Vec::new();
//         if readfditer.fdset.valid() {
//             for fd in 0..readfditer.fds.len() {
//                 log::trace!("[sys_pselect6] read fd: {}", readfditer.fds[fd]);
//                 if readfditer.files[fd].r_ready() {
//                     //e内核会根据嗅探的结果设置fdset的对应位为1
//                     log::trace!("[sys_pselect6] set read fd is {:?}", readfditer.fds[fd]);
//                     readfditer.fdset.set(readfditer.fds[fd]);
//                     set += 1;
//                     file_vec.push(readfditer.files[fd].clone());
//                 }
//             }
//         }
//         if writeiter.fdset.valid() {
//             for i in 0..writeiter.fds.len() {
//                 if writeiter.files[i].w_ready() {
//                     writeiter.fdset.set(writeiter.fds[i]);
//                     set += 1;
//                     file_vec.push(writeiter.files[i].clone());
//                 }
//             }
//         }
//         if set>0 {
//             break;
//         }
//         for file in file_vec{
//             log::error!("[sys_pselect6]task id is {:?}",task.tid());
//             file.add_wait_queue(task.tid());
//         }
//         if  has_deadline{
//             if tmo==TimeSpec::default() {
//                 break;
//             }
//             else {
//                 let ret = wait_timeout(tmo, -1);
//                 if ret == -1 {
//                     // 被信号唤醒
//                     log::error!("[sys_pselect6] wakeup by signal");
//                     return Err(Errno::EINTR);
//                 } else if ret == -2 {
//                     // 超时了, 返回
//                     log::error!("[sys_pselect6] timeout");
//                     break;
//                 }
//             }
//         }
//         else {
//             //一直阻塞
//             log::error!("[sys_pselect6] wait indefinitely");
//             wait();
//         }
//         if task.op_sig_pending_mut(|sig_pending| sig_pending.pending.contain_signal(Sig::SIGKILL)) {
//             return Err(Errno::EINTR);
//         }
//         drop(task);
//     }
//     //无论是否set为0,均需要返回
//     if readfds != 0 {
//         // log::error!("[sys_pselect6] readfds fdset addr is {:?}",readfditer.fdset.get_addr());
//         copy_to_user(
//             readfds as *mut usize,
//             readfditer.fdset.get_addr() as *const usize,
//             readfditer.fdset.get_len(),
//         )?;
//     }
//     if writefds != 0 {
//         copy_to_user(
//             writefds as *mut usize,
//             writeiter.fdset.get_addr() as *const usize,
//             nfds,
//         )?;
//     }
//     if exceptfds != 0 {
//         copy_to_user(
//             exceptfds as *mut usize,
//             exceptiter.fdset.get_addr() as *const usize,
//             nfds,
//         )
//         .unwrap();
//     }
//     if sigmask != 0 {
//         let task = current_task();
//         task.op_sig_pending_mut(|sig_pending| sig_pending.mask = origin_sigset);
//     }
//     if set > 0 {
//         return Ok(set);
//     }
//     return Ok(0);
// }

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
    if nfds > i32::MAX as usize {
        log::error!("[sys_ppoll] nfds is too large: {}", nfds);
        return Err(Errno::EINVAL);
    }
    let task = current_task();
    // 处理参数
    let has_deadline = !timeout.is_null();
    let mut tmo: TimeSpec = TimeSpec::default();
    if has_deadline {
        copy_from_user(timeout, &mut tmo as *mut TimeSpec, 1)?;
    }
    // Todo: 设置sigmaskconst
    // 用于保存原来的sigmask, 后续需要恢复
    let origin_sigset = task.op_sig_pending_mut(|sig_pending| sig_pending.mask.clone());
    if sigmask != 0 {
        let mut sigset: SigSet = SigSet::default();
        copy_from_user(sigmask as *const SigSet, &mut sigset as *mut SigSet, 1)?;
        task.op_sig_pending_mut(|sig_pending| sig_pending.mask = sigset);
    }
    drop(task);

    // Todo: 把fd的监听改成阻塞
    if !fds.is_null() {
        let mut poll_fds: Vec<PollFd> = vec![PollFd::default(); nfds];
        copy_from_user(fds, poll_fds.as_mut_ptr(), nfds)?;
        for poll_fd in poll_fds.iter_mut() {
            poll_fd.revents = PollEvents::empty();
        }
        let mut done;
        loop {
            log::trace!("[sys_ppoll]:loop");
            done = 0;
            let task = current_task();
            let mut file_vec = Vec::new();
            for i in 0..nfds {
                let poll_fd = &mut poll_fds[i];
                log::info!("[sys_ppoll] poll_fd: {:?}", poll_fd);
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
                        file_vec.push(file);
                        done += trigger;
                    } else {
                        // pollfd的fd字段大于0, 但是对应文件描述符并没有打开, 设置pollfd.revents为POLLNVAL
                        poll_fd.revents |= PollEvents::INVAL;
                        log::error!("[sys_ppoll] invalid fd: {}", poll_fd.fd);
                    }
                }
            }
            if done > 0 {
                log::error!("[sys_ppoll] done: {}", done);
                break;
            }
            // 添加等待队列
            for file in file_vec {
                // 添加到等待队列
                file.add_wait_queue(task.tid());
            }
            if has_deadline {
                if tmo == TimeSpec::default() {
                    // timeout为0表示立即返回, 即使没有fd准备好
                    log::error!("[sys_ppoll] timeout is 0");
                    break;
                } else {
                    let ret = wait_timeout(tmo, -1);
                    if ret == -1 {
                        // 被信号唤醒
                        log::error!("[sys_ppoll] wakeup by signal");
                        return Err(Errno::EINTR);
                    } else if ret == -2 {
                        // 超时了, 返回
                        log::error!("[sys_ppoll] timeout");
                        break;
                    }
                }
            } else {
                // 没有设置timeout, 无限期等待
                log::warn!("[sys_ppoll] wait indefinitely");
                wait();
            }
            log::info!("[sys_ppoll] wake up from wait");
        }
        // 写回用户空间
        copy_to_user(fds, poll_fds.as_ptr(), nfds)?;
        // 恢复origin sigmask
        if sigmask != 0 {
            let task = current_task();
            task.op_sig_pending_mut(|sig_pending| sig_pending.mask = origin_sigset);
        }
        Ok(done)
    } else {
        // 不监听fd，只是为了等待信号
        wait();
        log::error!("[sys_ppoll] wakeup by signal");
        return Err(Errno::EINTR);
    }
}

// pub fn sys_ppoll(
//     fds: *mut PollFd,
//     nfds: usize,
//     timeout: *const TimeSpec,
//     sigmask: usize,
// ) -> SyscallRet {
//     log::error!(
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
//         copy_from_user(timeout, &mut tmo as *mut TimeSpec, 1)?;
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

//     // Todo: 把fd的监听改成阻塞
//     if !fds.is_null() {
//         let mut poll_fds: Vec<PollFd> = vec![PollFd::default(); nfds];
//         copy_from_user(fds, poll_fds.as_mut_ptr(), nfds)?;
//         for poll_fd in poll_fds.iter_mut() {
//             poll_fd.revents = PollEvents::empty();
//         }
//         let mut done;
//         loop {
//             log::trace!("[sys_ppoll]:loop");
//             done = 0;
//             let task = current_task();
//             for i in 0..nfds {
//                 let poll_fd = &mut poll_fds[i];
//                 if poll_fd.fd < 0 {
//                     continue;
//                 } else {
//                     if let Some(file) = task.fd_table().get_file(poll_fd.fd as usize) {
//                         let mut trigger = 0;
//                         if file.hang_up() {
//                             poll_fd.revents |= PollEvents::HUP;
//                             trigger = 1;
//                         }
//                         if poll_fd.events.contains(PollEvents::IN) && file.r_ready() {
//                             poll_fd.revents |= PollEvents::IN;
//                             trigger = 1;
//                         }
//                         if poll_fd.events.contains(PollEvents::OUT) && file.w_ready() {
//                             poll_fd.revents |= PollEvents::OUT;
//                             trigger = 1;
//                         }
//                         done += trigger;
//                     } else {
//                         // pollfd的fd字段大于0, 但是对应文件描述符并没有打开, 设置pollfd.revents为POLLNVAL
//                         poll_fd.revents |= PollEvents::INVAL;
//                         log::error!("[sys_ppoll] invalid fd: {}", poll_fd.fd);
//                     }
//                 }
//             }
//             if done > 0 {
//                 log::error!("[sys_ppoll] done: {}", done);
//                 break;
//             }
//             if timeout == 0 {
//                 // timeout为0表示立即返回, 即使没有fd准备好
//                 break;
//             } else if timeout > 0 {
//                 if get_time_ms() > timeout as usize {
//                     // 超时了, 返回
//                     break;
//                 }
//             }
//             drop(task);
//             yield_current_task();
//         }
//         // 写回用户空间
//         copy_to_user(fds, poll_fds.as_ptr(), nfds)?;
//         // 恢复origin sigmask
//         if sigmask != 0 {
//             let task = current_task();
//             task.op_sig_pending_mut(|sig_pending| sig_pending.mask = origin_sigset);
//         }
//         Ok(done)
//     } else {
//         // 不监听fd，只是为了等待信号
//         wait();
//         log::error!("[sys_ppoll] wakeup by signal");
//         return Err(Errno::EINTR);
//     }
// }

pub fn sys_readlinkat(dirfd: i32, pathname: *const u8, buf: *mut u8, bufsiz: isize) -> SyscallRet {
    if bufsiz <= 0 {
        log::error!("[sys_readlinkat] bufsiz must be greater than 0");
        return Err(Errno::EINVAL);
    }
    let path = c_str_to_string(pathname)?;
    if path.len() > PATH_MAX {
        log::error!("[sys_readlinkat] pathname is too long: {}", path.len());
        return Err(Errno::ENAMETOOLONG);
    }
    if path.is_empty() {
        // 获取dirfd对应的符号链接
        if let Some(file) = current_task().fd_table().get_file(dirfd as usize) {
            let dentry = file.get_path().dentry.clone();
            if dentry.is_symlink() {
                let inode = file.get_inode();
                let link_path = inode.get_link();
                if link_path.len() > bufsiz as usize {
                    return Err(Errno::ENAMETOOLONG);
                }
                log::info!(
                    "[sys_readlinkat] readlinkat: {}, link_path: {:?}",
                    path,
                    link_path
                );
                copy_to_user(buf, link_path.as_ptr(), link_path.len())?;
                return Ok(link_path.len());
            } else {
                return Err(Errno::EINVAL);
            }
        }
    }
    let mut nd = Nameidata::new(&path, dirfd)?;
    match filename_lookup(&mut nd, false) {
        Ok(dentry) => {
            if dentry.is_symlink() {
                let inode = dentry.get_inode();
                let link_path = inode.get_link();
                if link_path.len() > bufsiz as usize {
                    return Err(Errno::ENAMETOOLONG);
                }
                log::info!(
                    "[sys_readlinkat] readlinkat: {}, link_path: {:?}",
                    path,
                    link_path
                );
                copy_to_user(buf, link_path.as_ptr(), link_path.len())?;
                return Ok(link_path.len());
            } else {
                return Err(Errno::EINVAL);
            }
        }
        Err(e) => {
            log::info!("[sys_readlinkat] fail to readlinkat: {}, {:?}", path, e);
            return Err(e);
        }
    }
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
    let path = if pathname.is_null() {
        if flags & AT_EMPTY_PATH == 0 {
            log::warn!("[sys_utimensat] pathname is NULL, but AT_EMPTY_PATH is not set");
            // 因为linux kernel abi, 这里不返回EINVAL
        }
        None
    } else {
        Some(c_str_to_string(pathname)?)
    };
    let mut time_spec2_buf: [TimeSpec; 2] = [TimeSpec::default(); 2];
    let time_specs = if time_spec2.is_null() {
        None
    } else {
        copy_from_user(time_spec2, &mut time_spec2_buf as *mut TimeSpec, 2)?;
        Some(&time_spec2_buf)
    };
    let inode = if let Some(path) = path {
        let mut nd = Nameidata::new(&path, dirfd)?;
        let follow_symlink = flags & AT_SYMLINK_NOFOLLOW == 0;
        match filename_lookup(&mut nd, follow_symlink) {
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
    let len: usize;
    if offset_ptr.is_null() {
        len = in_file.read(&mut buf)?;
    } else {
        // offset不为NULL, 则sendfile不会修改`in_fd`的文件偏移量
        let mut offset = 0;
        copy_from_user(offset_ptr, &mut offset, 1)?;
        let origin_offset = in_file.get_offset();
        in_file.seek(offset as isize, Whence::SeekSet)?;
        len = in_file.read(&mut buf)?;
        in_file.seek(origin_offset as isize, Whence::SeekSet)?;
        // 将新的偏移量写回用户空间
        copy_to_user(offset_ptr, &(offset + len), 1)?;
    }
    let ret = out_file.write(&buf[..len])?;
    log::info!("[sys_sendfile] ret: {}", ret);
    Ok(ret)
}

pub fn sys_ftruncate(fildes: usize, length: isize) -> SyscallRet {
    log::info!("[sys_ftruncate] fd: {}, length: {}", fildes, length);
    if length < 0 {
        log::error!("[sys_ftruncate] length is negative");
        return Err(Errno::EINVAL);
    }
    let task = current_task();
    if let Some(file) = task.fd_table().get_file(fildes) {
        let mode = file.get_inode().get_mode();
        if mode & S_IFSOCK == S_IFSOCK {
            log::error!("[sys_ftruncate] ftruncate on a socket");
            return Err(Errno::EINVAL);
        }
        if mode & S_IFDIR == S_IFDIR {
            log::error!("[sys_ftruncate] ftruncate on a directory");
            return Err(Errno::EISDIR);
        }
        if !file.writable() {
            log::error!("[sys_ftruncate] file is not writable");
            return Err(Errno::EINVAL);
        }
        file.truncate(length as usize)
    } else {
        Err(Errno::EBADF)
    }
}

pub fn sys_truncate(path: *const u8, length: isize) -> SyscallRet {
    const MAX_FILE_SIZE: usize = 16 * 1024 * 1024;
    log::info!("[sys_truncate] path: {:?}, length: {}", path, length);

    if length < 0 {
        log::error!("[sys_truncate] negative length");
        return Err(Errno::EINVAL);
    }
    if length >= MAX_FILE_SIZE as isize {
        log::error!("[sys_truncate] length exceeds maximum file size");
        return Err(Errno::EFBIG);
    }
    let path = c_str_to_string(path)?;
    if path.len() > PATH_MAX as usize {
        log::error!("[sys_truncate] pathname too long");
        return Err(Errno::ENAMETOOLONG);
    }
    let mut nd = Nameidata::new(&path, AT_FDCWD)?;
    let dentry = filename_lookup(&mut nd, true)?;

    if dentry.is_dir() {
        log::error!("[sys_truncate] truncate on directory");
        return Err(Errno::EISDIR);
    }
    dentry_check_access(&dentry, W_OK, true)?;
    dentry.get_inode().truncate(length as usize)
}

/* loongarch */
// Todo: 使用mask指示内核需要返回哪些信息
pub fn sys_statx(
    dirfd: i32,
    pathname: *const u8,
    flags: i32,
    mask: u32,
    statxbuf: *mut Statx,
    // statbuf: *mut Stat,
) -> SyscallRet {
    log::info!(
        "[sys_statx] dirfd: {}, pathname: {:?}, flags: {}, mask: {}",
        dirfd,
        pathname,
        flags,
        mask
    );
    if flags < 0 {
        log::error!("[sys_statx] invalid flags: {}", flags);
        return Err(Errno::EINVAL);
    }
    if flags & AT_EMPTY_PATH != 0 {
        if let Some(file) = current_task().fd_table().get_file(dirfd as usize) {
            let inode = file.get_inode();
            let statx = Statx::from(inode.getattr());
            log::error!("statx: statx: {:?}", statx);
            copy_to_user(statxbuf, &statx as *const Statx, 1)?;
            return Ok(0);
        }
        // 根据fd获取文件失败
        return Err(Errno::EBADF);
    }
    const VALID_MASK: u32 = STATX_TYPE
        | STATX_MODE
        | STATX_NLINK
        | STATX_UID
        | STATX_GID
        | STATX_ATIME
        | STATX_MTIME
        | STATX_CTIME
        | STATX_INO
        | STATX_SIZE
        | STATX_BLOCKS
        | STATX_BTIME
        | STATX_ALL;
    if (mask & !VALID_MASK) != 0 {
        log::error!("[sys_statx] invalid mask: {}", mask);
        return Err(Errno::EINVAL);
    }
    let path = c_str_to_string(pathname)?;
    if path.is_empty() {
        log::error!("[sys_statx] pathname is empty");
        return Err(Errno::ENOENT);
    }
    let mut nd = Nameidata::new(&path, dirfd)?;
    let follow_symlink = flags & AT_SYMLINK_NOFOLLOW == 0;
    match filename_lookup(&mut nd, follow_symlink) {
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

/// 请求文件类型 (stx_mode & S_IFMT)
pub const STATX_TYPE: u32 = 0x00000001;
/// 请求文件权限模式 (stx_mode & ~S_IFMT)
pub const STATX_MODE: u32 = 0x00000002;
/// 请求硬链接计数 (stx_nlink)
pub const STATX_NLINK: u32 = 0x00000004;
/// 请求文件所有者UID (stx_uid)
pub const STATX_UID: u32 = 0x00000008;
/// 请求文件所属组GID (stx_gid)
pub const STATX_GID: u32 = 0x00000010;
/// 请求最后访问时间 (stx_atime)
pub const STATX_ATIME: u32 = 0x00000020;
/// 请求最后修改时间 (stx_mtime)
pub const STATX_MTIME: u32 = 0x00000040;
/// 请求最后状态变更时间 (stx_ctime)
pub const STATX_CTIME: u32 = 0x00000080;
/// 请求inode编号 (stx_ino)
pub const STATX_INO: u32 = 0x00000100;
/// 请求文件大小 (stx_size)
pub const STATX_SIZE: u32 = 0x00000200;
/// 请求分配的磁盘块数 (stx_blocks)
pub const STATX_BLOCKS: u32 = 0x00000400;

/// 基础统计信息 (包含传统stat结构中的所有字段)
pub const STATX_BASIC_STATS: u32 = 0x000007ff;
pub const STATX_ALL: u32 = 0x00000fff;

/// 请求文件创建时间 (stx_btime)
pub const STATX_BTIME: u32 = 0x00000800;
/// 请求挂载点ID (stx_mnt_id)
pub const STATX_MNT_ID: u32 = 0x00001000;
/// 请求直接I/O对齐信息
pub const STATX_DIOALIGN: u32 = 0x00002000;
/// 请求扩展的唯一挂载点ID
pub const STATX_MNT_ID_UNIQUE: u32 = 0x00004000;
/// 请求子卷信息 (stx_subvol)
pub const STATX_SUBVOL: u32 = 0x00008000;
// pub fn sys_statx(
//     dirfd: i32,
//     pathname: *const u8,
//     flags: i32,
//     mask: u32,
//     statxbuf: *mut Statx,
// ) -> SyscallRet {
//     log::info!(
//         "[sys_statx] dirfd: {}, pathname: {:?}, flags: {}, mask: {}",
//         dirfd,
//         pathname,
//         flags,
//         mask
//     );

//     // 检查无效的标志组合
//     const VALID_FLAGS: i32 =
//         AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_STATX_SYNC_TYPE;
//     if (flags & !VALID_FLAGS) != 0 {
//         log::error!("[sys_statx] invalid flags: {}", flags);
//         return Err(Errno::EINVAL);
//     }

//     // 检查 mask 是否有效
//     const VALID_MASK: u32 = STATX_TYPE
//         | STATX_MODE
//         | STATX_NLINK
//         | STATX_UID
//         | STATX_GID
//         | STATX_ATIME
//         | STATX_MTIME
//         | STATX_CTIME
//         | STATX_INO
//         | STATX_SIZE
//         | STATX_BLOCKS
//         | STATX_BTIME
//         | STATX_ALL;
//     if (mask & !VALID_MASK) != 0 {
//         log::error!("[sys_statx] invalid mask: {}", mask);
//         return Err(Errno::EINVAL);
//     }

//     // 检查路径名是否为空
//     let path = c_str_to_string(pathname)?;
//     if path.is_empty() {
//         log::error!("[sys_statx] pathname is empty");
//         return Err(Errno::ENOENT);
//     }

//     // 处理过长的路径名
//     if path.len() > PATH_MAX as usize {
//         log::error!("[sys_statx] pathname too long");
//         return Err(Errno::ENAMETOOLONG);
//     }

//     // 处理 AT_EMPTY_PATH 标志
//     if flags & AT_EMPTY_PATH != 0 {
//         if let Some(file) = current_task().fd_table().get_file(dirfd as usize) {
//             let inode = file.get_inode();
//             let statx = Statx::from(inode.getattr());
//             // 根据 mask 过滤不需要的字段
//             let filtered_statx = filter_statx_by_mask(statx, mask);
//             log::debug!("statx: {:?}", filtered_statx);
//             copy_to_user(statxbuf, &filtered_statx as *const Statx, 1)?;
//             return Ok(0);
//         }
//         return Err(Errno::EBADF);
//     }

//     // 查找文件
//     let mut nd = Nameidata::new(&path, dirfd)?;
//     let follow_symlink = flags & AT_SYMLINK_NOFOLLOW == 0;

//     match filename_lookup(&mut nd, follow_symlink) {
//         Ok(dentry) => {
//             let inode = dentry.get_inode();
//             let statx = Statx::from(inode.getattr());
//             // 根据 mask 过滤不需要的字段
//             let filtered_statx = filter_statx_by_mask(statx, mask);
//             if let Err(e) = copy_to_user(statxbuf, &filtered_statx as *const Statx, 1) {
//                 log::error!("statx: copy_to_user failed: {:?}", e);
//                 return Err(e);
//             }
//             Ok(0)
//         }
//         Err(e) => {
//             log::info!("[sys_statx] fail to statx: {}, {:?}", path, e);
//             Err(e)
//         }
//     }
// }

/// 根据 mask 过滤不需要的 statx 字段
fn filter_statx_by_mask(mut statx: Statx, mut mask: u32) -> Statx {
    if mask == 0 {
        // 如果 mask 为 0，默认返回基本字段
        mask = STATX_BASIC_STATS;
    }
    // Todo: 根据 mask 清除不需要的字段
    statx
}

/* loongarch end */

// Todo: 需要支持除根目录以外的vfs挂载
pub fn sys_statfs(path: *const u8, buf: *mut StatFs) -> SyscallRet {
    let path = c_str_to_string(path)?;
    if path.is_empty() {
        log::error!("[sys_statfs] pathname is empty");
        return Err(Errno::EINVAL);
    }
    if path.len() > PATH_MAX as usize {
        log::error!("[sys_statfs] pathname too long");
        return Err(Errno::ENAMETOOLONG);
    }
    log::info!("[sys_statfs] path: {:?}, buf: {:?}", path, buf);
    let mut nd = Nameidata::new(&path, AT_FDCWD)?;
    let dentry = filename_lookup(&mut nd, true)?;
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
}

/// Todo: 需要支持除根目录以外的vfs挂j
pub fn sys_fstatfs(fd: usize, buf: *mut StatFs) -> SyscallRet {
    log::info!("[sys_fstatfs] fd: {}, buf: {:?}", fd, buf);
    let task = current_task();
    if let Some(file) = task.fd_table().get_file(fd) {
        // let dentry = file.get_path().dentry.clone();
        let dentry = task.root().dentry.clone();
        let mount = get_mount_by_dentry(dentry).ok_or(Errno::ENOENT)?;
        match mount.statfs(buf) {
            Ok(_) => {
                log::info!("[sys_fstatfs] success to fstatfs");
                return Ok(0);
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
    Err(Errno::EBADF)
}

pub fn sys_copy_file_range(
    in_fd: usize,
    in_off_ptr: usize,
    out_fd: usize,
    out_off_ptr: usize,
    len: usize,
    flags: i32,
) -> SyscallRet {
    log::info!(
        "[sys_copy_file_range] in_fd: {}, in_off_ptr: {:#x}, out_fd: {}, out_off_ptr: {:#x}, len: {}, flags: {}",
        in_fd,
        in_off_ptr,
        out_fd,
        out_off_ptr,
        len,
        flags
    );

    if len >= 0x1000000000000 {
        log::error!("[sys_copy_file_range] len is too large");
        return Err(Errno::EINVAL);
    }

    let task = current_task();
    let in_file = task.fd_table().get_file(in_fd);
    let out_file = task.fd_table().get_file(out_fd);

    if let (Some(in_file), Some(out_file)) = (in_file, out_file) {
        if !in_file.readable() || !out_file.writable() {
            log::error!("[sys_copy_file_range] invalid fd");
            return Err(Errno::EBADF);
        }

        let mut in_off = 0usize;
        let mut out_off = 0usize;

        // 从用户空间读取偏移值（如果提供了指针）
        if in_off_ptr != 0 {
            copy_from_user(in_off_ptr as *const usize, &mut in_off, 1)?;
        }
        if out_off_ptr != 0 {
            copy_from_user(out_off_ptr as *const usize, &mut out_off, 1)?;
        }

        // 分配缓冲区并读取数据
        if len > EXT4_MAX_FILE_SIZE {
            // Todo: 应该分块
            log::error!("[sys_copy_file_range] length exceeds max file size");
            return Err(Errno::EINVAL);
        } else {
            let mut buf = vec![0u8; len];
            let read_len = if in_off_ptr == 0 {
                in_file.read(&mut buf)?
            } else {
                in_file.pread(&mut buf, in_off)?
            };

            if read_len == 0 {
                log::info!("[sys_copy_file_range] reached end of file, nothing copied");
                return Ok(0);
            }

            let write_len = if out_off_ptr == 0 {
                out_file.write(&buf[..read_len])?
            } else {
                out_file.pwrite(&buf[..read_len], out_off)?
            };

            // 更新偏移值并写回用户空间
            if in_off_ptr != 0 {
                let new_in_off = in_off + read_len;
                copy_to_user(in_off_ptr as *mut usize, &new_in_off, 1)?;
            }
            if out_off_ptr != 0 {
                let new_out_off = out_off + write_len;
                copy_to_user(out_off_ptr as *mut usize, &new_out_off, 1)?;
            }

            Ok(write_len)
        }
    } else {
        Err(Errno::EBADF)
    }
}

pub fn sys_umask(mask: usize) -> SyscallRet {
    log::info!("[sys_umask] mask: {:o}", mask);
    let task = current_task();
    let old_mask = task.umask();
    task.set_umask(mask as u16 & 0o777);
    Ok(old_mask as usize)
}

/* Todo: fake start  */
pub fn sys_fallocate(fd: usize, mode: i32, offset: isize, len: isize) -> SyscallRet {
    log::info!(
        "[sys_fallocate] fd: {}, mode: {}, offset: {}, len: {}",
        fd,
        mode,
        offset,
        len
    );
    if offset < 0 || len <= 0 {
        log::error!("[sys_fallocate] offset or len is negative");
        return Err(Errno::EINVAL);
    }
    if offset as usize + len as usize > EXT4_MAX_FILE_SIZE {
        log::error!("[sys_fallocate] offset + len exceeds max file size");
        return Err(Errno::EFBIG);
    }
    let mode = FallocFlags::from_bits(mode).ok_or(Errno::EINVAL)?;
    let task = current_task();
    if let Some(file) = task.fd_table().get_file(fd) {
        // let dentry = file.get_path().dentry.clone();
        if file.get_inode().get_mode() & S_IFDIR != 0 {
            log::error!("[sys_fallocate] fallocate on a directory");
            return Err(Errno::EISDIR);
        }
        if file.get_flags().contains(OpenFlags::O_WRONLY)
            || file.get_flags().contains(OpenFlags::O_RDWR)
        {
            return file.fallocate(mode, offset as usize, len as usize);
        } else {
            log::error!("[sys_fallocate] fd is not writable");
            return Err(Errno::EBADF);
        }
    }
    Err(Errno::EBADF)
}

pub fn sys_mount(
    source: *const u8,
    target: *const u8,
    fs_type: *const u8,
    flags: usize,
    _data: *const u8,
) -> SyscallRet {
    let source = c_str_to_string(source)?;
    let target = c_str_to_string(target)?;
    let fs_type = c_str_to_string(fs_type)?;
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

// 使用有效user and group id检查文件访问权限(faccessat默认使用real id检查)
pub const AT_EACCESS: i32 = 0x200;

/// 检查进程是否可以访问指定的文件
/// Todo: 目前只检查pathname指定的文件是否存在, 没有检查权限
pub fn sys_faccessat(fd: usize, pathname: *const u8, mode: i32, flags: i32) -> SyscallRet {
    let path = c_str_to_string(pathname)?;
    if path.is_empty() {
        log::error!("[sys_faccessat] pathname is empty");
        return Err(Errno::EINVAL);
    }
    // 检查 mode 是否合法：只能包含 F_OK, R_OK, W_OK, X_OK
    if mode & !(F_OK | R_OK | W_OK | X_OK) != 0 {
        log::error!("[sys_faccessat] Invalid mode: {}", mode);
        return Err(Errno::EINVAL);
    }
    // 检查 flags 是否只包含支持的标志
    let supported_flags =
        AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | 0x60 | 0x2 | 0xfffe | 0x1 | 0xca4b2;
    if flags & !supported_flags != 0 {
        log::error!("[sys_faccessat] Unsupported flags: {:#x}", flags);
        return Err(Errno::EINVAL);
    }
    log::info!(
        "[sys_faccessat] fd: {}, pathname: {:?}, mode: {}, flags: {}",
        fd,
        path,
        mode,
        flags
    );
    let mut nd = Nameidata::new(&path, fd as i32)?;
    let follow_symlink = flags & AT_SYMLINK_NOFOLLOW == 0;
    let dentry = filename_lookup(&mut nd, follow_symlink)?;
    if mode == 0 {
        // mode为0表示只检查文件是否存在
        return Ok(0);
    }
    let use_effective = flags & AT_EACCESS != 0;
    dentry_check_access(&dentry, mode, use_effective)
}

pub fn sys_sync() -> SyscallRet {
    log::info!("[sys_sync] Unimplemented");
    Ok(0)
}

pub fn sys_fsync(fd: usize) -> SyscallRet {
    let file = current_task().fd_table().get_file(fd);
    if let Some(file) = file {
        log::info!("[sys_fsync] fd: {}", fd);
        return file.fsync();
    }
    return Err(Errno::EBADF);
}

pub fn sys_fdatasync(fd: usize) -> SyscallRet {
    log::info!("[sys_fdatasync] fd: {}", fd);
    let file = current_task().fd_table().get_file(fd);
    if let Some(file) = file {
        return file.fdatasync();
    }
    Err(Errno::EBADF)
}

// 定义标志位常量
pub const SYNC_FILE_RANGE_WAIT_BEFORE: i32 = 1;
pub const SYNC_FILE_RANGE_WRITE: i32 = 2;
pub const SYNC_FILE_RANGE_WAIT_AFTER: i32 = 4;

/// Todo: 现在只有错误检查，还需要实现具体的同步逻辑
pub fn sys_sync_file_range(fd: usize, offset: isize, nbytes: isize, flags: i32) -> SyscallRet {
    if offset < 0 || nbytes < 0 {
        return Err(Errno::EINVAL);
    }
    // 检查标志位有效性
    let valid_flags =
        SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;

    if flags & !valid_flags != 0 {
        return Err(Errno::EINVAL);
    }
    let file = current_task().fd_table().get_file(fd).ok_or(Errno::EBADF)?;
    // Todo:
    return file.fsync();
}

pub const MS_ASYNC: i32 = 1;
pub const MS_SYNC: i32 = 4;
pub const MS_INVALIDATE: i32 = 2;

pub fn sys_msync(addr: usize, len: usize, flags: i32) -> SyscallRet {
    log::info!(
        "[sys_msync] addr: {:#x}, len: {}, flags: {}",
        addr,
        len,
        flags
    );
    if addr % PAGE_SIZE != 0 {
        log::error!("[sys_msync] addr is not page aligned");
        return Err(Errno::EINVAL);
    }
    if flags & !(MS_ASYNC | MS_SYNC | MS_INVALIDATE) != 0 {
        log::error!("[sys_msync] Invalid flags: {:#x}", flags);
        return Err(Errno::EINVAL);
    }
    if flags & MS_ASYNC != 0 && flags & MS_SYNC != 0 {
        log::error!("[sys_msync] MS_ASYNC and MS_SYNC cannot be used together");
        return Err(Errno::EINVAL);
    }
    let start_vpn = VirtAddr::from(addr).floor();
    let end_vpn = VirtAddr::from(addr + len).ceil();
    let mut covered_vpn: VirtPageNum = end_vpn;
    let sync_range = VPNRange::new(start_vpn, end_vpn);
    current_task().op_memory_set_mut(|mm| {
        for (_vpn, area) in mm.areas.range_mut(..end_vpn).rev() {
            if let Some(overlap_range) = area.vpn_range.intersection(&sync_range) {
                // 如果内存区域与同步范围有交集, 则进行同步
                log::info!(
                    "[sys_msync] Syncing memory area: {:?} for range: {:?}",
                    area,
                    overlap_range
                );
                if area.map_type != MapType::Filebe {
                    log::error!(
                        "[sys_msync] Only file-backed memory areas can be synced, found: {:?}",
                        area.map_type
                    );
                    return Err(Errno::ENOMEM);
                }
                if area.locked {
                    log::error!("[sys_msync] Memory area is locked, cannot sync");
                    return Err(Errno::EBUSY);
                }
                if flags & MS_INVALIDATE != 0 {
                    // 如果是MS_INVALIDATE, 则需要清除页面内容
                    log::info!("[sys_msync] Invalidating memory area: {:?}", area);
                    // 如果完全覆盖了, 则直接清除页面内容
                    if sync_range.is_contain(&area.vpn_range) {
                        log::info!("[sys_msync] Invalidating entire memory area: {:?}", area);
                        // 清除整个内存区域的页面内容
                        // Todo: 还应该清除backend_file的页缓存
                        area.pages.clear();
                    } else {
                        // 只清除覆盖范围内的页面内容(后半部分)
                        area.pages.retain(|vpn, _page| vpn < &start_vpn);
                    }
                } else {
                    area.pages
                        .range_mut(overlap_range.get_start()..overlap_range.get_end())
                        .for_each(|(_vpn, page)| {
                            page.sync();
                        });
                }
                covered_vpn = overlap_range.get_start();
            } else {
                // 如果内存区域与同步范围没有交集, 则可以退出
                break;
            }
        }
        if covered_vpn == start_vpn {
            return Ok(0);
        } else {
            return Err(Errno::ENOMEM);
        }
    })
}

pub fn sys_fchmod(fd: usize, mode: usize) -> SyscallRet {
    log::info!("[sys_fchmod] fd: {}, mode: {:o}", fd, mode);
    let task = current_task();
    if let Some(file) = task.fd_table().get_file(fd) {
        // Todo: 检查权限
        let flags = file.get_flags();
        if flags.contains(OpenFlags::O_PATH) {
            log::error!("[sys_fchmod] O_PATH files cannot be modified");
            return Err(Errno::EBADF);
        }
        // 修改权限
        file.get_inode().set_perm(mode as u16);
        Ok(0)
    } else {
        Err(Errno::EBADF)
    }
}

/// 文件名的最大长度
pub const NAME_MAX: usize = 255;
/// 绝对路径的最大长度
pub const PATH_MAX: usize = 4096;

/// 将 path 参数指向的文件权限位修改为mode
/// root 可任意修改任何文件的权限,无需检查其他条件
/// 普通用户的euid需要与文件的Owner相同才能修改文件权限
pub fn sys_fchmodat(fd: usize, path: *const u8, mode: usize, flag: i32) -> SyscallRet {
    let path = c_str_to_string(path)?;
    if path.len() > NAME_MAX {
        log::error!("[sys_fchmodat] path is too long: {}", path.len());
        return Err(Errno::ENAMETOOLONG);
    }
    if path.is_empty() {
        log::error!("[sys_fchmodat] path is empty");
        return Err(Errno::ENOENT);
    }
    log::info!(
        "[sys_fchmodat] fd: {}, path: {:?}, mode: {:o}, flag: {}",
        fd,
        path,
        mode,
        flag
    );
    let mut nd = Nameidata::new(&path, fd as i32)?;
    let follow_symlink = flag & AT_SYMLINK_NOFOLLOW == 0;
    match filename_lookup(&mut nd, follow_symlink) {
        Ok(dentry) => {
            let inode = dentry.get_inode();
            // Todo: 检查权限
            // if !current_task().can_write(&inode) {
            //     log::error!("[sys_fchmodat] permission denied");
            //     return Err(Errno::EACCES);
            // }
            // 修改权限
            inode.set_perm(mode as u16);
            return Ok(0);
        }
        Err(e) => {
            log::info!("[sys_fchmodat] fail to fchmodat: {}, {:?}", path, e);
            return Err(e);
        }
    }
}

pub fn sys_fchownat(fd: usize, path: *const u8, owner: u32, group: u32, flag: i32) -> SyscallRet {
    let path = c_str_to_string(path)?;
    if path.len() > NAME_MAX {
        log::error!("[sys_fchownat] path is too long: {}", path.len());
        return Err(Errno::ENAMETOOLONG);
    }
    if flag & !(AT_SYMLINK_NOFOLLOW) != 0 {
        log::error!("[sys_fchownat] Invalid flags: {:#x}", flag);
        return Err(Errno::EINVAL);
    }
    log::info!(
        "[sys_fchownat] fd: {}, path: {:?}, owner: {}, group: {}, flag: {}",
        fd,
        path,
        owner,
        group,
        flag
    );

    let mut nd = Nameidata::new(&path, fd as i32)?;
    let follow_symlink = flag & AT_SYMLINK_NOFOLLOW == 0;
    let dentry = filename_lookup(&mut nd, follow_symlink)?;
    chown(&dentry.get_inode(), owner, group)
}

pub fn sys_fchown(fd: usize, owner: u32, group: u32) -> SyscallRet {
    log::info!(
        "[sys_fchown] fd: {}, owner: {}, group: {}",
        fd,
        owner,
        group
    );
    let task = current_task();
    let file = task.fd_table().get_file(fd).ok_or(Errno::EBADF)?;
    if file.get_flags().contains(OpenFlags::O_PATH) {
        log::error!("[sys_fchown] O_PATH files cannot be modified");
        return Err(Errno::EBADF);
    }
    chown(&file.get_inode(), owner, group)
}

pub const POSIX_FADV_NORMAL: i32 = 0;
pub const POSIX_FADV_RANDOM: i32 = 1;
pub const POSIX_FADV_SEQUENTIAL: i32 = 2;
pub const POSIX_FADV_WILLNEED: i32 = 3;
pub const POSIX_FADV_DONTNEED: i32 = 4;
pub const POSIX_FADV_NOREUSE: i32 = 5;

pub fn sys_fadvise64(fd: usize, offset: usize, len: usize, advice: i32) -> SyscallRet {
    log::info!(
        "[sys_fadvise64] fd: {}, offset: {}, len: {}, advice: {}",
        fd,
        offset,
        len,
        advice
    );
    log::warn!("[sys_fadvise64] Unimplemented");
    // 检查合法的 advice 类型
    match advice {
        0..=5 => {}
        _ => return Err(Errno::EINVAL),
    }
    let file = current_task().fd_table().get_file(fd).ok_or(Errno::EBADF)?;
    // 目前不支持任何操作
    file.fadvise(offset, len, advice)
}

pub fn sys_fsopen(fs_name: *const u8, flags: i32) -> SyscallRet {
    let fs_name = c_str_to_string(fs_name)?;
    log::info!("[sys_fsopen] fs_name: {:?}, flags: {}", fs_name, flags);
    if fs_name.is_empty() {
        log::error!("[sys_fsopen] fs_name is empty");
        return Err(Errno::EINVAL);
    }
    if fs_name.len() > NAME_MAX {
        log::error!("[sys_fsopen] fs_name is too long: {}", fs_name.len());
        return Err(Errno::ENAMETOOLONG);
    }
    Ok(0)
}

pub fn sys_getxattr(
    pathname: *const u8,
    name: *const u8,
    value_ptr: *mut u8,
    size: usize,
) -> SyscallRet {
    log::info!(
        "[sys_getxattr] pathname: {:?}, name: {:?}, value_ptr: {:?}, size: {}",
        pathname,
        name,
        value_ptr,
        size
    );
    let path = c_str_to_string(pathname)?;
    if path.is_empty() {
        log::error!("[sys_getxattr] pathname is empty");
        return Err(Errno::ENOENT);
    }
    let name = c_str_to_string(name)?;
    if name.is_empty() {
        log::error!("[sys_getxattr] name is empty");
        return Err(Errno::EINVAL);
    }
    if name.len() > NAME_MAX {
        log::error!("[sys_getxattr] name is too long: {}", name.len());
        return Err(Errno::ERANGE);
    }
    let mut nd = Nameidata::new(&path, AT_FDCWD)?;
    let dentry = filename_lookup(&mut nd, true)?;
    let value = dentry.get_inode().getxattr(&name)?;
    if value.len() > size {
        log::error!("[sys_getxattr] buffer too small");
        return Err(Errno::ERANGE);
    }
    // 将属性值复制到用户空间
    let n = copy_to_user(value_ptr, value.as_ptr(), value.len())?;
    return Ok(n);
}

pub fn sys_lgetxattr(
    pathname: *const u8,
    name: *const u8,
    value_ptr: *mut u8,
    size: usize,
) -> SyscallRet {
    log::info!(
        "[sys_lgetxattr] pathname: {:?}, name: {:?}, value_ptr: {:?}, size: {}",
        pathname,
        name,
        value_ptr,
        size
    );
    let path = c_str_to_string(pathname)?;
    if path.is_empty() {
        log::error!("[sys_lgetxattr] pathname is empty");
        return Err(Errno::ENOENT);
    }
    let name = c_str_to_string(name)?;
    if name.is_empty() {
        log::error!("[sys_lgetxattr] name is empty");
        return Err(Errno::EINVAL);
    }
    if name.len() > NAME_MAX {
        log::error!("[sys_lgetxattr] name is too long: {}", name.len());
        return Err(Errno::ERANGE);
    }
    let mut nd = Nameidata::new(&path, AT_FDCWD)?;
    let dentry = filename_lookup(&mut nd, false)?;
    let value = dentry.get_inode().getxattr(&name)?;
    if value.len() > size {
        log::error!("[sys_lgetxattr] buffer too small");
        return Err(Errno::ERANGE);
    }
    // 将属性值复制到用户空间
    let n = copy_to_user(value_ptr, value.as_ptr(), value.len())?;
    return Ok(n);
}

pub fn sys_fgetxattr(fd: usize, name: *const u8, value_ptr: *mut u8, size: usize) -> SyscallRet {
    log::info!(
        "[sys_fgetxattr] fd: {}, name: {:?}, value_ptr: {:?}, size: {}",
        fd,
        name,
        value_ptr,
        size
    );
    let name = c_str_to_string(name)?;
    if name.is_empty() {
        log::error!("[sys_fgetxattr] name is empty");
        return Err(Errno::EINVAL);
    }
    if name.len() > NAME_MAX {
        log::error!("[sys_fgetxattr] name is too long: {}", name.len());
        return Err(Errno::ERANGE);
    }
    let task = current_task();
    if let Some(file) = task.fd_table().get_file(fd) {
        let flags = file.get_flags();
        if flags.contains(OpenFlags::O_PATH) {
            log::error!("[sys_fgetxattr] O_PATH files cannot be accessed");
            return Err(Errno::EBADF);
        }
        let value = file.get_inode().getxattr(&name)?;
        // 如果 value_ptr 是 NULL 且 size=0，直接返回属性值的长度（不复制数据）
        if value_ptr.is_null() && size == 0 {
            log::info!("[sys_fgetxattr] querying attribute size only");
            return Ok(value.len());
        }
        if value.len() > size {
            log::error!("[sys_fgetxattr] buffer too small");
            return Err(Errno::ERANGE);
        }
        // 将属性值复制到用户空间
        let n = copy_to_user(value_ptr, value.as_ptr(), value.len())?;
        return Ok(n);
    }
    Err(Errno::EBADF)
}

pub fn sys_listxattr(pathname: *const u8, list_ptr: *mut u8, size: usize) -> SyscallRet {
    log::info!(
        "[sys_listxattr] pathname: {:?}, list_ptr: {:?}, size: {}",
        pathname,
        list_ptr,
        size
    );
    let path = c_str_to_string(pathname)?;
    if path.is_empty() {
        log::error!("[sys_listxattr] pathname is empty");
        return Err(Errno::ENOENT);
    }
    let mut nd = Nameidata::new(&path, AT_FDCWD)?;
    let dentry = filename_lookup(&mut nd, true)?;
    let xattrs = dentry.get_inode().listxattr()?;
    let total_size = xattrs.iter().map(|s| s.len() + 1).sum::<usize>();
    if list_ptr.is_null() && size == 0 {
        // 如果 list_ptr 是 NULL 且 size=0，直接返回属性名列表的总大小
        log::info!("[sys_listxattr] querying attribute names size only");
        return Ok(total_size);
    }
    if total_size > size {
        log::error!("[sys_listxattr] buffer too small");
        return Err(Errno::ERANGE);
    }
    // 将属性名列表复制到用户空间
    let mut offset = 0;
    for name in xattrs {
        unsafe {
            copy_to_user(list_ptr.add(offset), name.as_ptr(), name.len())?;
        }
        unsafe { *(list_ptr.add(offset + name.len())) = 0 }; // 添加空字符结尾
        offset += name.len() + 1;
    }
    Ok(total_size)
}

pub fn sys_llistxattr(pathname: *const u8, list_ptr: *mut u8, size: usize) -> SyscallRet {
    log::info!(
        "[sys_llistxattr] pathname: {:?}, list_ptr: {:?}, size: {}",
        pathname,
        list_ptr,
        size
    );
    let path = c_str_to_string(pathname)?;
    if path.is_empty() {
        log::error!("[sys_llistxattr] pathname is empty");
        return Err(Errno::ENOENT);
    }
    let mut nd = Nameidata::new(&path, AT_FDCWD)?;
    let dentry = filename_lookup(&mut nd, false)?;
    let xattrs = dentry.get_inode().listxattr()?;
    let total_size = xattrs.iter().map(|s| s.len() + 1).sum::<usize>();
    if list_ptr.is_null() && size == 0 {
        // 如果 list_ptr 是 NULL 且 size=0，直接返回属性名列表的总大小
        log::info!("[sys_llistxattr] querying attribute names size only");
        return Ok(total_size);
    }
    if total_size > size {
        log::error!("[sys_llistxattr] buffer too small");
        return Err(Errno::ERANGE);
    }
    // 将属性名列表复制到用户空间
    let mut offset = 0;
    for name in xattrs {
        unsafe {
            copy_to_user(list_ptr.add(offset), name.as_ptr(), name.len())?;
        }
        unsafe { *(list_ptr.add(offset + name.len())) = 0 }; // 添加空字符结尾
        offset += name.len() + 1;
    }
    Ok(total_size)
}

pub fn sys_flistxattr(fd: usize, list_ptr: *mut u8, size: usize) -> SyscallRet {
    log::info!(
        "[sys_flistxattr] fd: {}, list_ptr: {:?}, size: {}",
        fd,
        list_ptr,
        size
    );
    let task = current_task();
    if let Some(file) = task.fd_table().get_file(fd) {
        let flags = file.get_flags();
        if flags.contains(OpenFlags::O_PATH) {
            log::error!("[sys_flistxattr] O_PATH files cannot be accessed");
            return Err(Errno::EBADF);
        }
        let xattrs = file.get_inode().listxattr()?;
        let total_size = xattrs.iter().map(|s| s.len() + 1).sum::<usize>();
        if list_ptr.is_null() && size == 0 {
            // 如果 list_ptr 是 NULL 且 size=0，直接返回属性名列表的总大小
            log::info!("[sys_flistxattr] querying attribute names size only");
            return Ok(total_size);
        }
        if total_size > size {
            log::error!("[sys_flistxattr] buffer too small");
            return Err(Errno::ERANGE);
        }
        // 将属性名列表复制到用户空间
        let mut offset = 0;
        for name in xattrs {
            unsafe {
                copy_to_user(list_ptr.add(offset), name.as_ptr(), name.len())?;
            }
            unsafe { *(list_ptr.add(offset + name.len())) = 0 }; // 添加空字符结尾
            offset += name.len() + 1;
        }
        return Ok(total_size);
    }
    Err(Errno::EBADF)
}

// 当操作对象是符号链接时，扩展属性会设置在链接本身而非其指向的文件上。
pub fn sys_lsetxattr(
    pathname: *const u8,
    name: *const u8,
    value_ptr: *const u8,
    size: usize,
    flags: i32,
) -> SyscallRet {
    log::info!(
        "[sys_lsetxattr] pathname: {:?}, name: {:?}, value: {:?}, size: {}",
        pathname,
        name,
        value_ptr,
        size
    );
    let flags = SetXattrFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
    if size > XATTR_SIZE_MAX {
        log::error!("[sys_lsetxattr] size is too large");
        return Err(Errno::E2BIG);
    }
    let path = c_str_to_string(pathname)?;
    if path.is_empty() {
        log::error!("[sys_lsetxattr] pathname is empty");
        return Err(Errno::ENOENT);
    }
    let name = c_str_to_string(name)?;
    if name.is_empty() {
        log::error!("[sys_lsetxattr] name is empty");
        return Err(Errno::EINVAL);
    }
    if name.len() > NAME_MAX {
        log::error!("[sys_lsetxattr] name is too long: {}", name.len());
        return Err(Errno::ERANGE);
    }
    let mut value = vec![0; size];
    copy_from_user(value_ptr, value.as_mut_ptr(), size);
    let mut nd = Nameidata::new(&path, AT_FDCWD)?;
    let dentry = filename_lookup(&mut nd, false)?;
    dentry.get_inode().setxattr(name, value, &flags)
}

pub fn sys_fsetxattr(
    fd: usize,
    name: *const u8,
    value_ptr: *const u8,
    size: usize,
    flags: i32,
) -> SyscallRet {
    log::info!(
        "[sys_fsetxattr] fd: {}, name: {:?}, value: {:?}, size: {}, flags: {}",
        fd,
        name,
        value_ptr,
        size,
        flags
    );
    let flags = SetXattrFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
    if size > XATTR_SIZE_MAX {
        log::error!("[sys_fsetxattr] size is too large");
        return Err(Errno::E2BIG);
    }
    let name = c_str_to_string(name)?;
    if name.is_empty() {
        log::error!("[sys_fsetxattr] name is empty");
        return Err(Errno::ERANGE);
    }
    if name.len() > NAME_MAX {
        log::error!("[sys_fsetxattr] name is too long: {}", name.len());
        return Err(Errno::ERANGE);
    }
    let mut value = vec![0; size];
    copy_from_user(value_ptr, value.as_mut_ptr(), size);
    let task = current_task();
    if let Some(file) = task.fd_table().get_file(fd) {
        file.get_inode().setxattr(name, value, &flags)
    } else {
        Err(Errno::EBADF)
    }
}

pub fn sys_setxattr(
    pathname: *const u8,
    name: *const u8,
    value_ptr: *const u8,
    size: usize,
    flags: i32,
) -> SyscallRet {
    log::info!(
        "[sys_setxattr] pathname: {:?}, name: {:?}, value: {:?}, size: {}, flags: {}",
        pathname,
        name,
        value_ptr,
        size,
        flags
    );
    let flags = SetXattrFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
    if size > XATTR_SIZE_MAX {
        log::error!("[sys_setxattr] size is too large");
        return Err(Errno::E2BIG);
    }
    let path = c_str_to_string(pathname)?;
    if path.is_empty() {
        log::error!("[sys_setxattr] pathname is empty");
        return Err(Errno::ENOENT);
    }
    let name = c_str_to_string(name)?;
    if name.is_empty() {
        log::error!("[sys_setxattr] name is empty");
        return Err(Errno::ERANGE);
    }
    if name.len() > NAME_MAX {
        log::error!("[sys_setxattr] name is too long: {}", name.len());
        return Err(Errno::ERANGE);
    }
    let mut value = vec![0; size];
    copy_from_user(value_ptr, value.as_mut_ptr(), size);
    let mut nd = Nameidata::new(&path, AT_FDCWD)?;
    let dentry = filename_lookup(&mut nd, true)?;
    dentry.get_inode().setxattr(name, value, &flags)
}

pub fn sys_removexattr(pathname: *const u8, name: *const u8) -> SyscallRet {
    log::info!(
        "[sys_removexattr] pathname: {:?}, name: {:?}",
        pathname,
        name
    );
    let path = c_str_to_string(pathname)?;
    if path.is_empty() {
        log::error!("[sys_removexattr] pathname is empty");
        return Err(Errno::ENOENT);
    }
    let name = c_str_to_string(name)?;
    if name.is_empty() {
        log::error!("[sys_removexattr] name is empty");
        return Err(Errno::EINVAL);
    }
    if name.len() > NAME_MAX {
        log::error!("[sys_removexattr] name is too long: {}", name.len());
        return Err(Errno::ERANGE);
    }
    let mut nd = Nameidata::new(&path, AT_FDCWD)?;
    let dentry = filename_lookup(&mut nd, true)?;
    dentry.get_inode().removexattr(&name)
}

pub fn sys_lremovexattr(pathname: *const u8, name: *const u8) -> SyscallRet {
    log::info!(
        "[sys_lremovexattr] pathname: {:?}, name: {:?}",
        pathname,
        name
    );
    let path = c_str_to_string(pathname)?;
    if path.is_empty() {
        log::error!("[sys_lremovexattr] pathname is empty");
        return Err(Errno::ENOENT);
    }
    let name = c_str_to_string(name)?;
    if name.is_empty() {
        log::error!("[sys_lremovexattr] name is empty");
        return Err(Errno::EINVAL);
    }
    if name.len() > NAME_MAX {
        log::error!("[sys_lremovexattr] name is too long: {}", name.len());
        return Err(Errno::ERANGE);
    }
    let mut nd = Nameidata::new(&path, AT_FDCWD)?;
    let dentry = filename_lookup(&mut nd, false)?;
    dentry.get_inode().removexattr(&name)
}

pub fn sys_fremovexattr(fd: usize, name: *const u8) -> SyscallRet {
    log::info!("[sys_fremovexattr] fd: {}, name: {:?}", fd, name);
    let name = c_str_to_string(name)?;
    if name.is_empty() {
        log::error!("[sys_fremovexattr] name is empty");
        return Err(Errno::EINVAL);
    }
    if name.len() > NAME_MAX {
        log::error!("[sys_fremovexattr] name is too long: {}", name.len());
        return Err(Errno::ERANGE);
    }
    let task = current_task();
    if let Some(file) = task.fd_table().get_file(fd) {
        file.get_inode().removexattr(&name)
    } else {
        Err(Errno::EBADF)
    }
}

pub fn sys_memfd_create(name: *const u8, flags: u32) -> SyscallRet {
    log::info!("[sys_memfd_create] name: {:?}, flags: {}", name, flags);
    let name = c_str_to_string(name)?;
    if name.is_empty() {
        log::error!("[sys_memfd_create] name is empty");
        return Err(Errno::EINVAL);
    }
    if name.len() > NAME_MAX {
        log::error!("[sys_memfd_create] name is too long: {}", name.len());
        return Err(Errno::ENAMETOOLONG);
    }

    unimplemented!()
}

/* fake end */

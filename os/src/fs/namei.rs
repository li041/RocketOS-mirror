use core::panic;

use super::{
    dentry::{insert_dentry, lookup_dcache_with_absolute_path, Dentry},
    dev::tty::{TtyFile, TTY},
    file::{File, FileOp, OpenFlags},
    inode::InodeOp,
    mount::VfsMount,
    path::Path,
    pipe::Pipe,
    proc::{
        exe::EXE,
        maps::MAPS,
        meminfo::{self, MEMINFO},
        mounts::{MountsFile, MOUNTS},
        pagemap::PAGEMAP,
        pid::PID_STAT,
        status::STATUS,
    },
    tmp,
    uapi::ResolveFlags,
    FileOld, Stdin, FS_BLOCK_SIZE,
};
use crate::{
    ext4::{
        dentry,
        inode::{self, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFMT, S_IFREG},
    },
    fs::{
        dentry::{dentry_check_open, DentryFlags},
        dev::{
            loop_device::{get_loop_device, LOOP_CONTROL},
            null::NULL,
            rtc::RTC,
            urandom::URANDOM,
            zero::ZERO,
        },
        fdtable::{FdEntry, FdFlags},
        proc::{
            cpuinfo::CPUINFO,
            fd::{record_fd, FD_FILE},
            pid::{record_target_pid, TARGERT_PID},
            pid_max::PIDMAX,
            smaps::SMAPS,
            tainted::TAINTED,
        },
        AT_FDCWD,
    },
    syscall::{errno::Errno, AT_SYMLINK_NOFOLLOW, NAME_MAX},
    task::current_task,
};
use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

pub struct Nameidata {
    pub(crate) path_segments: Vec<String>,
    // 以下字段在路径解析过程中需要更新
    // 通过dentry可以找到inode
    // 注意Dentry和InodeOp的锁粒度都在他们自己的结构体内部
    pub(crate) dentry: Arc<Dentry>,
    pub(crate) mnt: Arc<VfsMount>,
    // pub path: Path,
    // 当前处理到的路径
    pub(crate) depth: usize,
    // pub(crate) symlink_depth: usize, // 解析符号链接的次数, 防止符号链接循环
}

/// 特殊处理根目录, 如果path为`\`, 则path_segments格外压入`.`
pub fn parse_path_uncheck(path: &str) -> Vec<String> {
    let mut path_segments: Vec<String> = Vec::new();
    for segment in path.split("/") {
        if !segment.is_empty() {
            path_segments.push(segment.to_string());
        }
    }
    if path_segments.is_empty() && path.starts_with("/") {
        path_segments.push(".".to_string());
    }
    path_segments
}

pub fn parse_path(path: &str) -> Result<Vec<String>, Errno> {
    let mut path_segments: Vec<String> = Vec::new();
    for segment in path.split("/") {
        if !segment.is_empty() {
            if segment.len() > NAME_MAX {
                log::error!(
                    "[parse_path] segment '{}' is too long, max length is {}",
                    segment,
                    NAME_MAX
                );
                return Err(Errno::ENAMETOOLONG);
            }
            path_segments.push(segment.to_string());
        }
    }
    if path_segments.is_empty() && path.starts_with("/") {
        path_segments.push(".".to_string());
    }
    Ok(path_segments)
}

// pub fn parse_path(path: &str) -> Vec<String> {
//     let mut path_segments: Vec<String> = Vec::new();
//     for segment in path.split("/") {
//         if !segment.is_empty() {
//             if segment == "." {
//                 // 跳过当前目录
//                 continue;
//             } else if segment == ".." {
//                 if !path_segments.is_empty() {
//                     path_segments.pop(); // 删除上一个目录
//                 }
//             } else {
//                 // 正常的目录名
//                 path_segments.push(segment.to_string());
//             }
//         }
//     }
//     if path_segments.is_empty() {
//         if path.starts_with("/") || path == "." {
//             path_segments.push(".".to_string());
//         }
//         if path == ".." {
//             path_segments.push("..".to_string());
//         }
//     }
//     path_segments
// }

impl Nameidata {
    /// 如果是绝对路径, 则dfd不会被使用
    /// 绝对路径dentry初始化为root, 相对路径则是cwd
    /// 相当于linux中的`path_init`
    pub fn new(filename: &str, dfd: i32) -> Result<Self, Errno> {
        let path_segments: Vec<String> = parse_path(filename)?;
        let path: Arc<Path>;
        let cur_task = current_task();
        if filename.starts_with("/") {
            // 绝对路径
            path = cur_task.root();
        } else {
            // 相对路径
            if dfd == AT_FDCWD {
                // 当前进程的工作目录
                path = cur_task.pwd();
                debug_assert!(!path.dentry.is_negative());
            } else {
                // dfd是一个文件描述符, 通过文件描述符找到dentry
                // Todo: 权限检查
                if let Some(file) = cur_task.fd_table().get_file(dfd as usize) {
                    // if let Some(file) = file.as_any().downcast_ref::<File>() {
                    //     if !file.is_dir() {
                    //         log::error!(
                    //             "[Nameidata::new] file descriptor {} is not a directory",
                    //             dfd
                    //         );
                    //         return Err(Errno::ENOTDIR);
                    //     }
                    //     path = file.inner_handler(|inner| inner.path.clone());
                    // } else {
                    //     // panic!("[Nameidata::new] file descriptor {} is not valid", dfd);
                    //     log::error!(
                    //         "[Nameidata::new] file descriptor {} is not a valid File type",
                    //         dfd
                    //     );
                    //     return Err(Errno::EBADF);
                    // }
                    if !file.get_inode().can_lookup() {
                        log::error!(
                            "[Nameidata::new] file descriptor {} is not a directory",
                            dfd
                        );
                        return Err(Errno::ENOTDIR);
                    }
                    path = file.get_path();
                } else {
                    log::error!("[Nameidata::new] file descriptor {} is not valid", dfd);
                    return Err(Errno::EBADF);
                }
            }
        }
        Ok(Nameidata {
            path_segments,
            dentry: path.dentry.clone(),
            mnt: path.mnt.clone(),
            depth: 0,
        })
    }
    // used by `openat2`
    pub fn new2(filename: &str, dfd: i32, in_root: bool) -> Result<Self, Errno> {
        let path_segments: Vec<String> = parse_path_uncheck(filename);
        let path: Arc<Path>;
        let cur_task = current_task();
        if filename.starts_with("/") {
            // 绝对路径
            if in_root {
                if dfd == AT_FDCWD {
                    // 当前进程的根目录
                    path = cur_task.pwd();
                } else {
                    // dfd是一个文件描述符, 通过文件描述符找到dentry
                    if let Some(file) = cur_task.fd_table().get_file(dfd as usize) {
                        if !file.get_inode().can_lookup() {
                            log::error!(
                                "[Nameidata::new] file descriptor {} is not a directory",
                                dfd
                            );
                            return Err(Errno::ENOTDIR);
                        }
                        path = file.get_path();
                    } else {
                        log::error!("[Nameidata::new] file descriptor {} is not valid", dfd);
                        return Err(Errno::EBADF);
                    }
                }
            } else {
                path = cur_task.root();
            }
        } else {
            // 相对路径
            if dfd == AT_FDCWD {
                // 当前进程的工作目录
                path = cur_task.pwd();
                debug_assert!(!path.dentry.is_negative());
            } else {
                // dfd是一个文件描述符, 通过文件描述符找到dentry
                // Todo: 权限检查
                if let Some(file) = cur_task.fd_table().get_file(dfd as usize) {
                    if !file.get_inode().can_lookup() {
                        log::error!(
                            "[Nameidata::new] file descriptor {} is not a directory",
                            dfd
                        );
                        return Err(Errno::ENOTDIR);
                    }
                    path = file.get_path();
                } else {
                    log::error!("[Nameidata::new] file descriptor {} is not valid", dfd);
                    return Err(Errno::EBADF);
                }
            }
        }
        Ok(Nameidata {
            path_segments,
            dentry: path.dentry.clone(),
            mnt: path.mnt.clone(),
            depth: 0,
        })
    }

    pub fn resolve_symlink(&mut self, symlink_target: &str) -> Result<(), Errno> {
        if symlink_target.starts_with("/") {
            // 绝对路径符号链接，重新解析
            self.dentry = current_task().root().dentry.clone();
            self.path_segments = parse_path_uncheck(&symlink_target);
            self.depth = 0; // 重新从头解析
        } else {
            // 相对路径符号链接，插入到当前解析路径
            let mut new_segments = Vec::new();
            // 已解析的深度
            let alread_parsed_depth = self.depth;
            // 保持已解析部分
            new_segments.extend_from_slice(&self.path_segments[0..alread_parsed_depth]);
            // new_segments.extend(parse_path(&symlink_target));
            // 解析符号链接目标
            for segment in symlink_target.split("/") {
                if !segment.is_empty() {
                    if segment == "." {
                        // 跳过当前目录
                        continue;
                    } else if segment == ".." {
                        // 删除上一个目录
                        if !new_segments.is_empty() {
                            new_segments.pop();
                            self.depth -= 1; // 更新深度
                            self.dentry = self.dentry.get_parent(); // 更新dentry为父目录
                        }
                    } else {
                        // 正常的目录名
                        new_segments.push(segment.to_string());
                    }
                }
            }
            new_segments.extend_from_slice(&self.path_segments[alread_parsed_depth + 1..]); // 追加剩余部分
            self.path_segments = new_segments;
            log::error!("path_segments: {:?}", self.path_segments);
        }
        Ok(())
    }
}

pub const MAX_SYMLINK_DEPTH: usize = 40;

pub fn open_last_lookups(
    nd: &mut Nameidata,
    flags: OpenFlags,
    mode: i32,
) -> Result<Arc<dyn FileOp>, Errno> {
    let absolute_current_dir = nd.dentry.absolute_path.clone();

    // 判断是否是 O_TMPFILE
    if flags.contains(OpenFlags::O_TMPFILE) {
        // 确保传入的是目录路径
        let dir_inode = nd.dentry.get_inode();
        if !dir_inode.get_mode() & S_IFMT == S_IFDIR {
            return Err(Errno::ENOTDIR);
        }

        // 创建匿名 inode，不插入 dentry
        let tmp_inode = dir_inode.tmpfile(mode as u16 & !current_task().umask());
        // 创建匿名dentry, 但不插入目录树
        let tmp_dentry = Dentry::tmp(nd.dentry.clone(), tmp_inode.clone());
        insert_dentry(tmp_dentry.clone());

        // 用 inode 创建文件对象（不绑定路径）
        return Ok(Arc::new(File::new(
            Path::new(nd.mnt.clone(), tmp_dentry),
            tmp_inode,
            flags,
        )));
    }

    let mut follow_symlink = 0;
    loop {
        if follow_symlink > MAX_SYMLINK_DEPTH {
            return Err(Errno::ELOOP); // 避免符号链接循环
        }
        log::error!(
            "open_last_lookups: depth: {}, path_segments: {:?}",
            nd.depth,
            nd.path_segments
        );

        let segment = nd.path_segments[nd.depth].as_str();

        let target_dentry = if segment == "." {
            nd.depth += 1;
            nd.dentry.clone()
        } else if segment == ".." {
            let parent = nd.dentry.get_parent();
            nd.depth += 1;
            nd.dentry = parent.clone();
            parent
        } else {
            let dentry = lookup_dentry(nd);
            if !dentry.is_negative() {
                if dentry.is_symlink() {
                    if flags.contains(OpenFlags::O_NOFOLLOW) {
                        // 路径最后一个分量是符号链接, 但禁止跟随, 返回ELOOP
                        if flags.contains(OpenFlags::O_DIRECTORY) {
                            return Err(Errno::ENOTDIR);
                        }
                        return Err(Errno::ELOOP);
                        // let path = Path::new(nd.mnt.clone(), dentry.clone());
                        // return Ok(Arc::new(File::new(path, dentry.get_inode(), flags)));
                    }
                    let symlink_target = dentry.get_inode().get_link();
                    log::warn!(
                        "[open_last_lookups] Resolving symlink: {:?} -> {:?}",
                        nd.path_segments[nd.depth],
                        symlink_target
                    );
                    // 根据符号链接目标, 更新nd
                    nd.resolve_symlink(&symlink_target)?;
                    follow_symlink += 1;
                    continue;
                }
                nd.dentry = dentry.clone();
                if nd.depth != nd.path_segments.len() - 1 {
                    nd.depth += 1;
                    continue;
                }

                dentry_check_open(&dentry, flags, mode as i32)?;

                dentry
            } else {
                // 文件不存在
                if flags.contains(OpenFlags::O_CREAT) && nd.depth == nd.path_segments.len() - 1 {
                    let dir_inode = nd.dentry.get_inode();
                    dir_inode.create(dentry.clone(), mode as u16 & !current_task().umask());
                    debug_assert!(!dentry.is_negative());
                    dentry
                } else {
                    return Err(Errno::ENOENT);
                }
            }
        };
        return create_file_from_dentry(target_dentry, nd.mnt.clone(), flags);
    }
}

// used by `openat2`
pub fn open_last_lookups2(
    nd: &mut Nameidata,
    flags: OpenFlags,
    mode: i32,
    resolve_flags: &ResolveFlags,
) -> Result<Arc<dyn FileOp>, Errno> {
    let absolute_current_dir = nd.dentry.absolute_path.clone();

    // 判断是否是 O_TMPFILE
    if flags.contains(OpenFlags::O_TMPFILE) {
        // 确保传入的是目录路径
        let dir_inode = nd.dentry.get_inode();
        if !dir_inode.get_mode() & S_IFMT == S_IFDIR {
            return Err(Errno::ENOTDIR);
        }

        // 创建匿名 inode，不插入 dentry
        let tmp_inode = dir_inode.tmpfile(mode as u16 & !current_task().umask());
        // 创建匿名dentry, 但不插入目录树
        let tmp_dentry = Dentry::tmp(nd.dentry.clone(), tmp_inode.clone());
        insert_dentry(tmp_dentry.clone());

        // 用 inode 创建文件对象（不绑定路径）
        return Ok(Arc::new(File::new(
            Path::new(nd.mnt.clone(), tmp_dentry),
            tmp_inode,
            flags,
        )));
    }

    let mut follow_symlink = 0;
    loop {
        if follow_symlink > MAX_SYMLINK_DEPTH {
            return Err(Errno::ELOOP); // 避免符号链接循环
        }
        log::error!(
            "open_last_lookups: depth: {}, path_segments: {:?}",
            nd.depth,
            nd.path_segments
        );

        let segment = nd.path_segments[nd.depth].as_str();

        let target_dentry = if segment == "." {
            nd.depth += 1;
            nd.dentry.clone()
        } else if segment == ".." {
            let parent = nd.dentry.get_parent();
            nd.depth += 1;
            nd.dentry = parent.clone();
            parent
        } else {
            let dentry = lookup_dentry(nd);
            if !dentry.is_negative() {
                if dentry.is_symlink() {
                    if resolve_flags.contains(ResolveFlags::RESOLVE_NO_SYMLINKS) {
                        return Err(Errno::ELOOP); // 禁止跟随符号链接
                    }
                    if flags.contains(OpenFlags::O_NOFOLLOW) {
                        // 路径最后一个分量是符号链接, 但禁止跟随, 直接返回符号链接的dentry
                        let path = Path::new(nd.mnt.clone(), dentry.clone());
                        return Ok(Arc::new(File::new(path, dentry.get_inode(), flags)));
                    }
                    let symlink_target = dentry.get_inode().get_link();
                    log::warn!(
                        "[open_last_lookups] Resolving symlink: {:?} -> {:?}",
                        nd.path_segments[nd.depth],
                        symlink_target
                    );
                    // 根据符号链接目标, 更新nd
                    nd.resolve_symlink(&symlink_target);
                    follow_symlink += 1;
                    continue;
                }
                nd.dentry = dentry.clone();
                if nd.depth != nd.path_segments.len() - 1 {
                    nd.depth += 1;
                    continue;
                }

                dentry_check_open(&dentry, flags, mode as i32)?;

                dentry
            } else {
                // 文件不存在
                if flags.contains(OpenFlags::O_CREAT) && nd.depth == nd.path_segments.len() - 1 {
                    let dir_inode = nd.dentry.get_inode();
                    dir_inode.create(dentry.clone(), mode as u16 & !current_task().umask());
                    debug_assert!(!dentry.is_negative());
                    dentry
                } else {
                    return Err(Errno::ENOENT);
                }
            }
        };
        return create_file_from_dentry(target_dentry, nd.mnt.clone(), flags);
    }
}

// 根据类型创建对应类型文件, 同时处理OpenFlags
fn create_file_from_dentry(
    dentry: Arc<Dentry>,
    mount: Arc<VfsMount>,
    flags: OpenFlags,
) -> Result<Arc<dyn FileOp>, Errno> {
    let inode = dentry.get_inode();
    let file_type = inode.get_mode() & S_IFMT;
    log::warn!(
        "[create_file_from_dentry] Creating file from dentry: {}, type: {:?}, flags: {:?}",
        dentry.absolute_path,
        file_type,
        flags
    );

    let path = Path::new(mount, dentry.clone());

    if dentry.absolute_path.starts_with("/proc") {
        // procfs的文件类型
        if dentry.absolute_path == "/proc/mounts" {
            return Ok(MOUNTS.get().unwrap().clone());
        }
        if dentry.absolute_path == "/proc/meminfo" {
            let meminfo: Arc<dyn FileOp> = MEMINFO.get().unwrap().clone();
            meminfo.seek(0, super::uapi::Whence::SeekSet).unwrap();
            return Ok(meminfo);
        }
        if dentry.absolute_path == "/proc/self/exe" {
            return Ok(EXE.get().unwrap().clone());
        }
        if dentry.absolute_path == "/proc/self/maps" {
            let maps: Arc<dyn FileOp> = MAPS.get().unwrap().clone();
            maps.seek(0, super::uapi::Whence::SeekSet).unwrap();
            return Ok(maps);
        }
        if dentry.absolute_path == "/proc/self/smaps" {
            let smaps: Arc<dyn FileOp> = SMAPS.get().unwrap().clone();
            smaps.seek(0, super::uapi::Whence::SeekSet).unwrap();
            return Ok(smaps);
        }
        if dentry.absolute_path == "/proc/self/pagemap" {
            let pagemap: Arc<dyn FileOp> = PAGEMAP.get().unwrap().clone();
            pagemap.seek(0, super::uapi::Whence::SeekSet).unwrap();
            return Ok(pagemap);
        }
        if dentry.absolute_path == "/proc/self/status" {
            let status: Arc<dyn FileOp> = STATUS.get().unwrap().clone();
            status.seek(0, super::uapi::Whence::SeekSet).unwrap();
            return Ok(status);
        }
        if dentry.absolute_path == "/proc/pid/stat" {
            let pid_stat: Arc<dyn FileOp> = PID_STAT.get().unwrap().clone();
            pid_stat.seek(0, super::uapi::Whence::SeekSet).unwrap();
            return Ok(pid_stat);
        }
        if dentry.absolute_path.starts_with("/proc/self/fd/") {
            // /proc/self/fd/XXX
            return Ok(FD_FILE.get().unwrap().clone());
        }
        if dentry.absolute_path == "/proc/sys/kernel/tainted" {
            // /proc/sys/kernel/tainted
            let tainted_file = TAINTED.get().unwrap().clone();
            return Ok(tainted_file);
        }
        if dentry.absolute_path == "/proc/sys/kernel/pid_max" {
            // /proc/sys/kernel/pid_max
            let pid_max: Arc<dyn FileOp> = PIDMAX.get().unwrap().clone();
            pid_max.seek(0, super::uapi::Whence::SeekSet).unwrap();
            return Ok(pid_max);
        }
        if dentry.absolute_path == "/proc/cpuinfo" {
            let cpuinfo: Arc<dyn FileOp> = CPUINFO.get().unwrap().clone();
            cpuinfo.seek(0, super::uapi::Whence::SeekSet).unwrap();
            return Ok(cpuinfo);
        }
    }

    let file: Arc<dyn FileOp> = match file_type {
        S_IFREG => Arc::new(File::new(path, inode, flags)),
        S_IFDIR => Arc::new(File::new(path, inode, flags)),
        S_IFIFO => {
            // 创建命名管道
            // 根据flags创建读/写端
            let inode = Arc::downcast(inode).unwrap();
            if flags.contains(OpenFlags::O_RDWR) {
                Pipe::rw_end(inode, flags, true)?
            } else if flags.contains(OpenFlags::O_WRONLY) {
                Pipe::write_end(inode, flags, true)?
            } else {
                // O_RDONLY = 0
                Pipe::read_end(inode, flags, true)?
            }
        }
        S_IFCHR => {
            // 根据设备号创建对应字符设备文件
            match inode.get_devt() {
                (1, 3) => NULL.get().unwrap().clone(), // /dev/null
                (1, 5) => ZERO.get().unwrap().clone(), // /dev/zero
                (5, 0) => {
                    assert!(dentry.absolute_path.starts_with("/dev/tty"));
                    TTY.get().unwrap().clone()
                } // /dev/tty
                (10, 0) => {
                    assert!(dentry.absolute_path == "/dev/rtc");
                    RTC.get().unwrap().clone()
                } // /dev/rtc
                (1, 9) => {
                    assert!(dentry.absolute_path == "/dev/urandom");
                    URANDOM.get().unwrap().clone()
                } // /dev/urandom
                (10, 237) => {
                    // /dev/loop-control
                    assert!(dentry.absolute_path == "/dev/loop-control");
                    LOOP_CONTROL.get().unwrap().clone()
                }
                _ => panic!(
                    "[create_file_from_dentry]Unsupported device, devt: {:?}",
                    inode.get_devt()
                ),
            }
        }
        S_IFBLK => {
            let (_major, id) = inode.get_devt();
            // /dev/loopX
            // assert!(dentry.absolute_path == format!("/dev/loop{}", id));
            // 这里的id是从0开始的
            let loop_device = get_loop_device(id as usize);
            if loop_device.is_none() {
                return Err(Errno::ENODEV);
            }
            loop_device.unwrap()
        }
        _ => {
            log::error!(
                "[create_file_from_dentry] Unsupported file type: {:?}",
                file_type
            );
            return Err(Errno::ENOSYS);
        } // 类型不支持
    };

    Ok(file)
}

// Todo: 增加权限检查
/// 根据路径查找inode, 如果不存在, 则根据flags创建
/// path可以是绝对路径或相对路径
/// mode在open时用于检查打开权限, 在create时用于设置文件的权限
pub fn path_openat(
    path: &str,
    flags: OpenFlags,
    dfd: i32,
    mode: i32,
) -> Result<Arc<dyn FileOp>, Errno> {
    // 解析路径的目录部分，遇到最后一个组件时停止
    // Todo: 正常有符号链接的情况下, 这里应该是一个循环
    let mut nd = Nameidata::new(path, dfd)?;
    loop {
        link_path_walk(&mut nd)?;
        // let symlink_target = link_path_walk(&mut nd)?;
        // if !symlink_target.is_empty() {
        //     // 符号链接
        //     nd.path_segments = parse_path(&symlink_target);
        //     continue;
        // }
        // 到达最后一个组件
        match open_last_lookups(&mut nd, flags, mode) {
            Ok(file) => {
                return Ok(file);
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
}

// 先查找dentry cache, 如果没有, 则调用InodeOp::lookup
// 对于查找dentry的时候, 都应该通过这个函数
// 该函数会建立dentry的父子关系, 并将dentry放入dentry cache
// 由上层调用者保证:
//     1. nd.dentry即为父目录
pub fn lookup_dentry(nd: &mut Nameidata) -> Arc<Dentry> {
    // let segment = &nd.path_segments[nd.depth];
    // let absolute_path = format!("{}/{}", nd.dentry.absolute_path, segment);
    let segment = &nd.path_segments[nd.depth];
    let mut absolute_path = nd.dentry.absolute_path.clone();
    // if nd.path_segments.len() >= 2 && nd.path_segments[0] == "proc" && nd.path_segments[1] == "pid"
    // {
    //     // 特殊处理/proc/pid目录
    //     absolute_path += "/pid";
    //     println!("after add /pid: {}", absolute_path);
    // }
    let absolute_path = format!("{}/{}", absolute_path, segment);
    log::info!("[lookup_dentry] Looking up path: {}", absolute_path);
    // 尝试从 dcache 查找
    if let Some(dentry) = lookup_dcache_with_absolute_path(&absolute_path) {
        return dentry;
    }
    // log::warn!(
    //     "[lookup_dentry] Cache miss, performing inode lookup for: {}",
    //     segment
    // );
    // 从 inode 进行实际查找
    let parent_inode = nd.dentry.get_inode();
    let dentry = parent_inode.lookup(segment, nd.dentry.clone());
    // 插入 dentry，无论是正的还是负的
    insert_dentry(dentry.clone());
    dentry
}

const EEXIST: isize = 17;

// 创建新文件或目录时用于解析路径, 获得对应的`dentry`
// 同时检查路径是否存在, 若存在则返回错误
/// 预期的返回值是负目录项(已建立父子关系), nd的dentry和inode为父目录
pub fn filename_create(nd: &mut Nameidata, _lookup_flags: usize) -> Result<Arc<Dentry>, Errno> {
    let mut error: i32;
    // 解析路径的目录部分，调用后nd.dentry是最后一个组件的父目录
    match link_path_walk(nd) {
        Ok(_) => {
            // 到达最后一个组件
            let mut absolute_current_dir = nd.dentry.absolute_path.clone();
            // 处理`.`和`..`, 最后一个组件不能是`.`或`..`, 不合法
            if nd.path_segments[nd.depth] == "." {
                return Err(Errno::EEXIST);
            } else if nd.path_segments[nd.depth] == ".." {
                return Err(Errno::EEXIST);
            } else {
                // name是String
                let dentry = lookup_dentry(nd);
                if !dentry.is_negative() {
                    return Err(Errno::EEXIST);
                }
                return Ok(dentry);
            }
        }
        Err(e) => {
            return Err(e);
        }
    };
}

/// 根据路径查找inode, 如果不存在, 则返回error
/// flags可能包含AT_SYMLINK_NOFOLLOW, 如果包含则路径最后一个组件不跟随符号链接
pub fn filename_lookup(nd: &mut Nameidata, follow_symlink: bool) -> Result<Arc<Dentry>, Errno> {
    let mut error: i32;
    match link_path_walk(nd) {
        Ok(_) => {
            // 到达最后一个组件
            let mut follow_symlink_cnt = 0;
            loop {
                if follow_symlink_cnt > MAX_SYMLINK_DEPTH {
                    return Err(Errno::ELOOP); // 避免符号链接循环
                }
                let segment = nd.path_segments[nd.depth].as_str();
                let target_dentry = if segment == "." {
                    nd.dentry.clone()
                } else if segment == ".." {
                    let parent = nd.dentry.get_parent();
                    debug_assert!(!parent.is_symlink());
                    parent
                } else {
                    let dentry = lookup_dentry(nd);
                    if !dentry.is_negative() {
                        if dentry.is_symlink() {
                            if !follow_symlink {
                                // 路径最后一个分量是符号链接, 但禁止跟随, 直接返回符号链接的dentry
                                return Ok(dentry);
                            }
                            let symlink_target = dentry.get_inode().get_link(); // 读取符号链接目标
                            log::warn!(
                                "[filename_lookup] Resolving symlink: {:?} -> {:?}",
                                nd.path_segments[nd.depth],
                                symlink_target
                            );
                            nd.resolve_symlink(&symlink_target);
                            follow_symlink_cnt += 1;
                            continue;
                        }
                        // 如果不是最后一个组件, 则继续解析
                        if nd.depth != nd.path_segments.len() - 1 {
                            // 更新nd.dentry
                            nd.dentry = dentry.clone();
                            nd.depth += 1;
                            continue;
                        }
                        dentry
                    } else {
                        return Err(Errno::ENOENT);
                    }
                };
                return Ok(target_dentry);
            }
        }
        Err(e) => {
            return Err(e);
        }
    }
}

// /// 根据路径查找inode, 如果不存在, 则返回error
// /// flags可能包含AT_SYMLINK_NOFOLLOW, 如果包含则不跟随符号链接
// pub fn filename_lookup(nd: &mut Nameidata, lookup_flags: i32) -> Result<Arc<Dentry>, Errno> {
//     let mut error: i32;
//     match link_path_walk(nd) {
//         Ok(_) => {
//             // 到达最后一个组件
//             // 处理`.`和`..`
//             if nd.path_segments[nd.depth] == "." {
//                 return Ok(nd.dentry.clone());
//             } else if nd.path_segments[nd.depth] == ".." {
//                 let parent_dentry = nd.dentry.get_parent();
//                 return Ok(parent_dentry);
//             } else {
//                 // name是String
//                 let dentry = lookup_dentry(nd);
//                 if dentry.is_negative() {
//                     return Err(Errno::ENOENT);
//                 }
//                 // if dentry.is_symlink() && lookup_flags & AT_SYMLINK_NOFOLLOW == 0 {
//                 //     // 需要跟随符号链接
//                 //     let mut follow_symlink = 0;
//                 //     loop {
//                 //         if follow_symlink > MAX_SYMLINK_DEPTH {
//                 //             return Err(Errno::ELOOP); // 避免符号链接循环
//                 //         }
//                 //         let segment = nd.path_segments[nd.depth].as_str();
//                 // let symlink_target = dentry.get_inode().get_link(); // 读取符号链接目标
//                 // log::warn!(
//                 //     "Resolving symlink: {:?} -> {:?}",
//                 //     nd.path_segments[nd.depth],
//                 //     symlink_target
//                 // );
//                 // // 根据符号链接目标, 更新nd
//                 // nd.resolve_symlink(&symlink_target);
//                 // }
//                 return Ok(dentry);
//             }
//         }
//         Err(e) => {
//             return Err(e);
//         }
//     }
// }

// 不是目录
const ENOTDIR: isize = 20;
// 访问路径组件不存在
const ENOENT: isize = 2;

// 注意: name可能为"."或"..", 在DentryCache中绝对路径不包括这两个特殊目录
/// 若找不到, 则返回负目录项, nd中的dentry和inode为父目录的
/// 由上层调用者保真nd.dentry是positive
/// basic name resolution function: path -> dentry
/// 解析路径的父目录部分，找到 dentry。
/// 会跟随路径中的符号链接, 确保最终路径是目录
pub fn link_path_walk(nd: &mut Nameidata) -> Result<(), Errno> {
    // assert!(!nd.dentry.is_negative());
    if nd.dentry.is_negative() {
        // 如果dentry是负的, 则返回错误
        return Err(Errno::ENOENT);
    }
    // log::info!("[link_path_walk] path: {:?}", nd.path_segments);
    // 解析路径的目录部分，遇到最后一个组件时停止检查最后一个路径分量
    if nd.path_segments.is_empty() {
        // 空路径
        return Err(Errno::ENOENT);
    }
    if !nd.dentry.is_dir() {
        return Err(Errno::ENOTDIR);
    }
    let mut len = nd.path_segments.len() - 1;
    let mut symlink_count = 0;
    let task = current_task();
    while nd.depth < len {
        log::info!(
            "[link_path_walk] depth: {}, path_segment: {:?}",
            nd.depth,
            nd.path_segments[nd.depth]
        );
        if nd.path_segments[nd.depth] == "." {
            nd.depth += 1;
            continue;
        } else if nd.path_segments[nd.depth] == ".." {
            let parent_dentry = nd.dentry.get_parent();
            nd.depth += 1;
            nd.dentry = parent_dentry;
        } else if nd.path_segments[nd.depth].parse::<usize>().is_ok() {
            record_target_pid(nd.path_segments[nd.depth].parse::<usize>().unwrap());
            nd.path_segments[nd.depth] = "pid".to_string();
            nd.depth += 1;
        } else {
            // name是String
            let mut dentry = lookup_dentry(nd);
            // 路径组件不存在
            if dentry.is_negative() {
                return Err(Errno::ENOENT);
            }
            // 先检查是否是符号链接
            while dentry.is_symlink() {
                if symlink_count > SYMLINK_MAX {
                    return Err(Errno::ELOOP); // 防止无限循环解析符号链接
                }
                symlink_count += 1;
                let symlink_target = dentry.get_inode().get_link(); // 读取符号链接目标
                log::info!(
                    "[link_path_walk] Resolving symlink: {:?} -> {:?}",
                    nd.path_segments[nd.depth],
                    symlink_target
                );
                // 根据符号链接目标, 更新nd
                nd.resolve_symlink(&symlink_target);
                // 更新len
                len = nd.path_segments.len() - 1;
                // 重新查找
                dentry = lookup_dentry(nd);
                if dentry.is_negative() {
                    return Err(Errno::ENOENT);
                }
            }
            // 确保是目录
            if !dentry.get_inode().can_lookup() {
                return Err(Errno::ENOTDIR);
            }
            // 检查对目录有无搜索权限
            if task.fsuid() != 0 {
                if !dentry.can_search() {
                    return Err(Errno::EACCES); // 没有搜索权限
                }
            }
            nd.depth += 1;
            nd.dentry = dentry;
        }
    }
    Ok(())
}

/// used by `openat2`
pub fn link_path_walk2(nd: &mut Nameidata, resolve_flags: &ResolveFlags) -> Result<(), Errno> {
    // assert!(!nd.dentry.is_negative());
    if nd.dentry.is_negative() {
        // 如果dentry是负的, 则返回错误
        return Err(Errno::ENOENT);
    }
    // log::info!("[link_path_walk] path: {:?}", nd.path_segments);
    // 解析路径的目录部分，遇到最后一个组件时停止检查最后一个路径分量
    if nd.path_segments.is_empty() {
        // 空路径
        return Err(Errno::ENOENT);
    }
    if !nd.dentry.is_dir() {
        return Err(Errno::ENOTDIR);
    }
    let mut len = nd.path_segments.len() - 1;
    let mut symlink_count = 0;
    let task = current_task();
    let start_dentry = nd.dentry.clone();
    while nd.depth < len {
        log::info!(
            "[link_path_walk] depth: {}, path_segment: {:?}",
            nd.depth,
            nd.path_segments[nd.depth]
        );
        if nd.path_segments[nd.depth] == "." {
            nd.depth += 1;
            continue;
        } else if nd.path_segments[nd.depth] == ".." {
            // Todo: 检查是否跳出起始目录
            if resolve_flags.contains(ResolveFlags::RESOLVE_BENEATH)
                || resolve_flags.contains(ResolveFlags::RESOLVE_IN_ROOT)
            {
                if Arc::ptr_eq(&nd.dentry, &start_dentry) {
                    // 已在起始目录，不允许跳出
                    return Err(Errno::EXDEV);
                }
            }
            let parent_dentry = nd.dentry.get_parent();
            nd.depth += 1;
            nd.dentry = parent_dentry;
        } else if nd.path_segments[nd.depth].parse::<usize>().is_ok() {
            record_target_pid(nd.path_segments[nd.depth].parse::<usize>().unwrap());
            nd.path_segments[nd.depth] = "pid".to_string();
            nd.depth += 1;
        } else {
            // name是String
            let mut dentry = lookup_dentry(nd);
            // 路径组件不存在
            if dentry.is_negative() {
                return Err(Errno::ENOENT);
            }
            // 先检查是否是符号链接
            while dentry.is_symlink() {
                if resolve_flags.contains(ResolveFlags::RESOLVE_NO_SYMLINKS) {
                    // 如果不允许符号链接
                    return Err(Errno::ELOOP);
                }
                if symlink_count > SYMLINK_MAX {
                    return Err(Errno::ELOOP); // 防止无限循环解析符号链接
                }
                symlink_count += 1;
                let symlink_target = dentry.get_inode().get_link(); // 读取符号链接目标
                log::info!(
                    "[link_path_walk] Resolving symlink: {:?} -> {:?}",
                    nd.path_segments[nd.depth],
                    symlink_target
                );
                // 根据符号链接目标, 更新nd
                nd.resolve_symlink(&symlink_target);
                // 更新len
                len = nd.path_segments.len() - 1;
                // 重新查找
                dentry = lookup_dentry(nd);
                if dentry.is_negative() {
                    return Err(Errno::ENOENT);
                }
            }
            // 确保是目录
            if !dentry.get_inode().can_lookup() {
                return Err(Errno::ENOTDIR);
            }
            // 检查对目录有无搜索权限
            if task.fsuid() != 0 {
                if !dentry.can_search() {
                    return Err(Errno::EACCES); // 没有搜索权限
                }
            }
            nd.depth += 1;
            nd.dentry = dentry;
        }
    }
    Ok(())
}

pub const SYMLINK_MAX: usize = 10;

// // 注意: name可能为"."或"..", 在DentryCache中绝对路径不包括这两个特殊目录
// /// 若找不到, 则返回负目录项, nd中的dentry和inode为父目录的
// /// 由上层调用者保真nd.dentry是positive
// /// basic name resolution function: path -> dentry
// /// 解析路径的父目录部分，找到 dentry。
// /// 如果是符号链接, 则返回解析后的链接目标
// pub fn link_path_walk(nd: &mut Nameidata) -> Result<String, isize> {
//     assert!(!nd.dentry.is_negative());
//     log::info!("[link_path_walk] path: {:?}", nd.path_segments);
//     let mut absolute_current_dir = nd.dentry.absolute_path.clone();
//     let mut symlink_count = 0;

//     // 解析路径的目录部分，遇到最后一个组件时停止
//     let len = nd.path_segments.len() - 1;
//     while nd.depth < len {
//         let component = &nd.path_segments[nd.depth];

//         if component == "." {
//             nd.depth += 1;
//             continue;
//         } else if component == ".." {
//             let parent_dentry = nd.dentry.get_parent();
//             nd.depth += 1;
//             nd.dentry = parent_dentry;
//         } else {
//             let mut dentry = lookup_dentry(nd);

//             if dentry.is_negative() {
//                 return Err(-ENOENT);
//             }

//             while dentry.is_symlink() {
//                 if symlink_count > SYMLINK_MAX {
//                     return Err(-ELOOP); // 防止无限循环解析符号链接
//                 }
//                 symlink_count += 1;

//                 let symlink_target = dentry.get_inode().get_link(); // 读取符号链接目标
//                 log::info!("Resolving symlink: {:?} -> {:?}", component, symlink_target);

//                 if symlink_target.starts_with("/") {
//                     // 绝对路径符号链接，重新解析
//                     nd.dentry = current_task().root().dentry.clone();
//                     nd.path_segments = parse_path(&symlink_target);
//                     nd.depth = 0; // 重新从头解析
//                 } else {
//                     // 相对路径符号链接，插入到当前解析路径
//                     let mut new_segments = Vec::new();
//                     new_segments.extend_from_slice(&nd.path_segments[0..nd.depth]); // 保持已解析部分
//                     new_segments.extend(parse_path(&symlink_target)); // 解析符号链接目标
//                     new_segments.extend_from_slice(&nd.path_segments[nd.depth + 1..]); // 追加剩余部分
//                     nd.path_segments = new_segments;
//                 }

//                 // 重新查找
//                 dentry = lookup_dentry(nd);
//                 if dentry.is_negative() {
//                     return Err(-ENOENT);
//                 }
//             }

//             // 确保最终路径是目录
//             if !dentry.get_inode().can_lookup() {
//                 return Err(-ENOTDIR);
//             }

//             nd.depth += 1;
//             nd.dentry = dentry;
//         }
//     }
//     Ok(String::new())
// }

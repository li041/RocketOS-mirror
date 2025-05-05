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
        meminfo::MEMINFO,
        mounts::{MountsFile, MOUNTS},
    },
    Stdin, FS_BLOCK_SIZE,
};
use crate::{
    ext4::{
        dentry,
        inode::{self, S_IFCHR, S_IFDIR, S_IFIFO, S_IFMT, S_IFREG},
    },
    fs::{
        dentry::DentryFlags,
        dev::{null::NULL, rtc::RTC, urandom::URANDOM, zero::ZERO},
        fdtable::{FdEntry, FdFlags},
        AT_FDCWD,
    },
    syscall::errno::Errno,
    task::current_task,
};
use alloc::{
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
}

/// 特殊处理根目录, 如果path为`\`, 则path_segments格外压入`.`
pub fn parse_path(path: &str) -> Vec<String> {
    let mut path_segments: Vec<String> = Vec::new();
    for segment in path.split("/") {
        if !segment.is_empty() {
            path_segments.push(segment.to_string());
        }
    }
    if path_segments.is_empty() {
        path_segments.push(".".to_string());
    }
    path_segments
}

impl Nameidata {
    /// 如果是绝对路径, 则dfd不会被使用
    /// 绝对路径dentry初始化为root, 相对路径则是cwd
    /// 相当于linux中的`path_init`
    pub fn new(filename: &str, dfd: i32) -> Self {
        let path_segments: Vec<String> = parse_path(filename);
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
                assert!(!path.dentry.is_negative());
            } else {
                // dfd是一个文件描述符, 通过文件描述符找到dentry
                // Todo: 权限检查
                if let Some(file) = cur_task.fd_table().get_file(dfd as usize) {
                    if let Some(file) = file.as_any().downcast_ref::<File>() {
                        path = file.inner_handler(|inner| inner.path.clone());
                    } else {
                        panic!("[Nameidata::new] file descriptor {} is not valid", dfd);
                    }
                } else {
                    panic!("[Nameidata::new] file descriptor {} is not valid", dfd);
                }
            }
        }
        Nameidata {
            path_segments,
            dentry: path.dentry.clone(),
            mnt: path.mnt.clone(),
            depth: 0,
        }
    }
    pub fn resolve_symlink(&mut self, symlink_target: &str) {
        if symlink_target.starts_with("/") {
            // 绝对路径符号链接，重新解析
            self.dentry = current_task().root().dentry.clone();
            self.path_segments = parse_path(&symlink_target);
            self.depth = 0; // 重新从头解析
        } else {
            // 相对路径符号链接，插入到当前解析路径
            let mut new_segments = Vec::new();
            new_segments.extend_from_slice(&self.path_segments[0..self.depth]); // 保持已解析部分
            new_segments.extend(parse_path(&symlink_target)); // 解析符号链接目标
            new_segments.extend_from_slice(&self.path_segments[self.depth + 1..]); // 追加剩余部分
            self.path_segments = new_segments;
            log::error!("path_segments: {:?}", self.path_segments);
        }
    }
}

// /// 处理路径的最后一个组件
// /// 如果open_flag包含O_CREAT, 则创建文件(注意这里不是创建符号链接)
// pub fn open_last_lookups(
//     nd: &mut Nameidata,
//     flags: usize,
//     mode: usize,
// ) -> Result<Arc<File>, isize> {
//     let absolute_current_dir = nd.dentry.absolute_path.clone();
//     // 处理`.`和`..`
//     if nd.path_segments[nd.depth] == "." {
//         return Ok(Arc::new(File::new(
//             Path::new(nd.mnt.clone(), nd.dentry.clone()),
//             nd.dentry.get_inode(),
//             flags,
//         )));
//     } else if nd.path_segments[nd.depth] == ".." {
//         let parent_dentry = nd.dentry.get_parent();
//         return Ok(Arc::new(File::new(
//             Path::new(nd.mnt.clone(), parent_dentry.clone()),
//             parent_dentry.get_inode(),
//             flags,
//         )));
//     } else {
//         // name是String
//         // 先查找文件, 如果文件不存在, 看是否设置了O_CREAT
//         // 先查找dentry cache
//         let dentry = lookup_dentry(nd);
//         if !dentry.is_negative() {
//             return Ok(Arc::new(File::new(
//                 Path::new(nd.mnt.clone(), dentry.clone()),
//                 dentry.get_inode(),
//                 flags,
//             )));
//         }

//         if flags & O_CREAT != 0 {
//             // Todo: 最后打开的是目录还是文件要区分
//             // 创建文件
//             let dir_inode = nd.dentry.get_inode();
//             // Todo: 设置mode
//             let new_dentry = Dentry::negative(
//                 absolute_current_dir + "/" + &nd.path_segments[nd.depth],
//                 Some(nd.dentry.clone()),
//             );
//             dir_inode.create(new_dentry.clone(), mode as u16);
//             insert_dentry(new_dentry.clone());
//             assert!(!new_dentry.is_negative());
//             return Ok(Arc::new(File::new(
//                 Path::new(nd.mnt.clone(), new_dentry.clone()),
//                 new_dentry.get_inode(),
//                 flags,
//             )));
//         }
//         // 文件不存在, 且没有设置O_CREAT
//         return Err(-ENOENT);
//     }
// }

pub fn open_last_lookups(
    nd: &mut Nameidata,
    flags: OpenFlags,
    mode: usize,
) -> Result<Arc<dyn FileOp>, Errno> {
    const MAX_SYMLINK_DEPTH: usize = 40;
    let mut follow_symlink = 0;

    let absolute_current_dir = nd.dentry.absolute_path.clone();

    loop {
        // 判断是否是 O_TMPFILE
        if flags.contains(OpenFlags::O_TMPFILE) {
            // 确保传入的是目录路径
            let dir_inode = nd.dentry.get_inode();
            if !dir_inode.get_mode() & S_IFMT == S_IFDIR {
                return Err(Errno::ENOTDIR);
            }

            // 创建匿名 inode，不插入 dentry
            let tmp_inode = dir_inode.tmpfile(mode as u16);

            // 用 inode 创建文件对象（不绑定路径）
            return Ok(Arc::new(File::new(Path::zero_init(), tmp_inode, flags)));
        }

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
            nd.dentry.clone()
        } else if segment == ".." {
            let parent = nd.dentry.get_parent();
            assert!(!parent.is_symlink());
            parent
        } else {
            let dentry = lookup_dentry(nd);
            if !dentry.is_negative() {
                if dentry.is_symlink() {
                    if flags.contains(OpenFlags::O_NOFOLLOW) {
                        return Err(Errno::ELOOP);
                    }
                    let symlink_target = dentry.get_inode().get_link();
                    log::warn!(
                        "Resolving symlink: {:?} -> {:?}",
                        nd.path_segments[nd.depth],
                        symlink_target
                    );
                    nd.resolve_symlink(&symlink_target);
                    follow_symlink += 1;
                    continue;
                }

                if nd.depth != nd.path_segments.len() - 1 {
                    nd.depth += 1;
                    continue;
                }

                dentry
            } else {
                // 文件不存在
                if flags.contains(OpenFlags::O_CREAT) && nd.depth == nd.path_segments.len() - 1 {
                    let dir_inode = nd.dentry.get_inode();
                    dir_inode.create(dentry.clone(), mode as u16);
                    assert!(!dentry.is_negative());
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

    let path = Path::new(mount, dentry.clone());

    if dentry.absolute_path.starts_with("/proc") {
        // procfs的文件类型
        if dentry.absolute_path == "/proc/mounts" {
            return Ok(MOUNTS.get().unwrap().clone());
        }
        if dentry.absolute_path == "/proc/meminfo" {
            return Ok(MEMINFO.get().unwrap().clone());
        }
        if dentry.absolute_path == "/proc/self/exe" {
            return Ok(EXE.get().unwrap().clone());
        }
    }

    let file: Arc<dyn FileOp> = match file_type {
        S_IFREG => Arc::new(File::new(path, inode, flags)),
        S_IFDIR => Arc::new(File::new(path, inode, flags)),
        S_IFIFO => {
            // 创建命名管道
            // 根据flags创建读/写端
            let inode = Arc::downcast(inode).unwrap();
            if flags.contains(OpenFlags::O_WRONLY) || flags.contains(OpenFlags::O_RDWR) {
                Pipe::write_end(inode, flags, true)
            } else {
                // O_RDONLY = 0
                Pipe::read_end(inode, flags, true)
            }
        }
        S_IFCHR => {
            // 根据设备号创建对应字符设备文件
            match inode.get_devt() {
                (1, 3) => {
                    assert!(dentry.absolute_path == "/dev/null");
                    NULL.get().unwrap().clone()
                } // /dev/null
                (1, 5) => {
                    assert!(dentry.absolute_path == "/dev/zero");
                    ZERO.get().unwrap().clone()
                } // /dev/zero
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
                _ => panic!(
                    "[create_file_from_dentry]Unsupported device, devt: {:?}",
                    inode.get_devt()
                ),
            }
        }
        _ => {
            panic!(
                "[create_file_from_dentry] Unsupported file type: {:?}",
                file_type
            );
        } // 类型不支持
    };

    Ok(file)
}

// /// 认为符号链接的目标路径不含dot和dot-dot
// /// mode只在O_CREAT时有效
// /// Todo: 支持不同类型的FileOp, 比如说字符设备类型的
// pub fn open_last_lookups(
//     nd: &mut Nameidata,
//     flags: OpenFlags,
//     mode: usize,
// ) -> Result<Arc<dyn FileOp>, isize> {
//     const MAX_SYMLINK_DEPTH: usize = 40;
//     let mut follow_symlink = 0;

//     let absolute_current_dir = nd.dentry.absolute_path.clone();

//     loop {
//         if follow_symlink > MAX_SYMLINK_DEPTH {
//             return Err(-ELOOP); // 避免符号链接循环
//         }

//         log::error!(
//             "open_last_lookups: depth: {}, path_segments: {:?}",
//             nd.depth,
//             nd.path_segments
//         );
//         let segment = nd.path_segments[nd.depth].as_str();

//         if segment == "." {
//             assert!(nd.depth == nd.path_segments.len() - 1);
//             return Ok(Arc::new(File::new(
//                 Path::new(nd.mnt.clone(), nd.dentry.clone()),
//                 nd.dentry.get_inode(),
//                 flags,
//             )));
//         } else if segment == ".." {
//             assert!(nd.depth == nd.path_segments.len() - 1);
//             let parent_dentry = nd.dentry.get_parent();
//             // parent即使是符号链接也不需要解析
//             assert!(!parent_dentry.is_symlink());
//             return Ok(Arc::new(File::new(
//                 Path::new(nd.mnt.clone(), parent_dentry.clone()),
//                 parent_dentry.get_inode(),
//                 flags,
//             )));
//         }

//         // 查找路径分量的 `dentry`
//         let dentry = lookup_dentry(nd);
//         if !dentry.is_negative() {
//             if dentry.is_symlink() {
//                 if flags.contains(OpenFlags::O_NOFOLLOW) {
//                     return Err(-ELOOP);
//                 }
//                 // 解析符号链接
//                 let symlink_target = dentry.get_inode().get_link();
//                 log::warn!(
//                     "Resolving symlink: {:?} -> {:?}",
//                     nd.path_segments[nd.depth],
//                     symlink_target
//                 );
//                 nd.resolve_symlink(&symlink_target);
//                 follow_symlink += 1;
//                 // nd.depth += 1;
//                 continue;
//             }
//             if nd.depth != nd.path_segments.len() - 1 {
//                 nd.depth += 1;
//                 continue; // 继续解析下一个路径分量
//             }
//             return Ok(Arc::new(File::new(
//                 Path::new(nd.mnt.clone(), dentry.clone()),
//                 dentry.get_inode(),
//                 flags,
//             )));
//         }

//         // 文件不存在，若 `O_CREAT` 设置，则创建文件
//         if flags.contains(OpenFlags::O_CREAT) {
//             assert!(nd.depth == nd.path_segments.len() - 1);
//             let dir_inode = nd.dentry.get_inode();
//             let new_dentry = Dentry::negative(
//                 absolute_current_dir + "/" + &nd.path_segments[nd.depth],
//                 Some(nd.dentry.clone()),
//             );
//             dir_inode.create(new_dentry.clone(), mode as u16);
//             insert_dentry(new_dentry.clone());
//             assert!(!new_dentry.is_negative());
//             return Ok(Arc::new(File::new(
//                 Path::new(nd.mnt.clone(), new_dentry.clone()),
//                 new_dentry.get_inode(),
//                 flags,
//             )));
//         }
//         return Err(-ENOENT);
//     }
// }

// Todo: 增加权限检查
/// 根据路径查找inode, 如果不存在, 则根据flags创建
/// path可以是绝对路径或相对路径
/// mode只在flags包含O_CREAT时有效
pub fn path_openat(
    path: &str,
    flags: OpenFlags,
    dfd: i32,
    mode: usize,
) -> Result<Arc<dyn FileOp>, Errno> {
    // 解析路径的目录部分，遇到最后一个组件时停止
    // Todo: 正常有符号链接的情况下, 这里应该是一个循环
    let mut nd = Nameidata::new(path, dfd);
    loop {
        let symlink_target = link_path_walk(&mut nd)?;
        if !symlink_target.is_empty() {
            // 符号链接
            nd.path_segments = parse_path(&symlink_target);
            continue;
        }
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
    let mut absolute_current_dir = nd.dentry.absolute_path.clone();
    absolute_current_dir = absolute_current_dir + "/" + &nd.path_segments[nd.depth];
    let mut dentry = lookup_dcache_with_absolute_path(&absolute_current_dir);
    if dentry.is_none() {
        let current_dir_inode = nd.dentry.get_inode();
        // 在目录中查找目录项
        dentry = Some(current_dir_inode.lookup(&nd.path_segments[nd.depth], nd.dentry.clone()));
        // 注意这里插入的dentry可能是负目录项
        // log::warn!("[lookup_dentry] try to lookup in dir_inode");
    }
    let dentry = dentry.unwrap();
    insert_dentry(dentry.clone());
    // log::info!(
    //     "[lookup_dentry] dentry: {:?}, is_negative: {}",
    //     dentry.absolute_path,
    //     dentry.is_negative()
    // );
    dentry
}

const EEXIST: isize = 17;

// 创建新文件或目录时用于解析路径, 获得对应的`dentry`
// 同时检查路径是否存在, 若存在则返回错误
// 预期的返回值是负目录项(已建立父子关系)
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
pub fn filename_lookup(nd: &mut Nameidata, _lookup_flags: usize) -> Result<Arc<Dentry>, Errno> {
    let mut error: i32;
    match link_path_walk(nd) {
        Ok(_) => {
            // 到达最后一个组件
            // 处理`.`和`..`
            if nd.path_segments[nd.depth] == "." {
                return Ok(nd.dentry.clone());
            } else if nd.path_segments[nd.depth] == ".." {
                let parent_dentry = nd.dentry.get_parent();
                return Ok(parent_dentry);
            } else {
                // name是String
                let dentry = lookup_dentry(nd);
                if dentry.is_negative() {
                    return Err(Errno::ENOENT);
                }
                return Ok(dentry);
            }
        }
        Err(e) => {
            return Err(e);
        }
    }
}

// 不是目录
const ENOTDIR: isize = 20;
// 访问路径组件不存在
const ENOENT: isize = 2;

// 注意: name可能为"."或"..", 在DentryCache中绝对路径不包括这两个特殊目录
/// 若找不到, 则返回负目录项, nd中的dentry和inode为父目录的
/// 由上层调用者保真nd.dentry是positive
/// basic name resolution function: path -> dentry
/// 解析路径的父目录部分，找到 dentry。
/// 如果是符号链接, 则返回解析后的链接目标
pub fn link_path_walk(nd: &mut Nameidata) -> Result<String, Errno> {
    assert!(!nd.dentry.is_negative());
    // log::info!("[link_path_walk] path: {:?}", nd.path_segments);
    // 解析路径的目录部分，遇到最后一个组件时停止检查最后一个路径分量
    // 注意对于根目录, nd.path_segments是空的
    let mut len = nd.path_segments.len() - 1;
    let mut symlink_count = 0;
    while nd.depth < len {
        if nd.path_segments[nd.depth] == "." {
            nd.depth += 1;
            continue;
        } else if nd.path_segments[nd.depth] == ".." {
            let parent_dentry = nd.dentry.get_parent();
            nd.depth += 1;
            nd.dentry = parent_dentry;
        } else {
            // name是String
            let mut dentry = lookup_dentry(nd);
            // 路径组件不存在
            if dentry.is_negative() {
                return Err(Errno::ENOENT);
            }
            while dentry.is_symlink() {
                if symlink_count > SYMLINK_MAX {
                    return Err(Errno::ELOOP); // 防止无限循环解析符号链接
                }
                symlink_count += 1;
                let symlink_target = dentry.get_inode().get_link(); // 读取符号链接目标
                log::info!(
                    "Resolving symlink: {:?} -> {:?}",
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
            // 确保最终路径是目录
            if !dentry.get_inode().can_lookup() {
                return Err(Errno::ENOTDIR);
            }
            nd.depth += 1;
            nd.dentry = dentry;
        }
    }
    Ok(String::new())
}

pub const SYMLINK_MAX: usize = 10;
// 符号链接解析过程中出现循环
pub const ELOOP: isize = 40;

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

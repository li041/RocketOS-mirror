use super::{
    dentry::{insert_dentry, lookup_dcache_with_absolute_path, Dentry},
    file::{File, O_CREAT},
    inode::InodeOp,
    mount::VfsMount,
    path::Path,
    FS_BLOCK_SIZE,
};
use crate::{fs::AT_FDCWD, task::current_task};
use alloc::{sync::Arc, vec::Vec};

pub struct Nameidata<'a> {
    path_segments: Vec<&'a str>,
    // 以下字段在路径解析过程中需要更新
    // 通过dentry可以找到inode
    // 注意Dentry和InodeOp的锁粒度都在他们自己的结构体内部
    pub dentry: Arc<Dentry>,
    pub mnt: Arc<VfsMount>,
    // pub path: Path,
    // 当前处理到的路径
    depth: usize,
}

impl<'a> Nameidata<'a> {
    // 如果是绝对路径, 则dfd不会被使用
    // 绝对路径dentry初始化为root, 相对路径则是cwd
    // 相当于linux中的`path_init`
    pub fn new(filename: &'a str, dfd: i32) -> Self {
        let path_segments: Vec<&'a str> = filename.split('/').filter(|s| !s.is_empty()).collect();
        let path: Arc<Path>;
        let cur_task = current_task();
        if filename.starts_with("/") {
            // 绝对路径
            path = cur_task.root();
        } else {
            let task = current_task();
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
}

/// 处理路径的最后一个组件
/// 如果open_flag包含O_CREAT, 则创建文件
pub fn open_last_lookups(
    nd: &mut Nameidata,
    flags: usize,
    mode: usize,
) -> Result<Arc<File>, isize> {
    let absolute_current_dir = nd.dentry.absolute_path.clone();
    // 处理`.`和`..`
    if nd.path_segments[nd.depth] == "." {
        return Ok(Arc::new(File::new(
            Path::new(nd.mnt.clone(), nd.dentry.clone()),
            nd.dentry.get_inode(),
            flags,
        )));
    } else if nd.path_segments[nd.depth] == ".." {
        let parent_dentry = nd.dentry.get_parent();
        return Ok(Arc::new(File::new(
            Path::new(nd.mnt.clone(), parent_dentry.clone()),
            parent_dentry.get_inode(),
            flags,
        )));
    } else {
        // name是String
        // 先查找文件, 如果文件不存在, 看是否设置了O_CREAT
        // 先查找dentry cache
        let dentry = lookup_dentry(nd);
        if !dentry.is_negative() {
            return Ok(Arc::new(File::new(
                Path::new(nd.mnt.clone(), dentry.clone()),
                dentry.get_inode(),
                flags,
            )));
        }

        if flags & O_CREAT != 0 {
            // Todo: 最后打开的是目录还是文件要区分
            // 创建文件
            let dir_inode = nd.dentry.get_inode();
            // Todo: 设置mode
            let new_dentry = Dentry::negative(
                absolute_current_dir + "/" + nd.path_segments[nd.depth],
                Some(nd.dentry.clone()),
            );
            dir_inode.create(new_dentry.clone(), mode as u16);
            insert_dentry(new_dentry.clone());
            assert!(!new_dentry.is_negative());
            return Ok(Arc::new(File::new(
                Path::new(nd.mnt.clone(), new_dentry.clone()),
                new_dentry.get_inode(),
                flags,
            )));
        }
        // 文件不存在, 且没有设置O_CREAT
        return Err(-ENOENT);
    }
}

// Todo: 增加权限检查
/// 根据路径查找inode, 如果不存在, 则根据flags创建
/// path可以是绝对路径或相对路径
/// Todo: 符号链接
pub fn path_openat(path: &str, flags: usize, dfd: i32, mode: usize) -> Result<Arc<File>, isize> {
    let mut nd = Nameidata::new(path, dfd);
    // 解析路径的目录部分，遇到最后一个组件时停止
    // Todo: 正常有符号链接的情况下, 这里应该是一个循环
    // loop {
    link_path_walk(&mut nd)?;
    // 到达最后一个组件
    match open_last_lookups(&mut nd, flags, mode) {
        Ok(file) => {
            return Ok(file);
        }
        Err(e) => {
            return Err(e);
        }
    }
    // }
}

// 先查找dentry cache, 如果没有, 则调用InodeOp::lookup
// 对于查找dentry的时候, 都应该通过这个函数
// 该函数会建立dentry的父子关系, 并将dentry放入dentry cache
// 由上层调用者保证:
//     1. nd.dentry即为父目录
pub fn lookup_dentry(nd: &mut Nameidata) -> Arc<Dentry> {
    let mut absolute_current_dir = nd.dentry.absolute_path.clone();
    absolute_current_dir = absolute_current_dir + "/" + nd.path_segments[nd.depth];
    let mut dentry = lookup_dcache_with_absolute_path(&absolute_current_dir);
    if dentry.is_none() {
        let current_dir_inode = nd.dentry.get_inode();
        dentry = Some(current_dir_inode.lookup(&nd.path_segments[nd.depth], nd.dentry.clone()));
        // 注意这里插入的dentry可能是负目录项
    }
    let dentry = dentry.unwrap();
    insert_dentry(dentry.clone());
    log::info!(
        "[lookup_dentry] dentry: {:?}, is_negative: {}",
        dentry.absolute_path,
        dentry.is_negative()
    );
    dentry
}

const EEXIST: isize = 17;

// 创建新文件或目录时用于解析路径, 获得对应的`dentry`
// 同时检查路径是否存在
// 预期的返回值是负目录项(已建立父子关系)
pub fn filename_create(nd: &mut Nameidata, _lookup_flags: usize) -> Result<Arc<Dentry>, isize> {
    let mut error: i32;
    // 解析路径的目录部分，调用后nd.dentry是最后一个组件的父目录
    match link_path_walk(nd) {
        Ok(_) => {
            // 到达最后一个组件
            let mut absolute_current_dir = nd.dentry.absolute_path.clone();
            // 处理`.`和`..`, 最后一个组件不能是`.`或`..`, 不合法
            if nd.path_segments[nd.depth] == "." {
                return Err(-EEXIST);
            } else if nd.path_segments[nd.depth] == ".." {
                return Err(-EEXIST);
            } else {
                // name是String
                let dentry = lookup_dentry(nd);
                if !dentry.is_negative() {
                    return Err(-EEXIST);
                }
                return Ok(dentry);
            }
        }
        Err(e) => {
            return Err(e);
        }
    };
}

pub fn filename_lookup(nd: &mut Nameidata, _lookup_flags: usize) -> Result<Arc<Dentry>, isize> {
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
                    return Err(-ENOENT);
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
/// Todo: 处理符号链接
pub fn link_path_walk(nd: &mut Nameidata) -> Result<(), isize> {
    assert!(!nd.dentry.is_negative());
    log::info!("[link_path_walk] path: {:?}", nd.path_segments);
    let mut absolute_current_dir = nd.dentry.absolute_path.clone();
    // 解析路径的目录部分，遇到最后一个组件时停止检查最后一个路径分量
    let len = nd.path_segments.len() - 1;
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
            let dentry = lookup_dentry(nd);
            // 路径组件不存在
            if dentry.is_negative() {
                return Err(-ENOENT);
            }
            // 不是目录
            if !dentry.get_inode().can_lookup() {
                return Err(-ENOTDIR);
            }
            nd.depth += 1;
            nd.dentry = dentry;
        }
    }
    Ok(())
}

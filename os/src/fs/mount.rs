use alloc::{
    string::{String, ToString},
    sync::{Arc, Weak},
    vec::Vec,
};
use bitflags::Flag;

use crate::{
    drivers::{block::block_dev::BlockDevice, BLOCK_DEVICE},
    ext4::{fs::Ext4FileSystem, inode::Ext4Inode},
    mutex::SpinNoIrqLock,
};

use super::{
    dentry::{insert_dentry, Dentry},
    inode::InodeOp,
    path::Path,
    super_block::{Fake_FS, FileSystemOp},
};

use lazy_static::lazy_static;

use alloc::vec;

// 对于一个挂载的文件系统有一个VfsMount, 对于其的每一个挂载点有一个Mount
pub struct VfsMount {
    root: Arc<Dentry>,         // root of the mounted tree
    fs: Arc<dyn FileSystemOp>, // 挂载的文件系统(超级块)
    flags: i32,                // mount flags
}

impl VfsMount {
    pub fn zero_init() -> Self {
        VfsMount {
            root: Arc::new(Dentry::zero_init()),
            fs: Arc::new(Fake_FS),
            flags: 0,
        }
    }
    pub fn new(root: Arc<Dentry>, fs: Arc<dyn FileSystemOp>, flags: i32) -> Arc<Self> {
        Arc::new(VfsMount { root, fs, flags })
    }
}

/// 表示一个挂载点 (相当于 Linux 的 struct mount)
pub struct Mount {
    mountpoint: Arc<Dentry>,         // 挂载点
    vfs_mount: Arc<VfsMount>,        // vfs层
    pub parent: Option<Weak<Mount>>, // 父挂载点
    children: Vec<Arc<Mount>>,       // 子挂载点
}

impl Mount {
    pub fn new_root(mountpoint: Arc<Dentry>, vfs_mount: Arc<VfsMount>) -> Arc<Self> {
        Arc::new(Mount {
            mountpoint,
            vfs_mount,
            parent: None,
            children: vec![],
        })
    }
    /// 创建一个新的挂载点
    pub fn new(mountpoint: Arc<Dentry>, mnt: Arc<VfsMount>, parent: Arc<Mount>) -> Self {
        Mount {
            mountpoint,
            vfs_mount: mnt,
            parent: Some(Arc::downgrade(&parent)),
            children: vec![],
        }
    }
}

/// 全局 mount 树
struct MountTree {
    mount_table: Vec<Arc<Mount>>,
}

impl MountTree {
    /// 创建一个新的全局 mount 树，默认只有根 "/"
    fn new() -> Self {
        MountTree {
            mount_table: { Vec::new() },
        }
    }
}

lazy_static! {
    /// 全局的 mount 树
    static ref MOUNT_TREE: SpinNoIrqLock<MountTree> = {
        SpinNoIrqLock::new(MountTree::new())
    };
}

pub fn add_mount(mount: Arc<Mount>) {
    let mut mount_tree = MOUNT_TREE.lock();
    mount_tree.mount_table.push(mount);
}

pub fn get_mount_by_path(path: Path) -> Option<Arc<Mount>> {
    let mount_tree = MOUNT_TREE.lock();
    for mount in mount_tree.mount_table.iter() {
        // 如果mount的parent->mnt与path.mnt相同(同一棵Mount Tree),
        // 且path.dentry是mount的root, 则返回这个mount(挂载点)
        if Arc::ptr_eq(
            &mount.parent.as_ref().unwrap().upgrade().unwrap().vfs_mount,
            &path.mnt,
        ) && Arc::ptr_eq(&mount.mountpoint, &path.dentry)
        {
            return Some(mount.clone());
        }
    }
    log::warn!("get_mount_by_path failed");
    return None;
}

/// 挂载最初的文件系统, 返回根目录的Path
// 初始化全局的根目录
//  1. 创建根目录inode
//  2. 创建根目录dentry
//  3. 创建根目录的Mount
pub fn do_ext4_mount(block_device: Arc<dyn BlockDevice>) -> Arc<Path> {
    let ext4_fs = Ext4FileSystem::open(block_device.clone());
    let root_inode = Ext4Inode::new_root(
        block_device.clone(),
        ext4_fs.clone(),
        &ext4_fs.block_groups[0],
    );
    ext4_list_apps(root_inode.clone());
    let root_dentry = Dentry::new("".to_string(), None, 0, root_inode.clone());
    root_dentry.inner.lock().parent = Some(Arc::downgrade(&root_dentry));
    insert_dentry(root_dentry.clone());
    // 创建根目录的Mount, 并加入全局Mount表
    let fake_mount_flag = 0;
    let root_vfs_mount = VfsMount::new(root_dentry.clone(), ext4_fs, fake_mount_flag);
    let root_mount = Mount::new_root(root_dentry.clone(), root_vfs_mount.clone());
    add_mount(root_mount);
    // Path
    let root_path = Path::new(root_vfs_mount, root_dentry);
    root_path
}

// Todo
pub fn do_mount(
    dev_name: String,
    dir_name: String,
    fs_type: String,
    flags: usize,
    _data: *const u8,
) -> isize {
    // user_path_at
    // 需要把dev_name先转换成BlockDevice?
    // path_mount
    // 最后更新全局的Mount Tree
    0
}

pub fn ext4_list_apps(root_inode: Arc<dyn InodeOp>) {
    println!("/**** ROOT APPS ****");
    let dirents = root_inode.getdents(0).1;
    if dirents.is_empty() {
        println!("No apps found!");
    } else {
        for dirent in dirents.iter() {
            print!("{}\t", String::from_utf8_lossy(&dirent.d_name));
        }
    }
    println!("\n**************/");
}

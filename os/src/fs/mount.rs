use alloc::{
    format,
    string::{String, ToString},
    sync::{Arc, Weak},
    vec::Vec,
};
use spin::Mutex;

use crate::{
    drivers::block::block_dev::{self, BlockDevice},
    ext4::{
        fs::Ext4FileSystem,
        inode::{write_inode_on_disk, Ext4Inode},
    },
    net::socket::{SocketInode, SOCKET_INODE},
    syscall::errno::SyscallRet,
};

use super::{
    dentry::{insert_dentry, Dentry, DentryFlags},
    dev::init_devfs,
    inode::InodeOp,
    manager::{FakeFS, FileSystemOp},
    path::Path,
    proc::init_procfs,
    tmp::init_tmpfs,
    uapi::StatFs,
};

use lazy_static::lazy_static;

use alloc::vec;

// 对于一个挂载的文件系统有一个VfsMount, 对于其的每一个挂载点有一个Mount
#[allow(unused)]
pub struct VfsMount {
    root: Arc<Dentry>,         // root of the mounted tree
    fs: Arc<dyn FileSystemOp>, // 挂载的文件系统(超级块)
    flags: i32,                // mount flags
}

impl VfsMount {
    pub fn zero_init() -> Self {
        VfsMount {
            root: Arc::new(Dentry::zero_init()),
            fs: Arc::new(FakeFS),
            flags: 0,
        }
    }
    pub fn new(root: Arc<Dentry>, fs: Arc<dyn FileSystemOp>, flags: i32) -> Arc<Self> {
        Arc::new(VfsMount { root, fs, flags })
    }
}

/// 表示一个挂载点 (相当于 Linux 的 struct mount)
#[allow(unused)]
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
    #[allow(unused)]
    pub fn new(mountpoint: Arc<Dentry>, mnt: Arc<VfsMount>, parent: Arc<Mount>) -> Self {
        Mount {
            mountpoint,
            vfs_mount: mnt,
            parent: Some(Arc::downgrade(&parent)),
            children: vec![],
        }
    }
    pub fn statfs(&self, buf: *mut StatFs) -> SyscallRet {
        self.vfs_mount.fs.statfs(buf)
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
    static ref MOUNT_TREE: Mutex<MountTree> = {
        Mutex::new(MountTree::new())
    };
}

pub fn read_proc_mounts() -> String {
    let mount_tree = MOUNT_TREE.lock();
    let mut output = String::new();

    for mount in &mount_tree.mount_table {
        // let source = mount.vfs_mount.fs.get_block_device().get_name();
        let source = "none";
        // 注意: 根目录的root_dentry的absolute_path是空字符串, 需要特殊处理
        let target = if mount.mountpoint.absolute_path.is_empty() {
            "/".to_string()
        } else {
            mount.mountpoint.absolute_path.clone()
        };
        let fstype = mount.vfs_mount.fs.type_name();
        let options = "rw,relatime";

        // 类似于: "dev/sda1 / ext4 rw,relatime 0 0\n"
        log::error!(
            "source: {}, target: {}, fstype: {}, options: {}",
            source,
            target,
            fstype,
            options
        );
        let line = format!("{} {} {} {} 0 0\n", source, target, fstype, options);
        output.push_str(&line);
    }
    output
}

pub fn add_mount(mount: Arc<Mount>) {
    let mut mount_tree = MOUNT_TREE.lock();
    mount_tree.mount_table.push(mount);
}

// pub fn get_mount_by_path(path: Path) -> Option<Arc<Mount>> {
//     let mount_tree = MOUNT_TREE.lock();
//     for mount in mount_tree.mount_table.iter() {
//         // 如果mount的parent->mnt与path.mnt相同(同一棵Mount Tree),
//         // 且path.dentry是mount的root, 则返回这个mount(挂载点)
//         if Arc::ptr_eq(
//             &mount.parent.as_ref().unwrap().upgrade().unwrap().vfs_mount,
//             &path.mnt,
//         ) && Arc::ptr_eq(&mount.mountpoint, &path.dentry)
//         {
//             return Some(mount.clone());
//         }
//     }
//     log::warn!("get_mount_by_path failed");
//     return None;
// }
pub fn get_mount_by_dentry(dentry: Arc<Dentry>) -> Option<Arc<Mount>> {
    let mount_tree = MOUNT_TREE.lock();
    for mount in mount_tree.mount_table.iter() {
        // 如果mount的parent->mnt与path.mnt相同(同一棵Mount Tree),
        // 且path.dentry是mount的root, 则返回这个mount(挂载点)
        if Arc::ptr_eq(&mount.mountpoint, &dentry) {
            return Some(mount.clone());
        }
    }
    log::warn!("get_mount_by_dentry failed");
    return None;
}

/// 挂载最初的文件系统, 返回根目录的Path
// 1. 初始化全局的根目录
//  a. 创建根目录inode
//  b. 创建根目录dentry
//  c. 创建根目录的Mount
// 2. 初始化/dev下的设备文件
// 3. 初始化/proc下的procfs
// 4. 为了busybox which ls, 创建一个空的/bin/ls
pub fn do_ext4_mount(block_device: Arc<dyn BlockDevice>) -> Arc<Path> {
    let ext4_fs = Ext4FileSystem::open(block_device.clone());
    let root_inode = Ext4Inode::new_root(
        block_device.clone(),
        ext4_fs.clone(),
        &ext4_fs.block_groups[0],
    );
    let root_dentry = Dentry::new(
        "".to_string(),
        None,
        DentryFlags::DCACHE_DIRECTORY_TYPE,
        root_inode.clone(),
    );
    root_dentry.inner.lock().parent = Some(root_dentry.clone());
    insert_dentry(root_dentry.clone());
    let inode_num = ext4_fs.alloc_inode(block_device.clone(), false);
    let socket_inode = SocketInode::new(inode_num);
    write_inode_on_disk(
        &root_inode,
        &socket_inode.inner.read().inode_on_disk,
        inode_num,
        block_device.clone(),
    );
    SOCKET_INODE.call_once(|| socket_inode.clone());
    // 创建根目录的Mount, 并加入全局Mount表
    let fake_mount_flag = 0;
    let root_vfs_mount = VfsMount::new(root_dentry.clone(), ext4_fs, fake_mount_flag);
    let root_mount = Mount::new_root(root_dentry.clone(), root_vfs_mount.clone());
    add_mount(root_mount);
    // Path
    let root_path = Path::new(root_vfs_mount, root_dentry);
    init_devfs(root_path.clone());
    init_procfs(root_path.clone());
    init_tmpfs(root_path.clone());
    root_path
}

// Todo
#[allow(unused)]
pub fn do_mount(
    dev_name: String,
    dir_name: String,
    fs_type: String,
    flags: usize,
    _data: *const u8,
) -> SyscallRet {
    // user_path_at
    // 需要把dev_name先转换成BlockDevice?
    // path_mount
    // 最后更新全局的Mount Tree
    Ok(0)
}

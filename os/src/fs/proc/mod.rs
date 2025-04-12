use crate::ext4::inode::{S_IFCHR, S_IFDIR, S_IFREG};

use super::{
    dentry::{self, Dentry},
    file::OpenFlags,
    mount::VfsMount,
    namei::{filename_create, parse_path, path_openat, Nameidata},
    path::Path,
    uapi::DevT,
    AT_FDCWD,
};
use alloc::sync::Arc;
use meminfo::{MemInfoFile, MEMINFO};
use mounts::{MountsFile, MOUNTS};

pub mod meminfo;
pub mod mounts;

pub fn init_procfs(root_path: Arc<Path>) {
    let proc_path = "/proc";
    // let mut nd = Nameidata::new(proc_path, AT_FDCWD);
    let mut nd = Nameidata {
        path_segments: parse_path(proc_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    let proc_mode = S_IFDIR as u16 | 0o755;
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.mkdir(dentry, proc_mode);
        }
        Err(e) => {
            panic!("create {} failed: {}", proc_path, e);
        }
    };
    // /proc/mounts
    // 只读, 虚拟文件
    let mounts_path = "/proc/mounts";
    let mounts_mode = S_IFREG as u16 | 0o444;
    nd = Nameidata {
        path_segments: parse_path(mounts_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.create(dentry.clone(), mounts_mode);
            // 现在dentry的inode指向/proc/mounts
            let mounts_file = MountsFile::new(
                Path::new(root_path.mnt.clone(), dentry.clone()),
                dentry.get_inode().clone(),
                // ReadOnly
                OpenFlags::empty(),
            );
            MOUNTS.call_once(|| mounts_file.clone());
        }
        Err(e) => {
            panic!("create {} failed: {}", mounts_path, e);
        }
    };
    // /proc/meminfo
    // 只读, 虚拟文件
    let meminfo_path = "/proc/meminfo";
    let meminfo_mode = S_IFREG as u16 | 0o444;
    nd = Nameidata {
        path_segments: parse_path(meminfo_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.create(dentry.clone(), meminfo_mode);
            // 现在dentry的inode指向/proc/meminfo
            let meminfo_file = MemInfoFile::new(
                Path::new(root_path.mnt.clone(), dentry.clone()),
                dentry.get_inode().clone(),
                // ReadOnly
                OpenFlags::empty(),
            );
            MEMINFO.call_once(|| meminfo_file.clone());
        }
        Err(e) => {
            panic!("create {} failed: {}", mounts_path, e);
        }
    };
}

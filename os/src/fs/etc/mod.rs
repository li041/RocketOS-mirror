use alloc::sync::Arc;

use crate::ext4::inode::{S_IFDIR, S_IFREG};

use super::{
    dentry::{self, insert_core_dentry, Dentry},
    file::OpenFlags,
    mount::VfsMount,
    namei::{filename_create, parse_path, path_openat, Nameidata},
    path::Path,
    proc::meminfo::MemInfoFile,
    uapi::DevT,
    AT_FDCWD,
};

pub fn init_etcfs(root_path: Arc<Path>) {
    let etc_path = "/etc";
    // let mut nd = Nameidata::new(etc_path, AT_FDCWD);
    let mut nd = Nameidata {
        path_segments: parse_path(etc_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    let etc_mode = S_IFDIR as u16 | 0o755;
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.mkdir(dentry, etc_mode);
        }
        Err(e) => {
            panic!("create {} failed: {:?}", etc_path, e);
        }
    };
}

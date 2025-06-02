use alloc::sync::Arc;

use crate::ext4::inode::S_IFDIR;

use super::{
    dentry::insert_core_dentry,
    namei::{filename_create, parse_path, Nameidata},
    path::Path,
};

pub fn init_tmpfs(root_path: Arc<Path>) {
    let tmp_path = "/tmp";
    // let mut nd = Nameidata::new(tmp_path, AT_FDCWD);
    let mut nd = Nameidata {
        path_segments: parse_path(tmp_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    let tmp_mode = S_IFDIR as u16 | 0o755;
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.mkdir(dentry.clone(), tmp_mode);
            insert_core_dentry(dentry);
        }
        Err(e) => {
            panic!("create {} failed: {:?}", tmp_path, e);
        }
    };
}

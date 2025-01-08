use alloc::sync::Arc;

use super::{
    create_dir,
    devfs::dev::DevInode,
    inode::Inode,
    os_inode::{list_apps, ROOT_INODE},
    procfs::proc::ProcInode,
    AT_FDCWD,
};

/// used on start of os
pub fn init() {
    mount_fs();
    list_apps();
}

fn mount_fs() {
    let root_meta = ROOT_INODE.get_meta();
    let mut root_inner = root_meta.inner.lock();

    // 'mount' inner fs es
    let dev: Arc<dyn Inode> = Arc::new(DevInode::new(ROOT_INODE.clone()));
    let proc: Arc<dyn Inode> = Arc::new(ProcInode::new(ROOT_INODE.clone()));
    root_inner.children.insert(dev.get_name(), dev.clone());
    root_inner.children.insert(proc.get_name(), proc.clone());

    drop(root_inner);

    log::debug!("[mount_fs] Mounted dev and proc fs");
    // create new '/tmp' directory
    match create_dir(AT_FDCWD, &"/tmp".into()) {
        Ok(_) => {}
        Err(e) => log::info!("[mount_fs] Fail to create '/tmp' directory: {}", e),
    }
}

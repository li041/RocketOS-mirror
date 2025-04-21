use crate::ext4::inode::{S_IFCHR, S_IFDIR};

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
use rtc::{RtcFile, RTC};
use tty::{TtyFile, TTY};

pub mod rtc;
pub mod tty;

// Todo: /dev/zero, /dev/null
pub fn init_devfs(root_path: Arc<Path>) {
    let dev_path = "/dev";
    // let mut nd = Nameidata::new(dev_path, AT_FDCWD);
    let mut nd = Nameidata {
        path_segments: parse_path(dev_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    let dev_mode = S_IFDIR as u16 | 0o755;
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.mkdir(dentry, dev_mode);
        }
        Err(e) => {
            panic!("create {} failed: {:?}", dev_path, e);
        }
    };
    // /dev/tty
    let tty_path = "/dev/tty";
    let tty_mode = S_IFCHR as u16 | 0o666;
    let tty_devt = DevT::tty_devt();
    nd = Nameidata {
        path_segments: parse_path(tty_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.mknod(dentry.clone(), tty_mode, tty_devt);
            // 现在dentry的inode指向/dev/tty
            let tty_file = TtyFile::new(
                Path::new(root_path.mnt.clone(), dentry.clone()),
                dentry.get_inode().clone(),
                OpenFlags::O_RDWR,
            );
            TTY.call_once(|| tty_file.clone());
        }
        Err(e) => {
            panic!("create {} failed: {:?}", tty_path, e);
        }
    };
    // /dev/rtc
    let rtc_path = "/dev/rtc";
    let rtc_mode = S_IFCHR as u16 | 0o666;
    let rtc_devt = DevT::rtc_devt();
    nd = Nameidata {
        path_segments: parse_path(rtc_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.mknod(dentry.clone(), rtc_mode, rtc_devt);
            // 现在dentry的inode指向/dev/rtc
            let rtc_file = RtcFile::new(
                Path::new(root_path.mnt.clone(), dentry.clone()),
                dentry.get_inode().clone(),
                OpenFlags::O_RDWR,
            );
            RTC.call_once(|| rtc_file.clone());
        }
        Err(e) => {
            panic!("create {} failed: {:?}", rtc_path, e);
        }
    }
}

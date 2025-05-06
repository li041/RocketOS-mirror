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
use null::{NullFile, NULL};
use rtc::{RtcFile, RTC};
use tty::{TtyFile, TTY};
use zero::{ZeroFile, ZERO};

pub mod null;
pub mod rtc;
pub mod tty;
pub mod zero;

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
    // /dev/cpu_dma_latency
    let cpu_dma_latency_path = "/dev/cpu_dma_latency";
    let mut nd = Nameidata {
        path_segments: parse_path(cpu_dma_latency_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    let cpu_dma_latency_mode = S_IFDIR as u16 | 0o755;
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.mkdir(dentry, cpu_dma_latency_mode);
        }
        Err(e) => {
            panic!("create {} failed: {:?}", cpu_dma_latency_path, e);
        }
    };
    // /dev/shm
    let shm_path = "/dev/shm";
    let shm_mode = S_IFDIR as u16 | 0o755;
    nd = Nameidata {
        path_segments: parse_path(shm_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.mkdir(dentry, shm_mode);
        }
        Err(e) => {
            panic!("create {} failed: {:?}", shm_path, e);
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
    // /dev/ttyS0
    let tty_path = "/dev/ttyS0";
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
            // 现在dentry的inode指向/dev/ttyS0
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
    // /dev/null
    let null_path = "/dev/null";
    let null_mode = S_IFCHR as u16 | 0o666;
    let null_devt = DevT::null_devt();
    nd = Nameidata {
        path_segments: parse_path(null_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.mknod(dentry.clone(), null_mode, null_devt);
            // 现在dentry的inode指向/dev/null
            let null_file = NullFile::new(
                Path::new(root_path.mnt.clone(), dentry.clone()),
                dentry.get_inode().clone(),
                OpenFlags::O_RDWR,
            );
            NULL.call_once(|| null_file.clone());
        }
        Err(e) => {
            panic!("create {} failed: {:?}", null_path, e);
        }
    }
    // /dev/zero
    let zero_path = "/dev/zero";
    let zero_mode = S_IFCHR as u16 | 0o666;
    let zero_devt = DevT::zero_devt();
    nd = Nameidata {
        path_segments: parse_path(zero_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.mknod(dentry.clone(), zero_mode, zero_devt);
            let zero_file = ZeroFile::new(
                Path::new(root_path.mnt.clone(), dentry.clone()),
                dentry.get_inode().clone(),
                OpenFlags::O_RDWR,
            );
            ZERO.call_once(|| zero_file.clone());
        }
        Err(e) => {
            panic!("create {} failed: {:?}", zero_path, e);
        }
    }
}

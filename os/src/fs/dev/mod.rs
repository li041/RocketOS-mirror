use crate::ext4::inode::{S_IFBLK, S_IFCHR, S_IFDIR, S_IFREG};

use super::{
    dentry::insert_core_dentry,
    file::OpenFlags,
    namei::{filename_create, parse_path_uncheck, Nameidata},
    path::Path,
    uapi::DevT,
};
use alloc::sync::Arc;
use loop_device::{insert_loop_device, LoopControlFile, LoopDevice, LOOP_CONTROL};
use null::{NullFile, NULL};
use rtc::{RtcFile, RTC};
use tty::{TtyFile, TTY};
use urandom::{UrandomFile, URANDOM};
use zero::{ZeroFile, ZERO};

pub mod invalid;
pub mod loop_device;
pub mod null;
pub mod rtc;
pub mod tty;
pub mod urandom;
pub mod zero;

// Todo: /dev/zero, /dev/null
pub fn init_devfs(root_path: Arc<Path>) {
    let dev_path = "/dev";
    // let mut nd = Nameidata::new(dev_path, AT_FDCWD);
    let mut nd = Nameidata {
        path_segments: parse_path_uncheck(dev_path),
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
            // panic!("create {} failed: {:?}", dev_path, e);
            // 8.19 tmp 统计哪些文件夹是已在的
            println!("create {} failed: {:?}, maybe already exists", dev_path, e);
            log::debug!("create {} failed: {:?}, maybe already exists", dev_path, e);
        }
    };
    // /dev/cpu_dma_latency
    let cpu_dma_latency_path = "/dev/cpu_dma_latency";
    let mut nd = Nameidata {
        path_segments: parse_path_uncheck(cpu_dma_latency_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    let cpu_dma_latency_mode = S_IFREG as u16 | 0o755;
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.create(dentry, cpu_dma_latency_mode);
        }
        Err(e) => {
            // 8.19 tmp 统计哪些文件夹是已在的
            // panic!("create {} failed: {:?}", dev_path, e);
            println!(
                "create {} failed: {:?}, maybe already exists",
                cpu_dma_latency_path, e
            );
            log::debug!(
                "create {} failed: {:?}, maybe already exists",
                cpu_dma_latency_path,
                e
            );
        }
    };
    // /dev/shm
    let shm_path = "/dev/shm";
    let shm_mode = S_IFDIR as u16 | 0o755;
    nd = Nameidata {
        path_segments: parse_path_uncheck(shm_path),
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
            // 8.19 tmp 统计哪些文件夹是已在的
            println!("create {} failed: {:?}, maybe already exists", shm_path, e);
            log::debug!("create {} failed: {:?}, maybe already exists", shm_path, e);
        }
    };
    // /dev/tty
    let tty_path = "/dev/tty";
    let tty_mode = S_IFCHR as u16 | 0o666;
    let tty_devt = DevT::tty_devt();
    nd = Nameidata {
        path_segments: parse_path_uncheck(tty_path),
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
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            // 8.19 tmp 统计哪些文件夹是已在的
            println!("create {} failed: {:?}, maybe already exists", dev_path, e);
            log::debug!("create {} failed: {:?}, maybe already exists", dev_path, e);
        }
    };
    // /dev/ttyS0
    let tty_path = "/dev/ttyS0";
    let tty_mode = S_IFCHR as u16 | 0o666;
    let tty_devt = DevT::tty_devt();
    nd = Nameidata {
        path_segments: parse_path_uncheck(tty_path),
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
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            // 8.19 tmp 统计哪些文件夹是已在的
            println!("create {} failed: {:?}, maybe already exists", dev_path, e);
            log::debug!("create {} failed: {:?}, maybe already exists", dev_path, e);
        }
    };
    // /dev/rtc
    let rtc_path = "/dev/rtc";
    let rtc_mode = S_IFCHR as u16 | 0o666;
    let rtc_devt = DevT::rtc_devt();
    nd = Nameidata {
        path_segments: parse_path_uncheck(rtc_path),
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
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            // 8.19 tmp 统计哪些文件夹是已在的
            println!("create {} failed: {:?}, maybe already exists", dev_path, e);
            log::debug!("create {} failed: {:?}, maybe already exists", dev_path, e);
        }
    }
    // /dev/null
    let null_path = "/dev/null";
    let null_mode = S_IFCHR as u16 | 0o666;
    let null_devt = DevT::null_devt();
    nd = Nameidata {
        path_segments: parse_path_uncheck(null_path),
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
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            // panic!("create {} failed: {:?}", null_path, e);
            println!(
                "create {} failed: {:?}, maybe already exists",
                nd.dentry.absolute_path, e
            );
            log::debug!(
                "create {} failed: {:?}, maybe already exists",
                nd.dentry.absolute_path,
                e
            );
        }
    }
    // /dev/zero
    let zero_path = "/dev/zero";
    let zero_mode = S_IFCHR as u16 | 0o666;
    let zero_devt = DevT::zero_devt();
    nd = Nameidata {
        path_segments: parse_path_uncheck(zero_path),
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
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            // panic!("create {} failed: {:?}", zero_path, e);
            println!(
                "create {} failed: {:?}, maybe already exists",
                nd.dentry.absolute_path, e
            );
            log::debug!(
                "create {} failed: {:?}, maybe already exists",
                nd.dentry.absolute_path,
                e
            );
        }
    }
    //dev/urandom
    let urandom_path = "/dev/urandom";
    let urandom_node = S_IFCHR as u16 | 0o666;
    let urandom_devt = DevT::urandom_devt();
    nd = Nameidata {
        path_segments: parse_path_uncheck(urandom_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.mknod(dentry.clone(), urandom_node, urandom_devt);
            // 现在dentry的inode指向/dev/urandom
            let urandom_file = UrandomFile::new(
                Path::new(root_path.mnt.clone(), dentry.clone()),
                dentry.get_inode().clone(),
                OpenFlags::O_RDWR,
            );
            URANDOM.call_once(|| urandom_file.clone());
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            // panic!("create {} failed: {:?}", urandom_path, e);
            println!(
                "create {} failed: {:?}, maybe already exists",
                nd.dentry.absolute_path, e
            );
            log::debug!(
                "create {} failed: {:?}, maybe already exists",
                nd.dentry.absolute_path,
                e
            );
        }
    }
    // /dev/loop-control
    let loop_control_path = "/dev/loop-control";
    let loop_control_mode = S_IFCHR as u16 | 0o666;
    let loop_control_devt = DevT::loop_control_devt();
    nd = Nameidata {
        path_segments: parse_path_uncheck(loop_control_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.mknod(dentry.clone(), loop_control_mode, loop_control_devt);
            // 现在dentry的inode指向/dev/loop-control
            let loop_control_file = LoopControlFile::new(
                Path::new(root_path.mnt.clone(), dentry.clone()),
                dentry.get_inode().clone(),
                OpenFlags::O_RDWR,
            );
            LOOP_CONTROL.call_once(|| loop_control_file.clone());
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            // panic!("create {} failed: {:?}", loop_control_path, e);
            println!(
                "create {} failed: {:?}, maybe already exists",
                nd.dentry.absolute_path, e
            );
            log::debug!(
                "create {} failed: {:?}, maybe already exists",
                nd.dentry.absolute_path,
                e
            );
        }
    }
    // /dev/loop0
    let loop0_path = "/dev/loop0";
    let loop0_mode = S_IFBLK as u16 | 0o666;
    let loop_devt = DevT::loopx_devt(0);
    nd = Nameidata {
        path_segments: parse_path_uncheck(loop0_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.mknod(dentry.clone(), loop0_mode, loop_devt);
            let loop0_file = LoopDevice::new(
                dentry.clone(),
                dentry.get_inode().clone(),
                OpenFlags::O_RDWR,
                0,
            );
            insert_loop_device(loop0_file, 0);
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            // panic!("create {} failed: {:?}", loop0_path, e);
            println!(
                "create {} failed: {:?}, maybe already exists",
                nd.dentry.absolute_path, e
            );
            log::debug!(
                "create {} failed: {:?}, maybe already exists",
                nd.dentry.absolute_path,
                e
            );
        }
    }
}

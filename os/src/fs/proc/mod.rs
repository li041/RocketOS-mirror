use crate::ext4::inode::{Ext4InodeDisk, S_IFCHR, S_IFDIR, S_IFLNK, S_IFREG};

use super::{
    dentry::{self, insert_core_dentry, Dentry},
    file::OpenFlags,
    mount::VfsMount,
    namei::{filename_create, parse_path, path_openat, Nameidata},
    path::Path,
    pipe::PipeInode,
    uapi::DevT,
    AT_FDCWD,
};
use alloc::sync::Arc;
use exe::{ExeFile, ExeInode, EXE};
use fd::FdDirInode;
use meminfo::{MemInfoFile, MEMINFO};
use mounts::{MountsFile, MOUNTS};
use tainted::{TaintedFile, TAINTED};

pub mod exe;
pub mod fd;
pub mod maps;
pub mod meminfo;
pub mod mounts;
pub mod pagemap;
pub mod pid;
pub mod status;
pub mod tainted;

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
            parent_inode.mkdir(dentry.clone(), proc_mode);
            insert_core_dentry(dentry);
        }
        Err(e) => {
            panic!("create {} failed: {:?}", proc_path, e);
        }
    };
    let sys_path = "/proc/sys";
    let mut nd = Nameidata {
        path_segments: parse_path(sys_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    let sys_mode = S_IFDIR as u16 | 0o755;
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.mkdir(dentry.clone(), sys_mode);
        }
        Err(e) => {
            panic!("create {} failed: {:?}", sys_path, e);
        }
    };
    let kernel_path = "/proc/sys/kernel";
    let mut nd = Nameidata {
        path_segments: parse_path(kernel_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    let kernel_mode = S_IFDIR as u16 | 0o755;
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.mkdir(dentry.clone(), kernel_mode);
        }
        Err(e) => {
            panic!("create {} failed: {:?}", kernel_path, e);
        }
    };
    let taint_path = "/proc/sys/kernel/tainted";
    let mut nd = Nameidata {
        path_segments: parse_path(taint_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    let taint_mode = S_IFREG as u16 | 0o444;
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.create(dentry.clone(), taint_mode);
            // 现在dentry的inode指向/proc/sys/kernel/tainted
            let taint_file = TaintedFile::new(
                Path::new(root_path.mnt.clone(), dentry.clone()),
                dentry.get_inode().clone(),
                // ReadOnly
                OpenFlags::empty(),
            );
            TAINTED.call_once(|| taint_file.clone());
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            panic!("create {} failed: {:?}", taint_path, e);
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
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            panic!("create {} failed: {:?}", mounts_path, e);
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
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            panic!("create {} failed: {:?}", mounts_path, e);
        }
    };
    // /proc/self/exe
    // /proc/self
    let self_path = "/proc/self";
    let mut nd = Nameidata {
        path_segments: parse_path(self_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    let self_mode = S_IFDIR as u16 | 0o755;
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.mkdir(dentry, self_mode);
        }
        Err(e) => {
            panic!("create {} failed: {:?}", self_path, e);
        }
    };
    // /proc/self/exe
    let exe_path = "/proc/self/exe";
    let exe_mode = S_IFLNK as u16 | 0o444;
    nd = Nameidata {
        path_segments: parse_path(exe_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.create(dentry.clone(), exe_mode);
            *dentry.flags.write() = dentry::DentryFlags::DCACHE_SYMLINK_TYPE; // 设置为符号链接类型
            let exe_inode = ExeInode::new(Ext4InodeDisk::default());
            dentry.inner.lock().inode.replace(exe_inode.clone());

            // 现在dentry的inode指向/proc/self/exe
            let exe_file = ExeFile::new(
                Path::new(root_path.mnt.clone(), dentry.clone()),
                exe_inode,
                OpenFlags::empty(),
            );
            EXE.call_once(|| exe_file.clone());
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            panic!("create {} failed: {:?}", exe_path, e);
        }
    }
    // /proc/self/fd
    let fd_path = "/proc/self/fd";
    let fd_mode = S_IFDIR as u16 | 0o755;
    nd = Nameidata {
        path_segments: parse_path(fd_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.create(dentry.clone(), fd_mode);
            // 现在dentry的inode指向/proc/self/fd
            let fd_inode = FdDirInode::new(Ext4InodeDisk::default());
            dentry.inner.lock().inode.replace(fd_inode.clone());
            let fd_file = fd::FdFile::new(
                Path::new(root_path.mnt.clone(), dentry.clone()),
                fd_inode,
                OpenFlags::empty(),
            );
            fd::FD_FILE.call_once(|| fd_file.clone());
            insert_core_dentry(dentry);
        }
        Err(e) => {
            panic!("create {} failed: {:?}", fd_path, e);
        }
    };
    // /proc/self/maps
    let maps_path = "/proc/self/maps";
    let maps_mode = S_IFREG as u16 | 0o444;
    nd = Nameidata {
        path_segments: parse_path(maps_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.create(dentry.clone(), maps_mode);
            // 现在dentry的inode指向/proc/self/maps
            let maps_file = maps::MapsFile::new(
                Path::new(root_path.mnt.clone(), dentry.clone()),
                dentry.get_inode().clone(),
                OpenFlags::empty(),
            );
            maps::MAPS.call_once(|| maps_file.clone());
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            panic!("create {} failed: {:?}", maps_path, e);
        }
    }
    // /proc/self/pagemap
    let pagemap_path = "/proc/self/pagemap";
    let pagemap_mode = S_IFREG as u16 | 0o444;
    nd = Nameidata {
        path_segments: parse_path(pagemap_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.create(dentry.clone(), pagemap_mode);
            // 现在dentry的inode指向/proc/self/pagemap
            let pagemap_file = pagemap::PageMapFile::new(
                Path::new(root_path.mnt.clone(), dentry.clone()),
                dentry.get_inode().clone(),
                OpenFlags::empty(),
            );
            pagemap::PAGEMAP.call_once(|| pagemap_file.clone());
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            panic!("create {} failed: {:?}", pagemap_path, e);
        }
    }
    // /proc/self/status
    let status_path = "/proc/self/status";
    let status_mode = S_IFREG as u16 | 0o444;
    nd = Nameidata {
        path_segments: parse_path(status_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.create(dentry.clone(), status_mode);
            // 现在dentry的inode指向/proc/self/status
            let status_file = status::StatusFile::new(
                Path::new(root_path.mnt.clone(), dentry.clone()),
                dentry.get_inode().clone(),
                OpenFlags::empty(),
            );
            status::STATUS.call_once(|| status_file.clone());
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            panic!("create {} failed: {:?}", status_path, e);
        }
    }

    // /proc/pid
    let pid_path = "/proc/pid";
    let mut nd = Nameidata {
        path_segments: parse_path(pid_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    let pid_mode = S_IFDIR as u16 | 0o755;
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.mkdir(dentry, pid_mode);
        }
        Err(e) => {
            panic!("create {} failed: {:?}", pid_path, e);
        }
    };
    // /proc/pid/stat
    let pid_stat_path = "/proc/pid/stat";
    let pid_stat_mode = S_IFREG as u16 | 0o444;
    nd = Nameidata {
        path_segments: parse_path(pid_stat_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.create(dentry.clone(), pid_stat_mode);
            // 现在dentry的inode指向/proc/pid/stat
            let pid_stat_file = pid::PidStatFile::new(
                Path::new(root_path.mnt.clone(), dentry.clone()),
                dentry.get_inode().clone(),
                OpenFlags::empty(),
            );
            pid::PID_STAT.call_once(|| pid_stat_file.clone());
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            panic!("create {} failed: {:?}", pid_stat_path, e);
        }
    }
}

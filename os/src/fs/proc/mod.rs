use crate::{
    ext4::inode::{Ext4InodeDisk, S_IFCHR, S_IFDIR, S_IFLNK, S_IFREG},
    fs::proc::{
        cpuinfo::{CPUInfoFile, CPUINFO},
        pid_max::{PidMaxFile, PIDMAX},
    },
};

use super::{
    dentry::{self, insert_core_dentry, Dentry},
    file::OpenFlags,
    mount::VfsMount,
    namei::{filename_create, parse_path_uncheck, path_openat, Nameidata},
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

pub mod cpuinfo;
pub mod exe;
pub mod fd;
pub mod maps;
pub mod meminfo;
pub mod mounts;
pub mod pagemap;
pub mod pid;
pub mod pid_max;
pub mod smaps;
pub mod status;
pub mod tainted;

pub fn init_procfs(root_path: Arc<Path>) {
    let proc_path = "/proc";
    // let mut nd = Nameidata::new(proc_path, AT_FDCWD);
    let mut nd = Nameidata {
        path_segments: parse_path_uncheck(proc_path),
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
        path_segments: parse_path_uncheck(sys_path),
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
    let fs_path = "/proc/sys/fs";
    let mut nd = Nameidata {
        path_segments: parse_path_uncheck(fs_path),
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
            panic!("create {} failed: {:?}", fs_path, e);
        }
    };
    let pipe_max_size_path = "/proc/sys/fs/pipe-max-size";
    let mut nd = Nameidata {
        path_segments: parse_path_uncheck(pipe_max_size_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    let pipe_max_size_mode = S_IFREG as u16 | 0o444;
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.create(dentry.clone(), pipe_max_size_mode);
            // 现在dentry的inode指向/proc/sys/kernel/pipe_max_size
            dentry.get_inode().write(0, b"4096"); // 设置默认的管道最大大小为4096字节
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            panic!("create {} failed: {:?}", pipe_max_size_path, e);
        }
    };
    let kernel_path = "/proc/sys/kernel";
    let mut nd = Nameidata {
        path_segments: parse_path_uncheck(kernel_path),
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
    let domain_path = "/proc/sys/kernel/domainname";
    let mut nd = Nameidata {
        path_segments: parse_path_uncheck(domain_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    let domain_mode = S_IFREG as u16 | 0o444;
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.create(dentry.clone(), domain_mode);
            dentry.get_inode().write(0, b"localdomain"); // 设置默认的域名为"localdomain"
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            panic!("create {} failed: {:?}", domain_path, e);
        }
    };

    let taint_path = "/proc/sys/kernel/tainted";
    let mut nd = Nameidata {
        path_segments: parse_path_uncheck(taint_path),
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
    let osrelease_path = "/proc/sys/kernel/osrelease";
    let osrelease_mode = S_IFREG as u16 | 0o444;
    let mut nd = Nameidata {
        path_segments: parse_path_uncheck(osrelease_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.create(dentry.clone(), osrelease_mode);
            // 现在dentry的inode指向/proc/sys/kernel/osrelease
            let inode = dentry.get_inode();
            let buf = b"6.6.87.1-microsoft-standard-WSL2";
            inode.write(0, buf);
        }
        Err(e) => {
            panic!("create {} failed: {:?}", osrelease_path, e);
        }
    }
    let pid_max_path = "/proc/sys/kernel/pid_max";
    let pid_max_mode = S_IFREG as u16 | 0o444;
    nd = Nameidata {
        path_segments: parse_path_uncheck(pid_max_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.create(dentry.clone(), pid_max_mode);
            // 现在dentry的inode指向/proc/sys/kernel/pid_max
            let pid_max_file = PidMaxFile::new(
                Path::new(root_path.mnt.clone(), dentry.clone()),
                dentry.get_inode().clone(),
                // ReadOnly
                OpenFlags::empty(),
            );
            PIDMAX.call_once(|| pid_max_file.clone());
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            panic!("create {} failed: {:?}", pid_max_path, e);
        }
    };
    // /proc/mounts
    // 只读, 虚拟文件
    let mounts_path = "/proc/mounts";
    let mounts_mode = S_IFREG as u16 | 0o444;
    nd = Nameidata {
        path_segments: parse_path_uncheck(mounts_path),
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
        path_segments: parse_path_uncheck(meminfo_path),
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
            panic!("create {} failed: {:?}", meminfo_path, e);
        }
    };
    // /proc/self/exe
    // /proc/self
    let self_path = "/proc/self";
    let mut nd = Nameidata {
        path_segments: parse_path_uncheck(self_path),
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
        path_segments: parse_path_uncheck(exe_path),
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
        path_segments: parse_path_uncheck(fd_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.mkdir(dentry.clone(), fd_mode);
            let mut inode_on_disk = Ext4InodeDisk::default();
            inode_on_disk.set_mode(fd_mode);
            dentry
                .flags
                .write()
                .insert(dentry::DentryFlags::DCACHE_DIRECTORY_TYPE); // 设置为目录类型
                                                                     // 现在dentry的inode指向/proc/self/fd
            let fd_inode = FdDirInode::new(inode_on_disk);
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
    let maps_mode = S_IFREG as u16 | 0o744;
    nd = Nameidata {
        path_segments: parse_path_uncheck(maps_path),
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
    // /proc/self/smaps
    let smaps_path = "/proc/self/smaps";
    let smaps_mode = S_IFREG as u16 | 0o444;
    nd = Nameidata {
        path_segments: parse_path_uncheck(smaps_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.create(dentry.clone(), smaps_mode);
            // 现在dentry的inode指向/proc/self/smaps
            let smaps_file = smaps::SMapsFile::new(
                Path::new(root_path.mnt.clone(), dentry.clone()),
                dentry.get_inode().clone(),
                OpenFlags::empty(),
            );
            smaps::SMAPS.call_once(|| smaps_file.clone());
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            panic!("create {} failed: {:?}", smaps_path, e);
        }
    }
    // /proc/self/pagemap
    let pagemap_path = "/proc/self/pagemap";
    let pagemap_mode = S_IFREG as u16 | 0o444;
    nd = Nameidata {
        path_segments: parse_path_uncheck(pagemap_path),
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
        path_segments: parse_path_uncheck(status_path),
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
        path_segments: parse_path_uncheck(pid_path),
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
        path_segments: parse_path_uncheck(pid_stat_path),
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
    // /proc/cpuinfo
    // 只读, 虚拟文件
    let cpuinfo_path = "/proc/cpuinfo";
    let cpuinfo_mode = S_IFREG as u16 | 0o444;
    nd = Nameidata {
        path_segments: parse_path_uncheck(cpuinfo_path),
        dentry: root_path.dentry.clone(),
        mnt: root_path.mnt.clone(),
        depth: 0,
    };
    match filename_create(&mut nd, 0) {
        Ok(dentry) => {
            let parent_inode = nd.dentry.get_inode();
            parent_inode.create(dentry.clone(), cpuinfo_mode);
            // 现在dentry的inode指向/proc/cpuinfo
            let cpuinfo_file = CPUInfoFile::new(
                Path::new(root_path.mnt.clone(), dentry.clone()),
                dentry.get_inode().clone(),
                // ReadOnly
                OpenFlags::empty(),
            );
            CPUINFO.call_once(|| cpuinfo_file.clone());
            insert_core_dentry(dentry.clone());
        }
        Err(e) => {
            panic!("create {} failed: {:?}", mounts_path, e);
        }
    };
}

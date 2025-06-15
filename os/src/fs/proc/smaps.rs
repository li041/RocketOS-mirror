use core::{default, fmt::Write, mem, str};

use lazy_static::lazy_static;
use spin::{lazy, mutex, Once, RwLock};

use crate::{
    arch::config::PAGE_SIZE_BITS,
    ext4::inode::Ext4InodeDisk,
    fs::{
        file::{FileOp, OpenFlags},
        inode::InodeOp,
        kstat::Kstat,
        path::Path,
        uapi::Whence,
        FileOld,
    },
    mm::MapPermission,
    syscall::errno::{Errno, SyscallRet},
    task::current_task,
    timer::TimeSpec,
};

use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
};

pub static SMAPS: Once<Arc<dyn FileOp>> = Once::new();

pub struct SMapsInode {
    pub inner: RwLock<SMapsInodeInner>,
}
pub struct SMapsInodeInner {
    pub inode_on_disk: Ext4InodeDisk,
}

impl SMapsInode {
    pub fn new(inode_on_disk: Ext4InodeDisk) -> Arc<Self> {
        Arc::new(SMapsInode {
            inner: RwLock::new(SMapsInodeInner { inode_on_disk }),
        })
    }
}

impl InodeOp for SMapsInode {
    fn getattr(&self) -> Kstat {
        let mut kstat = Kstat::new();
        let inner_guard = self.inner.read();
        let inode_on_disk = &inner_guard.inode_on_disk;

        kstat.mode = inode_on_disk.get_mode();
        kstat.uid = inode_on_disk.get_uid() as u32;
        kstat.gid = inode_on_disk.get_gid() as u32;
        kstat.nlink = inode_on_disk.get_nlinks() as u32;
        kstat.size = inode_on_disk.get_size();

        // Todo: 目前没有更新时间戳
        kstat.atime = inode_on_disk.get_atime();
        kstat.mtime = inode_on_disk.get_mtime();
        kstat.ctime = inode_on_disk.get_ctime();
        // Todo: 创建时间
        // kstat.btime = TimeSpec {
        //     sec: inode_on_disk.create_time as usize,
        //     nsec: (inode_on_disk.create_time_extra >> 2) as usize,
        // };
        // Todo: Direct I/O 对齐参数
        // inode版本号
        kstat.change_cookie = inode_on_disk.generation as u64;

        kstat
    }
    fn get_resident_page_count(&self) -> usize {
        0
    }

    /* get/set属性方法 */
    // Todo
    fn get_mode(&self) -> u16 {
        self.inner.read().inode_on_disk.get_mode()
    }
    /* 时间戳 */
    fn get_atime(&self) -> TimeSpec {
        self.inner.read().inode_on_disk.get_atime()
    }
    fn set_atime(&self, atime: TimeSpec) {
        self.inner.write().inode_on_disk.set_atime(atime);
    }
    fn get_mtime(&self) -> TimeSpec {
        self.inner.read().inode_on_disk.get_mtime()
    }
    fn set_mtime(&self, mtime: TimeSpec) {
        self.inner.write().inode_on_disk.set_mtime(mtime);
    }
    fn get_ctime(&self) -> TimeSpec {
        self.inner.read().inode_on_disk.get_ctime()
    }
    fn set_ctime(&self, ctime: TimeSpec) {
        self.inner.write().inode_on_disk.set_ctime(ctime);
    }
    fn set_mode(&self, mode: u16) {
        self.inner.write().inode_on_disk.set_mode(mode);
    }
}

pub struct SMapsFile {
    pub path: Arc<Path>,
    pub inode: Arc<dyn InodeOp>,
    pub flags: OpenFlags,
    pub inner: RwLock<SMapsFileInner>,
}

pub struct SMapsFileInner {
    pub offset: usize,
}

impl SMapsFile {
    pub fn new(path: Arc<Path>, inode: Arc<dyn InodeOp>, flags: OpenFlags) -> Arc<Self> {
        Arc::new(SMapsFile {
            path,
            inode,
            flags,
            inner: RwLock::new(SMapsFileInner { offset: 0 }),
        })
    }
    pub fn get_smaps(&self) -> String {
        let mut result = String::new();
        let task = current_task();

        task.op_memory_set(|mm| {
            let areas = &mm.areas;
            for (vpn, area) in areas.iter() {
                let start_va = vpn.0 << PAGE_SIZE_BITS;
                let end_va = area.vpn_range.get_end().0 << PAGE_SIZE_BITS;
                // let perms = area.perm.to_string(); // e.g., "rwxp"
                let perms = {
                    let mut s = String::new();
                    s.push(if area.map_perm.contains(MapPermission::R) {
                        'r'
                    } else {
                        '-'
                    });
                    s.push(if area.map_perm.contains(MapPermission::W) {
                        'w'
                    } else {
                        '-'
                    });
                    s.push(if area.map_perm.contains(MapPermission::X) {
                        'x'
                    } else {
                        '-'
                    });
                    s.push(if area.map_perm.contains(MapPermission::S) {
                        's'
                    } else {
                        'p'
                    });
                    s
                };
                // let file = if let Some(file) = &area.backend_file {
                //     let path = file.get_path().dentry.absolute_path;
                //     path
                // } else {
                //     "[anon]".to_string()
                // };
                let file = "fake";
                // 基础映射行
                writeln!(
                    result,
                    "{:08x}-{:08x} {:<4} 00000000 00:00 0     {}",
                    start_va, end_va, perms, file
                )
                .unwrap();

                // 模拟一些字段，后面可以扩展为实际物理页框状态统计
                // let size_kb = area.len / 1024;
                // writeln!(result, "Size:               {:>5} kB", size_kb).unwrap();
                // writeln!(result, "Rss:                {:>5} kB", 0).unwrap(); // 可填 page_table.query_rss(&area)
                // writeln!(result, "Pss:                {:>5} kB", 0).unwrap();
                // writeln!(result, "Shared_Clean:       {:>5} kB", 0).unwrap();
                // writeln!(result, "Shared_Dirty:       {:>5} kB", 0).unwrap();
                // writeln!(result, "Private_Clean:      {:>5} kB", 0).unwrap();
                // writeln!(result, "Private_Dirty:      {:>5} kB", 0).unwrap();
                // writeln!(result, "Referenced:         {:>5} kB", 0).unwrap();
                // writeln!(
                //     result,
                //     "Anonymous:          {:>5} kB",
                //     if area.file.is_none() { size_kb } else { 0 }
                // )
                // .unwrap();
                // writeln!(result, "VmFlags: {}", area.get_vmflags()).unwrap(); // 需要你实现 `get_vmflags()` 方法
                writeln!(result).unwrap(); // 空行分隔每个区域
            }
        });

        result
    }
}

impl FileOp for SMapsFile {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn get_inode(&self) -> Arc<dyn InodeOp> {
        self.inode.clone()
    }
    fn read(&self, buf: &mut [u8]) -> SyscallRet {
        let content = self.get_smaps();
        let bytes = content.as_bytes();
        let offset = self.inner.read().offset;
        let len = bytes.len();
        if offset >= len {
            return Ok(0);
        }

        let to_copy = buf.len().min(len - offset);
        buf[..to_copy].copy_from_slice(&bytes[offset..offset + to_copy]);
        // 更新偏移量
        self.inner.write().offset += to_copy;

        Ok(to_copy)
    }
    fn seek(&self, offset: isize, whence: Whence) -> SyscallRet {
        let mut inner_guard = self.inner.write();
        match whence {
            crate::fs::uapi::Whence::SeekSet => {
                if offset < 0 {
                    return Err(Errno::EINVAL);
                }
                inner_guard.offset = offset as usize;
            }
            crate::fs::uapi::Whence::SeekCur => {
                inner_guard.offset = inner_guard.offset.checked_add_signed(offset).unwrap()
            }
            crate::fs::uapi::Whence::SeekEnd => {
                let content = self.get_smaps();
                let len = content.len();
                inner_guard.offset = len.checked_add_signed(offset).unwrap();
            }
            _ => {
                return Err(Errno::EINVAL); // Invalid argument
            }
        }
        Ok(inner_guard.offset)
    }
    fn readable(&self) -> bool {
        true
    }
    fn get_flags(&self) -> OpenFlags {
        self.flags
    }
}

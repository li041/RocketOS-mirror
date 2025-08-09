use spin::{Once, RwLock};

use crate::{
    arch::config::PAGE_SIZE_BITS,
    ext4::inode::Ext4InodeDisk,
    fs::{
        file::{FileOp, OpenFlags},
        inode::InodeOp,
        kstat::Kstat,
        path::Path,
        uapi::Whence,
    },
    mm::MapPermission,
    syscall::errno::{Errno, SyscallRet},
    task::current_task,
    timer::TimeSpec,
};

use alloc::{format, string::String, sync::Arc};

pub static MAPS: Once<Arc<dyn FileOp>> = Once::new();

pub struct MapsInode {
    pub inner: RwLock<MapsInodeInner>,
}
pub struct MapsInodeInner {
    pub inode_on_disk: Ext4InodeDisk,
}

impl MapsInode {
    #[allow(unused)]
    pub fn new(inode_on_disk: Ext4InodeDisk) -> Arc<Self> {
        Arc::new(MapsInode {
            inner: RwLock::new(MapsInodeInner { inode_on_disk }),
        })
    }
}

impl InodeOp for MapsInode {
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

#[allow(unused)]
pub struct MapsFile {
    pub path: Arc<Path>,
    pub inode: Arc<dyn InodeOp>,
    pub flags: OpenFlags,
    pub inner: RwLock<MapsFileInner>,
}

pub struct MapsFileInner {
    pub offset: usize,
}

impl MapsFile {
    pub fn new(path: Arc<Path>, inode: Arc<dyn InodeOp>, flags: OpenFlags) -> Arc<Self> {
        Arc::new(MapsFile {
            path,
            inode,
            flags,
            inner: RwLock::new(MapsFileInner { offset: 0 }),
        })
    }
    pub fn get_maps(&self) -> String {
        let task = current_task();
        let mut content = String::new();
        task.op_memory_set(|memory| {
            for (_, area) in memory.areas.iter() {
                let start_va = area.vpn_range.get_start().0 << PAGE_SIZE_BITS;
                let end_va = area.vpn_range.get_end().0 << PAGE_SIZE_BITS;
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
                let offset = area.offset;
                // 设备号(主次设备号), inode , 文件名暂时伪造
                let dev = "00:00";
                let inode = 0;

                let pathname = String::from("");

                content.push_str(&format!(
                    "{:08x}-{:08x} {:4} {:08x} {:5} {:5} {}\n",
                    start_va, end_va, perms, offset, dev, inode, pathname
                ));
            }
        });
        content
    }
}

impl FileOp for MapsFile {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn get_inode(&self) -> Arc<dyn InodeOp> {
        self.inode.clone()
    }
    fn read(&self, buf: &mut [u8]) -> SyscallRet {
        let content = self.get_maps();
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
                let content = self.get_maps();
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
    fn writable(&self) -> bool {
        false
    }
    fn get_flags(&self) -> OpenFlags {
        self.flags
    }
}

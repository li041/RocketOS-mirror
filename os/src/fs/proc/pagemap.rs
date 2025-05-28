use core::{default, mem, str};

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
    mm::{MapPermission, VPNRange, VirtPageNum},
    syscall::errno::{Errno, SyscallRet},
    task::current_task,
    timer::TimeSpec,
};

use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

pub static PAGEMAP: Once<Arc<dyn FileOp>> = Once::new();

pub struct PageMapInode {
    pub inner: RwLock<PageMapInodeInner>,
}
pub struct PageMapInodeInner {
    pub inode_on_disk: Ext4InodeDisk,
}

impl PageMapInode {
    pub fn new(inode_on_disk: Ext4InodeDisk) -> Arc<Self> {
        Arc::new(PageMapInode {
            inner: RwLock::new(PageMapInodeInner { inode_on_disk }),
        })
    }
}

impl InodeOp for PageMapInode {
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
}

pub struct PageMapFile {
    pub path: Arc<Path>,
    pub inode: Arc<dyn InodeOp>,
    pub flags: OpenFlags,
    pub inner: RwLock<MapsFileInner>,
}

pub struct MapsFileInner {
    pub offset: usize,
}

impl PageMapFile {
    pub fn new(path: Arc<Path>, inode: Arc<dyn InodeOp>, flags: OpenFlags) -> Arc<Self> {
        Arc::new(PageMapFile {
            path,
            inode,
            flags,
            inner: RwLock::new(MapsFileInner { offset: 0 }),
        })
    }
    pub fn get_pagemap(&self, buf: &mut [u8], start_vpn: VirtPageNum) -> usize {
        // let task = current_task();
        // let mut ret = Vec::new();
        // task.op_memory_set(|mm| {
        //     for (_area_start_vpn, area) in mm.areas.iter() {
        //         for (_vpn, page) in area.pages.iter() {
        //             let mut entry: u64 = 0;
        //             entry |= 1 << 63; //  标记为存在
        //             entry |= page.ppn().0 as u64; // 页帧号
        //             ret.extend_from_slice(&entry.to_le_bytes());
        //             // 其他字段可以根据需要添加
        //         }
        //     }
        // });
        let task = current_task();
        let count = buf.len() / 8; // 每个虚拟页对应8个字节
        let vpn_end = VirtPageNum(start_vpn.0 + count);
        let vpn_range = VPNRange::new(start_vpn, vpn_end);
        // 字节为单位
        let mut copied = 0;
        task.op_memory_set(|mm| {
            for vpn in vpn_range {
                let mut entry_value: u64 = 0;
                if let Some(pte) = mm.page_table.find_pte(vpn) {
                    // 标记为存在
                    entry_value |= 1 << 63;
                    // 页帧号
                    entry_value |= pte.ppn().0 as u64;
                    // 其他字段可以根据需要添加
                }
                // 将entry_value转换为字节并存储到buf中
                let entry_bytes = entry_value.to_le_bytes();
                if copied < count * 8 {
                    let to_copy = buf.len().min(copied + 8);
                    buf[copied..to_copy].copy_from_slice(&entry_bytes[..to_copy - copied]);
                    copied += 8;
                } else {
                    break; // 如果buf已满，退出循环
                }
            }
        });
        return copied;
    }
}

impl FileOp for PageMapFile {
    fn get_inode(&self) -> Arc<dyn InodeOp> {
        self.inode.clone()
    }
    // 对于/proc/[pid]/pagemap文件，每8个字节对应一个虚拟页
    // 读取count字节表示请求`buf.len() / 8`个虚拟页的映射信息
    // 文件偏移量决定起始虚拟地址(offset / 8 * PAGE_SIZE)，
    fn read(&self, buf: &mut [u8]) -> SyscallRet {
        let offset = self.inner.read().offset;
        // 5.28
        log::warn!(
            "[pagemap] read offset: {:#x}, buf len: {}",
            offset,
            buf.len()
        );
        let start_vpn = VirtPageNum(offset / 8);
        Ok(self.get_pagemap(buf, start_vpn))
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
                unimplemented!("SeekEnd is not supported for pagemap");
                // let content = self.get_pagemap();
                // let len = content.len();
                // inner_guard.offset = len.checked_add_signed(offset).unwrap();
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

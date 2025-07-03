use core::{default, str};

use lazy_static::lazy_static;
use spin::{lazy, mutex, Once, RwLock};

use crate::{
    ext4::inode::Ext4InodeDisk,
    fs::{
        file::{FileOp, OpenFlags},
        inode::InodeOp,
        kstat::Kstat,
        path::Path,
        proc,
        uapi::Whence,
        FileOld,
    },
    syscall::errno::{Errno, SyscallRet},
    timer::TimeSpec,
};

use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};

pub static CPUINFO: Once<Arc<dyn FileOp>> = Once::new();

pub struct CPUInfoInode {
    pub inner: RwLock<CPUInfoInodeInner>,
}

pub struct CPUInfoInodeInner {
    pub inode_on_disk: Ext4InodeDisk,
}

impl CPUInfoInode {
    pub fn new(inode_on_disk: Ext4InodeDisk) -> Arc<Self> {
        Arc::new(CPUInfoInode {
            inner: RwLock::new(CPUInfoInodeInner { inode_on_disk }),
        })
    }
}

impl InodeOp for CPUInfoInode {
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

pub struct CPUInfoFile {
    pub path: Arc<Path>,
    pub inode: Arc<dyn InodeOp>,
    pub flags: OpenFlags,
    pub inner: RwLock<CPUInfoFileInner>,
}

#[derive(Default)]
pub struct CPUInfoFileInner {
    pub offset: usize,
}

impl CPUInfoFile {
    pub fn new(path: Arc<Path>, inode: Arc<dyn InodeOp>, flags: OpenFlags) -> Arc<Self> {
        Arc::new(CPUInfoFile {
            path,
            inode,
            flags,
            inner: RwLock::new(CPUInfoFileInner::default()),
        })
    }
    pub fn add_offset(&self, offset: usize) {
        self.inner.write().offset += offset;
    }
}

impl FileOp for CPUInfoFile {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn read(&self, buf: &mut [u8]) -> SyscallRet {
        let info = FAKECPUInfo.read().serialize();
        let len = info.len();
        if self.inner.read().offset >= len {
            return Ok(0);
        }
        buf[..len].copy_from_slice(info.as_bytes());
        self.add_offset(len);
        Ok(len)
    }
    fn readable(&self) -> bool {
        true
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
                inner_guard.offset = FAKECPUInfo
                    .read()
                    .serialize()
                    .len()
                    .checked_add_signed(offset)
                    .unwrap();
            }
            _ => {
                log::warn!("[CPUInfoFile::seek] Unsupported whence: {:?}", whence);
                return Err(Errno::EINVAL); // Invalid argument
            }
        }
        Ok(inner_guard.offset)
    }
    fn get_inode(&self) -> Arc<dyn InodeOp> {
        self.inode.clone()
    }
    fn get_flags(&self) -> OpenFlags {
        self.flags
    }
}

lazy_static! {
    static ref FAKECPUInfo: RwLock<FakeCPUInfo> = RwLock::new(FakeCPUInfo::new());
}

struct FakeCPUInfo {
    pub processor: usize,
    pub vendor_id: String,
    pub cpu_family: usize,
    pub model: usize,
    pub model_name: String,
    pub stepping: usize,
    pub microcode: String,
    pub cpu_mhz: usize,
    pub cache_size: usize,
    pub physical_id: usize,
    pub siblings: usize,
    pub core_id: usize,
    pub cpu_cores: usize,
    pub apicid: usize,
    pub initial_apicid: usize,
    pub fpu: String,
    pub fpu_exception: String,
    pub cpuid_level: usize,
    pub wp: String,
    pub flags: Vec<String>,
    pub bugs: Vec<String>,
    pub bogomips: usize,
    pub clflush_size: usize,
    pub cache_alignment: usize,
    pub address_sizes: String,
    pub power_management: String,
}
impl FakeCPUInfo {
    pub fn new() -> Self {
        Self {
            processor: 0,
            vendor_id: "GenuineIntel".to_string(),
            cpu_family: 6,
            model: 154,
            model_name: "12th Gen Intel(R) Core(TM) i7-12700H".to_string(),
            stepping: 3,
            microcode: "0xffffffff".to_string(),
            cpu_mhz: 2688,
            cache_size: 8192,
            physical_id: 0,
            siblings: 4,
            core_id: 0,
            cpu_cores: 2,
            apicid: 0,
            initial_apicid: 0,
            fpu: "yes".to_string(),
            fpu_exception: "yes".to_string(),
            cpuid_level: 28,
            wp: "yes".to_string(),
            // 没写全
            flags: vec![
                "fpu".to_string(),
                "vme".to_string(),
                "de".to_string(),
                "pse".to_string(),
                "tsc".to_string(),
                "msr".to_string(),
                "pae".to_string(),
                "mce".to_string(),
                "cx8".to_string(),
                "apic".to_string(),
                "sep".to_string(),
                "mtrr".to_string(),
                "pge".to_string(),
                "mca".to_string(),
                "cmov".to_string(),
                "pat".to_string(),
                "pse36".to_string(),
                "clflush".to_string(),
                "mmx".to_string(),
                "fxsr".to_string(),
                "sse".to_string(),
                "sse2".to_string(),
                "ss".to_string(),
                "ht".to_string(),
                "syscall".to_string(),
                "nx".to_string(),
                "pdpe1gb".to_string(),
                "rdtscp".to_string(),
                "lm".to_string(),
                "constant_tsc".to_string(),
                "arch_perfmon".to_string(),
            ],
            bugs: vec![
                "spectre_v1".to_string(),
                "spectre_v2".to_string(),
                "spec_store_bypass".to_string(),
                "swapgs".to_string(),
                "retbleed".to_string(),
                "eibrs_pbrsb".to_string(),
                "rfds".to_string(),
                "bhi".to_string(),
            ],
            bogomips: 5375,
            clflush_size: 64,
            cache_alignment: 64,
            address_sizes: "39 bits physical, 48 bits virtual".to_string(),
            power_management: "".to_string(),
        }
    }
    pub fn serialize(&self) -> String {
        let mut result = String::new();

        // 基本信息
        result.push_str("processor: ");
        result.push_str(&self.processor.to_string());
        result.push('\n');
        result.push_str("vendor_id: ");
        result.push_str(&self.vendor_id);
        result.push('\n');
        result.push_str("cpu_family: ");
        result.push_str(&self.cpu_family.to_string());
        result.push('\n');
        result.push_str("model: ");
        result.push_str(&self.model.to_string());
        result.push('\n');
        result.push_str("model_name: ");
        result.push_str(&self.model_name);
        result.push('\n');
        result.push_str("stepping: ");
        result.push_str(&self.stepping.to_string());
        result.push('\n');
        result.push_str("microcode: ");
        result.push_str(&self.microcode);
        result.push('\n');
        result.push_str("cpu_mhz: ");
        result.push_str(&self.cpu_mhz.to_string());
        result.push('\n');
        result.push_str("cache_size: ");
        result.push_str(&self.cache_size.to_string());
        result.push('\n');
        result.push_str("physical_id: ");
        result.push_str(&self.physical_id.to_string());
        result.push('\n');
        result.push_str("siblings: ");
        result.push_str(&self.siblings.to_string());
        result.push('\n');
        result.push_str("core_id: ");
        result.push_str(&self.core_id.to_string());
        result.push('\n');
        result.push_str("cpu_cores: ");
        result.push_str(&self.cpu_cores.to_string());
        result.push('\n');
        result.push_str("apicid: ");
        result.push_str(&self.apicid.to_string());
        result.push('\n');
        result.push_str("initial_apicid: ");
        result.push_str(&self.initial_apicid.to_string());
        result.push('\n');
        result.push_str("fpu: ");
        result.push_str(&self.fpu);
        result.push('\n');
        result.push_str("fpu_exception: ");
        result.push_str(&self.fpu_exception);
        result.push('\n');
        result.push_str("cpuid_level: ");
        result.push_str(&self.cpuid_level.to_string());
        result.push('\n');
        result.push_str("wp: ");
        result.push_str(&self.wp);
        result.push('\n');

        // flags
        result.push_str("flags: [");
        for (i, flag) in self.flags.iter().enumerate() {
            result.push_str(flag);
            if i != self.flags.len() - 1 {
                result.push_str(", ");
            }
        }
        result.push_str("]\n");

        // bugs
        result.push_str("bugs: [");
        for (i, bug) in self.bugs.iter().enumerate() {
            result.push_str(bug);
            if i != self.bugs.len() - 1 {
                result.push_str(", ");
            }
        }
        result.push_str("]\n");

        // 其他字段
        result.push_str("bogomips: ");
        result.push_str(&self.bogomips.to_string());
        result.push('\n');
        result.push_str("clflush_size: ");
        result.push_str(&self.clflush_size.to_string());
        result.push('\n');
        result.push_str("cache_alignment: ");
        result.push_str(&self.cache_alignment.to_string());
        result.push('\n');
        result.push_str("address_sizes: ");
        result.push_str(&self.address_sizes);
        result.push('\n');
        result.push_str("power_management: ");
        result.push_str(&self.power_management);
        result.push('\n');

        result
    }
}

use core::fmt::Debug;

use alloc::{collections::btree_map::BTreeMap, vec::Vec};
use spin::RwLock;

use crate::{fs::file::FileOp, syscall::errno::Errno};

#[derive(Debug)]
pub struct BpfMap {
    map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    max_entries: u32,
    pub data: RwLock<BTreeMap<Vec<u8>, Vec<u8>>>, // key/value 用 Vec<u8> 表示任意类型
}

impl Drop for BpfMap {
    fn drop(&mut self) {
        log::info!(
            "[BpfMap::Drop] Dropping BpfMap with type: {}, key_size: {}, value_size: {}, max_entries: {}",
            self.map_type,
            self.key_size,
            self.value_size,
            self.max_entries
        );
        // 清理数据
        let mut data = self.data.write();
        for (key, value) in data.iter() {
            log::info!("[BpfMap::Drop] Clearing key: {:?}, value: {:?}", key, value);
        }
        data.clear();
        log::info!("[BpfMap] BpfMap dropped and data cleared.");
    }
}

impl FileOp for BpfMap {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl BpfMap {
    pub fn new(map_type: u32, key_size: u32, value_size: u32, max_entries: u32) -> Self {
        BpfMap {
            map_type,
            key_size,
            value_size,
            max_entries,
            data: RwLock::new(BTreeMap::new()),
        }
    }
    #[allow(unused)]
    pub fn lookup(&self, key_ptr: usize) -> Option<Vec<u8>> {
        let key_size = self.key_size as usize;
        let key_buf = unsafe { core::slice::from_raw_parts(key_ptr as *const u8, key_size) };
        let key_vec = Vec::from(key_buf);
        self.data.read().get(&key_vec).cloned()
    }
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.data.read().get(key).cloned()
    }
}

#[repr(u32)]
#[derive(Debug)]
pub enum BpfMapType {
    Unspec = 0,
    Hash,
    Array,
    ProgArray,
    PerfEventArray,
    PerCpuHash,
    PerCpuArray,
    StackTrace,
    CgroupArray,
    LruHash,
    LruPerCpuHash,
    LpmTrie,
    ArrayOfMaps,
    HashOfMaps,
    DevMap,
    SockMap,
    CpuMap,
    XskMap,
    SockHash,
    // ...
}

impl TryFrom<u32> for BpfMapType {
    type Error = Errno;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(BpfMapType::Unspec),
            1 => Ok(BpfMapType::Hash),
            2 => Ok(BpfMapType::Array),
            3 => Ok(BpfMapType::ProgArray),
            4 => Ok(BpfMapType::PerfEventArray),
            5 => Ok(BpfMapType::PerCpuHash),
            6 => Ok(BpfMapType::PerCpuArray),
            7 => Ok(BpfMapType::StackTrace),
            8 => Ok(BpfMapType::CgroupArray),
            9 => Ok(BpfMapType::LruHash),
            10 => Ok(BpfMapType::LruPerCpuHash),
            11 => Ok(BpfMapType::LpmTrie),
            12 => Ok(BpfMapType::ArrayOfMaps),
            13 => Ok(BpfMapType::HashOfMaps),
            14 => Ok(BpfMapType::DevMap),
            15 => Ok(BpfMapType::SockMap),
            16 => Ok(BpfMapType::CpuMap),
            17 => Ok(BpfMapType::XskMap),
            18 => Ok(BpfMapType::SockHash),
            _ => Err(Errno::EINVAL), // 无效的map类型
        }
    }
}

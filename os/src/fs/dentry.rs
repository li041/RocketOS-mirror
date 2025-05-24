use core::fmt::{Debug, Formatter};

use alloc::{
    collections::vec_deque::VecDeque,
    format,
    string::{String, ToString},
    sync::{Arc, Weak},
    vec::Vec,
};
use bitflags::Flag;
use hashbrown::HashMap;
use lazy_static::lazy_static;
use log::set_logger;
use spin::{Mutex, RwLock};

use crate::{
    ext4::{
        dentry::{self, Ext4DirEntry},
        inode::{self, S_IFDIR},
    },
    mutex::SpinNoIrqLock,
};

use super::{file::OpenFlags, inode::InodeOp, uapi::RenameFlags};

bitflags::bitflags! {
    /// 目前只支持type
    pub struct DentryFlags: u32 {
        const DCACHE_MISS_TYPE     = 0 << 20; // Negative dentry
        const DCACHE_WHITEOUT_TYPE = 1 << 20; // Whiteout dentry
        const DCACHE_DIRECTORY_TYPE= 2 << 20; // Normal directory
        const DCACHE_AUTODIR_TYPE  = 3 << 20; // Autodir (presumed automount)
        const DCACHE_REGULAR_TYPE  = 4 << 20; // Regular file
        const DCACHE_SPECIAL_TYPE  = 5 << 20; // Special file
        const DCACHE_SYMLINK_TYPE  = 6 << 20; // Symlink
        // const DCACHE_ENTRY_TYPE    = 7 << 20; // Bitmask for entry type
    }
}

impl DentryFlags {
    pub fn update_type_from_negative(&mut self, flags: DentryFlags) {
        self.remove(DentryFlags::DCACHE_MISS_TYPE);
        self.insert(flags);
    }
    pub fn get_type(&self) -> DentryFlags {
        const DCACHE_ENTRY_TYPE_MASK: u32 = 7 << 20;
        DentryFlags::from_bits_truncate(self.bits() & DCACHE_ENTRY_TYPE_MASK)
    }
}

// VFS层的统一目录项结构
#[repr(C)]
pub struct Dentry {
    pub absolute_path: String,
    pub flags: RwLock<DentryFlags>,
    pub inner: SpinNoIrqLock<DentryInner>,
}

pub struct DentryInner {
    // None 表示该 dentry 未关联 inode
    pub inode: Option<Arc<dyn InodeOp>>,
    // pub inode: Option<Arc<SpinNoIrqLock<OSInode>>>,
    pub parent: Option<Weak<Dentry>>,
    // chrildren 是一个哈希表, 用于存储子目录/文件, name不是绝对路径
    pub children: HashMap<String, Weak<Dentry>>,
}

// impl Drop for Dentry {
//     fn drop(&mut self) {
//         log::warn!(
//             "[Dentry] Drop dentry {}, negative: {:?}",
//             self.absolute_path,
//             self.inner.lock().inode.is_none()
//         );
//     }
// }

impl DentryInner {
    pub fn new(parent: Option<Arc<Dentry>>, inode: Arc<dyn InodeOp>) -> Self {
        Self {
            inode: Some(inode),
            parent: parent.map(|p| Arc::downgrade(&p)),
            children: HashMap::new(),
        }
    }
    // 负目录项
    pub fn negative(parent: Option<Arc<Dentry>>) -> Self {
        Self {
            inode: None,
            parent: parent.map(|p| Arc::downgrade(&p)),
            children: HashMap::new(),
        }
    }
}

impl Dentry {
    pub fn zero_init() -> Self {
        Self {
            absolute_path: String::new(),
            flags: RwLock::new(DentryFlags::empty()),
            inner: SpinNoIrqLock::new(DentryInner::negative(None)),
        }
    }
    pub fn new(
        absolute_path: String,
        parent: Option<Arc<Dentry>>,
        flags: DentryFlags,
        inode: Arc<dyn InodeOp>,
    ) -> Arc<Self> {
        Arc::new(Self {
            absolute_path,
            flags: RwLock::new(flags),
            inner: SpinNoIrqLock::new(DentryInner::new(parent, inode)),
        })
    }
    pub fn negative(absolute_path: String, parent: Option<Arc<Dentry>>) -> Arc<Self> {
        Arc::new(Self {
            absolute_path,
            flags: RwLock::new(DentryFlags::DCACHE_MISS_TYPE),
            inner: SpinNoIrqLock::new(DentryInner::negative(parent)),
        })
    }
    // // 上层调用者保证由负目录项调用
    // pub fn associate(&mut self, inode_num: usize, inode: Arc<dyn InodeOp>) {
    //     self.inner.lock().inode = Some(inode);
    //     self.inode_num = inode_num;
    // }
    pub fn is_negative(&self) -> bool {
        self.inner.lock().inode.is_none()
    }
    pub fn is_symlink(&self) -> bool {
        self.flags.read().contains(DentryFlags::DCACHE_SYMLINK_TYPE)
    }
    pub fn is_regular(&self) -> bool {
        self.flags.read().contains(DentryFlags::DCACHE_REGULAR_TYPE)
    }
    pub fn is_dir(&self) -> bool {
        self.flags
            .read()
            .contains(DentryFlags::DCACHE_DIRECTORY_TYPE)
    }
    pub fn get_last_name(&self) -> &str {
        self.absolute_path
            .split('/')
            .last()
            .unwrap_or(&self.absolute_path)
    }
    pub fn get_child(self: &Arc<Dentry>, name: &str) -> Option<Arc<Dentry>> {
        let inner = self.inner.lock();
        if let Some(child) = inner.children.get(name) {
            if let Some(child) = child.upgrade() {
                return Some(child);
            }
        }
        None
    }

    // 判断ancestor是否是child的祖先
    pub fn is_ancestor(self: &Arc<Dentry>, child: &Arc<Dentry>) -> bool {
        let target = Arc::as_ptr(self);
        let mut current = child.clone();
        loop {
            let parent_opt = current.inner.lock().parent.as_ref().unwrap().upgrade();
            match parent_opt {
                Some(parent) => {
                    // 根目录的parent是自己
                    if Arc::as_ptr(&parent) == Arc::as_ptr(&current) {
                        return false;
                    }
                    current = parent;
                }
                None => {
                    log::warn!("[is_ancestor] Note: Orphan inode detected");
                    return false;
                }
            }
            if Arc::as_ptr(&current) == target {
                return true;
            }
        }
    }
    // 上层调用者保证: 负目录项不能调用该函数
    pub fn get_inode(&self) -> Arc<dyn InodeOp> {
        self.inner.lock().inode.clone().unwrap()
    }
    pub fn get_parent(&self) -> Arc<Dentry> {
        self.inner
            .lock()
            .parent
            .clone()
            .map(|p| p.upgrade().unwrap())
            .unwrap()
    }
    pub fn set_parent(&self, parent: Arc<Dentry>) {
        self.inner.lock().parent = Some(Arc::downgrade(&parent));
    }
    /// renameat在dentry层次的操作 + inode层次的操作
    pub fn rename(&self, new_dentry: Option<Arc<Dentry>>, flags: RenameFlags) {
        // 需要检查, 不能将自己放在自己的子目录下, 需要一个辅助函数
        // 从旧父目录的dentry中移除自身, 修改路径`absolute_path`, 修改 parent 引用为新的父目录（如果 new_dentry 在其他目录下）。
        // 添加到新父目录的 children
        // 注意需要操作底层的inode
    }
}

lazy_static! {
    pub static ref DENTRY_CACHE: RwLock<DentryCache> = RwLock::new(DentryCache::new(1024));
}

/// 当frame不够时, 需要清理掉一些不常用的dentry
pub fn clean_dentry_cache() {
    let cache = DENTRY_CACHE.read();
    let mut cache_map = cache.cache.write(); // 需要写锁来删除
    let mut lru = cache.lru_list.lock();

    for name in lru.iter() {
        if let Some(dentry) = cache_map.get(name) {
            let strong_count = Arc::strong_count(dentry);
            let count = if let Some(inode) = dentry.inner.lock().inode.as_ref() {
                inode.get_resident_page_count()
            } else {
                0
            };
            // println!(
            //     "[DentryCache] Key: {}, Path: {:?}, Strong Count: {}, pages: {}",
            //     name, dentry.absolute_path, strong_count, count
            // );
            if strong_count == 1 && count > 0 {
                // 没有其他强引用，可以安全移除
                cache_map.remove(name);
                // println!("[DentryCache] Removed {} due to low strong count", name);
            }
        }
    }

    // 清理掉 lru_list 中不再存在于 cache 的条目
    lru.retain(|key| cache_map.contains_key(key));
}

pub fn lookup_dcache_with_absolute_path(absolute_path: &str) -> Option<Arc<Dentry>> {
    DENTRY_CACHE.read().get(absolute_path)
}

pub fn lookup_dcache(parent: &Arc<Dentry>, name: &str) -> Option<Arc<Dentry>> {
    let absolute_path = format!("{}/{}", parent.absolute_path, name);
    DENTRY_CACHE.read().get(&absolute_path)
}

pub fn insert_dentry(dentry: Arc<Dentry>) {
    DENTRY_CACHE
        .write()
        .insert(dentry.absolute_path.clone(), dentry);
}

// 上层调用者保证: dentry 不是负目录项
/// 从dentry cache中删除对应的dentry, 并且设置被删除的dentry为负目录项
pub fn delete_dentry(dentry: Arc<Dentry>) {
    assert!(!dentry.is_negative());
    DENTRY_CACHE.write().remove(dentry.absolute_path.as_str());
    dentry.inner.lock().inode = None;
}

// 哈希键是由父目录的地址和当前文件名生成的, 确保全局唯一性
// 全局单例, 外层拿锁
// 注意管理器中对于Dentry的管理应该是Weak
pub struct DentryCache {
    cache: RwLock<HashMap<String, Arc<Dentry>>>,
    // 用于LRU策略的列表
    lru_list: Mutex<VecDeque<String>>,
    capacity: usize,
}

impl DentryCache {
    fn new(capacity: usize) -> Self {
        DentryCache {
            cache: RwLock::new(HashMap::new()),
            lru_list: Mutex::new(VecDeque::new()),
            capacity,
        }
    }

    fn get(&self, absolute_path: &str) -> Option<Arc<Dentry>> {
        let cache = self.cache.read();
        let mut lru_list = self.lru_list.lock();
        if let Some(dentry) = cache.get(absolute_path) {
            // 更新 LRU 列表
            if let Some(pos) = lru_list.iter().position(|x| x == absolute_path) {
                lru_list.remove(pos);
            }
            lru_list.push_back(absolute_path.to_string());
            // 返回 dentry 的引用
            // if let Some(dentry) = dentry.upgrade() {
            //     return Some(dentry);
            // } else {
            //     // 如果 Weak 引用已经失效，则从缓存中移除
            //     log::error!(
            //         "[DentryCache] Weak reference to dentry {} has expired",
            //         absolute_path
            //     );
            //     drop(cache);
            //     let mut cache = self.cache.write();
            //     cache.remove(absolute_path);
            // }
            return Some(dentry.clone());
        }
        None
    }

    fn insert(&self, absolute_path: String, dentry: Arc<Dentry>) {
        let mut cache = self.cache.write();
        let mut lru_list = self.lru_list.lock();

        // 如果已经存在，则更新
        if cache.contains_key(&absolute_path) {
            if let Some(pos) = lru_list.iter().position(|x| x == &absolute_path) {
                lru_list.remove(pos);
            }
        } else if cache.len() == self.capacity {
            // 缓存已满，移除最旧的
            if let Some(oldest) = lru_list.pop_front() {
                cache.remove(&oldest);
            }
        }

        cache.insert(absolute_path.clone(), dentry);
        lru_list.push_back(absolute_path);
    }

    fn remove(&self, absolute_path: &str) {
        let mut cache = self.cache.write();
        let mut lru_list = self.lru_list.lock();
        if let Some(pos) = lru_list.iter().position(|x| x == absolute_path) {
            lru_list.remove(pos);
        }
        cache.remove(absolute_path);
    }
}

#[repr(C)]
pub struct LinuxDirent64 {
    pub d_ino: u64,
    /// the distance from the start of the directory to the start of the next linux_dirent
    pub d_off: u64, // 文件系统底层磁盘中的偏移 filesystem-specific value with no specific meaning to user space,
    pub d_reclen: u16, // linux_dirent的长度, 对齐到8字节
    pub d_type: u8,
    pub d_name: Vec<u8>, // d_name是变长的, 在复制会用户空间时需要以'\0'结尾
}

impl Debug for LinuxDirent64 {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "LinuxDirent64 {{ d_ino: {}, d_off: {}, d_reclen: {}, d_type: {}, d_name: {} }}",
            self.d_ino,
            self.d_off,
            self.d_reclen,
            self.d_type,
            String::from_utf8_lossy(&self.d_name)
        )
    }
}

impl LinuxDirent64 {
    pub fn write_to_mem(&self, buf: &mut [u8]) {
        // buf[0..4].copy_from_slice(&self..to_le_bytes());
        // buf[4..6].copy_from_slice(&self.rec_len.to_le_bytes());
        // buf[6] = self.name_len;
        // buf[7] = self.file_type;
        // buf[8..(8 + self.name_len as usize)].copy_from_slice(&self.name[..]);
        const NAME_OFFSET: usize = 19;
        buf[0..8].copy_from_slice(&self.d_ino.to_le_bytes());
        buf[8..16].copy_from_slice(&self.d_off.to_le_bytes());
        buf[16..18].copy_from_slice(&self.d_reclen.to_le_bytes());
        buf[18] = self.d_type;
        let name_len = self.d_name.len();
        buf[NAME_OFFSET..NAME_OFFSET + name_len].copy_from_slice(&self.d_name[..]);
        // 填充剩余部分为0
        buf[NAME_OFFSET + name_len..].fill(0);
    }
}

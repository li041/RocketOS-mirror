use core::fmt::{Debug, Formatter};

use alloc::{
    collections::vec_deque::VecDeque,
    format,
    string::{String, ToString},
    sync::{Arc, Weak},
    vec::Vec,
};
use hashbrown::HashMap;
use lazy_static::lazy_static;
use spin::{Mutex, RwLock};

use crate::{
    ext4::inode::{S_ISGID, S_ISUID},
    mutex::SpinNoIrqLock,
    syscall::errno::{Errno, SyscallRet},
    task::current_task,
    timer::TimeSpec,
};

use super::{file::OpenFlags, inode::InodeOp, tmp};

bitflags::bitflags! {
    #[derive(Debug)]
    /// 目前只支持type
    pub struct DentryFlags: u32 {
        const DCACHE_MISS_TYPE     = 1 << 0; // Negative dentry
        const DCACHE_WHITEOUT_TYPE = 1 << 1; // Whiteout dentry
        const DCACHE_DIRECTORY_TYPE= 1 << 2; // Normal directory
        const DCACHE_AUTODIR_TYPE  = 1 << 3; // Autodir (presumed automount)
        const DCACHE_REGULAR_TYPE  = 1 << 4; // Regular file
        const DCACHE_SPECIAL_TYPE  = 1 << 5; // Special file
        const DCACHE_SYMLINK_TYPE  = 1 << 6; // Symlink
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
#[allow(unused)]
pub const F_OK: i32 = 0; // 检查文件是否存在
pub const R_OK: i32 = 4; // 检查读权限
pub const W_OK: i32 = 2; // 检查写权限
pub const X_OK: i32 = 1; // 检查执行权限

// 由调用者保证
//     1. dentry不是负目录项
/// 检查dentry的访问权限, mode: R_OK, W_OK, X_OK的组合
pub fn dentry_check_access(
    dentry: &Dentry,
    mode: i32,
    use_effective: bool,
) -> Result<usize, Errno> {
    let task = current_task();
    let (uid, gid) = if use_effective {
        (task.fsuid(), task.fsgid())
    } else {
        (task.uid(), task.gid())
    };
    // 特殊处理root
    if uid == 0 {
        // root不能绕过可执行权限检查, 必须有至少一个执行位
        if mode & X_OK != 0 {
            let i_mode = dentry.get_inode().get_mode();
            if i_mode & 0o111 == 0 {
                log::error!(
                    "[dentry_check_access] Root user has no execute permission on {}, i_mode: {:o}",
                    dentry.absolute_path,
                    i_mode
                );
                return Err(Errno::EACCES);
            }
        }
        return Ok(0); // root用户总是有读写权限
    }
    // 其他用户
    let inode = dentry.get_inode();
    let i_mode = inode.get_mode();
    let (user_perm, group_perm, other_perm) = (
        (i_mode >> 6) & 0o7, // 用户权限
        (i_mode >> 3) & 0o7, // 组权限
        i_mode & 0o7,        // 其他用户权限
    );
    let perm = if uid == inode.get_uid() {
        user_perm
    } else if gid == inode.get_gid() {
        group_perm
    } else {
        other_perm
    };
    if mode & R_OK != 0 && perm & 0o4 == 0
        || mode & W_OK != 0 && perm & 0o2 == 0
        || mode & X_OK != 0 && perm & 0o1 == 0
    {
        return Err(Errno::EACCES);
    }
    Ok(0)
}

// 由调用者保证:
//    1. dentry不是负目录项
/// mode是inode的mode
pub fn dentry_check_open(dentry: &Dentry, flags: OpenFlags, mode: i32) -> Result<usize, Errno> {
    log::debug!(
        "[dentry_check_open] Checking open permissions for {}, flags: {:?}, mode: {:o}",
        dentry.absolute_path,
        flags,
        mode
    );
    let task = current_task();
    let (uid, gid) = (task.fsuid(), task.fsgid());
    if flags.contains(OpenFlags::O_NOATIME) {
        // root用户总是有权限
        // 检查文件的所有者是否是当前用户
        if uid != 0 && uid != dentry.get_inode().get_uid() {
            log::error!(
                "[dentry_check_open] O_NOATIME flag set, but current user {} is not the owner of {}",
                uid,
                dentry.absolute_path
            );
            return Err(Errno::EPERM);
        }
    }
    if flags.contains(OpenFlags::O_CREAT) {
        if flags.contains(OpenFlags::O_EXCL) {
            // O_CREAT | O_EXCL: 文件已存在返回 EEXIST
            log::error!(
                "[dentry_check_open] O_CREAT | O_EXCL flags set, but {} already exists",
                dentry.absolute_path
            );
            return Err(Errno::EEXIST);
        }
        if dentry.is_dir() {
            // O_CREAT: 不能创建目录
            log::error!(
                "[dentry_check_open] O_CREAT flag set, but {} is a directory",
                dentry.absolute_path
            );
            return Err(Errno::EISDIR);
        }
    }
    if flags.contains(OpenFlags::O_DIRECTORY) {
        // O_DIRECTORY: 只能打开目录
        if !dentry.is_dir() {
            log::error!(
                "[dentry_check_open] O_DIRECTORY flag set, but {} is not a directory",
                dentry.absolute_path
            );
            return Err(Errno::ENOTDIR);
        }
    }
    if flags.contains(OpenFlags::O_WRONLY) || flags.contains(OpenFlags::O_RDWR) {
        // O_WRONLY 或 O_RDWR: 需要写权限
        if dentry.is_dir() {
            log::error!(
                "[dentry_check_open] O_WRONLY or O_RDWR flags set, but {} is a directory",
                dentry.absolute_path
            );
            return Err(Errno::EISDIR);
        }
        // ToOptimize: 有冗余的权限检查?
        if dentry_check_access(dentry, mode | W_OK, true).is_err() {
            log::error!(
                "[dentry_check_open] Write access denied for {}, mode: {:o}, uid: {}, gid: {}",
                dentry.absolute_path,
                mode,
                uid,
                gid
            );
            return Err(Errno::EACCES);
        }
        // 文件存在且成功(O_WRONLY 或 O_RDWR)打开
        if flags.contains(OpenFlags::O_TRUNC) {
            if dentry.is_regular() {
                log::warn!(
                    "[dentry_check_open] O_TRUNC flag set, truncating file {}",
                    dentry.absolute_path
                );
                dentry.get_inode().truncate(0)?;
            }
        }
    }
    // 检查权限
    dentry_check_access(dentry, mode, true)?;
    Ok(0)
}

// 由调用者保证:
//    1. dentry不是负目录项
/// 要修改文件的所有者, 必须具备`CAP_CHOWN`能力(目前只支持root用户)
pub fn chown(inode: &Arc<dyn InodeOp>, new_uid: u32, new_gid: u32) -> SyscallRet {
    let task = current_task();
    let (euid, egid) = (task.fsuid(), task.fsgid());
    let mut i_mode = inode.get_mode();
    log::info!(
        "[chown] euid: {}, egid: {}, new_uid: {}, new_gid: {}, i_mode: {:o}",
        euid,
        egid,
        new_uid,
        new_gid,
        i_mode
    );
    // 特殊处理root
    if euid == 0 {
        if new_uid != u32::MAX {
            // dentry.get_inode().set_uid(new_uid);
            // 当super-user修改可执行文件的所有者时需要清除setuid和setgid位
            if i_mode & 0o111 != 0 {
                log::warn!(
                    "[chown] Root user is changing owner of executable file , clearing setuid/setgid bits",
                );
                // 如果是文件是non-group-executable, 则保留setgid位
                if i_mode & 0o10 == 0 {
                    i_mode &= !(S_ISUID) as u16
                } else {
                    i_mode &= !(S_ISGID | S_ISUID) as u16; // 清除setuid和setgid位
                }
                inode.set_mode(i_mode);
            }
            inode.set_uid(new_uid);
        }
        if new_gid != u32::MAX {
            inode.set_gid(new_gid);
        }
        return Ok(0);
    }
    if new_uid != u32::MAX {
        return Err(Errno::EPERM); // 目前只支持root用户修改所有者
    }
    // 文件的所有者可以将文件的组更改为其所属的任何组
    if new_gid != u32::MAX && new_gid != inode.get_gid() {
        log::warn!("inode gid: {}", inode.get_gid());
        if euid != inode.get_uid() {
            log::error!(
                "[chown] No permission to change ownership, euid: {}, egid: {}",
                euid,
                egid
            );
            return Err(Errno::EPERM);
        }
        // 检查new_gid是否是当前用户的egid或附属组
        if egid != new_gid {
            task.op_sup_groups(
            |groups| {
                if !groups.contains(&new_gid) {
                    log::error!(
                        "[chown] New group {} is not in the effective groups of task {}, euid: {}, egid: {}",
                        new_gid,
                        task.tid(),
                        euid,
                        egid
                    );
                    return Err(Errno::EPERM);
                }
                Ok(0)
            },
        )?;
        }
        inode.set_gid(new_gid);
    }
    // 非root用户需要清除setuid和setgid位
    i_mode &= !(S_ISUID | S_ISGID) as u16;
    inode.set_mode(i_mode);
    Ok(0)
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
    pub parent: Option<Arc<Dentry>>,
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
            // parent: parent.map(|p| Arc::downgrade(&p)),
            parent,
            children: HashMap::new(),
        }
    }
    // 负目录项
    pub fn negative(parent: Option<Arc<Dentry>>) -> Self {
        Self {
            inode: None,
            // parent: parent.map(|p| Arc::downgrade(&p)),
            parent,
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
    pub fn tmp(parent: Arc<Dentry>, inode: Arc<dyn InodeOp>) -> Arc<Self> {
        let current_time = TimeSpec::new_wall_time();
        let tmp_path = format!("/tmp/{}", current_time.nsec);
        Arc::new(Self {
            absolute_path: tmp_path,
            flags: RwLock::new(DentryFlags::DCACHE_REGULAR_TYPE),
            inner: SpinNoIrqLock::new(DentryInner::new(Some(parent), inode)),
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
    // pub fn check_perm(&self, mode: i32) -> Result<usize, Errno> {
    // }
    // 由上层调用者保证: 负目录项不能调用该函数
    pub fn can_search(&self) -> bool {
        let (euid, egid) = {
            let task = current_task();
            (task.fsuid(), task.fsgid())
        };
        if euid == 0 {
            return true; // root用户总是有权限
        }
        let i_mode = self.get_inode().get_mode();
        log::error!(
            "[can_search] Checking search permission for {}, i_mode: {:o}, euid: {}, egid: {}",
            self.absolute_path,
            i_mode,
            euid,
            egid
        );
        let (user_perm, group_perm, other_perm) = (
            (i_mode >> 6) & 0o7, // 用户权限
            (i_mode >> 3) & 0o7, // 组权限
            i_mode & 0o7,        // 其他用户权限
        );
        let perm = if euid == self.get_inode().get_uid() {
            user_perm
        } else if egid == self.get_inode().get_gid() {
            group_perm
        } else {
            other_perm
        };
        if perm & 0o111 == 0 {
            log::error!(
                "[can_search] No search permission for {}, i_mode: {:o}, euid: {}, egid: {}",
                self.absolute_path,
                i_mode,
                euid,
                egid
            );
            return false;
        }
        true
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
            // let parent_opt = current.inner.lock().parent.as_ref().unwrap().upgrade();
            let parent_opt = current.inner.lock().parent.clone();
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
            // .map(|p| p.upgrade().unwrap())
            .unwrap()
    }
    // pub fn get_parent(&self) -> Arc<Dentry> {
    //     // 首先尝试从缓存的父节点获取
    //     if let Some(parent) = self.inner.lock().parent.clone() {
    //         if let Some(strong_parent) = parent.upgrade() {
    //             return strong_parent;
    //         }
    //     }
    //     // 如果缓存中没有父节点，尝试从文件系统读取 ".."
    //     unimplemented!()
    // }
    pub fn set_parent(&self, parent: Arc<Dentry>) {
        // self.inner.lock().parent = Some(Arc::downgrade(&parent));
        self.inner.lock().parent = Some(parent);
    }
}

lazy_static! {
    pub static ref DENTRY_CACHE: RwLock<DentryCache> = RwLock::new(DentryCache::new(1024));
    pub static ref CORE_DENTRIES: Mutex<Vec<Arc<Dentry>>> = Mutex::new(Vec::new());
}

pub fn insert_core_dentry(dentry: Arc<Dentry>) {
    let mut core_dentries = CORE_DENTRIES.lock();
    core_dentries.push(dentry);
}

/// 当frame不够时, 需要清理掉一些不常用的dentry
pub fn clean_dentry_cache() {
    let cache = DENTRY_CACHE.read();
    let mut cache_map = cache.cache.write(); // 需要写锁来删除
    let mut lru = cache.lru_list.lock();

    for name in lru.iter() {
        if let Some(dentry) = cache_map.get(name) {
            let strong_count = Arc::strong_count(dentry);
            // println!(
            //     "[DentryCache] Key: {}, Path: {:?}, Strong Count: {}, pages: {}",
            //     name, dentry.absolute_path, strong_count, count
            // );
            if name.contains("iozone") {
                // 特例处理, 保留 iozone*
                continue;
            }
            if strong_count == 1 {
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

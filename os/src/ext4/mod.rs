use crate::{
    fs::{
        dentry::{Dentry, DentryFlags},
        dev::{
            invalid::InvalidInode,
            loop_device::{self, insert_loop_device, LoopDevice, LoopInode},
            null::NullInode,
            rtc::RtcInode,
            tty::TtyInode,
            urandom::UrandomInode,
        },
        file::OpenFlags,
        inode::InodeOp,
        kstat::Kstat,
        pipe::PipeInode,
        uapi::{DevT, FallocFlags, RenameFlags},
    },
    mm::Page,
    net::socket::{Domain, Protocol, Socket, SocketInode, SocketType},
    syscall::errno::{Errno, SyscallRet},
    task::current_task,
    timer::TimeSpec,
};
use alloc::vec;
use alloc::vec::Vec;
use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
};
use block_op::Ext4DirContentWE;
use dentry::{EXT4_DT_CHR, EXT4_DT_DIR, EXT4_DT_FIFO, EXT4_DT_LNK, EXT4_DT_SOCK};
use fs::EXT4_BLOCK_SIZE;
use inode::{
    load_inode, write_inode, write_inode_on_disk, Ext4Inode, EXT4_EXTENTS_FL, EXT4_INLINE_DATA_FL,
    S_IALLUGO, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK, S_ISGID,
    S_ISVTX,
};

use core::any::Any;

mod block_group;
pub mod block_op;
pub mod dentry;
pub mod extent_tree;
pub mod fs;
#[cfg(not(feature = "la2000"))]
pub mod inode;
#[cfg(feature = "la2000")]
pub mod inode_la2000;
#[cfg(feature = "la2000")]
pub use inode_la2000 as inode;

pub mod super_block;

pub const MAX_FS_BLOCK_ID: usize = 0x100000000; // 文件系统块号的最大值, 用于表示稀疏文件中的空洞

impl InodeOp for Ext4Inode {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn read<'a>(&'a self, offset: usize, buf: &'a mut [u8]) -> usize {
        self.read(offset, buf).expect("Ext4Inode::read failed")
    }
    // 共享文件映射和私有文件映射只读时调用
    fn get_page<'a>(&'a self, page_index: usize) -> Option<Arc<Page>> {
        self.get_page_cache(page_index)
    }
    fn get_pages<'a>(&'a self, page_index: usize, page_count: usize) -> Vec<Arc<Page>> {
        // 获取指定范围的页
        self.get_page_caches(page_index, page_count)
    }
    // 返回对应的文件系统中的物理块号和长度
    // extent.len为0表示无效的extent, 即没有对应的物理块
    #[cfg(feature = "la2000")]
    fn lookup_extent<'a>(&'a self, page_index: usize) -> Option<(usize, usize)> {
        let extent = self.lookup_extent(page_index);
        if extent.len > 0 {
            // log::info!("[Ext4Inode::lookup_extent] page_index: {}, block_num: {}, block_count: {}", page_index, block_num, block_count);
            Some((extent.physical_start_block(), extent.len as usize))
        } else {
            None
        }
    }
    // 返回对应的文件系统中的物理块号和长度
    #[cfg(not(feature = "la2000"))]
    fn lookup_extent<'a>(&'a self, page_index: usize) -> Option<(usize, usize)> {
        let extent = self.lookup_extent(page_index);
        if let Some(extent) = extent {
            // log::info!("[Ext4Inode::lookup_extent] page_index: {}, block_num: {}, block_count: {}", page_index, block_num, block_count);
            Some((extent.physical_start_block(), extent.len as usize))
        } else {
            None
        }
    }

    fn write<'a>(&'a self, page_offset: usize, buf: &'a [u8]) -> usize {
        self.write(page_offset, buf)
    }
    fn write_dio<'a>(&'a self, page_offset: usize, buf: &'a [u8]) -> usize {
        self.write_direct(page_offset, buf)
    }
    fn truncate<'a>(&'a self, size: usize) -> SyscallRet {
        self.truncate(size as u64)
    }
    fn fallocate<'a>(&'a self, mode: FallocFlags, offset: usize, len: usize) -> SyscallRet {
        self.fallocate(mode, offset, len)
    }
    fn fsync<'a>(&'a self) -> SyscallRet {
        self.fsync()
    }
    // 上层调用者应先查找DentryCache, 如果没有才调用该函数
    // 先查找parent_entry的child(child是惰性加载的), 如果还没有则从目录中查找
    // name在parent_entry下的命名空间下, 不是绝对路径, 例如`/a/b/c`中的`c`, parent_entry是`/a/b`
    // 对于之前未加载的inode: 1. 加载inode 2. 关联到Dentry 3. 建立dentry的父子关系
    fn lookup<'a>(&'a self, name: &str, parent_entry: Arc<Dentry>) -> Arc<Dentry> {
        // log::info!("lookup: {}", name);
        // 注意: 这里应该使用绝对路径
        // let mut dentry = Dentry::negative(absolute_path, Some(parent_entry.clone()));
        let mut dentry: Arc<Dentry> = Dentry::negative(
            format!("{}/{}", parent_entry.absolute_path, name),
            Some(parent_entry.clone()),
        );
        if let Some(child) = parent_entry.get_child(name) {
            // 先查找parent_entry的child
            debug_assert!(
                child.absolute_path == format!("{}/{}", parent_entry.absolute_path, name)
            );
            return child.clone();
        } else {
            // 从目录中查找
            if let Some(ext4_dentry) = self.lookup(name) {
                log::info!("[InodeOp::lookup] ext4_dentry: {:?}", ext4_dentry);
                let absolute_path = format!("{}/{}", parent_entry.absolute_path, name);
                let inode_num = ext4_dentry.inode_num as usize;
                // 1.从磁盘加载inode
                let inode = load_inode(
                    inode_num,
                    self.block_device.clone(),
                    self.ext4_fs.upgrade().unwrap().clone(),
                );

                let inode_mode = inode.get_mode();
                let dentry_flags;
                // log::error!("inode: {:#x}", inode_mode & S_IFMT);
                match inode_mode & S_IFMT {
                    S_IFREG => dentry_flags = DentryFlags::DCACHE_REGULAR_TYPE,
                    S_IFDIR => dentry_flags = DentryFlags::DCACHE_DIRECTORY_TYPE,
                    S_IFCHR => dentry_flags = DentryFlags::DCACHE_SPECIAL_TYPE,
                    S_IFLNK => dentry_flags = DentryFlags::DCACHE_SYMLINK_TYPE,
                    S_IFIFO => {
                        // 处理特殊命名管道
                        dentry_flags = DentryFlags::DCACHE_SPECIAL_TYPE;
                        let pipe_inode = PipeInode::new(inode_num);
                        return Dentry::new(
                            absolute_path,
                            Some(parent_entry.clone()),
                            dentry_flags,
                            pipe_inode,
                        );
                    }
                    _ => {
                        log::error!("inode: {:?}", inode.inner.write().inode_on_disk);
                        panic!(
                            "[InodeOp::lookup] unknown inode type: {}, path: {:?}",
                            inode_mode, absolute_path
                        );
                    }
                }
                // 2. 关联到Dentry
                dentry = Dentry::new(
                    absolute_path,
                    Some(parent_entry.clone()),
                    dentry_flags,
                    inode,
                );
            }
            // } else {
            // 不存在, 返回负目录项
            // }
        }
        // 注意: 这里建立父子关系的dentry可能是负目录项
        // 3. 建立dentry的父子关系
        parent_entry
            .inner
            .lock()
            .children
            .insert(name.to_string(), Arc::downgrade(&dentry));
        dentry
    }
    // Todo: 增加日志
    // 1. 创建新的inode, 关联到dentry
    // 2. 更新父目录的数据块
    // 上层调用者保证: dentry是负目录项, 且父子关系已经建立
    /// 用于创建常规文件(S_IFREG)
    fn create<'a>(&'a self, dentry: Arc<Dentry>, mode: u16) {
        // dentry应该是负目录项
        debug_assert!(dentry.is_negative());
        // 分配inode_num
        let new_inode_num = self
            .ext4_fs
            .upgrade()
            .unwrap()
            .alloc_inode(self.block_device.clone(), false);
        // let (child_uid, child_gid, inode_mode) = self.child_uid_gid(mode & S_IALLUGO);
        let task = current_task();
        let child_uid = task.fsuid();
        let child_gid;
        let mut mode = mode & S_IALLUGO | S_IFREG; // 常规文件标志
        if self.inner.read().inode_on_disk.get_mode() & S_ISGID != 0 {
            // 如果父目录的S_ISGID标志位被设置, 则子文件的gid与父目录相同
            child_gid = self.inner.read().inode_on_disk.get_gid();
            log::warn!(
                "[Ext4Inode::create] dir S_ISGID set, child_gid: {}",
                child_gid
            );
            if child_uid != 0 {
                log::warn!(
                    "[Ext4Inode::create] clear S_ISGID flag for child: uid: {}, gid: {}",
                    child_uid,
                    child_gid
                );
                mode &= !S_ISGID; // 清除S_ISGID标志位
            }
        } else {
            // 否则使用当前任务的fsgid
            child_gid = task.fsgid();
        }
        // 初始化新的inode结构
        let new_inode = Ext4Inode::new(
            mode,
            EXT4_INLINE_DATA_FL,
            self.ext4_fs.clone(),
            new_inode_num,
            self.block_device.clone(),
            child_uid as u16,
            child_gid as u16,
        );
        // 将inode写入block_cache
        write_inode(&new_inode, new_inode_num, self.block_device.clone());
        // 在父目录中添加对应项
        self.add_entry(dentry.clone(), new_inode_num as u32, EXT4_DT_DIR);
        // 关联到dentry
        dentry.inner.lock().inode = Some(new_inode);
        // 更新dentry flags, 去掉负目录项标志, 添加常规文件标志
        dentry
            .flags
            .write()
            .update_type_from_negative(DentryFlags::DCACHE_REGULAR_TYPE);
    }
    // ToOptimize: 对于new_dir_entry, 没有通过指针直接操作, 而是内存复制
    fn rename<'a>(
        &'a self,
        new_dir: Arc<dyn InodeOp>,
        old_dentry: Arc<Dentry>,
        new_dentry: Arc<Dentry>,
        flags: RenameFlags,
        should_mv: bool,
    ) -> SyscallRet {
        // Noreplace已经在上层调用者中检查过了, exchange还未支持
        if flags.contains(RenameFlags::EXCHANGE) {
            // panic!("[rename] EXCHANGE not supported");
            log::warn!("[rename] EXCHANGE not supported");
            // return Err(Errno::ENOSYS);
        }
        let old_dir_entry = match self.lookup(&old_dentry.get_last_name()) {
            Some(entry) => entry,
            None => {
                log::warn!("[rename] old_dentry not found");
                return Err(Errno::ENOENT);
            }
        };
        // 如果更新的old_dentry是目录, 且new_dentry所在的目录不同, 需要更新`..`条目, 使其指向new_dir
        if old_dentry.is_dir() && should_mv {
            // 需要更新`..`条目
            old_dentry
                .get_inode()
                .as_any()
                .downcast_ref::<Ext4Inode>()
                .unwrap()
                .set_entry("..", new_dir.get_inode_num() as u32, EXT4_DT_DIR);
        }
        // 添加新目录项
        // 如果new_dentry已经存在, 则更新现有目录项, 如果不存在, 则创建新的目录项
        if new_dentry.is_negative() {
            // new_dentry是负目录项, 需要创建新的目录项
            new_dir
                .as_any()
                .downcast_ref::<Ext4Inode>()
                .unwrap()
                .add_entry(
                    new_dentry.clone(),
                    old_dir_entry.inode_num as u32,
                    old_dir_entry.file_type,
                );
            // 关联到dentry
            new_dentry.inner.lock().inode = Some(old_dentry.get_inode());
            // 更新dentry flags, 去掉负目录项标志, 添加对应文件标志
            new_dentry
                .flags
                .write()
                .update_type_from_negative(old_dentry.flags.read().get_type());
        } else {
            // new_dentry存在
            let new_dir_entry = match self.lookup(&new_dentry.get_last_name()) {
                Some(entry) => entry,
                None => {
                    log::warn!("[rename] new_dentry not found");
                    return Err(Errno::ENOENT);
                }
            };
            debug_assert!(old_dir_entry.file_type == new_dir_entry.file_type);
            new_dir
                .as_any()
                .downcast_ref::<Ext4Inode>()
                .unwrap()
                .set_entry(
                    &new_dentry.get_last_name(),
                    old_dir_entry.inode_num as u32,
                    old_dir_entry.file_type,
                );
        }

        let (old_name, old_inode_num) = {
            let inode = old_dentry.get_inode();
            let inode_num = inode.get_inode_num();
            let ext4_inode = inode.as_any().downcast_ref::<Ext4Inode>().unwrap();
            // 更新inode的ctime
            ext4_inode.set_ctime(TimeSpec::new_wall_time());
            (old_dentry.get_last_name(), inode_num as u32)
        };
        // 删除旧目录项
        self.delete_entry(&old_name, old_inode_num)?;
        return Ok(0);
    }
    // 上层调用者保证:
    //  1.old_dentry不是负目录项, new_dentry是负目录项
    //  2. new_dentry的父子关系已经建立
    fn link<'a>(&'a self, old_dentry: Arc<Dentry>, new_dentry: Arc<Dentry>) {
        debug_assert!(!old_dentry.is_negative());
        debug_assert!(new_dentry.is_negative());
        debug_assert!(
            new_dentry
                .inner
                .lock()
                .parent
                .as_ref()
                .unwrap()
                .get_inode()
                .get_inode_num()
                == self.inode_num
        );
        // 更新inode的硬链接数, ctime
        let old_inode = old_dentry.get_inode();
        let old_inode_num = old_inode.get_inode_num();
        let old_ext4_inode = old_inode.as_any().downcast_ref::<Ext4Inode>().unwrap();
        old_ext4_inode.add_nlinks();
        // 在父目录中添加对应项
        self.add_entry(new_dentry.clone(), old_inode_num as u32, EXT4_DT_DIR);
        // 关联到dentry
        new_dentry.inner.lock().inode = Some(old_inode);
        // 更新dentry flags, 去掉负目录项标志, 添加文件标志
        new_dentry
            .flags
            .write()
            .update_type_from_negative(old_dentry.flags.read().get_type());
    }
    fn symlink<'a>(&'a self, dentry: Arc<Dentry>, target: String) {
        // dentry应该是负目录项
        debug_assert!(dentry.is_negative());
        debug_assert!(target.len() < 4096); // 符号链接目标路径长度限制
                                            // 分配inode_num
        let new_inode_num = self
            .ext4_fs
            .upgrade()
            .unwrap()
            .alloc_inode(self.block_device.clone(), false);
        let (child_uid, child_gid) = { self.child_uid_gid() };
        // 初始化新的inode结构
        let new_inode = Ext4Inode::new(
            (S_IALLUGO | S_IFLNK) as u16,
            EXT4_INLINE_DATA_FL,
            self.ext4_fs.clone(),
            new_inode_num,
            self.block_device.clone(),
            child_uid as u16,
            child_gid as u16,
        );
        // 设置符号链接目标路径
        new_inode.write_inline_data_dio(0, target.as_bytes());
        // 设置快速路径
        new_inode.link.write().replace(target);
        // 将inode写入block_cache
        write_inode(&new_inode, new_inode_num, self.block_device.clone());
        // 在父目录中添加对应项
        self.add_entry(dentry.clone(), new_inode_num as u32, EXT4_DT_LNK);
        // 关联到dentry
        dentry.inner.lock().inode = Some(new_inode);
        // 更新dentry flags, 去掉负目录项标志, 添加符号链接标志
        dentry
            .flags
            .write()
            .update_type_from_negative(DentryFlags::DCACHE_SYMLINK_TYPE);
    }
    fn unlink<'a>(&'a self, dentry: Arc<Dentry>) -> Result<(), Errno> {
        // 1. 更新inode的硬链接数, ctime
        let inode = dentry.get_inode();
        let inode_num = inode.get_inode_num();
        // 检查粘滞位，如果设置了粘滞位, 且当前任务的uid不是文件的所有者, 返回EPERM
        if self.get_mode() & S_ISVTX != 0 && current_task().fsuid() != self.get_uid() {
            log::warn!(
                "[Ext4Inode::unlink] sticky bit set, uid: {}, inode_uid: {}",
                current_task().fsuid(),
                self.get_uid()
            );
            return Err(Errno::EPERM);
        }
        if let Some(ext4_inode) = inode.as_any().downcast_ref::<Ext4Inode>() {
            ext4_inode.sub_nlinks();
            // Todo: 检查硬链接数是否为0, 如果是则加入orphan list延迟删除
            if ext4_inode.get_nlinks() == 0 {
                self.ext4_fs.upgrade().unwrap().add_orphan_inode(inode_num);
            }
        }
        // 2. 在父目录中删除对应项
        self.delete_entry(&dentry.get_last_name(), inode_num as u32)
    }
    fn tmpfile<'a>(&'a self, mode: u16) -> Arc<Ext4Inode> {
        // 创建临时文件, 用于临时文件系统, inode没有对应的路径, 不会分配目录项
        // 临时文件没有对应的目录项, 只能通过fd进行访问
        // 与create的唯一区别是: 1. 没有对应的目录项
        // 1. 分配inode_num
        let new_inode_num = self
            .ext4_fs
            .upgrade()
            .unwrap()
            .alloc_inode(self.block_device.clone(), false);
        let task = current_task();
        let child_uid = task.fsuid();
        let child_gid;
        let mut mode = mode & S_IALLUGO | S_IFREG; // 常规文件标志
        if self.inner.read().inode_on_disk.get_mode() & S_ISGID != 0 {
            // 如果父目录的S_ISGID标志位被设置, 则子文件的gid与父目录相同
            child_gid = self.inner.read().inode_on_disk.get_gid();
            log::warn!(
                "[Ext4Inode::create] dir S_ISGID set, child_gid: {}",
                child_gid
            );
            if child_uid != 0 {
                log::warn!(
                    "[Ext4Inode::create] clear S_ISGID flag for child: uid: {}, gid: {}",
                    child_uid,
                    child_gid
                );
                mode &= !S_ISGID; // 清除S_ISGID标志位
            }
        } else {
            // 否则使用当前任务的fsgid
            child_gid = task.fsgid();
        }
        // 2. 初始化新的inode结构
        let new_inode = Ext4Inode::new(
            (mode & S_IALLUGO) as u16 | S_IFREG,
            EXT4_INLINE_DATA_FL,
            self.ext4_fs.clone(),
            new_inode_num,
            self.block_device.clone(),
            child_uid as u16,
            child_gid as u16,
        );
        // 3. 将inode写入block_cache
        write_inode(&new_inode, new_inode_num, self.block_device.clone());
        new_inode
    }
    fn mkdir<'a>(&'a self, dentry: Arc<Dentry>, mode: u16) {
        // dentry应该是负目录项
        debug_assert!(dentry.is_negative());
        debug_assert!(mode & S_IFDIR != 0);
        let ext4_block_size = self.get_block_size();
        // 分配inode_num
        let new_inode_num = self
            .ext4_fs
            .upgrade()
            .unwrap()
            .alloc_inode(self.block_device.clone(), true);
        let (child_uid, child_gid) = self.child_uid_gid();
        let mut mode = mode & S_IALLUGO | S_IFDIR; // 目录标志
        if self.get_mode() & S_ISGID != 0 {
            // 继承父目录的S_ISGID标志位
            mode |= S_ISGID;
        }
        // 初始化新的inode结构
        let new_inode = Ext4Inode::new(
            (mode & S_IALLUGO) | S_IFDIR as u16,
            EXT4_EXTENTS_FL,
            self.ext4_fs.clone(),
            new_inode_num,
            self.block_device.clone(),
            child_uid as u16,
            child_gid as u16,
        );
        // 分配数据块
        let new_block_num = self
            .ext4_fs
            .upgrade()
            .unwrap()
            .alloc_one_block(self.block_device.clone());
        // 初始化目录的第一个块, 添加`.`, `..`
        let mut buffer = vec![0u8; ext4_block_size];
        Ext4DirContentWE::new(&mut buffer).init_dot_dotdot(
            self.inode_num as u32,
            new_inode_num as u32,
            ext4_block_size,
        );
        // 更新inode的extent tree
        new_inode
            .insert_extent(
                0,
                new_block_num as u64,
                1,
                self.block_device.clone(),
                ext4_block_size,
            )
            .expect("[Ext4Inode::mkdir]");
        // 将数据块写回page cache
        new_inode
            .get_page_cache(0)
            .unwrap()
            .modify(0, |data: &mut [u8; EXT4_BLOCK_SIZE]| {
                data.copy_from_slice(&buffer);
            });
        // 更新inode的size
        new_inode.set_size(ext4_block_size as u64);
        // 将inode写入block_cache
        write_inode(&new_inode, new_inode_num, self.block_device.clone());
        // 在父目录中添加对应项
        self.add_entry(dentry.clone(), new_inode_num as u32, EXT4_DT_DIR);
        // 关联到dentry
        dentry.inner.lock().inode = Some(new_inode);
        // 更新dentry flags, 去掉负目录项标志, 添加目录标志
        dentry
            .flags
            .write()
            .update_type_from_negative(DentryFlags::DCACHE_DIRECTORY_TYPE);
    }
    /// 不同的字符设备类型, 使用Inode不同
    /// 目前仅支持字符设备, 设备号都是静态分配
    fn mknod<'a>(&'a self, dentry: Arc<Dentry>, mode: u16, dev: DevT) {
        debug_assert!(dentry.is_negative());
        let file_type = mode & S_IFMT;
        match file_type {
            S_IFIFO => {
                let new_inode_num = self
                    .ext4_fs
                    .upgrade()
                    .unwrap()
                    .alloc_inode(self.block_device.clone(), true);
                let pipe_inode = PipeInode::new(new_inode_num);
                // 写回inode
                write_inode_on_disk(
                    self,
                    &pipe_inode.inner.read().inode_on_disk,
                    new_inode_num,
                    self.block_device.clone(),
                );
                // 在父目录中添加对应项
                self.add_entry(dentry.clone(), new_inode_num as u32, EXT4_DT_FIFO);
                // 关联到dentry
                dentry.inner.lock().inode = Some(pipe_inode);
            }
            S_IFCHR => {
                // 提取主,次设备号
                let (major, minor) = dev.new_decode_dev();
                // 主设备号1表示mem
                match (major, minor) {
                    (1, 3) => {
                        // assert!(dentry.absolute_path == "/dev/null");
                        let new_inode_num = self
                            .ext4_fs
                            .upgrade()
                            .unwrap()
                            .alloc_inode(self.block_device.clone(), true);
                        let null_inode = NullInode::new(new_inode_num, mode, 1, 3);
                        // 在父目录中添加对应项
                        self.add_entry(dentry.clone(), new_inode_num as u32, EXT4_DT_CHR);
                        // 关联到dentry
                        dentry.inner.lock().inode = Some(null_inode);
                    } // /dev/null等
                    (1, 5) => {
                        // assert!(dentry.absolute_path == "/dev/zero");
                        let new_inode_num = self
                            .ext4_fs
                            .upgrade()
                            .unwrap()
                            .alloc_inode(self.block_device.clone(), true);
                        let zero_inode = NullInode::new(new_inode_num, mode, 1, 5);
                        // 写回inode
                        write_inode_on_disk(
                            self,
                            &zero_inode.inner.read().inode_on_disk,
                            new_inode_num,
                            self.block_device.clone(),
                        );
                        // 在父目录中添加对应项
                        self.add_entry(dentry.clone(), new_inode_num as u32, EXT4_DT_CHR);
                        // 关联到dentry
                        dentry.inner.lock().inode = Some(zero_inode);
                    } // /dev/zero
                    (5, 0) => {
                        // /dev/tty
                        // 分配inode_num
                        debug_assert!(dentry.absolute_path.starts_with("/dev/tty"));
                        let new_inode_num = self
                            .ext4_fs
                            .upgrade()
                            .unwrap()
                            .alloc_inode(self.block_device.clone(), true);
                        let tty_inode = TtyInode::new(new_inode_num, mode, 5, 0);
                        // 在父目录中添加对应项
                        self.add_entry(dentry.clone(), new_inode_num as u32, EXT4_DT_CHR);
                        // 关联到dentry
                        dentry.inner.lock().inode = Some(tty_inode);
                    } // /dev/tty
                    (10, 0) => {
                        debug_assert!(dentry.absolute_path == "/dev/rtc");
                        let new_inode_num = self
                            .ext4_fs
                            .upgrade()
                            .unwrap()
                            .alloc_inode(self.block_device.clone(), true);
                        let rtc_inode = RtcInode::new(new_inode_num, mode, 10, 0);
                        // 在父目录中添加对应项
                        self.add_entry(dentry.clone(), new_inode_num as u32, EXT4_DT_CHR);
                        // 关联到dentry
                        dentry.inner.lock().inode = Some(rtc_inode);
                    }
                    // /dev/urandom
                    (1, 9) => {
                        log::error!("urandom absolute_path: {:?}", dentry.absolute_path);
                        debug_assert!(dentry.absolute_path == "/dev/urandom");
                        let new_inode_num = self
                            .ext4_fs
                            .upgrade()
                            .unwrap()
                            .alloc_inode(self.block_device.clone(), true);
                        let urandom_inode = UrandomInode::new(new_inode_num, mode, 1, 9);
                        self.add_entry(dentry.clone(), new_inode_num as u32, EXT4_DT_CHR);
                        dentry.inner.lock().inode = Some(urandom_inode);
                    }
                    (10, 237) => {
                        // /dev/loop-control
                        debug_assert!(dentry.absolute_path == "/dev/loop-control");
                        let new_inode_num = self
                            .ext4_fs
                            .upgrade()
                            .unwrap()
                            .alloc_inode(self.block_device.clone(), true);
                        // Todo: 这里需要实现LoopControlInode
                        let loop_control_inode = NullInode::new(new_inode_num, mode, 10, 237);
                        self.add_entry(dentry.clone(), new_inode_num as u32, EXT4_DT_CHR);
                        dentry.inner.lock().inode = Some(loop_control_inode);
                    }
                    _ => panic!("Unsupported device: major: {}, minor: {}", major, minor),
                }
            }
            S_IFBLK => {
                // 提取主,次设备号
                let (major, minor) = dev.new_decode_dev();
                match (major, minor) {
                    (7, id) => {
                        // /dev/loopX, X是设备号
                        // assert!(dentry.absolute_path.starts_with("/dev/loop"));
                        let new_inode_num = self
                            .ext4_fs
                            .upgrade()
                            .unwrap()
                            .alloc_inode(self.block_device.clone(), false);
                        let loop_inode = LoopInode::new(new_inode_num, mode, 7, id);
                        self.add_entry(dentry.clone(), new_inode_num as u32, EXT4_DT_CHR);
                        dentry.inner.lock().inode = Some(loop_inode.clone());
                        let loop_device = LoopDevice::new(
                            dentry.clone(),
                            loop_inode,
                            OpenFlags::empty(),
                            id as usize,
                        );
                        insert_loop_device(loop_device, id as usize);
                    }
                    (0, 0) => {
                        // 会创建成功, 但dev=0是无效的设备号, 没有对应的内核驱动会处理该设备
                        log::warn!("[Ext4Inode::mknod] dev=0, no device driver will handle this");
                        let new_inode_num = self
                            .ext4_fs
                            .upgrade()
                            .unwrap()
                            .alloc_inode(self.block_device.clone(), false);
                        let invalid_inode = InvalidInode::new(new_inode_num);
                        self.add_entry(dentry.clone(), new_inode_num as u32, EXT4_DT_CHR);
                        dentry.inner.lock().inode = Some(invalid_inode.clone());
                        let loop_device =
                            LoopDevice::new(dentry.clone(), invalid_inode, OpenFlags::empty(), 0);
                        insert_loop_device(loop_device, 0);
                    }
                    _ => panic!(
                        "Unsupported block device: major: {}, minor: {}",
                        major, minor
                    ),
                }
            }
            S_IFSOCK => {
                // Unix域套接字
                let new_inode_num = self
                    .ext4_fs
                    .upgrade()
                    .unwrap()
                    .alloc_inode(self.block_device.clone(), false);
                let socket_inode = SocketInode::new(new_inode_num);
                self.add_entry(dentry.clone(), new_inode_num as u32, EXT4_DT_SOCK);
                dentry.inner.lock().inode = Some(socket_inode);
            }
            _ => panic!("Unsupported file type: {}", file_type),
        }
        // 更新dentry flags, 去掉负目录项标志, 添加特殊设备标志
        dentry
            .flags
            .write()
            .update_type_from_negative(DentryFlags::DCACHE_SPECIAL_TYPE);
    }
    // 返回(file_offset, linux_dirents)
    fn getdents(&self, buf: &mut [u8], offset: usize) -> Result<(usize, usize), Errno> {
        self.getdents(buf, offset)
    }
    fn getattr(&self) -> Kstat {
        self.getattr()
    }
    /// 获取符号链接的路径
    /// inode->link直接存储符号链接目标路径, 如果存在, 则直接返回
    /// 如果inode->link为空, 则从数据块中读取
    fn get_link(&self) -> String {
        if let Some(link) = self.link.read().as_ref() {
            return link.clone();
        }
        // 从inode中读取
        log::warn!("[Ext4Inode::get_link] link not found, reading from inode data");
        self.read_link().unwrap()
    }
    fn can_lookup(&self) -> bool {
        self.can_lookup()
    }
    fn get_inode_num(&self) -> usize {
        self.inode_num
    }
    fn setxattr(
        &self,
        key: String,
        value: Vec<u8>,
        flags: &crate::fs::uapi::SetXattrFlags,
    ) -> SyscallRet {
        self.setxattr(key, value, &flags)
    }
    fn getxattr(&self, key: &str) -> Result<Vec<u8>, Errno> {
        self.getxattr(key)
    }
    fn listxattr(&self) -> Result<Vec<String>, Errno> {
        self.listxattr()
    }
    fn removexattr(&self, key: &str) -> SyscallRet {
        self.removexattr(key)
    }
    fn get_size(&self) -> usize {
        self.inner.read().inode_on_disk.get_size() as usize
    }
    fn get_resident_page_count(&self) -> usize {
        self.address_space.lock().len()
    }
    fn get_mode(&self) -> u16 {
        self.inner.read().inode_on_disk.get_mode()
    }
    fn set_mode(&self, mode: u16) {
        self.inner.write().inode_on_disk.set_mode(mode);
    }
    fn set_perm(&self, perm: u16) {
        self.inner.write().inode_on_disk.set_perm(perm);
    }
    fn get_gid(&self) -> u32 {
        self.inner.read().inode_on_disk.get_gid()
    }
    fn set_gid(&self, gid: u32) {
        self.inner.write().inode_on_disk.set_gid(gid);
    }
    fn get_uid(&self) -> u32 {
        self.inner.read().inode_on_disk.get_uid()
    }
    fn set_uid(&self, uid: u32) {
        self.inner.write().inode_on_disk.set_uid(uid);
    }
    fn get_devt(&self) -> (u32, u32) {
        self.inner.read().inode_on_disk.get_devt()
    }
    fn get_atime(&self) -> TimeSpec {
        self.inner.read().inode_on_disk.get_atime()
    }
    fn get_ctime(&self) -> TimeSpec {
        self.inner.read().inode_on_disk.get_ctime()
    }
    fn get_mtime(&self) -> TimeSpec {
        self.inner.read().inode_on_disk.get_mtime()
    }
    fn set_atime(&self, atime: TimeSpec) {
        self.inner.write().inode_on_disk.set_atime(atime);
    }
    fn set_ctime(&self, ctime: TimeSpec) {
        self.inner.write().inode_on_disk.set_ctime(ctime);
    }
    fn set_mtime(&self, mtime: TimeSpec) {
        self.inner.write().inode_on_disk.set_mtime(mtime);
    }
}

use crate::{
    arch::timer::TimeSpec,
    drivers::block::block_cache::get_block_cache,
    fs::{
        dentry::{Dentry, DentryFlags, LinuxDirent64},
        dev::{rtc::RtcInode, tty::TtyInode},
        inode::InodeOp,
        kstat::Kstat,
        uapi::{DevT, RenameFlags},
    },
    mm::Page,
};
use alloc::vec;
use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
};
use block_op::Ext4DirContentWE;
use dentry::{EXT4_DT_CHR, EXT4_DT_DIR};
use fs::EXT4_BLOCK_SIZE;
use inode::{
    load_inode, write_inode, Ext4Inode, EXT4_EXTENTS_FL, EXT4_INLINE_DATA_FL, S_IALLUGO, S_IFCHR,
    S_IFDIR, S_IFLNK, S_IFREG,
};

use alloc::vec::Vec;
use core::any::Any;
use spin::RwLock;
use virtio_drivers::PAGE_SIZE;

mod block_group;
pub mod block_op;
pub mod dentry;
pub mod extent_tree;
pub mod fs;
pub mod inode;
pub mod super_block;

impl InodeOp for Ext4Inode {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn read<'a>(&'a self, offset: usize, buf: &'a mut [u8]) -> usize {
        self.read(offset, buf).expect("Ext4Inode::read failed")
    }
    // 共享文件映射和私有文件映射只读时调用
    fn get_page(self: Arc<Self>, page_index: usize) -> Result<Arc<Page>, &'static str> {
        self.get_page_cache(page_index)
            .ok_or("Ext4Inode::get_page failed")
    }

    fn write<'a>(&'a self, page_offset: usize, buf: &'a [u8]) -> usize {
        self.write(page_offset, buf)
    }
    // 上层调用者应先查找DentryCache, 如果没有才调用该函数
    // 先查找parent_entry的child(child是惰性加载的), 如果还没有则从目录中查找
    // name在parent_entry下的命名空间下, 不是绝对路径, 例如`/a/b/c`中的`c`, parent_entry是`/a/b`
    // 对于之前未加载的inode: 1. 加载inode 2. 关联到Dentry 3. 建立dentry的父子关系
    fn lookup<'a>(&'a self, name: &str, parent_entry: Arc<Dentry>) -> Arc<Dentry> {
        log::info!("lookup: {}", name);
        // 注意: 这里应该使用绝对路径
        // let mut dentry = Dentry::negative(absolute_path, Some(parent_entry.clone()));
        let mut dentry: Arc<Dentry> = Dentry::negative(
            format!("{}/{}", parent_entry.absolute_path, name),
            Some(parent_entry.clone()),
        );
        if let Some(child) = parent_entry.inner.lock().children.get(name) {
            // 先查找parent_entry的child
            assert!(child.absolute_path == format!("{}/{}", parent_entry.absolute_path, name));
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
                match inode_mode & 0o170000 {
                    S_IFREG => dentry_flags = DentryFlags::DCACHE_REGULAR_TYPE,
                    S_IFDIR => dentry_flags = DentryFlags::DCACHE_DIRECTORY_TYPE,
                    S_IFCHR => dentry_flags = DentryFlags::DCACHE_SPECIAL_TYPE,
                    S_IFLNK => dentry_flags = DentryFlags::DCACHE_SYMLINK_TYPE,
                    _ => panic!("[InodeOp::lookup] unknown inode type"),
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
            .insert(name.to_string(), dentry.clone());
        dentry
    }
    // Todo: 增加日志
    // 1. 创建新的inode, 关联到dentry
    // 2. 更新父目录的数据块
    // 上层调用者保证: dentry是负目录项, 且父子关系已经建立
    /// 用于创建常规文件(S_IFREG)
    fn create<'a>(&'a self, dentry: Arc<Dentry>, mode: u16) {
        // dentry应该是负目录项
        assert!(dentry.is_negative());
        // 分配inode_num
        let new_inode_num = self
            .ext4_fs
            .upgrade()
            .unwrap()
            .alloc_inode(self.block_device.clone(), false);
        // 初始化新的inode结构
        let new_inode = Ext4Inode::new(
            (mode & S_IALLUGO) as u16 | S_IFREG,
            EXT4_INLINE_DATA_FL,
            self.ext4_fs.clone(),
            new_inode_num,
            self.block_device.clone(),
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
    ) -> Result<(), &'static str> {
        // Noreplace已经在上层调用者中检查过了, exchange还未支持
        if flags.contains(RenameFlags::EXCHANGE) {
            panic!("[rename] EXCHANGE not supported");
        }
        let old_dir_entry = match self.lookup(&old_dentry.get_last_name()) {
            Some(entry) => entry,
            None => {
                log::warn!("[rename] old_dentry not found");
                return Err("old_dentry not found");
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
                    return Err("new_dentry not found");
                }
            };
            assert!(old_dir_entry.file_type == new_dir_entry.file_type);
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
        self.delete_entry(&old_name, old_inode_num);
        return Ok(());
    }
    // 上层调用者保证:
    //  1.old_dentry不是负目录项, new_dentry是负目录项
    //  2. new_dentry的父子关系已经建立
    fn link<'a>(&'a self, old_dentry: Arc<Dentry>, new_dentry: Arc<Dentry>) {
        assert!(!old_dentry.is_negative());
        assert!(new_dentry.is_negative());
        assert!(
            new_dentry
                .inner
                .lock()
                .parent
                .as_ref()
                .unwrap()
                .upgrade()
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
    fn unlink<'a>(&'a self, dentry: Arc<Dentry>) {
        // 1. 更新inode的硬链接数, ctime
        let inode = dentry.get_inode();
        let inode_num = inode.get_inode_num();
        let ext4_inode = inode.as_any().downcast_ref::<Ext4Inode>().unwrap();
        ext4_inode.sub_nlinks();
        // Todo: 检查硬链接数是否为0, 如果是则加入orphan list延迟删除
        if ext4_inode.get_nlinks() == 0 {
            self.ext4_fs.upgrade().unwrap().add_orphan_inode(inode_num);
        }
        // 2. 在父目录中删除对应项
        self.delete_entry(&dentry.get_last_name(), inode_num as u32);
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
        // 2. 初始化新的inode结构
        let new_inode = Ext4Inode::new(
            (mode & S_IALLUGO) as u16 | S_IFREG,
            EXT4_INLINE_DATA_FL,
            self.ext4_fs.clone(),
            new_inode_num,
            self.block_device.clone(),
        );
        // 3. 将inode写入block_cache
        write_inode(&new_inode, new_inode_num, self.block_device.clone());
        new_inode
    }
    fn mkdir<'a>(&'a self, dentry: Arc<Dentry>, mode: u16) {
        // dentry应该是负目录项
        assert!(dentry.is_negative());
        assert!(mode & S_IFDIR != 0);
        let ext4_block_size = self.get_block_size();
        // 分配inode_num
        let new_inode_num = self
            .ext4_fs
            .upgrade()
            .unwrap()
            .alloc_inode(self.block_device.clone(), true);
        // 初始化新的inode结构
        let new_inode = Ext4Inode::new(
            (mode & S_IALLUGO) | S_IFDIR as u16,
            EXT4_EXTENTS_FL,
            self.ext4_fs.clone(),
            new_inode_num,
            self.block_device.clone(),
        );
        // 分配数据块
        let new_block_num = self
            .ext4_fs
            .upgrade()
            .unwrap()
            .alloc_block(self.block_device.clone());
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
        assert!(dentry.is_negative());
        assert!(mode & S_IFCHR != 0);
        // 提取主,次设备号
        let (major, minor) = dev.unpack();
        /// 主设备号1表示mem
        match (major, minor) {
            (1, 3) => {
                unimplemented!();
            } // /dev/null
            (1, 5) => {
                unimplemented!();
            } // /dev/zero
            (5, 0) => {
                // /dev/tty
                // 分配inode_num
                assert!(dentry.absolute_path == "/dev/tty");
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
                assert!(dentry.absolute_path == "/dev/rtc");
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
            _ => panic!("Unsupported device: major: {}, minor: {}", major, minor),
        }
        // 更新dentry flags, 去掉负目录项标志, 添加特殊设备标志
        dentry
            .flags
            .write()
            .update_type_from_negative(DentryFlags::DCACHE_SPECIAL_TYPE);
    }
    fn getdents(&self, offset: usize) -> (usize, Vec<LinuxDirent64>) {
        let ext4_dirents: Vec<dentry::Ext4DirEntry> = self.getdents(offset);

        let mut offset = 0;
        const NAME_OFFSET: usize = 19;
        let linux_dirents = ext4_dirents
            .iter()
            .filter_map(|entry| {
                // 跳过无效的目录项(inode_num为0)
                if entry.inode_num == 0 {
                    offset += entry.rec_len as usize;
                    return None;
                }
                let null_term_name_len = entry.name.len() + 1;
                // reclen需要对齐到8字节
                let d_reclen = (NAME_OFFSET + null_term_name_len + 7) & !0x7;
                let dirent = LinuxDirent64 {
                    d_ino: entry.inode_num as u64,
                    d_off: offset as u64,
                    d_reclen: d_reclen as u16,
                    d_type: entry.file_type,
                    d_name: entry.name.clone(),
                };
                offset += entry.rec_len as usize;
                Some(dirent)
            })
            .collect();
        (offset, linux_dirents)
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
        self.read_link().unwrap()
    }
    fn can_lookup(&self) -> bool {
        self.can_lookup()
    }
    fn get_inode_num(&self) -> usize {
        self.inode_num
    }
    fn get_size(&self) -> usize {
        self.inner.read().inode_on_disk.get_size() as usize
    }
    fn get_mode(&self) -> u16 {
        self.inner.read().inode_on_disk.get_mode()
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

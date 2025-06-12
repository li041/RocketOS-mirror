//! new
use crate::ext4::inode::Ext4Inode;
use crate::mm::Page;
use crate::syscall::errno::{Errno, SyscallRet};
use crate::timer::TimeSpec;

use super::dentry::Dentry;
use super::kstat::Kstat;
use super::uapi::{DevT, FallocFlags, RenameFlags};
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;

/// 由页缓存直接和block device交互
/// inode查extent_tree, 返回页号
/// page_offset是页偏移, page_offset * PAGE_SIZE是字节偏移
pub trait InodeOp: Any + Send + Sync {
    // 主要用来获得在disk上的结构
    fn as_any(&self) -> &dyn Any {
        unimplemented!();
    }
    // 用于文件读写
    fn read<'a>(&'a self, _offset: usize, _buf: &'a mut [u8]) -> usize {
        unimplemented!();
    }
    // 先查找页缓存, 如果没有则从块设备中读取, 如果磁盘中没有extent, 则是hole, 分配block
    fn get_page<'a>(&'a self, _page_index: usize) -> Option<Arc<Page>> {
        unimplemented!();
    }
    fn lookup_extent<'a>(&'a self, _page_index: usize) -> Option<(usize, usize)> {
        unimplemented!();
    }
    fn write<'a>(&'a self, _page_offset: usize, _buf: &'a [u8]) -> usize {
        unimplemented!();
    }
    fn write_dio<'a>(&'a self, _page_offset: usize, _buf: &'a [u8]) -> usize {
        unimplemented!();
    }
    fn truncate<'a>(&'a self, _size: usize) -> SyscallRet {
        unimplemented!();
    }
    fn fallocate<'a>(&'a self, _mode: FallocFlags, _offset: usize, _len: usize) -> SyscallRet {
        unimplemented!();
    }
    fn fsync<'a>(&'a self) -> SyscallRet {
        unimplemented!();
    }
    // 返回目录项
    // 先查找Denrty的children, 如果没有再查找目录
    // 注意这里的返回值不是`Option<..>`, 对于没有查找的情况, 返回负目录项`dentry.inode = NULL`
    // lookup需要加载Inode进入内存, 关联到Dentry(除非是负目录项), 建立dentry的父子关系
    // 注意: 这里可能返回负目录项
    // 上层调用者保证:
    //      1. 先查找dentry cache, 如果没有再查找目录
    //      3. 上层调用者保证将dentry放进dentry cache中
    fn lookup<'a>(&'a self, _name: &str, _parent_dentry: Arc<Dentry>) -> Arc<Dentry> {
        unimplemented!();
    }
    // self是目录inode, name是新建文件的名字, mode是新建文件的类型
    // self是目录, Dentry是上层根据文件名新建的负目录项(已经建立了父子关系)
    // 上层调用者保证:
    //      1. 创建的文件名在目录中不存在
    //      2. Dentry的inode字段为None(负目录项)
    fn create<'a>(&'a self, _negative_dentry: Arc<Dentry>, _mode: u16) {
        unimplemented!();
    }
    // 由上层调用者保证: 进行了类型 + ancestor + flags检查
    // rename不会做任何检查, 只会直接修改目录项
    // self是old_dir, 注意如果移到另一个目录, 需要修改数据块中的`..`
    fn rename<'a>(
        &'a self,
        _new_dir: Arc<dyn InodeOp>,
        _old_dentry: Arc<Dentry>,
        _new_dentry: Arc<Dentry>,
        _flags: RenameFlags,
        _should_mv: bool,
    ) -> SyscallRet {
        unimplemented!();
    }
    // self是目录inode, old_dentry是旧的目录项, new_dentry是新的目录项, 他们指向同一个inode
    fn link<'a>(&'a self, _old_dentry: Arc<Dentry>, _new_dentry: Arc<Dentry>) {
        unimplemented!();
    }
    // self是目录inode, dentry是符号链接的目录项, target是符号链接的目标
    fn symlink<'a>(&'a self, _dentry: Arc<Dentry>, _target: String) {
        unimplemented!();
    }
    // 上层调用者保证:
    //     1. 在unlink调用后, inode的dentry cache中中对应的dentry无效化(变为负目录项)
    //     2. 仅有已有`File`可以访问inode
    fn unlink<'a>(&'a self, _dentry: Arc<Dentry>) -> Result<(), Errno> {
        unimplemented!();
    }
    // 创建临时文件, 用于临时文件系统, inode没有对应的路径, 不会分配目录项
    // 临时文件没有对应的目录项, 只能通过fd进行访问
    // 与create的唯一区别是: 1. 没有对应的目录项
    fn tmpfile<'a>(&'a self, _mode: u16) -> Arc<Ext4Inode> {
        unimplemented!();
    }
    fn mkdir<'a>(&'a self, _dentry: Arc<Dentry>, _mode: u16) {
        unimplemented!();
    }
    fn mknod<'a>(&'a self, _dentry: Arc<Dentry>, _mode: u16, _dev: DevT) {
        unimplemented!();
    }
    // 检查是否是目录, 且有子目录项可以用于lookup
    fn can_lookup(&self) -> bool {
        // unimplemented!();
        false
    }
    // 上层readdir调用
    // 返回(file_offset, buf_offset)
    fn getdents(&self, _buf: &mut [u8], _offset: usize) -> Result<(usize, usize), Errno> {
        unimplemented!();
    }
    // 上层fstat调用
    fn getattr(&self) -> Kstat {
        unimplemented!();
    }
    fn get_link(&self) -> String {
        unimplemented!();
    }
    /* get/set属性方法 */
    fn get_inode_num(&self) -> usize {
        unimplemented!();
    }
    fn get_size(&self) -> usize {
        unimplemented!();
    }
    fn get_resident_page_count(&self) -> usize {
        unimplemented!();
    }
    fn get_mode(&self) -> u16 {
        unimplemented!();
    }
    // 设置mode, file type + permission bits
    fn set_mode(&self, _mode: u16) {
        unimplemented!();
    }
    fn set_perm(&self, _perm: u16) {
        unimplemented!();
    }
    fn get_uid(&self) -> u32 {
        unimplemented!();
    }
    fn set_uid(&self, _uid: u32) {
        unimplemented!();
    }
    fn get_gid(&self) -> u32 {
        unimplemented!();
    }
    fn set_gid(&self, _gid: u32) {
        unimplemented!();
    }
    // (主设备号, 次设备号)
    fn get_devt(&self) -> (u32, u32) {
        unimplemented!();
    }
    /* 时间戳相关 */
    fn get_atime(&self) -> TimeSpec {
        unimplemented!();
    }
    fn set_atime(&self, _atime: TimeSpec) {
        unimplemented!();
    }
    fn get_mtime(&self) -> TimeSpec {
        unimplemented!();
    }
    fn set_mtime(&self, _mtime: TimeSpec) {
        unimplemented!();
    }
    fn get_ctime(&self) -> TimeSpec {
        unimplemented!();
    }
    fn set_ctime(&self, _ctime: TimeSpec) {
        unimplemented!();
    }
}

// pub struct InodeMeta {
//     /// inode number
//     pub inode_num: usize,
//     /// name which doesn't have slash
//     pub name: String,
//     inner: SpinNoIrqLock<InodeMetaInner>,
// }

// pub struct InodeMetaInner {
//     pub size: usize,
//     // link count
//     pub nlink: usize,
//     // Last access time
//     pub atime: TimeSpec,
//     // Last modification time
//     pub mtime: TimeSpec,
//     // Last status change time
//     pub ctime: TimeSpec,
// }

use alloc::sync::Arc;

use crate::{fs::inode::InodeOp, syscall::errno::Errno};

pub struct InvalidInode {
    inode_num: usize,
}

impl InvalidInode {
    pub fn new(inode_num: usize) -> Arc<Self> {
        Arc::new(InvalidInode { inode_num })
    }
}
impl InodeOp for InvalidInode {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn getxattr(&self, _key: &str) -> Result<alloc::vec::Vec<u8>, crate::syscall::errno::Errno> {
        Err(Errno::ENODATA) // /dev/invalid没有扩展属性
    }
    fn setxattr(
        &self,
        _key: alloc::string::String,
        _value: alloc::vec::Vec<u8>,
        _flags: &crate::fs::uapi::SetXattrFlags,
    ) -> crate::syscall::errno::SyscallRet {
        Err(Errno::EPERM) // /dev/invalid不支持设置扩展属性
    }
    fn get_inode_num(&self) -> usize {
        self.inode_num
    }
}

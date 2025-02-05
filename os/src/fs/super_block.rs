use alloc::sync::Arc;

use crate::ext4::fs::Ext4FileSystem;

use super::dentry::Dentry;

pub struct Fake_FS;

impl FileSystemOp for Fake_FS {
    fn type_name(&self) -> &'static str {
        "fake_fs"
    }
}
pub trait FileSystemOp: Send + Sync {
    fn type_name(&self) -> &'static str;
}

impl FileSystemOp for Ext4FileSystem {
    fn type_name(&self) -> &'static str {
        "ext4"
    }
}

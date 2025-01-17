use alloc::{sync::Arc, vec::Vec};

use crate::{
    config::SysResult,
    fs::{
        inode_trait::{InodeMeta, InodeMode, InodeTrait},
        path::Path,
        FSMutex,
    },
};

use super::{
    dentry::{FAT32DentryContent, FAT32DirEntry, ATTR_DIRECTORY},
    fat::FAT32FileAllocTable,
    file::FAT32File,
};

pub struct FAT32Inode {
    fat: Arc<FAT32FileAllocTable>,
    file: Arc<FSMutex<FAT32File>>,
    meta: Arc<InodeMeta>,
}

impl FAT32Inode {
    pub fn new_root(
        fat: Arc<FAT32FileAllocTable>,
        fa_inode: Option<Arc<dyn InodeTrait>>,
        path: &Path,
        first_cluster: usize,
    ) -> Self {
        let file = FAT32File::new(Arc::clone(&fat), first_cluster, None);
        Self {
            fat: Arc::clone(&fat),
            file: Arc::new(FSMutex::new(file)),
            meta: Arc::new(InodeMeta::new(
                fa_inode,
                path.clone(),
                InodeMode::FileDIR,
                0,
            )),
        }
    }

    pub fn from_dentry(
        fat: Arc<FAT32FileAllocTable>,
        // fa_inode: Option<Arc<dyn Inode>>,
        fa_inode: Arc<dyn InodeTrait>,
        dentry: &FAT32DirEntry,
    ) -> Self {
        let parent_path = &fa_inode.get_meta().path;
        let path = parent_path.clone_and_append(&dentry.fname());
        let mode = if (dentry.attr & ATTR_DIRECTORY) == ATTR_DIRECTORY {
            InodeMode::FileDIR
        } else {
            InodeMode::FileREG
        };
        let file = FAT32File::new(
            Arc::clone(&fat),
            dentry.fstcluster as usize,
            match mode {
                InodeMode::FileREG => Some(dentry.filesize as usize),
                InodeMode::FileDIR => None,
            },
        );
        Self {
            fat: Arc::clone(&fat),
            file: Arc::new(FSMutex::new(file)),
            meta: Arc::new(InodeMeta::new(
                Some(fa_inode),
                path,
                mode,
                dentry.filesize as usize,
            )),
        }
    }

    pub fn new(
        fat: Arc<FAT32FileAllocTable>,
        fa_inode: Arc<dyn InodeTrait>,
        name: &str,
        mode: InodeMode,
    ) -> Self {
        let parent_path = &fa_inode.get_meta().path;
        let path = parent_path.clone_and_append(name);
        log::debug!(
            "[FAT32Inode::new] parent_path: {}, path: {}",
            parent_path,
            path
        );
        let file = FAT32File::new(
            Arc::clone(&fat),
            0,
            match mode {
                InodeMode::FileREG => Some(0),
                InodeMode::FileDIR => None,
            },
        );
        Self {
            fat: Arc::clone(&fat),
            file: Arc::new(FSMutex::new(file)),
            meta: Arc::new(InodeMeta::new(
                Some(fa_inode),
                Path::from(path.clone()),
                mode,
                0,
            )),
        }
    }
}

impl InodeTrait for FAT32Inode {
    fn read<'a>(&'a self, offset: usize, buf: &'a mut [u8]) -> usize {
        self.file.lock().read(buf, offset)
    }

    fn write<'a>(&'a self, _offset: usize, _buf: &'a [u8]) -> usize {
        self.file.lock().write(_buf, _offset)
    }

    fn mknod(
        &self,
        this: Arc<dyn InodeTrait>,
        name: &str,
        mode: InodeMode,
    ) -> SysResult<Arc<dyn InodeTrait>> {
        if self.meta.mode != InodeMode::FileDIR {
            return Err(1);
        }
        let fat = Arc::clone(&self.fat);
        let s_inode = FAT32Inode::new(fat, this, name, mode);
        Ok(Arc::new(s_inode))
    }

    fn find(&self, this: Arc<dyn InodeTrait>, name: &str) -> SysResult<Arc<dyn InodeTrait>> {
        if self.meta.mode != InodeMode::FileDIR {
            return Err(1);
        }
        self.get_meta()
            .children_handler(this, |children| match children.get(name) {
                Some(inode) => Ok(inode.clone()),
                _ => Err(1),
            })
    }

    fn list(&self, this: Arc<dyn InodeTrait>) -> SysResult<Vec<Arc<dyn InodeTrait>>> {
        if self.meta.mode != InodeMode::FileDIR {
            return Err(1);
        }
        Ok(self
            .get_meta()
            .children_handler(this, |children| children.values().cloned().collect()))
    }

    fn get_meta(&self) -> Arc<InodeMeta> {
        Arc::clone(&self.meta)
    }

    /// as we call this method on `dyn Inode`, we need to use `Arc<dyn Inode>` as children's father inode
    fn load_children_from_disk(&self, this: Arc<dyn InodeTrait>) {
        assert_eq!(self.meta.mode, InodeMode::FileDIR);
        let meta = self.meta.clone();
        let mut meta_inner = meta.inner.lock();
        let mut content = self.file.lock();
        let fat = Arc::clone(&content.fat);
        let mut dentry_content = FAT32DentryContent::new(&mut content);
        while let Some(dentry) = FAT32DirEntry::read_dentry(&mut dentry_content) {
            let fname = dentry.fname();
            if fname == "." || fname == ".." {
                continue;
            }
            let inode = FAT32Inode::from_dentry(Arc::clone(&fat), Arc::clone(&this), &dentry);
            let inode_rc: Arc<dyn InodeTrait> = Arc::new(inode);
            meta_inner
                .children
                .insert(dentry.fname(), Arc::clone(&inode_rc));
        }
    }

    fn clear(&self) {
        self.file.lock().clear();
    }
}

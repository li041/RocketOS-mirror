use alloc::vec;
use alloc::{boxed::Box, sync::Arc};
use log::info;

use crate::{
    config::{AsyncResult, SysResult},
    fs_arona::{
        inode::{Inode, InodeMeta, InodeMode},
        path::Path,
    },
};

use super::{
    dentry::{FAT32DentryContent, FAT32DirEntry, ATTR_DIRECTORY},
    fat::FAT32FileAllocTable,
    file::FAT32File,
    SpinNoIrqLock,
};

pub struct FAT32Inode {
    fat: Arc<FAT32FileAllocTable>,
    file: Arc<SpinNoIrqLock<FAT32File>>,
    meta: Arc<InodeMeta>,
}

impl FAT32Inode {
    pub fn new_root(
        fat: Arc<FAT32FileAllocTable>,
        fa_inode: Option<Arc<dyn Inode>>,
        path: &Path,
        first_cluster: usize,
    ) -> Self {
        let file = FAT32File::new(Arc::clone(&fat), first_cluster, None);
        Self {
            fat: Arc::clone(&fat),
            file: Arc::new(SpinNoIrqLock::new(file)),
            meta: Arc::new(InodeMeta::new(
                fa_inode,
                path.clone(),
                InodeMode::FileDIR,
                0,
                fat.alloc_ino(),
            )),
        }
    }

    pub fn from_dentry(
        fat: Arc<FAT32FileAllocTable>,
        // fa_inode: Option<Arc<dyn Inode>>,
        fa_inode: Arc<dyn Inode>,
        dentry: &FAT32DirEntry,
    ) -> Self {
        let parent_path = &fa_inode.get_meta().path;
        let path = parent_path.append_name(&dentry.fname());
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
                _ => None,
            },
        );
        Self {
            fat: Arc::clone(&fat),
            file: Arc::new(SpinNoIrqLock::new(file)),
            meta: Arc::new(InodeMeta::new(
                Some(fa_inode),
                path,
                mode,
                dentry.filesize as usize,
                fat.alloc_ino(),
            )),
        }
    }

    pub fn new(
        fat: Arc<FAT32FileAllocTable>,
        fa_inode: Arc<dyn Inode>,
        name: &str,
        mode: InodeMode,
    ) -> Self {
        let parent_path = &fa_inode.get_meta().path;
        let path = parent_path.append_name(name);
        // log::debug!(
        //     "[FAT32Inode::new] parent_path: {}, path: {}",
        //     parent_path,
        //     path
        // );
        let file = FAT32File::new(
            Arc::clone(&fat),
            0,
            match mode {
                InodeMode::FileREG => Some(0),
                _ => None,
            },
        );
        Self {
            fat: Arc::clone(&fat),
            file: Arc::new(SpinNoIrqLock::new(file)),
            meta: Arc::new(InodeMeta::new(
                Some(fa_inode),
                Path::from(path.clone()),
                mode,
                0,
                fat.alloc_ino(),
            )),
        }
    }

    fn update_size(&self) {
        self.meta.inner.lock().data_size = self.file.lock().size.unwrap_or(0);
    }
}

impl Inode for FAT32Inode {
    fn read<'a>(&'a self, offset: usize, buf: &'a mut [u8]) -> AsyncResult<usize> {
        Box::pin(async move { Ok(self.file.lock().read(buf, offset)) })
    }

    // dir cannot be open as Writeable
    fn write<'a>(&'a self, offset: usize, buf: &'a [u8]) -> AsyncResult<usize> {
        Box::pin(async move {
            let data_size = self.file.lock().size.unwrap_or(0);
            if offset > data_size {
                // fill gap with '\0'
                info!(
                    "[FAT32Inode::write] filling offset gap, offset: {}, data_size: {}",
                    offset, data_size
                );
                let zero_buffer = vec![0u8; offset - data_size];
                self.file.lock().write(&zero_buffer, offset);
            }
            let bytes_write = self.file.lock().write(buf, offset);
            self.update_size();
            // update data_size
            // self.meta.inner.lock().data_size = self.file.lock().size.unwrap_or(0);
            Ok(bytes_write)
        })
    }

    fn mknod(
        &self,
        this: Arc<dyn Inode>,
        name: &str,
        mode: InodeMode,
    ) -> SysResult<Arc<dyn Inode>> {
        if self.meta.mode != InodeMode::FileDIR {
            return Err(1);
        }
        let fat = Arc::clone(&self.fat);
        let s_inode = FAT32Inode::new(fat, this, name, mode);
        Ok(Arc::new(s_inode))
    }

    fn get_meta(&self) -> Arc<InodeMeta> {
        Arc::clone(&self.meta)
    }

    /// as we call this method on `dyn Inode`, we need to use `Arc<dyn Inode>` as children's father inode
    fn load_children_from_disk(&self, this: Arc<dyn Inode>) {
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
            let inode_rc: Arc<dyn Inode> = Arc::new(inode);
            meta_inner
                .children
                .insert(dentry.fname(), Arc::clone(&inode_rc));
        }
    }

    fn clear(&self) {
        self.file.lock().clear();
        self.update_size();
    }
}

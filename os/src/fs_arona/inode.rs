use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::{Arc, Weak},
    vec::Vec,
};
use log::debug;

use crate::{
    config::{AsyncResult, SysResult},
    mutex::SpinNoIrqLock,
    timer::TimeSpec,
};

use super::path::Path;

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum InodeMode {
    FileSOCK = 0xC000, /* socket */
    FileLNK = 0xA000,  /* symbolic link */
    FileREG = 0x8000,  /* regular file */
    FileBLK = 0x6000,  /* block device */
    FileDIR = 0x4000,  /* directory */
    FileCHR = 0x2000,  /* character device */
    FileFIFO = 0x1000, /* FIFO */
}

// impl From<u32> for InodeMode {
//     fn from(value: u32) -> Self {
//         match value {
//             0xC000 => InodeMode::FileSOCK,
//             0xA000 => InodeMode::FileLNK,
//             0x8000 => InodeMode::FileREG,
//             0x6000 => InodeMode::FileBLK,
//             0x4000 => InodeMode::FileDIR,
//             0x2000 => InodeMode::FileCHR,
//             0x1000 => InodeMode::FileFIFO,
//             _ => panic!("Invalid InodeMode value: {}", value),
//         }
//     }
// }

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum InodePerm {
    S_IREAD = 0x0100,
    S_IWRITE = 0x0080,
    S_IEXEC = 0x0040,
    S_ISUID = 0x0800,
    S_ISGID = 0x0400,
}

pub trait Inode: Send + Sync {
    fn read<'a>(&'a self, offset: usize, buf: &'a mut [u8]) -> AsyncResult<usize>;
    fn write<'a>(&'a self, offset: usize, buf: &'a [u8]) -> AsyncResult<usize>;
    fn mknod(&self, this: Arc<dyn Inode>, name: &str, mode: InodeMode)
        -> SysResult<Arc<dyn Inode>>;
    fn get_meta(&self) -> Arc<InodeMeta>;
    fn load_children_from_disk(&self, this: Arc<dyn Inode>);
    /// clear the file content, inode still exists
    fn clear(&self);
}

impl dyn Inode {
    pub fn find(self: &Arc<Self>, name: &str) -> SysResult<Arc<dyn Inode>> {
        if self.get_meta().mode != InodeMode::FileDIR {
            return Err(1);
        }
        self.get_meta()
            .children_handler(self.clone(), |children| match children.get(name) {
                Some(inode) => Ok(inode.clone()),
                _ => Err(1),
            })
    }

    pub fn list(self: &Arc<Self>) -> SysResult<Vec<Arc<dyn Inode>>> {
        if self.get_meta().mode != InodeMode::FileDIR {
            return Err(1);
        }
        Ok(self.get_meta().children_handler(self.clone(), |children| {
            children.values().cloned().collect()
        }))
    }

    pub fn get_name(&self) -> String {
        self.get_meta().name.clone()
    }

    pub fn mknod_v(self: &Arc<Self>, name: &str, mode: InodeMode) -> SysResult<Arc<dyn Inode>> {
        let child = self.mknod(self.clone(), name, mode)?;
        self.get_meta().children_handler(self.clone(), |chidren| {
            chidren.insert(name.to_string(), child.clone());
        });
        Ok(child)
    }

    pub fn open_path(
        self: &Arc<Self>,
        path: &Path,
        create_file: bool,
        create_dir: bool,
    ) -> SysResult<Arc<dyn Inode>> {
        let mut current_node = self.clone();
        for (i, name) in path.get_inner().iter().enumerate() {
            if name == "." {
                continue;
            } else if name == ".." {
                if let Some(new_dir) = current_node.get_meta().inner.lock().parent.clone() {
                    current_node = new_dir.upgrade().unwrap();
                } else {
                    return Err(1);
                }
            } else {
                // name is a String
                if let Ok(new_node) = current_node.find(name) {
                    current_node = new_node.clone();
                } else if i == path.len() - 1 && create_file {
                    debug!("[open_path] file {} created", name);
                    current_node = current_node.mknod_v(name, InodeMode::FileREG).unwrap();
                } else if i == path.len() - 1 && create_dir {
                    debug!("[open_path] dir {} created", name);
                    current_node = current_node.mknod_v(name, InodeMode::FileDIR).unwrap();
                } else {
                    debug!("[open_path] file {} not found", name);
                    return Err(1);
                }
            }
        }
        Ok(current_node)
    }

    pub fn delete(&self) {
        let parent = self.get_meta().inner.lock().parent.clone();
        if let Some(parent) = parent {
            let parent = parent.upgrade().unwrap();
            let name = self.get_name();
            parent
                .get_meta()
                .children_handler(parent.clone(), |children| {
                    children.remove(&name);
                });
        }
    }
}

pub struct InodeMeta {
    /// inode number
    pub ino: usize,
    /// type of inode
    pub mode: InodeMode,
    /// name which doesn't have slash
    pub name: String,
    /// path
    pub path: Path,
    /// if mode == FileLNK, then link_target is none-empty.
    /// link_target is the RELATIVE path that the symlink pargets to.
    pub link_target: Option<Path>,
    pub inner: SpinNoIrqLock<InodeMetaInner>,
}

impl InodeMeta {
    pub fn new(
        parent: Option<Arc<dyn Inode>>,
        path: Path,
        mode: InodeMode,
        data_size: usize,
        ino: usize,
    ) -> Self {
        Self::new_symlink(parent, path, mode, None, data_size, ino)
    }

    pub fn new_symlink(
        parent: Option<Arc<dyn Inode>>,
        path: Path,
        mode: InodeMode,
        link_target: Option<Path>,
        data_size: usize,
        ino: usize,
    ) -> Self {
        let parent = match parent {
            Some(parent) => Some(Arc::downgrade(&parent)),
            None => None,
        };

        Self {
            ino,
            mode,
            name: path.get_name(),
            path,
            link_target,
            inner: SpinNoIrqLock::new(InodeMetaInner {
                st_atim: TimeSpec::new(),
                st_mtim: TimeSpec::new(),
                st_ctim: TimeSpec::new(),
                parent,
                children: BTreeMap::new(),
                data_size,
                state: InodeState::Init,
            }),
        }
    }

    /// use this method **instead of** access inode.meta.inner.children directly
    /// to ensure children are loaded from disk before use  
    /// We can do whatever we want to do on children by providing a handler
    pub fn children_handler<T>(
        &self,
        this: Arc<dyn Inode>,
        f: impl FnOnce(&mut BTreeMap<String, Arc<dyn Inode>>) -> T,
    ) -> T {
        let mut inner = self.inner.lock();
        if inner.state == InodeState::Init {
            inner.state = InodeState::Unmodified;
            drop(inner); // release lock, avoid deadlock in load_children_from_disk()
            this.load_children_from_disk(this.clone());
            f(&mut self.inner.lock().children)
        } else {
            f(&mut inner.children)
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub enum InodeState {
    /// children not loaded yet
    Init,
    /// children loaded, no modification
    Unmodified,
    /// children loaded, modification
    Dirty,
}

#[derive(Clone)]
pub struct InodeMetaInner {
    /// last access time, need to flush to disk.
    pub st_atim: TimeSpec,
    /// last modification time, need to flush to disk
    pub st_mtim: TimeSpec,
    /// last status change time, need to flush to disk
    pub st_ctim: TimeSpec,
    /// parent
    pub parent: Option<Weak<dyn Inode>>,
    /// children list (name, inode)
    /// USE INODEMETA::GET_CHILDREN() TO ENSURE CHILDREN ARE LOADED FROM DISK BEFORE USE
    pub children: BTreeMap<String, Arc<dyn Inode>>,
    /// file content len
    pub data_size: usize,
    // inode state, mainly for Dir inode
    pub state: InodeState,
}

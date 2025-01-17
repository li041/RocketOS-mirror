use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::{Arc, Weak},
    vec::Vec,
};
use log::debug;

use crate::{config::SysResult, timer::TimeSpec};

use super::{path::Path, FSMutex};

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum InodeMode {
    FileDIR,
    FileREG,
}

pub trait InodeTrait: Send + Sync {
    fn read<'a>(&'a self, offset: usize, buf: &'a mut [u8]) -> usize;
    fn write<'a>(&'a self, offset: usize, buf: &'a [u8]) -> usize;
    fn mknod(
        &self,
        this: Arc<dyn InodeTrait>,
        name: &str,
        mode: InodeMode,
    ) -> SysResult<Arc<dyn InodeTrait>>;
    fn find(&self, this: Arc<dyn InodeTrait>, name: &str) -> SysResult<Arc<dyn InodeTrait>>;
    fn list(&self, this: Arc<dyn InodeTrait>) -> SysResult<Vec<Arc<dyn InodeTrait>>>;
    fn get_meta(&self) -> Arc<InodeMeta>;
    fn load_children_from_disk(&self, this: Arc<dyn InodeTrait>);
    /// clear the file content, inode still exists
    fn clear(&self);
}

#[allow(unused)]
impl dyn InodeTrait {
    pub fn insert_child(&self, name: String, inode: Arc<dyn InodeTrait>) {
        self.get_meta().inner.lock().children.insert(name, inode);
    }

    pub fn sync(&self) {
        todo!();
    }

    pub fn get_name(&self) -> String {
        self.get_meta().name.clone()
    }

    pub fn mkdir_v(
        self: &Arc<Self>,
        name: &str,
        mode: InodeMode,
    ) -> SysResult<Arc<dyn InodeTrait>> {
        let child = self.mknod(self.clone(), name, mode)?;
        log::info!("[mkdir_v] child inode name {}", name);
        self.get_meta()
            .inner
            .lock()
            .children
            .insert(name.to_string(), child.clone());
        Ok(child)
    }

    pub fn mknod_v(
        self: &Arc<Self>,
        name: &str,
        mode: InodeMode,
    ) -> SysResult<Arc<dyn InodeTrait>> {
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
    ) -> SysResult<Arc<dyn InodeTrait>> {
        let mut current_dir = self.clone();
        for (i, name) in path.get_inner().iter().enumerate() {
            if name == "." {
                continue;
            } else if name == ".." {
                if let Some(new_dir) = current_dir.get_meta().inner.lock().parent.clone() {
                    current_dir = new_dir.upgrade().unwrap();
                } else {
                    return Err(1);
                }
            } else {
                // name is a String
                if let Ok(new_dir) = current_dir.find(current_dir.clone(), name)
                // .get_meta()
                // .children_handler(current_dir.clone(), |children| children.get(name).clone())
                {
                    current_dir = new_dir.clone();
                } else if i == path.len() - 1 && create_file {
                    debug!("[open_path] file {} created", name);
                    current_dir = current_dir.mknod_v(name, InodeMode::FileREG).unwrap();
                } else if i == path.len() - 1 && create_dir {
                    debug!("[open_path] dir {} created", name);
                    current_dir = current_dir.mkdir_v(name, InodeMode::FileDIR).unwrap();
                } else {
                    debug!("[open_path] file {} not found", name);
                    return Err(1);
                }
            }
        }
        Ok(current_dir)
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

const FAT32_INODE_CONST: usize = 0x1000_0000;

/// FAT的inode设置为常量, 与on-disk location无关
#[allow(unused)]
pub struct InodeMeta {
    /// inode number
    pub ino: usize,
    /// type of inode
    pub mode: InodeMode,
    /// name which doesn't have slash
    pub name: String,
    /// path
    pub path: Path,
    pub inner: FSMutex<InodeMetaInner>,
}

impl InodeMeta {
    pub fn new(
        parent: Option<Arc<dyn InodeTrait>>,
        path: Path,
        mode: InodeMode,
        data_len: usize,
    ) -> Self {
        let parent = match parent {
            Some(parent) => Some(Arc::downgrade(&parent)),
            None => None,
        };

        Self {
            ino: FAT32_INODE_CONST,
            mode,
            name: path.get_name(),
            path,
            inner: FSMutex::new(InodeMetaInner {
                st_atim: TimeSpec::new(),
                st_mtim: TimeSpec::new(),
                st_ctim: TimeSpec::new(),
                parent,
                children: BTreeMap::new(),
                data_len,
                state: InodeState::Init,
            }),
        }
    }

    /// We can do whatever we want to do on children by providing a handler
    pub fn children_handler<T>(
        &self,
        this: Arc<dyn InodeTrait>,
        f: impl FnOnce(&mut BTreeMap<String, Arc<dyn InodeTrait>>) -> T,
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
#[allow(unused)]
pub enum InodeState {
    /// children not loaded yet
    Init,
    /// children loaded, no modification
    Unmodified,
    /// children loaded, modification
    Dirty,
}

#[derive(Clone)]
#[allow(unused)]
pub struct InodeMetaInner {
    /// last access time, need to flush to disk.
    pub st_atim: TimeSpec,
    /// last modification time, need to flush to disk
    pub st_mtim: TimeSpec,
    /// last status change time, need to flush to disk
    pub st_ctim: TimeSpec,
    /// parent
    pub parent: Option<Weak<dyn InodeTrait>>,
    /// children list (name, inode)
    /// USE INODEMETA::GET_CHILDREN() TO ENSURE CHILDREN ARE LOADED FROM DISK BEFORE USE
    pub children: BTreeMap<String, Arc<dyn InodeTrait>>,
    /// file content len
    pub data_len: usize,
    // inode state, mainly for Dir inode
    pub state: InodeState,
}

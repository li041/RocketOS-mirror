use core::sync::atomic::{AtomicI32, Ordering};

use alloc::{
    collections::{btree_map::BTreeMap, vec_deque::VecDeque},
    string::String,
    sync::Arc,
};
use spin::{Mutex, RwLock};

use crate::{
    fs::file::{FileOp, OpenFlags},
    syscall::errno::Errno,
};

pub const IN_NONBLOCK: i32 = 0o0004000;
pub const IN_CLOEXEC: i32 = 0o02000000;
// 实例信息
pub struct InotifyHandle {
    is_nonblocking: bool,
    next_wd: AtomicI32, // 下一个 watch descriptor,
    watches: RwLock<BTreeMap<i32, InotifyWatch>>,
    events: Mutex<VecDeque<InotifyEvent>>,
}

impl InotifyHandle {
    pub fn new(flags: i32) -> Result<Arc<Self>, Errno> {
        Ok(Arc::new(Self {
            is_nonblocking: flags & IN_NONBLOCK != 0,
            next_wd: AtomicI32::new(1), // 从 1 开始，0 通常保留
            watches: RwLock::new(BTreeMap::new()),
            events: Mutex::new(VecDeque::new()),
        }))
    }

    /// 添加一个监听对象
    pub fn add_watch(&self, path: String, mask: u32) -> i32 {
        let wd = self.next_wd.fetch_add(1, Ordering::SeqCst);
        self.watches
            .write()
            .insert(wd, InotifyWatch { wd, path, mask });
        wd
    }

    /// 移除监听对象
    pub fn remove_watch(&self, wd: i32) -> Option<InotifyWatch> {
        self.watches.write().remove(&wd)
    }

    /// 模拟事件推送
    #[allow(unused)]
    pub fn push_event(&self, event: InotifyEvent) {
        self.events.lock().push_back(event);
    }

    /// 读取一个事件
    pub fn fetch_event(&self) -> Option<InotifyEvent> {
        self.events.lock().pop_front()
    }
}

impl FileOp for InotifyHandle {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        let exevt_size = core::mem::size_of::<InotifyEvent>();
        if buf.len() < exevt_size {
            return Err(Errno::EINVAL);
        }

        // Todo：阻塞
        if let Some(event) = self.fetch_event() {
            return event.serialize(buf);
        } else {
            return Err(Errno::EAGAIN);
        }
    }

    fn write(&self, _buf: &[u8]) -> Result<usize, Errno> {
        Err(Errno::EINVAL) // inotify 不支持写操作
    }

    fn get_flags(&self) -> super::file::OpenFlags {
        if self.is_nonblocking {
            OpenFlags::O_NONBLOCK
        } else {
            OpenFlags::empty()
        }
    }
    fn hang_up(&self) -> bool {
        false
    }
    fn readable(&self) -> bool {
        true
    }
    fn w_ready(&self) -> bool {
        false // TimerFd 通常不支持写操作
    }
    fn writable(&self) -> bool {
        false
    }
}

/// 单个监听对象（对应内核的 inotify_watch）
#[allow(unused)]
pub struct InotifyWatch {
    pub wd: i32,      // watch descriptor
    pub path: String, // 监听的路径
    pub mask: u32,    // 监听的事件掩码
}

/// 事件结构（对应内核的 struct inotify_event）
pub struct InotifyEvent {
    pub wd: i32,      // 哪个 watch 触发的
    pub mask: u32,    // 事件类型
    pub cookie: u32,  // 跨 rename 的 cookie
    pub len: u32,     // 名称长度
    pub name: String, // 发生变化的文件名
}

impl InotifyEvent {
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        let mut offset = 0;
        // 写 wd
        buf[offset..offset + 4].copy_from_slice(&self.wd.to_ne_bytes());
        offset += 4;

        // 写 mask
        buf[offset..offset + 4].copy_from_slice(&self.mask.to_ne_bytes());
        offset += 4;

        // 写 cookie
        buf[offset..offset + 4].copy_from_slice(&self.cookie.to_ne_bytes());
        offset += 4;

        // 写 len
        buf[offset..offset + 4].copy_from_slice(&self.len.to_ne_bytes());
        offset += 4;

        // 写 name（含 \0）
        let mut name_bytes = self.name.as_bytes().to_vec();
        if !name_bytes.ends_with(&[0]) {
            name_bytes.push(0);
        }
        buf[offset..offset + self.len as usize].copy_from_slice(&name_bytes);
        offset += self.len as usize;

        Ok(offset)
    }
}

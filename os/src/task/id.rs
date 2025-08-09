//! id allocator
use super::Tid;
// use crate::mutex::Mutex;
use alloc::vec::Vec;
use core::fmt::Display;
use lazy_static::lazy_static;
use spin::Mutex;

// 进程（线程）号分配器
lazy_static! {
    static ref TID_ALLOCATOR: Mutex<IdAllocator> = Mutex::new(IdAllocator::new());
    static ref KID_ALLOCATOR: Mutex<IdAllocator> = Mutex::new(IdAllocator::new());
}

pub fn info_allocator() {
    let tid_allocator = TID_ALLOCATOR.lock();
    let kid_allocator = KID_ALLOCATOR.lock();
    println!(
        "[IdAllocator] TID: next={}, recycled={:?}, KID: next={}, recycled={:?}",
        tid_allocator.next, tid_allocator.recycled, kid_allocator.next, kid_allocator.recycled
    );
}

/// 申请内核栈号
pub fn kid_alloc() -> usize {
    KID_ALLOCATOR.lock().alloc()
}

pub fn kid_dealloc(kid: usize) {
    KID_ALLOCATOR.lock().dealloc(kid);
}

/// 申请进程（线程）号
pub fn tid_alloc() -> TidHandle {
    TidHandle(TID_ALLOCATOR.lock().alloc())
}

/// Generic Allocator struct
pub struct IdAllocator {
    next: usize,
    recycled: Vec<usize>,
}

impl IdAllocator {
    pub fn new() -> Self {
        Self {
            next: 0,
            recycled: Vec::new(),
        }
    }

    pub fn alloc(&mut self) -> Tid {
        if let Some(id) = self.recycled.pop() {
            id
        } else {
            let id = self.next;
            self.next += 1;
            id
        }
    }

    pub fn dealloc(&mut self, id: usize) {
        debug_assert!(id < self.next);
        //if !self.recycled.contains(&id) {
        self.recycled.push(id);
        //}
    }
}

#[derive(PartialEq, Debug)]
pub struct TidHandle(pub Tid);

impl Drop for TidHandle {
    fn drop(&mut self) {
        TID_ALLOCATOR.lock().dealloc(self.0);
    }
}

impl Display for TidHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TidHandle {
    #[allow(unused)]
    pub fn set(&mut self, tid: Tid) {
        self.0 = tid;
    }
}

pub struct TidAddress {
    // 当 set_child_tid 被设置时，新线程做的第一件事就是将其线程 ID 写入此地址。
    pub set_child_tid: Option<usize>,
    pub clear_child_tid: Option<usize>,
}

impl TidAddress {
    pub fn new() -> Self {
        Self {
            set_child_tid: None,
            clear_child_tid: None,
        }
    }
}

// #[derive(PartialEq, Debug)]
// pub struct KIdHandle(pub usize);
// impl Drop for KIdHandle {
//     fn drop(&mut self) {
//         KID_ALLOCATOR.lock().dealloc(self.0);
//     }
// }

#[cfg(test)]
fn test_id_allocator() {
    let mut allocator = IdAllocator::new();
    let id1 = allocator.alloc();
    let id2 = allocator.alloc();
    assert_eq!(id1, 0);
    assert_eq!(id2, 1);
    allocator.dealloc(id1);
    let id3 = allocator.alloc();
    assert_eq!(id3, 0);
    let id4 = allocator.alloc();
    assert_eq!(id4, 2);
    allocator.dealloc(id2);
    allocator.dealloc(id3);
    let id5 = allocator.alloc();
    assert_eq!(id5, 1);
    println!("test_id_allocator passed");
}

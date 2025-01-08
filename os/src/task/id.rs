//! id allocator

use core::fmt::Display;

use crate::mutex::SpinNoIrqLock;
use alloc::vec::Vec;
use lazy_static::lazy_static;

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

    pub fn alloc(&mut self) -> usize {
        if let Some(id) = self.recycled.pop() {
            id
        } else {
            let id = self.next;
            self.next += 1;
            id
        }
    }

    pub fn dealloc(&mut self, id: usize) {
        assert!(id < self.next);
        assert!(!self.recycled.contains(&id), "id {} has been recycled", id);
        self.recycled.push(id);
    }
}

#[derive(PartialEq, Debug)]
pub struct TidHandle(pub usize);
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

#[derive(PartialEq, Debug)]
pub struct KIdHandle(pub usize);
impl Drop for KIdHandle {
    fn drop(&mut self) {
        KID_ALLOCATOR.lock().dealloc(self.0);
    }
}

lazy_static! {
    /// kstack id allocator instance through lazy_static!
    pub static ref KID_ALLOCATOR: SpinNoIrqLock<IdAllocator> = SpinNoIrqLock::new(IdAllocator::new());
    pub static ref TID_ALLOCATOR: SpinNoIrqLock<IdAllocator> = SpinNoIrqLock::new(IdAllocator::new());
}

pub fn kid_alloc() -> usize {
    KID_ALLOCATOR.lock().alloc()
}

pub fn tid_alloc() -> TidHandle {
    TidHandle(TID_ALLOCATOR.lock().alloc())
}

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

use super::futex::{FutexKey, FutexQ};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use log::{info, warn};

use super::jhash::jhash2;
use crate::mutex::SpinNoIrqLock;

use lazy_static::lazy_static;

/// the number of hash buckets, must be a power of 2
const FUTEX_HASH_SIZE: usize = 256;

lazy_static! {
    // can only hold the mutex through `futex_hash_bucket`
   pub static ref FUTEXQUEUES: FutexQueues = {
        info!("Initializing futex queues");
        let futex_queues = FutexQueues::new(FUTEX_HASH_SIZE);
        futex_queues
   };
}

#[allow(unused)]
/// print all futex_q that are in the FUTEXQUEUES
pub fn display_futexqueues() {
    warn!("[display_futexqueues]");
    for i in 0..FUTEX_HASH_SIZE {
        let hash_bucket = FUTEXQUEUES.buckets[i].lock();
        if !hash_bucket.is_empty() {
            for futex_q in hash_bucket.iter() {
                warn!(
                    "task {} is still wait for {:?}",
                    futex_q.task.upgrade().unwrap().tid(),
                    futex_q.key
                );
            }
        }
        drop(hash_bucket);
    }
}

/// the outer vector is the bucket, the inner vector is the futex queue
pub struct FutexQueues {
    pub buckets: Box<[SpinNoIrqLock<VecDeque<FutexQ>>]>,
}

impl FutexQueues {
    fn new(size: usize) -> Self {
        let mut buckets = Vec::with_capacity(size);
        for _ in 0..size {
            buckets.push(SpinNoIrqLock::new(VecDeque::new()));
        }
        Self {
            buckets: buckets.into_boxed_slice(),
        }
    }
}

pub fn futex_hash(futex_key: &FutexKey) -> usize {
    let key = &[
        futex_key.ptr as u32,
        futex_key.aligned as u32,
        futex_key.offset,
    ];
    let hash = jhash2(key, key[2]);
    let index = hash as usize & (FUTEX_HASH_SIZE - 1);
    index
}

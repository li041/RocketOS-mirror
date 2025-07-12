use alloc::string::ToString;
use alloc::vec::Vec;
use core::iter::repeat_with;
use core::ops::Add;
use spin::RwLock;

use crate::arch::config::KERNEL_BASE;
use crate::mm::VirtAddr;

use super::block_dev::BlockDevice;

const BLOCK_SIZE: usize = 512;
#[cfg(feature="vf2")]
pub const RAMDISK_BASE: usize = 0x70000000; // RamDisk 基地址
#[cfg(feature="la2000")]
pub const RAMDISK_BASE: usize = 0xA0000000; // RamDisk 基地址
pub const RAMDISK_SIZE: usize = 0x80000000; // RamDisk 大小为 2GB


pub struct RamDisk {
    // 基地址
    base_addr: usize,
    // 使用 RwLock 来保护每个块的读写操作
    segments: Vec<RwLock<()>>,
}

impl RamDisk {
    pub fn new() -> Self {
        Self {
            base_addr: RAMDISK_BASE + KERNEL_BASE,
            segments: Vec::from_iter(
                repeat_with(|| RwLock::new(())).take(RAMDISK_SIZE / BLOCK_SIZE),
            ),
        }
    }
}

impl BlockDevice for RamDisk {
    fn read_blocks(&self, start_block_id: usize, buf: &mut [u8]) {
        // log::info!(
        //     "[RamDisk::read_blocks] start_block_id: {}, buf_len: {}",
        //     start_block_id,
        //     buf.len()
        // );
        let num_blocks = buf.len() / BLOCK_SIZE;
        assert_eq!(
            buf.len() % BLOCK_SIZE,
            0,
            "Buffer size must be multiple of block size"
        );
        for i in 0..num_blocks {
            let blk_id = start_block_id + i;
            let _guard = self.segments[blk_id].read(); // 多读并发
            let blk_ptr = self.base_addr.add(blk_id * BLOCK_SIZE) as *const u8;
            unsafe {
                let dst = &mut buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
                dst.copy_from_slice(core::slice::from_raw_parts(blk_ptr, BLOCK_SIZE));
            }
        }
    }
    fn write_blocks(&self, start_block_id: usize, buf: &[u8]) {
        assert_eq!(
            buf.len() % BLOCK_SIZE,
            0,
            "Buffer size must be multiple of BLOCK_SIZE"
        );
        let num_blocks = buf.len() / BLOCK_SIZE;

        for i in 0..num_blocks {
            let blk_id = start_block_id + i;
            let _guard = self.segments[blk_id].write(); // 写操作需要独占
            let blk_ptr = self.base_addr.add(blk_id * BLOCK_SIZE) as *mut u8;
            unsafe {
                let src = &buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
                core::slice::from_raw_parts_mut(blk_ptr, BLOCK_SIZE).copy_from_slice(src);
            }
        }
    }
}

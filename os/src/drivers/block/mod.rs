pub mod block_cache;
pub mod block_dev;
mod virtio_blk;

use block_dev::BlockDevice;
pub use virtio_blk::VirtIOBlock;

// use crate::board::BlockDeviceImpl;
use alloc::sync::Arc;
// use easy_fs::BlockDevice;
use lazy_static::*;

use crate::boards::qemu::BlockDeviceImpl;

lazy_static! {
    pub static ref BLOCK_DEVICE: Arc<dyn BlockDevice> = Arc::new(BlockDeviceImpl::new());
}

const BLOCK_SIZE: usize = 1024;
const BLOCK_CACHE_SIZE: usize = 16;

#[allow(unused)]
/// 注意这个函数会破坏文件镜像
pub fn block_device_test() {
    let block_device = BLOCK_DEVICE.clone();
    let mut write_buffer = [0u8; BLOCK_SIZE];
    let mut read_buffer = [0u8; BLOCK_SIZE];
    for i in 0..512 {
        for byte in write_buffer.iter_mut() {
            *byte = i as u8;
        }
        block_device.write_block(i as usize, &write_buffer);
        block_device.read_block(i as usize, &mut read_buffer);
        assert_eq!(write_buffer, read_buffer);
    }
    println!("block device test passed!");
}

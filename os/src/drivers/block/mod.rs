pub mod block_cache;
pub mod block_dev;
#[cfg(feature="board")]
pub mod ramdisk;
pub mod sdio;

use block_dev::BlockDevice;

use alloc::sync::Arc;
use lazy_static::*;

#[cfg(feature = "virt")]
pub type BlockDeviceImpl = crate::arch::VirtIOBlock;
#[cfg(all(feature = "board", not(feature = "sdcard")))]
pub type BlockDeviceImpl = crate::drivers::block::ramdisk::RamDisk;
#[cfg(all(feature = "board", feature = "sdcard"))]
pub type BlockDeviceImpl = crate::drivers::block::sdio::MmcDevice;

lazy_static! {
    pub static ref BLOCK_DEVICE: Arc<dyn BlockDevice> = Arc::new(BlockDeviceImpl::new());
}

pub const VIRTIO_BLOCK_SIZE: usize = 512;
const BLOCK_CACHE_SIZE: usize = 16;

#[allow(unused)]
/// 注意这个函数会破坏文件镜像
pub fn block_device_test() {
    let block_device = BLOCK_DEVICE.clone();
    let mut write_buffer = [0u8; VIRTIO_BLOCK_SIZE];
    let mut read_buffer = [0u8; VIRTIO_BLOCK_SIZE];
    for i in 0..512 {
        for byte in write_buffer.iter_mut() {
            *byte = i as u8;
        }
        block_device.write_blocks(i as usize, &write_buffer);
        block_device.read_blocks(i as usize, &mut read_buffer);
        assert_eq!(write_buffer, read_buffer);
    }
    println!("block device test passed!");
}

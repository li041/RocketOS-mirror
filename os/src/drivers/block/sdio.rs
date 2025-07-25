use dw_sd::DwMmcHost;
use spin::Mutex;

use crate::{
    arch::{config::KERNEL_BASE, timer::get_time},
    mm::{MapArea, MapPermission, MapType, VPNRange, VirtAddr, KERNEL_SPACE},
};

use super::block_dev::BlockDevice;

const SDIO_BASE: usize = 0x16020000;
const MTIME_BASE: usize = 0x0200_BFF8;
// Todo: 需要确定VisionFive2的时钟频率
const TIME_BASE: usize = 4000000;

const BLOCK_SIZE: usize = 512; // Block size in bytes

pub struct MmcDevice {
    device: Mutex<DwMmcHost>,
}

fn get_macros() -> usize {
    // let now = unsafe { ((KERNEL_BASE + MTIME_BASE) as *mut usize).read_volatile() };
    let now = get_time();
    now * 1000000 / TIME_BASE
}

impl MmcDevice {
    pub fn new() -> Self {
        let mmio_base = 0x16020000;
        let size = 0x10000;
        KERNEL_SPACE.lock().push_with_offset(
            MapArea::new(
                VPNRange::new(
                    VirtAddr::from(KERNEL_BASE + mmio_base).floor(),
                    VirtAddr::from(KERNEL_BASE + mmio_base + size).ceil(),
                ),
                MapType::Linear,
                MapPermission::R | MapPermission::W,
                None,
                0,
                false,
            ),
            None,
            0,
        );
        let size = 0x1000;
        KERNEL_SPACE.lock().push_with_offset(
            MapArea::new(
                VPNRange::new(
                    VirtAddr::from(KERNEL_BASE + MTIME_BASE).floor(),
                    VirtAddr::from(KERNEL_BASE + MTIME_BASE + size).ceil(),
                ),
                MapType::Linear,
                MapPermission::R | MapPermission::W,
                None,
                0,
                false,
            ),
            None,
            0,
        );
        // 7.25 Debug
        log::info!("before call get_macros");
        let macros = get_macros();
        log::info!("after call get_macros, macros: {macros}");
        let mut device = DwMmcHost::new(KERNEL_BASE + SDIO_BASE, get_macros);
        device.init().unwrap();
        Self {
            device: Mutex::new(device),
        }
    }
}

impl BlockDevice for MmcDevice {
    fn read_blocks(&self, start_block_id: usize, buf: &mut [u8]) {
        let num_blocks = buf.len() / BLOCK_SIZE;
        assert_eq!(
            buf.len() % BLOCK_SIZE,
            0,
            "Buffer size must be multiple of block size"
        );
        for i in 0..num_blocks {
            let dst = &mut buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
            self.device
                .lock()
                .read_block(start_block_id + i, dst)
                .unwrap();
        }
    }
    fn write_blocks(&self, write_block_id: usize, buf: &[u8]) {
        let num_blocks = buf.len() / BLOCK_SIZE;
        assert_eq!(
            buf.len() % BLOCK_SIZE,
            0,
            "Buffer size must be multiple of block size"
        );
        for i in 0..num_blocks {
            let src = &buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE];
            self.device
                .lock()
                .write_block(write_block_id + i, src)
                .unwrap();
        }
    }
}

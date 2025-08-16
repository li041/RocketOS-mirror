use crate::{Device, DeviceError, DeviceInfo};
use core::fmt::Debug;

/// 设备块大小
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockSize {
    Lb512 = 512,
    Lb4096 = 4096,
}

/// 块设备驱动接口
// pub trait BlockDevice: Device {
//     /// 设备块大小
//     fn block_size(&self) -> BlockSize;
//     /// 从块设备读取数据
//     fn read_block(&mut self, lba: usize, buf: &mut [u8]) -> Result<(), DeviceError>;
//     /// 向块设备写入数据
//     fn write_block(&self, lba: usize, data: &[u8]) -> Result<(), DeviceError>;
//     /// 获取块设备信息
//     fn information(&self) -> &dyn BlkDevInfo;
// }

/// 块设备信息 todo
pub trait BlkDevInfo: DeviceInfo {}

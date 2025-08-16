use crate::{Device, DeviceError, DeviceInfo};

/// 字符设备驱动接口
pub trait CharDevice: Device {
    /// 从字符设备读取字节
    fn get_char(&self) -> Result<u8, DeviceError>;
    /// 向字符设备写入数据
    fn put_char(&self, data: u8) -> Result<(), DeviceError>;
    /// 获取字符设备信息
    fn information(&self) -> &dyn CharDevInfo;
}

/// 字符设备信息 todo
pub trait CharDevInfo: DeviceInfo {}

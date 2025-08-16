use crate::DeviceError;
use core::fmt::Debug;

/// 设备状态信息
#[allow(unused)]
#[derive(Debug, Clone, Copy)]
pub enum DeviceStatus {
    Uninitialized,
    Idle,
    Transfer,
    Error,
    Suspended,
    Stop,
}

/// 设备类型
#[derive(Debug, Clone, Copy)]
pub enum DeviceType {
    Block,
    Char,
    Net,
    Bus,
}

/// 设备接口
pub trait Device: Sync {
    fn init(&mut self) -> Result<(), DeviceError>;
    fn close(&mut self) -> Result<(), DeviceError>;
    fn reinit(&mut self) -> Result<(), DeviceError>;
    fn status(&self) -> DeviceStatus;
    fn device_type(&self) -> DeviceType;
    fn error_handle(&self) -> DeviceStatus;
    // fn id(&self)->u16;
    // fn mmap_reg_addr(&self)->usize;
    // //fn interrupt_msg()
    // fn mmap_addr(&self)->usize;
    // fn io_port(&self)->usize;
}

/// 设备信息
pub trait DeviceInfo: Debug {
    fn name(&self) -> &'static str;
    fn device_type(&self) -> DeviceType;
    fn vendor(&self) -> Option<&'static str>;
    fn hardware_id(&self) -> Option<&'static str>;
}

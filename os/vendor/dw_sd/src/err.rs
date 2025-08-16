use lego_device::DeviceError;

use super::reg::InterruptMask;
use core::fmt::{Debug, Display};

#[derive(Debug, Clone, Copy)]
pub enum CardError {
    CardInitErr,
    InterruptErr(Interrupt),
    TimeoutErr(Timeout),
    VoltagePattern,
    DataTransferTimeout,
}

impl Display for CardError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CardInitErr => write!(f, "Card init failed!"),
            Self::DataTransferTimeout => write!(f, "Data transfer timeout!"),
            Self::InterruptErr(itr) => write!(f, "{}", itr),
            Self::TimeoutErr(to) => write!(f, "{}", to),
            Self::VoltagePattern => write!(f, "Card voltage pattern failed!"),
        }
    }
}

impl From<Timeout> for CardError {
    fn from(value: Timeout) -> Self {
        Self::TimeoutErr(value)
    }
}

impl From<Interrupt> for CardError {
    fn from(value: Interrupt) -> Self {
        Self::InterruptErr(value)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Timeout {
    WaitReset,
    WaitCmdLine,
    WaitCmdDone,
    WaitDataLine,
    FifoStatus,
}

impl Display for Timeout {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Timeout::WaitReset => write!(f, "Card wait reset timeout!"),
            Timeout::WaitCmdLine => write!(f, "Card wait command line timeout!"),
            Timeout::WaitCmdDone => write!(f, "Card wait command done timeout!"),
            Timeout::WaitDataLine => write!(f, "Card wait data line timeout!"),
            Timeout::FifoStatus => write!(f, "Card fifo status exception!"),
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub enum Interrupt {
    ResponseTimeout,
    ResponseErr,
    ResponseCrc,
    EndBitErr,
    StartBitErr,
    HardwareLock,
    Fifo,
    DataReadTimeout,
    DataCrc,
}

impl Interrupt {
    pub fn check(mask: u32) -> Result<(), Interrupt> {
        let mut ret = Ok(());

        if mask & InterruptMask::dcrc.bits() != 0 {
            ret = Err(Interrupt::DataCrc);
        }
        if mask & InterruptMask::drto.bits() != 0 {
            ret = Err(Interrupt::DataReadTimeout);
        }
        if mask & InterruptMask::frun.bits() != 0 {
            ret = Err(Interrupt::Fifo);
        }
        if mask & InterruptMask::hle.bits() != 0 {
            ret = Err(Interrupt::HardwareLock);
        }
        if mask & InterruptMask::sbe.bits() != 0 {
            ret = Err(Interrupt::StartBitErr);
        }
        if mask & InterruptMask::ebe.bits() != 0 {
            ret = Err(Interrupt::EndBitErr);
        }
        ret
    }
}

impl Display for Interrupt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Interrupt::ResponseTimeout => write!(f, "Card response timeout interrupt!"),
            Interrupt::ResponseErr => write!(f, "Card response error interrupt!"),
            Interrupt::EndBitErr => write!(f, "Card end bit error interrupt!"),
            Interrupt::StartBitErr => write!(f, "Card  start bit error interrupt!"),
            Interrupt::HardwareLock => write!(f, "Card hardware lock interrupt!"),
            Interrupt::Fifo => write!(f, "Card fifo error interrupt!"),
            Interrupt::DataReadTimeout => write!(f, "Card data read timeout interrupt!"),
            Interrupt::DataCrc => write!(f, "Card data crc error interrupt!"),
            Interrupt::ResponseCrc => write!(f, "Card response crc error interrupt!"),
        }
    }
}

impl From<CardError> for DeviceError {
    fn from(value: CardError) -> Self {
        match value {
            CardError::CardInitErr => DeviceError::InvalidConfiguration,
            CardError::InterruptErr(_) => DeviceError::IoError,
            CardError::TimeoutErr(_) => DeviceError::Timeout,
            CardError::VoltagePattern => DeviceError::UnsupportedOperation,
            CardError::DataTransferTimeout => DeviceError::IoError,
        }
    }
}

impl From<Timeout> for DeviceError {
    fn from(_value: Timeout) -> Self {
        DeviceError::Timeout
    }
}

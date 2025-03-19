use self::spin_mutex::SpinMutex;

/// SpinMutex
pub mod spin_mutex;
/// let's use `SpinNoIrqLock`
/// SpinNoIrqLock(Cannot be interrupted)
pub type SpinNoIrqLock<T> = SpinMutex<T, SpinNoIrq>;

#[cfg(target_arch = "riscv64")]
mod riscv;

#[cfg(target_arch = "riscv64")]
pub use riscv::*;

#[cfg(target_arch = "loongarch64")]
mod la64;

#[cfg(target_arch = "loongarch64")]
pub use la64::*;

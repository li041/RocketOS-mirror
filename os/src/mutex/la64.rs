//! Mutex support

use crate::arch::CrMd;

/// Low-level support for mutex (spinlock, sleeplock, etc)
pub trait MutexSupport {
    /// Guard data
    type GuardData;
    /// Called before lock() & try_lock()
    fn before_lock() -> Self::GuardData;
    /// Called when MutexGuard drops
    fn after_unlock(_: &mut Self::GuardData);
}

/// Spin MutexSupport
pub struct Spin;

impl MutexSupport for Spin {
    type GuardData = ();
    #[inline(always)]
    fn before_lock() -> Self::GuardData {}
    #[inline(always)]
    fn after_unlock(_: &mut Self::GuardData) {}
}

/// IE Guard
pub struct IeGuard(bool);

impl IeGuard {
    /// Construct an IeGuard
    pub fn new() -> Self {
        Self({
            let mut crmd = CrMd::read();
            let ie_before = crmd.is_interrupt_enabled();
            crmd.set_ie(false);
            crmd.write();
            ie_before
        })
    }
}

impl Drop for IeGuard {
    fn drop(&mut self) {
        if self.0 {
            let mut crmd = CrMd::read();
            crmd.set_ie(true);
            crmd.write();
        }
    }
}

/// SpinNoIrq MutexSupport
pub struct SpinNoIrq;

impl MutexSupport for SpinNoIrq {
    type GuardData = IeGuard;
    #[inline(always)]
    fn before_lock() -> Self::GuardData {
        IeGuard::new()
    }
    #[inline(always)]
    fn after_unlock(_: &mut Self::GuardData) {}
}

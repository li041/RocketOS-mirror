#![cfg_attr(not(test), no_std)]
#![doc = include_str!("../README.md")]

use core::cell::UnsafeCell;
use core::fmt;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

/// A wrapper of a lazy initialized value.
///
/// It implements [`Deref`] and [`DerefMut`]. The caller must use the dereference
/// operation after initialization, otherwise it will panic.
pub struct LazyInit<T> {
    inited: AtomicBool,
    data: UnsafeCell<MaybeUninit<T>>,
}

unsafe impl<T: Send + Sync> Sync for LazyInit<T> {}
unsafe impl<T: Send> Send for LazyInit<T> {}

impl<T> LazyInit<T> {
    /// Creates a new uninitialized value.
    pub const fn new() -> Self {
        Self {
            inited: AtomicBool::new(false),
            data: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// Initializes the value once and only once.
    ///
    /// # Panics
    ///
    /// Panics if the value is already initialized.
    pub fn init_once(&self, data: T) -> &T {
        match self
            .inited
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        {
            Ok(_) => {
                unsafe { (*self.data.get()).as_mut_ptr().write(data) };
                unsafe { self.force_get() }
            }
            Err(_) => panic!("Already initialized"),
        }
    }

    /// Performs an initialization routine once and only once.
    ///
    /// If the value is already initialized, the function will not be called
    /// and a [`None`] will be returned.
    pub fn call_once<F>(&self, f: F) -> Option<&T>
    where
        F: FnOnce() -> T,
    {
        match self
            .inited
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        {
            Ok(_) => {
                unsafe { (*self.data.get()).as_mut_ptr().write(f()) };
                Some(unsafe { self.force_get() })
            }
            Err(_) => None,
        }
    }

    /// Checks whether the value is initialized.
    pub fn is_inited(&self) -> bool {
        self.inited.load(Ordering::Acquire)
    }

    /// Gets a reference to the value.
    ///
    /// Returns [`None`] if the value is not initialized.
    pub fn get(&self) -> Option<&T> {
        if self.is_inited() {
            Some(unsafe { self.force_get() })
        } else {
            None
        }
    }

    /// Gets a mutable reference to the value.
    ///
    /// Returns [`None`] if the value is not initialized.
    pub fn get_mut(&mut self) -> Option<&mut T> {
        if self.is_inited() {
            Some(unsafe { self.force_get_mut() })
        } else {
            None
        }
    }

    /// Gets the reference to the value without checking if it is initialized.
    ///
    /// # Safety
    ///
    /// Must be called after initialization.
    #[inline]
    pub unsafe fn get_unchecked(&self) -> &T {
        debug_assert!(self.is_inited());
        self.force_get()
    }

    /// Get a mutable reference to the value without checking if it is initialized.
    ///
    /// # Safety
    ///
    /// Must be called after initialization.
    #[inline]
    pub unsafe fn get_mut_unchecked(&mut self) -> &mut T {
        debug_assert!(self.is_inited());
        self.force_get_mut()
    }

    #[inline]
    unsafe fn force_get(&self) -> &T {
        (*self.data.get()).assume_init_ref()
    }

    #[inline]
    unsafe fn force_get_mut(&mut self) -> &mut T {
        (*self.data.get()).assume_init_mut()
    }

    fn panic_message(&self) -> ! {
        panic!(
            "Use uninitialized value: {:?}",
            core::any::type_name::<Self>()
        )
    }
}

impl<T: fmt::Debug> fmt::Debug for LazyInit<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.get() {
            Some(s) => write!(f, "LazyInit {{ data: ")
                .and_then(|()| s.fmt(f))
                .and_then(|()| write!(f, "}}")),
            None => write!(f, "LazyInit {{ <uninitialized> }}"),
        }
    }
}

impl<T> Default for LazyInit<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Deref for LazyInit<T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        if self.is_inited() {
            unsafe { self.force_get() }
        } else {
            self.panic_message()
        }
    }
}

impl<T> DerefMut for LazyInit<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        if self.is_inited() {
            unsafe { self.force_get_mut() }
        } else {
            self.panic_message()
        }
    }
}

impl<T> Drop for LazyInit<T> {
    fn drop(&mut self) {
        if self.is_inited() {
            unsafe { core::ptr::drop_in_place((*self.data.get()).as_mut_ptr()) };
        }
    }
}

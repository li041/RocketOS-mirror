// use crate::task::processor::{current_process, get_local_hart};
// use crate::task::INITPROC;
use core::{
    cell::UnsafeCell,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, Ordering},
};

// use riscv::register::sstatus;

use super::MutexSupport;

/*========================= Spin Mutex ====================================*/
/// T: 互斥锁保护的数据类型。在 SpinMutex 结构体中，T: ?Sized 表示 T 可以是任何大小的类型，包括零大小类型。如果不加 ?Sized 限制，则 T 必须是已知大小的类型。
/// S: 代表附加互斥锁支持功能的 trait,
pub struct SpinMutex<T: ?Sized, S: MutexSupport> {
    // debug_cnt: UnsafeCell<usize>,
    lock: AtomicBool,
    _marker: PhantomData<S>,
    data: UnsafeCell<T>, // 实际被保护的数据，包装在 UnsafeCell 中以进行原始访问
}

/*
 类型参数 S 被声明了但没有在结构体的字段或方法中被使用。
 在Rust中，如果你声明了一个类型参数但没有使用它，编译器会认为它是多余的，因此会发出警告。使用 PhantomData 作为标记：
 如果你想要保留 S 作为某种形式的标记或为了将来的扩展，但目前不需要在结构体中存储任何与 S 相关的数据，你可以使用
 PhantomData。PhantomData 是一种特殊的标记类型，它不占用任何实际的空间，但会强制编译器考虑类型 S 的存在。
*/

// Forbid Mutex step over `await` and lead to dead lock
impl<'a, T: ?Sized, S: MutexSupport> !Sync for MutexGuard<'a, T, S> {}
impl<'a, T: ?Sized, S: MutexSupport> !Send for MutexGuard<'a, T, S> {}

unsafe impl<T: ?Sized + Send, S: MutexSupport> Sync for SpinMutex<T, S> {}
unsafe impl<T: ?Sized + Send, S: MutexSupport> Send for SpinMutex<T, S> {}

impl<'a, T, S: MutexSupport> SpinMutex<T, S> {
    /// 新建一个锁
    pub const fn new(user_data: T) -> Self {
        SpinMutex {
            lock: AtomicBool::new(false),
            _marker: PhantomData,
            data: UnsafeCell::new(user_data),
            // debug_cnt: UnsafeCell::new(0),
        }
    }

    /// 消耗 SpinMutex 并返回底层数据, 我们假设没有对要消耗的 SpinMutex 的未解决引用。
    /// 如果代码中还有其他部分持有此 SpinMutex 的锁，则直接访问数据可能会导致未定义行为或数据竞争。
    pub fn into_inner(self) -> T {
        // 在静态分析中我们知道不存在对`self`的未解决引用，所以不需要lock
        // 使用解构来提取 SpinMutex 实例中的字段。指示提取 data 字段以及其他所有字段（使用 .. 通配符）。
        let SpinMutex { data, .. } = self;
        data.into_inner()
    }

    /// &mut T: 可变引用，指向 T 类型的对象。它允许您修改对象的内容。
    #[inline(always)]
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }

    /// *mut T: 裸指针，指向 T 类型的对象的内存地址。它允许您直接访问对象的内存，但您需要负责管理内存安全。
    #[inline(always)]
    pub fn get_ptr(&self) -> *mut T {
        self.data.get()
    }

    ///它不需要调用者持有锁，但只能用于修改数据，不能读取数据。该方法是 unsafe 的，因为它可能导致数据竞争或其他安全问题。
    #[inline(always)]
    pub unsafe fn unsafe_get(&self) -> &T {
        &*self.data.get()
    }

    /// 自行管理复杂性
    #[allow(clippy::mut_from_ref)]
    #[inline(always)]
    pub unsafe fn unsafe_get_mut(&self) -> &mut T {
        &mut *self.data.get()
    }

    /// Wait until the lock looks unlocked before retrying
    #[inline(always)]
    fn wait_unlock(&self) {
        //let mut try_count = 0usize;
        while self.lock.load(Ordering::Relaxed) {
            core::hint::spin_loop();
        }
    }

    /// Note that the locked data cannot step over `await`,
    /// i.e. cannot be sent between thread.
    #[inline(always)]
    pub fn lock(&self) -> impl DerefMut<Target = T> + '_ {
        let support_guard = S::before_lock();
        loop {
            self.wait_unlock();
            if self
                .lock
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                // println!("[lock] by {}", get_local_hart().hart_id,);
                break;
            }
        }

        MutexGuard {
            mutex: self,
            support_guard,
        }
    }

    /// 尝试锁上一个mutex，如果已经上锁了，None，不然就MutexGuard，里面有个some.
    #[inline(always)]
    pub fn try_lock(&self) -> Option<impl DerefMut<Target = T> + '_> {
        // 这是lw，没有使用原子操作
        if self.lock.load(Ordering::Relaxed) {
            return None;
        }
        let mut support_guard = S::before_lock();
        if self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            // debug!(
            //     "[lock] by {}, cur pid is {}",
            //     get_local_hart().hart_id,
            //     get_local_hart().current().unwrap().pid.0
            // );
            Some(MutexGuard {
                mutex: self,
                support_guard,
            })
        } else {
            S::after_unlock(&mut support_guard);
            None
        }
    }
}

/* ======================= Mutex Guard =============================*/

/// 实际上来讲是锁的一个wrapper, lock的时候会自动上Mutex Guard
struct MutexGuard<'a, T: ?Sized, S: MutexSupport> {
    mutex: &'a SpinMutex<T, S>,
    support_guard: S::GuardData,
}

impl<'a, T: ?Sized, S: MutexSupport> Deref for MutexGuard<'a, T, S> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<'a, T: ?Sized, S: MutexSupport> DerefMut for MutexGuard<'a, T, S> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<'a, T: ?Sized, S: MutexSupport> Drop for MutexGuard<'a, T, S> {
    /// The dropping of the MutexGuard will release the lock it was created from.
    #[inline(always)]
    fn drop(&mut self) {
        assert!(self.mutex.lock.load(Ordering::Relaxed));
        // println!("[auto unlock] by {}", get_local_hart().hart_id,);
        self.mutex.lock.store(false, Ordering::Release);
        S::after_unlock(&mut self.support_guard);
    }
}

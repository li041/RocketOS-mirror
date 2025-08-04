//! Implementation of physical and virtual address.

use core::fmt::{Debug, Formatter};

use alloc::fmt;

use crate::arch::config::{KERNEL_BASE, PAGE_SIZE_BITS};
use crate::arch::mm::PageTableEntry;

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysAddr(pub usize);

impl From<usize> for PhysAddr {
    fn from(addr: usize) -> Self {
        Self(addr)
    }
}

impl From<PhysAddr> for usize {
    fn from(addr: PhysAddr) -> Self {
        addr.0
    }
}

impl From<PhysPageNum> for PhysAddr {
    fn from(ppn: PhysPageNum) -> Self {
        Self(ppn.0 << PAGE_SIZE_BITS)
    }
}

impl PhysAddr {
    /// `PhysAddr` to `PhysPageNum`
    pub fn floor(&self) -> PhysPageNum {
        PhysPageNum(self.0 >> PAGE_SIZE_BITS)
    }
    /// `PhysAddr` to `PhysPageNum`
    pub fn ceil(&self) -> PhysPageNum {
        if self.0 == 0 {
            return PhysPageNum(0);
        }
        PhysPageNum((self.0 + (1 << PAGE_SIZE_BITS) - 1) >> PAGE_SIZE_BITS)
    }
    /// get page offset
    pub fn page_offset(&self) -> usize {
        self.0 & ((1 << PAGE_SIZE_BITS) - 1)
    }
    /// check page aligned
    pub fn is_page_aligned(&self) -> bool {
        self.page_offset() == 0
    }
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtAddr(pub usize);

impl From<usize> for VirtAddr {
    fn from(addr: usize) -> Self {
        Self(addr)
    }
}

impl From<VirtAddr> for usize {
    fn from(addr: VirtAddr) -> Self {
        addr.0
    }
}

impl VirtAddr {
    /// `VirtAddr` to `VirtPageNum`
    pub fn floor(&self) -> VirtPageNum {
        VirtPageNum(self.0 >> PAGE_SIZE_BITS)
    }
    /// `VirtAddr` to `VirtPageNum`
    pub fn ceil(&self) -> VirtPageNum {
        if self.0 == 0 {
            return VirtPageNum(0);
        }
        // 注意这里要先减1, 因为对于kstack_id = 0的栈top为0xffff_ffff_ffff_f000, 会溢出
        VirtPageNum((self.0 - 1 + (1 << PAGE_SIZE_BITS)) >> PAGE_SIZE_BITS)
    }
    /// Get page offset
    pub fn page_offset(&self) -> usize {
        self.0 & ((1 << PAGE_SIZE_BITS) - 1)
    }
    /// Check page aligned
    pub fn is_page_aligned(&self) -> bool {
        self.page_offset() == 0
    }
}

pub trait StepByOne {
    fn step(&mut self);
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysPageNum(pub usize);

impl From<usize> for PhysPageNum {
    fn from(addr: usize) -> Self {
        // Self(addr & ((1 << PPN_WIDTH_SV39) - 1))
        Self(addr)
    }
}

impl StepByOne for PhysPageNum {
    fn step(&mut self) {
        self.0 += 1;
    }
}

// 注意通过ppn获取对应物理页帧仍然是使用虚拟地址, 内核虚拟地址空间偏移KERNEL_BASE(0xffff_ffc0_0000_0000)
// 映射关系是在entry.asm中设置的
// riscv64对内核虚拟地址空间进行了偏移, 而loongarch64是直接映射
impl PhysPageNum {
    /// Get `PageTableEntry` on `PhysPageNum`
    pub fn get_pte_array(&self) -> &'static mut [PageTableEntry] {
        let pa = PhysAddr::from(*self);
        let va = VirtAddr::from(pa.0 + KERNEL_BASE);
        let ptr = va.0 as *mut PageTableEntry;
        unsafe { core::slice::from_raw_parts_mut(ptr, 512) }
    }
    /// Get u8 array on `PhysPageNum`
    pub fn get_bytes_array(&self) -> &'static mut [u8] {
        let pa = PhysAddr::from(*self);
        let va = VirtAddr::from(pa.0 + KERNEL_BASE);
        let ptr = va.0 as *mut u8;
        unsafe { core::slice::from_raw_parts_mut(ptr, 4096) }
    }
    /// Get mutable reference to T on `PhysPageNum`
    pub fn get_mut<T>(&self) -> &'static mut T {
        let pa = PhysAddr::from(*self);
        let va = VirtAddr::from(pa.0 + KERNEL_BASE);
        let ptr = va.0 as *mut T;
        unsafe { &mut *ptr }
    }
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtPageNum(pub usize);

impl From<usize> for VirtPageNum {
    fn from(addr: usize) -> Self {
        Self(addr)
    }
}

impl VirtPageNum {
    ///Return VPN 3 level index
    pub fn indexes(&self) -> [usize; 3] {
        let mut vpn = self.0;
        let mut idx = [0usize; 3];
        for i in (0..3).rev() {
            idx[i] = vpn & 511;
            vpn >>= 9;
        }
        idx
    }
}

impl StepByOne for VirtPageNum {
    fn step(&mut self) {
        self.0 += 1;
    }
}

impl Debug for VirtAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("va: {:#x}", self.0))
    }
}
impl Debug for VirtPageNum {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("vpn: {:#x}", self.0))
    }
}
impl Debug for PhysAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("pa: {:#x}", self.0))
    }
}
impl Debug for PhysPageNum {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("ppn: {:#x}", self.0))
    }
}

#[derive(Copy, Clone, PartialEq)]
pub struct SimpleRange<T>
where
    T: StepByOne + Copy + PartialEq + PartialOrd + Debug,
{
    l: T,
    r: T,
}
impl<T> SimpleRange<T>
where
    T: StepByOne + Copy + PartialEq + PartialOrd + Debug,
{
    pub fn new(start: T, end: T) -> Self {
        debug_assert!(start <= end, "start {:?} > end {:?}!", start, end);
        Self { l: start, r: end }
    }
    #[inline(always)]
    pub fn get_start(&self) -> T {
        self.l
    }
    pub fn get_end(&self) -> T {
        self.r
    }
    pub fn set_start(&mut self, start: T) {
        self.l = start;
    }
    pub fn set_end(&mut self, end: T) {
        self.r = end;
    }
    pub fn is_intersect_with(&self, other: &Self) -> bool {
        self.l < other.r && self.r > other.l
    }
    pub fn is_contain(&self, other: &Self) -> bool {
        self.l <= other.l && self.r >= other.r
    }
}

impl<T> IntoIterator for SimpleRange<T>
where
    T: StepByOne + Copy + PartialEq + PartialOrd + Debug,
{
    type Item = T;
    type IntoIter = SimpleRangeIterator<T>;
    fn into_iter(self) -> Self::IntoIter {
        SimpleRangeIterator::new(self.l, self.r)
    }
}
pub struct SimpleRangeIterator<T>
where
    T: StepByOne + Copy + PartialEq + PartialOrd + Debug,
{
    current: T,
    end: T,
}
impl<T> SimpleRangeIterator<T>
where
    T: StepByOne + Copy + PartialEq + PartialOrd + Debug,
{
    pub fn new(l: T, r: T) -> Self {
        Self { current: l, end: r }
    }
}
impl<T> Iterator for SimpleRangeIterator<T>
where
    T: StepByOne + Copy + PartialEq + PartialOrd + Debug,
{
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        if self.current == self.end {
            None
        } else {
            let t = self.current;
            self.current.step();
            Some(t)
        }
    }
}
pub type VPNRange = SimpleRange<VirtPageNum>;

impl VPNRange {
    pub fn contains_vpn(self, other: VirtPageNum) -> bool {
        self.get_start() <= other && other < self.get_end()
    }
    pub fn intersection(&self, other: &Self) -> Option<Self> {
        let start: VirtPageNum = self.get_start().max(other.get_start());
        let end: VirtPageNum = self.get_end().min(other.get_end());
        if start < end {
            Some(VPNRange::new(start, end))
        } else {
            None
        }
    }
}

impl Debug for VPNRange {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!(
            "{:#x}, {:#x}",
            self.get_start().0,
            self.get_end().0
        ))
    }
}

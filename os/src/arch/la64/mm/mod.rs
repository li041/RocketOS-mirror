use frame_allocator::{frame_allocator_test, init_frame_allocator};
#[cfg(feature = "test")]
use heap_allocator::heap_test;

use crate::{
    arch::{
        config::{DIR_WIDTH, PAGE_SIZE_BITS, PTE_WIDTH},
        CrMd, TLBREHi, DMW0, DMW1, DMW2, DMW3, PWCH, PWCL, STLBPS,
    },
    mm::heap_allocator::init_heap,
};

pub use address::{PhysAddr, PhysPageNum, StepByOne, VPNRange, VirtAddr, VirtPageNum};

mod address;
pub mod frame_allocator;
// mod memory_set;

pub fn init() {
    init_heap();
    init_frame_allocator();
}

// 配置页表格式
pub fn mmu_init() {
    // 直接映射配置窗口
    println!("DMW0: {:?}", DMW0::read());
    println!("DMW1: {:?}", DMW1::read());
    println!("DMW2: {:?}", DMW2::read());
    println!("DMW3: {:?}", DMW3::read());

    // STLB
    // STLB页大小为`2^(ps)` byte, 例如`ps=0xc`时，页大小为`2^12=4KB`
    assert!(STLBPS::read().get_ps() == 0xc);
    println!("TLBREHi: {:?}", TLBREHi::read());

    // 设置页表遍历控制寄存器PWC(PWCL + PWCH)
    // loongarch支持5级页表, 这里设置为Sv39
    // 页大小为4KB, PTEWidth为8字节, 页表索引位数为9
    // PWCL::read()
    //     .set_ptbase(PAGE_SIZE_BITS)
    //     .set_ptwidth(DIR_WIDTH)
    //     .set_dir1_base(PAGE_SIZE_BITS + DIR_WIDTH)
    //     .set_dir2_base(0)
    //     .set_dir2_width(0)
    //     .set_pte_width(PTE_WIDTH)
    //     .write();
    // PWCH::read()
    //     .set_dir3_base(PAGE_SIZE_BITS + DIR_WIDTH * 2)
    //     .set_dir3_base(DIR_WIDTH)
    //     .set_dir4_base(0)
    //     .set_dir4_base(0)
    //     .write();
    log::error!("PWCL: {:?}", PWCL::read());
    log::error!("PWCH: {:?}", PWCH::read());
    // CrMd::read()
    //     .set_watchpoint_enabled(false)
    //     .set_paging(true)
    //     .set_ie(false)
    //     .write();
}

// Todo:
pub fn copy_to_user<T: Copy>(to: *mut T, from: *const T, n: usize) -> Result<usize, &'static str> {
    todo!()
}

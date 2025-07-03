pub mod boards;
pub mod config;
pub mod drivers;
pub mod lang_items;
pub mod mm;
mod register;
pub mod sbi;
pub mod serial;
pub mod switch;
pub mod timer;
mod tlb;
pub mod trampoline;
pub mod trap;
pub mod virtio_blk;

global_asm!(include_str!("entry.S"));
global_asm!(include_str!("tlb_refill.S"));

use core::arch::{asm, global_asm};

use config::{DIR_WIDTH, PAGE_SIZE, PAGE_SIZE_BITS, PTE_WIDTH, SUC_DMW_VESG};
use lazy_static::lazy_static;
pub use register::*;
use spin::lazy;
pub use virtio_blk::VirtIOBlock;

extern "C" {
    fn __rfill();
}

pub fn bootstrap_init() {
    // 扩展部件使能, 使能基础浮点指令
    EUEn::read().set_float_point_stat(true).write();
    // 清除时钟中断标记
    TIClr::read().clear_timer().write();
    // 清除时钟中断使能
    TCfg::read().set_enable(false).write();
    // 启用分页(注意, 此时内核代码通过DMW0直接映射)
    CrMd::read()
        .set_watchpoint_enabled(false)
        .set_paging(true)
        .set_ie(false)
        .write();

    // Todo: 设置TLB重填例外处理函数地址, Ok
    TLBREntry::read().set_addr(__rfill as usize).write();

    // 设置页表相关, STLBPS, TLBRHI, PWCL
    // Todo: IMPACR的STLBPS和TLBrEHI的set_page_size都是`PTE_WIDTH_BITS`, 跟文档的语义不太对
    // 目前是根据文档的语义, 而不是参考IMPACE
    STLBPS::read().set_ps(PAGE_SIZE_BITS).write();
    TLBREHi::read().set_page_size(PAGE_SIZE).write();
    // 设置页表遍历控制寄存器PWC(PWCL + PWCH)
    // loongarch支持5级页表, 这里设置为Sv39
    // Todo: 为什么设置dir3, 而不设置dir2?
    PWCL::read()
        .set_ptbase(PAGE_SIZE_BITS)
        .set_ptwidth(DIR_WIDTH)
        .set_dir1_base(PAGE_SIZE_BITS + DIR_WIDTH)
        .set_dir1_width(DIR_WIDTH) // 512*512*4096 should be enough for 256MiB of 2k500.
        .set_dir2_base(PAGE_SIZE_BITS + DIR_WIDTH * 2)
        .set_dir2_width(DIR_WIDTH)
        .set_pte_width(PTE_WIDTH)
        .write();
    PWCH::read()
        .set_dir3_base(0)
        .set_dir3_width(0)
        .set_dir4_base(0)
        .set_dir4_width(0)
        .write();
    // 初始化tlb
    unsafe {
        core::arch::asm!("invtlb 0x0, $r0, $r0");
    }
    log::error!("PWCL: {:?}", PWCL::read());
    log::error!("PWCH: {:?}", PWCH::read());
    // 输出配置寄存器信息
    println!("[bootstrap_init] {:?}", PRCfg1::read());
    show_address_len();
}

/// loongarch中CPUCFG支持软件在执行过程中动态识别处理器的属性
/// 根据字号读取CPUCFG对应字
pub fn cpu_config_read(index: usize) -> usize {
    let value: usize;
    unsafe {
        asm!(
            "cpucfg {0}, {1}",
            out(reg) value,
            in(reg) index,
        );
    }
    value
}

pub fn show_address_len() {
    let cpu_cfg1 = cpu_config_read(1);
    let palen = ((cpu_cfg1 >> 4) & 0xFF) + 1;
    let valen = ((cpu_cfg1 >> 12) & 0xFF) + 1;
    log::error!("PALEN: {}, VALEN: {}", palen, valen);
}

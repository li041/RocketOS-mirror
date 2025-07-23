#[cfg(target_arch = "riscv64")]
use crate::arch::timer::{read_rtc, GOLDFISH_RTC_BASE, NANOS_PER_SEC};
use crate::arch::virtio_blk::HalImpl;
use crate::drivers::net::VirtioNetDevice;
use crate::utils::seconds_to_beijing_datetime;
use crate::{
    arch::config::KERNEL_BASE,
    mm::{MapArea, MapPermission, MapType, VPNRange, VirtAddr, KERNEL_SPACE},
};
use alloc::vec::Vec;
pub use block::BLOCK_DEVICE;
use core::arch::asm;
use core::ptr::NonNull;
use fdt::{self, node::FdtNode};
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
use virtio_drivers::transport::DeviceType;
use virtio_drivers::transport::Transport; // Bring the trait into scope

pub mod block;
pub mod net;
pub(crate) fn get_dev_tree_size(addr: usize) -> usize {
    // 安全地解析设备树
    let dev_tree = unsafe { fdt::Fdt::from_ptr(addr as *const u8).unwrap() };

    // 直接获取设备树的总大小
    let total_size = dev_tree.total_size();
    println!(
        "[get_dev_tree_size]:Device tree total size: {} bytes",
        total_size
    );
    total_size
}
#[cfg(target_arch = "riscv64")]
pub fn init_device(addr: usize) -> usize {
    let dev_tree = unsafe { fdt::Fdt::from_ptr((addr + KERNEL_BASE) as *const u8).unwrap() };

    // println!("{:?}",size_cells);
    for node in dev_tree.all_nodes() {
        for prop in node.properties() {
            log::error!("{},{}", node.name, prop.name);
        }
    }
    for node in dev_tree.all_nodes() {
        if node.name == "soc" {
            for node_t in node.children() {
                let address_cells = node
                    .properties()
                    .find(|prop| prop.name == "#address-cells")
                    .unwrap()
                    .value[3];
                let size_cells = node
                    .properties()
                    .find(|prop| prop.name == "#size-cells")
                    .unwrap()
                    .value[3];
                let reg = parse_reg(&node_t, address_cells as usize, size_cells as usize);
                if reg.is_empty() {
                    continue;
                }
                let mmio_base = reg.get(0).unwrap().0;
                let mmio_size = reg.get(0).unwrap().1;
                log::error!(
                    "[init_device]:net device node_t name is {:?} mmio base {:#x} mmio size {:?}",
                    node_t.name,
                    mmio_base,
                    mmio_size
                );
                KERNEL_SPACE.lock().push_with_offset(
                    MapArea::new(
                        VPNRange::new(
                            VirtAddr::from(KERNEL_BASE + mmio_base).floor(),
                            VirtAddr::from(KERNEL_BASE + mmio_base + mmio_size).ceil(),
                        ),
                        MapType::Linear,
                        MapPermission::R | MapPermission::W,
                        None,
                        0,
                        false,
                    ),
                    None,
                    0,
                );
                // unsafe {
                //     asm!("sfence.vma");
                // }
                if node_t.name.contains("rtc") {
                    GOLDFISH_RTC_BASE.lock().replace(mmio_base);
                }
                if node_t.name == "virtio_mmio@10008000" {
                    let header =
                        NonNull::new((KERNEL_BASE + mmio_base) as *mut VirtIOHeader).unwrap();
                    // log::error!("[init_net_device]:addr:{:?}",unsafe{core::slice::from_raw_parts((KERNEL_BASE+mmio_base) as *const usize, 0x20)});
                    let a = unsafe {
                        core::slice::from_raw_parts((KERNEL_BASE + mmio_base) as *const u8, 30)
                    };
                    log::error!("[init_device] part is {:?}", a);
                    let transport = match unsafe { MmioTransport::new(header) } {
                        Ok(t) => t,
                        Err(e) => panic!("{}", e),
                    };
                    log::error!("[init_device]:the transport vendor_id is {:#x},version is {:?},device_type:{:?}",transport.vendor_id(),transport.version(),transport.device_type());
                    let dev = VirtioNetDevice::<32, HalImpl, MmioTransport>::new(transport);
                    log::error!("[init_device]:the dev has built");
                    crate::net::init(Some(dev));
                }
                #[cfg(feature = "vf2")]
                if node_t.name == "ethernet@16030000" {
                    crate::net::init_vf2();
                }
            }
        }
    }
    return 0;
}

//解析设备 compatibel中的reg中的mmio_base mmio_size，基本返回的就是2各元素
fn parse_reg(node: &FdtNode, addr_cells: usize, size_cells: usize) -> Vec<(usize, usize)> {
    let reg_property = node.properties().find(|prop| prop.name == "reg");

    // 如果没有找到 "reg" 属性，返回一个空的 Vec
    if let Some(prop) = reg_property {
        let reg = prop.value;
        let reg: &[u32] = bytemuck::cast_slice(reg); // Big endian
        let mut res = Vec::new();
        for pos in (0..reg.len()).step_by(addr_cells + size_cells) {
            let phys_start = reg[pos..pos + addr_cells]
                .iter()
                .fold(0, |acc, &x| acc << 32 | x.swap_bytes() as usize);
            let size = reg[pos + addr_cells..pos + addr_cells + size_cells]
                .iter()
                .fold(0, |acc, &x| acc << 32 | x.swap_bytes() as usize);
            res.push((phys_start, size));
        }
        res
    } else {
        // 如果没有 "reg" 属性，返回空的 Vec
        Vec::new()
    }
}

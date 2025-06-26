use fdt::{node::FdtNode, standard_nodes::Compatible, Fdt};

use core::ptr::NonNull;

use virtio_drivers::{
    device::blk::VirtIOBlk,
    transport::{
        mmio::{MmioTransport, VirtIOHeader},
        pci::{
            bus::{Cam, PciRoot},
            virtio_device_type, PciTransport,
        },
        DeviceType, Transport,
    },
};

use crate::{
    arch::{
        config::DEVICE_TREE_ADDR,
        drivers::mem_allocator::{allocate_bars, dump_bar_contents, PciMemory32Allocator},
        virtio_blk::HalImpl,
    },
    drivers::net::init_net_dev_la,
};

fn virtio_device(transport: impl Transport + 'static) {
    match transport.device_type() {
        DeviceType::Block => virtio_blk(transport),
        DeviceType::Network => {
            log::trace!("[initlize net]");
            virtio_net(transport)
        }
        t => log::warn!("Unsupported VirtIO device type {:?}", t),
    }
}

// 动态的Virtual IO块设备
fn virtio_blk<T: Transport>(transport: T) {
    let blk = VirtIOBlk::<HalImpl, T>::new(transport).expect("failed to create blk driver");
    debug_assert!(!blk.readonly());
}
//在enumerate_pci过来初始化网络
#[cfg(target_arch = "loongarch64")]
fn virtio_net<T: Transport + 'static>(transport: T) {
    log::trace!("[virtio_net] pci virtio_net device init");
    crate::drivers::net::init_net_dev_la(transport);
}

// 读取设备树, 识别VirtIO设备
pub fn init() {
    let fdt = unsafe {
        Fdt::from_ptr(DEVICE_TREE_ADDR as *const u8).expect("failed to parse device tree")
    };
    for node in fdt.all_nodes() {
        // Dump information about the node for debugging.
        log::warn!(
            "{}: {:?}",
            node.name,
            node.compatible().map(Compatible::first),
        );
        if let Some(reg) = node.reg() {
            for range in reg {
                log::warn!(
                    "  {:#018x?}, length {:?}",
                    range.starting_address,
                    range.size
                );
            }
        }

        // Check whether it is a VirtIO MMIO device.
        if let (Some(compatible), Some(region)) =
            (node.compatible(), node.reg().and_then(|mut reg| reg.next()))
        {
            if compatible.all().any(|s| s == "virtio,mmio")
                && region.size.unwrap_or(0) > size_of::<VirtIOHeader>()
            {
                log::warn!("Found VirtIO MMIO device at {:?}", region);

                let header = NonNull::new(region.starting_address as *mut VirtIOHeader).unwrap();
                match unsafe { MmioTransport::new(header) } {
                    Err(e) => log::warn!("Error creating VirtIO MMIO transport: {}", e),
                    Ok(transport) => {
                        log::warn!(
                            "Detected virtio MMIO device with vendor id {:#X}, device type {:?}, version {:?}",
                            transport.vendor_id(),
                            transport.device_type(),
                            transport.version(),
                        );
                        virtio_device(transport);
                    }
                }
            }
        }
    }

    if let Some(pci_node) = fdt.find_compatible(&["pci-host-cam-generic"]) {
        log::error!("Found PCI node {:?}", pci_node);
        enumerate_pci(pci_node, Cam::MmioCam);
    }

    // loongarch: 0x20000000 ~ 0x28000000
    if let Some(pcie_node) = fdt.find_compatible(&["pci-host-ecam-generic"]) {
        log::error!("Found PCIe node: {}", pcie_node.name);
        enumerate_pci(pcie_node, Cam::Ecam);
    }
}

fn enumerate_pci(pci_node: FdtNode, cam: Cam) {
    let reg = pci_node.reg().expect("PCI node missing reg property.");
    let mut allocator = PciMemory32Allocator::for_pci_ranges(&pci_node);

    for region in reg {
        log::info!(
            "Reg: {:?}-{:#x}",
            region.starting_address,
            region.starting_address as usize + region.size.unwrap()
        );
        // Safe because we know the pointer is to a valid MMIO region.
        let mut pci_root = unsafe { PciRoot::new(region.starting_address as *mut u8, cam) };
        for (device_function, info) in pci_root.enumerate_bus(0) {
            let (status, command) = pci_root.get_status_command(device_function);
            log::info!(
                "Found {} at {}, status {:?} command {:?}",
                info,
                device_function,
                status,
                command
            );
            if let Some(virtio_type) = virtio_device_type(&info) {
                log::info!("  VirtIO {:?}", virtio_type);
                allocate_bars(&mut pci_root, device_function, &mut allocator);
                dump_bar_contents(&mut pci_root, device_function, 4);
                let mut transport =
                    PciTransport::new::<HalImpl>(&mut pci_root, device_function).unwrap();
                log::info!(
                    "Detected virtio PCI device with device type {:?}, features {:#018x}",
                    transport.device_type(),
                    transport.read_device_features(),
                );
                virtio_device(transport);
            }
        }
    }
}

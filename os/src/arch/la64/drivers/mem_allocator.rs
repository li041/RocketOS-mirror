use core::ptr;
use fdt::node::FdtNode;
use virtio_drivers::transport::pci::bus::{
    BarInfo, Command, DeviceFunction, MemoryBarType, PciRoot,
};

/// Allocates 32-bit memory addresses for PCI BARs.
pub struct PciMemory32Allocator {
    start: u32,
    end: u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum PciRangeType {
    ConfigurationSpace,
    IoSpace,
    Memory32,
    Memory64,
}

impl From<u8> for PciRangeType {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::ConfigurationSpace,
            1 => Self::IoSpace,
            2 => Self::Memory32,
            3 => Self::Memory64,
            _ => panic!("Tried to convert invalid range type {}", value),
        }
    }
}

impl PciMemory32Allocator {
    /// Creates a new allocator based on the ranges property of the given PCI node.
    pub fn for_pci_ranges(pci_node: &FdtNode) -> Self {
        let ranges = pci_node
            .property("ranges")
            .expect("PCI node missing ranges property.");
        let mut memory_32_address = 0;
        let mut memory_32_size = 0;
        for i in 0..ranges.value.len() / 28 {
            let range = &ranges.value[i * 28..(i + 1) * 28];
            let prefetchable = range[0] & 0x80 != 0;
            let range_type = PciRangeType::from(range[0] & 0x3);
            let cpu_physical = u64::from_be_bytes(range[12..20].try_into().unwrap());
            let bus_address = u64::from_be_bytes(range[4..12].try_into().unwrap());
            let size = u64::from_be_bytes(range[20..28].try_into().unwrap());
            log::info!(
                "range: {:?} {}prefetchable bus address: {:#018x} host physical address: {:#018x} size: {:#018x}",
                range_type,
                if prefetchable { "" } else { "non-" },
                bus_address,
                cpu_physical,
                size,
            );
            // Use the largest range within the 32-bit address space for 32-bit memory, even if it
            // is marked as a 64-bit range. This is necessary because crosvm doesn't currently
            // provide any 32-bit ranges.
            if !prefetchable
                && matches!(range_type, PciRangeType::Memory32 | PciRangeType::Memory64)
                && size > memory_32_size.into()
                && bus_address + size < u32::MAX.into()
            {
                assert_eq!(bus_address, cpu_physical);
                memory_32_address = u32::try_from(cpu_physical).unwrap();
                memory_32_size = u32::try_from(size).unwrap();
            }
        }
        if memory_32_size == 0 {
            panic!("No 32-bit PCI memory region found.");
        }
        Self {
            start: memory_32_address,
            end: memory_32_address + memory_32_size,
        }
    }

    /// Allocates a 32-bit memory address region for a PCI BAR of the given power-of-2 size.
    ///
    /// It will have alignment matching the size. The size must be a power of 2.
    pub fn allocate_memory_32(&mut self, size: u32) -> u32 {
        assert!(size.is_power_of_two());
        let allocated_address = align_up(self.start, size);
        assert!(allocated_address + size <= self.end);
        self.start = allocated_address + size;
        allocated_address
    }
}

const fn align_up(value: u32, alignment: u32) -> u32 {
    ((value - 1) | (alignment - 1)) + 1
}

pub fn dump_bar_contents(root: &mut PciRoot, device_function: DeviceFunction, bar_index: u8) {
    let bar_info = root.bar_info(device_function, bar_index).unwrap();
    log::trace!("Dumping bar {}: {:#x?}", bar_index, bar_info);
    if let BarInfo::Memory { address, size, .. } = bar_info {
        let start = address as *const u8;
        unsafe {
            let mut buf = [0u8; 32];
            for i in 0..size / 32 {
                let ptr = start.add(i as usize * 32);
                ptr::copy(ptr, buf.as_mut_ptr(), 32);
                if buf.iter().any(|b| *b != 0xff) {
                    log::trace!("  {:?}: {:x?}", ptr, buf);
                }
            }
        }
    }
    log::trace!("End of dump");
}

/// Allocates appropriately-sized memory regions and assigns them to the device's BARs.
pub fn allocate_bars(
    root: &mut PciRoot,
    device_function: DeviceFunction,
    allocator: &mut PciMemory32Allocator,
) {
    for (bar_index, info) in root.bars(device_function).unwrap().into_iter().enumerate() {
        let Some(info) = info else { continue };
        log::debug!("BAR {}: {}", bar_index, info);
        // Ignore I/O bars, as they aren't required for the VirtIO driver.
        if let BarInfo::Memory {
            address_type, size, ..
        } = info
        {
            match address_type {
                MemoryBarType::Width32 => {
                    if size > 0 {
                        let address = allocator.allocate_memory_32(size);
                        log::debug!("Allocated address {:#010x}", address);
                        root.set_bar_32(device_function, bar_index as u8, address);
                    }
                }
                MemoryBarType::Width64 => {
                    if size > 0 {
                        let address = allocator.allocate_memory_32(size);
                        log::debug!("Allocated address {:#010x}", address);
                        root.set_bar_64(device_function, bar_index as u8, address.into());
                    }
                }

                _ => panic!("Memory BAR address type {:?} not supported.", address_type),
            }
        }
    }

    // Enable the device to use its BARs.
    root.set_command(
        device_function,
        Command::IO_SPACE | Command::MEMORY_SPACE | Command::BUS_MASTER,
    );
    let (status, command) = root.get_status_command(device_function);
    log::debug!(
        "Allocated BARs and enabled device, status {:?} command {:?}",
        status,
        command
    );
}

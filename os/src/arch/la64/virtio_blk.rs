use fdt::{node::FdtNode, standard_nodes::Compatible, Fdt};
use spin::Mutex;

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

use core::{
    alloc::Layout,
    ptr::{self},
};

use buddy_system_allocator::FrameAllocator;
use lazy_static::lazy_static;

use alloc::{
    alloc::{alloc_zeroed, dealloc, handle_alloc_error},
    boxed::Box,
    vec::Vec,
};
use virtio_drivers::{BufferDirection, Hal};

use crate::{
    arch::drivers::mem_allocator::{allocate_bars, dump_bar_contents, PciMemory32Allocator},
    drivers::block::block_dev::BlockDevice,
};

pub struct VirtIOBlock(Mutex<VirtIOBlk<HalImpl, PciTransport>>);

use crate::arch::config::PAGE_SIZE;

use zerocopy::FromZeroes;

use super::config::DEVICE_TREE_ADDR;

pub struct HalImpl;

unsafe impl Hal for HalImpl {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (usize, NonNull<u8>) {
        assert_ne!(pages, 0);
        let layout = Layout::from_size_align(pages * PAGE_SIZE, PAGE_SIZE).unwrap();
        // Safe because the size and alignment of the layout are non-zero.
        let ptr = unsafe { alloc_zeroed(layout) };
        if let Some(ptr) = NonNull::new(ptr) {
            (ptr.as_ptr() as usize, ptr)
        } else {
            handle_alloc_error(layout);
        }
    }

    unsafe fn dma_dealloc(_paddr: usize, vaddr: NonNull<u8>, pages: usize) -> i32 {
        assert_ne!(pages, 0);
        let layout = Layout::from_size_align(pages * PAGE_SIZE, PAGE_SIZE).unwrap();
        // Safe because the layout is the same as was used when the memory was allocated by
        // `dma_alloc` above.
        unsafe {
            dealloc(vaddr.as_ptr(), layout);
        }
        0
    }

    unsafe fn mmio_phys_to_virt(paddr: usize, _size: usize) -> NonNull<u8> {
        NonNull::new(paddr as _).unwrap()
    }

    unsafe fn share(buffer: NonNull<[u8]>, direction: BufferDirection) -> usize {
        assert_ne!(buffer.len(), 0);
        // To ensure that the driver is handling and unsharing buffers properly, allocate a new
        // buffer and copy to it if appropriate.
        let mut shared_buffer = u8::new_box_slice_zeroed(buffer.len());
        if let BufferDirection::DriverToDevice | BufferDirection::Both = direction {
            unsafe {
                buffer
                    .as_ptr()
                    .cast::<u8>()
                    .copy_to(shared_buffer.as_mut_ptr(), buffer.len());
            }
        }
        let vaddr = Box::into_raw(shared_buffer) as *mut u8 as usize;
        // Nothing to do, as the host already has access to all memory.
        virt_to_phys(vaddr)
    }

    unsafe fn unshare(paddr: usize, buffer: NonNull<[u8]>, direction: BufferDirection) {
        assert_ne!(buffer.len(), 0);
        assert_ne!(paddr, 0);
        let vaddr = phys_to_virt(paddr);
        let shared_buffer = unsafe {
            Box::from_raw(ptr::slice_from_raw_parts_mut(
                vaddr as *mut u8,
                buffer.len(),
            ))
        };
        if let BufferDirection::DeviceToDriver | BufferDirection::Both = direction {
            unsafe {
                buffer
                    .as_ptr()
                    .cast::<u8>()
                    .copy_from(shared_buffer.as_ptr(), buffer.len());
            }
        }
    }
}

pub fn virt_to_phys(vaddr: usize) -> usize {
    vaddr
}

pub fn phys_to_virt(paddr: usize) -> usize {
    paddr
}

impl BlockDevice for VirtIOBlock {
    fn read_blocks(&self, start_block_id: usize, buf: &mut [u8]) {
        self.0
            .lock()
            .read_blocks(start_block_id, buf)
            .expect("Error when reading VirtIOBlk");
    }
    fn write_blocks(&self, write_block_id: usize, buf: &[u8]) {
        self.0
            .lock()
            .write_blocks(write_block_id, buf)
            .expect("Error when writing VirtIOBlk");
    }
}

// 适用于pci-host-ecam-generic
fn virtio_blk_pci(transport: PciTransport) -> VirtIOBlock {
    let blk =
        VirtIOBlk::<HalImpl, PciTransport>::new(transport).expect("failed to create blk driver");
    debug_assert!(!blk.readonly());
    VirtIOBlock(Mutex::new(blk))
}

impl VirtIOBlock {
    // pub fn new() -> Self {
    //     let fdt = unsafe {
    //         Fdt::from_ptr(DEVICE_TREE_ADDR as *const u8).expect("failed to parse device tree")
    //     };
    //     if let Some(pci_node) = fdt.find_compatible(&["pci-host-ecam-generic"]) {
    //         log::info!("Found PCI node {:?}", pci_node.name);
    //         // virtio_blk_pci(transport)
    //         let reg = pci_node.reg().expect("failed to get reg property");
    //         let mut allocator = PciMemory32Allocator::for_pci_ranges(&pci_node);
    //         // assert!(reg.count() == 1);
    //         for region in reg {
    //             log::info!(
    //                 "  {:#018x?}, length {:#x}",
    //                 region.starting_address,
    //                 region.size.unwrap()
    //             );
    //             let mut pci_root =
    //                 unsafe { PciRoot::new(region.starting_address as *mut u8, Cam::Ecam) };
    //             for (device_function, info) in pci_root.enumerate_bus(0) {
    //                 let (status, command) = pci_root.get_status_command(device_function);
    //                 log::info!(
    //                     "Found {} at {}, status {:?} command {:?}",
    //                     info,
    //                     device_function,
    //                     status,
    //                     command
    //                 );
    //                 // Todo: 扫描到了网络设备, 但是未做处理
    //                 if let Some(virtio_type) = virtio_device_type(&info) {
    //                     log::info!("  VirtIO {:?}", virtio_type);
    //                     if virtio_type == DeviceType::Block {
    //                         allocate_bars(&mut pci_root, device_function, &mut allocator);
    //                         dump_bar_contents(&mut pci_root, device_function, 4);
    //                         let mut transport =
    //                             PciTransport::new::<HalImpl>(&mut pci_root, device_function)
    //                                 .unwrap();
    //                         log::info!(
    //                         "Detected virtio PCI device with device type {:?}, features {:#018x}",
    //                         transport.device_type(),
    //                         transport.read_device_features(),
    //                     );
    //                         return virtio_blk_pci(transport);
    //                     }
    //                 }
    //             }
    //         }
    //         panic!("failed to find virtio_blk");
    //     } else {
    //         panic!("failed to find pci-host-ecam-generic node");
    //     }
    // }
    pub fn new() -> Self {
        let fdt = unsafe {
            Fdt::from_ptr(DEVICE_TREE_ADDR as *const u8).expect("failed to parse device tree")
        };
        if let Some(pci_node) = fdt.find_compatible(&["pci-host-ecam-generic"]) {
            log::info!("Found PCI node {:?}", pci_node.name);
            let reg = pci_node.reg().expect("failed to get reg property");
            let mut allocator = PciMemory32Allocator::for_pci_ranges(&pci_node);

            for region in reg {
                log::info!(
                    "  {:#018x?}, length {:#x}",
                    region.starting_address,
                    region.size.unwrap()
                );
                let mut pci_root =
                    unsafe { PciRoot::new(region.starting_address as *mut u8, Cam::Ecam) };
                let mut blk_index = 0; // 用于计数第几个 virtio-blk 设备
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
                        if virtio_type == DeviceType::Block {
                            if blk_index == 1 {
                                // 第2个 virtio-blk（drive=x1）
                                allocate_bars(&mut pci_root, device_function, &mut allocator);
                                dump_bar_contents(&mut pci_root, device_function, 4);
                                let mut transport =
                                    PciTransport::new::<HalImpl>(&mut pci_root, device_function)
                                        .unwrap();
                                log::info!(
                                    "Using 2nd Virtio Block device, features: {:#018x}",
                                    transport.read_device_features(),
                                );
                                return virtio_blk_pci(transport);
                            } else {
                                blk_index += 1;
                            }
                        }
                    }
                }
            }
            panic!("failed to find second virtio_blk device (drive=x1)");
        } else {
            panic!("failed to find pci-host-ecam-generic node");
        }
    }
}

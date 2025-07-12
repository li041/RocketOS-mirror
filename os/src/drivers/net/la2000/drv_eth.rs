#![allow(dead_code, unused_assignments, unused_mut)]

use crate::arch::config::KERNEL_BASE;
use crate::arch::virtio_blk::phys_to_virt;
use crate::drivers::net::la2000::eth_defs::*;
use crate::drivers::net::la2000::eth_dev::*;
use crate::drivers::net::la2000::platform::*;
use crate::drivers::net::netdevice::NetBufPtr;
use crate::mm::MapArea;
use crate::mm::MapPermission;
use crate::mm::MapType;
use crate::mm::VPNRange;
use crate::mm::VirtAddr;
use crate::mm::KERNEL_SPACE;
use crate::task::current_task;
use crate::task::kernel_exit;

// 检查rgmii链路状态
// platform_update_linkstate通知操作系统链路状态
pub fn eth_phy_rgsmii_check(gmacdev: &mut net_device) {
    let mut value: u32 = 0;
    let mut status: u32 = 0;

    value = eth_mac_read_reg(gmacdev.MacBase, GmacRgsmiiStatus);
    status = value & (MacLinkStatus >> MacLinkStatusOff);

    if gmacdev.LinkStatus != status {
        unsafe { platform_update_linkstate(gmacdev, status) };
    }

    if status != 0 {
        gmacdev.LinkStatus = 1;
        gmacdev.DuplexMode = value & MacLinkMode;
        let mut speed: u32 = value & MacLinkSpeed;
        if speed == MacLinkSpeed_125 {
            gmacdev.Speed = 1000;
        } else if speed == MacLinkSpeed_25 {
            gmacdev.Speed = 100;
        } else {
            gmacdev.Speed = 10;
        }
        
            println!("Link is Up - {:?} Mpbs / {:?} Duplex",gmacdev.Speed,
                if gmacdev.DuplexMode != 0 {
                    "Full" 
                } else {
                    "Half"
                },
            );
    } else {
        gmacdev.LinkStatus = 0;
        println!("please check net connection,Link is Down");
        kernel_exit(current_task(), 5);
    };
}

// 初始化phy
pub fn eth_phy_init(gmacdev: &mut net_device) {
    let mut phy: u32 = 0;
    let mut data: u32 = 0;

    data = eth_mdio_read(gmacdev.MacBase, gmacdev.PhyBase as u32, 2) as u32;
    phy |= data << 16;
    data = eth_mdio_read(gmacdev.MacBase, gmacdev.PhyBase as u32, 3) as u32;
    phy |= data;

    match phy {
        0x0000010a => {
            
                println!(
                    "probed ethernet phy YT8511H/C, id {:#x?}",
                    phy,
                );
        }
        _ => {
                println!(
                    "probed unknown ethernet phy, id {:#x}",
                    phy,
                );
        }
    };
}

pub fn eth_handle_tx_over(gmacdev: &mut net_device) {
    loop {
        log::info!("eth_handle_tx_over loop");
        let mut desc_idx: u32 = gmacdev.TxBusy;
        let mut txdesc: DmaDesc = unsafe { gmacdev.TxDesc[desc_idx as usize].read() } as DmaDesc;
        log::info!("[eth_handle_tx_over] txdesc is {:?}",txdesc);
        if eth_get_desc_owner(&txdesc) || eth_is_desc_empty(&txdesc) {
            log::info!("[eth_handle_tx_over] recover handle complete");
            break;
        }

        if eth_is_tx_desc_valid(&txdesc) {
            let mut length: u32 = (txdesc.length & DescSize1Mask) >> DescSize1Shift;
            gmacdev.tx_bytes += length as u64;
            gmacdev.tx_packets += 1;
            log::info!("[eth_is_tx_desc_valid] no error length is {:?}",length);
        } else {
            log::info!("[eth_is_tx_desc_valid] send desc has error");
            gmacdev.tx_errors += 1;
        }

        let is_last: bool = eth_is_last_tx_desc(&txdesc);
        txdesc.status =if is_last { TxDescEndOfRing } else { 0 };
        txdesc.length =  0;
        txdesc.buffer1 = 0;
        txdesc.buffer2 = 0;
        unsafe {
            gmacdev.TxDesc[desc_idx as usize].write(txdesc);
            log::info!("[eth_handle_tx_over] after write txdesc is {:?}",gmacdev.TxDesc[desc_idx as usize]);
            let mut res: DmaDesc = unsafe { gmacdev.TxDesc[desc_idx as usize].read() } as DmaDesc;
            log::info!("[eth_handle_tx_over] txdesc is {:?}",res);
        }
        gmacdev.TxBusy = if is_last { 0 } else { desc_idx + 1 };
        sync_dcache();
    }

    log::info!("[eth_handle_tx_over] return");
    return;
}

// 操作系统传递接收数据的单元pbuf给驱动
// pbuf可能是操作系统自定义结构
// 返回接收到的数据字节数
pub fn eth_tx(gmacdev: &mut net_device, pbuf: NetBufPtr) -> i32 {
    log::info!("[eth_tx]begin tx");
    let mut buffer: u64 = 0;
    let mut length: u32 = pbuf.packcet_len as u32;
    let mut dma_addr: u32 = 0;
    let mut desc_idx: u32 = gmacdev.TxNext;
    log::info!("[eth_tx] tx desc addr is {:?}",gmacdev.TxDesc[desc_idx as usize]);
    let mut txdesc: DmaDesc = unsafe { gmacdev.TxDesc[desc_idx as usize].read_volatile() } as DmaDesc;
    log::info!("[eth_tx] txdesc is {:?}",txdesc);
    let mut is_last: bool = eth_is_last_tx_desc(&txdesc);

    if eth_get_desc_owner(&txdesc) {
        return -1;
    }

    // buffer = gmacdev.TxBuffer[desc_idx as usize];
    // length = unsafe { plat_handle_tx_buffer(pbuf, buffer) };
    dma_addr = unsafe { plat_virt_to_phys(pbuf.packet().as_ptr() as usize as u64) };
    // //todo length >2048
    txdesc.status |= DescOwnByDma | DescTxIntEnable | DescTxLast | DescTxFirst;
    txdesc.length = length << DescSize1Shift & DescSize1Mask;
    log::info!("[eth_tx] length is {:?}",length);
    txdesc.buffer1 = dma_addr;
    txdesc.buffer2 = 0;
    unsafe {
        gmacdev.TxDesc[desc_idx as usize].write_volatile(txdesc);
        log::info!("[eth_tx] write addr is {:?}",gmacdev.TxDesc[desc_idx as usize]);
        let mut res: DmaDesc = unsafe { gmacdev.TxDesc[desc_idx as usize].read_volatile() } as DmaDesc;
        log::info!("[eth_tx] after write txdesc is {:?}",txdesc);
    }

    gmacdev.TxNext = if is_last { 0 } else { desc_idx + 1 };

    unsafe { sync_dcache() };

    eth_gmac_resume_dma_tx(gmacdev);
    log::info!("[eth_tx] tx end");

    return 0;
}
#[derive(Copy, Clone,Default,Debug)]
#[repr(C)]
pub struct AddrLen {
    pub addr: u64,
    pub len:  u32,
}
// pbuf是返回给操作系统的数据单元
// 可能是操作系统自定义结构
pub fn eth_rx(gmacdev: &mut net_device) -> AddrLen {
    log::info!("[eth_rx]begin rx");
    let mut desc_idx: u32 = gmacdev.RxBusy;
    let mut rxdesc: DmaDesc = unsafe { gmacdev.RxDesc[desc_idx as usize].read() } as DmaDesc;
    let mut is_last: bool = eth_is_last_rx_desc(&rxdesc);

    if eth_is_desc_empty(&rxdesc) || eth_get_desc_owner(&rxdesc) {
        //eth_dma_enable_interrupt(gmacdev, DmaIntEnable);
        return AddrLen{addr:0,len:0}
    }

    let mut pbuf: u64 = 0;
    let mut dma_addr = rxdesc.buffer1;
    let mut len:u32=0;
    if eth_is_rx_desc_valid(&rxdesc) {
        let mut length: u32 = eth_get_rx_length(&rxdesc);
        len=length;
        let mut buffer: u64 = unsafe { plat_phys_to_virt(dma_addr) };

        unsafe {
            sync_dcache();
        }
        //log::info!("[eth_rx] rx desc {:?}",rxdesc);
        pbuf = unsafe { plat_handle_rx_buffer(buffer, length) };
        gmacdev.rx_bytes += length as u64;
        gmacdev.rx_packets += 1;
    } else {
        gmacdev.rx_errors += 1;
    }

    rxdesc.status = DescOwnByDma;
    rxdesc.length = if is_last { RxDescEndOfRing } else { 0 };
    rxdesc.length |= (4096) << DescSize1Shift & DescSize1Mask;
    rxdesc.buffer1 = dma_addr;
    rxdesc.buffer2 = 0;
    unsafe {
        gmacdev.RxDesc[desc_idx as usize].write(rxdesc);
    }
        unsafe {
        sync_dcache();
    }
    gmacdev.RxBusy = if is_last { 0 } else { desc_idx + 1 };
    log::info!("[eth_tx] rx end");
    return AddrLen { addr: pbuf, len: len }
}
pub fn eth_phy_scan(gmacdev:&mut net_device,phybase:u64){

}


// 中断处理程序
// plat_rx_ready通知操作系统可以接收数据
// eth_handle_tx_over用于处理已经发送完的描述符
pub fn eth_irq(gmacdev: &mut net_device) {
    let mut dma_status: u32 = 0;
    let mut dma_int_enable: u32 = DmaIntEnable;

    dma_status = eth_mac_read_reg(gmacdev.DmaBase, DmaStatus);
    if dma_status == 0 {
        return;
    }

    //eth_dma_disable_interrupt_all(gmacdev);

    if dma_status & GmacPmtIntr != 0 {
        println!("gmac pmt interrupt");
    }
    if dma_status & GmacMmcIntr != 0 {
        println!("gmac mmc interrupt");
    }
    if dma_status & GmacLineIntfIntr != 0 {
        eth_mac_read_reg(gmacdev.MacBase, GmacInterruptStatus);
        eth_mac_read_reg(gmacdev.MacBase, GmacInterruptMask);
        if eth_mac_read_reg(gmacdev.MacBase, GmacInterruptStatus) & GmacRgmiiIntSts != 0 {
            eth_mac_read_reg(gmacdev.MacBase, GmacRgsmiiStatus);
        }
        eth_phy_rgsmii_check(gmacdev);
    }

    eth_mac_write_reg(gmacdev.DmaBase, DmaStatus, dma_status);

    if dma_status & DmaIntBusError != 0 {
        println!("gmac fatal bus error interrupt");
    }
    if dma_status & DmaIntRxStopped != 0 {
        println!("gmac receive process stopped");
        eth_dma_enable_rx(gmacdev);
    }
    if dma_status & DmaIntRxNoBuffer != 0 {
        println!("gmac receive buffer unavailable");
        dma_int_enable &= !DmaIntRxNoBuffer;
        eth_gmac_resume_dma_rx(gmacdev);
        unsafe { plat_rx_ready(gmacdev) };
    }
    if dma_status & DmaIntRxCompleted != 0 {
        dma_int_enable &= !DmaIntRxCompleted;
        unsafe { plat_rx_ready(gmacdev) };
    }
    if dma_status & DmaIntTxUnderflow != 0 {
        println!("gmac transmit underflow");
    }
    if dma_status & DmaIntRcvOverflow != 0 {
        println!("gmac receive underflow");
    }
    if dma_status & DmaIntTxNoBuffer != 0 {}
    if dma_status & DmaIntTxStopped != 0 {
        println!("gmac transmit process stopped");
    }
    if dma_status & DmaIntTxCompleted != 0 {
        eth_handle_tx_over(gmacdev);
    }
    //eth_dma_enable_interrupt(gmacdev, dma_int_enable);
}

// 初始化
pub fn eth_init(gmacdev: &mut net_device) -> net_device {
    println!("eth_init begin");
    // 在eth_init内或外，利用uncached地址初始化结构体的iobase
    println!("[eth_init] kerner map complete");
    gmacdev.MacBase = gmacdev.iobase + 0x0000;
    gmacdev.DmaBase = gmacdev.iobase + 0x1000;
    gmacdev.PhyBase = 0;
    gmacdev.Version = eth_mac_read_reg(gmacdev.MacBase, GmacVersion);
    println!("[eth_init]eth_mac_read_reg complete version is {:#x?}",gmacdev.Version);
    let mut mac_addr:[u8;6]=[0; 6];
    eth_gmac_get_mac_addr(&gmacdev,&mut mac_addr);
     println!("[eth_init]eth_gmac_get_mac_addr is {:#x?}",mac_addr);
    eth_dma_reset(gmacdev);
    println!("[eth_init]eth_dma_reset complete");
    eth_mac_set_addr(gmacdev);
    println!("[eth_init]eth_mac_set_addr complete");
    eth_phy_init(gmacdev);
    println!("[eth_init]eth_phy_init complete");
    eth_setup_rx_desc_queue(gmacdev, 128);
    println!("[eth_init]eth_setup_rx_desc_queue complete");
    eth_setup_tx_desc_queue(gmacdev,128);
    println!("[eth_init]eth_setup_tx_desc_queue complete");

    eth_dma_reg_init(gmacdev);
    println!("[eth_init]eth_dma_reg_init complete");
    eth_gmac_reg_init(gmacdev);
    println!("[eth_init]eth_gmac_reg_init complete");
    unsafe { sync_dcache() };

    eth_gmac_disable_mmc_irq(gmacdev);
    println!("[eth_init]eth_gmac_disable_mmc_irq complete");
    eth_dma_clear_curr_irq(gmacdev);
    println!("[eth_init]eth_dma_clear_curr_irq complete");
    // eth_dma_enable_interrupt(gmacdev, DmaIntEnable);
    // println!("[eth_init]eth_dma_enable_interrupt complete");
    // eth_dma_disable_interrupt_all(gmacdev);
    // println!("[eth_init]eth_dma_disable_interrupt_all complete");
    eth_gmac_enable_rx(gmacdev);
    println!("[eth_init]eth_gmac_enable_rx complete");
    eth_gmac_enable_tx(gmacdev);
    println!("[eth_init]eth_gmac_enable_tx complete");
    eth_dma_enable_rx(gmacdev);
    println!("[eth_init]eth_dma_enable_rx complete");
    eth_dma_enable_tx(gmacdev);
    println!("[eth_init]eth_dma_enable_tx complete");

    unsafe { plat_isr_install() };

    // return 0;
    *gmacdev
}

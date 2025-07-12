use core::{arch::asm, marker::PhantomData, mem, ptr::{copy_nonoverlapping, read_volatile, write_volatile, NonNull}};

use crate::{arch::{config::KERNEL_BASE, virtio_blk::{phys_to_virt, virt_to_phys}}, drivers::net::{self, config::{ DESC_RXSTS_FRMLENMSK, DESC_RXSTS_FRMLENSHFT, DMA_BUS_MODE, DMA_CHAN_BASE_ADDR, DMA_CHAN_CONTROL, DMA_CHAN_CUR_RX_BUF_ADDR, DMA_CHAN_RX_BASE_ADDR, DMA_CHAN_RX_CONTROL, DMA_CHAN_RX_END_ADDR, DMA_CHAN_RX_RING_LEN, DMA_CHAN_STATUS, DMA_CHAN_TX_BASE_ADDR, DMA_CHAN_TX_CONTROL, DMA_CHAN_TX_END_ADDR, DMA_CHAN_TX_RING_LEN, DMA_CONTROL_SR, DMA_CONTROL_ST, DMA_STATUS_RS_MASK, DMA_STATUS_RS_SHIFT, DMA_STATUS_TS_MASK, DMA_STATUS_TS_SHIFT, DMA_XMT_POLL_DEMAND, GMAC_CONFIG_RE, GMAC_CONFIG_TE, GMAC_QX_TX_FLOW_CTRL, GMAC_RXQ_CTRL0, MAC_ADDR_HI, MAC_ADDR_LO, MAC_ENABLE_RX, MAC_ENABLE_TX, MII_BUSY, MTL_CHAN_BASE_ADDR, MTL_CHAN_RX_OP_MODE, MTL_RXQ_DMA_MAP0, RX_DESC_START, RX_SKB_BUF_START, TX_SKB_BUF_START}, netdevice::{NetBufPtr, NetDevice}, ring::{RxDes, RxRing, TxDes, TxRing}, NetBuf, NetBufBox, NetBufPool}, mm::{MapArea, MapType, VPNRange, VirtAddr}};
use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec::Vec};
use virtio_drivers::Hal;
use smoltcp::{
    phy::{DeviceCapabilities, Medium},
    wire::{self, EthernetAddress},
};
use zerocopy::big_endian::U32;
use crate::mm::{KERNEL_SPACE,MapPermission};
const NET_BUF_LEN: usize = 1536;
const TX_BUF_SIZE: usize = 1536;
static mut TX_BUFFERS: [[u8; TX_BUF_SIZE]; 64] = [[0; TX_BUF_SIZE]; 64];
/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-07-25 20:56:10
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-07-26 18:45:19
 * @FilePath: /RocketOS_netperfright/os/src/drivers/net/starfive.rs
 * @Description: 
 * 
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved. 
 */
// //this file will generate the driver for the StarFive network controller
// pub trait Starfive2Hal {
//     fn phys_to_virt(pa: usize) -> usize {
//         pa
//     }
//     fn virt_to_phys(va: usize) -> usize {
//         va
//     }

//     fn dma_alloc_pages(pages: usize) -> (usize, usize);

//     fn dma_free_pages(vaddr: usize, pages: usize);

//     fn mdelay(m_times: usize);

//     fn fence();
// }
pub fn dump_reg() {
    let ioaddr = 0x16040000;
    log::info!("------------------------------dumpreg--------------------------------------");
    for i in 0..25 {
        let value = unsafe { read_volatile(phys_to_virt(ioaddr + 0x00001100 + i * 4) as *mut u32) };
        if i==0 {
            log::info!("reg DMA_CHAN_CONTROL = {:#x?}", value);
        }
        else if i==1 {
            log::info!("reg DMA_CHAN_TX_CONTROL ={:#x?}", value);
        }else if i==2 {
            log::info!("reg DMA_CHAN_RX_CONTROL  = {:#x?}", value);
        }else if i==4 {
            log::info!("reg DMA_CHAN_TX_BASE_ADDR_HI = {:#x?}", value);
        }
        else if i==5 {
            log::info!("reg DMA_CHAN_TX_BASE_ADDR = {:#x?}", value);
        }
        else if i==6 {
            log::info!("reg DMA_CHAN_RX_BASE_ADDR_HI = {:#x?}", value);
        }
        else if i==7 {
            log::info!("reg DMA_CHAN_RX_BASE_ADDR = {:#x?}", value);
        }
        else if i==8 {
            log::info!("reg DMA_CHAN_TX_END_ADDR = {:#x?}", value);
        }
        else if i==10 {
            log::info!("reg DMA_CHAN_RX_END_ADDR = {:#x?}", value);
        }
        else if i==11 {
            log::info!("reg DMA_CHAN_TX_RING_LEN = {:#x?}", value);
        }
        else if i==12 {
            log::info!("reg DMA_CHAN_RX_RING_LEN = {:#x?}", value);
        }
        else if i==13 {
            log::info!("reg DMA_CHAN_INTR_ENA = {:#x?}", value);
        }
        else if i==14 {
            log::info!("reg DMA_CHAN_RX_WATCHDOG = {:#x?}", value);
        }
        else if i==15 {
            log::info!("reg DMA_CHAN_SLOT_CTRL_STATUS = {:#x?}", value);
        }
        else if i==17 {
            log::info!("reg DMA_CHAN_CUR_TX_DESC = {:#x?}", value);
        }
        else if i==19 {
            log::info!("reg DMA_CHAN_CUR_RX_DESC = {:#x?}", value);
        }
        else if i==21 {
            log::info!("reg DMA_CHAN_CUR_TX_BUF_ADDR = {:#x?}", value);
        }
        else if i==23 {
            log::info!("reg DMA_CHAN_CUR_RX_BUF_ADDR = {:#x?}", value);
        }
        else if i==24 {
            log::info!("reg DMA_CHAN_STATUS = {:#x?}", value);
            
        }
    }
}

pub fn dump_tx_status() {
    let status=unsafe { read_volatile(phys_to_virt(0x16040000 + DMA_CHAN_STATUS) as *const u32) };
    let state = (status & DMA_STATUS_TS_MASK) >> DMA_STATUS_TS_SHIFT;
    if state == 0 {
        log::debug!("- TX (Stopped): Reset or Stop command");
    } else if state == 1 {
        log::debug!("- TX (Running): Fetching the Tx desc");
    } else if state == 2 {
        log::debug!("- TX (Running): Waiting for end of tx");
    } else if state == 3 {
        log::debug!("- TX (Running): Reading the data and queuing the data into the Tx buf");
    } else if state == 6 {
        log::debug!("- TX (Suspended): Tx Buff Underflow or an unavailable Transmit descriptor");
    } else if state == 7 {
        log::debug!("- TX (Running): Closing Tx descriptor");
    } else {
        log::debug!("unknown state {}, optionally handle or ignore", state);
    }
}
pub fn dump_rx_status() {
    let status=unsafe { read_volatile(phys_to_virt(0x16040000 + DMA_CHAN_STATUS) as *const u32) };
    let state = (status & DMA_STATUS_RS_MASK) >> DMA_STATUS_RS_SHIFT;
    if state == 0 {
        log::debug!("- RX (Stopped): Reset or Stop command");
    } else if state == 1 {
        log::debug!("- RX (Running): Fetching the Rx desc");
    } else if state == 2 {
        log::debug!("- RX (Running): Checking for end of pkt");
    } else if state == 3 {
        log::debug!("- RX (Running): Waiting for Rx pkt");
    } else if state == 4 {
        log::debug!("- RX (Suspended): Unavailable Rx buf");
    } else if state == 5 {
        log::debug!("- RX (Running): Closing Rx descriptor");
    } else if state == 6 {
        log::debug!("- RX (Running): Flushing the current frame from the Rx buf");
    } else if state == 7 {
        log::debug!("- RX (Running): Queuing the Rx frame from the Rx buf into memory");
    } else {
        log::debug!("unknown state {}, optionally handle or ignore", state);
    }
}
pub struct Starfive2NetDevice<const QS:usize,A: Hal> {
    pub rx_ring: RxRing<A>,
    pub tx_ring: TxRing<A>,
    phantom: PhantomData<A>,
}

impl<const QS:usize,A: Hal> Starfive2NetDevice<QS,A> {
    pub fn new() -> Self {
        // let ioaddr = phys_to_virt(0x16040000);
        // log::info!("---------init clk-------------");
        unsafe {
        //     for i in 97..112 {
        //         write_volatile(phys_to_virt(0x13020000 + i * 4) as *mut u32, 0x80000000);
        //     }
            KERNEL_SPACE.lock().push_with_offset(
                MapArea::new(
                    VPNRange::new(
                        VirtAddr::from(KERNEL_BASE + 0x17000000).floor(),
                        VirtAddr::from(KERNEL_BASE + 0x17000000 + 65536).ceil(),
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
            KERNEL_SPACE.lock().push_with_offset(
                MapArea::new(
                    VPNRange::new(
                        VirtAddr::from(KERNEL_BASE + 0x8200_0000).floor(),
                        VirtAddr::from(KERNEL_BASE + 0x8200_0000 + 65536).ceil(),
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
            KERNEL_SPACE.lock().push_with_offset(
                MapArea::new(
                    VPNRange::new(
                        VirtAddr::from(KERNEL_BASE + RX_SKB_BUF_START).floor(),
                        VirtAddr::from(KERNEL_BASE + RX_SKB_BUF_START + 65536).ceil(),
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
            KERNEL_SPACE.lock().push_with_offset(
                MapArea::new(
                    VPNRange::new(
                        VirtAddr::from(KERNEL_BASE + 0x8202_0000).floor(),
                        VirtAddr::from(KERNEL_BASE + 0x8202_0000 + 65536).ceil(),
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
            for i in 221..228 {
                write_volatile(
                    phys_to_virt(0x17000000 + (i - 219) * 4) as *mut u32,
                    0x80000000,
                );
            }
        }

        let ioaddr = phys_to_virt(0x16040000);


        log::info!("---------init clk-------------");
        unsafe{
            for i in 97..112{
                write_volatile(phys_to_virt(0x13020000 + i *4) as *mut u32, 0x80000000);
            }  

            for i in 221..228{
                write_volatile(phys_to_virt(0x17000000 + (i - 219) *4) as *mut u32, 0x80000000);
            }           
        }

        
        mdio_write::<A>(ioaddr,0xa001 ,0x8020);
        mdio_write::<A>(ioaddr,0xa010 ,0xcbff);
        mdio_write::<A>(ioaddr,0xa003 ,0x850);

        // -------jh7110_reset_trigger-------value=ffe5afc4 reset.assert=13020300
        // -------jh7110_reset_trigger-------value=ffe5afc0 reset.assert=13020300

        unsafe{
            write_volatile((phys_to_virt(0x13020300) ) as *mut u32, 0xffe5afc4);
            write_volatile((phys_to_virt(0x13020300) ) as *mut u32, 0xffe5afc0);

            write_volatile((phys_to_virt(0x17000038) ) as *mut u32, 0xe1);
            write_volatile((phys_to_virt(0x17000038) ) as *mut u32, 0xe0);
            write_volatile((phys_to_virt(0x17000038) ) as *mut u32, 0xe2);
            write_volatile((phys_to_virt(0x17000038) ) as *mut u32, 0xe3);

            write_volatile((phys_to_virt(0x13020190) ) as *mut u32, 0x8);
            write_volatile((phys_to_virt(0x13020194) ) as *mut u32, 0x1);
        }



        log::info!("-------------------phylink_start phylink_speed_up--------------");
        log::info!("-------------------phy_config_aneg--------------");
        mdio_write::<A>(ioaddr,0x1de1,0x300);

        log::info!("-------------------open--------------");

        log::info!("init_dma_rx_desc_rings");

        let mut rx_ring = RxRing::<A>::new();
        // A::fence();
        let rdes_base = rx_ring.rd.phy_addr as u32;

        let size = mem::size_of::<RxDes>() * 64;

        let rdes_end = rdes_base + size as u32;


        let skb_start = RX_SKB_BUF_START as usize;
        for i in 0..64 {
            let buff_addr = skb_start + 0x1000 * i;
            rx_ring.init_rx_desc(i, buff_addr);
        }
        dump_reg();
        // sifive_ccache_flush_range::<A>(RX_DESC_START as usize, RX_DESC_START as usize + 0x1000);
        // sifive_ccache_flush_range::<A>(RX_SKB_BUF_START as usize, RX_SKB_BUF_START+0x1000);
        



        log::info!("init_dma_tx_desc_rings");
        let mut tx_ring = TxRing::<A>::new();
        // A::fence();
        let tdes_base = tx_ring.td.phy_addr as u32;
        let tskb_start = TX_SKB_BUF_START as usize;
        for i in 0..64 {
            tx_ring.init_tx_desc(i,  false);
        }




        // A::fence();
        dump_reg();




        unsafe{
            log::info!("-------------dwmac_dma_reset--------------------");
            let mut value = read_volatile((ioaddr + DMA_BUS_MODE) as *mut u32);
        
            value |= 1 as u32;

            write_volatile((ioaddr + DMA_BUS_MODE) as *mut u32, value);
         
        }

        // unsafe {
        //     log::info!("-------------DMA_CHAN_CUR_RX_BUF_ADDR--------------------");
        //     write_volatile((ioaddr + DMA_CHAN_CUR_RX_BUF_ADDR ) as *mut u32, RX_SKB_BUF_START as u32);
        // }


        log::info!("---------------dwmac4_dma_init----------------------------");
        unsafe{
            write_volatile((ioaddr + DMA_BUS_MODE) as *mut u32, 0x1);
        }

        // f0f08f1
        log::info!("---------------axi------------------------------");
        unsafe{
            write_volatile((ioaddr + DMA_BUS_MODE) as *mut u32, 0xf0f08f1);
        }

        log::info!("------------------dwmac410_dma_init_channel------------------");
        unsafe{
            write_volatile((ioaddr + 0x1100) as *mut u32, 0);
        }

        log::info!("------------------dwmac4_dma_init_rx_chan------------------");
        unsafe{
            write_volatile((ioaddr + 0x1108) as *mut u32, 0x100000);
        }


        log::info!("-------------set rx base --------------------");
        unsafe {

            write_volatile((ioaddr + 0x1100 + 0x1c) as *mut u32, rdes_base);
        }


        log::info!("-------------set rx end --------------------");
        unsafe {
            write_volatile((ioaddr + 0x1100 + 0x28) as *mut u32, rdes_end);
        }

        log::info!("------------------dwmac4_dma_init_tx_chan------------------");
        unsafe{
            write_volatile((ioaddr + 0x1104) as *mut u32, 0x100010);
        }

        log::info!("-------------set tx base --------------------");
        unsafe {
            write_volatile((ioaddr + 0x1100 + 0x14) as *mut u32, tdes_base);
        }

        log::info!("set mac addr");
        let mac_id: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0x05, 0x06];

        let macid_lo = 0xddccbbaa;

        let macid_hi = 0x0605;

        unsafe {
            write_volatile((ioaddr + 0x300) as *mut u32, macid_hi);
        }

        unsafe {
            write_volatile((ioaddr + 0x304) as *mut u32, macid_lo);
        }
        log::info!("-----------------dwmac4_core_init-------");

        unsafe{
            write_volatile((ioaddr) as *mut u32, 0x78200);
        }


        log::info!("------------------dwmac4_map_mtl_dma-----------------");
        
        unsafe{
            write_volatile((ioaddr + 0xc30) as *mut u32, 0x0);
        }


        log::info!("------------------dwmac4_rx_queue_enable-----------------");
        
        unsafe{
            write_volatile((ioaddr + 0xa0) as *mut u32, 0x2);
        }


        log::info!("------------------dwmac4_dma_rx_chan_op_mode-----------------");
        
        unsafe{
            write_volatile((ioaddr + 0xd00 + 0x30) as *mut u32, 0x700000);
        }

        log::info!("------------------dwmac4_dma_tx_chan_op_mode-----------------");
        
        unsafe{
            write_volatile((ioaddr + 0xd00) as *mut u32, 0x70018);
        }

        
        log::info!("-------------set tx ring length --------------------");
        unsafe {
            write_volatile((ioaddr + 0x1100 + 0x2c) as *mut u32, 64);
        }
 
                
        log::info!("-------------set rx ring length --------------------");
        unsafe {
            write_volatile((ioaddr + 0x1100 + 0x30) as *mut u32, 64);
        }

        log::info!("--------------tx flow contrl----------------------");
        unsafe{
            write_volatile((ioaddr + 0x70) as *mut u32, 0xffff0000);
        }
        log::info!("--------------tx flow contrl----------------------");
        unsafe{
            write_volatile((ioaddr + 0x70) as *mut u32, 1 << 1);
        }
        // log::info!("-------------tx flow contrl--------------------");
        // unsafe {
        //     write_volatile((ioaddr + 0x1100 + 0x30) as *mut u32, 64);
        // }



        log::info!("---------start dma tx/rx----------------------------");
        unsafe {
            let mut value = read_volatile((ioaddr + 0x1108) as *mut u32);
            value |= 1 << 0;
            write_volatile((ioaddr + 0x1108) as *mut u32, value);

            let mut value = read_volatile((ioaddr) as *mut u32);
            value |= 1 << 0;
            write_volatile((ioaddr) as *mut u32, value);
            

            let mut value = read_volatile((ioaddr + 0x1104) as *mut u32);
            value |= 1 << 0;
            write_volatile((ioaddr + 0x1104) as *mut u32, value);
            let mut value = read_volatile((ioaddr) as *mut u32);
            value |= 1 << 1;
            write_volatile((ioaddr) as *mut u32, value);

        }





        // mdio_write::<A>(ioaddr,0xa001 ,0x8020);
        // mdio_write::<A>(ioaddr,0xa010 ,0xcbff);
        // mdio_write::<A>(ioaddr,0xa003 ,0x850);

        log::info!("--------------stmmac_mac_link_up----------------------");

        unsafe{
            write_volatile((ioaddr) as *mut u32, 0x8072203);
        }
        log::info!("--------------------enable mac rx/tx-----------------------");
        stmmac_set_mac(ioaddr, true);




        log::info!("--------------tx flow contrl----------------------");

        unsafe{
            write_volatile((ioaddr + 0x70) as *mut u32, 0xffff0002);
        }
        
        log::info!("-------------------sending------------------------");
        dump_reg();
        dump_tx_status();
        dump_rx_status();
        // let x: &mut [u8] = &mut [
        //     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xbb, 0xcc, 0xdd, 0x05, 0x06, 0x08, 0x06, 0x00,0x01, 
        //     0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0x05, 0x06, 
        //     0xc0, 0xa8, 0x05, 0x64, 
        //     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        //     0xc0, 0xa8, 0x05, 0x83, 
        //     0x00, 0x00, 0x00,
        //     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // ];
        
        // for i in 0..64{
        
        //     let buff_addr = tskb_start + 0x1000 * i;
        //     let raw_pointer = x.as_mut_ptr();
        //     let packet_pa: usize = tskb_start + 0x1000 * i;
        //     let packet_va = phys_to_virt(packet_pa);
        //     let buff = packet_va as *mut u8;
        //     unsafe {
        //         core::ptr::copy_nonoverlapping(raw_pointer as *const u8, buff as *mut u8, 0x3c);
        //     }


        //     sifive_ccache_flush_range::<A>(0x8200_1000 as usize, 0x8200_3000 );
        //     sifive_ccache_flush_range::<A>(RX_SKB_BUF_START as usize, 0x8203_0000 as usize);

        //     let mut td = tx_ring.td.read_volatile(i).unwrap();
            
        //     td.tdes0 = buff_addr as u32;
        //     td.tdes2 = 0x3c;
        //     td.tdes3 |= 1 << 29;
        //     td.tdes3 |= 1 << 28;
        //     td.tdes3 |= 1 << 31;
        //     tx_ring.td.write_volatile(i, &td);
        //     unsafe{
        //         core::arch::asm!("fence	ow,ow");
        //     }
        //     // A::fence();
            
        //     sifive_ccache_flush_range::<A>(0x8200_1000 as usize, 0x8200_3000);
        //     sifive_ccache_flush_range::<A>(RX_SKB_BUF_START as usize, 0x8203_0000 as usize);
        //     tx_ring.td.write_volatile(i, &td);
        //     // A::mdelay(500);
        //     log::info!("td {:x?}", td);
        //     // let offset = mem::size_of::<TxDes>() * i;
        //     let tail_ptr = tdes_base + (mem::size_of::<TxDes>() * (i+1)) as u32;

        //     unsafe{
        //         core::arch::asm!("fence	ow,ow");
        //     }
        //     sifive_ccache_flush_range::<A>(0x8200_1000 as usize, 0x8200_3000 );
        //     sifive_ccache_flush_range::<A>(RX_SKB_BUF_START as usize, 0x8203_0000 as usize);
        //     //set end send ptr
        //     unsafe{
        //         write_volatile((ioaddr + 0x1120) as *mut u32, tail_ptr);
        //     }
        //     loop{
        //         let mut td = tx_ring.td.read_volatile(i).unwrap();
        //         log::info!("td {:x?}", td);    

        //         if td.tdes3 & ( 1 << 31) == 0{
        //             break;
        //         }
        //         // A::mdelay(1000);
        //     }
        //     // A::mdelay(1000);    
                
        //     let value = unsafe{
        //         read_volatile((ioaddr + 0x1154) as *mut u32)
        //     };
        //     log::info!("Current Host tx buffer{:#x?}", value);
        // }
        let nic = Starfive2NetDevice::<QS,A> {
            rx_ring: rx_ring,
            tx_ring: tx_ring,
            phantom: PhantomData,
        };

        nic
    }

     pub fn receive(&mut self) -> Option<(*mut u8, u32)> {
        let rx_ring = &mut self.rx_ring;
        let rd_dma = &mut rx_ring.rd;
        let idx = rx_ring.idx;
        let rd = rd_dma.read_volatile(idx).unwrap();

        let rdes0 = rd.rdes0;

        let status = rdes0 & (1 << 31);

        if status >> 31 == 0 {
            // log::info!("dma own");
            return None;
        }

        let len = (rdes0 & DESC_RXSTS_FRMLENMSK as u32) >> DESC_RXSTS_FRMLENSHFT;

        // get data from skb
        if rx_ring.skbuf.is_empty() {
            log::error!("rx skbuf is empty");
            return None;
        }
        let skb_va = rx_ring.skbuf[idx];
        let skb = skb_va as *mut u8;
        unsafe {
            let packet: &[u8] = core::slice::from_raw_parts(skb, len as usize);
            log::info!("idx {:?} packet {:x?} ", idx, packet);
        }

        Some((skb, len))
    }

    pub fn rx_clean(&mut self) {
        let rx_ring = &mut self.rx_ring;
        let rd_dma = &mut rx_ring.rd;
        let idx = rx_ring.idx;

        log::info!("clean idx {:?}", idx);
        let ioaddr = phys_to_virt(0x1002_0000);
        let value = unsafe { read_volatile((ioaddr + 0x104c) as *mut u32) };
        log::info!("Current Host rx descriptor -----{:#x?}", value);
        if idx == 15 {
            let skb_start = 0x1801_0000 as usize;
            for i in 0..16 {
                let buff_addr = skb_start + 0x1000 * i;
                rx_ring.init_rx_desc(i, buff_addr);
            }
            let rdes_base = rx_ring.rd.phy_addr as u32;
            sifive_ccache_flush_range::<A>(rdes_base as usize, rdes_base as usize + 0x1000);
            sifive_ccache_flush_range::<A>(0x1801_0000 as usize, 0x1802_0000);
        }

        rx_ring.idx = (idx + 1) % 16;
    }

    pub fn transmit(&mut self, skb_pa: usize, len: usize) {
        let tskb_start=TX_SKB_BUF_START as usize;
        let tx_ring: &mut TxRing<A> = &mut self.tx_ring;
        let idx: usize = tx_ring.idx;
        let buff_addr = tskb_start + 0x1000 * idx;
        let ioaddr = phys_to_virt(0x16040000);
        unsafe {
            copy_nonoverlapping(phys_to_virt(skb_pa) as *const u8, phys_to_virt(buff_addr) as *mut u8, len);
        }
        let tdes_base = tx_ring.td.phy_addr as u32;
        sifive_ccache_flush_range::<A>(tdes_base as usize, tdes_base as usize + 0x2000);
        sifive_ccache_flush_range::<A>(buff_addr as usize, buff_addr as usize + 0x2000);
        tx_ring.set_transmit_des(idx, buff_addr, len);
        unsafe{
                core::arch::asm!("fence	ow,ow");
        }
        sifive_ccache_flush_range::<A>(tdes_base as usize, tdes_base as usize + 0x2000);
        sifive_ccache_flush_range::<A>(buff_addr as usize, buff_addr as usize + 0x2000);
        tx_ring.set_transmit_des(idx, buff_addr, len);
        // log::info!("td {:x?}", td)
        
        let tail_ptr = tdes_base + (mem::size_of::<TxDes>() * (idx + 1)) as u32;
        unsafe{
                core::arch::asm!("fence	ow,ow");
            }
        sifive_ccache_flush_range::<A>(tdes_base as usize, tdes_base as usize + 0x2000);
        sifive_ccache_flush_range::<A>(buff_addr as usize, buff_addr as usize + 0x2000);
        unsafe {
            write_volatile((ioaddr + DMA_CHAN_TX_END_ADDR) as *mut u32, tail_ptr);
            // write_volatile((ioaddr + DMA_XMT_POLL_DEMAND as usize) as *mut u32, 1u32);
        }
        dump_reg();
        dump_rx_status();
        dump_tx_status();
        // wait until transmit finish
        loop{
            let mut td = tx_ring.td.read_volatile(idx).unwrap();
            log::info!("[Starfive2NetDevice_transmit]td {:x?}", td);    

            if td.tdes3 & ( 1 << 31) == 0{
                break;
            }
            // A::mdelay(1000);
        }

        tx_ring.idx = (idx + 1) % 64;

    }
}

pub fn mdio_write<A: Hal>(ioaddr: usize, data: u32, value: u32) {
    loop {
        let value = unsafe { read_volatile((ioaddr + 0x10) as *mut u32) };

        if value & MII_BUSY != 1 {
            break;
        }
        // A::mdelay(10);
    }

    unsafe {
        write_volatile((ioaddr + 0x14) as *mut u32, data);
        write_volatile((ioaddr + 0x10) as *mut u32, value);
    }

    loop {
        let value = unsafe { read_volatile((ioaddr + 0x10) as *mut u32) };

        if value & MII_BUSY != 1 {
            break;
        }
        // A::mdelay(10);
    }
}
pub fn sifive_ccache_flush_range<A: Hal>(start: usize, end:usize){


    // let start_pa = A::virt_to_phys(start) as u32;
    // let end_pa: u32 = A::virt_to_phys(end) as u32;
    log::info!("sifive_ccache_flush_range---------start:{:#x} end:{:#x?}", start, end);
    let start_pa = start as usize;
    let end_pa = end as usize;

    let mut s = start_pa;

    let cache_line_size = 0x40;

    let cache_flush = phys_to_virt(0x201_0000);

    // A::fence();\
    unsafe{
        core::arch::asm!("sfence.vma")
    };
    // asm!("sfence.vma");
    unsafe{
        core::arch::asm!("fence")
    };

    let addr = cache_flush + 0x200 as usize;

    // let va = phys_to_virt(addr);



    // let ptr = &va as _ as usize;
    // let ptr = &va as *const usize as usize;

    while s < end_pa as usize{


        // let flush64 = *((cache_flush + 0x200) as *mut u32);
        unsafe{
            write_volatile((cache_flush + 0x200) as *mut usize, s);
        }
        unsafe{
            write_volatile((cache_flush + 0x200) as *mut usize, phys_to_virt(s));
        }

        s += cache_line_size;
    }
    // A::fence();

    unsafe{
        core::arch::asm!("fence")
    };
}
pub fn stmmac_set_mac(ioaddr: usize, enable: bool) {
    let old_val: u32;
    let mut value: u32;

    log::info!("stmmac_set_mac--------------------enable={:?}", enable);

    old_val = unsafe { read_volatile(ioaddr as *mut u32) };
    value = old_val;

    if enable {
        value |= MAC_ENABLE_RX | MAC_ENABLE_TX;
    } else {
        value &= !(MAC_ENABLE_TX | MAC_ENABLE_RX);
    }

    if value != old_val {
        unsafe { write_volatile(ioaddr as *mut u32, value) }
    }
}

pub struct StarFiveDeviceWrapper<const QS: usize, A: Hal> {
    recv_buffers: VecDeque<NetBufPtr>,
    device: Starfive2NetDevice<QS,A>,
    pool: Arc<NetBufPool>,
}
impl<const QS: usize, A: Hal> StarFiveDeviceWrapper<QS, A> {
    pub fn new() -> Self {
        let device = Starfive2NetDevice::<QS,A>::new();
        let pool = NetBufPool::new(2 * QS, NET_BUF_LEN);
        let rx_buffer_queue = VecDeque::with_capacity(64);
        Self {
            recv_buffers: rx_buffer_queue,
            device,
            pool,
        }
    }
}
unsafe impl<const QS: usize, A: Hal> Send for StarFiveDeviceWrapper<QS, A> {}
unsafe impl<const QS: usize, A: Hal> Sync for StarFiveDeviceWrapper<QS, A> {}

impl<const QS: usize, A: Hal> NetDevice for StarFiveDeviceWrapper<QS, A> {
    fn capabilities(&self)->smoltcp::phy::DeviceCapabilities {
        let mut cap = DeviceCapabilities::default();
        cap.max_transmission_unit = 3_000_000;
        cap.max_burst_size = None;
        cap.medium = Medium::Ethernet;
        cap
    }

    fn mac_address(&self)->EthernetAddress {
        EthernetAddress([0xaa, 0xbb, 0xcc, 0xdd, 0x05, 0x06])
    }

    fn isok_send(&self)->bool {
        true 
    }

    fn isok_recv(&self)->bool {
       true
    }

    fn max_send_buf_num(&self)->usize {
        QS
    }

    fn max_recv_buf_num(&self)->usize {
        QS
    }

    fn recycle_recv_buffer(&mut self,recv_buf:NetBufPtr) {
        // self.device.rx_clean();
        // drop(recv_buf);
    }

    fn recycle_send_buffer(&mut self)->Result<(),()> {
        // let idx = self.device.tx_ring.idx;
        // self.device.rx_clean();
        Ok(())
    }

    fn send(&mut self,ptr:NetBufPtr)->usize {
        log::info!("--------transmit----------------");
        let packet_va: *mut u8 = ptr.raw_ptr();
        let packet_pa = virt_to_phys(packet_va as usize);
        let len = ptr.packcet_len;
        self.device.transmit(packet_pa as usize, len);
        return 0;
    }

    fn recv(&mut self)->Option<NetBufPtr> {
        println!("[Starfive2DeviceWrapper_recv] recv packet");
        if let Some((skb, len)) = self.device.receive() {
            if len==0 {
             return None;   
            }
            dump_reg();
            dump_rx_status();
            dump_tx_status();
            println!("[Starfive2DeviceWrapper_recv] receive skb:{:x?} len:{:?}", skb, len);
            println!("[Starfive2DeviceWrapper_recv] recv packet is {:?}", unsafe { core::slice::from_raw_parts(skb, len as usize) });
            let buffer_ptr = NonNull::new(skb).expect("-------");
            let packet_ptr = NonNull::new(skb).expect("-------");
            let net_buf = NetBufPtr::new(len as usize, buffer_ptr, packet_ptr);
            Some(net_buf)
        } else {
            None
        }
    }

    fn alloc_send_buffer(&mut self, size: usize) -> NetBufPtr {
        let idx = self.device.tx_ring.idx;
        assert!(size <= TX_BUF_SIZE);
        // 虚拟地址给 CPU 用
        unsafe {TX_BUFFERS[idx].fill(0);}
        let buf_va = unsafe { TX_BUFFERS[idx].as_mut_ptr() };
        NetBufPtr::new(size, NonNull::new(buf_va).unwrap(), NonNull::new(buf_va as *mut u8).unwrap())
    }
}

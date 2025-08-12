use core::{alloc::Layout, ptr::{copy_nonoverlapping, NonNull}};

use alloc::{alloc::alloc_zeroed, boxed::Box, sync::Arc, vec::Vec};
use smoltcp::{phy::{DeviceCapabilities, Medium}, wire::EthernetAddress};
const NET_BUF_LEN: usize = 1536;
const BUF_LEN: usize = 1 << 12;
const QUEUE_SIZE: usize = 16;
/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-08-10 11:39:56
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-08-12 16:29:18
 * @FilePath: /RocketOS_netperfright/os/src/drivers/net/starfive/platform.rs
 * @Description: 
 * 
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved. 
 */
use crate::{arch::config::KERNEL_BASE, drivers::net::{netdevice::{NetBufPtr, NetDevice}, starfive::{drv_eth::{eth_handle_tx_over, eth_init, eth_rx, eth_tx}, eth_def::{VisionfiveGmac, DMA_CH0_RX_CONTROL, DMA_CH0_STATUS, DMA_CHAN_STATUS_AIS, DMA_CHAN_STATUS_ERI, DMA_CHAN_STATUS_ETI, DMA_CHAN_STATUS_FBE, DMA_CHAN_STATUS_RBU, DMA_CHAN_STATUS_RI, DMA_CHAN_STATUS_RPS, DMA_CHAN_STATUS_RWT, DMA_CHAN_STATUS_TBU, DMA_CHAN_STATUS_TI, DMA_CHAN_STATUS_TPS, EQOS_DMA_CH0_RX_CONTROL_SR}, eth_dev::{eth_mac_read_reg, eth_mac_set_bits}}, NetBuf, NetBufBox, NetBufPool}, task::wait_timeout, timer::TimeSpec};

pub fn plat_mdelay(m_times: usize) {
    let dur = TimeSpec {
        sec: (m_times / 1000) as usize,
        nsec: ((m_times % 1000) * 1_000_000) as usize,
    };
    wait_timeout(dur, -1);
}
pub fn plat_malloc_align(size:u64,align:u32)->u64 {
    let layout = Layout::from_size_align(size as usize, align as usize).unwrap();
    let ptr = unsafe { alloc_zeroed(layout) };
    if !ptr.is_null() {
        return ptr as u64;
    }
    else {
        panic!("alloc error");
    }
    
}
pub fn plat_phys_to_virt(pa:u64)->u64 {
    ((KERNEL_BASE) as u64 + pa) 
}
pub fn plat_virt_to_phys(va:u64)->u32 {
    (va-(KERNEL_BASE) as u64) as u32
}

// #define RISCV_FENCE(p, s) \
//         __asm__ __volatile__ ("fence " #p "," #s : : : "memory")

// /* These barriers need to enforce ordering on both devices or memory. */
// #define mb()            RISCV_FENCE(iorw,iorw)
// #define rmb()           RISCV_FENCE(ir,ir)
// #define wmb()           RISCV_FENCE(ow,ow)
pub fn plat_fence(){
    unsafe {
        core::arch::asm!("fence iorw, iorw");
    }
}
pub fn plat_handle_tx_buffer(p: NetBufPtr, buffer: u64) -> u32 {
    let mut sendbuf = NetBuf::from_ptr_into_netbuf(p);
    let data = sendbuf.get_packet_with_header();
    // let data=[1].as_slice();
    let len = data.len();
    log::info!("[plat_handle_tx_buffer] len is {:?}",len);
    let dst = unsafe {
        core::slice::from_raw_parts_mut(buffer as *mut u8, len)
    };
    dst.copy_from_slice(data);    

    len as u32
}
pub fn  plat_handle_rx_buffer(buffer: u64, length: u32) -> u64 {
    // buffer是接收到的数据，length是字节数
    // OS需要分配内存，memcpy接收到的数据，并将地址返回
    //这里直接分配空间，在后续的wrapper里面通过Netptr再返回即可
    let recvbuf=plat_malloc_align(length as u64,32);
    log::info!("[plat_handle_rx_buffer]begin copy");
    unsafe{
        copy_nonoverlapping(buffer as *const u8, recvbuf as *mut u8, length as usize);
        //log::info!("[plat_handle_rx_buffer] recv buffer is {:#x?}",core::slice::from_raw_parts(buffer as *const u8, length as usize));
    }
    log::info!("[plat_handle_rx_buffer] copy end");
    recvbuf
}


pub struct VisionFive2_NetDevice<const QS:usize>{
    inner:VisionfiveGmac,
    pool:Arc<NetBufPool>,
    // free_send_buffers:Vec<NetBufBox>,
}
unsafe impl <const QS:usize> Send for VisionFive2_NetDevice<QS> {}
unsafe impl <const QS:usize> Sync for VisionFive2_NetDevice<QS> {}
impl <const QS:usize> VisionFive2_NetDevice<QS> {
    pub fn new()->Self {
        let pool=NetBufPool::new(2*QS, NET_BUF_LEN);
        let inner=eth_init(&mut VisionfiveGmac::init());
        // let free_send_buffers = Vec::with_capacity(QS);
        let mut dev=VisionFive2_NetDevice{
            // recv_buffers: recv_buffers,
            // send_buffers: send_buffers,
            pool: pool,
            // free_send_buffers: free_send_buffers,
            inner: inner,
        };
        // for _ in 0..QS {
        //     //分配sendbuf
        //     let mut alloc_buf = Box::new(dev.pool.alloc());
        //     // Fill the header of the `buffer` with [`VirtioNetHdr`].
        //     // If the `buffer` is not large enough, it returns [`Error::InvalidParam`]这里我们定义长度为1536
        //     // let header_len = dev
        //     //     .inner
        //     //     .fill_buffer_header(alloc_buf.get_raw_mut_buf())
        //     //     .unwrap();
        //     log::info!("[VisionFive2_NetDevice_new] alloc_buf ptr is {:#x?}",alloc_buf.buf_ptr);
        //     alloc_buf.set_header_len(0);
        //     dev.free_send_buffers.push(alloc_buf);
        // }
        dev
    }
}

impl <const QS:usize> NetDevice for VisionFive2_NetDevice<QS> {
    fn capabilities(&self)->smoltcp::phy::DeviceCapabilities {
        let mut cap = DeviceCapabilities::default();
        cap.max_transmission_unit = 1500;
        cap.max_burst_size = None;
        cap.medium = Medium::Ethernet;
        cap
    }

    fn mac_address(&self)->smoltcp::wire::EthernetAddress {
        EthernetAddress([0x00, 0x55, 0x7B, 0xB5, 0x7D, 0xF7])
    }

    fn isok_send(&self)->bool {
        true
    }

    fn isok_recv(&self)->bool {
        let mut flag=false;
        let mut device=self.inner;
        let status=eth_mac_read_reg(device.DmaBase, DMA_CH0_STATUS);
        log::error!("[isok_recv] status is {:#x?}",status);
        if status == 0 {
            panic!("invalid status");
        }
        if status&DMA_CHAN_STATUS_AIS!=0 {
            log::info!("[VisionFive2_NetDevice_isok_recv] abnormal interrupt");
        }
        if status&DMA_CHAN_STATUS_FBE!=0 {
            panic!("[VisionFive2_NetDevice_isok_recv]Fatal Bus Error");
        }
        if status&DMA_CHAN_STATUS_RWT!=0 {
            panic!("[VisionFive2_NetDevice_isok_recv] Receive Watchdog Timeout")
        }
        if status&DMA_CHAN_STATUS_ERI!=0{
            log::info!("[VisionFive2_NetDevice_isok_recv] Early Receive Interrupt");
        }
        if status&DMA_CHAN_STATUS_RPS!=0 {
            log::info!("[VisionFive2_NetDevice_isok_recv] Receive Process Stopped");
            eth_mac_set_bits(device.DmaBase, DMA_CH0_RX_CONTROL, EQOS_DMA_CH0_RX_CONTROL_SR);
        }
        if  status&DMA_CHAN_STATUS_RBU!=0{
            log::info!("[VisionFive2_NetDevice_isok_recv]gmac receive buffer unavailable");
            flag=true;
        }
        // else if status&DMA_CHAN_STATUS_TBU!=0 {
        //     log::info!("[VisionFive2_NetDevice_isok_recv]Transmit Buffer Unavailable");
        // }
        if status&DMA_CHAN_STATUS_TPS!=0 {
            panic!("[VisionFive2_NetDevice_isok_recv] send stopped");
        }
        if status&DMA_CHAN_STATUS_ETI!=0{
            // panic!("[VisionFive2_NetDevice_isok_recv]Early Transmit Interrupt")
        }
        if status&DMA_CHAN_STATUS_RI!=0 {
            log::info!("[VisionFive2_NetDevice_isok_recv]receive complete");
            flag=true;
        }
        if status&DMA_CHAN_STATUS_TI!=0 {
            log::info!("[VisionFive2_NetDevice_isok_recv] send success");
            // eth_handle_tx_over(&mut device);
        }
        flag
        // true
    }

    fn max_send_buf_num(&self)->usize {
        QS
    }

    fn max_recv_buf_num(&self)->usize {
        QS
    }

    fn recycle_recv_buffer(&mut self,recv_buf:NetBufPtr) {
        log::info!("[VisionFive2_NetDevice_send_recycle_recv_buffer] begin");
        let mut recv_buf = NetBuf::from_ptr_into_netbuf(recv_buf);
        self.pool.dealloc(recv_buf.pool_offset);
        log::info!("[VisionFive2_NetDevice_send_recycle_recv_buffer] end");
    }

    fn recycle_send_buffer(&mut self)->Result<(),()> {
        Ok(())
    }

    fn send(&mut self,ptr:NetBufPtr)->usize {
        log::info!("[VisionFive2_NetDevice_send]begin send");
        let send_netbuf = NetBuf::from_ptr_into_netbuf(ptr);
        log::error!(
            "[VisionFive2_NetDevice_send]:send buf {:?}",
            send_netbuf.get_packet()
        );
        let a=eth_tx(&mut self.inner, ptr);
        // return 0;
        if a==-1 {
            panic!("eth_tx failed");
        }
        let mut flag: bool=false;
        let mut device=self.inner;
        let status=eth_mac_read_reg(device.DmaBase, DMA_CH0_STATUS);
        if status == 0 {
            panic!("invalid status");
        }
        //todo diff the status
        loop {

            if status&DMA_CHAN_STATUS_AIS!=0 {
                log::info!("[VisionFive2_NetDevice_send] abnormal interrupt");
            }
            else if status&DMA_CHAN_STATUS_FBE!=0 {
                panic!("[VisionFive2_NetDevice_send]Fatal Bus Error");
            }
            else if status&DMA_CHAN_STATUS_RWT!=0 {
                panic!("[VisionFive2_NetDevice_send] Receive Watchdog Timeout")
            }
            else if status&DMA_CHAN_STATUS_ERI!=0{
                log::info!("[VisionFive2_NetDevice_send] Early Receive Interrupt");
            }
            else if status&DMA_CHAN_STATUS_RPS!=0 {
                log::info!("[VisionFive2_NetDevice_send] Receive Process Stopped");
                eth_mac_set_bits(device.DmaBase, DMA_CH0_RX_CONTROL, EQOS_DMA_CH0_RX_CONTROL_SR);
            }
            else if  status&DMA_CHAN_STATUS_RBU!=0{
                log::info!("[VisionFive2_NetDevice_send]gmac receive buffer unavailable");
            }
            else if status&DMA_CHAN_STATUS_TBU!=0 {
                log::info!("[VisionFive2_NetDevice_send]Transmit Buffer Unavailable");
                eth_handle_tx_over(&mut device);
                // self.free_send_buffers.push(send_netbuf);
                self.pool.dealloc(send_netbuf.pool_offset);
                break;
            }
            else if status&DMA_CHAN_STATUS_TPS!=0 {
                panic!("[VisionFive2_NetDevice_send] send stopped");
            }
            else if status&DMA_CHAN_STATUS_ETI!=0{
                panic!("[VisionFive2_NetDevice_send]Early Transmit Interrupt")
            }
            else if status&DMA_CHAN_STATUS_RI!=0 {
                log::info!("[VisionFive2_NetDevice_send]receive complete");
            }
            else if status&DMA_CHAN_STATUS_TI!=0 {
                log::info!("[VisionFive2_NetDevice_send] send success");
                eth_handle_tx_over(&mut device);
                // self.free_send_buffers.push(send_netbuf);
                self.pool.dealloc(send_netbuf.pool_offset);
                break;
            }
        }
        log::info!("[VisionFive2_NetDevice_send] send complete");
        return 0;
    }

    fn recv(&mut self)->Option<NetBufPtr> {
        log::info!("[VisionFive2_NetDevice]begin recv");
        let addlen=eth_rx(&mut self.inner);
        log::info!("[VisionFive2_NetDevice recv] addlen is {:?},addrlen addr is {:#x?}",addlen.len,addlen.addr);
        if addlen.len==0 {
            return None;
        }
        let pool=&self.pool;
        let mut rx_buf:Box<NetBuf>=Box::new(pool.alloc());
        rx_buf.buf_ptr=NonNull::new(addlen.addr as *mut u8).unwrap();
        rx_buf.set_header_len(0);
        rx_buf.set_packet_len((addlen.len-4) as usize);
        log::error!(
            "[VisionFive2_NetDevice_recv]:recv_buf is {:?}",
            rx_buf.get_packet()
        );
        // let status=eth_mac_read_reg(self.inner.DmaBase, DMA_CH0_STATUS);
        // log::error!("[VisionFive2_NetDevice_recv] status is {:#x?}",status);
        Some(rx_buf.into_buf_ptr())
    }

    fn alloc_send_buffer(&mut self,size:usize)->NetBufPtr {
        log::info!("[VisionFive2_NetDevice_alloc_sendbuffer] begin alloc_send_buffer");
        // let mut send_buf = self.free_send_buffers.pop().unwrap();
        let mut send_buf=Box::new(self.pool.alloc());
        log::info!("[VisionFive2_NetDevice_alloc_sendbuffer] sendbuf_ptr is {:#x?}",send_buf.buf_ptr);
        let header_len = send_buf.header_len;
        assert!(header_len + size < send_buf.capacity);
        send_buf.set_packet_len(size);
        log::info!("[VisionFive2_NetDevice_alloc_sendbuffer] end alloc_send_buffer");
        send_buf.into_buf_ptr()

    }
}
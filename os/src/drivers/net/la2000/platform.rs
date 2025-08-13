use core::{alloc::Layout, arch::asm, ptr::{copy_nonoverlapping, NonNull}, slice::{self, from_raw_parts}};

use alloc::{alloc::{alloc_zeroed, handle_alloc_error}, boxed::Box, sync::Arc, vec::Vec};
use smoltcp::{phy::{DeviceCapabilities, Medium}, wire::EthernetAddress};

use crate::{arch::backtrace::backtrace::dump_backtrace, drivers::net::{la2000::{drv_eth::{eth_handle_tx_over, eth_init, eth_phy_rgsmii_check, eth_rx, eth_tx}, eth_defs::*, eth_dev::{eth_dma_disable_interrupt_all, eth_dma_enable_interrupt, eth_dma_enable_rx, eth_gmac_disable_dma_rx, eth_gmac_disable_rx, eth_gmac_enable_rx, eth_gmac_resume_dma_rx, eth_gmac_resume_dma_tx, eth_mac_read_reg, eth_mac_write_reg}}, netdevice::{NetBufPtr, NetDevice}, NetBuf, NetBufBox, NetBufPool}, net::poll_interfaces, task::yield_current_task};
const NET_BUF_LEN: usize = 1536;
const BUF_LEN: usize = 1 << 12;
const QUEUE_SIZE: usize = 16;
/*
// for C test
unsafe {
    pub fn plat_printf(fmt: *const u8, _: ...) -> i32;
    pub fn sync_dcache();
    pub fn plat_virt_to_phys(va: u64) -> u32;
    pub fn plat_phys_to_virt(pa: u32) -> u64;
    pub fn plat_malloc_align(size: u64, align: u32) -> u64;
    pub fn plat_handle_tx_buffer(p: u64, buffer: u64) -> u32;
    pub fn plat_handle_rx_buffer(buffer: u64, length: u32) -> u64;
    pub fn plat_rx_ready(gmacdev: *mut net_device);
    pub fn platform_update_linkstate(gmacdev: *mut net_device, status: u32);
    pub fn plat_isr_install();
}
*/


// 同步dcache中所有cached和uncached访存请求
pub fn sync_dcache() {
    unsafe {
        asm!("dbar 0");
    }
}

// cached虚拟地址转换为物理地址
// dma仅接受32位的物理地址
pub fn plat_virt_to_phys(va: u64) -> u32 {
    log::error!("[plat_virt_to_phs] va is {:?}",va);
    va as u32
}

// 物理地址转换为cached虚拟地址
pub fn plat_phys_to_virt(pa: u32) -> u64 {
    pa as u64
}

// 物理地址转换为uncached虚拟地址
pub fn plat_phys_to_uncached(pa: u64) -> u64 {
    pa+0x8000_0000_0000_0000
}

// 分配按align字节对齐的内存
pub fn plat_malloc_align(size: u64, align: u32) -> u64 {
    // log::info!("[plat_malloc_align] alloc begin");
    let size = size as usize;
    let align = align as usize;
    // 构造带对齐要求的 Layout
    let layout = Layout::from_size_align(size, align)
        .expect("plat_malloc_align: invalid size/align");
    // log::info!("[plat_malloc_align] Layout size align complete");
    unsafe {
        // alloc_zeroed 会返回对齐到 `align` 的内存
        let ptr = alloc_zeroed(layout);
        // log::info!("[plat_malloc_align] alloc complete");
        if ptr.is_null() {
            handle_alloc_error(layout);
        }
        ptr as u64
    }
}

// 处理tx buffer
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
// 处理rx buffer
pub fn  plat_handle_rx_buffer(buffer: u64, length: u32) -> u64 {
    // buffer是接收到的数据，length是字节数
    // OS需要分配内存，memcpy接收到的数据，并将地址返回
    //这里直接分配空间，在后续的wrapper里面通过Netptr再返回即可
    let recvbuf=plat_malloc_align(length as u64,16);
    unsafe{
        copy_nonoverlapping(buffer as *const u8, recvbuf as *mut u8, length as usize);
        //log::info!("[plat_handle_rx_buffer] recv buffer is {:#x?}",slice::from_raw_parts(buffer as *const u8, length as usize));
    }
    recvbuf
}

// 中断isr通知OS可以调用rx函数
// 函数由eth_irq注册的中断处理函数进行调用，当发生硬件中断之后如果可以接受会进入这里
pub fn plat_rx_ready(gmacdev: *mut net_device) {
    log::info!("[plat_rx_ready]is ready to recvice");
    // poll_interfaces();
}

// 中断isr通知链路状态发生变化，status - 1表示up，0表示down
// 链路目前仅支持1000Mbps duplex
//函数用于表示当前网卡是否可以工作
pub fn  platform_update_linkstate(gmacdev: *mut net_device, status: u32) {

}

// OS注册中断，中断号为12,在eth_init时进行注册
//将eth的中断处理函数注册到中断号为12
pub fn plat_isr_install() {


    
}



//这里打算通过一个NetDeviceWrapper封装net_device并实现NetDevice trait和smoltcp中的NetDevice trait
pub struct La2k1000_NetDevice<const QS: usize>{
        //发送的netbuf package
    // recv_buffers: [Option<NetBufBox>; QS],
    // //接受的netbuf package
    // send_buffers: [Option<NetBufBox>; QS],
    inner:net_device,
    pool: Arc<NetBufPool>,
    ///需要注意pool负责的是e整个所有buf的分配，而free_send_buffers负责的则是已经分配的send_buf中send_complete的，
    ///这个里面增加的唯一方式是ryclcye send buf
    free_send_buffers: Vec<NetBufBox>,
}
unsafe impl <const QS:usize> Send for La2k1000_NetDevice<QS>{}
unsafe impl <const QS:usize> Sync for La2k1000_NetDevice<QS>{}


impl <const QS: usize> La2k1000_NetDevice<QS> {
    pub fn new()->Self {
        let pool = NetBufPool::new(2 * QS, NET_BUF_LEN);
        log::error!("[La2k1000_NetDevice]:pool build complete");

        let inner=eth_init(&mut net_device::init());
        log::error!("[La2k1000_NetDevice]:net_device build complete");
        let free_send_buffers = Vec::with_capacity(QS);
        // let recv_buffers = [const { None }; QS];
        // let send_buffers = [const { None }; QS];
        let mut dev=La2k1000_NetDevice{
            // recv_buffers: recv_buffers,
            // send_buffers: send_buffers,
            pool: pool,
            free_send_buffers: free_send_buffers,
            inner: inner,
        };
        // for (i, buf) in dev.recv_buffers.iter_mut().enumerate() {
        //     let mut alloc_buf = Box::new(dev.pool.alloc());
        //     *buf = Some(alloc_buf);
        // }
        for _ in 0..QS {
            //分配sendbuf
            let mut alloc_buf = Box::new(dev.pool.alloc());
            // Fill the header of the `buffer` with [`VirtioNetHdr`].
            // If the `buffer` is not large enough, it returns [`Error::InvalidParam`]这里我们定义长度为1536
            // let header_len = dev
            //     .inner
            //     .fill_buffer_header(alloc_buf.get_raw_mut_buf())
            //     .unwrap();
            alloc_buf.set_header_len(0);
            dev.free_send_buffers.push(alloc_buf);
        }
        dev
    }
}
impl <const QS:usize> NetDevice for La2k1000_NetDevice<QS> {
    fn capabilities(&self)->smoltcp::phy::DeviceCapabilities {
        let mut cap = DeviceCapabilities::default();
        cap.max_transmission_unit = 1500;
        cap.max_burst_size = None;
        cap.medium = Medium::Ethernet;
        cap
    }
    //ee:0c:a3:5d:77:f2
    fn mac_address(&self)->smoltcp::wire::EthernetAddress {
        EthernetAddress([0x00, 0x55, 0x7B, 0xB5, 0x7D, 0xF7])
    }

    fn isok_send(&self)->bool {
        // !self.free_send_buffers.is_empty()
        true
    }
    //todo
    fn isok_recv(&self)->bool {
        let mut flag=false;
        // plat_rx_ready(self.inner)
        log::info!("[La2k1000_NetDevice_is_ok_recv] begin recv");
        let mut device=self.inner;
        let mut dma_status: u32 = 0;
        let mut dma_int_enable: u32 = DmaIntEnable;
        dma_status = eth_mac_read_reg(device.DmaBase, DmaStatus);
        log::info!("[La2k1000_NetDevice_is_ok_recv] recv status is {:#x?}",dma_status);
        if dma_status == 0 {
            panic!("invalid status");
        }
        //eth_dma_disable_interrupt_all(&device);
        if dma_status & GmacPmtIntr != 0 {
            panic!("gmac pmt interrupt");
        }
        if dma_status & GmacMmcIntr != 0 {
            panic!("gmac mmc interrupt");
        }
        if dma_status & GmacLineIntfIntr != 0 {
            eth_mac_read_reg(device.MacBase, GmacInterruptStatus);
            eth_mac_read_reg(device.MacBase, GmacInterruptMask);
            if eth_mac_read_reg(device.MacBase, GmacInterruptStatus) & GmacRgmiiIntSts != 0 {
                eth_mac_read_reg(device.MacBase, GmacRgsmiiStatus);
            }
            eth_phy_rgsmii_check(&mut device);
        }

        eth_mac_write_reg(device.DmaBase, DmaStatus, dma_status);

        if dma_status & DmaIntBusError != 0 {
            panic!("gmac fatal bus error interrupt");
        }
        if dma_status & DmaIntRxStopped != 0 {
            log::info!("gmac receive process stopped");
            eth_dma_enable_rx(&device);
        }
        if dma_status & DmaIntRxNoBuffer != 0 {
            log::info!("gmac receive buffer unavailable");
            dma_int_enable &= !DmaIntRxNoBuffer;
            eth_gmac_resume_dma_rx(&device);
            // unsafe { plat_rx_ready(device) };
            flag=true;
        }
        if dma_status & DmaIntRxCompleted != 0 {
            dma_int_enable &= !DmaIntRxCompleted;
            log::info!("gmac receive buffer complete");
            // unsafe { plat_rx_ready(device) };
            flag=true;
        }
        if dma_status & DmaIntTxUnderflow != 0 {
            panic!("gmac transmit underflow");
        }
        if dma_status & DmaIntRcvOverflow != 0 {
            panic!("gmac receive underflow");
        }
        if dma_status & DmaIntTxNoBuffer != 0 {
            log::info!("La2k1000_NetDevice_is_ok_recv no txbuffer");
            // dma_int_enable &= !DmaIntTxNoBuffer;
            // eth_gmac_resume_dma_tx(&device);
        }
        if dma_status & DmaIntTxStopped != 0 {
            log::info!("gmac transmit process stopped");
        }
        if dma_status & DmaIntTxCompleted != 0 {
            log::info!("gmac send buffer complete");
            eth_handle_tx_over(&mut device);
        }
        //eth_dma_enable_interrupt(&device, dma_int_enable);
        log::info!("[La2k1000_NetDevice_is_ok_recv] recv nothing");
        if !flag {
            eth_gmac_resume_dma_rx(&device);
        }
        flag
    }

    fn max_send_buf_num(&self)->usize {
        QS
    }

    fn max_recv_buf_num(&self)->usize {
        QS
    }
    //todo
    fn recycle_recv_buffer(&mut self,recv_buf_ptr:NetBufPtr) {
        log::info!("[La2k1000_NetDevice_send_recycle_recv_buffer] begin");
        let mut recv_buf = NetBuf::from_ptr_into_netbuf(recv_buf_ptr);
        self.pool.dealloc(recv_buf.pool_offset);
        log::info!("[La2k1000_NetDevice_send_recycle_recv_buffer] end");
        // drop(recv_buf_ptr);
    }
    //todo
    fn recycle_send_buffer(&mut self)->Result<(),()> {
        //初步想法是直接全部flush一遍，毕竟没有tokee这里
        Ok(())
    }

    fn send(&mut self,ptr:NetBufPtr)->usize {
        let send_netbuf = NetBuf::from_ptr_into_netbuf(ptr);
        log::error!(
            "[La2k1000_NetDevice_send]:send buf {:?}",
            send_netbuf.get_packet()
        );
        let a=eth_tx(&mut self.inner, ptr);
        // return 0;
        if a==-1 {
            panic!("eth_tx failed");
        }
        let mut flag: bool=false;
        log::info!("[La2k1000_NetDevice_send] begin waiting tx over");
        // loop {
            let mut device=self.inner;
            let mut dma_status: u32 = 0;
            let mut dma_int_enable: u32 = DmaIntEnable;
            dma_status = eth_mac_read_reg(device.DmaBase, DmaStatus);
            log::info!("[La2k1000_NetDevice_send] send status is {:#x?}",dma_status);
            // eth_dma_disable_interrupt_all(&device);
            if dma_status & GmacPmtIntr != 0 {
                panic!("gmac pmt interrupt");
            }
            if dma_status & GmacMmcIntr != 0 {
                panic!("gmac mmc interrupt");
            }
            if dma_status & GmacLineIntfIntr != 0 {
                eth_mac_read_reg(device.MacBase, GmacInterruptStatus);
                eth_mac_read_reg(device.MacBase, GmacInterruptMask);
                if eth_mac_read_reg(device.MacBase, GmacInterruptStatus) & GmacRgmiiIntSts != 0 {
                    eth_mac_read_reg(device.MacBase, GmacRgsmiiStatus);
                }
                eth_phy_rgsmii_check(&mut device);
            }

            eth_mac_write_reg(device.DmaBase, DmaStatus, dma_status);
            if dma_status & DmaIntBusError != 0 {
                panic!("gmac fatal bus error interrupt");
            }
            if dma_status & DmaIntRxStopped != 0 {
                log::debug!("gmac receive process stopped");
                eth_dma_enable_rx(&device);
            }
            if dma_status & DmaIntRxNoBuffer != 0 {
                log::debug!("gmac receive buffer unavailable");
                dma_int_enable &= !DmaIntRxNoBuffer;
                eth_gmac_resume_dma_rx(&device);
                // unsafe { plat_rx_ready(device) };
            }
            if dma_status & DmaIntRxCompleted != 0 {
                dma_int_enable &= !DmaIntRxCompleted;
                log::debug!("gmac receive buffer complete remember to recv");
                // let a=eth_rx(&mut device);
                // log::info!("receive addlen {:?}",a);
                // unsafe { plat_rx_ready(device) };
            }
            if dma_status & DmaIntTxUnderflow != 0 {
                panic!("gmac transmit underflow");
            }
            if dma_status & DmaIntRcvOverflow != 0 {
                panic!("gmac receive underflow");
            }
            if dma_status & DmaIntTxNoBuffer != 0 {
                dma_int_enable &= !DmaIntTxNoBuffer;
                log::debug!("gmac send buffer unavailable");
            }
            if dma_status & DmaIntTxCompleted != 0 {
                dma_int_enable &= !DmaIntTxCompleted;
                log::info!("[La2k1000_NetDevice_send] send is over");
                eth_handle_tx_over(&mut device);
                self.free_send_buffers.push(send_netbuf);
                flag=true;
            }  
        log::info!("[La2k1000_NetDevice_send] send complete");
        return 0;
    }

    fn recv(&mut self)->Option<NetBufPtr> {
        log::info!("[La2k1000_NetDevice]begin recv");
        // if !self.isok_recv() {
        //     return None;
        // }
        let addlen=eth_rx(&mut self.inner);
        log::info!("[La2k1000_NetDevice recv] addlen is {:?},addrlen addr is {:#x?}",addlen.len,addlen.addr);
        //从地址转化为NetBufPtr
        if addlen.len==0 {
            return None;
        }
        // let mut rx_buf=NetBuf::from_rawptr_into_netbuf(addlen.addr as usize);
        let pool=&self.pool;
        let mut rx_buf:Box<NetBuf>=Box::new(pool.alloc());
        rx_buf.buf_ptr=NonNull::new(addlen.addr as *mut u8).unwrap();
        rx_buf.set_header_len(0);
        rx_buf.set_packet_len((addlen.len-4) as usize);
        log::error!(
            "[La2k1000_NetDevice_recv]:recv_buf is {:?}",
            rx_buf.get_packet()
        );
        Some(rx_buf.into_buf_ptr())
    }

    fn alloc_send_buffer(&mut self,size:usize)->NetBufPtr {
        let mut send_buf = self.free_send_buffers.pop().unwrap();
        let header_len = send_buf.header_len;
        debug_assert!(header_len + size < send_buf.capacity);
        send_buf.set_packet_len(size);
        send_buf.into_buf_ptr()
    }
}
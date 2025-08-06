use crate::drivers::net::{netdevice::NetBufPtr, starfive::{eth_def::{DmaDesc, VisionfiveGmac, DMA_CH0_RX_CONTROL, DMA_CH0_RX_DESC_TAIL_POINTER, DMA_CH0_STATUS, DMA_CH0_TX_CONTROL, DMA_CH0_TX_DESC_TAIL_POINTER, DMA_CHAN_STATUS_AIS, DMA_CHAN_STATUS_CDE, DMA_CHAN_STATUS_ERI, DMA_CHAN_STATUS_ETI, DMA_CHAN_STATUS_FBE, DMA_CHAN_STATUS_NIS, DMA_CHAN_STATUS_RBU, DMA_CHAN_STATUS_RI, DMA_CHAN_STATUS_RPS, DMA_CHAN_STATUS_RWT, DMA_CHAN_STATUS_TBU, DMA_CHAN_STATUS_TI, DMA_CHAN_STATUS_TPS, EQOS_DESC2_IOC, EQOS_DESC3_BUF1V, EQOS_DESC3_FD, EQOS_DESC3_IOC, EQOS_DESC3_LD, EQOS_DESC3_OWN, EQOS_DMA_BASE, EQOS_DMA_CH0_RX_CONTROL_SR, EQOS_DMA_CH0_TX_CONTROL_ST, EQOS_MAC_BASE, EQOS_MAC_CONFIGURATION_RE, EQOS_MAC_CONFIGURATION_TE, EQOS_MTL_BASE, GMAC_DESC_NUM, MAC_CONFIGURATION}, eth_dev::{eth_dma_reset, eth_get_desc_owner, eth_is_desc_empty, eth_is_last_rx_desc, eth_is_last_tx_desc, eth_mac_read_reg, eth_mac_set_bits, eth_mac_write_reg, eth_set_dma, eth_set_mac, eth_set_mac_addr, eth_set_mtl, eth_set_rx_desc, eth_set_speed_duplex, eth_set_tx_desc, gmac1_clk_init}, eth_phy::genric_gmac_phy_init, platform::{plat_fence, plat_handle_rx_buffer, plat_handle_tx_buffer, plat_phys_to_virt, plat_virt_to_phys}}};

pub fn eth_init(gmacdev:&mut VisionfiveGmac)->VisionfiveGmac {
    //here we just init 0x16040000
    gmac1_clk_init();
    gmacdev.MacBase = gmacdev.iobase + (EQOS_MAC_BASE) as u64;
    gmacdev.DmaBase = gmacdev.iobase + (EQOS_DMA_BASE) as u64;
    gmacdev.MtlBase=gmacdev.iobase+(EQOS_MTL_BASE) as u64;
    gmacdev.PhyBase = 0;
    //todo phy init
    genric_gmac_phy_init(gmacdev);
    eth_dma_reset(gmacdev);
    eth_set_mac_addr(gmacdev);
    eth_set_speed_duplex(gmacdev);
    eth_set_mtl(gmacdev);
    eth_set_mac(gmacdev);
    eth_set_dma(gmacdev);
    eth_set_tx_desc(gmacdev, GMAC_DESC_NUM as u32);
    eth_set_rx_desc(gmacdev, GMAC_DESC_NUM as u32);
    //enable tx
    eth_mac_set_bits(gmacdev.DmaBase, DMA_CH0_TX_CONTROL, EQOS_DMA_CH0_TX_CONTROL_ST);
    //enable rx
    eth_mac_set_bits(gmacdev.DmaBase, DMA_CH0_RX_CONTROL, EQOS_DMA_CH0_RX_CONTROL_SR);
    eth_mac_set_bits(gmacdev.MacBase, MAC_CONFIGURATION, EQOS_MAC_CONFIGURATION_TE | EQOS_MAC_CONFIGURATION_RE);
    log::info!("[eth_init] init complete");
    *gmacdev
}
pub fn eth_tx(gmacdev:&mut VisionfiveGmac,pbuf:NetBufPtr)->i32 {
    log::error!("[eth_tx]begin send");
    let mut buffer: u64 = 0;
    let mut length: u32 = pbuf.packcet_len as u32;
    let mut dma_addr: u32 = 0;
    let mut desc_idx: u32 = gmacdev.TxBusy;
    log::info!("[eth_tx] desc_idx {:?}",desc_idx);
    let mut txdesc: DmaDesc = unsafe { gmacdev.TxDesc[desc_idx as usize].read() } as DmaDesc;
    //in init we only define one desc with LD and we didn`t set pointer now we can definetly define these`
    // let mut is_last: bool = eth_is_last_tx_desc(&txdesc);
    if eth_get_desc_owner(&txdesc) {
        return -1;
    }
    // buffer = gmacdev.TxBuffer[desc_idx as usize];
    // length = unsafe { plat_handle_tx_buffer(pbuf, buffer) };
    // dma_addr = unsafe { plat_virt_to_phys(buffer) };
    dma_addr = unsafe { plat_virt_to_phys(pbuf.packet().as_ptr() as usize as u64) };

    txdesc.des0=dma_addr;
    txdesc.des1=0;
    txdesc.des2= length|EQOS_DESC2_IOC;
    plat_fence();
    txdesc.des3 = EQOS_DESC3_OWN | EQOS_DESC3_FD | EQOS_DESC3_LD | length;
    unsafe {
        gmacdev.TxDesc[desc_idx as usize].write(txdesc);
    }
    let vtail_ptr=gmacdev.TxDesc[desc_idx as usize] as u64;
    let ptail_ptr=plat_virt_to_phys(gmacdev.TxDesc[desc_idx as usize] as u64);
    log::info!("[eth_tx] ptail_ptr is {:#x?},vtail_p{:#x?}",ptail_ptr,vtail_ptr);
    eth_mac_write_reg(gmacdev.DmaBase, DMA_CH0_TX_DESC_TAIL_POINTER, ptail_ptr);
    gmacdev.TxBusy=if (desc_idx + 1)==GMAC_DESC_NUM.try_into().unwrap() { 0 } else { desc_idx + 1 };

    return 0;
}
#[derive(Copy, Clone,Default,Debug)]
#[repr(C)]
pub struct AddrLen {
    pub addr: u64,
    pub len:  u32,
}

pub fn eth_rx(gmacdev: &mut VisionfiveGmac) -> AddrLen {
    log::info!("[eth_rx]begin rx");
    let mut desc_idx: u32 = gmacdev.RxBusy;
    log::info!("[eth_rx] desc_idx {:?}",desc_idx);
    let mut rxdesc: DmaDesc = unsafe { gmacdev.RxDesc[desc_idx as usize].read() } as DmaDesc;
    // let mut is_last: bool = eth_is_last_rx_desc(&rxdesc);
    log::info!("[eth_rx] rxdesc is {:#x?}",rxdesc);
    // if desc_idx>0 {
    //     let rxdesc_front= unsafe { gmacdev.RxDesc[(desc_idx-1) as usize].read() } as DmaDesc;
    //     log::info!("[eth_rx] front desc is {:#x?}",rxdesc_front);
    //     log::info!("[eth_rx] current desc is {:#x?}",rxdesc);
    //     let front_length=rxdesc_front.des3&0x7fff;
    //     log::info!("[eth_rx] front length is {:#x?}",front_length);
    //     plat_handle_rx_buffer(plat_phys_to_virt(rxdesc_front.des0 as u64)as u64, front_length);
    // }

    if eth_is_desc_empty(&rxdesc) || eth_get_desc_owner(&rxdesc) {
        //eth_dma_enable_interrupt(gmacdev, DmaIntEnable);
        
        return AddrLen{addr:0,len:0}
    }

    let mut pbuf: u64 = 0;
    let mut dma_addr = rxdesc.des0;
    let mut len:u32=0;
    let mut length: u32 = rxdesc.des3&0x7fff;
    len=length;
    log::info!("[eth_rx]recv length is {:?}",length);
    let mut buffer: u64 = unsafe { plat_phys_to_virt(dma_addr as u64) as u64};

    plat_fence();
    log::info!("[eth_rx]begin handle rx buffer {:#x}",buffer);
    pbuf = unsafe { plat_handle_rx_buffer(buffer, length) };
    gmacdev.rx_bytes += length as u64;
    gmacdev.rx_packets += 1;

    rxdesc.des0=0;
    plat_fence();
    rxdesc.des0=dma_addr;
    rxdesc.des1=0;
    rxdesc.des2=0;
    plat_fence();
    rxdesc.des3=EQOS_DESC3_OWN | EQOS_DESC3_BUF1V|EQOS_DESC3_IOC;
    plat_fence();
    //gmac has ring method to complex

    unsafe {
        gmacdev.RxDesc[desc_idx as usize].write(rxdesc);
    }
    let v_tail_ptr =gmacdev.RxDesc[desc_idx as usize] as u64;
    let p_tail_prt=plat_virt_to_phys(gmacdev.RxDesc[desc_idx as usize] as u64);
    log::info!("[eth_rx] rx_tail_ptr is {:#x?} p_tail_prt{:#x?}",v_tail_ptr,p_tail_prt);
    eth_mac_write_reg(gmacdev.DmaBase, DMA_CH0_RX_DESC_TAIL_POINTER, p_tail_prt);
    plat_fence(); 

    gmacdev.RxBusy = if (desc_idx + 1) ==GMAC_DESC_NUM.try_into().unwrap() { 0 } else { desc_idx + 1 };
    log::info!("[eth_tx] rx end");
    return AddrLen { addr: pbuf, len: len }
}
pub fn eth_handle_tx_over(gmacdev: &mut VisionfiveGmac) {
    log::error!("[eth_handle_tx_over]begin");
    // loop {
    let mut desc_idx: u32 = gmacdev.TxBusy;
    let mut txdesc: DmaDesc = unsafe { gmacdev.TxDesc[desc_idx as usize].read() } as DmaDesc;
    
    // if !eth_get_desc_owner(&txdesc)&&eth_is_desc_empty(&txdesc) {
    //     log::info!("[eth_handle_tx_over] break");
    //     break;
    // }


    let mut length: u32 = txdesc.des3&0x7fff;
    gmacdev.tx_bytes += length as u64;
    gmacdev.tx_packets += 1;

    // let is_last: bool = eth_is_last_tx_desc(&txdesc);
    txdesc.des0=0;
    txdesc.des1=0;
    txdesc.des2=0;
    txdesc.des3=0;
    unsafe {
        gmacdev.TxDesc[desc_idx as usize].write(txdesc);
    }
    // gmacdev.TxBusy = if (desc_idx + 1)==128 { 0 } else { desc_idx + 1 };
    plat_fence();
    log::error!("[eth_handle_tx_over] txbusy {:?}",gmacdev.TxBusy);
    // }
}
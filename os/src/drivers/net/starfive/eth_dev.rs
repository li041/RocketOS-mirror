/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-08-10 11:24:07
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-08-12 15:36:30
 * @FilePath: /RocketOS_netperfright/os/src/drivers/net/starfive/eth_dev.rs
 * @Description: eth configuration file
 * 
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved. 
 */
use core::ptr::{null_mut, read_volatile, write_volatile};

use crate::{arch::{config::KERNEL_BASE, timer::get_time_ms}, drivers::net::starfive::{eth_def::{DmaDesc, VisionfiveGmac, AXI_CFG, DMA_CH0_CONTROL, DMA_CH0_RX_CONTROL, DMA_CH0_RX_DESC_LIST_ADDRESS, DMA_CH0_RX_DESC_LIST_HADDRESS, DMA_CH0_RX_DESC_RING_LENGTH, DMA_CH0_RX_DESC_TAIL_POINTER, DMA_CH0_TX_CONTROL, DMA_CH0_TX_DESC_LIST_ADDRESS, DMA_CH0_TX_DESC_LIST_HADDRESS, DMA_CH0_TX_DESC_RING_LENGTH, DMA_SYSBUS_MODE, EQOS_DESC2_IOC, EQOS_DESC3_BUF1V, EQOS_DESC3_FD, EQOS_DESC3_IOC, EQOS_DESC3_LD, EQOS_DESC3_OWN, EQOS_DMA_CH0_CONTROL_PBLX8, EQOS_DMA_CH0_RX_CONTROL_RBSZ_MASK, EQOS_DMA_CH0_RX_CONTROL_RBSZ_SHIFT, EQOS_DMA_CH0_RX_CONTROL_RXPBL_MASK, EQOS_DMA_CH0_RX_CONTROL_RXPBL_SHIFT, EQOS_DMA_CH0_TX_CONTROL_TXPBL_MASK, EQOS_DMA_CH0_TX_CONTROL_TXPBL_SHIFT, EQOS_DMA_MODE, EQOS_DMA_SWR, EQOS_DMA_SYSBUS_MODE_BLEN16, EQOS_DMA_SYSBUS_MODE_BLEN4, EQOS_DMA_SYSBUS_MODE_BLEN8, EQOS_DMA_SYSBUS_MODE_EAME, EQOS_DMA_SYSBUS_MODE_RD_OSR_LMT_SHIFT, EQOS_MAC_CONFIGURATION_DM, EQOS_MAC_CONFIGURATION_FES, EQOS_MAC_CONFIGURATION_GPSLCE, EQOS_MAC_CONFIGURATION_JD, EQOS_MAC_CONFIGURATION_JE, EQOS_MAC_CONFIGURATION_PS, EQOS_MAC_CONFIGURATION_WD, EQOS_MAC_HW_FEATURE1_RXFIFOSIZE_MASK, EQOS_MAC_HW_FEATURE1_RXFIFOSIZE_SHIFT, EQOS_MAC_HW_FEATURE1_TXFIFOSIZE_MASK, EQOS_MAC_HW_FEATURE1_TXFIFOSIZE_SHIFT, EQOS_MAC_MDIO_ADDRESS_C45E, EQOS_MAC_MDIO_ADDRESS_CR_100_150M, EQOS_MAC_MDIO_ADDRESS_CR_150_250M, EQOS_MAC_MDIO_ADDRESS_CR_20_35M, EQOS_MAC_MDIO_ADDRESS_CR_250_300M, EQOS_MAC_MDIO_ADDRESS_CR_300_500M, EQOS_MAC_MDIO_ADDRESS_CR_35_60M, EQOS_MAC_MDIO_ADDRESS_CR_500_800M, EQOS_MAC_MDIO_ADDRESS_CR_60_100M, EQOS_MAC_MDIO_ADDRESS_CR_DIV_10, EQOS_MAC_MDIO_ADDRESS_CR_DIV_4, EQOS_MAC_MDIO_ADDRESS_CR_DIV_6, EQOS_MAC_MDIO_ADDRESS_CR_DIV_8, EQOS_MAC_MDIO_ADDRESS_CR_SHIFT, EQOS_MAC_MDIO_ADDRESS_GB, EQOS_MAC_MDIO_ADDRESS_GOC_READ, EQOS_MAC_MDIO_ADDRESS_GOC_SHIFT, EQOS_MAC_MDIO_ADDRESS_GOC_WRITE, EQOS_MAC_MDIO_ADDRESS_PA_SHIFT, EQOS_MAC_MDIO_ADDRESS_RDA_SHIFT, EQOS_MAC_MDIO_ADDRESS_SKAP, EQOS_MAC_MDIO_DATA_GD_MASK, EQOS_MAC_Q0_TX_FLOW_CTRL_PT_SHIFT, EQOS_MAC_Q0_TX_FLOW_CTRL_TFE, EQOS_MAC_RXQ_CTRL0_RXQ0EN_ENABLED_DCB, EQOS_MAC_RXQ_CTRL0_RXQ0EN_MASK, EQOS_MAC_RXQ_CTRL0_RXQ0EN_SHIFT, EQOS_MAC_RXQ_CTRL2_PSRQ0_MASK, EQOS_MAC_RXQ_CTRL2_PSRQ0_SHIFT, EQOS_MAC_RX_FLOW_CTRL_RFE, EQOS_MAC_TXQ_PRTY_MAP0_PSTQ0_MASK, EQOS_MAC_TXQ_PRTY_MAP0_PSTQ0_SHIFT, EQOS_MAX_PACKET_SIZE, EQOS_MTL_RXQ0_OPERATION_MODE_EHFC, EQOS_MTL_RXQ0_OPERATION_MODE_FEP, EQOS_MTL_RXQ0_OPERATION_MODE_FUP, EQOS_MTL_RXQ0_OPERATION_MODE_RFA_MASK, EQOS_MTL_RXQ0_OPERATION_MODE_RFA_SHIFT, EQOS_MTL_RXQ0_OPERATION_MODE_RFD_MASK, EQOS_MTL_RXQ0_OPERATION_MODE_RFD_SHIFT, EQOS_MTL_RXQ0_OPERATION_MODE_RQS_MASK, EQOS_MTL_RXQ0_OPERATION_MODE_RQS_SHIFT, EQOS_MTL_RXQ0_OPERATION_MODE_RSF, EQOS_MTL_RXQ0_OP_MODE, EQOS_MTL_TXQ0_OPERATION_MODE_TQS_MASK, EQOS_MTL_TXQ0_OPERATION_MODE_TQS_SHIFT, EQOS_MTL_TXQ0_OPERATION_MODE_TSF, EQOS_MTL_TXQ0_OPERATION_MODE_TXQEN_ENABLED, EQOS_MTL_TXQ0_OPERATION_MODE_TXQEN_SHIFT, EQOS_MTL_TXQ0_OP_MODE, EQOS_MTL_TXQ0_QUANTUM_WEG, GMAC1_CLK_AHB, GMAC1_CLK_AXI, GMAC1_CLK_GTXC, GMAC1_CLK_PTP, GMAC1_CLK_TX, GMAC_CLK_AHB_RST, GMAC_CLK_AXI_RST, GMAC_PHY_FULL_DUPLEX, GMAC_PHY_HALF_DUPLEX, GMAC_PHY_SPEED_1000M, GMAC_PHY_SPEED_100M, GMAC_PHY_SPEED_10M, JH7110_PLL2_DACPD_MASK, JH7110_PLL2_DACPD_SHIFT, JH7110_PLL2_DSMPD_MASK, JH7110_PLL2_DSMPD_SHIFT, JH7110_PLL2_FBDIV_MASK, JH7110_PLL2_FBDIV_OFFSET, JH7110_PLL2_FBDIV_SHIFTL, JH7110_PLL2_FRAC_OFFSET, JH7110_PLL2_PD_OFFSET, JH7110_PLL2_PREDIV_OFFSET, JH7110_PLL_FRAC_MASK, JH7110_PLL_FRAC_SHIFT, JH7110_PLL_POSTDIV1_MASK, JH7110_PLL_POSTDIV1_SHIFT, JH7110_PLL_PREDIV_MASK, JH7110_PLL_PREDIV_SHIFT, MAC_ADDRESS_HIGH, MAC_ADDRESS_LOW, MAC_CONFIGURATION, MAC_HW_FEATURE1, MAC_MDIO_ADDRESS, MAC_MDIO_DATA, MAC_Q0_TX_FLOW_CTRL, MAC_RXQ_CTRL0, MAC_RXQ_CTRL2, MAC_RX_FLOW_CTRL, MAC_TXQ_PRTY_MAP0, PERI_ROOT, STG_AXI_AHB, SYS_CRG_BASE, SYS_CRG_RESET2, SYS_SYSCON_BASE, VA_SYS_CRG_BASE, VA_SYS_SYSCON_BASE}, platform::{plat_fence, plat_malloc_align, plat_mdelay, plat_virt_to_phys}}, mm::{MapArea, MapPermission, MapType, VPNRange, VirtAddr, KERNEL_SPACE}, task::wait_timeout};
/// 生成 [l..=h] 全 1 的掩码，返回 u32。
/// 如果 h < l 或 l >= 32，返回 0；如果 range 覆盖 0..=31（len == 32），返回 u32::MAX。
pub const fn genmask_u32(h: u32, l: u32) -> u32 {
    // 非法或越界情况
    if h < l || l >= 32 {
        return 0;
    }

    let len = h - l + 1;
    // 若长度 >= 32，则返回全 1（u32::MAX）
    if len >= 32 {
        return u32::MAX;
    }

    // 用 u128 做中间计算以避免移位溢出
    let mask128: u128 = ((1u128 << (len as u128)) - 1u128) << (l as u128);
    mask128 as u32
}


pub fn eth_mac_read_reg(base: u64, offset: u32) -> u32 {
    let mut addr: u64 = 0;
    let mut data: u32 = 0;
    addr = base + offset as u64;
    unsafe { data = read_volatile(addr as *mut u32) };
    return data;
}

pub fn eth_mac_write_reg(mut base: u64, mut offset: u32, mut data: u32) {
    let mut addr: u64;
    addr = base + offset as u64;
    unsafe { write_volatile(addr as *mut u32, data) };
}
pub fn eth_mac_set_bits(base: u64, offset: u32, pos: u32) {
    let mut data: u32 = 0;
    data = eth_mac_read_reg(base, offset);
    data |= pos;
    eth_mac_write_reg(base, offset, data);
}
pub fn eth_mac_clrset_bits(base: u64, offset: u32, clear: u32, set: u32) {
    let mut val: u32 = eth_mac_read_reg(base, offset);
    val = (val & !clear) | set;
    eth_mac_write_reg(base, offset, val);
}
pub fn eth_mac_clear_bits(base: u64, offset: u32, pos: u32) {
    let mut data: u32 = 0;
    data = eth_mac_read_reg(base, offset);
    data &= !pos;
    eth_mac_write_reg(base, offset, data);
}
pub fn eth_dma_reset(gmacdev:&VisionfiveGmac) {
    let mut data:u32=0;
    eth_mac_write_reg(gmacdev.DmaBase, EQOS_DMA_MODE, EQOS_DMA_SWR);
    loop {
        data = eth_mac_read_reg(gmacdev.DmaBase, EQOS_DMA_MODE);
        if (data & 1) == 0 {
            break;
        }
    }
}
pub fn eth_set_speed_duplex(gmacdev:&VisionfiveGmac){
    let speed=gmacdev.speedmode;
    let duplex=gmacdev.DuplexMode;
    if speed==GMAC_PHY_SPEED_10M {
        eth_mac_clrset_bits(gmacdev.DmaBase, MAC_CONFIGURATION,EQOS_MAC_CONFIGURATION_FES , EQOS_MAC_CONFIGURATION_PS);
    }
    else if speed==GMAC_PHY_SPEED_100M {
        eth_mac_set_bits(gmacdev.DmaBase,MAC_CONFIGURATION,EQOS_MAC_CONFIGURATION_PS|EQOS_MAC_CONFIGURATION_FES);
    }
    else if speed==GMAC_PHY_SPEED_1000M {
        eth_mac_clear_bits(gmacdev.DmaBase,MAC_CONFIGURATION,EQOS_MAC_CONFIGURATION_PS|EQOS_MAC_CONFIGURATION_FES);
    }

    if duplex==GMAC_PHY_HALF_DUPLEX {
        eth_mac_set_bits(gmacdev.DmaBase, MAC_CONFIGURATION, EQOS_MAC_CONFIGURATION_DM);
    }
    else if duplex==GMAC_PHY_FULL_DUPLEX {
        eth_mac_clear_bits(gmacdev.DmaBase, MAC_CONFIGURATION, EQOS_MAC_CONFIGURATION_DM);
        
    }
}
pub fn eth_set_mtl(gmacdev:&VisionfiveGmac) {
    /* Enable Store and Forward mode for TX */
    /* Program Tx operating mode */
    eth_mac_set_bits(gmacdev.MtlBase, EQOS_MTL_TXQ0_OP_MODE, EQOS_MTL_TXQ0_OPERATION_MODE_TSF|(EQOS_MTL_TXQ0_OPERATION_MODE_TXQEN_ENABLED<<EQOS_MTL_TXQ0_OPERATION_MODE_TXQEN_SHIFT));
    /* Transmit Queue weight */
    eth_mac_write_reg(gmacdev.MtlBase, EQOS_MTL_TXQ0_QUANTUM_WEG, 0x10);
    /* Enable Store and Forward mode for RX, since no jumbo frame */
    eth_mac_set_bits(gmacdev.MtlBase, EQOS_MTL_RXQ0_OP_MODE,EQOS_MTL_RXQ0_OPERATION_MODE_RSF |EQOS_MTL_RXQ0_OPERATION_MODE_FEP |EQOS_MTL_RXQ0_OPERATION_MODE_FUP );
    /* Transmit/Receive queue fifo size; use all RAM for 1 queue */
    let val=eth_mac_read_reg(gmacdev.MacBase, MAC_HW_FEATURE1);
    log::info!("[eth_set_mtl] read hw_features1 val{:#x?}",val);
    let tx_fifo_sz=(val>>EQOS_MAC_HW_FEATURE1_TXFIFOSIZE_SHIFT)&EQOS_MAC_HW_FEATURE1_TXFIFOSIZE_MASK;
    let rx_fifo_sz=(val>>EQOS_MAC_HW_FEATURE1_RXFIFOSIZE_SHIFT)&EQOS_MAC_HW_FEATURE1_RXFIFOSIZE_MASK;
    /*
    * r/tx_fifo_sz is encoded as log2(n / 128). Undo that by shifting.
    * r/tqs is encoded as (n / 256) - 1.
    */

    let tqs=(128<<tx_fifo_sz)/256-1;
    let rqs=(128<<rx_fifo_sz)/256-1;
    log::info!("[eth_set_mtl] tqs is {:?},rqs is {:?}",tqs,rqs);
    eth_mac_clrset_bits(gmacdev.MtlBase, EQOS_MTL_TXQ0_OP_MODE, EQOS_MTL_TXQ0_OPERATION_MODE_TQS_MASK <<
            EQOS_MTL_TXQ0_OPERATION_MODE_TQS_SHIFT, 
            tqs << EQOS_MTL_TXQ0_OPERATION_MODE_TQS_SHIFT);
    eth_mac_clrset_bits(gmacdev.MtlBase, EQOS_MTL_RXQ0_OP_MODE, EQOS_MTL_RXQ0_OPERATION_MODE_RQS_MASK <<
            EQOS_MTL_RXQ0_OPERATION_MODE_RQS_SHIFT,
            rqs << EQOS_MTL_RXQ0_OPERATION_MODE_RQS_SHIFT);
    /* Flow control used only if each channel gets 4KB or more FIFO */
    if (rqs>=((4096/256)-1)) {
        let mut rfd;
        let mut rfa;
        eth_mac_set_bits(gmacdev.MtlBase, EQOS_MTL_RXQ0_OP_MODE, EQOS_MTL_RXQ0_OPERATION_MODE_EHFC);
        /*
         * Set Thr eshold for Activating Flow Contol space for min 2
         * frames ie, (1500 * 1) = 1500 bytes.
         *
         * Set Threshold for Deactivating Flow Contol for space of
         * min 1 frame (frame size 1500bytes) in receive fifo
         */
        if (rqs == ((4096 / 256) - 1)) {
            /*
             * This violates the above formula because of FIFO size
             * limit therefore overflow may occur inspite of this.
             */
            rfd = 0x3;  /* Full-3K */
            rfa = 0x1;  /* Full-1.5K */
        } else if (rqs == ((8192 / 256) - 1)) {
            rfd = 0x6;  /* Full-4K */
            rfa = 0xa;  /* Full-6K */
        } else if (rqs == ((16384 / 256) - 1)) {
            rfd = 0x6;  /* Full-4K */
            rfa = 0x12; /* Full-10K */
        } else {
            rfd = 0x6;  /* Full-4K */
            rfa = 0x1E; /* Full-16K */
        }
        eth_mac_clrset_bits(gmacdev.MtlBase, EQOS_MTL_RXQ0_OP_MODE, 
            (EQOS_MTL_RXQ0_OPERATION_MODE_RFD_MASK <<
                 EQOS_MTL_RXQ0_OPERATION_MODE_RFD_SHIFT) |
                (EQOS_MTL_RXQ0_OPERATION_MODE_RFA_MASK <<
                 EQOS_MTL_RXQ0_OPERATION_MODE_RFA_SHIFT), 
                  (rfd <<
                 EQOS_MTL_RXQ0_OPERATION_MODE_RFD_SHIFT) |
                (rfa <<
                 EQOS_MTL_RXQ0_OPERATION_MODE_RFA_SHIFT));

    }
}

pub fn eth_set_mac(gmacdev:&VisionfiveGmac) {
    eth_mac_clrset_bits(gmacdev.MacBase, MAC_RXQ_CTRL0, 
        EQOS_MAC_RXQ_CTRL0_RXQ0EN_MASK <<
            EQOS_MAC_RXQ_CTRL0_RXQ0EN_SHIFT, 
        EQOS_MAC_RXQ_CTRL0_RXQ0EN_ENABLED_DCB <<
            EQOS_MAC_RXQ_CTRL0_RXQ0EN_SHIFT);
    /* Set TX flow control parameters */
    /* Set Pause Time */
    eth_mac_set_bits(gmacdev.MacBase, MAC_Q0_TX_FLOW_CTRL, 
        0xffff<<EQOS_MAC_Q0_TX_FLOW_CTRL_PT_SHIFT);
    /* Assign priority for TX flow control */
    eth_mac_clear_bits(gmacdev.MacBase, MAC_TXQ_PRTY_MAP0, 
        EQOS_MAC_TXQ_PRTY_MAP0_PSTQ0_MASK<<EQOS_MAC_TXQ_PRTY_MAP0_PSTQ0_SHIFT);
    /* Assign priority for RX flow control */
    eth_mac_clear_bits(gmacdev.MacBase, MAC_RXQ_CTRL2, 
         EQOS_MAC_RXQ_CTRL2_PSRQ0_MASK <<
             EQOS_MAC_RXQ_CTRL2_PSRQ0_SHIFT);
    /* Enable flow control */
    eth_mac_set_bits(gmacdev.MacBase, MAC_Q0_TX_FLOW_CTRL, 
        EQOS_MAC_Q0_TX_FLOW_CTRL_TFE);
    eth_mac_set_bits(gmacdev.MacBase, MAC_RX_FLOW_CTRL, EQOS_MAC_RX_FLOW_CTRL_RFE);

    eth_mac_clear_bits(gmacdev.MacBase, MAC_CONFIGURATION, 
        EQOS_MAC_CONFIGURATION_GPSLCE|
    EQOS_MAC_CONFIGURATION_WD|EQOS_MAC_CONFIGURATION_JD|EQOS_MAC_CONFIGURATION_JE);

}
pub fn eth_set_dma(gmacdev:&VisionfiveGmac) {
    //we don`t open osp here in case of we in loop we didn`t prepare for second packet
    /* RX buffer size. Must be a multiple of bus width */
    eth_mac_clrset_bits(gmacdev.DmaBase, DMA_CH0_RX_CONTROL, 
        EQOS_DMA_CH0_RX_CONTROL_RBSZ_MASK <<
            EQOS_DMA_CH0_RX_CONTROL_RBSZ_SHIFT,
            EQOS_MAX_PACKET_SIZE <<
            EQOS_DMA_CH0_RX_CONTROL_RBSZ_SHIFT);
    eth_mac_set_bits(gmacdev.DmaBase, DMA_CH0_CONTROL,EQOS_DMA_CH0_CONTROL_PBLX8);
    let mut val=eth_mac_read_reg(gmacdev.MacBase, MAC_HW_FEATURE1);
    log::info!("[eth_set_mtl] read hw_features1 val{:#x?}",val);
    let tx_fifo_sz=(val>>EQOS_MAC_HW_FEATURE1_TXFIFOSIZE_SHIFT)&EQOS_MAC_HW_FEATURE1_TXFIFOSIZE_MASK;
    let rx_fifo_sz=(val>>EQOS_MAC_HW_FEATURE1_RXFIFOSIZE_SHIFT)&EQOS_MAC_HW_FEATURE1_RXFIFOSIZE_MASK;
    /*
    * r/tx_fifo_sz is encoded as log2(n / 128). Undo that by shifting.
    * r/tqs is encoded as (n / 256) - 1.
    */

    let tqs=(128<<tx_fifo_sz)/256-1;
    let rqs=(128<<rx_fifo_sz)/256-1;
    log::info!("[eth_set_mtl] tqs is {:?},rqs is {:?}",tqs,rqs);
    /*
     * Burst length must be < 1/2 FIFO size.
     * FIFO size in tqs is encoded as (n / 256) - 1.
     * Each burst is n * 8 (PBLX8) * 16 (AXI width) == 128 bytes.
     * Half of n * 256 is n * 128, so pbl == tqs, modulo the -1.
     */
    let mut pbl = tqs + 1;
    if (pbl > 32)
    {
        pbl = 32;
    }
    eth_mac_clrset_bits(gmacdev.DmaBase, DMA_CH0_TX_CONTROL, 
        EQOS_DMA_CH0_TX_CONTROL_TXPBL_MASK<<EQOS_DMA_CH0_TX_CONTROL_TXPBL_SHIFT
        , pbl<<EQOS_DMA_CH0_TX_CONTROL_TXPBL_SHIFT);
    eth_mac_clrset_bits(gmacdev.DmaBase, DMA_CH0_RX_CONTROL, 
        EQOS_DMA_CH0_RX_CONTROL_RXPBL_MASK<<EQOS_DMA_CH0_RX_CONTROL_RXPBL_SHIFT
        , 8<<EQOS_DMA_CH0_RX_CONTROL_RXPBL_SHIFT);
    /* DMA performance configuration */
    let v= (2 << EQOS_DMA_SYSBUS_MODE_RD_OSR_LMT_SHIFT) |
        EQOS_DMA_SYSBUS_MODE_EAME | EQOS_DMA_SYSBUS_MODE_BLEN16 |
        EQOS_DMA_SYSBUS_MODE_BLEN8 | EQOS_DMA_SYSBUS_MODE_BLEN4;
    eth_mac_write_reg(gmacdev.DmaBase, DMA_SYSBUS_MODE, v);
}
pub fn eth_set_tx_desc(gmacdev:&mut VisionfiveGmac,desc_num:u32) {
    let mut desc: *mut DmaDesc = null_mut();
    let mut dma_addr: u32 = 0;
    let mut buffer: u64 = 0;

    desc = unsafe { plat_malloc_align((size_of::<DmaDesc>() * (desc_num as usize)) as u64, 32) }
        as *mut DmaDesc;
    dma_addr = unsafe { plat_virt_to_phys(desc as u64) };

    gmacdev.TxNext = 0;
    gmacdev.TxBusy = 0;
    eth_mac_write_reg(gmacdev.DmaBase, DMA_CH0_TX_DESC_LIST_HADDRESS, 0);
    eth_mac_write_reg(gmacdev.DmaBase,DMA_CH0_TX_DESC_LIST_ADDRESS, dma_addr);
    eth_mac_write_reg(gmacdev.DmaBase, DMA_CH0_TX_DESC_RING_LENGTH, desc_num);
    for i in 0..desc_num {
        // buffer = unsafe { plat_malloc_align(4096, 32) };
        gmacdev.TxDesc[i as usize] = desc;
        log::info!("[eth_set_tx_desc] desc is {:#x?}",desc as usize);
        gmacdev.TxBuffer[i as usize] = buffer;

        let is_last = i == desc_num - 1;
        unsafe {
            (*desc).des0 = 0;
            (*desc).des1= 0;
            (*desc).des2 = 0;
            (*desc).des3 = 0;
            // if i==0 {
            //     (*desc).des3|=EQOS_DESC3_FD;
            // }
            // else if is_last {
            //     (*desc).des3|=EQOS_DESC3_LD;
            // }
            plat_fence();
            desc = desc.offset(1);
        }
    }
}
pub fn eth_set_rx_desc(gmacdev:&mut VisionfiveGmac,desc_num:u32){
    let mut desc: *mut DmaDesc = null_mut();
    let mut dma_addr: u32 = 0;
    let mut buffer: u64 = 0;
    desc = unsafe { plat_malloc_align((size_of::<DmaDesc>() * (desc_num as usize)) as u64, 32) }
        as *mut DmaDesc;
    dma_addr = unsafe { plat_virt_to_phys(desc as u64)};

    gmacdev.RxBusy = 0;
    eth_mac_write_reg(gmacdev.DmaBase, DMA_CH0_RX_DESC_LIST_HADDRESS, 0);
    eth_mac_write_reg(gmacdev.DmaBase,DMA_CH0_RX_DESC_LIST_ADDRESS, dma_addr);
    eth_mac_write_reg(gmacdev.DmaBase, DMA_CH0_RX_DESC_RING_LENGTH, desc_num);
    for i in 0..desc_num{
        buffer = unsafe { plat_malloc_align(4096, 32) };
        dma_addr = unsafe { plat_virt_to_phys(buffer) };
        log::info!("[eth_set_rx_desc] desc is {:#x?}",desc as u64);
        gmacdev.RxDesc[i as usize] = desc;
        gmacdev.RxBuffer[i as usize] = buffer;
        let is_last = i == desc_num - 1;
        unsafe{
            (*desc).des0=dma_addr;
            //we don`t use interrupt here`
            (*desc).des3 |=EQOS_DESC3_OWN|EQOS_DESC3_BUF1V|EQOS_DESC3_IOC;
            // if i==0 {
            //     (*desc).des3|=EQOS_DESC3_FD;
            // }
            // else if is_last {
            //     (*desc).des3|=EQOS_DESC3_LD;
            // }
            plat_fence();
            if is_last {
                /* TX tail pointer not written until we need to TX a packet */
                /*
                * Point RX tail pointer at last descriptor. Ideally, we'd point at the
                * first descriptor, implying all descriptors were available. However,
                * that's not distinguishable from none of the descriptors being
                * available.
                */
                eth_mac_write_reg(gmacdev.DmaBase, 
                    DMA_CH0_RX_DESC_TAIL_POINTER, 
                    plat_virt_to_phys(desc as u64));
            }
            desc = desc.offset(1);
        }
    }
}
pub fn eth_is_last_rx_desc(desc: &DmaDesc) -> bool {
    return desc.des3 & EQOS_DESC3_LD != 0;
}

pub fn eth_is_last_tx_desc(desc: &DmaDesc) -> bool {
    return desc.des3 & EQOS_DESC3_LD != 0;
}
pub fn eth_get_desc_owner(desc: &DmaDesc) -> bool {
    return (desc.des3 & EQOS_DESC3_OWN) != 0;
}
pub fn eth_is_desc_empty(desc: &DmaDesc)->bool {
    return desc.des3&0x7fff==0;
}
pub fn eth_set_mac_addr(gmacdev:&VisionfiveGmac){
    let addr: [u8; 6] = gmacdev.MacAddr;
    let mut data: u32;

    data = ((addr[5] as u32) << 8) | (addr[4] as u32)|(1 << 31);
    eth_mac_write_reg(gmacdev.MacBase, MAC_ADDRESS_HIGH, data);

    data = ((addr[3] as u32) << 24)
        | ((addr[2] as u32) << 16)
        | ((addr[1] as u32) << 8)
        | (addr[0] as u32);
    eth_mac_write_reg(gmacdev.MacBase, MAC_ADDRESS_LOW, data);
}
pub fn gmac1_clk_init(){
    KERNEL_SPACE.lock().push_with_offset(
        MapArea::new(
            VPNRange::new(
                VirtAddr::from(KERNEL_BASE + 0x13020000).floor(),
                VirtAddr::from(KERNEL_BASE + 0x13020000 + 65536).ceil(),
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
            VirtAddr::from(KERNEL_BASE + 0x13030000).floor(),
            VirtAddr::from(KERNEL_BASE + 0x13030000 + 65536).ceil(),
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
    eth_mac_set_bits(VA_SYS_CRG_BASE, GMAC1_CLK_AHB, 1u32<<31);
    eth_mac_set_bits(VA_SYS_CRG_BASE, GMAC1_CLK_AXI, 1u32<<31);
    eth_mac_set_bits(VA_SYS_CRG_BASE, GMAC1_CLK_PTP, 1u32<<31);
    eth_mac_set_bits(VA_SYS_CRG_BASE, GMAC1_CLK_GTXC, 1u32<<31);
    eth_mac_set_bits(VA_SYS_CRG_BASE, GMAC1_CLK_TX, 1u32<<31);
    eth_mac_clear_bits(VA_SYS_CRG_BASE, SYS_CRG_RESET2, GMAC_CLK_AXI_RST);
    eth_mac_clear_bits(VA_SYS_CRG_BASE, SYS_CRG_RESET2, GMAC_CLK_AHB_RST);
}
pub fn wait_for_bits(base:u64,offset: u32,mask:u32,set:u32,timeout_ms:u32)->i32{
    let start=get_time_ms() as u32;
    loop{
        let mut val=eth_mac_read_reg(base, offset);
        if set==0 {
            val = !val;
        }
        if (val&mask)==mask{
            return 0;
        }
        //todo
        if start+timeout_ms>(get_time_ms()/10) as u32 {
            break;
        }
        plat_mdelay(1);
        
    }
    return -1;
}
pub fn eqos_mdio_read(gmacdev:&VisionfiveGmac,addr:u32,reg:u32)->i32{
    let mut ret=wait_for_bits(gmacdev.MacBase, MAC_MDIO_ADDRESS, EQOS_MAC_MDIO_ADDRESS_GB, 0, 1000000);
    if ret<0 {
        println!("[eqos_mdio_read] read time out");
        return -1;
    }
    let csr_clk_range=csr_clk_range_get();
    // log::info!("[eqos_mdio_read]csr_clk_range is {:?}",csr_clk_range);
    let mut mdio_val=eth_mac_read_reg(gmacdev.MacBase, MAC_MDIO_ADDRESS);
    mdio_val&=EQOS_MAC_MDIO_ADDRESS_SKAP|EQOS_MAC_MDIO_ADDRESS_C45E;
    mdio_val|=(addr<<EQOS_MAC_MDIO_ADDRESS_PA_SHIFT)|(reg<<EQOS_MAC_MDIO_ADDRESS_RDA_SHIFT)|
    (csr_clk_range<<EQOS_MAC_MDIO_ADDRESS_CR_SHIFT)|(EQOS_MAC_MDIO_ADDRESS_GOC_READ <<
         EQOS_MAC_MDIO_ADDRESS_GOC_SHIFT) |
        EQOS_MAC_MDIO_ADDRESS_GB;
    
    eth_mac_write_reg(gmacdev.MacBase, MAC_MDIO_ADDRESS, mdio_val);
    // log::info!("[eqos_mdio_read] write mdio address {:?}",mdio_val);
    // plat_mdelay(10);
    // log::info!("[eqos_mdio_read] after mdelay");
    // ret=wait_for_bits(gmacdev.MacBase, MAC_MDIO_ADDRESS,EQOS_MAC_MDIO_ADDRESS_GB, 0, 1000000);
    loop {
        ret=wait_for_bits(gmacdev.MacBase, MAC_MDIO_ADDRESS,EQOS_MAC_MDIO_ADDRESS_GB, 0, 1000000);
        if ret>=0 {
            break;
        }
    }
    mdio_val=eth_mac_read_reg(gmacdev.MacBase, MAC_MDIO_DATA);
    // log::info!("[eqos_mdio_read] read mdio val is {:#x}",mdio_val);
    mdio_val&=EQOS_MAC_MDIO_DATA_GD_MASK;
    // log::info!("[eqos_mdio_read] mdio_val is {:?}",mdio_val);
    return mdio_val as i32;
}
pub fn eqos_mdio_write(gmacdev:&VisionfiveGmac,addr:u32,reg:u32,data:u32)->i32 {
    let mut ret=wait_for_bits(gmacdev.MacBase, MAC_MDIO_ADDRESS, EQOS_MAC_MDIO_ADDRESS_GB, 0, 1000000);
    if ret<0 {
        println!("[eqos_mdio_write] read time out1");
        return ret;
    }
    eth_mac_write_reg(gmacdev.MacBase, MAC_MDIO_DATA, data&0xffff);
    //todo
    let csr_clk_range=csr_clk_range_get();
    let mut mdio_val=eth_mac_read_reg(gmacdev.MacBase, MAC_MDIO_ADDRESS);
    mdio_val&=EQOS_MAC_MDIO_ADDRESS_SKAP|EQOS_MAC_MDIO_ADDRESS_C45E;
    mdio_val|=(addr<<EQOS_MAC_MDIO_ADDRESS_PA_SHIFT)|(reg<<EQOS_MAC_MDIO_ADDRESS_RDA_SHIFT)|
    (csr_clk_range<<EQOS_MAC_MDIO_ADDRESS_CR_SHIFT)|(EQOS_MAC_MDIO_ADDRESS_GOC_WRITE <<
         EQOS_MAC_MDIO_ADDRESS_GOC_SHIFT) |
        EQOS_MAC_MDIO_ADDRESS_GB;
    
    eth_mac_write_reg(gmacdev.MacBase, MAC_MDIO_ADDRESS, mdio_val);
    // plat_mdelay(1000);
    loop {
        ret=wait_for_bits(gmacdev.MacBase, MAC_MDIO_ADDRESS,EQOS_MAC_MDIO_ADDRESS_GB, 0, 1000000);
        if ret>=0 {
            break;
        }
    }
    return 0;
}
pub fn gmac_mdio_read(gmacdev:&VisionfiveGmac,addr:u32,reg:u32)->i32 {
    //eqos_mdio_read(gmac->priv, gmac->gmac_config.phy_addr, reg, data, 2);
    eqos_mdio_read(gmacdev, addr, reg)
}

pub fn gmac_mdio_write(gmacdev:&VisionfiveGmac,addr:u32,reg:u32,data:u32)->i32 {
    //eqos_mdio_write(gmac->priv, gmac->gmac_config.phy_addr, reg, &data, 2);
    eqos_mdio_write(gmacdev, addr, reg, data)
}



pub fn csr_clk_range_get()->u32 {
    let mut clk_m=0;
    clk_m=sys_gmac_get_csr_clk();
    // log::info!("[csr_clk_range_get] clk_m is {:?}",clk_m);
    clk_m=clk_m/1000000;
    match clk_m {
        0..=7   => EQOS_MAC_MDIO_ADDRESS_CR_DIV_4,
        8..=11  => EQOS_MAC_MDIO_ADDRESS_CR_DIV_6,
        12..=15 => EQOS_MAC_MDIO_ADDRESS_CR_DIV_8,
        16..=19 => EQOS_MAC_MDIO_ADDRESS_CR_DIV_10,
        20..=34 => EQOS_MAC_MDIO_ADDRESS_CR_20_35M,   // div 16
        35..=59 => EQOS_MAC_MDIO_ADDRESS_CR_35_60M,   // div 26
        60..=99 => EQOS_MAC_MDIO_ADDRESS_CR_60_100M,  // div 42
        100..=149 => EQOS_MAC_MDIO_ADDRESS_CR_100_150M, // div 62
        150..=249 => EQOS_MAC_MDIO_ADDRESS_CR_150_250M, // div 102
        250..=299 => EQOS_MAC_MDIO_ADDRESS_CR_250_300M, // div 124
        300..=499 => EQOS_MAC_MDIO_ADDRESS_CR_300_500M, // div 204
        500..=800 => EQOS_MAC_MDIO_ADDRESS_CR_500_800M, // div 324
        _ => EQOS_MAC_MDIO_ADDRESS_CR_500_800M, // default
    }

    
}
pub fn sys_gmac_get_csr_clk()->u64 {
    get_stg_axi_ahb_rate()
}
pub fn get_stg_axi_ahb_rate()->u64 {
    let rate=get_axi_cfg_rate();
    let mask=genmask_u32(23, 0) as u64;
    let div=eth_mac_read_reg(VA_SYS_CRG_BASE, STG_AXI_AHB) as u64;
    rate/(div&mask)

}
pub fn get_axi_cfg_rate()->u64 {
    let rate=get_bus_root_rate();
    let mask=genmask_u32(23, 0) as u64;
    let div=eth_mac_read_reg(VA_SYS_CRG_BASE, AXI_CFG) as u64;
    rate/(div&mask)

}
pub fn get_bus_root_rate()->u64 {
    let rate=jh7110_pll_get_rate(2);
    let div=(eth_mac_read_reg(VA_SYS_CRG_BASE, PERI_ROOT)>>24)as u64;
    rate/div
}
const JH7110_PLL_OSC_RATE:u32=24000000;


#[derive(Debug,Copy, Clone)]
#[repr(C)]
pub struct jh7110_pll_regvals {
        dacpd:u32,
        dsmpd:u32,
        fbdiv:u32,
        frac:u32,
        postdiv1:u32,
        prediv:u32
}
#[derive(Debug)]
pub struct jh7110_pll_info{
    offsets:jh7110_pll_info_offset,
    masks:jh7110_pll_info_masks,
    shifts:jh7110_pll_info_shifts
}
#[derive(Debug)]
pub struct jh7110_pll_info_offset{
    pd:u32,
    fbdiv:u32,
    frac:u32,
    prediv:u32
}
#[derive(Debug)]
pub struct jh7110_pll_info_masks{
    dacpd:u32,
    dsmpd:u32,
    fbdiv:u32,
}
#[derive(Debug)]
pub struct jh7110_pll_info_shifts{
    dacpd:u32,
    dsmpd:u32,
    fbdiv:u32,
}
pub const JH7110_PLL_INFO:jh7110_pll_info=jh7110_pll_info{
    offsets:jh7110_pll_info_offset { pd: JH7110_PLL2_PD_OFFSET, fbdiv: JH7110_PLL2_FBDIV_OFFSET, frac: JH7110_PLL2_FRAC_OFFSET, prediv: JH7110_PLL2_PREDIV_OFFSET },
    masks:jh7110_pll_info_masks { dacpd: JH7110_PLL2_DACPD_MASK, dsmpd: JH7110_PLL2_DSMPD_MASK, fbdiv: JH7110_PLL2_FBDIV_MASK },
    shifts:jh7110_pll_info_shifts { dacpd: JH7110_PLL2_DACPD_SHIFT, dsmpd: JH7110_PLL2_DSMPD_SHIFT, fbdiv: JH7110_PLL2_FBDIV_SHIFTL }
};



pub fn jh7110_pll_get_rate(id:u32)->u64 {
    let mut rate=JH7110_PLL_OSC_RATE;
    let mut parent_rate=JH7110_PLL_OSC_RATE;
    let val=jh7110_pll_regvals_get(JH7110_PLL_INFO);
    // log::info!("[jh7110_pll_get_rate] val is {:?}",val);
    if (val.dacpd==0)&&(val.dsmpd==0) {
        rate=parent_rate*val.frac/(1u32<<24);
    }
    else if (val.dacpd==1)&&(val.dsmpd==1) {
        rate=0;
    }
    else {
        return 0;
    }
    rate+=parent_rate*val.fbdiv;
    rate/=val.prediv<<val.postdiv1;
    // log::info!("[jh7110_pll_get_rate] get rate complete");
    return rate as u64;
}
pub fn jh7110_pll_regvals_get(info:jh7110_pll_info)->jh7110_pll_regvals {
    let mut ret=jh7110_pll_regvals{
        dacpd: 0,
        dsmpd: 0,
        fbdiv: 0,
        frac: 0,
        postdiv1: 0,
        prediv: 0,
    };
    let mut val=eth_mac_read_reg(VA_SYS_SYSCON_BASE, info.offsets.pd);
    ret.dacpd=(val&info.masks.dacpd)>>info.shifts.dacpd;
    ret.dsmpd=(val&info.masks.dsmpd)>>info.shifts.dsmpd;
    
    val=eth_mac_read_reg(VA_SYS_SYSCON_BASE, info.offsets.fbdiv);
    ret.fbdiv=(val&info.masks.fbdiv)>>info.shifts.fbdiv;

    val=eth_mac_read_reg(VA_SYS_SYSCON_BASE, info.offsets.frac);
    ret.frac=(val&JH7110_PLL_FRAC_MASK)>>JH7110_PLL_FRAC_SHIFT;
    ret.postdiv1=(val&JH7110_PLL_POSTDIV1_MASK)>>JH7110_PLL_POSTDIV1_SHIFT;

    val=eth_mac_read_reg(VA_SYS_SYSCON_BASE, info.offsets.prediv);
    ret.prediv=(val&JH7110_PLL_PREDIV_MASK)>>JH7110_PLL_PREDIV_SHIFT;
    ret
}
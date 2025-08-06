use alloc::string::String;

use crate::drivers::net::starfive::{eth_def::{VisionfiveGmac, REG_DEBUG_ADDR_OFFSET, REG_DEBUG_DATA, REG_PHY_SPEC_STATUS, SPEED_10, SPEED_100, SPEED_1000, YTPHY_DUPLEX, YTPHY_DUPLEX_BIT, YTPHY_EXTREG_CHIP_CONFIG, YTPHY_EXTREG_RGMII_CONFIG1, YTPHY_PAD_DRIVES_STRENGTH_CFG, YTPHY_SPEED_MODE, YTPHY_SPEED_MODE_BIT}, eth_dev::{gmac_mdio_read, gmac_mdio_write}};

/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-08-11 18:17:56
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-08-11 19:41:15
 * @FilePath: /RocketOS_netperfright/os/src/drivers/net/starfive/ytphy.rs
 * @Description: 
 * 
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved. 
 */
pub fn ytphy_read_ext(gmacdev:&VisionfiveGmac,regnum:u32)->i32 {
    // let ret=gmac_mdio_read(gmacdev, gmacdev.PhyBase, REG)
    let ret=gmac_mdio_write(gmacdev, gmacdev.PhyBase as u32, REG_DEBUG_ADDR_OFFSET, regnum);
    if ret<0 {
        return ret;
    }
    let res=gmac_mdio_read(gmacdev, gmacdev.PhyBase as u32, REG_DEBUG_DATA);
    if res<0 {
        return res;
    }
    return res;
}
pub fn ytphy_write_ext(gmacdev:&VisionfiveGmac,regnum:u32,data:u16)->i32 {
    // let ret=gmac_mdio_read(gmacdev, gmacdev.PhyBase, REG)
    let ret=gmac_mdio_write(gmacdev, gmacdev.PhyBase as u32, REG_DEBUG_ADDR_OFFSET, regnum);
    if ret<0 {
        return ret;
    }
    // let res=gmac_mdio_read(gmacdev, gmacdev.PhyBase as u32, REG_DEBUG_DATA);
    let res=gmac_mdio_write(gmacdev, gmacdev.PhyBase as u32, REG_DEBUG_DATA, data as u32);
    return res;
}
pub fn bitfield_mask(shift:u32,width:u32)->u32{
    ((1<<width)-1)<<shift
}
pub fn bitfield_replace(reg_val:u32,shift:u32,width:u32,bitfield_val:u32)->u32 {
    let mask=bitfield_mask(shift, width);
    return (reg_val&!mask)|((bitfield_val<<shift)&mask);
}


//static struct phy_dts_config phy_dts[] = {
//     {
// 	.rgmii_sw_dr_2 = 0x0,
// 	.rgmii_sw_dr = 0x3,
// 	.rgmii_sw_dr_rxc = 0x6,
// 	.tx_delay_sel_fe = 5,
// #ifdef BSP_USING_DEVKITS
// 	.tx_delay_sel = 0xb,
// #else
// 	.tx_delay_sel = 0xa,
// #endif
// 	.rxc_dly_en = 0,
// 	.rx_delay_sel = 0xa,
// 	.tx_inverted_10 = 0x1,
// 	.tx_inverted_100 = 0x1,
// 	.tx_inverted_1000 = 0x1,
// 	.disable_llp = 0,
//     },
//     {
// 	.rgmii_sw_dr_2 = 0x0,
// 	.rgmii_sw_dr = 0x3,
// #ifdef BSP_USING_DEVKITS
// 	.rgmii_sw_dr_rxc = 0x7,
// #else
// 	.rgmii_sw_dr_rxc = 0x6,
// #endif
// 	.tx_delay_sel_fe = 5,
// 	.tx_delay_sel = 0x0,
// 	.rxc_dly_en = 0,
// 	.rx_delay_sel = 0x2,
// 	.tx_inverted_10 = 0x1,
// 	.tx_inverted_100 = 0x1,
// 	.tx_inverted_1000 = 0,
// 	.disable_llp = 0,
//     }
// };
#[derive(Copy, Clone, Debug)]
pub struct YtphyRegField {
    pub name: &'static str,
    pub size: u8, // Size of the bitfield, in bits
    pub off: u8,  // Offset from bit 0
    pub dflt: u8, // Default value
}

pub const YTPHY_DR_GRP: [YtphyRegField; 3] = [
    YtphyRegField { name: "rgmii_sw_dr",   size: 2, off:  4, dflt: 0x3 },
    YtphyRegField { name: "rgmii_sw_dr_2", size: 1, off: 12, dflt: 0x0 },
    YtphyRegField { name: "rgmii_sw_dr_rxc", size: 3, off: 13, dflt: 0x3 },
];

pub const YTPHY_RXTXD_GRP: [YtphyRegField; 3] = [
    YtphyRegField { name: "rx_delay_sel",  size: 4, off: 10, dflt: 0x0 },
    YtphyRegField { name: "tx_delay_sel_fe", size: 4, off: 4, dflt: 0xf },
    YtphyRegField { name: "tx_delay_sel",  size: 4, off:  0, dflt: 0x1 },
];

pub const YTPHY_TXINVER_GRP: [YtphyRegField; 3] = [
    YtphyRegField { name: "tx_inverted_1000", size: 1, off: 14, dflt: 0x0 },
    YtphyRegField { name: "tx_inverted_100",  size: 1, off: 14, dflt: 0x0 },
    YtphyRegField { name: "tx_inverted_10",   size: 1, off: 14, dflt: 0x0 },
];

pub const YTPHY_RXDEN_GRP: [YtphyRegField; 1] = [
    YtphyRegField { name: "rxc_dly_en",    size: 1, off: 8, dflt: 0x1 },
];

pub fn ytphy_of_config(gmacdev:&VisionfiveGmac)->i32 {
    //cfg = handle->phy_config.rxc_dly_en;
    let mut cfg=0;
    let mut val=ytphy_read_ext(gmacdev,YTPHY_EXTREG_CHIP_CONFIG);
    log::debug!("[ytphy_of_config] ext chip val 0 {:#x}",val);
    //todo
    cfg=if cfg>((1 << YTPHY_RXDEN_GRP[0].size) - 1) {
        ((1 << YTPHY_RXDEN_GRP[0].size) - 1) 
    }else{
        0
    };
    val=bitfield_replace(val as u32, YTPHY_RXDEN_GRP[0].off as u32, YTPHY_RXDEN_GRP[0].size as u32, cfg as u32) as i32;
    log::debug!("[ytphy_of_config] ext chip val 1 {:#x}",val);
    ytphy_write_ext(gmacdev, YTPHY_EXTREG_CHIP_CONFIG, (val&0xffff) as u16);

    val=ytphy_read_ext(gmacdev, YTPHY_PAD_DRIVES_STRENGTH_CFG);
    log::debug!("[ytphy_of_config] drv strength val 0 {:#x}",val);
    for i in 0..3{
        if i==0 {
            cfg=0x3;
        }
        else if i==1{
            cfg=0x0;
        }
        else{
            cfg=0x6;
        }
        /*check the cfg overflow or not*/
        cfg=if cfg>((1 << YTPHY_DR_GRP[i].size) - 1) {
            ((1 << YTPHY_DR_GRP[i].size) - 1) 
        }else{
            cfg
        };
        val=bitfield_replace(val as u32, YTPHY_DR_GRP[i].off as u32, YTPHY_DR_GRP[i].size as u32, cfg as u32) as i32;
        
    }
    log::debug!("[ytphy_of_config]drv strength val 1 {:#x?}",val);
    ytphy_write_ext(gmacdev, YTPHY_PAD_DRIVES_STRENGTH_CFG, (val&0xffff) as u16);

    val=ytphy_read_ext(gmacdev, YTPHY_EXTREG_RGMII_CONFIG1);
    log::debug!("[ytphy_of_config]rgmii strength val 0{:#x?}",val);
    for i in 0..3{
        if i==0 {
            cfg=0x2;
        }
        else if i==1 {
            cfg=5;
        }
        else {
            cfg=0x0;
        }
        /*check the cfg overflow or not*/
        cfg=if cfg>((1 << YTPHY_RXTXD_GRP[i].size) - 1) {
            ((1 << YTPHY_RXTXD_GRP[i].size) - 1) 
        }else{
            cfg
        };
        val=bitfield_replace(val as u32, YTPHY_RXTXD_GRP[i].off as u32, YTPHY_RXTXD_GRP[i].size as u32, cfg as u32) as i32;
    }
    log::debug!("[ytphy_of_config]rgmii strength val 1{:#x?}",val);
    ytphy_write_ext(gmacdev, YTPHY_EXTREG_RGMII_CONFIG1, (val&0xffff) as u16)
}
pub fn ytphy_parse_status(gmacdev:&mut VisionfiveGmac)->i32 {
    let ret=gmac_mdio_read(gmacdev, gmacdev.PhyBase as u32, REG_PHY_SPEC_STATUS);
    if ret<0 {
        return ret;
    }
    let val=ret as u32;
    let duplex=(val&YTPHY_DUPLEX)>>YTPHY_DUPLEX_BIT;
    let speed_mode=(val & YTPHY_SPEED_MODE) >> YTPHY_SPEED_MODE_BIT;
    let mut speed=0;
    if speed_mode==2 {
        speed=SPEED_1000;
    }
    else if speed_mode==1 {
        speed=SPEED_100;
    }
    else {
        speed=SPEED_10;
    }
    if (gmacdev.speedmode!=speed_mode)||gmacdev.DuplexMode!=duplex {
        gmacdev.DuplexMode=duplex;
        gmacdev.speedmode=speed_mode;
        gmacdev.Speed=speed;
        
    }
    log::info!("[ytphy_parse_status]dev speed {:?},duplex {:?},speedmode {:?}",gmacdev.Speed,gmacdev.DuplexMode,gmacdev.speedmode);
    0
    
}
pub fn ytphy_of_inverted(gmacdev:&VisionfiveGmac)->i32 {
    let mut val=ytphy_read_ext(gmacdev, YTPHY_EXTREG_RGMII_CONFIG1);
    let old_val=val;
    // 	.tx_inverted_10 = 0x1,
    // 	.tx_inverted_100 = 0x1,
    // 	.tx_inverted_1000 = 0,
    let inver_10=0x1;
    let inver_100=0x1;
    let inver_1000=0;
    log::debug!("[ytphy_of_inverted] val is {:#x?}",val);
    let speed=gmacdev.Speed;
    if speed==SPEED_1000 {
        val=bitfield_replace(val as u32, YTPHY_TXINVER_GRP[0].off as u32, YTPHY_TXINVER_GRP[0].size as u32, inver_1000) as i32;
        
    }
    else if speed==SPEED_100 {
        val=bitfield_replace(val as u32, YTPHY_TXINVER_GRP[1].off as u32, YTPHY_TXINVER_GRP[1].size as u32, inver_100) as i32;
    }
    else if speed==SPEED_10 {
        val=bitfield_replace(val as u32, YTPHY_TXINVER_GRP[2].off as u32, YTPHY_TXINVER_GRP[2].size as u32, inver_10) as i32;
    }
    else {
        panic!("[ytphy_of_inverted]UNKOWN SPEED");
    }
    if val==old_val {
        return 0;
    }
    log::debug!("[ytphy_of_inverted] new  val is {:#x?}",val);
    ytphy_write_ext(gmacdev, YTPHY_EXTREG_RGMII_CONFIG1, (val&0xffff) as u16)
}
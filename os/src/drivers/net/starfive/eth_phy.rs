use crate::drivers::net::starfive::{eth_def::{VisionfiveGmac, ADVERTISED_1000BASEX_FULL, ADVERTISED_1000BASEX_HALF, ADVERTISED_100BASET_FULL, ADVERTISED_100BASET_HALF, ADVERTISED_10BASET_FULL, ADVERTISED_10BASET_HALF, ADVERTISED_ASYM_PAUSE, ADVERTISED_PAUSE, ADVERTISE_1000FULL, ADVERTISE_1000HALF, ADVERTISE_1000XFULL, ADVERTISE_1000XHALF, ADVERTISE_100BASE4, ADVERTISE_100FULL, ADVERTISE_100HALF, ADVERTISE_10FULL, ADVERTISE_10HALF, ADVERTISE_ALL, ADVERTISE_PAUSE_ASYM, ADVERTISE_PAUSE_CAP, BMCR_ANENABLE, BMCR_ANRESTART, BMCR_ISOLATE, BMCR_RESET, BMSR_ANEGCOMPLETE, BMSR_ESTATEN, BMSR_LSTATUS, MII_ADVERTISE, MII_BMCR, MII_BMSR, MII_CTRL1000, MII_PHYSID1, MII_PHYSID2, PHY_GBIT_FEATURES, SUPPORTED_1000BASET_FULL, SUPPORTED_1000BASET_HALF}, eth_dev::{gmac_mdio_read, gmac_mdio_write}, platform::plat_mdelay, ytphy::{ytphy_of_config, ytphy_of_inverted, ytphy_parse_status}};

/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-08-10 23:28:27
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-08-12 15:15:46
 * @FilePath: /RocketOS_netperfright/os/src/drivers/net/starfive/eth_phy.rs
 * @Description: 
 * 
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved. 
 */
// static struct gmac_config gmac_config[] = {
//     {
// 0x16030000
// 	.speed_mode = GMAC_PHY_SPEED_1000M,
// 	.speed = 1000,
// 	.phy_addr = 0,
// 	.irq = 7, /* mac irq */
// 	.duplex = GMAC_PHY_FULL_DUPLEX,
//     },
//0x16040000
//     {
// 	.speed_mode = GMAC_PHY_SPEED_1000M,
// 	.speed = 1000,
// 	.phy_addr = 0,
// 	.irq = 78, /* mac irq */
// 	.duplex = GMAC_PHY_FULL_DUPLEX,
//     },
// };
//after set clk init we copy this to struct phy_config,first is for gmac0,second for gmac1
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
pub fn genric_gmac_phy_init(gmacdev:&mut VisionfiveGmac){
    //register gmac phy device

    let mut value=0;
    let mut gmac_config_phy_addr=0;
    for i in 0..0x1f{
        gmac_config_phy_addr=i;
        let mut temp_val=gmac_mdio_read(gmacdev, i, MII_PHYSID1);
        if temp_val<0 {
            continue;
        }
        // println!("[genric_gmac_phy_init] gmac_mdio_read 1");
        value=temp_val<<16;
        temp_val=gmac_mdio_read(gmacdev, i, MII_PHYSID2);
        if temp_val<0 {
            continue;
        }
        // println!("[genric_gmac_phy_init] gmac_mdio_read 2");
        value|=temp_val;
        if (value&0x1fffffff)==0x1fffffff {
            plat_mdelay(100);
            continue;
        }
        break;        
    }
    log::info!("[genric_gmac_phy_init] value is {:?} gmac_phy addr is {:?}",value,gmac_config_phy_addr);
    if gmac_config_phy_addr==0x1f {
        panic!("[genric_gmac_phy_init] no phy device");
    }
    gmacdev.PhyBase=gmac_config_phy_addr as u64;
    println!("[genric_gmac_phy_init] find phy device");
    if register_gmac_phy_driver(value as u32) {
        println!("[genric_gmac_phy_init] detected PHY_ID_YT8531 use PHY_ID_YT8531 init");
        gmac_phy_preinit(gmacdev);
        return;
    }
    //todo
    panic!("[genric_gmac_phy_init] use gen PHY init");
    // gmac_phy_preinit(gmacdev);


}
//YT8531 GMAC CHIP
const PHY_ID_YT8531:u32=0x4f51e91b;
const MOTORCOMM_8531_PHY_ID_MASK:u32=0xffffffff;
pub fn register_gmac_phy_driver(value:u32)->bool {
    //identify whether is the PHY_ID_YT8531
    if (PHY_ID_YT8531&MOTORCOMM_8531_PHY_ID_MASK)==value {
        return true;
    }
    false
}
pub fn gmac_phy_preinit(gmacdev:&mut VisionfiveGmac) {
    gmac_dev_genphy_reset(gmacdev);
    let ret=gmac_mdio_read(gmacdev, gmacdev.PhyBase as u32, MII_BMSR);
    if ret<0 {
        panic!("[gmac_phy_preinit] read MII_BMSR failed");
    }
    log::info!("[gmac_phy_preinit] ret is {:#x}",ret);
    if ((ret as u32)&BMSR_LSTATUS)!=0 {
        // println!("[gmac_phy_preinit] begin gmac init");
        gmac_phy_init(gmacdev);
        log::info!("[gmac_phy_init] init finish");
        return;
    }
    panic!();
}
pub fn gmac_dev_genphy_reset(gmacdev:&VisionfiveGmac) {
    let mut timeout =500;
    if gmac_mdio_write(gmacdev, gmacdev.PhyBase as u32, MII_BMCR,BMCR_RESET )<0{
        panic!("[gmac_dev_genphy_reset] PHY reset failed");
    }
    let mut timeout=500;
    // plat_mdelay(100);
    for i in 0..500{
        timeout-=1;
    }
    log::info!("[gmac_dev_genphy_reset] timeout is {:?}",timeout);
    /*
     * Poll the control register for the reset bit to go to 0 (it is
     * auto-clearing).  This should happen within 0.5 seconds per the
     * IEEE spec.
     */
    let mut ret=gmac_mdio_read(gmacdev, gmacdev.PhyBase as u32, MII_BMCR);
    if ret<0 {
        panic!("[gmac_dev_genphy_reset] phy read failed");
    }
    loop {
        ret=gmac_mdio_read(gmacdev, gmacdev.PhyBase as u32, MII_BMCR);
        log::info!("[gmac_dev_genphy_reset] ret is {:#x}",ret);
        if ret<0 {
            panic!("PHY status read failed");
        }
        //if timeout or reset has been 0 then has been reset success
        if ((ret as u32) & (BMCR_RESET as u32)) == 0 ||(timeout==0){
            break;
        }
        timeout-=1;
    }
    //make sure is reset
    if ((ret as u32) & (BMCR_RESET as u32)) != 0{
        panic!("PHY reset timed out");
    }
    println!("[gmac_dev_genphy_reset] phy reset success");
}
pub fn gmac_phy_init(gmacdev:&mut VisionfiveGmac) {
    let mut ret=0;
    ret=gmac_dev_genphy_config_aneg(gmacdev);
    if ret<0 {
        panic!("[gmac_phy_init]gmac_dev_genphy_config_aneg failed");
    }
    log::info!("[gmac_phy_init]gmac_dev_genphy_config_aneg ret is {:?}",ret);
    ret=gmac_dev_genphy_process_aneg_result(gmacdev, ret);
    if ret<0 {
        panic!("[gmac_phy_init]gmac_dev_genphy_process_aneg_result failed");
    }
    ret=ytphy_of_config(gmacdev);
    if ret<0{
        panic!("[gmac_phy_init]ytphy_of_config failed");
    }
    ret=genphy_update_link(gmacdev);
    if ret<0 {
        panic!("[gmac_phy_init]genphy_update_link failed");
    }
    ret=ytphy_parse_status(gmacdev);
    if ret<0 {
        panic!("[gmac_phy_init]ytphy_parse_status failed");
    }
    ret=ytphy_of_inverted(gmacdev);
    if ret<0 {
        panic!("[gmac_phy_init]ytphy_of_inverted failed");
    }
    //there because disable_llp is 0 we don't disable llp
}
pub fn gmac_dev_genphy_config_aneg(gmacdev:&VisionfiveGmac)->i32 {
    let mut advertise=PHY_GBIT_FEATURES;
    let mut supported=PHY_GBIT_FEATURES;
    let mut change=0;
    let mut err=0;
    let ret=gmac_mdio_read(gmacdev, gmacdev.PhyBase as u32, MII_ADVERTISE);
    if ret<0 {
        return err;
    }
    let old_adv=ret as u32;
    //must ret >0
    let mut adv=ret as u32;
    log::info!("[gmac_dev_genphy_config_aneg] advertise {:#x}",adv);
    adv&=!(ADVERTISE_ALL | ADVERTISE_100BASE4 | ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM);
    if (advertise & ADVERTISED_10BASET_HALF)!=0
    {
        adv |= ADVERTISE_10HALF;
    }
    if (advertise & ADVERTISED_10BASET_FULL)!=0
    {
        adv |= ADVERTISE_10FULL;
    }
    if (advertise & ADVERTISED_100BASET_HALF)!=0
    {
        adv |= ADVERTISE_100HALF;
    }
    if (advertise & ADVERTISED_100BASET_FULL)!=0
    {
        adv |= ADVERTISE_100FULL;
    }
    if (advertise & ADVERTISED_PAUSE)!=0
    {
        adv |= ADVERTISE_PAUSE_CAP;
    }
    if (advertise & ADVERTISED_ASYM_PAUSE)!=0
    {
        adv |= ADVERTISE_PAUSE_ASYM;
    }
    if (advertise & ADVERTISED_1000BASEX_HALF)!=0
    {
        adv |= ADVERTISE_1000XHALF;
    }
    if (advertise & ADVERTISED_1000BASEX_FULL)!=0
    {
        adv |= ADVERTISE_1000XFULL;
    }

    if adv!=old_adv {
        err=gmac_mdio_write(gmacdev, gmacdev.PhyBase as u32, MII_ADVERTISE, adv);
        if err<0 {
            return err;
        }
        log::info!("[gmac_dev_genphy_config_aneg]set advertise");
        change=1;
    }
    let bmsr=gmac_mdio_read(gmacdev, gmacdev.PhyBase as u32, MII_BMSR);
    if bmsr<0 {
        return bmsr;
    }
    /* Per 802.3-2008, Section 22.2.4.2.16 Extended status all
     * 1000Mbits/sec capable PHYs shall have the BMSR_ESTATEN bit set to a
     * logical 1.
     */
    if ((bmsr as u32) & BMSR_ESTATEN) == 0 {
        log::info!("[gmac_dev_genphy_config_aneg] BMSR_ESTATEN is 0");
        return change;
    }

    /* Configure gigabit if it's supported */
    log::info!("[gmac_dev_genphy_config_aneg]begin set gigabit");
    let ret=gmac_mdio_read(gmacdev, gmacdev.PhyBase as u32, MII_CTRL1000);
    if ret<0 {
        return ret;
    }
    let old_adv=ret as u32;
    //must ret >0
    let mut adv=ret as u32;
    adv &= !(ADVERTISE_1000FULL | ADVERTISE_1000HALF);

    if (supported & (SUPPORTED_1000BASET_HALF | SUPPORTED_1000BASET_FULL))!=0
    {
        if (advertise & SUPPORTED_1000BASET_HALF)!=0
        {
            adv |= ADVERTISE_1000HALF;
        }
        if (advertise & SUPPORTED_1000BASET_FULL)!=0
        {
            adv |= ADVERTISE_1000FULL;
        }
    }
    if (adv != old_adv)
    {
        log::info!("[gmac_dev_genphy_config_aneg]set gigabit is ok");
        change = 1;
    }
    err = gmac_mdio_write(gmacdev,gmacdev.PhyBase as u32,MII_CTRL1000,adv);
    if (err < 0)
    {
        return err;
    }

    return change;
}
pub fn gmac_dev_genphy_process_aneg_result(gmacdev:&VisionfiveGmac,result:i32)->i32 {
    let mut flag=false;
    if (result==0) {
        /*
        * Advertisment hasn't changed, but maybe aneg was never on to
        * begin with?	Or maybe phy was isolated?
        */
        let ret: i32=gmac_mdio_read(gmacdev, gmacdev.PhyBase as u32, MII_BMCR);
        if ret<0 {
            return ret;
        }
        let ctl: u32 = ret as u32;
        // 如果自动协商没有开启，或者 PHY 被隔离，则需要重启自动协商（result = 1）
        if (ctl & BMCR_ANENABLE) == 0 || (ctl & BMCR_ISOLATE) != 0 {
            flag = true;
        }
    }
    if flag {
        //restart aneg
        log::info!("[gmac_dev_genphy_process_aneg_result] restart aneg");
        let ret=gmac_mdio_read(gmacdev, gmacdev.PhyBase as u32, MII_BMCR);
        if ret<0 {
            return ret;
        }
        let mut ctl=ret as u32;
        ctl|=(BMCR_ANENABLE|BMCR_ANRESTART);
        ctl&=!(BMCR_ISOLATE);
        let ret=gmac_mdio_write(gmacdev, gmacdev.PhyBase as u32, MII_BMCR, ctl);
        if ret<0 {
            return ret;
        }
    }
    0
}

pub fn genphy_update_link(gmacdev:&VisionfiveGmac)->i32 {
    let ret=gmac_mdio_read(gmacdev, gmacdev.PhyBase as u32, MII_BMSR);
    if ret<0 {
        return ret;
    }
    let ctl=ret as u32;
    if (ctl&BMSR_ANEGCOMPLETE)==0 {
        print!("Waiting for PHY auto negotiation to complete");
        let mut times=0;
        loop {
            times+=1;
            let ret=gmac_mdio_read(gmacdev, gmacdev.PhyBase as u32, MII_BMSR);
            if ret<0 {
                return ret;
            }
            // log::info!("[genphy_update_link] ")
            if ((ret as u32)&BMSR_ANEGCOMPLETE)!=0 {
                // println!("[genphy_update_link] after waiting complete");
                break;
            }
            if times%11==0 {
                print!(".");
            }
        }
    }
    // println!("[[genphy_update_link] complete]");
    print!("Done\n");
    0
}
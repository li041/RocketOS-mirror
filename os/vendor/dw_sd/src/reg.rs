use core::fmt::Debug;

use bitflags::bitflags;
use lego_device::reg_map;
reg_map!(
    REG_CTRL 0x00,
    REG_PWREN 0x004,
    REG_CLKDIV 0x008,
    REG_CLKENA 0x010,
    REG_TMOUT 0x014,
    REG_CTYPE 0x018,
    REG_BLKSIZ 0x01C,
    REG_BYTCNT 0x020,
    REG_INTMASK 0x024,
    REG_RINTSTS 0x044,
    REG_CMDARG 0x028,
    REG_CMD 0x02C,
    REG_RESP0 0x030,
    REG_RESP1 0x034,
    REG_RESP2 0x038,
    REG_RESP3 0x03C,
    REG_STATUS 0x048,
    REG_FIFOTH 0x04C,
    REG_CDETECT 0x050,
    REG_WRTPRT 0x054,
    REG_GPIO 0x058,
    REG_TCMCNT 0x05C,
    REG_TBBCNT 0x060,
    REG_DEBNCE 0x064,
    REG_USRID 0x068,
    REG_VERID 0x06C,
    REG_HCON 0x070,
    REG_UHS 0x74,
    REG_RSTN 0x78,
    REG_BMOD 0x080,
    REG_PLDMND 0x84,
    REG_DBADDR 0x88,
    REG_IDSTS 0x8C,
    REG_IDINTEN 0x90,
    REG_DSCADDR 0x94,
    REG_BUFADDR 0x98,
    REG_CARD_THR_CTL 0x100,
    REG_DATA 0x200
);
pub const DATA_TMOUT_DEFUALT: usize = 0xFFFFFF << 8;
// pub const BLKSIZ_DEFAULT: usize = 0x200;
bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct InterruptMask: u32{
        const sdio_int_mask = 0xFFFF << 16;
        const ebe = 0b1 << 15;
        const acd = 0b1 << 14;
        const sbe = 0b1 << 13;
        const hle = 0b1 << 12;
        const frun = 0b1 << 11;
        const hto = 0b1 << 10;
        const drto = 0b1 << 9;
        const rto = 0b1 << 8;
        const dcrc = 0b1 << 7;
        const rcrc = 0b1 << 6;
        const rxdr = 0b1 << 5;
        const txdr = 0b1 << 4;
        const dto = 0b1 << 3;
        const cmd = 0b1 << 2;
        const re = 0b1 << 1;
        const cd = 0b1;
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ControlMask: u32{
        const use_internal_dmac = 0b1 << 25;
        const enable_od_pullup = 0b1 << 24;
        const card_voltage_b = 0b1111 << 20;
        const card_voltage_a = 0b1111 << 16;
        const ceata_device_interrupt = 0b1 << 11;
        const send_auto_stop_ccsd = 0b1 << 10;
        const send_ccsd = 0b1 << 9;
        const abort_read_data = 0b1 << 8;
        const send_irq_response = 0b1 << 7;
        const read_wait = 0b1 << 6;
        const dma_enable = 0b1 << 5;
        const int_enable = 0b1 << 4;
        const dma_reset = 0b1 << 2;
        const fifo_reset = 0b1 << 1;
        const controller_reset = 0b1;
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CmdMask: u32{
        const start_cmd = 0b1 << 31;
        const use_hold_reg = 0b1 << 29;
        const volt_switch = 0b1 << 28;
        const boot_mode = 0b1 << 27;
        const disable_boot = 0b1 << 26;
        const expect_boot_ack = 0b1 << 25;
        const enable_boot = 0b1 << 24;
        const ccs_expected = 0b1 << 23;
        const read_ceata_device = 0b1 << 22;
        const update_clock_registers_only = 0b1 << 21;
        const card_number = 0b11111 << 16;
        const send_initialization = 0b1 << 15;
        const stop_abort_cmd = 0b1 << 14;
        const wait_prvdata_complete = 0b1 << 13;
        const send_auto_stop = 0b1 << 12;
        const transfer_mode = 0b1 << 11;
        const write = 0b1 << 10;
        const data_expected = 0b1 << 9;
        const check_response_crc = 0b1 << 8;
        const response_length = 0b1 << 7;
        const response_expect = 0b1 << 6;
        const cmd_index = 0x3F;
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct StatusMask: u32{
        const dma_req= 0b1<< 31;
        const dma_ack= 0b1<< 30;
        const fifo_count= 0x1FFF<< 17;
        const response_index= 0x3F<< 11;
        const data_state_mc_busy= 0b1<< 10;
        const data_busy= 0b1<< 9;
        const data_3_status= 0b1<< 8;
        const command_fsm_states= 0xF<< 4;
        const fifo_full= 0b1<< 3;
        const fifo_empty= 0b1<< 2;
        const fifo_tx_watermark= 0b1<< 1;
        const fifo_rx_watermark= 0b1;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct HardConfig: u32{
        const card_type = 0x1;
        const num_cards_sub1 = 0x1F<<1;
        const h_bus_type = 0x1 << 6;
        const h_data_width = 0b111<<7;
        const h_addr_width = 0x3F << 10;
        const dma_interface = 0b11 << 16;
        const ge_dma_data_width = 0b111 << 18;
        const fifo_ram_inside = 0b1 << 21;
        const impl_hold_reg = 0b1 << 22;
        const set_clk_false_path = 0b1 <<23;
        const num_clk_div_sub1 = 0b11<<24;
        const area_optimized = 0b1 << 26;
        const fifo_depth = 0x1F << 27;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DmaIntEn: u32{
        const ti = 0b1;
        const ri = 0b1 << 1;
        const fbe = 0b1 << 2;
        const du = 0b1 << 4;
        const ces = 0b1 << 5;
        const ni = 0b1 << 8;
        const ai = 0b1 << 9;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DmaStatus: u32{
        const ti = 0b1;
        const ri = 0b1 << 1;
        const fbe = 0b1 << 2;
        const du = 0b1 << 4;
        const ces = 0b1 << 5;
        const nis = 0b1 << 8;
        const ais = 0b1 << 9;
        const eb = 0b111 << 10;
        const fsm = 0xF << 13;
    }
}

#[derive(Clone, Copy)]
pub struct HardConf(pub u32);
impl From<u32> for HardConf {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl Debug for HardConf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut f = f.debug_map();
        let conf = self.0;
        if conf | HardConfig::card_type.bits() != 0 {
            f.entry(&HardConfig::card_type, &"SD_MMC");
        } else {
            f.entry(&HardConfig::card_type, &"MMC_ONLY");
        }
        f.entry(
            &HardConfig::num_cards_sub1,
            &((conf & HardConfig::num_cards_sub1.bits()) >> 1),
        );
        if conf | HardConfig::h_bus_type.bits() != 0 {
            f.entry(&HardConfig::h_bus_type, &"AHB");
        } else {
            f.entry(&HardConfig::h_bus_type, &"APB");
        }
        let h_data = (conf & HardConfig::h_data_width.bits()) >> 7;
        match h_data {
            0 => {
                f.entry(&HardConfig::h_data_width, &"16 bit");
            }
            1 => {
                f.entry(&HardConfig::h_data_width, &"32 bit");
            }
            2 => {
                f.entry(&HardConfig::h_data_width, &"64 bit");
            }
            _ => {
                f.entry(&HardConfig::h_data_width, &"Other");
            }
        }
        f.entry(
            &HardConfig::h_addr_width,
            &((conf & HardConfig::h_addr_width.bits()) >> 10),
        );
        let dma_ifc = (conf & HardConfig::dma_interface.bits()) >> 16;
        match dma_ifc {
            0 => {
                f.entry(&HardConfig::dma_interface, &"None");
            }
            1 => {
                f.entry(&HardConfig::dma_interface, &"DW_DMA");
            }
            2 => {
                f.entry(&HardConfig::dma_interface, &"GENERIC_DMA");
            }
            3 => {
                f.entry(&HardConfig::dma_interface, &"NON-DW-DMA");
            }
            _ => {}
        }
        let ge_dma = (conf & HardConfig::ge_dma_data_width.bits()) >> 18;
        match ge_dma {
            0 => {
                f.entry(&HardConfig::ge_dma_data_width, &"None");
            }
            1 => {
                f.entry(&HardConfig::ge_dma_data_width, &"DW_DMA");
            }
            2 => {
                f.entry(&HardConfig::ge_dma_data_width, &"GENERIC_DMA");
            }
            _ => {
                f.entry(&HardConfig::ge_dma_data_width, &"Unknown");
            }
        }
        if conf | HardConfig::fifo_ram_inside.bits() != 0 {
            f.entry(&HardConfig::fifo_ram_inside, &"INSIDE");
        } else {
            f.entry(&HardConfig::fifo_ram_inside, &"OUTSIDE");
        }
        if conf | HardConfig::impl_hold_reg.bits() != 0 {
            f.entry(&HardConfig::impl_hold_reg, &"hold register");
        } else {
            f.entry(&HardConfig::impl_hold_reg, &"no hold register");
        }
        if conf | HardConfig::set_clk_false_path.bits() != 0 {
            f.entry(&HardConfig::set_clk_false_path, &"false path set");
        } else {
            f.entry(&HardConfig::set_clk_false_path, &"no false path");
        }
        f.entry(
            &HardConfig::num_clk_div_sub1,
            &((conf & HardConfig::num_clk_div_sub1.bits()) >> 24),
        );
        if conf | HardConfig::area_optimized.bits() != 0 {
            f.entry(&HardConfig::area_optimized, &"Area optimization");
        } else {
            f.entry(&HardConfig::area_optimized, &"no area optimization");
        }
        f.entry(
            &HardConfig::fifo_depth,
            &((conf & HardConfig::fifo_depth.bits()) >> 27),
        );
        f.finish()
    }
}

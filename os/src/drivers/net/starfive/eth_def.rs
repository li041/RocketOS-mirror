use crate::{arch::config::KERNEL_BASE, drivers::net::starfive::eth_dev::genmask_u32};


#[derive(Debug,Copy, Clone)]
#[repr(C)]
pub struct DmaDesc {
    pub des0: u32,
    pub des1: u32,
    pub des2: u32,
    pub des3: u32,
}
pub const EQOS_DESC2_IOC:u32=1u32<<31;
//own by dma
pub const EQOS_DESC3_OWN:u32=1u32<<31;
pub const EQOS_DESC3_IOC:u32=1u32<<30;
pub const EQOS_DESC3_FD:u32=1u32<<29;
pub const EQOS_DESC3_LD:u32=1u32<<28;
pub const EQOS_DESC3_BUF1V:u32=1u32<<24;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct VisionfiveGmac {
    pub parent: *mut u8,
    pub iobase: u64,
    pub MacAddr: [u8; 6],
    pub MacBase: u64,
    pub DmaBase: u64,
    pub PhyBase: u64,
    pub MtlBase:u64,
    pub Version: u32,
    pub TxBusy: u32,
    pub TxNext: u32,
    pub RxBusy: u32,
    pub TxDesc: [*mut DmaDesc; GMAC_DESC_NUM],
    pub RxDesc: [*mut DmaDesc; GMAC_DESC_NUM],
    pub TxBuffer: [u64; GMAC_DESC_NUM],
    pub RxBuffer: [u64; GMAC_DESC_NUM],
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub advertising: u32,
    pub LinkStatus: u32,
    pub DuplexMode: u32,
    pub Speed: u32,
    pub speedmode:u32,
}
impl VisionfiveGmac{
    pub fn init()->Self {
        // let gmac0_addr=pci_header::gmac0_register_addr_init();
        let gmac0_addr=(KERNEL_BASE+0x16040000) as u64;
        let a=VisionfiveGmac {
            parent: {
                let a=0 as *mut u8;
                println!("net_device init complete");
                a
            },
            iobase: gmac0_addr,
            MacAddr: {
                let a=[0x00, 0x55, 0x7B, 0xB5, 0x7D, 0xF7];
                println!("net_device init macaddr complete");
                a
            },
            MacBase: 0,
            DmaBase: 0,
            PhyBase: 0,
            MtlBase:0,
            Version: 0,
            TxBusy: 0,
            TxNext: 0,
            RxBusy: 0,
            TxDesc: {
                let a=[0 as *mut DmaDesc; GMAC_DESC_NUM];
                println!("net_device init txdesc");
                a
            },
            RxDesc: {
                let a=[0 as *mut DmaDesc; GMAC_DESC_NUM];
                println!("net_device init rxdesc");
                a
            },
            TxBuffer: {
                let a=[0; GMAC_DESC_NUM];
                println!("net_device init txbuffer complete");
                a
            },
            RxBuffer: {
                let a=[0; GMAC_DESC_NUM];
                println!("net_device init rxbuffer complete");
                a
            },
            rx_packets: 0,
            tx_packets: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_errors: 0,
            tx_errors: 0,
            advertising: 0,
            LinkStatus: 0,
            DuplexMode: 1,
            Speed: 2,
            speedmode:0,
        };
        println!("[net_device init] init complete");
        a
    }
}
//ARCH_DMA_MINALIGN   64
pub const DMA_ALIGN:u64=64;
pub const EQOS_MAX_PACKET_SIZE:u32=1568;
pub const GMAC_DESC_NUM:usize=300;
// ///pub const EQOS_MAC_REGS_BASE 0x000
// typedef struct gmac_mac_regs {
//     uint32_t configuration;             /* 0x000 */
//     uint32_t unused_004[(0x070 - 0x004) / 4];   /* 0x004 */
//     uint32_t q0_tx_flow_ctrl;           /* 0x070 */
//     uint32_t unused_070[(0x090 - 0x074) / 4];   /* 0x074 */
//     uint32_t rx_flow_ctrl;              /* 0x090 */
//     uint32_t unused_094;                /* 0x094 */
//     uint32_t txq_prty_map0;             /* 0x098 */
//     uint32_t unused_09c;                /* 0x09c */
//     uint32_t rxq_ctrl0;             /* 0x0a0 */
//     uint32_t unused_0a4;                /* 0x0a4 */
//     uint32_t rxq_ctrl2;             /* 0x0a8 */
//     uint32_t unused_0ac[(0x0c0 - 0x0ac) / 4];   /* 0x0ac */
//     uint32_t pmt_ctrl_status;            /* 0x0c0 */
//     uint32_t unused_0c4[(0x0dc - 0x0c4) / 4];   /* 0x0c4 */
//     uint32_t us_tic_counter;            /* 0x0dc */
//     uint32_t unused_0e0[(0x11c - 0x0e0) / 4];   /* 0x0e0 */
//     uint32_t hw_feature0;               /* 0x11c */
//     uint32_t hw_feature1;               /* 0x120 */
//     uint32_t hw_feature2;               /* 0x124 */
//     uint32_t unused_128[(0x200 - 0x128) / 4];   /* 0x128 */
//     uint32_t mdio_address;              /* 0x200 */
//     uint32_t mdio_data;             /* 0x204 */
//     uint32_t unused_208[(0x300 - 0x208) / 4];   /* 0x208 */
//     uint32_t address0_high;             /* 0x300 */
//     uint32_t address0_low;              /* 0x304 */
// }gmac_mac_regs_t;

pub type EQOS_MAC_REGS = u32;
pub const EQOS_MAC_BASE:EQOS_MAC_REGS=0x0000;
//offset
pub const MAC_CONFIGURATION:EQOS_MAC_REGS=0x0000;
pub const MAC_Q0_TX_FLOW_CTRL:EQOS_MAC_REGS=0x0070;
//FOR Q0_TX_FLOW_CTRL
pub const EQOS_MAC_Q0_TX_FLOW_CTRL_PT_SHIFT:u32=16;
pub const EQOS_MAC_Q0_TX_FLOW_CTRL_TFE:u32=1u32<<1;

pub const MAC_RX_FLOW_CTRL:EQOS_MAC_REGS=0x0090;
//FOR RX_FLOW_CTRL
pub const EQOS_MAC_RX_FLOW_CTRL_RFE:u32=1u32<<0;
pub const MAC_TXQ_PRTY_MAP0:EQOS_MAC_REGS=0x0098;
//FOR TXQ_PRTY_MAP0
pub const  EQOS_MAC_TXQ_PRTY_MAP0_PSTQ0_SHIFT:u32=0;
pub const  EQOS_MAC_TXQ_PRTY_MAP0_PSTQ0_MASK:u32=0xff;

pub const MAC_RXQ_CTRL0:EQOS_MAC_REGS=0x00a0;
//FOW RXQ_CTRL0 BITS
pub const EQOS_MAC_RXQ_CTRL0_RXQ0EN_SHIFT:u32=0;
pub const EQOS_MAC_RXQ_CTRL0_RXQ0EN_MASK:u32=3;
pub const EQOS_MAC_RXQ_CTRL0_RXQ0EN_NOT_ENABLED:u32=0;
pub const EQOS_MAC_RXQ_CTRL0_RXQ0EN_ENABLED_DCB:u32=2;
pub const EQOS_MAC_RXQ_CTRL0_RXQ0EN_ENABLED_AV:u32=1;

pub const MAC_RXQ_CTRL2:EQOS_MAC_REGS=0x00a8;
//FOR_RXL_CTRL2
pub const EQOS_MAC_RXQ_CTRL2_PSRQ0_SHIFT:u32=0;
pub const EQOS_MAC_RXQ_CTRL2_PSRQ0_MASK:u32=0xff;

pub const MAC_PMT_CTRL_STATUS:EQOS_MAC_REGS=0x00c0;
pub const MAC_US_TIC_COUNTER:EQOS_MAC_REGS=0x00dc;
pub const MAC_HW_FEATURE0:EQOS_MAC_REGS=0x011c;
pub const MAC_HW_FEATURE1:EQOS_MAC_REGS=0x0120;
//FOR HW_FEATURE1 BITS
pub const EQOS_MAC_HW_FEATURE1_TXFIFOSIZE_SHIFT:u32=6;
pub const EQOS_MAC_HW_FEATURE1_TXFIFOSIZE_MASK:u32=0x1f;
pub const EQOS_MAC_HW_FEATURE1_RXFIFOSIZE_SHIFT:u32=0;
pub const EQOS_MAC_HW_FEATURE1_RXFIFOSIZE_MASK:u32=0x1f;

pub const MAC_HW_FEATURE2:EQOS_MAC_REGS=0x0124;
pub const MAC_MDIO_ADDRESS:EQOS_MAC_REGS=0x0200;
/* MDIO address register CR definitions */
pub type MAC_CR_REGS=u32;
pub const EQOS_MAC_MDIO_ADDRESS_CR_SHIFT:MAC_CR_REGS=8;
pub const EQOS_MAC_MDIO_ADDRESS_CR_60_100M:MAC_CR_REGS=0;
pub const EQOS_MAC_MDIO_ADDRESS_CR_100_150M:MAC_CR_REGS=0x1;
pub const EQOS_MAC_MDIO_ADDRESS_CR_20_35M:MAC_CR_REGS=0x2;
pub const EQOS_MAC_MDIO_ADDRESS_CR_35_60M:MAC_CR_REGS=0x3;
pub const EQOS_MAC_MDIO_ADDRESS_CR_150_250M:MAC_CR_REGS=0x4;
pub const EQOS_MAC_MDIO_ADDRESS_CR_250_300M:MAC_CR_REGS=0x5;
pub const EQOS_MAC_MDIO_ADDRESS_CR_300_500M:MAC_CR_REGS=0x6;
pub const EQOS_MAC_MDIO_ADDRESS_CR_500_800M:MAC_CR_REGS=0x7;
pub const EQOS_MAC_MDIO_ADDRESS_CR_DIV_4:MAC_CR_REGS=0x8;
pub const EQOS_MAC_MDIO_ADDRESS_CR_DIV_6:MAC_CR_REGS=0x9;
pub const EQOS_MAC_MDIO_ADDRESS_CR_DIV_8:MAC_CR_REGS=0xA;
pub const EQOS_MAC_MDIO_ADDRESS_CR_DIV_10:MAC_CR_REGS=0xB;
pub const EQOS_MAC_MDIO_ADDRESS_CR_DIV_12:MAC_CR_REGS=0xC;
pub const EQOS_MAC_MDIO_ADDRESS_CR_DIV_14:MAC_CR_REGS=0xD;
pub const EQOS_MAC_MDIO_ADDRESS_CR_DIV_16:MAC_CR_REGS=0xE;
pub const EQOS_MAC_MDIO_ADDRESS_CR_DIV_18:MAC_CR_REGS=0xF;
pub const EQOS_MAC_MDIO_ADDRESS_SKAP:MAC_CR_REGS=1u32<<4;
pub const EQOS_MAC_MDIO_ADDRESS_GOC_SHIFT:MAC_CR_REGS=2;
pub const EQOS_MAC_MDIO_ADDRESS_GOC_READ:MAC_CR_REGS=3;
pub const EQOS_MAC_MDIO_ADDRESS_GOC_WRITE:MAC_CR_REGS=1;
pub const EQOS_MAC_MDIO_ADDRESS_C45E:MAC_CR_REGS=1u32<<1;
pub const EQOS_MAC_MDIO_ADDRESS_GB:MAC_CR_REGS=1u32<<0;
pub const EQOS_MAC_MDIO_DATA_GD_MASK:MAC_CR_REGS=0xffff;
pub const EQOS_MAC_MDIO_ADDRESS_PA_SHIFT:MAC_CR_REGS=21;
pub const EQOS_MAC_MDIO_ADDRESS_RDA_SHIFT:MAC_CR_REGS=16;


pub const MAC_MDIO_DATA:EQOS_MAC_REGS=0x0204;
pub const MAC_ADDRESS_HIGH:EQOS_MAC_REGS=0x0300;
pub const MAC_ADDRESS_LOW:EQOS_MAC_REGS=0x0304;
//set configuration bits
pub type EQOS_MAC_CONFIGURATION = u32;
pub const EQOS_MAC_CONFIGURATION_GPSLCE:  EQOS_MAC_CONFIGURATION = 1u32 << 23; // 0x0080_0000 = 8_388_608
pub const EQOS_MAC_CONFIGURATION_CST:     EQOS_MAC_CONFIGURATION = 1u32 << 21; // 0x0020_0000 = 2_097_152
pub const EQOS_MAC_CONFIGURATION_ACS:     EQOS_MAC_CONFIGURATION = 1u32 << 20; // 0x0010_0000 = 1_048_576
pub const EQOS_MAC_CONFIGURATION_WD:      EQOS_MAC_CONFIGURATION = 1u32 << 19; // 0x0008_0000 =   524_288
pub const EQOS_MAC_CONFIGURATION_JD:      EQOS_MAC_CONFIGURATION = 1u32 << 17; // 0x0002_0000 =   131_072
pub const EQOS_MAC_CONFIGURATION_JE:      EQOS_MAC_CONFIGURATION = 1u32 << 16; // 0x0001_0000 =    65_536
pub const EQOS_MAC_CONFIGURATION_PS:      EQOS_MAC_CONFIGURATION = 1u32 << 15; // 0x0000_8000 =    32_768
pub const EQOS_MAC_CONFIGURATION_FES:     EQOS_MAC_CONFIGURATION = 1u32 << 14; // 0x0000_4000 =    16_384
pub const EQOS_MAC_CONFIGURATION_DM:      EQOS_MAC_CONFIGURATION = 1u32 << 13; // 0x0000_2000 =     8_192
pub const EQOS_MAC_CONFIGURATION_LM:      EQOS_MAC_CONFIGURATION = 1u32 << 12; // 0x0000_1000 =     4_096
pub const EQOS_MAC_CONFIGURATION_TE:      EQOS_MAC_CONFIGURATION = 1u32 << 1;  // 0x0000_0002 =         2
pub const EQOS_MAC_CONFIGURATION_RE:      EQOS_MAC_CONFIGURATION = 1u32 << 0;  // 0x0000_0001 =         1
//pub const EQOS_DMA_REGS_BASE 0x1000
// typedef struct gmac_dma_regs {
//     uint32_t mode;                  /* 0x1000 */
//     uint32_t sysbus_mode;               /* 0x1004 */
//     uint32_t unused_1008[(0x1100 - 0x1008) / 4];    /* 0x1008 */
//     uint32_t ch0_control;               /* 0x1100 */
//     uint32_t ch0_tx_control;            /* 0x1104 */
//     uint32_t ch0_rx_control;            /* 0x1108 */
//     uint32_t unused_110c;               /* 0x110c */
//     uint32_t ch0_txdesc_list_haddress;      /* 0x1110 */
//     uint32_t ch0_txdesc_list_address;       /* 0x1114 */
//     uint32_t ch0_rxdesc_list_haddress;      /* 0x1118 */
//     uint32_t ch0_rxdesc_list_address;       /* 0x111c */
//     uint32_t ch0_txdesc_tail_pointer;       /* 0x1120 */
//     uint32_t unused_1124;               /* 0x1124 */
//     uint32_t ch0_rxdesc_tail_pointer;       /* 0x1128 */
//     uint32_t ch0_txdesc_ring_length;        /* 0x112c */
//     uint32_t ch0_rxdesc_ring_length;        /* 0x1130 */
//     uint32_t ch0_interrupt_enable;        /* 0x1134 */
//     uint32_t unused_1138[(0x1160 - 0x1138) / 4];    /* 0x1138 */
//     uint32_t ch0_status;                /* 0x1160 */
// }gmac_dma_regs_t;
pub type EQOS_DMA_REGS = u32;
pub const EQOS_DMA_BASE:EQOS_DMA_REGS=0x1000;
//offset
pub const EQOS_DMA_MODE:EQOS_DMA_REGS=0x0000;
pub const DMA_SYSBUS_MODE:EQOS_DMA_REGS=0x0004;
//BITS FOR DMA SYSBUS
pub const EQOS_DMA_SYSBUS_MODE_RD_OSR_LMT_SHIFT:u32=16;
pub const EQOS_DMA_SYSBUS_MODE_RD_OSR_LMT_MASK:u32=0xf;
pub const EQOS_DMA_SYSBUS_MODE_EAME:u32=1u32<<11;
pub const EQOS_DMA_SYSBUS_MODE_BLEN16:u32=1u32<<3;
pub const EQOS_DMA_SYSBUS_MODE_BLEN8:u32=1u32<<2;
pub const EQOS_DMA_SYSBUS_MODE_BLEN4:u32=1u32<<1;
pub const DMA_CH0_CONTROL:EQOS_DMA_REGS=0x0100;
//BITS FOR CH0_CONTROL
pub const EQOS_DMA_CH0_CONTROL_PBLX8:u32=1u32<<16;
pub const DMA_CH0_TX_CONTROL:EQOS_DMA_REGS=0x0104;
pub const DMA_CH0_RX_CONTROL:EQOS_DMA_REGS=0x0108;
pub const DMA_CH0_TX_DESC_LIST_HADDRESS:EQOS_DMA_REGS=0x0110;
pub const DMA_CH0_TX_DESC_LIST_ADDRESS:EQOS_DMA_REGS=0x0114;
pub const DMA_CH0_RX_DESC_LIST_HADDRESS:EQOS_DMA_REGS=0x0118;
pub const DMA_CH0_RX_DESC_LIST_ADDRESS:EQOS_DMA_REGS=0x011c;
pub const DMA_CH0_TX_DESC_TAIL_POINTER:EQOS_DMA_REGS=0x0120;
pub const DMA_CH0_RX_DESC_TAIL_POINTER:EQOS_DMA_REGS=0x0128;
pub const DMA_CH0_TX_DESC_RING_LENGTH:EQOS_DMA_REGS=0x012c;
pub const DMA_CH0_RX_DESC_RING_LENGTH:EQOS_DMA_REGS=0x0130;
pub const DMA_CH0_INTERRUPT_ENABLE:EQOS_DMA_REGS=0x0134;
pub const DMA_CH0_STATUS:EQOS_DMA_REGS=0x0160;
//DMA STATUS
pub type DMA_STATUS=u32;
pub const DMA_CHAN_STATUS_NIS:DMA_STATUS=1u32<<15;
pub const DMA_CHAN_STATUS_AIS:DMA_STATUS=1u32<<14;
pub const DMA_CHAN_STATUS_CDE:DMA_STATUS=1u32<<13;
pub const DMA_CHAN_STATUS_FBE:DMA_STATUS=1u32<<12;
pub const DMA_CHAN_STATUS_ERI:DMA_STATUS=1u32<<11;
pub const DMA_CHAN_STATUS_ETI:DMA_STATUS=1u32<<10;
pub const DMA_CHAN_STATUS_RWT:DMA_STATUS=1u32<<9;
pub const DMA_CHAN_STATUS_RPS:DMA_STATUS=1u32<<8;
pub const DMA_CHAN_STATUS_RBU:DMA_STATUS=1u32<<7;
pub const DMA_CHAN_STATUS_RI:DMA_STATUS=1u32<<6;
pub const DMA_CHAN_STATUS_TBU:DMA_STATUS=1u32<<2;
pub const DMA_CHAN_STATUS_TPS:DMA_STATUS=1u32<<1;
pub const DMA_CHAN_STATUS_TI:DMA_STATUS=1u32<<0;

//set dma mode bits
pub const EQOS_DMA_SWR: EQOS_DMA_REGS = 0x00000001;
pub const EQOS_DMA_CH0_TX_CONTROL_TXPBL_SHIFT:u32=16;
pub const EQOS_DMA_CH0_TX_CONTROL_TXPBL_MASK:u32=0x3f;
pub const EQOS_DMA_CH0_TX_CONTROL_OSP:u32=1u32<<4;
pub const EQOS_DMA_CH0_TX_CONTROL_ST:u32=1u32<<0;

pub const EQOS_DMA_CH0_RX_CONTROL_RXPBL_SHIFT:u32=16;
pub const EQOS_DMA_CH0_RX_CONTROL_RXPBL_MASK:u32=0x3f;
pub const EQOS_DMA_CH0_RX_CONTROL_RBSZ_SHIFT:u32=1;
pub const EQOS_DMA_CH0_RX_CONTROL_RBSZ_MASK:u32=0x3fff;
pub const EQOS_DMA_CH0_RX_CONTROL_SR:u32=1u32<<0;

//speed
pub type EQOS_GMAC_PHY_SPEED=u32;
pub const GMAC_PHY_SPEED_10M:EQOS_GMAC_PHY_SPEED = 0;
pub const GMAC_PHY_SPEED_100M:EQOS_GMAC_PHY_SPEED = 1;
pub const GMAC_PHY_SPEED_1000M:EQOS_GMAC_PHY_SPEED = 2;
//duplex
pub type EQOS_GMAC_PHY_DUPLEX=u32;
pub const GMAC_PHY_HALF_DUPLEX:EQOS_GMAC_PHY_DUPLEX=0;
pub const GMAC_PHY_FULL_DUPLEX:EQOS_GMAC_PHY_DUPLEX=1;

//pub const EQOS_MTL_REGS_BASE 0xd00
// typedef struct gmac_mtl_regs {
//     uint32_t txq0_operation_mode;           /* 0xd00 */
//     uint32_t unused_d04;                /* 0xd04 */
//     uint32_t txq0_debug;                /* 0xd08 */
//     uint32_t unused_d0c[(0xd18 - 0xd0c) / 4];   /* 0xd0c */
//     uint32_t txq0_quantum_weight;           /* 0xd18 */
//     uint32_t unused_d1c[(0xd30 - 0xd1c) / 4];   /* 0xd1c */
//     uint32_t rxq0_operation_mode;           /* 0xd30 */
//     uint32_t unused_d34;                /* 0xd34 */
//     uint32_t rxq0_debug;                /* 0xd38 */
// }gmac_mtl_regs_t;
pub type EQOS_MTL_REGS=u32;
pub const EQOS_MTL_BASE:EQOS_MTL_REGS=0x0d00;
//offset
pub const EQOS_MTL_TXQ0_OP_MODE:EQOS_MTL_REGS=0x0000;
pub const EQOS_MTL_TXQ0_DEBUG:EQOS_MTL_REGS=0x0008;
pub const EQOS_MTL_TXQ0_QUANTUM_WEG:EQOS_MTL_REGS=0x0018;
pub const EQOS_MTL_RXQ0_OP_MODE:EQOS_MTL_REGS=0x0030;
pub const EQOS_MTL_RXQ0_DEBUG:EQOS_MTL_REGS=0x0038;
//MTL_TXQ0_OP_MODE BITS
pub type EQOS_MTL_TXQO_MODE_BITS=u32;
pub const EQOS_MTL_TXQ0_OPERATION_MODE_TQS_SHIFT:EQOS_MTL_TXQO_MODE_BITS=16;
pub const EQOS_MTL_TXQ0_OPERATION_MODE_TXQEN_SHIFT:EQOS_MTL_TXQO_MODE_BITS=2;
pub const EQOS_MTL_TXQ0_OPERATION_MODE_TQS_MASK:EQOS_MTL_TXQO_MODE_BITS=0x1ff;
pub const EQOS_MTL_TXQ0_OPERATION_MODE_TXQEN_MASK:EQOS_MTL_TXQO_MODE_BITS=3;
pub const EQOS_MTL_TXQ0_OPERATION_MODE_TXQEN_ENABLED:EQOS_MTL_TXQO_MODE_BITS=2;
pub const EQOS_MTL_TXQ0_OPERATION_MODE_TSF:EQOS_MTL_TXQO_MODE_BITS=1u32<<1;
pub const EQOS_MTL_TXQ0_OPERATION_MODE_FTQ:EQOS_MTL_TXQO_MODE_BITS=1u32<<0;
//MTL_TXQ0_DEBUG_BITS
pub type EQOS_MTL_TXQO_DEBUG_BITS=u32;
pub const EQOS_MTL_TXQ0_DEBUG_TXQSTS:EQOS_MTL_TXQO_DEBUG_BITS=1u32<<4;
pub const EQOS_MTL_TXQ0_DEBUG_TRCSTS_SHIFT:EQOS_MTL_TXQO_DEBUG_BITS=1;
pub const EQOS_MTL_TXQ0_DEBUG_TRCSTS_MASK:EQOS_MTL_TXQO_DEBUG_BITS=3;
//MTL_RXQ0_OP_MODE BITS
pub type EQOS_MTL_RXQO_MODE_BITS=u32;
pub const EQOS_MTL_RXQ0_OPERATION_MODE_RQS_SHIFT:EQOS_MTL_RXQO_MODE_BITS=20;
pub const EQOS_MTL_RXQ0_OPERATION_MODE_RQS_MASK:EQOS_MTL_RXQO_MODE_BITS=0x3ff;
pub const EQOS_MTL_RXQ0_OPERATION_MODE_RFD_SHIFT:EQOS_MTL_RXQO_MODE_BITS=14;
pub const EQOS_MTL_RXQ0_OPERATION_MODE_RFD_MASK:EQOS_MTL_RXQO_MODE_BITS=0x3f;
pub const EQOS_MTL_RXQ0_OPERATION_MODE_RFA_SHIFT:EQOS_MTL_RXQO_MODE_BITS=8;
pub const EQOS_MTL_RXQ0_OPERATION_MODE_RFA_MASK:EQOS_MTL_RXQO_MODE_BITS=0x3f;
pub const EQOS_MTL_RXQ0_OPERATION_MODE_EHFC:EQOS_MTL_RXQO_MODE_BITS=1u32<<7;
pub const EQOS_MTL_RXQ0_OPERATION_MODE_RSF:EQOS_MTL_RXQO_MODE_BITS=1u32<<5;
pub const EQOS_MTL_RXQ0_OPERATION_MODE_FEP:EQOS_MTL_RXQO_MODE_BITS=1u32<<4;
pub const EQOS_MTL_RXQ0_OPERATION_MODE_FUP:EQOS_MTL_RXQO_MODE_BITS=1u32<<3;
//MTL_RXQ0_DEBUG_BITS
pub type EQOS_MTL_RXQO_DEBUG_BITS=u32;
pub const EQOS_MTL_RXQ0_DEBUG_PRXQ_SHIFT:EQOS_MTL_RXQO_DEBUG_BITS=16;
pub const EQOS_MTL_RXQ0_DEBUG_PRXQ_MASK:EQOS_MTL_RXQO_DEBUG_BITS=0x7fff;
pub const EQOS_MTL_RXQ0_DEBUG_RXQSTS_SHIFT:EQOS_MTL_RXQO_DEBUG_BITS=4;
pub const EQOS_MTL_RXQ0_DEBUG_RXQSTS_MASK:EQOS_MTL_RXQO_DEBUG_BITS=3;
pub const INT_TX_HARD_ERROR:u32=0xffffffff;
pub const INT_TX:u32=1;
pub const INT_RX:u32=2;
pub const LINK_STATUS:u32=3;


//JH7110
pub const SYS_CRG_BASE:u64=0x13020000;
pub const VA_SYS_CRG_BASE:u64=(KERNEL_BASE as u64)+SYS_CRG_BASE;
pub const SYS_SYSCON_BASE:u64=0x13030000;
pub const VA_SYS_SYSCON_BASE:u64=(KERNEL_BASE as u64)+SYS_SYSCON_BASE;
pub type SYS_CLK_REGS=u32;
pub const PERI_ROOT:SYS_CLK_REGS=0x10;
pub const AXI_CFG:SYS_CLK_REGS=0x1c;
pub const STG_AXI_AHB:SYS_CLK_REGS=0x20;
pub const GMAC1_CLK_AHB:SYS_CLK_REGS=0x184;
pub const GMAC1_CLK_AXI:SYS_CLK_REGS=0x188;
pub const GMAC1_CLK_PTP:SYS_CLK_REGS=0x198;
pub const GMAC1_CLK_GTXC:SYS_CLK_REGS=0x1ac;
pub const GMAC1_CLK_TX:SYS_CLK_REGS=0x1a4;
pub const GMAC_CLK_AXI_RST:u32=1u32<<2;
pub const GMAC_CLK_AHB_RST:u32=1u32<<3;
pub const SYS_CRG_RESET2:u32=0x300;

pub const JH7110_PLL2_PD_OFFSET:u32=0x2c;
pub const JH7110_PLL2_DACPD_SHIFT:u32=15;
pub const JH7110_PLL2_DACPD_MASK:u32=1u32<<15;
pub const JH7110_PLL2_DSMPD_SHIFT:u32=16;
pub const JH7110_PLL2_DSMPD_MASK:u32=1u32<<16;
pub const JH7110_PLL2_FBDIV_OFFSET:u32=0x2c;
pub const JH7110_PLL2_FBDIV_SHIFTL:u32=17;
pub const JH7110_PLL2_FBDIV_MASK:u32=genmask_u32(28, 17);
pub const JH7110_PLL2_FRAC_OFFSET:u32=0x30;
pub const JH7110_PLL2_PREDIV_OFFSET:u32=0x34;
pub const JH7110_PLL_FRAC_SHIFT:u32=0;
pub const JH7110_PLL_FRAC_MASK:u32=genmask_u32(23, 0);
pub const JH7110_PLL_POSTDIV1_SHIFT:u32=28;
pub const JH7110_PLL_POSTDIV1_MASK:u32=genmask_u32(29, 28);
pub const JH7110_PLL_PREDIV_SHIFT:u32=0;
pub const JH7110_PLL_PREDIV_MASK:u32=genmask_u32(5, 0);
/* Generic MII registers. */
pub type MII_REGS=u32;
pub const MII_BMCR:MII_REGS=0x00;    /* Basic mode control register */
pub const MII_BMSR:MII_REGS=0x01;    /* Basic mode status register  */
pub const MII_PHYSID1:MII_REGS=0x02;    /* PHYS ID 1               */
pub const MII_PHYSID2:MII_REGS=0x03;    /* PHYS ID 2               */
pub const MII_ADVERTISE:MII_REGS=0x04;
pub const MII_CTRL1000:MII_REGS=0x09; 
/* Basic mode control register. */
pub const BMCR_RESV:u32=0x003f;  /* Unused...               */
pub const BMCR_SPEED1000:u32=0x0040;  /* MSB of Speed (1000)         */
pub const BMCR_CTST:u32=0x0080;  /* Collision test          */
pub const BMCR_FULLDPLX:u32=0x0100;  /* Full duplex             */
pub const BMCR_ANRESTART:u32=0x0200;  /* Auto negotiation restart    */
pub const BMCR_ISOLATE:u32=0x0400;  /* Disconnect DP83840 from MII */
pub const BMCR_PDOWN:u32=0x0800;  /* Powerdown the DP83840       */
pub const BMCR_ANENABLE:u32=0x1000;  /* Enable auto negotiation     */
pub const BMCR_SPEED100:u32=0x2000;  /* Select 100Mbps          */
pub const BMCR_LOOPBACK:u32=0x4000;  /* TXD loopback bits           */
pub const BMCR_RESET:u32=0x8000; /* Reset the DP83840           */

/* Basic mode status register. */
pub const BMSR_ERCAP:u32=0x0001;  /* Ext-reg capability          */
pub const BMSR_JCD        :u32=0x0002;  /* Jabber detected         */
pub const BMSR_LSTATUS        :u32=0x0004;  /* Link status             */
pub const BMSR_ANEGCAPABLE    :u32=0x0008;  /* Able to do auto-negotiation */
pub const BMSR_RFAULT     :u32=0x0010;  /* Remote fault detected       */
pub const BMSR_ANEGCOMPLETE   :u32=0x0020;  /* Auto-negotiation complete   */
pub const BMSR_RESV       :u32=0x00c0;  /* Unused...               */
pub const BMSR_ESTATEN        :u32=0x0100;  /* Extended Status in R15 */
pub const BMSR_100HALF2       :u32=0x0200;  /* Can do 100BASE-T2 HDX */
pub const BMSR_100FULL2       :u32=0x0400;  /* Can do 100BASE-T2 FDX */
pub const BMSR_10HALF     :u32=0x0800;  /* Can do 10mbps, half-duplex  */
pub const BMSR_10FULL     :u32=0x1000;  /* Can do 10mbps, full-duplex  */
pub const BMSR_100HALF        :u32=0x2000;  /* Can do 100mbps, half-duplex */
pub const BMSR_100FULL        :u32=0x4000;  /* Can do 100mbps, full-duplex */
pub const BMSR_100BASE4       :u32=0x8000;  /* Can do 100mbps, 4k packets  */


pub const SUPPORTED_10BASET_HALF: u32        = 1u32 << 0;
pub const SUPPORTED_10BASET_FULL: u32        = 1u32 << 1;
pub const SUPPORTED_100BASET_HALF: u32       = 1u32 << 2;
pub const SUPPORTED_100BASET_FULL: u32       = 1u32 << 3;
pub const SUPPORTED_1000BASET_HALF: u32      = 1u32 << 4;
pub const SUPPORTED_1000BASET_FULL: u32      = 1u32 << 5;
pub const SUPPORTED_AUTONEG: u32             = 1u32 << 6;
pub const SUPPORTED_TP: u32                  = 1u32 << 7;
pub const SUPPORTED_AUI: u32                 = 1u32 << 8;
pub const SUPPORTED_MII: u32                 = 1u32 << 9;
pub const SUPPORTED_FIBRE: u32               = 1u32 << 10;
pub const SUPPORTED_BNC: u32                 = 1u32 << 11;
pub const SUPPORTED_10000BASET_FULL: u32     = 1u32 << 12;
pub const SUPPORTED_PAUSE: u32               = 1u32 << 13;
pub const SUPPORTED_ASYM_PAUSE: u32          = 1u32 << 14;
pub const SUPPORTED_2500BASEX_FULL: u32      = 1u32 << 15;
pub const SUPPORTED_BACKPLANE: u32           = 1u32 << 16;
pub const SUPPORTED_1000BASEKX_FULL: u32     = 1u32 << 17;
pub const SUPPORTED_10000BASEKX4_FULL: u32   = 1u32 << 18;
pub const SUPPORTED_10000BASEKR_FULL: u32    = 1u32 << 19;
pub const SUPPORTED_10000BASER_FEC: u32      = 1u32 << 20;
pub const SUPPORTED_1000BASEX_HALF: u32      = 1u32 << 21;
pub const SUPPORTED_1000BASEX_FULL: u32      = 1u32 << 22;

/* Indicates what features are advertised by the interface. */
pub const ADVERTISED_10BASET_HALF: u32        = 1u32 << 0;
pub const ADVERTISED_10BASET_FULL: u32        = 1u32 << 1;
pub const ADVERTISED_100BASET_HALF: u32       = 1u32 << 2;
pub const ADVERTISED_100BASET_FULL: u32       = 1u32 << 3;
pub const ADVERTISED_1000BASET_HALF: u32      = 1u32 << 4;
pub const ADVERTISED_1000BASET_FULL: u32      = 1u32 << 5;
pub const ADVERTISED_AUTONEG: u32            = 1u32 << 6;
pub const ADVERTISED_TP: u32                 = 1u32 << 7;
pub const ADVERTISED_AUI: u32                = 1u32 << 8;
pub const ADVERTISED_MII: u32                = 1u32 << 9;
pub const ADVERTISED_FIBRE: u32              = 1u32 << 10;
pub const ADVERTISED_BNC: u32                = 1u32 << 11;
pub const ADVERTISED_10000BASET_FULL: u32    = 1u32 << 12;
pub const ADVERTISED_PAUSE: u32              = 1u32 << 13;
pub const ADVERTISED_ASYM_PAUSE: u32         = 1u32 << 14;
pub const ADVERTISED_2500BASEX_FULL: u32     = 1u32 << 15;
pub const ADVERTISED_BACKPLANE: u32          = 1u32 << 16;
pub const ADVERTISED_1000BASEKX_FULL: u32    = 1u32 << 17;
pub const ADVERTISED_10000BASEKX4_FULL: u32  = 1u32 << 18;
pub const ADVERTISED_10000BASEKR_FULL: u32   = 1u32 << 19;
pub const ADVERTISED_10000BASER_FEC: u32     = 1u32 << 20;
pub const ADVERTISED_1000BASEX_HALF: u32     = 1u32 << 21;
pub const ADVERTISED_1000BASEX_FULL: u32     = 1u32 << 22;

pub const PHY_DEFAULT_FEATURES: u32 = SUPPORTED_AUTONEG | SUPPORTED_TP | SUPPORTED_MII;

pub const PHY_10BT_FEATURES: u32 = SUPPORTED_10BASET_HALF | SUPPORTED_10BASET_FULL;

pub const PHY_100BT_FEATURES: u32 = SUPPORTED_100BASET_HALF | SUPPORTED_100BASET_FULL;

pub const PHY_1000BT_FEATURES: u32 = SUPPORTED_1000BASET_HALF | SUPPORTED_1000BASET_FULL;

pub const PHY_BASIC_FEATURES: u32 = PHY_10BT_FEATURES | PHY_100BT_FEATURES | PHY_DEFAULT_FEATURES;

pub const PHY_GBIT_FEATURES: u32 = PHY_BASIC_FEATURES | PHY_1000BT_FEATURES;

/// Advertisement control register.
pub const ADVERTISE_SLCT: u32           = 0x001f; // Selector bits
pub const ADVERTISE_CSMA: u32           = 0x0001; // Only selector supported
pub const ADVERTISE_10HALF: u32         = 0x0020; // Try for 10mbps half-duplex
pub const ADVERTISE_1000XFULL: u32      = 0x0020; // Try for 1000BASE-X full-duplex
pub const ADVERTISE_10FULL: u32         = 0x0040; // Try for 10mbps full-duplex
pub const ADVERTISE_1000XHALF: u32      = 0x0040; // Try for 1000BASE-X half-duplex
pub const ADVERTISE_100HALF: u32        = 0x0080; // Try for 100mbps half-duplex
pub const ADVERTISE_1000XPAUSE: u32     = 0x0080; // Try for 1000BASE-X pause
pub const ADVERTISE_100FULL: u32        = 0x0100; // Try for 100mbps full-duplex
pub const ADVERTISE_1000XPSE_ASYM: u32  = 0x0100; // Try for 1000BASE-X asym pause
pub const ADVERTISE_100BASE4: u32       = 0x0200; // Try for 100mbps 4k packets
pub const ADVERTISE_PAUSE_CAP: u32      = 0x0400; // Try for pause
pub const ADVERTISE_PAUSE_ASYM: u32     = 0x0800; // Try for asymmetric pause
pub const ADVERTISE_RESV: u32           = 0x1000; // Unused...
pub const ADVERTISE_RFAULT: u32         = 0x2000; // Say we can detect faults
pub const ADVERTISE_LPACK: u32          = 0x4000; // Ack link partners response
pub const ADVERTISE_NPAGE: u32          = 0x8000; // Next page bit
pub const ADVERTISE_1000FULL:u32=  0x0200;  /* Advertise 1000BASE-T full duplex */
pub const ADVERTISE_1000HALF:u32=0x0100; 
pub const ADVERTISE_FULL: u32 = ADVERTISE_100FULL | ADVERTISE_10FULL | ADVERTISE_CSMA;
pub const ADVERTISE_ALL: u32 = ADVERTISE_10HALF | ADVERTISE_10FULL |
                              ADVERTISE_100HALF | ADVERTISE_100FULL;


//DEFINE PHY_ID_YT8531
pub const REG_PHY_SPEC_STATUS:u32=0x11;
pub const REG_DEBUG_ADDR_OFFSET:u32=0x1e;
pub const REG_DEBUG_DATA:u32=0x1f;
pub const YTPHY_EXTREG_CHIP_CONFIG: u32 = 0xa001;
pub const YTPHY_EXTREG_RGMII_CONFIG1: u32 = 0xa003;
pub const YTPHY_PAD_DRIVES_STRENGTH_CFG: u32 = 0xa010;
pub const YTPHY_DUPLEX: u32 = 0x2000;
pub const YTPHY_DUPLEX_BIT: u32 = 13;
pub const YTPHY_SPEED_MODE: u32 = 0xc000;
pub const YTPHY_SPEED_MODE_BIT: u32 = 14;
pub const SPEED_10:u32=10;
pub const SPEED_100:u32=100;
pub const SPEED_1000:u32=1000;
pub const SPEED_2500:u32=2500;
pub const SPEED_10000:u32=10000;
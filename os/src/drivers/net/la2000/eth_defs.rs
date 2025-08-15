#![allow(non_upper_case_globals, non_snake_case, non_camel_case_types)]

use core::default::Default;
#[derive(Copy, Clone,Default,Debug)]
#[repr(C)]
pub struct DmaDesc {
    pub status: u32,
    pub length: u32,
    pub buffer1: u32,
    pub buffer2: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct net_device {
    pub parent: *mut u8,
    pub iobase: u64,
    pub MacAddr: [u8; 6],
    pub MacBase: u64,
    pub DmaBase: u64,
    pub PhyBase: u64,
    pub Version: u32,
    pub TxBusy: u32,
    pub TxNext: u32,
    pub RxBusy: u32,
    pub TxDesc: [*mut DmaDesc; 300],
    pub RxDesc: [*mut DmaDesc; 300],
    pub TxBuffer: [u64; 300],
    pub RxBuffer: [u64; 300],
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
}
#[repr(C)]
pub struct pci_header{
    pub vendorid:u16,
    pub deviceid:u16,
    pub command:u16,
    pub status:u16,
    pub revisionid:u32,
    pub classcode:u32,
    pub cachelinesize:u8,
    pub latencytimer:u8,
    pub headertype:u8,
    pub bist:u8,
    pub baseaddressregister:[u32;6],
    pub cardbusispointer:u32,
    pub subsystemid:u16,
    pub ExpansionROMBaseAddress:u32,
    pub CapabilitiesPointer:u32,
    pub resv1:u32,
    pub resv2:u32,
    pub InterruptLine:u8,
    pub InterruptPin:u8,
    pub Min_Gnt:u8,
    pub Max_Lat:u8
}
impl pci_header{
    pub fn gmac0_register_addr_init() -> u64 {
        // 把 LS_PCIE_GMAC0_ADDR 当成指向 pci_header 的只读映射基址
        let p = LS_PCIE_GMAC0_ADDR as *const pci_header;
        // 这里用 volatile 读，确保编译器不会 optimize 掉
        let bar0 = unsafe { core::ptr::read_volatile(&(*p).baseaddressregister[0]) };
        // 清除低 4 位
        let phys = (bar0 & 0xFFFF_FFF0) as u64;
        // 转到 uncached 区返回
        println!("[gmac0_register_addr_init] get gmac0 phy addr is {:#x?}",phys);
        phys
    }
}


impl net_device{
    pub fn init()->Self {
        // let gmac0_addr=pci_header::gmac0_register_addr_init();
        let gmac0_addr=0x8000000040040000;
        let a=net_device {
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
            Version: 0,
            TxBusy: 0,
            TxNext: 0,
            RxBusy: 0,
            TxDesc: {
                let a=[0 as *mut DmaDesc; 300];
                println!("net_device init txdesc");
                a
            },
            RxDesc: {
                let a=[0 as *mut DmaDesc; 300];
                println!("net_device init rxdesc");
                a
            },
            TxBuffer: {
                let a=[0; 300];
                println!("net_device init txbuffer complete");
                a
            },
            RxBuffer: {
                let a=[0; 300];
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
            DuplexMode: 0,
            Speed: 0,
        };
        println!("[net_device init] init complete");
        a
    }
}

pub type GmacRegisters = u32;
pub const GmacRgsmiiStatus: GmacRegisters = 0x00D8;
pub const GmacAddr0Low: GmacRegisters = 0x0044;
pub const GmacAddr0High: GmacRegisters = 0x0040;
pub const GmacInterruptMask: GmacRegisters = 0x003C;
pub const GmacInterruptStatus: GmacRegisters = 0x0038;
pub const GmacVersion: GmacRegisters = 0x0020;
pub const GmacFlowControl: GmacRegisters = 0x0018;
pub const GmacGmiiData: GmacRegisters = 0x0014;
pub const GmacGmiiAddr: GmacRegisters = 0x0010;
pub const GmacFrameFilter: GmacRegisters = 0x0004;
pub const GmacConfig: GmacRegisters = 0x0000;

pub type GmacInterruptStatus = u32;
pub const GmacRgmiiIntSts: GmacInterruptStatus = 0x00000001;

pub type GmacConfigReg = u32;
pub const GmacRx: GmacConfigReg = 0x00000004;
pub const GmacTx: GmacConfigReg = 0x00000008;
pub const GmacDeferralCheck: GmacConfigReg = 0x00000010;
pub const GmacBackoffLimit0: GmacConfigReg = 0x00000000;
pub const GmacBackoffLimit: GmacConfigReg = 0x00000060;
pub const GmacPadCrcStrip: GmacConfigReg = 0x00000080;
pub const GmacLinkDown: GmacConfigReg = 0x00000100;
pub const GmacLinkUp: GmacConfigReg = 0x00000100;
pub const GmacRetry: GmacConfigReg = 0x00000200;
pub const GmacHalfDuplex: GmacConfigReg = 0x00000000;
pub const GmacFullDuplex: GmacConfigReg = 0x00000800;
pub const GmacDuplex: GmacConfigReg = 0x00000800;
pub const GmacLoopback: GmacConfigReg = 0x00001000;
pub const GmacRxOwn: GmacConfigReg = 0x00002000;
pub const GmacSelectGmii: GmacConfigReg = 0x00000000;
pub const GmacSelectMii: GmacConfigReg = 0x00008000;
pub const GmacMiiGmii: GmacConfigReg = 0x00008000;
pub const GmacJumboFrame: GmacConfigReg = 0x00100000;
pub const GmacFrameBurst: GmacConfigReg = 0x00200000;
pub const GmacJabber: GmacConfigReg = 0x00400000;
pub const GmacWatchdog: GmacConfigReg = 0x00800000;
pub const GmacTxConfig: GmacConfigReg = 0x01000000;

pub type GmacFrameFilterReg = u32;
pub const GmacPromiscuousMode: GmacFrameFilterReg = 0x00000001;
pub const GmacUcastHashFilter: GmacFrameFilterReg = 0x00000002;
pub const GmacMcastHashFilter: GmacFrameFilterReg = 0x00000004;
pub const GmacDestAddrFilter: GmacFrameFilterReg = 0x00000008;
pub const GmacMulticastFilter: GmacFrameFilterReg = 0x00000010;
pub const GmacBroadcast: GmacFrameFilterReg = 0x00000020;
pub const GmacPassControl0: GmacFrameFilterReg = 0x00000000;
pub const GmacPassControl: GmacFrameFilterReg = 0x000000C0;
pub const GmacSrcAddrFilter: GmacFrameFilterReg = 0x00000200;
pub const GmacFilter: GmacFrameFilterReg = 0x80000000;

pub type GmacGmiiAddrReg = u32;
pub const GmiiBusy: GmacGmiiAddrReg = 0x00000001;
pub const GmiiRead: GmacGmiiAddrReg = 0x00000000;
pub const GmiiWrite: GmacGmiiAddrReg = 0x00000002;
pub const GmiiCsrClk4: GmacGmiiAddrReg = 0x00000010;
pub const GmiiRegShift: GmacGmiiAddrReg = 6;
pub const GmiiRegMask: GmacGmiiAddrReg = 0x000007C0;
pub const GmiiDevShift: GmacGmiiAddrReg = 11;
pub const GmiiDevMask: GmacGmiiAddrReg = 0x0000F800;

pub type GmacFlowControlReg = u32;
pub const GmacTxFlowControl: GmacFlowControlReg = 0x00000002;
pub const GmacRxFlowControl: GmacFlowControlReg = 0x00000004;
pub const GmacPauseTimeMask: GmacFlowControlReg = 0xFFFF0000;

pub type DmaRegisters = u32;
pub const DmaHWFeature: DmaRegisters = 0x0058;
pub const DmaRxCurrAddr: DmaRegisters = 0x0054;
pub const DmaTxCurrAddr: DmaRegisters = 0x0050;
pub const DmaRxCurrDesc: DmaRegisters = 0x004C;
pub const DmaTxCurrDesc: DmaRegisters = 0x0048;
pub const DmaInterrupt: DmaRegisters = 0x001C;
pub const DmaControl: DmaRegisters = 0x0018;
pub const DmaStatus: DmaRegisters = 0x0014;
pub const DmaTxBaseAddr: DmaRegisters = 0x0010;
pub const DmaRxBaseAddr: DmaRegisters = 0x000C;
pub const DmaRxPollDemand: DmaRegisters = 0x0008;
pub const DmaTxPollDemand: DmaRegisters = 0x0004;
pub const DmaBusMode: DmaRegisters = 0x0000;

pub type DmaStatusReg = u32;
pub const DmaIntTxCompleted: DmaStatusReg = 0x00000001;
pub const DmaIntTxStopped: DmaStatusReg = 0x00000002;
pub const DmaIntTxNoBuffer: DmaStatusReg = 0x00000004;
pub const DmaIntTxJabberTO: DmaStatusReg = 0x00000008;
pub const DmaIntRcvOverflow: DmaStatusReg = 0x00000010;
pub const DmaIntTxUnderflow: DmaStatusReg = 0x00000020;
pub const DmaIntRxCompleted: DmaStatusReg = 0x00000040;
pub const DmaIntRxNoBuffer: DmaStatusReg = 0x00000080;
pub const DmaIntRxStopped: DmaStatusReg = 0x00000100;
pub const DmaIntEarlyTx: DmaStatusReg = 0x00000400;
pub const DmaIntBusError: DmaStatusReg = 0x00002000;
pub const DmaIntEarlyRx: DmaStatusReg = 0x00004000;
pub const DmaIntAbnormal: DmaStatusReg = 0x00008000;
pub const DmaIntNormal: DmaStatusReg = 0x00010000;
pub const GmacLineIntfIntr: DmaStatusReg = 0x04000000;
pub const GmacMmcIntr: DmaStatusReg = 0x08000000;
pub const GmacPmtIntr: DmaStatusReg = 0x10000000;

pub type GmacRgsmiiStatus = u32;
pub const MacLinkMode: GmacRgsmiiStatus = 0x00000001;
pub const MacLinkSpeed_2_5: GmacRgsmiiStatus = 0x00000000;
pub const MacLinkSpeed_25: GmacRgsmiiStatus = 0x00000002;
pub const MacLinkSpeed_125: GmacRgsmiiStatus = 0x00000004;
pub const MacLinkSpeed: GmacRgsmiiStatus = 0x00000006;
pub const MacLinkStatusOff: GmacRgsmiiStatus = 0x00000003;
pub const MacLinkStatus: GmacRgsmiiStatus = 0x00000008;
pub const MacJabberTimeout: GmacRgsmiiStatus = 0x00000010;
pub const MacFalseCarrier: GmacRgsmiiStatus = 0x00000020;

pub type DmaBusModeReg = u32;
pub const DmaResetOn: DmaBusModeReg = 0x00000001;
pub const DmaDescriptorSkip0: DmaBusModeReg = 0x00000000;
pub const DmaDescriptor4DWords: DmaBusModeReg = 0x00000000;
pub const DmaDescriptor8DWords: DmaBusModeReg = 0x00000080;
pub const DmaBurstLength32: DmaBusModeReg = 0x00002000;
pub const DmaBurstLengthx8: DmaBusModeReg = 0x01000000;
pub const DmaFixedBurstEnable: DmaBusModeReg = 0x00010000;
pub const DmaMixedBurstEnable: DmaBusModeReg = 0x04000000;

pub type DmaControlReg = u32;
pub const DmaRxStart: DmaControlReg = 0x00000002;
pub const DmaTxSecondFrame: DmaControlReg = 0x00000004;
pub const DmaEnHwFlowCtrl: DmaControlReg = 0x00000100;
pub const DmaRxFlowCtrlAct: DmaControlReg = 0x00800600;
pub const DmaRxFlowCtrlDeact: DmaControlReg = 0x00401800;
pub const DmaTxStart: DmaControlReg = 0x00002000;
pub const DmaStoreAndForward: DmaControlReg = 0x02200000;

pub type DmaDescriptorStatus = u32;
pub const DescSize1Shift: DmaDescriptorStatus = 0;
pub const DescSize1Mask: DmaDescriptorStatus = 0x00001FFF;
pub const DescSize2Shift: DmaDescriptorStatus = 16;
pub const DescSize2Mask: DmaDescriptorStatus = 0x1FFF0000;
pub const RxDescEndOfRing: DmaDescriptorStatus = 0x00008000;
pub const RxDisIntCompl: DmaDescriptorStatus = 0x80000000;
pub const DescTxDeferred: DmaDescriptorStatus = 0x00000001;
pub const DescTxUnderflow: DmaDescriptorStatus = 0x00000002;
pub const TxDescChain: DmaDescriptorStatus = 0x00100000;
pub const TxDescEndOfRing: DmaDescriptorStatus = 0x00200000;
pub const DescTxFirst: DmaDescriptorStatus = 0x10000000;
pub const DescTxLast: DmaDescriptorStatus = 0x20000000;
pub const DescTxIntEnable: DmaDescriptorStatus = 0x40000000;
pub const DescRxLast: DmaDescriptorStatus = 0x00000100;
pub const DescRxFirst: DmaDescriptorStatus = 0x00000200;
pub const DescError: DmaDescriptorStatus = 0x00008000;
pub const DescFrameLengthShift: DmaDescriptorStatus = 16;
pub const DescFrameLengthMask: DmaDescriptorStatus = 0x3FFF0000;
pub const DescOwnByDma: DmaDescriptorStatus = 0x80000000;

pub type MMC_ENABLE = u32;
pub const GmacMmcIntrMaskTx: MMC_ENABLE = 0x0110;
pub const GmacMmcIntrMaskRx: MMC_ENABLE = 0x010C;

pub type MMC_IP_RELATED = u32;
pub const GmacMmcRxIpcIntr: MMC_IP_RELATED = 0x0208;
pub const GmacMmcRxIpcIntrMask: MMC_IP_RELATED = 0x0200;

pub type InitialRegisters = u32;
pub const DmaIntDisable: InitialRegisters = 0;
pub const DmaIntEnable: InitialRegisters = DmaIntNormal      | // 16
                                           DmaIntAbnormal    | // 15
                                           DmaIntBusError    | // 13
                                           DmaIntRxStopped   | // 8
                                           DmaIntRxNoBuffer  | // 7
                                           DmaIntRxCompleted | // 6
                                           DmaIntTxUnderflow  | // 5
                                           DmaIntRcvOverflow  | // 4
                                           DmaIntTxNoBuffer  | // 2
                                           DmaIntTxStopped   | // 1
                                           DmaIntTxCompleted; // 0
pub const LS_PCIE_GMAC0_ADDR:u64=0x800000fe00001800;
pub const LS_PCIE_GMAC1_ADDR:u64=0x800000fe00001900;
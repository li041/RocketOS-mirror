use super::{FSINFO_LEADSIG, FSINFO_STRUCSIG, FSINFO_TRAILSIG};

//确保结构体在内存中的排列方式与 C 语言中的布局相同，并且使用紧凑的排列方式
// packed: 不引入任何填充字节。通常情况下，编译器会在结构体字段之间插入填充字节，以满足对齐要求。但使用 packed 属性后，所有字段将紧密排列，不会有额外的填充。
#[repr(C, packed)]
#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug)]
/// FAT32引导扇区
pub struct FAT32BootSector {
    // Boot
    pub BS_jmpBoot: [u8; 3], // 启动跳转指令（仅用于 x86 启动，通常忽略）
    pub BS_OEMName: [u8; 8], // OEM 名称，通常是 "MSWIN4.1"

    // 必须字段（BPB - BIOS Parameter Block）
    // 53 字节
    pub BPB_BytesPerSector: u16, // 每扇区字节数（通常为 512), 合法值为 512, 1024, 2048, 4096
    pub BPB_SectorPerCluster: u8, // 每簇扇区数（1, 2, 4,...128）
    pub BPB_ReservedSectorCount: u16, // 保留扇区数（FAT32 通常为 32), 第一个FAT开始之前的扇区数(包括引导扇区)
    pub BPB_NumFATs: u8,              // FAT 表数量（通常为 2, 一个用来备份）
    pub BPB_RootEntryCount: u16,      // 根目录条目数(只有FAT12/FAT16使用此字段, FAT32 必须为 0）
    pub BPB_SmallSectorCount: u16,    // 小扇区数(同上)
    pub BPB_MediaDescriptor: u8, // 媒体描述符（通常为 0xF8, 0xF8表示硬盘, 0xF0表示高密度的3.5寸软盘）
    pub BPB_SectorPerTrack: u16, // 每磁道扇区数（与中断 0x13 相关，通常忽略）
    pub BPB_SectorPerFAT: u16,   // 每FAT扇区数(只被 FAT12/FAT16 所使用,FAT32 必须为 0）
    pub BPB_NumHeads: u16,       // 磁头数（与中断 0x13 相关，通常忽略）
    pub BPB_HiddSec: u32,        // 隐藏扇区数（通常忽略）
    pub BPB_TotalSector32: u32,  // 总扇区数（文件系统的整体大小）

    // FAT32 特有字段
    /// 使用这个数`BPB_SectorPerFAT32`和FAT数`BPB_NumFATs`以及保留扇区数`BPB_ReservedSectorCount`可以计算出`根目录`的起始位置
    pub BPB_SectorPerFAT32: u32, //(只被 FAT32 使用)该分区每个 FAT 所占的扇区数
    pub BPB_ExtFlags: u16,       // 扩展标志（通常为 0）
    pub BPB_FSVer: u16,          // 文件系统版本号（当前版本为 0）
    pub BPB_RootClusterNum: u32, // 根目录起始簇号（通常为 2）
    pub BPB_FSInfo: u16,         // FSInfo 扇区号（通常为 1）
    pub BPB_BkBootSec: u16,      // 引导扇区的备份位置（通常为 6）
    pub BPB_Reserved: [u8; 12],  // 保留字段

    // 引导区结束字段
    pub BS_PhysicalDrvNum: u8,   // 驱动器号（与中断 0x13 相关）
    pub BS_Reserved1: u8,        // 保留字段
    pub BS_BootSig: u8,          // 引导签名（通常为 0x29）
    pub BS_VolID: u32,           // 卷序列号（通常随机生成, 用于区分磁盘）
    pub BS_VolLabel: [u8; 11],   // 卷标签（11 字节，通常为空格填充）
    pub BS_FileSysType: [u8; 8], // 文件系统类型字符串（例如 "FAT32   "）
}

impl FAT32BootSector {
    pub fn is_valid(&self) -> bool {
        // self.BS_BootSig == 0x29 &&
        self.BS_FileSysType == "FAT32   ".as_bytes() && self.BPB_BytesPerSector == 512
        // hardwired sector size for simplicity
    }
}

#[repr(C, packed)] // make sure layout is packed and exactly the same as on disk(512 bytes)
#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug)]
pub struct FAT32FSInfoSector {
    pub FSI_LeadSig: u32,         // 0x41615252
    pub FSI_Reserved1: [u8; 480], // 保留字段, 当前应该为全0
    pub FSI_StrucSig: u32,        // 0x61417272
    pub FSI_Free_Count: u32,      // free cluster count. 0xFFFFFFFF means unknown.
    pub FSI_Nxt_Free: u32,        // next free cluster, 用于快速分配簇的参考
    pub FSI_Reserved2: [u8; 12],  // 0
    pub FSI_TrailSig: u32,        // 0xAA550000
}

impl FAT32FSInfoSector {
    pub fn is_valid(&self) -> bool {
        self.FSI_LeadSig == FSINFO_LEADSIG
            && self.FSI_StrucSig == FSINFO_STRUCSIG
            && self.FSI_TrailSig == FSINFO_TRAILSIG
    }
}

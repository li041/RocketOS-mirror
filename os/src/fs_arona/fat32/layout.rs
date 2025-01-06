use super::{FSI_LEADSIG, FSI_STRUCSIG, FSI_TRAILSIG};

#[repr(C, packed)] // make sure layout is packed and exactly the same as on disk(90 bytes)
#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug)]
pub struct FAT32BootSector {
    // Boot
    pub BS_jmpBoot: [u8; 3], // use for x86 boot, ignore.
    pub BS_OEMName: [u8; 8], // usually "MSWIN4.1"

    // essential BPB
    pub BPB_BytesPerSector: u16,      // must 512, ..., 4096, usually 512
    pub BPB_SectorPerCluster: u8,     // must 1,2,4,...,128.
    pub BPB_ReservedSectorCount: u16, // usually 32 for FAT32
    pub BPB_NumFATs: u8,              // usually 2 for FAT32
    pub BPB_RootEntryCount: u16,      // must 0 for FAT32
    pub BPB_TotSector16: u16,         // must 0 for FAT32
    pub BPB_Media: u8,                // usually 0xF8, ignore.
    pub BPB_FATsize16: u16,           // must 0 for FAT32
    pub BPB_SectorPerTrack: u16,      // use for interrupt 0x13, ignore.
    pub BPB_NumHeads: u16,            // use for interrupt 0x13, ignore.
    pub BPB_HiddSec: u32,             // Hidden Sector Count, ignore.
    pub BPB_TotSector32: u32,         // Total Sector count, region 1, 2, 3, 4.

    // BPB For FAT32
    pub BPB_FATsize32: u32,     // ONE FAT Sector count.
    pub BPB_ExtFlags: u16,      // usually 0 when FAT is mirrored at runtime.
    pub BPB_FSVer: u16,         // must 0 in current version
    pub BPB_RootCluster: u32,   // Root Dir Cluster id, usally 2
    pub BPB_FSInfo: u16,        // FSINFO Sector id, usually 1
    pub BPB_BkBootSec: u16,     // Backup Sector id, usually 6
    pub BPB_Reserved: [u8; 12], // 0

    // BS(end)
    pub BS_DrvNum: u8,           // use for interrupt 0x13, 0x80 for hard disk
    pub BS_Reserved1: u8,        // 0
    pub BS_BootSig: u8,          // 0x29
    pub BS_VolID: u32,           // xjb Generator ?
    pub BS_VolLabel: [u8; 11],   // 11*0x30 ?
    pub BS_FileSysType: [u8; 8], // "FAT32 0x30*3"
}

impl FAT32BootSector {
    pub fn is_valid(&self) -> bool {
        self.BS_BootSig == 0x29
            && self.BS_FileSysType == "FAT32   ".as_bytes()
            && self.BPB_BytesPerSector == 512 // hardwired sector size for simplicity
    }
}

#[repr(C, packed)] // make sure layout is packed and exactly the same as on disk(512 bytes)
#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug)]
pub struct FAT32FSInfoSector {
    pub FSI_LeadSig: u32,         // 0x41615252
    pub FSI_Reserved1: [u8; 480], // 0
    pub FSI_StrucSig: u32,        // 0x61417272
    pub FSI_Free_Count: u32,      // free cluster count. 0xFFFFFFFF means unknown.
    pub FSI_Nxt_Free: u32,        // next free cluster
    pub FSI_Reserved2: [u8; 12],  // 0
    pub FSI_TrailSig: u32,        // 0xAA550000
}

impl FAT32FSInfoSector {
    pub fn is_valid(&self) -> bool {
        self.FSI_LeadSig == FSI_LEADSIG
            && self.FSI_StrucSig == FSI_STRUCSIG
            && self.FSI_TrailSig == FSI_TRAILSIG
    }
}

use crate::fs::inode::PhysicalBlockRange;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExtentHeader {
    pub magic: u16,   // 魔数, 0xF30A
    pub entries: u16, // 本节点中Header后有效的extent条目数
    pub max: u16,     // 本节点中最大extent条目数
    pub depth: u16, // 本节点的深度, 0表示叶子节点, 指向数据块, >0指向其他extent节点(索引节点), 最大值为4
    generation: u32, // 本节点的generation, 用于标识节点的版本, used by Lustre, 不是standard ext4
}

// Interal nodes of the extent tree
// 索引节点
#[repr(C)]
pub struct ExtentIdx {
    // This index node covers file blocks from 'block' onward.
    pub block: u32, // 子索引节点的起始块号
    // 	Lower 32-bits of the block number of the extent node that is the next level lower in the tree. The tree node pointed to can be either another internal node or a leaf node, described below.
    leaf_lo: u32, // 子节点的block号(低32位), 子节点可以是索引节点或叶子节点
    leaf_hi: u16, // 叶子节点号的高16位
    unused: u16,  // 未使用
}

impl ExtentIdx {
    pub fn physical_leaf_block(&self) -> usize {
        (self.leaf_hi as usize) << 32 | self.leaf_lo as usize
    }
}

// 叶子节点
#[repr(C)]
#[derive(Debug)]
// 逻辑快好
pub struct Extent {
    // First file block number that this extent covers.
    pub block: u32, // 子节点的起始逻辑块号
    // Number of blocks covered by extent. If the value of this field is <= 32768, the extent is initialized. If the value of the field is > 32768, the extent is uninitialized and the actual extent length is ee_len - 32768. Therefore, the maximum length of a initialized extent is 32768 blocks, and the maximum length of an uninitialized extent is 32767.
    pub len: u16, // 所覆盖的逻辑块的数量
    // Upper 16-bits of the block number to which this extent points.
    start_hi: u16, // 数据块号的高16位
    start_lo: u32, // 数据块号的低32位
}

impl Extent {
    // 这个对应的EXT4的物理块号(fs_block_id), 不是qemu上VirtIOBlock的块号, 在BlockCache中转换
    pub fn physical_start_block(&self) -> usize {
        (self.start_hi as usize) << 32 | self.start_lo as usize
    }
    pub fn to_physical_block_range(&self) -> PhysicalBlockRange {
        PhysicalBlockRange {
            logical_block_id: self.block as usize,
            physical_block_id: self.physical_start_block(),
            len: self.len as u32,
        }
    }
}

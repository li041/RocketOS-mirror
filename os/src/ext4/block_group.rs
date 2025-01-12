pub struct GroupDesc {
    pub block_bitmap_lo: u32,  // block位图的起始块号(低32位)
    pub inode_bitmap_lo: u32,  // inode位图的起始块号(低32位)
    inode_table_lo: u32,       // inode表的起始块号(低32位)
    free_blocks_count_lo: u16, // 空闲的block总数(低16位)
    free_inodes_count_lo: u16, // 空闲的inode总数(低16位)
    used_dirs_count_lo: u16,   // 使用的目录总数(低16位)
    pub flags: u16,            // 块组标志, EXT$_BG_flags(INODE_UNINIT, etc)
    exclude_bitmap_lo: u32,    // 快照排除位图
    block_bitmap_csum_lo: u16, // block位图校验和(低16位, crc32c(s_uuid+grp_num+bitmap)) LE
    inode_bitmap_csum_lo: u16, // inode位图校验和(低16位, crc32c(s_uuid+grp_num+bitmap)) LE
    itable_unused_lo: u16,     // 未使用的inode 数量(低16位)
    checksum: u16,             // crc16(sb_uuid+group_num+desc)
    block_bitmap_hi: u32,      // block位图的起始块号(高32位)
    inode_bitmap_hi: u32,      // inode位图的起始块号(高32位)
    inode_table_hi: u32,       // inode表的起始块号(高32位)
    free_blocks_count_hi: u16, // 空闲的block总数(高16位)
    free_inodes_count_hi: u16, // 空闲的inode总数(高16位)
    used_dirs_count_hi: u16,   // 使用的目录总数(高16位)
    itable_unused_hi: u16,     // 未使用的inode 数量(高16位)
    exclude_bitmap_hi: u32,    // 快照排除位图
    block_bitmap_csum_hi: u16, // crc32c(s_uuid+grp_num+bitmap)的高16位
    inode_bitmap_csum_hi: u16, // crc32c(s_uuid+grp_num+bitmap)的高16位
    reserved: u32,             // 保留字段, 填充
}

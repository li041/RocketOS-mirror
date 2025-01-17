use super::{inode::Ext4Inode, super_block::Ext4SuperBlock};
use alloc::{sync::Arc, vec::Vec};

use crate::{
    drivers::{
        block::{block_cache::get_block_cache, block_dev::BlockDevice},
        BLOCK_DEVICE,
    },
    ext4::{
        block_group::{self, GroupDesc},
        dentry::{DirEntry, Ext4DirContent},
        inode,
        super_block::Ext4Meta,
    },
    fs::{inode::Inode, FSMutex},
};

pub struct Ext4FileSystem {
    pub block_device: Arc<dyn BlockDevice>,
    pub ext4_meta: Arc<Ext4Meta>,
    pub block_groups: Vec<block_group::GroupDesc>,
    pub root_inode: Arc<Ext4Inode>,
}

const EXT4_SUPERBLOCK_OFFSET: usize = 1024;
pub const EXT4_BLOCK_SIZE: usize = 4096;

impl Ext4FileSystem {
    /// Opens and loads an Ext4 from the `block_device`
    pub fn open(block_device: Arc<dyn BlockDevice>) -> Arc<FSMutex<Self>> {
        // log::info!(
        //     "sizeof(Ext4SuperBlock): {}",
        //     core::mem::size_of::<Ext4SuperBlock>()
        // );
        log::debug!("[Ext4FileSystem::open()]");
        // 对于Ext4文件系统block_size是4096, 其中superblock在0x400偏移处, 前512bytes是留给引导程序的
        let ext4_meta = get_block_cache(0, block_device.clone(), EXT4_BLOCK_SIZE)
            .lock()
            .read(EXT4_SUPERBLOCK_OFFSET, |super_block: &Ext4SuperBlock| {
                log::debug!("[Ext4FileSystem::open()] super_block: {:?}", super_block);
                assert!(
                    super_block.is_valid(),
                    "[Ext4FileSystem::open()] Error loading super_block!"
                );
                log::info!("inode size: {}", super_block.inode_size as usize);
                log::info!(
                    "inode EXT4_INODE_SIZE: {}",
                    core::mem::size_of::<Ext4Inode>()
                );
                Arc::new(Ext4Meta::new(super_block))
            });
        // 读取块组信息
        // 块组描述符表的位置是紧跟在超级块之后，即从 块 1 开始。
        log::info!(
            "size of GroupDesc: {}",
            core::mem::size_of::<block_group::GroupDesc>()
        );
        let mut block_groups = Vec::new();
        // 注意这里有假设: 假设块组描述符表在第一个块组中
        assert!(
            ext4_meta.block_group_count as usize * core::mem::size_of::<GroupDesc>()
                < EXT4_BLOCK_SIZE
        );
        let block_groups_block = get_block_cache(1, block_device.clone(), EXT4_BLOCK_SIZE);
        for i in 0..ext4_meta.block_group_count as usize {
            block_groups_block.lock().read(
                i * core::mem::size_of::<GroupDesc>(),
                |group_desc: &GroupDesc| {
                    block_groups.push(group_desc.clone());
                },
            );
        }
        log::info!("Group 0 inode_table: {}", block_groups[0].inode_table());

        let root_inode =
            Ext4Inode::new_root(Arc::clone(&block_device), &ext4_meta, &block_groups[0]);
        log::info!("root_inode: {:?}", root_inode);
        root_inode.flags();
        // root_inode Ok

        let generic_inode = Inode::new(root_inode.clone());

        let mut read_buf: [u8; 4096] = [0; 4096];

        generic_inode
            .read(0, &mut read_buf)
            .expect("Inode::read failed");

        let dir_content = Ext4DirContent::new(&read_buf);
        dir_content.list();

        Arc::new(FSMutex::new(Self {
            block_device,
            ext4_meta,
            block_groups,
            root_inode,
        }))
    }
}


pub mod block;
pub mod net;
pub use block::BLOCK_DEVICE;


pub(crate) fn get_dev_tree_size(addr: usize)->usize {
    // 安全地解析设备树
    let dev_tree = unsafe { fdt::Fdt::from_ptr(addr as *const u8).unwrap() };
    
    // 直接获取设备树的总大小
    let total_size = dev_tree.total_size();
    println!("[get_dev_tree_size]:Device tree total size: {} bytes", total_size);
    total_size
}

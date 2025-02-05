use core::any::Any;
/// Trait for block devices
/// which reads and writes data in the unit of blocks
/// 支持muliple blocks的读写
pub trait BlockDevice: Send + Sync + Any {
    ///Read data form block to buffer
    fn read_blocks(&self, start_block_id: usize, buf: &mut [u8]);
    ///Write data from buffer to block
    fn write_blocks(&self, write_block_id: usize, buf: &[u8]);
    /// Return device ID
    /// Todo
    fn get_id(&self) -> usize {
        66666666
    }
}

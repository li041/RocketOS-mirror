use super::{inode::Inode, FileOp};

pub struct File {
    pub inode: Inode,
    /// 单位是字节
    pub offset: usize,
}

impl FileOp for File {
    fn read<'a>(&'a self, buf: &'a mut [u8]) -> Result<usize, &'static str> {
        self.inode.read(self.offset, buf)
    }

    fn write<'a>(&'a self, buf: &'a [u8]) -> usize {
        self.inode.write(self.offset, buf)
    }
}

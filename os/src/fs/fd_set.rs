use crate::task::current_task;
use crate::{arch::mm::copy_from_user, syscall::errno::Errno};
use alloc::vec;
use alloc::{sync::Arc, vec::Vec};

use super::{fdtable::MAX_FDS, file::FileOp};

/// 重构后的FdSet结构，通过RAII管理内核缓冲区
pub struct FdSet {
    // 内核缓冲区（所有权由FdSet持有）
    kernel_buf: Vec<usize>,
    // 指向缓冲区的指针
    addr: *mut usize,
    // 元素数量（按位计算）
    len: usize,
}

impl FdSet {
    /// 创建一个空的FdSet（无缓冲区）
    pub fn new_empty() -> Self {
        FdSet {
            kernel_buf: Vec::new(),
            addr: core::ptr::null_mut(),
            len: 0,
        }
    }

    /// 从用户空间地址初始化（核心方法）
    pub fn from_user(addr: usize, len: usize) -> Result<Self, Errno> {
        if len > MAX_FDS || len == 0 {
            return Err(Errno::EINVAL);
        }

        let kernel_len = core::cmp::min(len, 15);
        // 创建内核缓冲区并拷贝数据
        let mut kernel_buf = vec![0; kernel_len];

        copy_from_user(
            addr as *const i32,
            kernel_buf.as_mut_ptr() as *mut i32,
            kernel_len,
        )?;

        Ok(FdSet {
            addr: kernel_buf.as_mut_ptr(),
            len: kernel_len,
            kernel_buf,
        })
    }

    pub fn get_addr(&self) -> *mut usize {
        self.addr
    }
    pub fn get_len(&self) -> usize {
        self.len
    }
    pub fn check(&self, fd: usize) -> bool {
        if fd >= self.len {
            return false;
        }
        let byte_index = fd / 64;
        let bit_index = fd & 0x3f;
        unsafe { *(self.addr.add(byte_index)) & (1 << bit_index) != 0 }
    }

    /// 设置指定fd位
    pub fn set(&mut self, fd: usize) {
        if fd >= self.len * 64 {
            return;
        }
        let byte_index = fd / 64;
        let bit_index = fd % 64;
        unsafe {
            *self.addr.add(byte_index) |= 1 << bit_index;
        }
    }
    pub fn valid(&self) -> bool {
        self.addr as usize != 0
    }
    pub fn clear(&self) {
        for i in 0..=(self.len - 1) / 64 {
            unsafe {
                *(self.addr.add(i)) = 0;
            }
        }
    }
}

impl Drop for FdSet {
    fn drop(&mut self) {
        // 缓冲区会随结构体自动释放
        // 此处可以添加日志或其他清理操作
        log::debug!("Dropping FdSet with {} entries", self.len);
    }
}

// 修改后的FdSetIter
pub struct FdSetIter {
    pub fdset: FdSet, // 现在由FdSet自己管理缓冲区
    pub files: Vec<Arc<dyn FileOp>>,
    pub fds: Vec<usize>,
}
pub fn init_fdset(addr: usize, len: usize) -> Result<FdSetIter, Errno> {
    if len > MAX_FDS {
        //非法长度
        return Err(Errno::EINVAL);
    }
    if addr == 0 {
        return Ok(FdSetIter {
            // kernel_buffer:Vec::new(),
            fdset: FdSet::new_empty(),
            files: Vec::new(),
            fds: Vec::new(),
        });
    }
    // let mut kernel_fs=vec![0;len];
    // copy_from_user(addr as *const i32,kernel_fs.as_mut_ptr() ,len)?;
    let fdset = FdSet::from_user(addr, len)?;
    let task = current_task();
    let mut files: Vec<Arc<dyn FileOp>> = Vec::new();
    let mut fds: Vec<usize> = Vec::new();
    for fd in 0..len {
        if fdset.check(fd) {
            // let fd=addr[i] as usize;
            log::error!("[init_fdset]:fdset check fd {} ", fd);
            // let file=task.fd_table().get_file(fd).unwrap();
            if let Some(file) = task.fd_table().get_file(fd) {
                files.push(file.clone());
                fds.push(fd);
            } else {
                //不是合法的fd
                return Err(Errno::EBADF);
            }
        }
    }
    drop(task);
    fdset.clear();
    Ok(FdSetIter { fdset, files, fds })
}
// use alloc::{sync::Arc, vec:: Vec};
// use alloc::vec;
// use crate::task::current_task;
// use crate::{arch::mm::{copy_from_user, copy_to_user}, syscall::errno::Errno};

// use super::{fdtable::MAX_FDS, file::FileOp};

// /// 重构后的FdSet结构，通过RAII管理内核缓冲区
// pub struct FdSet {
//     // 内核缓冲区（所有权由FdSet持有）
//     kernel_buf: Vec<usize>,
//     // 指向缓冲区的指针
//     addr: *mut usize,
//     // 元素数量（按位计算）
//     len: usize,
// }

// impl FdSet {
//     /// 创建一个空的FdSet（无缓冲区）
//     pub fn new_empty() -> Self {
//         FdSet {
//             kernel_buf: Vec::new(),
//             addr: core::ptr::null_mut(),
//             len: 0,
//         }
//     }

//     /// 从用户空间地址初始化（核心方法）
//     pub fn from_user(addr: usize, len: usize) -> Result<Self, Errno> {
//         if len > MAX_FDS || len == 0 {
//             return Err(Errno::EINVAL);
//         }

//         // 创建内核缓冲区并拷贝数据
//         let mut kernel_buf = vec![0; len];
//             copy_from_user(
//                 addr as *const i32,
//                 kernel_buf.as_mut_ptr() as *mut i32,
//                 len,
//             )?;

//         Ok(FdSet {
//             addr: kernel_buf.as_mut_ptr(),
//             len,
//             kernel_buf,
//         })
//     }

//     pub fn get_addr(&self) -> *mut usize {
//         self.addr
//     }
//     pub fn get_len(&self) -> usize {
//         self.len
//     }
//     pub fn check(&self, fd: usize) -> bool {
//         if fd >= self.len {
//             return false;
//         }
//         let byte_index = fd / 64;
//         let bit_index = fd & 0x3f;
//         unsafe { *(self.addr.add(byte_index)) & (1 << bit_index) != 0 }
//     }

//     /// 设置指定fd位
//     pub fn set(&mut self, fd: usize) {
//         if fd >= self.len * 64 {
//             return;
//         }
//         let byte_index = fd / 64;
//         let bit_index = fd % 64;
//         unsafe {
//             *self.addr.add(byte_index) |= 1 << bit_index;
//         }
//     }
//     pub fn valid(&self) -> bool {
//         self.addr as usize != 0
//     }
//     pub fn clear(&self) {
//         for i in 0..=(self.len - 1) / 64 {
//             unsafe {
//                 *(self.addr.add(i)) = 0;
//             }
//         }
//     }
// }

// impl Drop for FdSet {
//     fn drop(&mut self) {
//         // 缓冲区会随结构体自动释放
//         // 此处可以添加日志或其他清理操作
//         log::debug!("Dropping FdSet with {} entries", self.len);
//     }
// }

// // 修改后的FdSetIter
// pub struct FdSetIter {
//     pub fdset: FdSet,       // 现在由FdSet自己管理缓冲区
//     pub files: Vec<Arc<dyn FileOp>>,
//     pub fds: Vec<usize>,
// }
// pub fn init_fdset(addr: usize, len: usize) -> Result<FdSetIter, Errno> {
//         if len > MAX_FDS || len < 0 {
//             //非法长度
//             return Err(Errno::EINVAL);
//         }
//         if addr == 0 {
//             return Ok(FdSetIter {
//                 // kernel_buffer:Vec::new(),
//                 fdset: FdSet::new_empty(),
//                 files: Vec::new(),
//                 fds: Vec::new(),
//             });
//         }
//         let mut kernel_fs=vec![0;len];
//         copy_from_user(addr as *const i32,kernel_fs.as_mut_ptr() ,len)?;
//         let fdset = FdSet::from_user(addr, len)?;
//         let task = current_task();
//         let mut files: Vec<Arc<dyn FileOp>> = Vec::new();
//         let mut fds: Vec<usize> = Vec::new();
//         for fd in 0..len {
//             if fdset.check(fd) {
//                 // let fd=addr[i] as usize;
//                 log::error!("[init_fdset]:fdset check fd {} ", fd);
//                 // let file=task.fd_table().get_file(fd).unwrap();
//                 if let Some(file) = task.fd_table().get_file(fd) {
//                     files.push(file.clone());
//                     fds.push(fd);
//                 } else {
//                     //不是合法的fd
//                     return Err(Errno::EBADF);
//                 }
//             }
//         }
//         fdset.clear();
//         Ok(FdSetIter {
//             fdset,
//             files,
//             fds,
//         })
// }

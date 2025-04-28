/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-04-22 22:31:04
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-04-27 21:01:03
 * @FilePath: /RocketOS/os/src/fs/fdSet.rs
 * @Description: 
 * 
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved. 
 */
use core::{default, ops::Add};

use alloc::{sync::Arc, vec::Vec};

use crate::{arch::mm::{copy_from_user, copy_from_user_mut}, mm::VirtAddr, syscall::errno::Errno, task::{self, current_task}};

use super::{fdtable::MAX_FDS, file::FileOp};

pub struct FdSet {
    //复制到的内核地址
    addr:*mut usize,
    //元素
    len:usize
}
impl FdSet {
    pub fn new_raw()->Self {
        FdSet {
            addr: 0 as *mut usize,
            len: 0
        }
    }
    pub fn new(addr:*mut usize,len:usize)->Self {
        FdSet { addr: addr, len: len }
    }
    pub fn get_addr(&self)->*mut usize {
        self.addr
    }
    pub fn get_len(&self)->usize {
        self.len
    }
        /// set the index in the bitset
    pub fn set(&mut self, index: usize) {
        if index >= self.len {
            return;
        }
        let byte_index = index / 64;
        let bit_index = index & 0x3f;
        unsafe {
            *self.addr.add(byte_index) |= 1 << bit_index;
        }
    }
    //检查i指定fd对应掩码是否为1
    pub fn check(&self,fd:usize)->bool{
        if fd>=self.len{
            return false;
        }
        let byte_index = fd / 64;
        let bit_index = fd & 0x3f;
        unsafe { *(self.addr.add(byte_index)) & (1 << bit_index) != 0 }
    }
    // 清空自己
    pub fn clear(&self) {
        for i in 0..=(self.len - 1) / 64 {
            unsafe {
                *(self.addr.add(i)) = 0;
            }
        }
    }
    pub fn valid(&self)->bool {
        self.addr as usize!=0
    }
}
//用于保存一个fdset中满足要求的文件集合
pub struct FdSetIter {
    pub fdset: FdSet,
    pub files: Vec<Arc<dyn FileOp>>,
    pub fds:Vec<usize>,
}


///addr是数组地址，len是长度
///
pub fn init_fdset(addr:usize,len:usize)->Result<FdSetIter,Errno> {
    if len>MAX_FDS||len<0 {
        //非法长度
        return Err(Errno::EINVAL);
    }
    if addr==0 {
        return Ok(FdSetIter {
            fdset: FdSet::new_raw(),
            files: Vec::new(),
            fds:Vec::new()
        });
    }
    let addr=copy_from_user_mut(addr as *mut i32, len).unwrap();
    let fdset=FdSet::new(addr.as_mut_ptr() as *mut usize, len);
    let task=current_task();
    let mut files=Vec::new();
    let mut fds=Vec::new();
    for fd in 0..len{
        if fdset.check(fd) {
            // let fd=addr[i] as usize;
            log::error!("[init_fdset]:fdset check fd {} ",fd);
            // let file=task.fd_table().get_file(fd).unwrap();
            if let Some(file)=task.fd_table().get_file(fd) {
                files.push(file.clone());
                fds.push(fd);
            }
            else {
                //不是合法的fd
                return Err(Errno::EBADF);
            }
            // files.push(task.fd_table().get_file(fd).unwrap().clone());
            // fds.push(fd);
        }
    }
    fdset.clear();
    Ok(FdSetIter {
        fdset,
        files,
        fds
    })
}
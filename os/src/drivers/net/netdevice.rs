/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-03-26 10:01:09
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-08-06 17:55:59
 * @FilePath: /RocketOS_netperfright/os/src/drivers/net/netdevice.rs
 * @Description: 
 * 
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved. 
 */

use core::ptr::NonNull;

use smoltcp::wire::EthernetAddress;
/// The ethernet address of the NIC (MAC address).
// pub struct EthernetAddress(pub [u8; 6]);
///这个文件用于定义net-device的trait方便后续调用
pub trait NetDevice:Sync + Send {
    fn capabilities(&self)->smoltcp::phy::DeviceCapabilities;
    fn mac_address(&self)->EthernetAddress;
    //是否可以发送数据
    fn isok_send(&self)->bool;
    //是否可以接收数据
    fn isok_recv(&self)->bool;
    //一次最多可以发送报文数量
    fn max_send_buf_num(&self)->usize;
    //一次最多可以发送报文数量
    fn max_recv_buf_num(&self)->usize;
    //回收接收的buffer
    fn recycle_recv_buffer(&mut self,recv_buf:NetBufPtr);
    fn recycle_send_buffer(&mut self)->Result<(),()>;
    fn send(&mut self,ptr:NetBufPtr)->usize;
    fn recv(&mut self)->Option<NetBufPtr>;
    //分配一个发送的数据包
    fn alloc_send_buffer(&mut self,size:usize)->NetBufPtr;
}

// pub trait NetBufPtrOps{
//     fn packet(&self)->&[u8];
//     fn packet_mut(&mut self)->&mut [u8];
//     fn packet_len(&self)->usize;
// }



#[repr(C)]
#[derive(Debug,Clone, Copy)]
pub struct NetBufPtr{
    ///NetBuf指针
    pub netbuf_ptr:NonNull<u8>,
    ///NetBuf中epackt的指针,这里是n不报哈header
    pub(crate) packet_ptr:NonNull<u8>,
    ////packet长度
    pub packcet_len:usize
}
impl NetBufPtr {
    pub fn new(len:usize,raw_ptr:NonNull<u8>,buf_ptr:NonNull<u8>)->Self {
        NetBufPtr { netbuf_ptr: raw_ptr, packet_ptr: buf_ptr, packcet_len: len }
    }    
    pub fn raw_ptr<T>(&self)->*mut T {
        self.netbuf_ptr.as_ptr() as *mut T
    }
    pub fn packet_len(&self)->usize {
        self.packcet_len
    }
    ///返回packet
    pub fn packet(&self)->&[u8] {
        unsafe { core::slice::from_raw_parts(self.packet_ptr.as_ptr(), self.packcet_len) }       
    }
    pub fn packet_mut(&self)->&mut [u8]{
        unsafe { core::slice::from_raw_parts_mut(self.packet_ptr.as_ptr(), self.packcet_len) }
    }
}

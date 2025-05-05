/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-03-26 00:18:48
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-04-30 14:45:51
 * @FilePath: /RocketOS/os/src/drivers/net/loopback.rs
 * @Description: 
 * 
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved. 
 */
use core::ptr::NonNull;

use alloc::{boxed::Box, collections::vec_deque::VecDeque, vec::Vec};
use smoltcp::{phy::{DeviceCapabilities, Medium}, wire::EthernetAddress};

use crate::drivers::net::netdevice::NetBufPtr;
use alloc::vec;
use super::{netdevice::{NetDevice}, NetBuf};

///本文件主要用于初始化本机回环网络设备，而不是直接的mmio的virtio_net device



pub struct LoopbackDev{
    ///这里考虑是由于是本地回环发送，所以没必要考虑太麻烦，直接用一个变量存储数据，发送的数据存入，
    /// 需要接收的时候从这里接收e即可
    queue:VecDeque<Vec<u8>>
}

impl LoopbackDev {
    pub fn new()->Box<Self> {
        Box::new(Self {
            queue: VecDeque::with_capacity(256),
        })
        
    }
}

//本地当然需要可以完成NETDEVICE任务
impl NetDevice for LoopbackDev {
    fn mac_address(&self)->EthernetAddress {
        EthernetAddress([0x00,0x00,0x00,0x00,0x00,0x00])
    }
    fn isok_recv(&self)->bool {
        true
    }
    fn isok_send(&self)->bool {
        true
    }
    fn max_recv_buf_num(&self)->usize {
        usize::MAX
    }
    fn max_send_buf_num(&self)->usize {
        usize::MAX
    }
    fn recycle_recv_buffer(&mut self,recv_buf:super::netdevice::NetBufPtr) {
       
    }
    fn recycle_send_buffer(&mut self)->Result<(),()> {
        Ok(())
    }
    fn send(&mut self,ptr:super::netdevice::NetBufPtr) {
        let send_buf=ptr.packet().to_vec();
        let len=ptr.packet_len();
        self.queue.push_back(send_buf);
        log::error!("[LoopbackDev]:LoopbackDev has send data {} bytes",len)
    }
    //直接从queue中读取即可，由于push back,故而需要pop front
    fn recv(&mut self)->Option<super::netdevice::NetBufPtr> {
        if let Some(mut data) = self.queue.pop_front() {
            log::error!("[LoopbackDev]:LoopbackDev has recv data {} bytes",data.len());
            // Some(NetBufPtr(
            //     netbuf_ptr:NonNull::new(data.as_ptr()),
            //     packet_ptf:
            //     packet_len:data.len()
            // ))
            Some(NetBufPtr::new(data.len(), 
            NonNull::new(data.as_mut_ptr()).unwrap(),
             NonNull::new(unsafe { data.as_mut_ptr().add(20) } as *mut u8).unwrap()))
        }
        else {
            None
        }
    }

    //size是packet_size，正常是从free_list中pop出来
    fn alloc_send_buffer(&mut self,size:usize)->super::netdevice::NetBufPtr {
        log::error!("[loopback alloc_send_buffer]:size is {}",size);
        let mut data=vec![0;size];
        // data.resize(size, 0);
        NetBufPtr::new(size, NonNull::new(data.as_mut_ptr()).unwrap(), NonNull::new(unsafe { data.as_mut_ptr().add(20)as *mut u8 } ).unwrap())
    }
    
    fn capabilities(&self)->smoltcp::phy::DeviceCapabilities {
        let mut cap = DeviceCapabilities::default();
        cap.max_transmission_unit = 65535;
        cap.max_burst_size = None;
        cap.medium = Medium::Ip;
        cap
    }

}
use core::{ops::{Deref, DerefMut}, pin};

/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-03-31 22:34:08
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-05-21 21:12:05
 * @FilePath: /RocketOS_netperfright/os/src/net/listentable.rs
 * @Description: listentable file
 * 
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved. 
 */
use alloc::{boxed::Box, collections::vec_deque::VecDeque};
use hashbrown::Equivalent;
use log::logger;
use spin::Mutex;
use smoltcp::{iface::{SocketHandle, SocketSet}, socket::{tcp::{self, State}, Socket}, wire::{IpAddress, IpEndpoint, IpListenEndpoint, Ipv4Address}};

use crate::{net::ETH0, syscall::errno::Errno};

use super::{SocketSetWrapper, LISTEN_QUEUE_SIZE, SOCKET_SET};

struct ListenTableEntry{
    //表示监听的server地址，addr
    listen_endpoint:IpListenEndpoint,
    //监听client发送过来的syn,这个vec的长度决定其可以同时接受client的数量
    syn_queue:VecDeque<SocketHandle>
}
impl ListenTableEntry {
    pub fn new(listen_endpoint:IpListenEndpoint)->Self {

        ListenTableEntry { listen_endpoint: listen_endpoint, syn_queue: VecDeque::with_capacity(LISTEN_QUEUE_SIZE) }
    }
    pub fn can_accept(&self,dst:IpAddress)->bool {
        //这里只决定是否可以对client建立连接，这里的判断标准只是比较client传过来的remote_addr
        //具体是否可以监听需要看syn_queue中是否有空
        match self.listen_endpoint.addr {
            Some(addr) => addr == dst,
            None => true,
        }
    }
}
impl Drop for ListenTableEntry {
    fn drop(&mut self) {
        for &handle in &self.syn_queue {
            //需要注意socketset中socket就是smoltcp中socket,而我们在tcp中的socket是自己设定的，唯一o有关系的是handle
            SOCKET_SET.remove(handle);
        }
    }
}

pub struct ListenTable{
    //是由listenentry构建的监听表
    //监听表的表项个数与端口个数有关，每个端口只允许一个地址使用
    table:Box<[Mutex<Option<Box<ListenTableEntry>>>]>,
}

impl ListenTable {
    pub fn new()->Self {
    let table=
       unsafe {
        let mut buf=Box::new_uninit_slice(65536);
        for i in 0..65536{
            buf[i].write(Mutex::new(None));
        }
        buf.assume_init()
       }; 
        ListenTable { table: table }
    }
    pub fn can_listen(&self,port:u16)->bool {
        self.table[port as usize].lock().is_none()
    }
    // pub fn is_local(&self,port:u16)->bool {
    //     let local_addr=IpAddress::v4(127, 0, 0, 1);
    //     if let Some(entry) = self.table[port as usize].lock().deref()  {
    //         if let Some(addr) = entry.listen_endpoint.addr {
    //             if addr.equivalent(&local_addr) {
    //                 true
    //             }
    //             else {
    //                 false
    //             }
    //         }
    //         else {
    //             false
    //         }
    //     }
    //     else {
    //         false
    //     }
    // }
    pub fn listen(&self,listen_endpoint:IpListenEndpoint) {
        //判断listen_endpoint想要监听的port是否有人已经在监听e了
        let port=listen_endpoint.port;
        assert!(port!=0);
        let mut entry=self.table[port as usize].lock();
        if entry.is_none(){
            log::error!("[listen_table_listen]:has create a listen entry");
            *entry= Some(Box::new(ListenTableEntry::new(listen_endpoint)));
        }
        else {
            log::error!("[listentable]:has already listen");
        }
    }
    pub fn unlisten(&self,port:u16) {
        *self.table[port as usize].lock()=None
    }
    ///这里根据port找到对应的entry并判断其中的handle对应socket状态是否可以accept
    pub fn can_accept(&self, port: u16) -> bool {
        if let Some(entry) = self.table[port as usize].lock().deref() {
            entry.syn_queue.iter().any(|&handle| is_connected(handle))
        } else {
            panic!("socket accept() failed: not listen")
        }
    }
        // log::error!("[listentable_can_accept]:listen port is {:?}",port);
        // if let Some(entry)=self.table[port as usize].lock().deref(){
        //     //检查1每个syn_queue中的handle是否状态是否为connected
        //     log::error!("[listentable_can_accept]:entry listenendpoint {:?}",entry.listen_endpoint);
        //     log::error!("[listentable_can_accept]:entry syn_queue {:?}",entry.syn_queue);
        //     if entry.syn_queue.len()>0 {
        //         entry.syn_queue.iter().any(|&handle|{
        //             log::error!("[listentable_can_accept]:handle is {}",handle);
        //             SOCKET_SET.with_socket::<_,tcp::Socket,_>(handle, |socekt|{
        //                 log::error!("[listentable_can_accept]:socket state is {:?}",socekt.state());
        //                 !matches!(socekt.state(),tcp::State::SynReceived|tcp::State::Listen)
        //             })
        //         })
        //     }
        //     else {
        //         true
        //     }
        // }
        // else {
        //     false
        // }
    // }
    //这个函数根据输入的参数port查看对应的entry的handle vec,由底层smoltcp完成数据链路层和物理层的连接，并改变状态，如果状态合理，需要
    //得到对应的local_addr,remote_addr
    pub fn accept(&self, port: u16) -> Result<(SocketHandle, (IpEndpoint, IpEndpoint)),Errno> {
        log::error!("[ListenTable_accept]:accept port is {:?}",port);
        if let Some(entry) = self.table[port as usize].lock().deref_mut() {
            log::error!("[ListenTable_accept]:entry listenendpoint {:?}",entry.listen_endpoint);
            let syn_queue: &mut VecDeque<SocketHandle> = &mut entry.syn_queue;
            let idx = syn_queue
                .iter()
                .enumerate()
                .find_map(|(idx, &handle)| is_connected(handle).then(|| idx))
                .ok_or(Errno::EAGAIN)?; // wait for connection

            let handle = syn_queue.swap_remove_front(idx).unwrap();
            // If the connection is reset, return ConnectionReset error
            // Otherwise, return the handle and the address tuple
            log::error!("[ListenTable_accept]:handle is {:?}",handle);
            if is_closed(handle) {
                Err(Errno::ECONNRESET)
            } else {
                Ok((handle, get_addr_tuple(handle)))
            }
        } else {
            Err(Errno::ECONNREFUSED)
        }
    }

    ///函数将push socket进入对应的entry
    /// 判断对应entry是否有剩下位置，一个端口最多与256个socekt建立连接，
    /// 判断地址是否正确，我们认为一个端口只有一个地址
    /// dst:服务器addr
    /// src：用户地址
    /// sockets:SOCKET_SET
    pub fn push_incoming_packet(&self,dst:IpEndpoint,src:IpEndpoint,sockets:&mut SocketSet) {
        log::error!("[push_incoming_packet]dst addr:{:?},src_packet{:?}",dst,src);
        if let Some(entry) = self.table[dst.port as usize].lock().deref_mut() {
            if !entry.can_accept(dst.addr) {
                // not listening on this address
                //println!("[push_incoming_packet] can not accept the packet is not listen");
                return;
            }
            if entry.syn_queue.len() >= LISTEN_QUEUE_SIZE {
                // SYN queue is full, drop the packet
                // warn!("SYN queue overflow!");
                //println!("[push_incoming_packet]:syn queue is overflow");
                return;
            }
            let mut socket = SocketSetWrapper::new_tcp_socket();
            //log::error!("[push_incoming_packet]:socket listen endpoint{:?}",entry.listen_endpoint);
            //log::error!("[push_incoming_packet]:socket dst port{:?}",dst.port);
            // if socket.is_open() {
            //     println!("is open is true");
            // }
            if socket.listen(entry.listen_endpoint).is_ok() {
                log::error!("[push_incoming_packet]:socket listen_endpoint {:?}",entry.listen_endpoint);
                let handle = sockets.add(socket);
                log::error!("[push_incoming_packet]:socket handle {:?}",handle);
                // socket.remote_endpoint()
                // socket.set_bound_endpoint(entry.listen_endpoint);
                // socket.set_bound_endpoint(bound_endpoint);
                //log::error!(
                    // "TCP socket {}: prepare for connection {} -> {}",
                    // handle, src, entry.listen_endpoint
                //);
                //log::error!("[push_incoming_packet]handle:{:?}",handle);
                entry.syn_queue.push_back(handle);
            }
        }
    }
}
fn is_connected(handle: SocketHandle) -> bool {
    SOCKET_SET.with_socket::<_, tcp::Socket, _>(handle, |socket| {
        log::error!("[is_connected] socket state is {:?}",socket.state());
        !matches!(socket.state(), State::Listen | State::SynReceived)
    })
}
fn is_closed(handle: SocketHandle) -> bool {
    SOCKET_SET
        .with_socket::<_, tcp::Socket, _>(handle, |socket| {
            log::error!("[is_closed] socket state is {:?}",socket.state());
            matches!(socket.state(), State::Closed)
        })
}
fn get_addr_tuple(handle: SocketHandle) -> (IpEndpoint, IpEndpoint) {
    SOCKET_SET.with_socket::<_, tcp::Socket, _>(handle, |socket| {
        (
            socket.local_endpoint().unwrap(),
            socket.remote_endpoint().unwrap(),
        )
    })
}

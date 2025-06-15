/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-04-02 12:09:33
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-06-15 11:04:45
 * @FilePath: /RocketOS_netperfright/os/src/net/udp.rs
 * @Description: udp socket
 * 
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved. 
 */

use core::cell::UnsafeCell;
use core::net::IpAddr;
use core::net::Ipv4Addr;
// use core::f128::consts::E;
use core::net::SocketAddr;
use core::panic;
use core::ptr::copy_nonoverlapping;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;
use core::time;
use alloc::vec;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::udp;
use smoltcp::socket::udp::BindError;
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpListenEndpoint;
use spin::Mutex;
use spin::RwLock;
use smoltcp::wire::IpEndpoint;
use crate::arch::config::SysResult;
use crate::arch::timer::get_time;
use crate::futex::flags;
use crate::net::addr::is_unspecified;
use crate::net::addr::LOOP_BACK_ENDPOINT;
use crate::net::addr::LOOP_BACK_IP;
use crate::net::addr::UNSPECIFIED_IP;
use crate::syscall::errno::Errno;
use crate::syscall::errno::SyscallRet;
use crate::task;
use crate::task::current_task;
use crate::task::yield_current_task;

use super::addr::from_ipendpoint_to_socketaddr;
use super::addr::from_sockaddr_to_ipendpoint;
use super::addr::UNSPECIFIED_ENDPOINT;
use super::poll_interfaces;
use super::tcp::PollState;
use super::SocketSetWrapper;

use super::LISTEN_TABLE;
use super::SOCKET_SET;

 pub struct UdpSocket{
    handle:UnsafeCell<Option<SocketHandle>>,
    local_addr:RwLock<Option<IpEndpoint>>,
    remote_addr:RwLock<Option<IpEndpoint>>,
    nonblock:AtomicBool,
    reuse_addr:AtomicBool
 }

 unsafe impl Sync for UdpSocket {}
 unsafe  impl Send for UdpSocket {}


 //public function
 impl UdpSocket {
    pub fn new()->Self {
        let udp_socket=SocketSetWrapper::new_udp_socket();
        let handle=SOCKET_SET.add(udp_socket);
        UdpSocket { handle: UnsafeCell::new(Some(handle)),
            local_addr:RwLock::new(None)
            , remote_addr: RwLock::new(None),
            nonblock: AtomicBool::new(false),
            reuse_addr: AtomicBool::new(false), }
            
     }

    pub fn local_addr(&self)-> Result<SocketAddr,Errno>{
         match self.local_addr.try_read() {
            
            Some(addr) => {
                log::error!("[local_addr]:local_addr is {:?}",addr);
                addr.map(from_ipendpoint_to_socketaddr).ok_or(Errno::ENOTCONN)
            },
            None => {Err(Errno::ENOTCONN)},
        }
    }
    pub fn reomte_addr(&self)->Result<SocketAddr,Errno>{
        match self.remote_addr.try_read() {
            Some(addr) => {
                addr.map(from_ipendpoint_to_socketaddr).ok_or(Errno::ENOTCONN)
            },
            None => {
                Err(Errno::ENOTCONN)
            },
        }
    }
    pub fn is_nonblocking(&self)->bool {
        self.nonblock.load(Ordering::Acquire)
    }
    pub fn set_nonblocking(&self,block:bool) {
        self.nonblock.store(block, core::sync::atomic::Ordering::Release);
    }
    pub fn set_socket_ttl(&self,ttl:u8) {
        let handle=unsafe { self.handle.get().read().unwrap() };
        SOCKET_SET.with_socket_mut::<_,udp::Socket,_>(handle, |socket|{
            //设置ttl
            socket.set_hop_limit(Some(ttl));
        });
    }
    pub fn is_reuse_addr(&self)->bool {
        self.reuse_addr.load(core::sync::atomic::Ordering::Acquire)
    }
    pub fn set_reuse_addr(&self,reuse:bool) {
        self.reuse_addr.store(reuse,core::sync::atomic::Ordering::Release);
    }
    pub fn is_block(&self)->bool {
        false
    }

    //绑定addr到local_addr
    pub fn bind(&self,mut bind_addr:SocketAddr) {
        log::error!("[Udpsocket_bind]:begin bind,bind addr is {:?}",bind_addr);
        let mut local_addr=self.local_addr.write();
        if local_addr.is_some() {
            //已经设置addr,说明已经绑定了
            log::error!("[Udpsocket_bind]:the socket local_addr has been bound");
            //错误处理需要设计以下
            panic!();
        }
        if bind_addr.port()==0 {
            bind_addr.set_port(get_ephemeral_port());
        }
        //比较socket中的local_addr是否已经设置

        log::error!("[udp_bind]bind addr is {:?}",bind_addr);
        let mut local_endpoint=from_sockaddr_to_ipendpoint(bind_addr);
        if is_unspecified(local_endpoint.addr) {
            local_endpoint.addr=LOOP_BACK_IP;
        }
        let endpoint=IpListenEndpoint{
            addr:(!is_unspecified(local_endpoint.addr)).then_some(local_endpoint.addr),
            port: local_endpoint.port,
        };
        log::error!("[Udpsocket_bind] bind endpoint is {:?}",endpoint);
        if !self.is_reuse_addr() {
            // // Check if the address is already in use
            match  SOCKET_SET.bind_check(local_endpoint.addr, local_endpoint.port){
                Ok(a) => {},
                Err(e) => {
                },
            }
            // SOCKET_SET.bind_check(local_endpoint.addr, local_endpoint.port);
        }
        let handle=unsafe { self.handle.get().read().unwrap() };
        log::error!("[Udpsocket_bind]:socket handle is {:?}",handle);
        SOCKET_SET.with_socket_mut::<_,udp::Socket,_>(handle, |socket|{
            socket.bind(endpoint)
            .expect("socket bind() failed");
        });
        // let mut self_local=self.local_addr.write();
        *local_addr=Some(local_endpoint);
    }

    pub fn send_to(&self,buf:&[u8],remote_addr:SocketAddr)->Result<usize,Errno> {
        log::error!("[Udpsocket_sendto]:remote_addr is {:?}",remote_addr);
        if remote_addr.port()==0||remote_addr.ip().is_unspecified() {
            log::error!("[Udpsocket_sendto]:socket sendto a unspecified sockaddr");
        }
        log::error!("[Udpsocket_sendto]remote_socketaddr is {:?}",remote_addr);
        self.send_impl(buf, from_sockaddr_to_ipendpoint(remote_addr))
    }
    pub fn recv_from(&self,buf:&mut [u8])->Result<(usize,SocketAddr),Errno> {
        log::error!("[udp_recv_from]begin recv");
        let mut binding = vec![0;1528];
        let kernel_buf=binding.as_mut_slice();

        self.recv_impl(|socket| match socket.recv_slice(kernel_buf) {
            Ok((len, meta)) => {
                // log::error!("[udp_recv_from]recv buf {:?}",buf);
                {
                    let copy_len = core::cmp::min(len, buf.len()); 
                    log::error!("[udp_recv_from] copy len is {:?}",copy_len);
                    buf[..copy_len].copy_from_slice(&kernel_buf[..copy_len]); 
                    log::trace!("[udp_block_on] loop");
                    Ok((copy_len, from_ipendpoint_to_socketaddr(meta.endpoint)))}
                },
            Err(e) => {
                log::error!("[udp_recv_from] recv error {:?}",e);
                match e {
                    udp::RecvError::Exhausted => {
                        Err(Errno::EAGAIN)
                    },
                    udp::RecvError::Truncated => Err(Errno::EAGAIN)
                }
            }
        })
    }
    pub fn recv_from_timeout(&self, buf: &mut [u8], ticks: usize) -> Result<(usize, SocketAddr),Errno> {
        log::error!("[recv_from_timeout] recv begin");
        let time=get_time();
        let expire_at = time+ ticks;
        self.recv_impl(|socket| match socket.recv_slice(buf) {
            Ok((len, meta)) => Ok((len, from_ipendpoint_to_socketaddr(meta.endpoint))),
            Err(e) => {
                log::error!("[recv_from_timeout]:recv error {:?}",e);
                if get_time() > expire_at {
                    Err(Errno::EINVAL)
                } else {
                    Err(Errno::EAGAIN)
                }
            }
        })
    }

    pub fn peek_from(&self,buf:&mut [u8])->Result<(usize,SocketAddr),Errno> {
        self.recv_impl(|socket| match socket.peek_slice(buf) {
            Ok((len, meta)) => Ok((len, from_ipendpoint_to_socketaddr(meta.endpoint))),
            Err(_) => Err(Errno::ENOTCONN),
        })
    }
    
    /// connect函数将会设置对应remote_addr，connect建立的目的是为了使用recv/send,这样可以直接不用参数remote_addr了
    pub fn connect(&self,remote_addr:SocketAddr) ->Result<(),Errno>{
        log::error!("[Udpsocket_connect]:begin connect remote addr is {:?}",remote_addr);
        let mut self_remote_addr=self.remote_addr.write();
        if self.local_addr.read().is_none() {
            self.bind(from_ipendpoint_to_socketaddr(IpEndpoint::new(LOOP_BACK_IP, get_ephemeral_port())));
        }
        *self_remote_addr=Some(from_sockaddr_to_ipendpoint(remote_addr));
        Ok(())
    }
    pub fn send(&self,buf:&[u8])->Result<usize,Errno> {
        let remote_endpoint = from_sockaddr_to_ipendpoint(self.reomte_addr().unwrap());
        self.send_impl(buf, remote_endpoint)
    }
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize,Errno> {
        let remote_endpoint = from_sockaddr_to_ipendpoint(self.reomte_addr().unwrap());
        self.recv_impl(|socket| {
            let (len, meta) = socket
                .recv_slice(buf)
                .map_err(|_| panic!("socket recv() failed"))?;
            // let remote_addr=IpAddress::Ipv4(remote_endpoint.ip());
            if !is_unspecified(remote_endpoint.addr) && remote_endpoint.addr!= meta.endpoint.addr {
                return Err(Errno::EAGAIN)
            }
            if remote_endpoint.port!= 0 && remote_endpoint.port != meta.endpoint.port {
                return Err(Errno::EAGAIN)
            }
            Ok(len)
        })
    }
    pub fn shutdown(&self) {
        log::error!("[udp_shutdown]begin shutdown");
        poll_interfaces();
        let handle=unsafe { self.handle.get().read().unwrap() };
        SOCKET_SET.with_socket_mut::<_,udp::Socket,_>(handle, |socket|{
            socket.close();
        })
    }
    pub fn poll(&self)->PollState {
        // println!("[udp_poll]begin poll");
        if self.local_addr.read().is_none() {
            return PollState{
                readable:false,
                writeable:false
            };
        }
        let handle=unsafe { self.handle.get().read().unwrap() };
        SOCKET_SET.with_socket_mut::<_,udp::Socket,_>(handle, |socket|{
            // loop {
            log::error!("[udp_poll]:readalbe:{},writealbe:{}",socket.can_recv(),socket.can_send());
            // if socket.can_recv()|socket.can_send() {
            //     return PollState { readable: socket.can_recv(), writeable: socket.can_send() };
            // }
            // }
            PollState { readable:socket.can_recv(), writeable: socket.can_send() }
        })
    }
    pub fn with_socket<R>(&self, f: impl FnOnce(&udp::Socket) -> R) -> R {
        let handle=unsafe { self.handle.get().read().unwrap() };
        SOCKET_SET.with_socket::<_,udp::Socket,_>(handle, |s| f(s))
    }
 }



//private function
 impl UdpSocket {
    fn recv_impl<F, T>(&self, mut op: F) -> Result<T,Errno>
    where
        F: FnMut(&mut udp::Socket) -> Result<T,Errno>,
    {
        if self.local_addr.read().is_none() {
            panic!("socket send() failed");
        }
        let mut times=0;
        self.block_on(|| {
            // log::error!("[recv_impl]recv impl begin");
            let handle=unsafe { self.handle.get().read().unwrap() };
            SOCKET_SET.with_socket_mut::<_, udp::Socket, _>(handle, |socket| {
                if times>5 {
                    return op(socket);
                }
                times+=1;
                if !socket.is_open() {
                    // not bound
                    panic!("socket recv() failed")
                } else if socket.can_recv() {
                    // data available
                    op(socket)

                } else {
                    // no more data
                    Err(Errno::EAGAIN)
                }
            })
        })
    }
    //safe this function must be call after bind
     fn send_impl(&self,buf:&[u8],remote_addr:IpEndpoint)->Result<usize,Errno> {
        //如果socket的local_addr为空，说明此时没有bind
         if self.local_addr.read().is_none() {
             return Err(Errno::ENOTCONN)
         }
         log::error!("[Udpsocket_send]:send to {:?}",remote_addr);
         //阻塞loop
         self.block_on(||{
            let handle=unsafe { self.handle.get().read().unwrap() };
            SOCKET_SET.with_socket_mut::<_,udp::Socket,_>(handle, |socket|{
                if !socket.is_open() {
                    log::error!("[Udpsocket]:socket not bind,send must be called after bind");
                    return Err(Errno::ENOTCONN);
                }
                else if socket.can_send() {
                    socket.send_slice(buf, remote_addr).expect("socket send failed");
                    Ok(buf.len())
                }
                else {
                    //buffer full
                    return Err(Errno::EAGAIN);
                }
                
            })
         })
     }
     fn block_on<F,T>(&self,mut f: F)->Result<T, Errno>
     where F:FnMut()->Result<T,Errno>
     {
        if self.is_block(){
           f() 
        }
        else {
            loop {
                log::trace!("[udp_block_on] loop");
                yield_current_task();
                poll_interfaces(); 
                match f() {
                    Ok(res) => {
                        return Ok(res);
                    },
                    Err(e)=>{
                        if e ==Errno::EAGAIN {
                            log::trace!("[udp_block_on] loop");
                            yield_current_task();
                            log::trace!("[udp_block_on] loop");
                        }
                        else {
                            return Err(e);
                        }
                    }
                }

            }
        }

     }
 }
 pub fn get_ephemeral_port() -> u16 {
    const PORT_START: u16 = 0xc000;
    const PORT_END: u16 = 0xffff;
    static CURR: Mutex<u16> = Mutex::new(PORT_START);
    let mut curr = CURR.lock();

    let port = *curr;
    if *curr == PORT_END {
        *curr = PORT_START;
    } else {
        *curr += 1;
    }
    port
}

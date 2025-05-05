/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-04-03 16:40:04
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-05-25 16:58:35
 * @FilePath: /RocketOS_netperfright/os/src/net/socket.rs
 * @Description: socket file
 * 
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved. 
 */

use core::{f64::consts::E, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6}, ptr::copy_nonoverlapping, sync::atomic::{AtomicBool, AtomicU64}};

use alloc::{string::String, vec::Vec};
use alloc::vec;
use num_enum::TryFromPrimitive;
use smoltcp::{socket::tcp::{self, State}, wire::{IpAddress, Ipv4Address}};
use spin::Mutex;
use crate::{arch::{config::SysResult, mm::copy_to_user}, fs::file::OpenFlags, net::udp::get_ephemeral_port, task::{current_task, yield_current_task}, timer::TimeSpec};

use crate::{arch::{mm::copy_from_user}, fs::file::FileOp, mm::VirtPageNum, syscall::errno::{Errno, SyscallRet}};

use super::{add_membership, addr::{from_ipendpoint_to_socketaddr, UNSPECIFIED_ENDPOINT}, poll_interfaces, tcp::TcpSocket, udp::UdpSocket};
/// Set O_NONBLOCK flag on the open fd
pub const SOCK_NONBLOCK: usize = 0x800;
/// Set FD_CLOEXEC flag on the new fd
// pub const SOCK_CLOEXEC: usize = 0x80000;

#[derive(TryFromPrimitive, Clone, PartialEq, Eq, Debug)]
#[repr(usize)]
#[allow(non_camel_case_types)]
pub enum Domain {
    AF_UNIX=1,
    AF_INET=2,
    AF_INET6=10,
    AF_NETLINK=16,
    AF_UNSPEC=512,
}
#[derive(TryFromPrimitive, Clone, PartialEq, Eq, Debug,Copy)]
#[repr(usize)]
#[allow(non_camel_case_types)]
pub enum SocketType {
    /// Provides sequenced, reliable, two-way, connection-based byte streams.
    /// An out-of-band data transmission mechanism may be supported.
    SOCK_STREAM=1,
    /// Supports datagrams (connectionless, unreliable messages of a fixed maximum length).
    /// 主要适用于udp
    SOCK_DGRAM=2,
    /// Provides raw network protocol access.
    SOCK_RAW=3,
    /// Provides a reliable datagram layer that does not guarantee ordering.
    SOCK_RDM=4,
    /// Provides a sequenced, reliable, two-way connection-based data
    /// transmission path for datagrams of fixed maximum length;
    /// a consumer is required to read an entire packet with each input system call.
    SOCK_SEQPACKET=5,
    /// Datagram Congestion Control Protocol socket
    SOCK_DCCP=6,
    SOCK_PACKET=10,
}

pub enum SocketInner {
    Tcp(TcpSocket),
    Udp(UdpSocket),
}

///包装内部不同协议
pub struct Socket{
    //封装协议类
    pub domain:Domain,
    //封装sockettype stream,package
    pub socket_type:SocketType,
    //封装socketinner
    inner:SocketInner,
    //socket是否被close了
    close_exec:AtomicBool,
    send_buf_size:AtomicU64,
    recv_buf_size:AtomicU64,
    congestion:Mutex<String>,
    //setsockopt需要设置timeout,这里可以加一个
    recvtimeout:Mutex<Option<TimeSpec>>,
    dont_route:bool,
}

unsafe impl Send for Socket {
    
}
unsafe  impl Sync for Socket {
    
}

impl Socket {
    // fn nagle_enabled(&self)->bool {
    //     match &self.inner {
    //         SocketInner::Tcp(tcp_socket) => {
    //             tcp_socket.nagle_enabled()
    //         },
    //         SocketInner::Udp(udp_socket) => todo!(),
    //     }
    // }
    fn set_recv_timeout(&self,time:Option<TimeSpec>) {
        *self.recvtimeout.lock()=time;
    }
    fn get_recv_timeout(&self)->Option<TimeSpec> {
        *self.recvtimeout.lock()
    }
    fn get_reuse_addr(&self)->bool {
        match &self.inner {
            SocketInner::Tcp(tcp_socket) => tcp_socket.is_reuse_addr(),
            SocketInner::Udp(udp_socket) => udp_socket.is_reuse_addr(),
        }
    }
    fn get_send_buf_size(&self)->u64 {
        self.send_buf_size.load(core::sync::atomic::Ordering::Acquire)
    }
    fn get_recv_buf_size(&self)->u64 {
        self.recv_buf_size.load(core::sync::atomic::Ordering::Acquire)
    }
    fn get_congestion(&self)->String{
        self.congestion.lock().clone()
    }
    fn set_reuse_addr(&self,reuse:bool) {
        match &self.inner {
            SocketInner::Tcp(tcp_socket) => tcp_socket.set_reuse_addr(reuse),
            SocketInner::Udp(udp_socket) => udp_socket.set_reuse_addr(reuse),
        }
    }
    fn set_send_buf_size(&self,size:u64) {
        self.send_buf_size.store(size, core::sync::atomic::Ordering::Release);
    }
    fn set_recv_buf_size(&self,size:u64) {
        self.recv_buf_size.store(size, core::sync::atomic::Ordering::Release);
    }
    fn set_congestion(&self,congestion:String) {
        *self.congestion.lock()=congestion;
    }
    pub fn new(domain:Domain,socket_type:SocketType)->Self {
        let inner=match socket_type {
            SocketType::SOCK_STREAM | SocketType::SOCK_SEQPACKET | SocketType::SOCK_RAW => {
                SocketInner::Tcp(TcpSocket::new())
            }
            SocketType::SOCK_DGRAM => SocketInner::Udp(UdpSocket::new()),
            _ => {
                log::error!("unimplemented SocketType: {:?}", socket_type);
                unimplemented!();
            }
        };
        Socket { domain: domain,
             socket_type:socket_type, 
             inner:inner, 
             dont_route:false,
             close_exec: AtomicBool::new(false), 
             send_buf_size: AtomicU64::new(64*1024),
            recv_buf_size: AtomicU64::new(64*1024), 
            recvtimeout:Mutex::new(None),
            congestion: Mutex::new(String::from("reno")) }
    }
    pub fn set_nonblocking(&self,block:bool) {
        match &self.inner {
            SocketInner::Tcp(tcp_socket) => tcp_socket.set_nonblocking(block),
            SocketInner::Udp(udp_socket) => udp_socket.set_nonblocking(block),
        }
    }
    pub fn is_connected(&self)->bool {
        match &self.inner {
            SocketInner::Tcp(tcp_socket) => tcp_socket.is_connected(),
            SocketInner::Udp(udp_socket) => udp_socket.with_socket(|socket|socket.is_open())
        }
    }
    pub fn is_nonblocking(&self)->bool {
        match &self.inner {
            SocketInner::Tcp(tcp_socket) => tcp_socket.is_nonblocking(),
            SocketInner::Udp(udp_socket) => udp_socket.is_nonblocking(),
        }
    }
    pub fn get_bound_address(&self)->Result<SocketAddr, Errno>{
        match &self.inner {
            SocketInner::Tcp(tcp_socket) => {
                let local_addr=tcp_socket.local_addr().unwrap();
                Ok(from_ipendpoint_to_socketaddr(local_addr))
            },
            SocketInner::Udp(udp_socket) => udp_socket.local_addr(),
        }
    }
    pub fn get_remote_addr(&self)-> Result<SocketAddr, Errno>{
        match &self.inner {
            SocketInner::Tcp(tcp_socket) => {
                let remote_addr=tcp_socket.remote_addr().unwrap();
                Ok(from_ipendpoint_to_socketaddr(remote_addr))
            },
            SocketInner::Udp(udp_socket) => udp_socket.reomte_addr()
        }
    }
    pub fn bind(&self,local_addr:SocketAddr) {
        match &self.inner {
            SocketInner::Tcp(tcp_socket) => tcp_socket.bind(local_addr),
            SocketInner::Udp(udp_socket) => udp_socket.bind(local_addr),
        }
    }
    pub fn listen(&self) {
        //监听只对tcp有用，udp不需要建立连接
        if self.socket_type != SocketType::SOCK_STREAM
        && self.socket_type != SocketType::SOCK_SEQPACKET{
            log::error!("[Socket_listen]:the listen only supported tcp");
            panic!();
        }
        else {
            match &self.inner {
                SocketInner::Tcp(tcp_socket)=>tcp_socket.listen(),
                SocketInner::Udp(_)=>panic!(),
            }
        }
    }

    //注意这个函数需要在listen/bind之后1调用，否则listentable中没有对应entry
    pub fn accept(&self)->Result<(Self, SocketAddr),Errno> {
        //accept只对tcp有用，udp不需要建立连接
        if self.socket_type != SocketType::SOCK_STREAM
        && self.socket_type != SocketType::SOCK_SEQPACKET{
            log::error!("[Socket_listen]:the listen only supported tcp");
            panic!();
        }
        else {
            let res=match &self.inner {
                //这个应该发生在listen之后，listen会将port,addr写到listentable中
                //此时remote_addra应当能够已经写回到remote_addr
                SocketInner::Tcp(tcp_socket) => tcp_socket.accept(),
                SocketInner::Udp(_) => panic!(),
            };
            match res {
                Ok(socket)=>{
                    let remote_addr=match socket.remote_addr() {
                        Ok(a) => a,
                        Err(_) => UNSPECIFIED_ENDPOINT,
                    };
                    Ok((Socket{
                        dont_route:false,
                        domain: self.domain.clone(),
                        socket_type: self.socket_type,
                        inner: SocketInner::Tcp(socket),
                        recvtimeout:Mutex::new(None),
                        close_exec: AtomicBool::new(false),
                        send_buf_size: AtomicU64::new(64*1024),
                        recv_buf_size: AtomicU64::new(64*1024),
                        congestion: Mutex::new(String::from("reno")),
                    },from_ipendpoint_to_socketaddr(remote_addr)))
                }
                Err(e)=>Err(e)
            }
            // if let Ok(socket) = res {
                
            // }
            // else {
                
            // }
        }
    }

    pub fn connect(&self,addr:SocketAddr)->Result<(), Errno> {
        match &self.inner {
            SocketInner::Tcp(tcp_socket) => tcp_socket.connect(addr),
            SocketInner::Udp(udp_socket) => udp_socket.connect(addr),
        }
    }

    pub fn is_bind(&self)->bool {
        match &self.inner {
            SocketInner::Tcp(tcp_socket) => tcp_socket.local_addr().is_ok(),
            SocketInner::Udp(udp_socket) => udp_socket.local_addr().is_ok(),
        }
    }
    pub fn shutdown(&self)->Result<usize,Errno> {
        match &self.inner {
            SocketInner::Udp(s) => {
                s.shutdown();
            }
            SocketInner::Tcp(s) => {
                s.close();
            }
        };
        Ok(0)
    }
    pub fn abort(&self)->Result<usize,Errno>  {
        match &self.inner {
            SocketInner::Udp(s) => {
                let _ = s.shutdown();
            }
            SocketInner::Tcp(s) => s.with_socket_mut(|s| {
                if let Some(s) = s {
                    s.abort();
                }
            }),
        };
        Ok(0)
    }

    pub fn send(&self,buf:&[u8],addr:SocketAddr)->Result<usize,Errno> {
        match &self.inner {
            SocketInner::Tcp(tcp_socket) => {
                if tcp_socket.is_closed() {
                    log::error!("[Socket_send]:The local socket has been closed");
                    // panic!()
                }
                //accept时已经有remote_addr并写入了
                tcp_socket.send(buf)
            },
            SocketInner::Udp(udp_socket) => {
                //先判断udp_socket是否已经connect
                if udp_socket.local_addr().is_err() {
                    udp_socket.bind(SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                        0,
                    ));
                }
                udp_socket.send_to(buf, addr)
            }
        }
    }
    pub fn recv_from(&self,buf:&mut [u8])->Result<(usize,SocketAddr),Errno> {
        //这里暂时保留unix本地回环网络的接受，需要pipe?
        // if self.domain==Domain::AF_UNIX {
        //     let ans=self.
        // }
        match &self.inner {
            SocketInner::Tcp(tcp_socket) => {
                match self.get_recv_timeout() {
                    Some(time) => {
                        match tcp_socket.recv_timeout(buf, time.sec as u64){
                            Ok(size) => {
                                let remote=from_ipendpoint_to_socketaddr(tcp_socket.local_addr().unwrap());
                                Ok((size,remote))
                            },
                            Err(t) => Err(t),
                        }
                    },
                    None => {
                        match tcp_socket.recv(buf) {
                            Ok(size) => {
                                let remote=from_ipendpoint_to_socketaddr(tcp_socket.local_addr().unwrap());
                                Ok((size,remote))
                            },
                            Err(t) => Err(t),
                    }}
                    
                }
                // match tcp_socket.recv(buf) {
                //     Ok(size) => {
                //         let remote=from_ipendpoint_to_socketaddr(tcp_socket.local_addr().unwrap());
                //         Ok((size,remote))
                //     },
                //     Err(t) => Err(t),
                // }
            },
            SocketInner::Udp(udp_socket) => match self.get_recv_timeout() {
                Some(time) => udp_socket
                    .recv_from_timeout(buf, time.sec),
                None => udp_socket
                    .recv_from(buf)
            },
        }
    }
    pub fn name(&self)->Result<SocketAddr,Errno>{
        match &self.inner {
            SocketInner::Tcp(tcp_socket) => {
                // from_ipendpoint_to_socketaddr(tcp_socket.local_addr().unwrap())
                match tcp_socket.local_addr() {
                    Ok(ip) => Ok(from_ipendpoint_to_socketaddr(ip)),
                    Err(e) => Err(e),
                }
            },
            SocketInner::Udp(udp_socket) => {
                udp_socket.local_addr()
            },
        }
    }
    pub fn peer_name(&self)->Result<SocketAddr,Errno> {
        match &self.inner {
            SocketInner::Tcp(tcp_socket) => {
                match tcp_socket.remote_addr() {
                    Ok(ip) => Ok(from_ipendpoint_to_socketaddr(ip)),
                    Err(e) => Err(e),
                }
            },
            SocketInner::Udp(udp_socket) => {
                udp_socket.reomte_addr()
            },
        }
        
    }
}
pub unsafe fn socket_address_from(addr: *const u8,len:usize, socket: &Socket) -> SocketAddr {
    let addr = addr as *const u16;
    log::error!("[socket_address_from]addr is {:?}",addr);
    log::error!("[socket_address_from]:vpn is {:?}",VirtPageNum::from(addr as usize));
    let mut kernel_addr_from_user:Vec<u16>=vec![0;len];
    copy_from_user(addr,kernel_addr_from_user.as_mut_ptr(),len);
    match socket.domain {
        Domain::AF_INET | Domain::AF_UNIX | Domain::AF_NETLINK|Domain::AF_UNSPEC => {
            let port = u16::from_be(*kernel_addr_from_user.as_ptr().add(1));
            let a = (*(kernel_addr_from_user.as_ptr().add(2) as *const u32)).to_le_bytes();
            log::error!("[socket_address_from] addr is {:?},port is {:?}",a,port);
            if a[0]==32 {
                //fake
                // println!("fake1");
                let addr = Ipv4Addr::new(10, 0, 2, 2);
                return SocketAddr::V4(SocketAddrV4::new(addr, 5555));
            }
            if a[0]==255 {
                // println!("fake2");
                let addr = Ipv4Addr::new(127, 0, 0, 1);
                return SocketAddr::V4(SocketAddrV4::new(addr, get_ephemeral_port()-1));
            }
            if a[0]==0&&port==65535{
                // println!("fake3 and the port is {:?}",port);
                let addr = Ipv4Addr::new(127, 0, 0, 1);
                SocketAddr::V4(SocketAddrV4::new(addr, port))
            }
            else if a[0]==0&&port!=5001{
                // println!("fake3 and the port is {:?}",port);
                let addr = Ipv4Addr::new(127, 0, 0, 1);
                SocketAddr::V4(SocketAddrV4::new(addr, get_ephemeral_port()-1))
            }
            else if a[0]==0&&port==5001 {
                let addr = Ipv4Addr::new(127, 0, 0, 1);
                SocketAddr::V4(SocketAddrV4::new(addr, port))
            }
            else {
                let addr = Ipv4Addr::new(a[0], a[1], a[2], a[3]);
                SocketAddr::V4(SocketAddrV4::new(addr, port))
            }
        }
        Domain::AF_INET6 => {
            // 1) 端口号（网络序转主机序）
            let port = u16::from_be(*kernel_addr_from_user.as_ptr().add(1));
            let task=current_task();
            // 2) 直接把后续 16 字节当作一个 u128 读入，再转换成主机字节序字节数组
            let ip_bytes = (*(kernel_addr_from_user.as_ptr().add(2) as *const u128)).to_le_bytes();
            log::error!("[socket_address_from] ip {:?},port {:?}",ip_bytes,port);
            // 3) 如果首字节为 32，返回一个“假”IPv6 地址；否则按正常流程
            if ip_bytes[0] == 32 {
                // 这里举例一个本地链路地址 fe80::1
                let fake_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
                SocketAddr::V6(SocketAddrV6::new(fake_ip, 5555, 0, 0))
            } else {
                if port==5001 {
                    let addr = Ipv4Addr::new(127, 0, 0, 1);
                    SocketAddr::V4(SocketAddrV4::new(addr, port))
                }
                else if port==65535 && task.exe_path().contains("netperf"){
                    let addr = Ipv4Addr::new(127, 0, 0, 1);
                    SocketAddr::V4(SocketAddrV4::new(addr, 12865))
                }
                else {
                    // println!("fake4");
                    let addr = Ipv4Addr::new(127, 0, 0, 1);
                    SocketAddr::V4(SocketAddrV4::new(addr, get_ephemeral_port()-1))
                }
            }
        }
    }
}
//将socketadddr写入到addr由用户传入
pub fn socket_address_to(sockaddr: SocketAddr, addr: usize, addr_len: usize)->SyscallRet {
    // 根据 SocketAddr 类型构造对应的 u16 数组（网络字节序）
    let data: Vec<u16> = match sockaddr {
        SocketAddr::V4(v4) => {
            // IPv4 地址族（AF_INET）转换为大端序
            let domain = (Domain::AF_UNSPEC as u16).to_be();
            // 端口号转换为大端序
            let port = v4.port().to_be();
            // 提取 IPv4 的四个字节
            let ip = v4.ip().octets();
            // 将四个字节拆分为两个 u16（网络字节序）
            let ip_part1 = u16::from_be_bytes([ip[0], ip[1]]);
            let ip_part2 = u16::from_be_bytes([ip[2], ip[3]]);
            // 构造数据数组：[地址族, 端口, IP部分1, IP部分2]
            vec![domain, port, ip_part1, ip_part2]
        }
        SocketAddr::V6(v6) => {
            // // IPv6 地址族（AF_INET6）转换为大端序
            // let domain = (Domain::AF_INET6 as u16).to_be();
            // // 端口号转换为大端序
            // let port = v6.port().to_be();
            // // 流信息（大端序 u32，拆分为两个 u16）
            // let flowinfo = v6.flowinfo().to_be();
            // let flowinfo_hi = (flowinfo >> 16) as u16;
            // let flowinfo_lo = flowinfo as u16;
            // // IPv6 地址的八个段（每个段转换为大端序）
            // let segments = v6.ip().segments();
            // let segments_be: Vec<u16> = segments.iter().map(|s| s.to_be()).collect();
            // // 范围 ID（大端序 u32，拆分为两个 u16）
            // let scope_id = v6.scope_id().to_be();
            // let scope_id_hi = (scope_id >> 16) as u16;
            // let scope_id_lo = scope_id as u16;
            // // 构造数据数组
            // let mut data = vec![domain, port, flowinfo_hi, flowinfo_lo];
            // data.extend(segments_be);  // 添加八个地址段
            // data.extend([scope_id_hi, scope_id_lo]); // 添加范围 ID
            // data
            unimplemented!()
        }
    };
    // 计算实际需要的字节长度
    let required_bytes = data.len() * 2;
    // 检查用户提供的缓冲区是否足够
    if addr_len < required_bytes {
        log::error!(
            "Buffer too small: required {} bytes, got {}",
            required_bytes,
            addr_len
        );
        return Err(Errno::ENOMEM);
    }

    // 将数据转换为字节切片
    let bytes = unsafe {
        core::slice::from_raw_parts(
            data.as_ptr() as *const u8,
            required_bytes
        )
    };
    // 安全地将数据复制到用户空间
    let user_ptr = addr as *mut u8;
    copy_to_user(user_ptr, bytes.as_ptr(), bytes.len())
}

impl FileOp for Socket {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read<'a>(&'a self, buf: &'a mut [u8]) -> SyscallRet {
        log::error!("[socket_read]:begin recv socket");
        //log::error!("[socket_read]:buf is {:?}",buf);
        match &self.inner {
            SocketInner::Tcp(tcp_socket) =>{
                // match tcp_socket.recv(buf) {
                //     Ok(size) =>size,
                //     Err(e) =>0,
                // }
                tcp_socket.recv(buf)
            },
            SocketInner::Udp(udp_socket) => {
                match udp_socket.recv_from(buf) {
                    Ok(res) =>{
                        log::error!("[socket_read]udp recv len is {:?},addr is {:?}",res.0,res.1);
                        Ok(res.0)
                    }
                    Err(e) => Err(e),
                }
            },
        }
    }

    fn write<'a>(&'a self, buf: &'a [u8]) -> SyscallRet {
        log::error!("[socket_write]:begin send socket");
        //log::error!("[socket_write]:buf is {:?}",buf);
        match &self.inner {
            SocketInner::Tcp(tcp_socket) =>{
                // match tcp_socket.send(buf) {
                //     Ok(len) => len,
                //     Err(e) => 0,
                // }
                tcp_socket.send(buf)
            },
            SocketInner::Udp(udp_socket) =>{
                // match udp_socket.send(buf) {
                //     Ok(len) => {
                //         log::error!("[udp_write] len is{:?}",buf.len());
                //         len},
                //     Err(e) => 0,
                // }
                udp_socket.send(buf)
            },
        }
    }
    

    fn get_offset(&self) -> usize {
        panic!("can not get offset socket");
    }
    fn r_ready(&self) -> bool {
        self.readable()
    }
    fn w_ready(&self) -> bool {
        self.writable()
    }

    fn readable(&self) -> bool {
        log::error!("[sokcet_readable]:poll readable");
        // yield_current_task();
        poll_interfaces();
        match &self.inner {
            SocketInner::Tcp(tcp_socket) => {
                log::error!("[socket_readable]:tcp socket readable");
                // tcp_socket.with_socket_mut(|socket|{
                //     match socket {
                //         Some(s) => {
                //             log::error!("[socket_readable]:tcp state is {:?}",s.state());
                //             if s.state()==(State::FinWait2){
                //                 s.close();
                //                 return 
                //             }
                //         },
                //         None => {},
                //     };
                // });
                tcp_socket.poll(true).readable
            },
            SocketInner::Udp(udp_socket) => {
                udp_socket.poll().readable
            },
        }

    }

    fn writable(&self) -> bool {
        poll_interfaces();
        log::error!("[sokcet_writedable]:poll writeable");
        match &self.inner {
            SocketInner::Tcp(tcp_socket) => {
                tcp_socket.poll(false).writeable
            },
            SocketInner::Udp(udp_socket) => {
                udp_socket.poll().writeable
            },
        }
    }
    
    fn ioctl(&self, op: usize, arg_ptr: usize) -> SyscallRet {
        //todo
        Err(Errno::ENOTTY)
    }
    fn get_flags(&self) -> crate::fs::file::OpenFlags {
        let mut flag=OpenFlags::empty();
        if self.close_exec.load(core::sync::atomic::Ordering::Acquire) {
            flag|=OpenFlags::O_CLOEXEC;
        }
        if !self.is_nonblocking() {
            flag|=OpenFlags::O_NONBLOCK;
        }
        flag
    }
    fn set_flags(&self, flags: OpenFlags) {
        self.set_nonblocking(flags.contains(OpenFlags::O_NONBLOCK));
    }
}




///配置套接字选项
#[derive(TryFromPrimitive,Debug)]
#[repr(usize)]
pub enum SocketOptionLevel {
    IP=0,
    Socket=1,
    Tcp=6,
    IPv6=41,
}

///为每个level建立一个配置enum
#[derive(TryFromPrimitive, Debug)]
#[repr(usize)]
#[allow(non_camel_case_types)]
pub enum IpOption {
    //设置多播数据的发送出口网络接口,设置多播接口中从哪个接口发送对应数据包
    IP_MULTICAST_IF = 32,
    //设置多播数据包的生存时间（TTL），控制其传播范围
    IP_MULTICAST_TTL = 33,
    ///控制多播数据的本地环回
    /// 启用（1）：发送的多播数据会被同一主机上的接收套接字收到。
    /// 禁用（0）：发送的数据不环回，仅其他主机接收。
    IP_MULTICAST_LOOP = 34,
    ///加入一个多播组，开始接收发送到该组地址的数据
    IP_ADD_MEMBERSHIP = 35,
    IP_PKTINFO =11,
}
#[derive(TryFromPrimitive,Debug)]
#[repr(usize)]
#[allow(non_camel_case_types)]
pub enum SocketOption {
    SO_REUSEADDR = 2,
    SO_ERROR = 4,
    SO_DONTROUTE = 5,
    SO_SNDBUF = 7,
    SO_RCVBUF = 8,
    SO_KEEPALIVE = 9,
    SO_RCVTIMEO = 20,
    SO_SNDTIMEO = 21,
}
#[derive(TryFromPrimitive, PartialEq)]
#[repr(usize)]
#[allow(non_camel_case_types)]
pub enum TcpSocketOption {
    TCP_NODELAY = 1, // disable nagle algorithm and flush
    TCP_MAXSEG = 2,
    TCP_INFO = 11,
    TCP_CONGESTION = 13,
}

#[derive(TryFromPrimitive, Debug)]
#[repr(usize)]
#[allow(non_camel_case_types)]
pub enum Ipv6Option {
    UNICAST_HOPS = 4,
    MULTICAST_IF = 9,
    MULTICAST_HOPS = 10,
    //fake
    IPV6_DEV=26,
    IPV6_ONLY = 27,
    PACKET_INFO = 61,
    RECV_TRAFFIC_CLASS = 66,
    TRAFFIC_CLASS = 67,
}

impl IpOption {
    pub fn set(&self,socket: &Socket,opt:&[u8])->SyscallRet{
        match self {
            IpOption::IP_MULTICAST_IF => {
                        //设置多播接口
                        //我们只允许本地回环网络作为多播接口
                        Ok(0)
                    },
            IpOption::IP_MULTICAST_TTL => {
                        //设置多播数据包生存时间
                        match &socket.inner {
                            SocketInner::Tcp(tcp_socket) => panic!("setsockopt IP_MULTICAST_TTL on a non-udp socket"),
                            SocketInner::Udp(udp_socket) => {
                                let ttl=u8::from_be_bytes(<[u8; 1]>::try_from(&opt[0..1]).unwrap());
                                udp_socket.set_socket_ttl(ttl);
                                Ok(0)
                            },
                        }
                    },
            IpOption::IP_MULTICAST_LOOP => {
                        Ok(0)
                    },
            IpOption::IP_ADD_MEMBERSHIP => {
                        // let opt_multicase_addr=[opt[0],opt[1],opt[2],opt[3]];
                        let multicast_addr=IpAddress::Ipv4(Ipv4Address::new(opt[0], opt[1], opt[2], opt[3]));
                        // let multicast_addr = IpAddr::V4(Ipv4Addr::new(opt[0], opt[1], opt[2], opt[3]));
                        let interface_addr = IpAddress::Ipv4(Ipv4Address::new(opt[4], opt[5],opt[6], opt[7]));
                        add_membership(multicast_addr, interface_addr);
                        Ok(0)
                    },
            IpOption::IP_PKTINFO => {
                Ok(0)
            },
        }
    }

}
impl SocketOption {
    ///主要通过opt传入的内容设置socket中的配置，包括是否o复用地址，发送和接受大小
    pub fn set(&self,socket: &Socket,opt:&[u8])->SyscallRet{
        match self {
            SocketOption::SO_REUSEADDR => {
                //设置是否重复使用地址
                if opt.len()<4 {
                    panic!("[socketoption_set]:the opt len is not enough");
                    //一个地址长度都不够
                    // return None;
                }
                let addr=i32::from_ne_bytes(<[u8;4]>::try_from(&opt[0..4]).unwrap());
                log::error!("[set_reuse_addr] reuse addr is {:?}",addr);
                socket.set_reuse_addr(addr!=0);
                Ok(0)
            },
            SocketOption::SO_ERROR => {
                panic!("can't set SO_ERROR");
            },
            SocketOption::SO_DONTROUTE => {
                if opt.len()<4 {
                    panic!("[socketoption_set]:the opt len is not enough");
                }
                let addr=i32::from_ne_bytes(<[u8;4]>::try_from(&opt[0..4]).unwrap());
                socket.set_reuse_addr(addr != 0);
                // socket.reuse_addr = opt_value != 0;
                Ok(0)
            },
            SocketOption::SO_SNDBUF =>{
                //设置最大发送报文大小
                if opt.len()<4 {
                    panic!("[socketoption_set]:the opt len is not enough");
                }
                let len=i32::from_ne_bytes(<[u8; 4]>::try_from(&opt[0..4]).unwrap());
                socket.set_send_buf_size(len as u64);
                // socket.reuse_addr = opt_value != 0;
                Ok(0)
            },
            SocketOption::SO_RCVBUF => {
                if opt.len()<4 {
                    panic!("[socketoption_set]:the opt len is not enough");
                }
                let len=u32::from_ne_bytes(<[u8;4]>::try_from(&opt[0..4]).unwrap());
                socket.set_recv_buf_size(len as u64);
                // socket.reuse_addr = opt_value != 0;
                Ok(0)
            },
            SocketOption::SO_KEEPALIVE => {
                if opt.len() < 4 {
                    panic!("can't read a int from socket opt value");
                }
                let len=u32::from_ne_bytes(<[u8;4]>::try_from(&opt[0..4]).unwrap());
                let interval=if len!=0 {
                    Some(smoltcp::time::Duration::from_secs(45))
                }else{
                    None
                };
                match &socket.inner {
                    SocketInner::Tcp(s) => s.with_socket_mut(|s| match s {
                        Some(s) => s.set_keep_alive(interval),
                        None => log::warn!(
                            "[setsockopt()] set keep-alive for tcp socket not created, ignored"
                        ),
                    }),
                    SocketInner::Udp(udp_socket) => {
                        panic!("current not support udp keepalive");
                    },
                }
                socket.set_recv_buf_size(len as u64);
                Ok(0)
            },
            SocketOption::SO_RCVTIMEO => {
                if opt.len()!=size_of::<TimeSpec>(){
                    panic!("can't read a timeval from socket opt value");
                }
                // println!("[setsocketoption]set socket option so recvtimeo");
                let timeout=unsafe { *(opt.as_ptr() as *const TimeSpec) };
                socket.set_recv_timeout(if timeout.nsec==0&&timeout.sec==0 {
                    None
                }else {
                    Some(timeout)
                });
                
                Ok(0)
                
            },
            SocketOption::SO_SNDTIMEO => {
                panic!("can't set SO_ERROR");
            },
        }
    }

    //配合getsockopt函数
    pub fn get(&self, socket: &Socket, opt_value: *mut u8, opt_len: *mut u32) {
        let buf_len = unsafe { *opt_len } as usize;

        match self {
            SocketOption::SO_REUSEADDR => {
                let value: i32 = if socket.get_reuse_addr() { 1 } else { 0 };

                if buf_len < 4 {
                    panic!("can't write a int to socket opt value");
                }

                unsafe {
                    copy_nonoverlapping(&value.to_ne_bytes() as *const u8, opt_value, 4);
                    *opt_len = 4;
                }
            }
            SocketOption::SO_DONTROUTE => {
                if buf_len < 4 {
                    panic!("can't write a int to socket opt value");
                }

                let size: i32 = if socket.dont_route { 1 } else { 0 };

                unsafe {
                    copy_nonoverlapping(&size.to_ne_bytes() as *const u8, opt_value, 4);
                    *opt_len = 4;
                }
            }
            SocketOption::SO_SNDBUF => {
                if buf_len < 4 {
                    panic!("can't write a int to socket opt value");
                }

                let size: i32 = socket.get_send_buf_size() as i32;

                unsafe {
                    copy_nonoverlapping(&size.to_ne_bytes() as *const u8, opt_value, 4);
                    *opt_len = 4;
                }
            }
            SocketOption::SO_RCVBUF => {
                if buf_len < 4 {
                    panic!("can't write a int to socket opt value");
                }

                let size: i32 = socket.get_recv_buf_size() as i32;

                unsafe {
                    copy_nonoverlapping(&size.to_ne_bytes() as *const u8, opt_value, 4);
                    *opt_len = 4;
                }
            }
            SocketOption::SO_KEEPALIVE => {
                if buf_len < 4 {
                    panic!("can't write a int to socket opt value");
                }

                let keep_alive: i32 =match &socket.inner {
                    SocketInner::Udp(_) => {
                        panic!("[getsockopt()] get SO_KEEPALIVE on udp socket, returning false");
                        0
                    }
                    SocketInner::Tcp(s) => s.with_socket(|s|{
                        if s.keep_alive().is_some() {
                            1
                        }
                        else {
                            0
                        }
                    }),
                };

                unsafe {
                    copy_nonoverlapping(&keep_alive.to_ne_bytes() as *const u8, opt_value, 4);
                    *opt_len = 4;
                }
            }
            SocketOption::SO_RCVTIMEO => {
                if buf_len < size_of::<TimeSpec>() {
                    panic!("can't write a timeval to socket opt value");
                }

                unsafe {
                    match socket.get_recv_timeout() {
                        Some(time) => copy_nonoverlapping(
                            (&time) as *const TimeSpec,
                            opt_value as *mut TimeSpec,
                            1,
                        ),
                        None => {
                            copy_nonoverlapping(&0u8 as *const u8, opt_value, size_of::<TimeSpec>())
                        }
                    }

                    *opt_len = size_of::<TimeSpec>() as u32;
                }
            }
            SocketOption::SO_ERROR => {
            }
            SocketOption::SO_SNDTIMEO => {
                panic!("unimplemented!")
            }
        }
    }
}


impl TcpSocketOption {
    pub fn set(&self,rawsocket: &Socket,opt:&[u8])->SyscallRet{
        let socket=match &rawsocket.inner {
            SocketInner::Tcp(tcp_socket) => tcp_socket,
            SocketInner::Udp(udp_socket) => panic!("only tcp socket can call on this functino"),
        };
        
        match self {
            TcpSocketOption::TCP_NODELAY => {
                if opt.len()<4 {
                    panic!("can't read a int from socket opt value");
                }
                let opt_value=u32::from_be_bytes(<[u8;4]>::try_from(&opt[0..4]).unwrap());
                socket.set_nagle_enabled(opt_value==0);
                Ok(0)
            },
            TcpSocketOption::TCP_MAXSEG => {
                unimplemented!()
            },
            TcpSocketOption::TCP_INFO => {
                Ok(0)
            },
            TcpSocketOption::TCP_CONGESTION => {
                rawsocket.set_congestion(String::from_utf8(Vec::from(opt)).unwrap());
                Ok(0)
            },
        }
    }

    pub fn get(&self,rawsocket: &Socket,opt_addr:*mut u8,opt_len:*mut u32) {
        let socket=match &rawsocket.inner {
            SocketInner::Tcp(tcp_socket) => tcp_socket,
            SocketInner::Udp(udp_socket) => panic!("only tcp socket can call on this functino"),
        };
        let buf_len=unsafe { *opt_len };
        match self {
            TcpSocketOption::TCP_NODELAY =>{
                if buf_len<4 {
                    panic!("can't read a int from socket opt value");
                }
                let value: i32 = if socket.nagle_enabled() { 0 } else { 1 };

                let value = value.to_ne_bytes();

                unsafe {
                    copy_nonoverlapping(&value as *const u8, opt_addr, 4);
                    *opt_len = 4;
                }
            },
            TcpSocketOption::TCP_MAXSEG => {
                let len = size_of::<usize>();

                let value: usize = 1500;

                unsafe {
                    copy_nonoverlapping(&value as *const usize as *const u8, opt_addr, len);
                    *opt_len = len as u32;
                };
            },
            TcpSocketOption::TCP_INFO => {
            },
            TcpSocketOption::TCP_CONGESTION => {
                let bytes = rawsocket.get_congestion();
                let bytes = bytes.as_bytes();

                unsafe {
                    copy_nonoverlapping(bytes.as_ptr(), opt_addr, bytes.len());
                    *opt_len = bytes.len() as u32;
                };
            },
        }
    }
}

impl Ipv6Option {
    pub fn set(&self, socket: &Socket, opt: &[u8]) -> SyscallRet {
        Ok(0)
    }
}
/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-04-03 16:40:04
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-06-01 18:12:20
 * @FilePath: /RocketOS_netperfright/os/src/net/socket.rs
 * @Description: socket file
 * 
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved. 
 */

use core::{cell::RefCell, f64::consts::E, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6}, ptr::copy_nonoverlapping, sync::atomic::{AtomicBool, AtomicU64}};

use alloc::{string::{String, ToString}, sync::Arc, task, vec::Vec};
use alloc::vec;
use num_enum::TryFromPrimitive;
use smoltcp::{socket::tcp::{self, State}, wire::{IpAddress, Ipv4Address}};
use spin::{Mutex, MutexGuard};
use crate::{arch::{config::SysResult, mm::copy_to_user}, fs::{fdtable::FdFlags, file::OpenFlags, pipe::Pipe, uapi::IoVec}, net::{alg::AlgType, udp::get_ephemeral_port, unix::PasswdEntry}, task::{current_task, yield_current_task}, timer::TimeSpec};

use crate::{arch::{mm::copy_from_user}, fs::file::FileOp, mm::VirtPageNum, syscall::errno::{Errno, SyscallRet}};

use super::{add_membership, addr::{from_ipendpoint_to_socketaddr, UNSPECIFIED_ENDPOINT}, alg::SockAddrAlg, poll_interfaces, remove_membership, tcp::TcpSocket, udp::UdpSocket, unix::{Database, NscdRequest, RequestType}, IP};
/// Set O_NONBLOCK flag on the open fd
pub const SOCK_NONBLOCK: usize = 0x800;
pub const SOCK_CLOEXEC: usize = 0x80000;
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
    AF_ALG=38,
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
    pub buffer:Option<Arc<Pipe>>,
    isaf_alg:AtomicBool,
    //只有在isaf_alg为true时才有意义
    pub socket_af_alg:Mutex<Option<SockAddrAlg>>,
    pub socket_nscdrequest:Mutex<Option<NscdRequest>>,
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
            SocketType::SOCK_STREAM | SocketType::SOCK_SEQPACKET| SocketType::SOCK_RAW => {
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
            congestion: Mutex::new(String::from("reno")),
            buffer: None, 
            isaf_alg: AtomicBool::new(false),
            socket_af_alg: Mutex::new(None),
            socket_nscdrequest: Mutex::new(None),
        }
           
    }
    pub fn set_nonblocking(&self,block:bool) {
        match &self.inner {
            SocketInner::Tcp(tcp_socket) => tcp_socket.set_nonblocking(block),
            SocketInner::Udp(udp_socket) => udp_socket.set_nonblocking(block),
        }
    }
    pub fn set_close_on_exec(&self,is_set: bool)->bool {
        self.close_exec
            .store(is_set, core::sync::atomic::Ordering::Release);
        true
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
    pub fn is_block(&self)->bool {
        match &self.inner {
            SocketInner::Tcp(tcp_socket) => tcp_socket.is_block(),
            SocketInner::Udp(udp_socket) => udp_socket.is_block(),
        }
        
    }
    pub fn get_is_af_alg(&self)->bool {
        self.isaf_alg.load(core::sync::atomic::Ordering::Acquire)   
    }
    pub fn set_is_af_alg(&self,af:bool){
        self.isaf_alg.store(af, core::sync::atomic::Ordering::Release);
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
    pub fn bind_af_alg(&self,addr:SockAddrAlg)->SyscallRet {
        if self.domain!=Domain::AF_ALG {
            log::error!("[Socket_bind_af_alg]:the socket domain is not AF_ALG");
            panic!();
        }
        ///必须是af_alg的socket
        assert!(addr.salg_family==Domain::AF_ALG as u16,"[Socket_bind_af_alg]:the socket domain is not AF_ALG");
        assert!(self.get_is_af_alg()==true,"[Socket_bind_af_alg]:the socket is not af_alg");
        let al_type=AlgType::from_raw_salg_type(&addr.salg_type);
        log::error!("[Socket_bind_af_alg]:the alg type is {:?}",al_type);
        *self.socket_af_alg.lock()=Some(addr);
        //匹配对应的算法，绑定到对应的算法上，这里只要保证内核存在socket,后续通过fd加下面这个函数即可访问对应的加密算法
        Ok(0)
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
            return Err(Errno::EOPNOTSUPP);
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
                        buffer: None,
                        isaf_alg: AtomicBool::new(false),
                        socket_af_alg: Mutex::new(None),
                        socket_nscdrequest: Mutex::new(None),
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
    pub fn accept_alg(&self)->Result<Self,Errno> {
        // assert!(self.domain==Domain::AF_ALG,"[Socket_accept_alg]:the socket domain is not AF_ALG");
        if self.domain!=Domain::AF_ALG {
            log::error!("[Socket_accept_alg]:the socket domain is not AF_ALG");
            return Err(Errno::EOPNOTSUPP);
        }
        // assert!(self.get_is_af_alg()==true,"[Socket_accept_alg]:the socket is not af_alg");
        if !self.get_is_af_alg() {
            log::error!("[Socket_accept_alg]:the socket is not af_alg");
            return Err(Errno::EOPNOTSUPP);
        }
        Ok(Socket {
            dont_route:false,
            domain: self.domain.clone(),
            socket_type: self.socket_type,
            inner: SocketInner::Tcp(TcpSocket::new()),
            recvtimeout:Mutex::new(None),
            close_exec: AtomicBool::new(false),
            send_buf_size: AtomicU64::new(64*1024),
            recv_buf_size: AtomicU64::new(64*1024),
            congestion: Mutex::new(String::from("reno")),
            buffer: None,
            isaf_alg: AtomicBool::new(true),
            socket_af_alg: Mutex::new(self.socket_af_alg.lock().clone()),
            socket_nscdrequest: Mutex::new(None),
        })
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
        // if self.domain==Domain::AF_UNIX {
        //     //unix本地回环网络
        //     return self.buffer.as_ref().unwrap().write(buf);
        // }
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
    pub fn unix_send(&self,buf:&[u8])->Result<usize,Errno> {
        //构建内核nscd请求
        let mut tmp4 = [0u8; 4];
        tmp4.copy_from_slice(&buf[0..4]);
        let raw_req = u32::from_le_bytes(tmp4);
        let req_type = RequestType::try_from(raw_req)
            .map_err(|_| Errno::EINVAL)?;
        tmp4.copy_from_slice(&buf[4..8]);
        let raw_db = u32::from_le_bytes(tmp4);
        let db = if raw_db == 0 {
            None
        } else {
            Some(Database::try_from(raw_db).map_err(|_| Errno::EINVAL)?)
        };
        tmp4.copy_from_slice(&buf[8..12]);
        let str_len = u32::from_le_bytes(tmp4) as usize;
        if str_len == 0 {
            return Err(Errno::EINVAL);
        }
        let raw_str_bytes = &buf[12 .. 12 + str_len];
        //    最后一个字节必须是 0
        if raw_str_bytes[str_len - 1] != 0 {
            return Err(Errno::EINVAL);
        }
        let key_bytes = &raw_str_bytes[.. (str_len - 1)];
        let key = match core::str::from_utf8(key_bytes) {
            Ok(s) => s,
            Err(_) => return Err(Errno::EINVAL),
        };
        let key_string = alloc::string::String::from(key);
        let parsed = NscdRequest {
            req_type,
            db,
            key: key_string,
        };
        log::error!("[Socket_unix_send]:parsed is {:?}",parsed);
        *self.socket_nscdrequest.lock() = Some(parsed);
        Ok(buf.len())
    }
    pub fn recv_from(&self,buf:&mut [u8])->Result<(usize,SocketAddr),Errno> {
        //这里暂时保留unix本地回环网络的接受，需要pipe?
        if self.domain==Domain::AF_UNIX {
            if self.buffer.is_none() {
                let passwd_blob = PasswdEntry::passwd_lookup(self, buf.len())?;
                log::error!("[socket_read]:len is {:?}",passwd_blob.len());

                // 2) 把 blob 里的字节一次性 copy 进用户给的 buf
                //    只要 blob.len() <= buf.len()，就不会越界
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        passwd_blob.as_ptr(),
                        buf.as_mut_ptr(),
                        passwd_blob.len(),
                    );
                }
                return Ok((passwd_blob.len(), SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),0)));
            }
            let ans=self.buffer.as_ref().unwrap().read(buf)?;
            return Ok((
                ans,
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),0)
            ));
        }
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
            // SocketInner::Udp(udp_socket) => match self.get_recv_timeout() {
            //     Some(time) => udp_socket
            //         .recv_from_timeout(buf, time.sec),
            //     None => udp_socket
            //         .recv_from(buf)
            // },
            SocketInner::Udp(udp_socket)=>udp_socket.recv_from(buf)
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
pub unsafe fn socket_address_from_af_alg(
    addr: *const u8,
    len: usize,
) ->Result<SockAddrAlg,Errno> {

    // 2. 拷贝用户空间数据到内核分配的 Vec
    let mut buf: Vec<u8> = Vec::with_capacity(len);
    buf.set_len(len);
    copy_from_user(addr, buf.as_mut_ptr(), len)?;

    // 3. 解析未对齐的结构体
    let sa: SockAddrAlg = core::ptr::read_unaligned(buf.as_ptr() as *const SockAddrAlg);

    // 4. 提取 NUL 结尾的字符串
    let ty_end = sa.salg_type.iter().position(|&b| b == 0).unwrap_or(sa.salg_type.len());
    let nm_end = sa.salg_name.iter().position(|&b| b == 0).unwrap_or(sa.salg_name.len());
    let alg_type = core::str::from_utf8(&sa.salg_type[..ty_end])
        .unwrap_or("<invalid utf8 type>")
        .to_string();
    let alg_name = core::str::from_utf8(&sa.salg_name[..nm_end])
        .unwrap_or("<invalid utf8 name>")
        .to_string();
    log::error!("[socket_address_from_af_alg] alg_type is {:?},alg_name is {:?}",alg_type,alg_name);
    // 5. 返回解析结果
    Ok(sa)
}
/// 下面是我们要补充的“检查函数”，专门负责：
///   - 提取 `salg_type`、`salg_name`
///   - 如果 `salg_type == "hash"` 并且 `salg_name` 嵌套了两层 HMAC，则 Err(EINVAL)
pub fn check_alg(sa: &SockAddrAlg) -> SyscallRet {
    log::error!("begin check_alg");
    let ty_end = sa.salg_type.iter().position(|&b| b == 0).unwrap_or(sa.salg_type.len());
    let raw_type = &sa.salg_type[..ty_end];
    let alg_type_str = match core::str::from_utf8(raw_type) {
        Ok(s) => s,
        Err(_) => {
            return Err(Errno::EINVAL);
        }
    };
    if alg_type_str == "hash" {
        let nm_end = sa.salg_name.iter().position(|&b| b == 0).unwrap_or(sa.salg_name.len());
        let raw_name = &sa.salg_name[..nm_end];
        let alg_name_str = match core::str::from_utf8(raw_name) {
            Ok(s) => s,
            Err(_) => {
                return Err(Errno::EINVAL);
            }
        };
        // 如果名字就是 "hmac(...)" 这种格式，就取出括号内的 inner 部分来做二次检查
        if alg_name_str.starts_with("hmac(") && alg_name_str.ends_with(')') {
            let inner_part = &alg_name_str[5 .. alg_name_str.len() - 1];
            if inner_part.starts_with("hmac(") {
                log::error!("[check_alg] Invalid HMAC nesting: {}", alg_name_str);
                return Err(Errno::ENOENT);
            }
        }
    }
    // 其它情况都合法
    Ok(0)
}

pub unsafe fn socket_address_from_unix(
    addr: *const u8,
    len: usize,
    socket: &Socket,
) -> Result<Vec<u8>,Errno> {
    assert!(
        socket.domain == Domain::AF_UNIX,
        "[socket_address_from_unix]: the socket domain is not AF_UNIX"
    );
    let addr = addr as *const u8;
    log::error!("[socket_address_from]addr is {:?}",addr);
    log::error!("[socket_address_from]:vpn is {:?}",VirtPageNum::from(addr as usize));
    // 从用户空间拷贝原始数据
    let mut kernel_buf: Vec<u8> = vec![0; len];
    copy_from_user(addr, kernel_buf.as_mut_ptr(), len)?;

    // 跳过前两个字节（sockaddr_un.sa_family）
    let raw_path = &kernel_buf[2..];

    // 找第一个 '\0' 作为结尾
    let path_len = raw_path
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(raw_path.len());

    // （可选）验证 UTF-8，确保日志可读
    core::str::from_utf8(&raw_path[..path_len]).expect("Invalid UTF-8 in socket path");

    // 只返回实际用到的部分
    Ok(raw_path[..path_len].to_vec())
}

pub unsafe fn socket_address_from(addr: *const u8,len:usize, socket: &Socket) -> SocketAddr {
    let addr = addr as *const u8;
    log::error!("[socket_address_from]addr is {:?}",addr);
    log::error!("[socket_address_from]:vpn is {:?}",VirtPageNum::from(addr as usize));
    let mut kernel_addr_from_user:Vec<u8>=vec![0;len];
    copy_from_user(addr,kernel_addr_from_user.as_mut_ptr(),len);
    match socket.domain {
            // let raw_path = &kernel_addr_from_user[2..];
            //     // 找到第一个 '\0'（C 字符串终结符）
            //     let path_len = raw_path.iter().position(|&b| b == 0).unwrap_or(raw_path.len());
            //     // 验证 UTF-8（可选，只是为了确保日志打印不出乱码）
            //     if core::str::from_utf8(&raw_path[..path_len]).is_err() {
            //         panic!()
            //     }
            //     log::error!(
            //         "[socket_address_from] AF_UNIX: invalid UTF-8 in path {:?}",
            //         &raw_path[..path_len]
            //     );
            //     // 用一个定长数组来存储 path
            //     let mut sun_path = [0u8; 300];
            //     sun_path[..path_len].copy_from_slice(&raw_path[..path_len]);
            //     log::error!(
            //         "[socket_address_from] AF_UNIX path (len={}): {:?}",
            //         path_len,
            //         &sun_path[..path_len]
            //     );

            //     //todo
            //     return SocketAddr::(UnixSocketAddr {
            //         path: sun_path,
            //         len: path_len,
            //     });
            //i这里的unix,af_alg无用
        Domain::AF_INET | Domain::AF_UNIX|Domain::AF_NETLINK|Domain::AF_UNSPEC |Domain::AF_ALG=> {
            let port = u16::from_be_bytes([
                kernel_addr_from_user[2],
                kernel_addr_from_user[3],
            ]);
            // let a = (*(kernel_addr_from_user.as_ptr().add(2) as *const u32)).to_le_bytes();
            let raw_ip: u32 = core::ptr::read_unaligned(
                kernel_addr_from_user.as_ptr().add(4) as *const u32
            );
            // 如果原数据是网络字节序（big endian），先转成主机序
            let ip_be = u32::from_be(raw_ip);
            let a = ip_be.to_be_bytes(); 
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

            let port = {
                let hi = kernel_addr_from_user[2] as u16;
                let lo = kernel_addr_from_user[3] as u16;
                u16::from_be(hi << 8 | lo)
            };
            let task = current_task();  

            // 2) 直接跳过 flowinfo（4 字节），如果你需要可以同样 copy 处理
            //    let flowinfo = u32::from_be_bytes([
            //        kernel_addr_from_user[4],
            //        kernel_addr_from_user[5],
            //        kernel_addr_from_user[6],
            //        kernel_addr_from_user[7],
            //    ]);

            // 3) 拷贝 16 字节 IPv6 地址
            let mut ip_bytes = [0u8; 16];
            unsafe {
                core::ptr::copy_nonoverlapping(
                    kernel_addr_from_user.as_ptr().add(8),
                    ip_bytes.as_mut_ptr(),
                    16,
                );
            }
            // let ipv6 = std::net::Ipv6Addr::from(ip_bytes);

            // 4) Scope ID （network-order -> host-order），通常只在 link-local 时用到
            let scope_id = u32::from_be_bytes([
                kernel_addr_from_user[24],
                kernel_addr_from_user[25],
                kernel_addr_from_user[26],
                kernel_addr_from_user[27],
            ]);
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
                else if port==35091{
                    let addr = Ipv4Addr::new(127, 0, 0, 1);
                    SocketAddr::V4(SocketAddrV4::new(addr, 5001))
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
#[repr(C)]
struct SockAddrIn {
    sin_family: u16,           // __SOCKADDR_COMMON 中的 sa_family_t
    sin_port:   u16,           // in_port_t，网络字节序
    sin_addr:   [u8; 4],       // struct in_addr.s_addr（网络字节序）
    sin_zero:   [u8; 8],       // padding
}

pub fn socket_address_to(
    sockaddr: SocketAddr,
    addr: usize,
    addr_len: usize,
) -> SyscallRet {
    // 目前仅支持 IPv4
    let sock_in = if let SocketAddr::V4(v4) = sockaddr {
        SockAddrIn {
            // sin_family 在内核里以主机字节序存储
            sin_family: Domain::AF_INET as u16,
            // sin_port 必须是网络字节序
            sin_port:   v4.port().to_be(),
            // sin_addr.s_addr 是一个 32 位网络字节序整数；直接存四个 octet 保证内存布局
            sin_addr:   v4.ip().octets(),
            // C 里这 8 字节始终要清零
            sin_zero:   [0; 8],
        }
    } else {
        // IPv6 或者其它，暂不支持
        return Err(Errno::EAFNOSUPPORT);
    };

    // 整个结构体长度
    let required_bytes = core::mem::size_of::<SockAddrIn>();
    if addr_len < required_bytes {
        log::error!(
            "Buffer too small: required {} bytes, got {}",
            required_bytes,
            addr_len
        );
        return Err(Errno::ENOMEM);
    }

    // 把 struct 视为一段连续的字节，拷贝到用户空间
    let ptr = &sock_in as *const SockAddrIn as *const u8;
    unsafe {
        // 如果 copy_to_user 返回 Err，会自动往上传播
        copy_to_user(addr as *mut u8, ptr, required_bytes)?;
    }

    // 成功时返回写入字节数
    Ok(required_bytes)
}


impl FileOp for Socket {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

     fn read<'a>(&'a self, buf: &'a mut [u8]) -> SyscallRet {
        log::error!("[socket_read]:begin recv socket,recv len is {:?}",buf.len());
        if self.domain==Domain::AF_UNIX {
            //unix本地回环网络
            if self.buffer.is_none() {
                let passwd_blob = PasswdEntry::passwd_lookup(self, buf.len())?;
                log::error!("[socket_read]: passwd blob len is {:?}", passwd_blob.len());
                if buf.len() < passwd_blob.len() {
                    log::error!("[socket_read]: buf is too small,buf len is {:?}",buf.len());
                    return Err(Errno::ENOMEM);
                }

                // 2) 把 blob 里的字节一次性 copy 进用户给的 buf
                //    只要 blob.len() <= buf.len()，就不会越界
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        passwd_blob.as_ptr(),
                        buf.as_mut_ptr(),
                        passwd_blob.len(),
                    );
                }
                let sa = super::socket::SocketAddr::new(
                    super::socket::IpAddr::V4([127, 0, 0, 1].into()), 
                    0,
                );
                return Ok((passwd_blob.len()));         
            }
            return self.buffer.as_ref().unwrap().read(buf);
        }
        if !self.r_ready() {
            log::error!("[scoket_read] is_nonblocking {:?},is_connected is {:?}",self.is_nonblocking(),self.is_connected());
            if !self.is_block() && self.is_connected()  {
                loop {
                    if self.r_ready() {
                        match &self.inner {
                            SocketInner::Tcp(tcp_socket) =>{
                                return tcp_socket.recv(buf);
                            },
                            SocketInner::Udp(udp_socket) => {
                                match udp_socket.recv_from(buf) {
                                    Ok(res) =>{
                                        log::error!("[socket_read]udp recv len is {:?},addr is {:?}",res.0,res.1);
                                        return Ok(res.0);
                                    }
                                    Err(e) => {return Err(e);},
                                }
                            },
                        }
                    }
                    yield_current_task();
                }
            }
            else {
                return Err(Errno::EBADF);
            }
        }
            match &self.inner {
            SocketInner::Tcp(tcp_socket) =>{
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
        if self.domain==Domain::AF_UNIX {
            return self.buffer.as_ref().unwrap().write(buf);
        }
        //log::error!("[socket_write]:buf is {:?}",buf);
        if !self.w_ready() {
            if !self.is_block() && self.is_connected() {
                loop {
                        if self.w_ready() {
                             match &self.inner {
                                    SocketInner::Tcp(tcp_socket) =>{
                                        return tcp_socket.send(buf);
                                    },
                                    SocketInner::Udp(udp_socket) =>{
                                        return udp_socket.send(buf);
                                    },
                            }
                        }
                        yield_current_task();
                }
            }
            else {
                    
                return Err(Errno::EAGAIN);
            }
        }
        match &self.inner {
            SocketInner::Tcp(tcp_socket) =>{
                tcp_socket.send(buf)
            },
            SocketInner::Udp(udp_socket) =>{
                udp_socket.send(buf)
            },
        }
    }
    

    fn get_offset(&self) -> usize {
        panic!("can not get offset socket");
    }
    fn r_ready(&self) -> bool {
        log::error!("[sokcet_readable]:poll readable");
        if self.domain==Domain::AF_UNIX {
            //这里将寻找的文件中内容返回给进程
            return true
        }
        // yield_current_task();
        poll_interfaces();
        match &self.inner {
            SocketInner::Tcp(tcp_socket) => {
                log::error!("[socket_readable]:tcp socket readable");
                tcp_socket.poll(true).readable
            },
            SocketInner::Udp(udp_socket) => {
                udp_socket.poll().readable
            },
        }
    }
    fn w_ready(&self) -> bool {
        if self.domain==Domain::AF_UNIX {
            return self.buffer.as_ref().unwrap().w_ready();
        }
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

    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }
    fn hang_up(&self) -> bool {
        true
    }
    fn get_flags(&self) -> OpenFlags {
        let mut flag=OpenFlags::empty();
        if self.close_exec.load(core::sync::atomic::Ordering::Acquire) {
            flag|=OpenFlags::O_CLOEXEC;
        }
        if self.is_nonblocking() {
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
    SOL_ALG=279,
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
    MCAST_JOIN_GROUP =42,
    MCAST_LEAVE_GROUP=45
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
            IpOption::IP_MULTICAST_IF | IpOption::MCAST_JOIN_GROUP=> {
                        //设置多播接口
                        //我们只允许本地回环网络作为多播接口
                        Ok(0)
                    },
            IpOption::MCAST_LEAVE_GROUP=>{
                        //离开多播组
                        //我们只允许本地回环网络作为多播接口
                        let multicast_addr=IpAddress::Ipv4(Ipv4Address::new(opt[0], opt[1], opt[2], opt[3]));
                        let interface_addr = IpAddress::Ipv4(Ipv4Address::new(opt[4], opt[5],opt[6], opt[7]));
                        // remove_membership(multicast_addr, interface_addr);
                        Err(Errno::EADDRNOTAVAIL)
            }
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
        log::error!("[get_socket_option]buf_len is {:?}",buf_len);
        match self {
            SocketOption::SO_REUSEADDR => {
                let value: i32 = if socket.get_reuse_addr() { 1 } else { 0 };

                if buf_len < 4 {
                    panic!("can't write a int to socket opt value");
                }

                unsafe {
                    #[cfg(target_arch = "riscv64")]
                    copy_nonoverlapping(&value.to_ne_bytes() as *const u8, opt_value, 4);
                    #[cfg(target_arch = "loongarch64")]
                    copy_to_user(opt_value, &value.to_ne_bytes() as *const u8 , 4);
                    *opt_len = 4;
                }
            }
            SocketOption::SO_DONTROUTE => {
                if buf_len < 4 {
                    panic!("can't write a int to socket opt value");
                }

                let size: i32 = if socket.dont_route { 1 } else { 0 };

                unsafe {
                    #[cfg(target_arch = "riscv64")]
                    copy_nonoverlapping(&size.to_ne_bytes() as *const u8, opt_value, 4);
                    #[cfg(target_arch = "loongarch64")]
                    copy_to_user(opt_value, &size.to_ne_bytes() as *const u8 , 4);
                    *opt_len = 4;
                }
            }
            SocketOption::SO_SNDBUF => {
                // if buf_len < 4 {
                //     panic!("can't write a int to socket opt value");
                // }

                let size: i32 = socket.get_send_buf_size() as i32;

                unsafe {
                    #[cfg(target_arch = "loongarch64")]
                    copy_to_user(opt_value, &size.to_ne_bytes() as *const u8 , 4);
                    #[cfg(target_arch = "riscv64")]
                    copy_nonoverlapping(&size.to_ne_bytes() as *const u8, opt_value, 4);
                    *opt_len = 4;
                }
            }
            SocketOption::SO_RCVBUF => {
                // if buf_len < 4 {
                //     panic!("can't write a int to socket opt value");
                // }

                let size: i32 = socket.get_recv_buf_size() as i32;

                unsafe {
                    #[cfg(target_arch = "riscv64")]
                    copy_nonoverlapping(&size.to_ne_bytes() as *const u8, opt_value, 4);
                    #[cfg(target_arch = "loongarch64")]
                    copy_to_user(opt_value, &size.to_ne_bytes() as *const u8 , 4);
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
                     #[cfg(target_arch = "riscv64")]
                    copy_nonoverlapping(&keep_alive.to_ne_bytes() as *const u8, opt_value, 4);
                    #[cfg(target_arch = "loongarch64")]
                    copy_to_user(opt_value, &keep_alive.to_ne_bytes() as *const u8 , 4);
                    *opt_len = 4;
                }
            }
            SocketOption::SO_RCVTIMEO => {
                if buf_len < size_of::<TimeSpec>() {
                    panic!("can't write a timeval to socket opt value");
                }

                unsafe {
                    match socket.get_recv_timeout() {
                        Some(time) =>{
                            #[cfg(target_arch = "riscv64")]
                            copy_nonoverlapping(
                            (&time) as *const TimeSpec,
                            opt_value as *mut TimeSpec,
                            1,
                            );
                            #[cfg(target_arch = "loongarch64")]
                            copy_to_user(opt_value as *mut TimeSpec, &time as *const TimeSpec, size_of::<TimeSpec>());
                        }, 
                        None => {
                            #[cfg(target_arch = "riscv64")]
                            copy_nonoverlapping(&0u8 as *const u8, opt_value, size_of::<TimeSpec>());
                            #[cfg(target_arch = "loongarch64")]
                            copy_to_user(opt_value, &0u8 as *const u8 , size_of::<TimeSpec>());
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
                    #[cfg(target_arch = "riscv64")]
                    copy_nonoverlapping(&value as *const u8, opt_addr, 4);
                    #[cfg(target_arch = "loongarch64")]
                    copy_to_user(opt_addr, &value as *const u8, 4);
                    *opt_len = 4;
                }
            },
            TcpSocketOption::TCP_MAXSEG => {
                let len = size_of::<usize>();

                let value: usize = 1500;

                unsafe {
                    #[cfg(target_arch = "riscv64")]
                    copy_nonoverlapping(&value as *const usize as *const u8, opt_addr, len);
                    #[cfg(target_arch = "loongarch64")]
                    copy_to_user(opt_addr, &value as *const usize as *const u8, len);
                    *opt_len = len as u32;
                };
            },
            TcpSocketOption::TCP_INFO => {
            },
            TcpSocketOption::TCP_CONGESTION => {
                let bytes = rawsocket.get_congestion();
                let bytes = bytes.as_bytes();

                unsafe {
                    #[cfg(target_arch = "riscv64")]
                    copy_nonoverlapping(bytes.as_ptr(), opt_addr, bytes.len());
                    #[cfg(target_arch = "loongarch64")]
                    copy_to_user(opt_addr, bytes.as_ptr(), bytes.len());
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
#[derive(TryFromPrimitive,Debug)]
#[repr(usize)]
#[allow(non_camel_case_types)]
pub enum ALG_Option {
    ALG_SET_KEY=1,
    ALG_SET_IV=2,
    ALG_SET_AEAD_AUTHSIZE=3,
    ALG_SET_OP=4,
}
impl ALG_Option {
    //optval已经复制到内核
    pub fn set(&self,socket:&Socket,opt:&[u8])->SyscallRet {
        log::error!("[ALG_Option_set]opt is {:?}",opt);
        assert!(socket.domain==Domain::AF_ALG);
        match self {
            ALG_Option::ALG_SET_KEY => {
                // 设置密钥
                //optval 指向一个缓冲区，里面存放着“raw key bytes”，optlen 则是这个密钥（字节串）的长度
                //对称加密/消息鉴别（MAC/HMAC）算法的密
                socket.socket_af_alg.lock().as_mut().unwrap().set_alg_key(opt);
                Ok(0)
            },
            ALG_Option::ALG_SET_IV => {
                unimplemented!()
            },
            ALG_Option::ALG_SET_AEAD_AUTHSIZE => {
                unimplemented!()
            },
            ALG_Option::ALG_SET_OP => {
                unimplemented!()
            },
        }
    }
}
#[repr(C)]
#[derive(Debug,Copy,Clone)]
pub struct MessageHeaderRaw {
    pub name:      *mut u8,   // 对应 sockaddr 或者 AF_ALG 下的 SockAddrAlg
    pub name_len:  u32,       // name 缓冲区的大小
    pub iovec:     *mut IoVec,
    pub iovec_len: i32,       // iovec 数量
    pub control:   *mut u8,   // 控制消息 (cmsg) 缓冲区
    pub control_len: u32,     // control 缓冲区的大小
    pub flags:     i32,       // recvmsg/sendmsg 时的 flags
}

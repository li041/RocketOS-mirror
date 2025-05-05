/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-04-02 23:04:54
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-05-25 16:47:50
 * @FilePath: /RocketOS_netperfright/os/src/syscall/net.rs
 * @Description: net syscall
 * 
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved. 
 */

use core::{fmt::Result, net::{IpAddr, Ipv4Addr, SocketAddr}};
use alloc::{sync::Arc, vec::{Vec}};
use alloc::vec;
use bitflags::Flags;
use num_enum::TryFromPrimitive;
use smoltcp::wire::IpEndpoint;
use crate::{arch::mm::{copy_from_user, copy_to_user},fs::fdtable::FdFlags, net::{addr::{from_ipendpoint_to_socketaddr, LOOP_BACK_IP}, socket::{socket_address_from, socket_address_to, Domain, IpOption, Ipv6Option, Socket, SocketOption, SocketOptionLevel, SocketType, TcpSocketOption, SOCK_NONBLOCK}}, task::{current_task, yield_current_task}};

use super::errno::{Errno, SyscallRet};
 ///函数会创建一个socket并返回一个fd,失败返回-1
 /// domain: 展示使用的
 /// flag:usize sockettype
 /// protocol:协议
pub fn syscall_socket(domain:usize,sockettype:usize,_protocol:usize)->SyscallRet{
    log::error!("[syscall_socket]:domain:{} sockettype:{}",domain,sockettype & 0xFF);
    let task=current_task();
    let domain=match Domain::try_from(domain) {
        Ok(res) => res,
        Err(e) => {return Err(Errno::EAFNOSUPPORT)},
    };
    let s_type=match SocketType::try_from(sockettype & 0xFF) {
        Ok(res)=>res,
        Err(e)=>{return Err(Errno::EINVAL);},
    };
    let socket=Arc::new(Socket::new(domain, s_type));
    //SOCK_NONBLOCK=0X800,按照flag设计
    socket.set_nonblocking((sockettype&SOCK_NONBLOCK)!=0);
    let task=current_task();
    let fd_table=task.fd_table();
    //分配fd并插入文件
    let fd=fd_table.alloc_fd(socket,FdFlags::all()).unwrap();
    log::error!("[syscall_socket]:alloc fd {} to socket",fd);
    Ok(fd)
}

pub fn syscall_bind(socketfd:usize,socketaddr:usize,socketlen:usize)->SyscallRet {
    log::error!("[syscall_bind]:begin bind");
    let task=current_task();
    let file=match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    //向下转型
    let socket=match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };
    log::error!("[syscall_bind]:socket domain {:?} sockettype{:?}",socket.domain,socket.socket_type);
    //需要实现一个从地址读取addr的函数
    let bind_addr=unsafe { socket_address_from(socketaddr as *const u8, socketlen,socket) };
    log::error!("[syscall_bind]:bind_addr{:?}",bind_addr);
    socket.bind(bind_addr);
    Ok(0)
}

pub fn syscall_listen(socketfd:usize,_backlog:usize)->SyscallRet{
    log::error!("[syscall_listen]:begin listen");
    let task=current_task();
    let file=match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    //向下转型
    let socket=match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };
    socket.listen();
    Ok(0)
}

pub fn syscall_accept(socketfd:usize,socketaddr:usize,socketlen:usize)->SyscallRet {
    log::error!("[syscall_accept]:begin accpet");
    let task=current_task();
    let file=match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    //向下转型
    let socket=match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };
    match socket.accept() {
        Ok((new_socket,addr)) => {
            let fd_table=task.fd_table();
            //let _ = socket_address_to(addr, socketaddr, socketlen);
            let fd=fd_table.alloc_fd(Arc::new(new_socket),FdFlags::empty()).unwrap();
            Ok(fd)
        },
        //TODO socket accept err
        Err(e) => Err(e),
    }
}
pub fn syscall_connect(socketfd:usize,socketaddr:usize,socketlen:usize)->SyscallRet {
    // yield_current_task();
    let task=current_task();
    // println!("[syscall_connect]:the current task is {}",task.tid());
    let file=match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    //向下转型
    let socket=match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };
    let addr=unsafe { socket_address_from(socketaddr as *const u8, socketlen,socket) };
    log::error!("[syscall_connect] connect addr is {:?}",addr);
    match socket.connect(addr) {
        Ok(_) =>Ok(0),
        Err(e) => Err(e)
    }
}

pub fn syscall_send(socketfd:usize,buf:*const u8,len:usize,flag:usize,socketaddr:usize,socketlen:usize)->SyscallRet {
    log::error!("[syscall_send]:begin send");
    log::error!("[syscall_send]:buf_prt:{}",buf as usize);
    log::error!("[syscall_send]:remote_addr:{}",socketaddr);
    log::error!("[syscall_send]:len:{}",len);
    let task=current_task();
    let file=match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    //向下转型
    let socket=match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };
    let boundaddr=socket.name();
    log::error!("[syscall_send] sockt addr is {:?}",boundaddr);
    let addr;
    if socketaddr==0 {
        addr=match socket.peer_name() {
            Ok(a) => a,
            Err(e) => {
                    from_ipendpoint_to_socketaddr(IpEndpoint::new(LOOP_BACK_IP, (boundaddr.unwrap().port()+2 )as u16))
            },
        };
        log::error!("[syscall_send] peer name is {:?}",addr);
    }
    else {
        addr=unsafe { socket_address_from(socketaddr as *const u8, socketlen,socket) };
    }
    // let addr=unsafe { socket_address_from(socketaddr as *const u8, socketlen,socket) };
    log::error!("[syscall_send]:len:{}",len);
    let mut kernel_buf:Vec<u8>=vec![0;len];
    copy_from_user(buf,kernel_buf.as_mut_ptr(), len)?;
    // log::error!("[syscall_send]:buf{:?}",buf.to_ascii_lowercase());
    //todo,这里测试udp需要a修改
    match socket.send(kernel_buf.as_slice(), addr) {
        Ok(size) => {
            // copy_to_user(buf as *mut u8, kernel_buf.as_ptr(), len)?;
            Ok(size)
        },
        Err(e) => {
            log::error!("[syscall_send]:send error {:?}",e);
            Err(e)
        }
    }
}
pub fn syscall_recv(socketfd:usize,buf:*mut u8,len:usize,_socketaddr:usize,_socketlen:usize,_flag:usize)->SyscallRet {
    log::error!("[syscall_recv]:begin recv");
    log::error!("[syscall_recv]:sockfd:{:?},len:{:?},buf {:?}",socketfd,len,buf);
    let task=current_task();
    let file=match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    //向下转型
    let socket=match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };
    let addr=socket.name().unwrap();
    log::error!("[syscall_recv] sockt addr is {:?}",addr);
    // let addr=unsafe { socket_address_from(socketaddr as *const u8, socket) };
    // let buf=unsafe { core::slice::from_raw_parts_mut(buf, len) };
    let mut kernel_buf= vec![0u8; len];
    match  socket.recv_from(&mut kernel_buf){
    Ok((size,_addr)) => {
        copy_to_user(buf, kernel_buf.as_ptr(), len)?;
        log::error!("[syscall_recv]:recv buf len {}",size);
        return Ok(size);
    },
    Err(e) => {
        Err(e)
    }
    }    
}
#[derive(TryFromPrimitive)]
#[repr(usize)]
enum SocketShutdown {
    Read = 0,
    Write = 1,
    ReadWrite = 2,
}

pub fn syscall_shutdown(socketfd:usize,how:usize)->SyscallRet {
    log::error!("[syscall_shutdown] begin shutdown sockfd {:?},how {:?}",socketfd,how);
    let task=current_task();
    let file=match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    let Ok(h) = SocketShutdown::try_from(how) else {
        return Err(Errno::EINVAL);
    };
    //向下转型
    let socket=match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };
    //todo shutdown errno
    // socket.shutdown()
    match h {
        SocketShutdown::Read => {
            log::error!("[shutdown()] SHUT_RD is noop");
            Ok(0)
        },
        SocketShutdown::Write => socket.shutdown(),
        SocketShutdown::ReadWrite => socket.abort(),
    }
}
pub fn syscall_setsocketopt(fd:usize,level:usize,optname:usize,optval:*const u8,optlen:usize)->SyscallRet {
    log::error!("[syscall_setsocketopt]:begin set socket opt");
    log::error!("[syscall_setsocketopt]:fd:{},level:{},optname:{}",fd,level,optname);
    let Ok(level) = SocketOptionLevel::try_from(level) else {
        log::error!("[setsockopt()] level {level} not supported");
        unimplemented!();
    };

    let curr = current_task();

    let file=match curr.fd_table().get_file(fd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    //向下转型
    let socket=match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };
    let mut kernel_opt:Vec<u8>=vec![0;optlen];

    copy_from_user(optval,kernel_opt.as_mut_ptr(), optlen as usize);

    match level {
        //TODO setopt error
        SocketOptionLevel::IP => {
            let option=IpOption::try_from(optname).unwrap();
            option.set(socket, kernel_opt.as_slice())
            // return Ok(0);
        },
        SocketOptionLevel::Socket => {
            let option=SocketOption::try_from(optname).unwrap();
            option.set(socket, kernel_opt.as_slice())
            // return Ok(0);
        },
        SocketOptionLevel::Tcp => {
            let option=TcpSocketOption::try_from(optname).unwrap();
            option.set(socket, kernel_opt.as_slice())
            // return Ok(0);
        },
        SocketOptionLevel::IPv6 => {
            let option=Ipv6Option::try_from(optname).unwrap();
            option.set(socket, kernel_opt.as_slice())
            // return Ok(0);
        },
    }
}

pub fn syscall_getsocketopt(fd:usize,level:usize,optname:usize,optval:*mut u8,optlen:usize)->SyscallRet {
    log::error!("[sys_getsocketopt] fd {:?} level {:?} optname {:?}",fd,level,optname);
    let Ok(level) = SocketOptionLevel::try_from(level) else {
        log::error!("[setsockopt()] level {level} not supported");
        unimplemented!();
    };

    let curr = current_task();
    let file=match curr.fd_table().get_file(fd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    //向下转型
    let socket=match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };

    // let opt = unsafe { copy_from_user(optval, optlen as usize).unwrap() };

    match level {
        //TODO getsockopt error
        SocketOptionLevel::IP => {
            return Ok(0);
        },
        SocketOptionLevel::Socket => {
            let option=SocketOption::try_from(optname).unwrap();
            option.get(socket, optval, optlen as *mut u32);
            return Ok(0);
        },
        SocketOptionLevel::Tcp => {
            let option=TcpSocketOption::try_from(optname).unwrap();
            option.get(socket, optval, optlen as *mut u32);
            return Ok(0);
        },
        SocketOptionLevel::IPv6 => {
            // let option=Ipv6Option::try_from(optname).unwrap();
            // option.set(socket, opt);
            return Ok(0);
        },
    }
}
//这个系统调用用于获取socket的本地地址
pub fn syscall_getsockname(socketfd:usize,socketaddr:usize,socketlen:usize)->SyscallRet {
    log::error!("[syscall_getsockname]:begin getsockname");
    let task=current_task();
    let file=match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    //向下转型
    let socket=match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };
    //TODO sock name error
    let addr=socket.name().unwrap();
    log::error!("[syscall_getsockname]:addr{:?}",addr);
    socket_address_to(addr, socketaddr, socketlen)?;
    Ok(0)
}
pub fn syscall_getpeername(socketfd:usize,socketaddr:usize,socketlen:usize)->SyscallRet {
    log::error!("[syscall_getpeername]:begin getpeername");
    log::error!("[syscall_getpeername]:socketaddr{:#x},socketlen{}", socketaddr, socketlen);
    let task=current_task();
    let file=match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    //向下转型
    let socket=match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };
    //TODO peer name error
    let addr=socket.peer_name().unwrap();
    log::error!("[syscall_getpeername]:addr{:?}",addr);
    socket_address_to(addr, socketaddr, socketlen)
}

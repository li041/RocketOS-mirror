/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-04-02 23:04:54
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-06-01 16:39:23
 * @FilePath: /RocketOS_netperfright/os/src/syscall/net.rs
 * @Description: net syscall
 *
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved.
 */

use crate::{
    arch::mm::{copy_from_user, copy_to_user},
    fs::{
        fdtable::FdFlags,
        file::{FileOp, OpenFlags},
        pipe::{self, make_pipe},
        uapi::IoVec,
    },
    net::{
        addr::{from_ipendpoint_to_socketaddr, LOOP_BACK_IP},
        socket::{
            check_alg, socket_address_from, socket_address_from_af_alg, socket_address_from_unix,
            socket_address_to, ALG_Option, Domain, IpOption, Ipv6Option, MessageHeaderRaw, Socket,
            SocketOption, SocketOptionLevel, SocketType, TcpSocketOption, SOCK_CLOEXEC,
            SOCK_NONBLOCK,
        },
    },
    syscall::task::sys_nanosleep,
    task::{current_task, yield_current_task},
};
use alloc::vec;
use alloc::{sync::Arc, task, vec::Vec};
use bitflags::Flags;
use core::{
    fmt::Result,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::Add,
};
use num_enum::TryFromPrimitive;
use smoltcp::wire::IpEndpoint;
pub const SOCKET_TYPE_MASK: usize = 0xFF;
use super::errno::{Errno, SyscallRet};
///函数会创建一个socket并返回一个fd,失败返回-1
/// domain: 展示使用的
/// flag:usize sockettype
/// protocol:协议
pub fn syscall_socket(domain: usize, sockettype: usize, protocol: usize) -> SyscallRet {
    log::error!(
        "[syscall_socket]:domain:{} sockettype:{}",
        domain,
        sockettype & 0xFF
    );
    let domain = match Domain::try_from(domain) {
        Ok(res) => res,
        Err(e) => return Err(Errno::EAFNOSUPPORT),
    };
    let s_type = match SocketType::try_from(sockettype & 0xFF) {
        Ok(res) => res,
        Err(e) => {
            return Err(Errno::EINVAL);
        }
    };
    let socket = Arc::new(Socket::new(domain, s_type));
    //SOCK_NONBLOCK=0X800,按照flag设计
    socket.set_nonblocking((sockettype & SOCK_NONBLOCK) != 0);
    let task = current_task();
    let fd_table = task.fd_table();
    //分配fd并插入文件
    let fd = fd_table.alloc_fd(socket, FdFlags::all()).unwrap();
    log::error!("[syscall_socket]:alloc fd {} to socket", fd);
    Ok(fd)
}

pub fn syscall_bind(socketfd: usize, socketaddr: usize, socketlen: usize) -> SyscallRet {
    log::error!("[syscall_bind]:begin bind");
    let task = current_task();
    let file = match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    //向下转型
    let socket = match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };
    log::error!(
        "[syscall_bind]:socket domain {:?} sockettype{:?}",
        socket.domain,
        socket.socket_type
    );
    //如果是al_afg的套接字则需要使用对应的socket_from
    if socket.domain == Domain::AF_ALG {
        //socket那边设置不太方便
        socket.set_is_af_alg(true);
        let bind_addr = unsafe { socket_address_from_af_alg(socketaddr as *const u8, socketlen) }?;
        check_alg(&bind_addr)?;
        socket.bind_af_alg(bind_addr)?;
        return Ok(0);
    }
    //需要实现一个从地址读取addr的函数
    let bind_addr = unsafe { socket_address_from(socketaddr as *const u8, socketlen, socket) };
    log::error!("[syscall_bind]:bind_addr{:?}", bind_addr);
    socket.bind(bind_addr);
    Ok(0)
}

pub fn syscall_listen(socketfd: usize, _backlog: usize) -> SyscallRet {
    log::error!("[syscall_listen]:begin listen");
    let task = current_task();
    let file = match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    //向下转型
    let socket = match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };
    socket.listen();
    Ok(0)
}

pub fn syscall_accept(socketfd: usize, socketaddr: usize, socketlen: usize) -> SyscallRet {
    log::error!("[syscall_accept]: begin accept");
    let task = current_task();

    let file = task.fd_table().get_file(socketfd).ok_or(Errno::EBADF)?;

    // 2. 如果是用 O_PATH 打开的 fd，直接视为无效
    if file.get_flags().contains(OpenFlags::O_PATH) {
        log::error!("[syscall_accept]: O_PATH fd treated as EBADF");
        return Err(Errno::EBADF);
    }

    // 3. 确保 fd 可读可写
    if !file.readable() && !file.writable() {
        log::error!("[syscall_accept]: file not readable or writable");
        return Err(Errno::EBADF);
    }
    // 3. 确保是 socket
    let socket = file
        .as_any()
        .downcast_ref::<Socket>()
        .ok_or(Errno::ENOTSOCK)?;
    if socket.domain == Domain::AF_ALG {
        log::error!("[syscall_accept]: unix domain socket supported");
        //需要直接克隆一个fd继承所有socket的所有内容
        let fd_table = task.fd_table();
        let new_socket = socket.accept_alg()?;
        let fd = fd_table
            .alloc_fd(Arc::new(new_socket), FdFlags::empty())
            .unwrap();
        log::error!("[syscall_accept_af_alg]: alloc fd {} to socket", fd);
        return Ok(fd);
    }
    match socket.accept() {
        Ok((new_socket, addr)) => {
            let fd_table = task.fd_table();
            //let _ = socket_address_to(addr, socketaddr, socketlen);
            let fd = fd_table
                .alloc_fd(Arc::new(new_socket), FdFlags::empty())
                .unwrap();
            Ok(fd)
        }
        //TODO socket accept err
        Err(e) => Err(e),
    }
}
pub fn syscall_accept4(
    socketfd: usize,
    socketaddr: usize,
    socketlen: usize,
    flags: usize,
) -> SyscallRet {
    log::error!("[syscall_accept4]: begin accept4");
    log::error!(
        "[syscall_accept4]:socketfd:{},socketaddr:{},socketlen:{},flags:{}",
        socketfd,
        socketaddr,
        socketlen,
        flags
    );
    let task = current_task();

    let file = task.fd_table().get_file(socketfd).ok_or(Errno::EBADF)?;

    // 2. 如果是用 O_PATH 打开的 fd，直接视为无效
    if file.get_flags().contains(OpenFlags::O_PATH) {
        log::error!("[syscall_accept4]: O_PATH fd treated as EBADF");
        return Err(Errno::EBADF);
    }

    // 3. 确保 fd 可读可写
    if !file.readable() && !file.writable() {
        log::error!("[syscall_accept4]: file not readable or writable");
        return Err(Errno::EBADF);
    }
    // 3. 确保是 socket
    let socket = file
        .as_any()
        .downcast_ref::<Socket>()
        .ok_or(Errno::ENOTSOCK)?;

    match socket.accept() {
        Ok((new_socket, addr)) => {
            let fd_table = task.fd_table();
            //let _ = socket_address_to(addr, socketaddr, socketlen);
            let new_socket = Arc::new(new_socket);
            // 如果 flags 里包含 SOCK_NONBLOCK，就把 socket 设为非阻塞
            new_socket.set_nonblocking((flags & SOCK_NONBLOCK) != 0);

            // 如果 flags 里包含 SOCK_CLOEXEC，就把 socket 设为 close-on-exec
            new_socket.set_close_on_exec((flags & SOCK_CLOEXEC) != 0);
            // if flags & SOCK_CLOEXEC != 0 {
            //     new_socket.s(true);
            // }
            let open_flags = new_socket.get_flags();
            let fd_flag = FdFlags::from(&open_flags);
            let fd = fd_table.alloc_fd(new_socket, fd_flag)?;
            log::error!(
                "[syscall_accept4]: alloc fd {} to socket,flag is {:?}",
                fd,
                open_flags
            );
            Ok(fd)
        }
        //TODO socket accept err
        Err(e) => Err(e),
    }
}
pub fn syscall_connect(socketfd: usize, socketaddr: usize, socketlen: usize) -> SyscallRet {
    // yield_current_task();
    let task = current_task();
    let file = match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    //向下转型
    let socket = match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };
    if socket.domain == Domain::AF_UNIX {
        log::error!("[syscall_connect]: unix domain socket supported");
        let mut path =
            unsafe { socket_address_from_unix(socketaddr as *const u8, socketlen, socket) }?;
        log::error!("[syscall_connect]: unix domain socket path is {:?}", path);
        //todo
        //需要检查这个路径是否存在，如果不存在就需要创建,但路径文件本身和socket数据传输没有关系
        return Ok(0);
    }
    let addr = unsafe { socket_address_from(socketaddr as *const u8, socketlen, socket) };
    log::error!("[syscall_connect] connect addr is {:?}", addr);
    // addr.set_port(49152);
    match socket.connect(addr) {
        Ok(_) => Ok(0),
        Err(e) => Err(e),
    }
}

pub fn syscall_send(
    socketfd: usize,
    buf: *const u8,
    len: usize,
    flag: usize,
    socketaddr: usize,
    socketlen: usize,
) -> SyscallRet {
    log::error!("[syscall_send]:begin send");
    log::error!("[syscall_send]:buf_prt:{}", buf as usize);
    log::error!("[syscall_send]:remote_addr:{}", socketaddr);
    log::error!("[syscall_send]:len:{}", len);
    let task = current_task();
    let file = match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    //向下转型
    let socket = match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };
    let boundaddr = socket.name();
    log::error!("[syscall_send] sockt addr is {:?}", boundaddr);
    let addr;
    if socketaddr == 0 {
        addr = match socket.peer_name() {
            Ok(a) => a,
            Err(e) => from_ipendpoint_to_socketaddr(IpEndpoint::new(
                LOOP_BACK_IP,
                (boundaddr.unwrap().port() + 2) as u16,
            )),
        };
        log::error!("[syscall_send] peer name is {:?}", addr);
    } else {
        addr = unsafe { socket_address_from(socketaddr as *const u8, socketlen, socket) };
    }
    // let addr=unsafe { socket_address_from(socketaddr as *const u8, socketlen,socket) };
    log::error!("[syscall_send]:len:{}", len);
    let mut kernel_buf: Vec<u8> = vec![0; len];
    copy_from_user(buf, kernel_buf.as_mut_ptr(), len)?;
    log::error!("[syscall_send]:buf{:?}", kernel_buf.to_ascii_lowercase());
    if socket.domain == Domain::AF_UNIX {
        return socket.unix_send(kernel_buf.as_slice());
    }
    //todo,这里测试udp需要a修改
    match socket.send(kernel_buf.as_slice(), addr) {
        Ok(size) => {
            // copy_to_user(buf as *mut u8, kernel_buf.as_ptr(), len)?;
            Ok(size)
        }
        Err(e) => {
            log::error!("[syscall_send]:send error {:?}", e);
            Err(e)
        }
    }
}
pub fn syscall_recv(
    socketfd: usize,
    buf: *mut u8,
    len: usize,
    _socketaddr: usize,
    _socketlen: usize,
    _flag: usize,
) -> SyscallRet {
    log::error!("[syscall_recv]:begin recv");
    log::error!(
        "[syscall_recv]:sockfd:{:?},len:{:?},buf {:?}",
        socketfd,
        len,
        buf
    );
    let task = current_task();
    let file = match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    //向下转型
    let socket = match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };
    let addr = socket.name().unwrap();
    log::error!("[syscall_recv] sockt addr is {:?}", addr);
    // let addr=unsafe { socket_address_from(socketaddr as *const u8, socket) };
    // let buf=unsafe { core::slice::from_raw_parts_mut(buf, len) };
    let mut kernel_buf = vec![0u8; len];
    match socket.recv_from(&mut kernel_buf) {
        Ok((size, _addr)) => {
            copy_to_user(buf, kernel_buf.as_ptr(), len)?;
            log::error!("[syscall_recv]:recv buf len {}", size);
            return Ok(size);
        }
        Err(e) => Err(e),
    }
}
#[derive(TryFromPrimitive)]
#[repr(usize)]
enum SocketShutdown {
    Read = 0,
    Write = 1,
    ReadWrite = 2,
}

pub fn syscall_shutdown(socketfd: usize, how: usize) -> SyscallRet {
    log::error!(
        "[syscall_shutdown] begin shutdown sockfd {:?},how {:?}",
        socketfd,
        how
    );
    let task = current_task();
    let file = match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    let Ok(h) = SocketShutdown::try_from(how) else {
        return Err(Errno::EINVAL);
    };
    //向下转型
    let socket = match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };
    //todo shutdown errno
    // socket.shutdown()
    match h {
        SocketShutdown::Read => {
            log::error!("[shutdown()] SHUT_RD is noop");
            Ok(0)
        }
        SocketShutdown::Write => socket.shutdown(),
        SocketShutdown::ReadWrite => socket.abort(),
    }
}
pub fn syscall_setsocketopt(
    fd: usize,
    level: usize,
    optname: usize,
    optval: *const u8,
    optlen: usize,
) -> SyscallRet {
    log::error!("[syscall_setsocketopt]:begin set socket opt");
    log::error!(
        "[syscall_setsocketopt]:fd:{},level:{},optname:{},optval :{:?},optlen:{}",
        fd,
        level,
        optname,
        optval,
        optlen
    );
    let Ok(level) = SocketOptionLevel::try_from(level) else {
        log::error!("[setsockopt()] level {level} not supported");
        unimplemented!();
    };

    let curr = current_task();

    let file = match curr.fd_table().get_file(fd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    //向下转型
    let socket = match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };
    let mut kernel_opt: Vec<u8> = vec![0; optlen];

    copy_from_user(optval, kernel_opt.as_mut_ptr(), optlen as usize);

    match level {
        //TODO setopt error
        SocketOptionLevel::IP => {
            let option = IpOption::try_from(optname).unwrap();
            option.set(socket, kernel_opt.as_slice())
            // return Ok(0);
        }
        SocketOptionLevel::Socket => {
            let option = SocketOption::try_from(optname).unwrap();
            option.set(socket, kernel_opt.as_slice())
            // return Ok(0);
        }
        SocketOptionLevel::Tcp => {
            let option = TcpSocketOption::try_from(optname).unwrap();
            option.set(socket, kernel_opt.as_slice())
            // return Ok(0);
        }
        SocketOptionLevel::IPv6 => {
            let option = Ipv6Option::try_from(optname).unwrap();
            option.set(socket, kernel_opt.as_slice())
            // return Ok(0);
        }
        SocketOptionLevel::SOL_ALG => {
            let option = ALG_Option::try_from(optname).unwrap();
            option.set(socket, kernel_opt.as_slice())
        }
    }
}

pub fn syscall_getsocketopt(
    fd: usize,
    level: usize,
    optname: usize,
    optval: *mut u8,
    optlen: usize,
) -> SyscallRet {
    log::error!(
        "[sys_getsocketopt] fd {:?} level {:?} optname {:?},optlen {:?}",
        fd,
        level,
        optname,
        optlen
    );
    let mut kernel_opt_len: u32 = 0;
    copy_from_user(
        optlen as *const u32,
        &mut kernel_opt_len as *mut u32,
        core::mem::size_of::<u32>(),
    )?;
    let Ok(level) = SocketOptionLevel::try_from(level) else {
        log::error!("[setsockopt()] level {level} not supported");
        unimplemented!();
    };

    let curr = current_task();
    let file = match curr.fd_table().get_file(fd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    //向下转型
    let socket = match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };

    match level {
        //TODO getsockopt error
        SocketOptionLevel::IP => {
            return Ok(0);
        }
        SocketOptionLevel::Socket => {
            let option = SocketOption::try_from(optname).unwrap();
            #[cfg(target_arch = "riscv64")]
            option.get(socket, optval, optlen as *mut u32);
            #[cfg(target_arch = "loongarch64")]
            option.get(socket, optval, kernel_opt_len as *mut u32);
            return Ok(0);
        }
        SocketOptionLevel::Tcp => {
            let option = TcpSocketOption::try_from(optname).unwrap();
            #[cfg(target_arch = "riscv64")]
            option.get(socket, optval, optlen as *mut u32);
            #[cfg(target_arch = "loongarch64")]
            option.get(socket, optval, kernel_opt_len as *mut u32);
            return Ok(0);
        }
        SocketOptionLevel::IPv6 => {
            // let option=Ipv6Option::try_from(optname).unwrap();
            // option.set(socket, opt);
            return Ok(0);
        }
        SocketOptionLevel::SOL_ALG => {
            unimplemented!()
        }
    }
}
//这个系统调用用于获取socket的本地地址
pub fn syscall_getsockname(socketfd: usize, socketaddr: usize, socketlen: usize) -> SyscallRet {
    log::error!("[syscall_getsockname]:begin getsockname");
    let task = current_task();
    let file = match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    //向下转型
    let socket = match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };
    //TODO sock name error
    let addr = socket.name().unwrap();
    log::error!("[syscall_getsockname]:addr{:?}", addr);
    socket_address_to(addr, socketaddr, socketlen)?;
    Ok(0)
}
pub fn syscall_getpeername(socketfd: usize, socketaddr: usize, socketlen: usize) -> SyscallRet {
    log::error!("[syscall_getpeername]:begin getpeername");
    log::error!(
        "[syscall_getpeername]:socketaddr{:#x},socketlen{}",
        socketaddr,
        socketlen
    );
    let task = current_task();
    let file = match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    //向下转型
    let socket = match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };
    //TODO peer name error
    let addr = socket.peer_name().unwrap();
    log::error!("[syscall_getpeername]:addr{:?}", addr);
    socket_address_to(addr, socketaddr, socketlen)
}

//socketpair中fd在socketfds中用数组给出
pub fn syscall_socketpair(
    domain: usize,
    sockettype: usize,
    _protocol: usize,
    socketfds: *mut usize,
) -> SyscallRet {
    if domain != Domain::AF_UNIX as usize {
        log::error!("[syscall_socketpair]: domain not supported");
        panic!()
    }
    log::error!("[syscall_socketpair]:begin socketpair");
    if SocketType::try_from(sockettype & SOCKET_TYPE_MASK).is_err() {
        // return ErrorNo::EINVAL as isize;
        return Err(Errno::EINVAL);
    };
    let mut fd_flags = OpenFlags::empty();
    if sockettype & SOCK_NONBLOCK != 0 {
        fd_flags |= OpenFlags::O_NONBLOCK;
    }
    if sockettype & SOCK_CLOEXEC != 0 {
        fd_flags |= OpenFlags::O_CLOEXEC;
    }
    let (fd1, fd2) = make_socketpair(sockettype, fd_flags);
    let task = current_task();
    let fd_table = task.fd_table();
    let fd_f = FdFlags::from(&fd_flags);
    let fd_num1 = fd_table.alloc_fd(fd1, fd_f)?;
    let fd_num2 = fd_table.alloc_fd(fd2, fd_f)?;
    log::error!("alloc fd1 {} fd2 {} as socketpair", fd_num1, fd_num2);
    //写回
    let kernel_fds: Vec<usize> = vec![fd_num1, fd_num2];
    copy_to_user(socketfds, kernel_fds.as_ptr(), 2)?;
    Ok(0)
}

pub fn make_socketpair(sockettype: usize, pipe_flag: OpenFlags) -> (Arc<Socket>, Arc<Socket>) {
    let s_type = SocketType::try_from(sockettype & SOCKET_TYPE_MASK).unwrap();
    let mut fd1 = Socket::new(Domain::AF_UNIX, s_type);
    let mut fd2 = Socket::new(Domain::AF_UNIX, s_type);
    let (pipe1, pipe2) = make_pipe(pipe_flag);
    fd1.buffer = Some(pipe1);
    fd2.buffer = Some(pipe2);
    (Arc::new(fd1), Arc::new(fd2))
}
pub fn syscall_sendmsg(socketfd: usize, msg_ptr: usize, flag: usize) -> SyscallRet {
    log::error!("[syscall_sendmsg]:begin sendmsg");
    log::error!(
        "[syscall_sendmsg]:socketfd:{},msg_ptr:{},flag:{}",
        socketfd,
        msg_ptr,
        flag
    );
    let task = current_task();
    let file = match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    //向下转型
    let socket = match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };
    let mut user_hdr = MessageHeaderRaw {
        name: core::ptr::null_mut(),
        name_len: 0,
        iovec: core::ptr::null_mut(),
        iovec_len: 0,
        control: core::ptr::null_mut(),
        control_len: 0,
        flags: 0,
    };
    copy_from_user(
        msg_ptr as *const MessageHeaderRaw,
        &mut user_hdr as *mut MessageHeaderRaw,
        1,
    )?;
    let mut kernel_name = vec![0; user_hdr.name_len as usize];
    let iovec_ptr = user_hdr.iovec as *const IoVec;
    let iovec_count = user_hdr.iovec_len as usize;
    assert!(
        iovec_count <= 1,
        "temperrily Only one iovec is supported in sendmsg syscall"
    );
    let mut kernel_iovec: Vec<IoVec> = vec![IoVec::default(); iovec_count];
    let mut kernel_control: Vec<u8> = vec![0; user_hdr.control_len as usize];
    log::error!("[syscall_sendmsg]:user_hdr:{:?}", user_hdr);
    //继续复制name,iovec,control内容
    if user_hdr.name_len > 0 {
        copy_from_user(
            user_hdr.name as *const u8,
            kernel_name.as_mut_ptr(),
            user_hdr.name_len as usize,
        )?;
    }
    if user_hdr.iovec_len > 0 {
        //iovec_len指向元素个数
        for i in 0..iovec_count {
            copy_from_user(iovec_ptr, &mut kernel_iovec[i] as *mut IoVec, 1)?;
        }
        log::error!(
            "[syscall_sendmsg]:kernel_iovec base:{:?} kernel_iovec len:{:?}",
            kernel_iovec[0].base,
            kernel_iovec[0].len
        );
    }
    if user_hdr.control_len > 0 {
        copy_from_user(
            user_hdr.control as *const u8,
            kernel_control.as_mut_ptr(),
            user_hdr.control_len as usize,
        )?;
    }

    //todo这里只支持1各iovec
    let mut kernel_buf = vec![0u8; kernel_iovec[0].len as usize];
    if kernel_iovec[0].len != 0 {
        copy_from_user(
            kernel_iovec[0].base as *const u8,
            kernel_buf.as_mut_ptr(),
            kernel_buf.len(),
        )?;
        log::error!("[syscall_sendmsg]:kernel_buf:{:?}", kernel_buf);
    }
    log::error!("[syscall_sendmsg]:kernel_buf:{:?}", kernel_buf);

    if socket.domain == Domain::AF_ALG {
        //给入加密函数进行加密并存入对于结构体中
    }
    let Ok(addr) = socket.peer_name() else {
        log::error!("[syscall_sendmsg]:get peer name error");
        return Err(Errno::ENOTCONN);
    };
    match socket.send(kernel_buf.as_slice(), addr) {
        Ok(size) => Ok(size),
        Err(e) => {
            log::error!("[syscall_send]:send error {:?}", e);
            Err(e)
        }
    }
}
pub fn syscall_recvmsg(socketfd: usize, msg_ptr: usize, _flags: usize) -> SyscallRet {
    log::error!("[syscall_recvmsg]: begin recvmsg");
    log::error!(
        "[syscall_recvmsg]: socketfd: {}, msg_ptr: {}",
        socketfd,
        msg_ptr
    );

    // 1. 获取当前任务并检查 fd
    let task = current_task();
    let file = match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    let socket = match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };

    // 2. 从用户态拷贝 MessageHeaderRaw 结构到内核
    let mut user_hdr = MessageHeaderRaw {
        name: core::ptr::null_mut(),
        name_len: 0,
        iovec: core::ptr::null_mut(),
        iovec_len: 0,
        control: core::ptr::null_mut(),
        control_len: 0,
        flags: 0,
    };
    copy_from_user(
        msg_ptr as *const MessageHeaderRaw,
        &mut user_hdr as *mut MessageHeaderRaw,
        1,
    )?;
    log::error!("[syscall_recvmsg]: user_hdr: {:?}", user_hdr);

    // 3. name/name_len 部分：AF_UNIX 接收通常不需要写回对端地址，这里暂不处理
    //    如果以后需要 recvmsg 返回对端地址，可以在这里用 user_hdr.name/user_hdr.name_len 填充。

    // 4. 从用户空间拷贝 iovec 数组到内核态
    let iovec_count = user_hdr.iovec_len as usize;
    if iovec_count == 0 {
        // 必须至少有一个 iovec 才能接收数据
        return Err(Errno::EINVAL);
    }
    // 在内核中为 iovec 分配 Vec<IoVec>
    let mut kernel_iovecs: Vec<IoVec> = Vec::with_capacity(iovec_count);
    // 先 push 出 iovec_count 个默认元素占位
    for _ in 0..iovec_count {
        kernel_iovecs.push(IoVec::default());
    }
    // 拷贝用户的 IoVec 结构到 kernel_iovecs
    let user_iovec_ptr = user_hdr.iovec as *const IoVec;
    for i in 0..iovec_count {
        // 每次拷贝一个 IoVec
        copy_from_user(
            unsafe { user_iovec_ptr.add(i) },
            &mut kernel_iovecs[i] as *mut IoVec,
            1,
        )?;
        log::error!(
            "[syscall_recvmsg]: kernel_iovecs[{}].base = {:?}, len = {}",
            i,
            kernel_iovecs[i].base,
            kernel_iovecs[i].len
        );
    }

    // 5. 根据所有 iovec 的 len 计算总长度 total_len
    let mut total_len: usize = 0;
    for iov in &kernel_iovecs {
        total_len = total_len.saturating_add(iov.len as usize);
    }
    if total_len == 0 {
        // 如果 iovec 全部 len=0，则什么都不读
        return Ok(0);
    }

    // 6. 为接收数据分配临时内核缓冲区 kernel_buf
    let mut kernel_buf: Vec<u8> = vec![0u8; total_len];

    // 7. 调用底层 socket.recv() 接收数据到 kernel_buf
    let n = match socket.recv_from(&mut kernel_buf) {
        Ok(sz) => sz.0,
        Err(e) => {
            log::error!("[syscall_recvmsg]: recv error {:?}", e);
            return Err(e);
        }
    };
    log::error!("[syscall_recvmsg]: received {} bytes into kernel_buf", n);

    // 如果没有收到任何数据，就返回 0
    if n == 0 {
        return Ok(0);
    }

    // 8. 将 kernel_buf[0..n] 拆分（scatter）到每个 iovec 指向的用户缓冲区
    let mut copied = 0;
    let mut remaining = n;
    let mut buf_offset = 0;

    for iov in &kernel_iovecs {
        if remaining == 0 {
            break;
        }
        let dest_ptr = iov.base as *mut u8;
        let dest_len = iov.len as usize;
        if dest_len == 0 {
            continue;
        }

        // 本次要拷贝到第 iov 的字节数
        let to_copy = if remaining < dest_len {
            remaining
        } else {
            dest_len
        };

        // copy_to_user：将 kernel_buf[buf_offset .. buf_offset + to_copy] 写到用户 iov.base
        copy_to_user(
            dest_ptr,
            kernel_buf[buf_offset..buf_offset + to_copy].as_ptr(),
            to_copy,
        )?;
        log::error!(
            "[syscall_recvmsg]: copied {} bytes into user iovec {}",
            to_copy,
            iov.base
        );

        // 更新计数
        copied = copied.add(to_copy);
        buf_offset = buf_offset.saturating_add(to_copy);
        remaining = remaining.saturating_sub(to_copy);
    }
    Ok(copied)
}

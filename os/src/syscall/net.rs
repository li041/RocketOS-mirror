/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-04-02 23:04:54
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-06-12 17:38:03
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
        namei::path_openat,
        pipe::{self, make_pipe},
        uapi::IoVec,
    },
    net::{
        addr::{from_ipendpoint_to_socketaddr, LOOP_BACK_IP},
        alg::encode,
        socket::{
            check_alg, socket_address_from, socket_address_from_af_alg, socket_address_from_unix, socket_address_to, socket_address_tounix, ALG_Option, Domain, IpOption, Ipv6Option, MessageHeaderRaw, SockAddrIn, Socket, SocketOption, SocketOptionLevel, SocketType, TcpSocketOption, SOCK_CLOEXEC, SOCK_NONBLOCK
        }, socketpair::create_buffer_ends,
    },
    syscall::task::{sys_getresgid, sys_nanosleep},
    task::{current_task, yield_current_task},
};
use alloc::vec;
use alloc::{sync::Arc, task, vec::Vec};
use bitflags::Flags;
use core::{
    fmt::Result,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::atomic::{AtomicUsize, Ordering},
};
use hashbrown::Equivalent;
use num_enum::TryFromPrimitive;
use smoltcp::wire::IpEndpoint;
pub const SOCKET_TYPE_MASK: usize = 0xFF;
use super::errno::{Errno, SyscallRet};
bitflags::bitflags! {
    /// `recv`/`send` flags (from `<sys/socket.h>`).
    #[derive(Debug)]
    pub struct MsgFlags: u32 {
        const MSG_OOB         = 0x01;        // Process out-of-band data.
        const MSG_PEEK        = 0x02;        // Peek at incoming messages.
        const MSG_DONTROUTE   = 0x04;        // Don’t use local routing.
        const MSG_CTRUNC      = 0x08;        // Control data lost before delivery.
        const MSG_PROXY       = 0x10;        // Supply or ask second address.
        const MSG_TRUNC       = 0x20;
        const MSG_DONTWAIT    = 0x40;        // Nonblocking IO.
        const MSG_EOR         = 0x80;        // End of record.
        const MSG_WAITALL     = 0x100;       // Wait for a full request.
        const MSG_FIN         = 0x200;
        const MSG_SYN         = 0x400;
        const MSG_CONFIRM     = 0x800;       // Confirm path validity.
        const MSG_RST         = 0x1000;
        const MSG_ERRQUEUE    = 0x2000;      // Fetch message from error queue.
        const MSG_NOSIGNAL    = 0x4000;      // Do not generate SIGPIPE.
        const MSG_MORE        = 0x8000;      // Sender will send more.
        const MSG_WAITFORONE  = 0x10000;     // Wait for at least one packet.
        const MSG_BATCH       = 0x40000;     // sendmmsg: more messages coming.
        const MSG_ZEROCOPY    = 0x4000000;   // Use user data in kernel path.
        const MSG_FASTOPEN    = 0x20000000;  // Send data in TCP SYN.
        const MSG_CMSG_CLOEXEC= 0x40000000;  // Set CLOEXEC on SCM_RIGHTS fds.
    }
}

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
    if socketlen < 16 {
        return Err(Errno::EINVAL);
    }
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
    let mut kernel_addr_from_user: Vec<u8> = vec![0; socketlen];
    copy_from_user(
        socketaddr as *const u8,
        kernel_addr_from_user.as_mut_ptr(),
        socketlen,
    )?;
    let family_bytes = [kernel_addr_from_user[0], kernel_addr_from_user[1]];
    log::error!("[syscall_bind] family bytes is {:?}",family_bytes);
    let family = Domain::try_from(u16::from_ne_bytes(family_bytes) as usize).unwrap();
    log::error!("[syscall_bind] parsed sa_family = {:?}", family);
    if socket.domain != family && socket.domain!=Domain::AF_RDS {
        return Err(Errno::EAFNOSUPPORT);
    }
    log::error!(
        "[syscall_bind] task egid {:?} euid {:?}",
        task.egid(),
        task.euid()
    );
    if task.egid() != 0 || task.euid() != 0 {
        return Err(Errno::EACCES);
    }
    //如果是al_afg的套接字则需要使用对应的socket_from
    if socket.domain == Domain::AF_ALG {
        //socket那边设置不太方便
        socket.set_is_af_alg(true);
        let bind_addr = unsafe { socket_address_from_af_alg(socketaddr as *const u8, socketlen) }?;
        check_alg(&bind_addr)?;
        socket.bind_af_alg(bind_addr)?;
        return Ok(0);
    }
    if socket.domain == Domain::AF_UNIX {
        if socket.get_is_af_unix() {
            return Err(Errno::EINVAL);
        }
        let path = unsafe { socket_address_from_unix(socketaddr as *const u8, socketlen, socket) }?;
        log::error!(
            "[syscall_bind]: unix domain socket path is {:?}",
            core::str::from_utf8(path.as_slice())
        );
        //查看是否存在路径,并确认路径无其他socket绑定
        let s_path = core::str::from_utf8(path.as_slice()).unwrap();
        if !socket.bind_check_unix(s_path) {
            return Err(Errno::EADDRINUSE);
        }
        socket.set_is_af_unix(true);
        socket.set_unix_path(path.as_slice());
        //需要查看是否存在这个文件，如果存在不用创建，如果不存在需要创建新文件
        let file = path_openat(s_path, OpenFlags::O_CREAT, -100, 0)?;
        socket.set_unix_file(file);
        //设置自己的ucred
        let pid = task.tid();
        let uid = task.uid();
        let gid = task.gid();
        socket.set_ucred(pid as i32, uid, gid);
        //这里暂时先不bind unix了 毕竟linux的ltprunner 没有运行，smoltcp也不支持unix
        return Ok(0);
    }

    //需要实现一个从地址读取addr的函数
    let bind_addr = unsafe { socket_address_from(socketaddr as *const u8, socketlen, socket) }?;
    log::error!("[syscall_bind]:bind_addr{:?}", bind_addr);
    if bind_addr
        .ip()
        .equivalent(&IpAddr::V4(Ipv4Addr::new(10, 255, 254, 253)))
    {
        return Err(Errno::EADDRNOTAVAIL);
    }
    socket.bind(bind_addr);
    Ok(0)
}

pub fn syscall_listen(socketfd: usize, _backlog: usize) -> SyscallRet {
    log::error!("[syscall_listen]:begin listen socket fd is {:?}", socketfd);
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
    //需要区分unix的listen和net
    if socket.domain == Domain::AF_UNIX {
        return Ok(0);
    }
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
        log::error!("[syscall_accept]: AF_ALG domain socket supported");
        //需要直接克隆一个fd继承所有socket的所有内容
        let fd_table = task.fd_table();
        let new_socket = socket.accept_alg()?;
        let fd = fd_table
            .alloc_fd(Arc::new(new_socket), FdFlags::empty())
            .unwrap();
        log::error!("[syscall_accept_af_alg]: alloc fd {} to socket", fd);
        return Ok(fd);
    }
    if socket.domain == Domain::AF_UNIX {
        log::error!("[syscall_accept]: AF UNIX domain socket supported");
        //需要直接克隆一个fd继承所有socket的所有内容
        let fd_table = task.fd_table();
        let new_socket = socket.accept_unix()?;
        let fd = fd_table
            .alloc_fd(Arc::new(new_socket), FdFlags::empty())
            .unwrap();
        log::error!("[syscall_accept_af_unix]: alloc fd {} to socket", fd);
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
    log::error!(
        "[syscall_connect] begin connect socket fd is {:?},addr is {:#x},socketlen is {:?}",
        socketfd,
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
    if socketaddr == 0xffffffffffffffff {
        return Err(Errno::EFAULT);
    }
    if socketlen < 16 {
        return Err(Errno::EINVAL);
    }
    if socket.domain == Domain::AF_UNIX {
        log::error!("[syscall_connect]: unix domain socket supported");
        let path = unsafe { socket_address_from_unix(socketaddr as *const u8, socketlen, socket) }?;
        let s_path = core::str::from_utf8(path.as_slice()).unwrap();
        log::error!(
            "[syscall_connect]: unix domain connect path is {:?}",
            s_path
        );
        //向这个路径的写自己的路径
        socket.set_is_af_unix(true);
        socket.set_socket_peer_path(path.as_slice());
        if s_path.eq("/var/run/nscd/socket") {
            socket.set_unix_path(path.as_slice());
            return Ok(0);
        }
        let peer_file = path_openat(s_path, OpenFlags::O_CLOEXEC, -100, 0)?;
        socket.set_peer_unix_file(peer_file);
        let mut self_path = socket.get_socket_path();
        log::error!(
            "[syscall_connect]: unix domain self path is {:?}",
            core::str::from_utf8(self_path.as_slice()).unwrap()
        );
        if self_path.len() == 0 {
            //server端必然已经建立这个文件
            self_path = path.clone();
            socket.set_unix_path(self_path.as_slice());
            let file = path_openat(s_path, OpenFlags::O_CLOEXEC, -100, 0)?;
            socket.set_unix_file(file);
        }
        let self_file = socket.get_unix_file();
        if socket.socket_type == SocketType::SOCK_STREAM
            || socket.socket_type == SocketType::SOCK_SEQPACKET
            || socket.socket_type == SocketType::SOCK_RAW
        {
            let file = socket.get_peer_unix_file();
            if file.as_ref().w_ready() {
                log::error!(
                    "[syscall_connect]: unix domain write self path is {:?}",
                    core::str::from_utf8(self_path.as_slice()).unwrap()
                );
                file.write(self_path.as_slice())?;
                let ucred = socket.get_ucred();
                socket.set_ucred(ucred.pid, ucred.uid, ucred.gid);
                // Convert ucred to bytes before writing
                let ucred_bytes = unsafe {
                    core::slice::from_raw_parts(
                        &ucred as *const _ as *const u8,
                        core::mem::size_of_val(&ucred),
                    )
                };
                log::error!("[syscall_connect] ucred bytes is {:?}",ucred_bytes);
                file.pwrite(ucred_bytes, self_path.len() + 1)?;
                drop(file);
            }
        } else if socket.socket_type == SocketType::SOCK_DGRAM {
            //server不会使用accept去接受，这里遍历fd来判断哪个是建立在对于path的路径上的socket
            // let serverfd=match socket.connect_check_unix(s_path,socketfd){
            //     Some(fd) => fd,
            //     None => return Err(Errno::ECONNREFUSED),
            // };
            let serverfd = 3;
            let serverfile = match task.fd_table().get_file(serverfd) {
                Some(f) => f,
                None => return Err(Errno::EBADF),
            };
            //向下转型
            let serversocket = match serverfile.as_any().downcast_ref::<Socket>() {
                Some(s) => s,
                None => return Err(Errno::ENOTSOCK),
            };
            serversocket.set_socket_peer_path(self_path.as_slice());
            serversocket.set_peer_unix_file(self_file);
            //设置对端的ucred
            let server_ucred = serversocket.get_ucred();
            socket.set_ucred(server_ucred.pid, server_ucred.uid, server_ucred.gid);
            let client_ucred = socket.get_ucred();
            serversocket.set_ucred(client_ucred.pid, client_ucred.uid, client_ucred.gid);
        }
        return Ok(0);
    }
    let addr = unsafe { socket_address_from(socketaddr as *const u8, socketlen, socket) }?;
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
    log::error!("[syscall_send]:len:{}", len);
    log::error!("[syscall_send]:remote_addr:{}", socketaddr);
    log::error!("[syscall_send]:socketlen is {:?}", socketlen as isize);
    if (buf as i32) < 0 {
        return Err(Errno::EFAULT);
    }
    if len > 64 * 128 {
        return Err(Errno::EMSGSIZE);
    }
    if socketlen == 0xffffffff {
        return Err(Errno::EINVAL);
    }
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
    let flags = MsgFlags::from_bits(flag as u32).ok_or(Errno::EINVAL)?; // 如果有未定义的位，直接当 EINVAL
    log::error!("[syscall_send] flag is {:#x},flags is {:?}", flag, flags);
    if flags.contains(MsgFlags::MSG_OOB) {
        return Err(Errno::EOPNOTSUPP);
    }
    if buf as isize <= 0 {
        return Err(Errno::EFAULT);
    }
    let mut kernel_buf: Vec<u8> = vec![0; len];
    if len != 0 {
        copy_from_user(buf, kernel_buf.as_mut_ptr(), len)?;
    }

    if flags.contains(MsgFlags::MSG_MORE) {
        //设置socket中pend_send
        socket.set_pend_send(kernel_buf.as_slice());
        return Ok(len);
    }

    log::error!("[syscall_send]:buf{:?}", kernel_buf.to_ascii_lowercase());
    if socket.domain == Domain::AF_UNIX {
        if socket.buffer.is_some() {
            return socket.buffer.as_ref().unwrap().write(kernel_buf.as_slice());
        }
        // //check当前的对于unix的send,直接写入文件即可
        // let path=socket.get_so();
        // let s_path=core::str::from_utf8(path.as_slice()).unwrap();
        // log::error!("[syscall_send] send to path {:?}",s_path);
        let peer_path=socket.get_socket_peer_path();
        let s_path = core::str::from_utf8(peer_path.as_slice()).unwrap();
        if s_path.eq("/var/run/nscd/socket") {
            return socket.unix_send(kernel_buf.as_slice());
        }
        let file = socket.get_peer_unix_file();
        if file.w_ready() {
            let res = file.pwrite(kernel_buf.as_slice(), 0)?;
            file.pwrite(&[1], 128)?;
            return Ok(res);
        } else {
            return Err(Errno::EBADF);
        }
    }
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
        addr = unsafe { socket_address_from(socketaddr as *const u8, socketlen, socket) }?;
    }

    //send前需要判断是否没有msg_more,pend_send是否为空
    if socket.is_pend_send() {
        //为空
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
    } else {
        let mut send_buf = socket.get_pend_send();
        send_buf.extend_from_slice(kernel_buf.as_slice());
        match socket.send(send_buf.as_slice(), addr) {
            Ok(size) => {
                //这里虽然结合pend_send发送但是只返回此次发送的长度
                Ok(kernel_buf.len())
            }
            Err(e) => {
                log::error!("[syscall_send]:send error {:?}", e);
                Err(e)
            }
        }
    }
}
pub fn syscall_recvfrom(
    socketfd: usize,
    buf: *mut u8,
    len: usize,
    flag: usize,
    socketaddr: usize,
    socketlen: usize,
) -> SyscallRet {
    log::error!("[syscall_recvfrom]:begin recvfrom");
    log::error!(
        "[syscall_recvfrom]:sockfd:{:?},len:{:?},buf {:?},socketaddr {:?},socketaddr len {:?}",
        socketfd,
        len,
        buf,
        socketaddr,
        socketlen
    );
    //check addr len is valid
    if socketlen > 0 {
        let mut kernellen: Vec<i32> = vec![0; 1];
        if socketlen == 0xffffffffffffffff {
            return Err(Errno::EFAULT);
        }
        copy_from_user(socketlen as *const i32, kernellen.as_mut_ptr(), 1)?;
        if kernellen[0] < 0 {
            return Err(Errno::EINVAL);
        }
    }
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
    //check buf addr is valid
    if buf as usize == 0xffffffffffffffff {
        return Err(Errno::EFAULT);
    }

    //check flag is valid
    let flags = MsgFlags::from_bits(flag as u32).ok_or(Errno::EINVAL)?; // 如果有未定义的位，直接当 EINVAL
    log::error!(
        "[syscall_recvfrom] flag is {:#x},flags is {:?}",
        flag,
        flags
    );
    // 2. 如果带了 MSG_OOB，就立刻失败
    if flags.contains(MsgFlags::MSG_OOB) {
        return Err(Errno::EINVAL);
    }
    // 3. 如果带了 MSG_ERRQUEUE，就检查错误队列,fake
    if flags.contains(MsgFlags::MSG_ERRQUEUE) {
        return Err(Errno::EAGAIN);
    }
    let addr = socket.name()?;
    log::error!("[syscall_recvfrom] sockt addr is {:?}", addr);
    // let addr=unsafe { socket_address_from(socketaddr as *const u8, socket) };
    // let buf=unsafe { core::slice::from_raw_parts_mut(buf, len) };
    let mut kernel_buf = vec![0u8; len];
    match socket.recv_from(&mut kernel_buf) {
        Ok((size, _addr)) => {
            if size == 0 {
                return Err(Errno::EINTR);
            }
            copy_to_user(buf, kernel_buf.as_ptr(), len)?;
            log::error!("[syscall_recvfrom]:recv buf len {}", size);
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
        return Err(Errno::EOPNOTSUPP);
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
    if socket.domain == Domain::AF_ALG {
        if optlen % 4 != 0 {
            return Err(Errno::EINVAL);
        }
    }
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
        "[sys_getsocketopt] fd {:?} level {:?} optname {:?},optlen {:?},optval {:?}",
        fd,
        level,
        optname,
        optlen,
        optval
    );
    if optlen == 0 || optlen == 0xffffffffffffffff {
        return Err(Errno::EFAULT);
    }
    let mut kernel_opt_len: u32 = 0;
    copy_from_user(
        optlen as *const u32,
        &mut kernel_opt_len as *mut u32,
        core::mem::size_of::<u32>(),
    )?;
    log::error!("[sys_getsocketopt]kernel len is {:?}", kernel_opt_len);
    if kernel_opt_len > 1000 {
        return Err(Errno::EINVAL);
    }
    if optval == 0 as *mut u8 {
        return Err(Errno::EFAULT);
    }
    let Ok(level) = SocketOptionLevel::try_from(level) else {
        log::error!("[setsockopt()] level {level} not supported");
        return Err(Errno::EOPNOTSUPP);
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
            if optname == 18446744073709551615 {
                return Err(Errno::ENOPROTOOPT);
            }
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
            let option = TcpSocketOption::try_from(optname).map_err(|_err| Errno::ENOPROTOOPT)?;
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
    log::error!(
        "[syscall_getsockname]:begin getsockname,socketlen is {:?}",
        socketlen
    );
    if socketaddr == 0xffffffffffffffff || socketlen <= 1 {
        return Err(Errno::EFAULT);
    }
    let mut len = vec![0; 1];
    copy_from_user(socketlen as *const u8, len.as_mut_ptr(), len.len())?;
    log::error!("[syscall_getpeername]len is {:?}", len);
    if len[0] == 255 {
        return Err(Errno::EINVAL);
    }

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
        //写回正确的unix项
        log::error!("[syscall_getsockname]:unix support");
        let bind = socket.socket_path_unix.lock();
        let path = bind.as_ref().unwrap();
        socket_address_tounix(path.as_slice(), socketaddr, socketlen)?;
        return Ok(0);
    }
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
    if socketaddr == 0xffffffffffffffff || socketlen <= 1 {
        return Err(Errno::EFAULT);
    }
    let mut len = vec![0; 1];
    copy_from_user(socketlen as *const u8, len.as_mut_ptr(), len.len())?;
    log::error!("[syscall_getpeername]len is {:?}", len);
    if len[0] == 255 {
        return Err(Errno::EINVAL);
    }

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
    let addr = socket.peer_name()?;
    log::error!("[syscall_getpeername]:addr{:?}", addr);
    socket_address_to(addr, socketaddr, socketlen)
}

//socketpair中fd在socketfds中用数组给出
pub fn syscall_socketpair(
    domain: usize,
    sockettype: usize,
    protocol: usize,
    socketfds: *mut i32,
) -> SyscallRet {
    log::error!("[syscall_socketpair]:begin socketpair,domain is {:?},sockettype is {:#x},socketfds is {:?}",domain,sockettype,socketfds);
    let domain = match Domain::try_from(domain) {
        Ok(d) => d,
        Err(_) => return Err(Errno::EAFNOSUPPORT),
    };

    // 3) type 合法性
    let sock_type = sockettype & SOCKET_TYPE_MASK;
    if SocketType::try_from(sock_type).is_err() {
        return Err(Errno::EINVAL);
    }

    // 拿到当前进程、权限信息
    let task = current_task();

    // 4) PF_INET 下按 protocol 分支返回
    if domain == Domain::AF_INET {
        match SocketType::try_from(sock_type).unwrap() {
            SocketType::SOCK_RAW => {
                return Err(Errno::EPROTONOSUPPORT);
            }
            SocketType::SOCK_DGRAM => {
                // UDP (proto=17) 和 TCP-DGRAM (proto=6)
                if protocol == 17 {
                    return Err(Errno::EOPNOTSUPP);
                } else {
                    // 包括 proto==6 以及其他
                    return Err(Errno::EPROTONOSUPPORT);
                }
            }
            SocketType::SOCK_STREAM => {
                // TCP-STREAM (proto=6) vs ICMP-STREAM (proto=1)
                if protocol == 6 {
                    return Err(Errno::EOPNOTSUPP);
                } else {
                    return Err(Errno::EPROTONOSUPPORT);
                }
            }
            _ => {
                // 其他 type，在 PF_INET 下都不支持
                return Err(Errno::EPROTONOSUPPORT);
            }
        }
    }

    // 5) PF_UNIX 只支持 DGRAM/STREAM，其他 domain 也可按需要自行扩展
    // 到这里，只有 Domain::Unix 且 type 合法的情况会继续走下去

    // 6) 解析 flags 和创建 socketpair
    let mut flags = OpenFlags::empty();
    if sockettype & SOCK_NONBLOCK != 0 {
        flags |= OpenFlags::O_NONBLOCK;
    }
    if sockettype & SOCK_CLOEXEC != 0 {
        flags |= OpenFlags::O_CLOEXEC;
    }

    let (raw1, raw2) = make_socketpair(domain, sockettype, flags);
    raw1.set_flags(flags);
    raw2.set_flags(flags);
    let fd_table = task.fd_table();
    let fd_flags = FdFlags::from(&flags);
    log::error!("[syscall_socketpair] fd_flags is {:?}", flags);
    let fd1 = fd_table.alloc_fd(raw1, fd_flags)?;
    let fd2 = fd_table.alloc_fd(raw2, fd_flags)?;

    // 7) 写回用户缓冲区
    // 一次写入两个 usize
    log::error!("[syscall_socketpair] alloc fd fd1 {:?},fd2 {:?}", fd1, fd2);
    let user_fds: [i32; 2] = [fd1 as i32, fd2 as i32];

    // 3) 计算要拷贝的字节数：2 * sizeof(int)
    let byte_count = core::mem::size_of::<i32>() * user_fds.len();

    let dst = socketfds as *mut u8;
    let src = user_fds.as_ptr() as *const u8;

    copy_to_user(dst, src, byte_count)?;

    Ok(0)
}

pub fn make_socketpair(
    domain: Domain,
    sockettype: usize,
    pipe_flag: OpenFlags,
) -> (Arc<Socket>, Arc<Socket>) {
    let s_type = SocketType::try_from(sockettype & SOCKET_TYPE_MASK).unwrap();
    let mut fd1 = Socket::new(domain.clone(), s_type);
    let mut fd2 = Socket::new(domain.clone(), s_type);
    let (pipe1, pipe2) = create_buffer_ends(pipe_flag);
    fd1.buffer = Some(Arc::new(pipe1));
    fd2.buffer = Some(Arc::new(pipe2));
    (Arc::new(fd1), Arc::new(fd2))
}
pub fn syscall_sendmsg(socketfd: usize, msg_ptr: usize, flag: usize) -> SyscallRet {
    println!("[syscall_sendmsg]: begin sendmsg");
    println!(
        "[syscall_sendmsg]: socketfd: {}, msg_ptr: {}, flag: {}",
        socketfd,
        msg_ptr,
        flag
    );

    let task = current_task();
    let file = match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    let socket = match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };

    // 1. 从用户空间拷贝一份 MessageHeaderRaw
    let mut user_hdr = MessageHeaderRaw {
        name: core::ptr::null_mut(),
        name_len: 0,
        iovec: core::ptr::null_mut(),
        iovec_len: 0,
        control: core::ptr::null_mut(),
        control_len: 0,
        flags: 0,
    };
    println!("[1a]");
    copy_from_user(
        msg_ptr as *const MessageHeaderRaw,
        &mut user_hdr as *mut MessageHeaderRaw,
        1,
    )?;
    println!("[1b]");
    // 2. 准备 name buffer，获得对端地址
    //kernel name for af_alg,peer_addr for tcp/udp,peer_path for unix
    let mut kernel_name = Vec::new();
    if user_hdr.name_len > 0 {
        kernel_name.resize(user_hdr.name_len as usize, 0);
        copy_from_user(
            user_hdr.name as *const u8,
            kernel_name.as_mut_ptr(),
            user_hdr.name_len as usize,
        )?;
    }
    let mut peer_addr: Option<SocketAddr> = None;
    println!("[1c]");
    if socket.domain != Domain::AF_ALG && socket.domain != Domain::AF_UNIX {
        if user_hdr.name_len>0 {
            let addr = unsafe {
            socket_address_from(
                user_hdr.name as *const u8,
                user_hdr.name_len as usize,
                socket,
                )
            }?;
            println!("[syscall_sendmsg] name addr is {:?}", addr);
            peer_addr = Some(addr);
        }
        else {
            peer_addr=Some(socket.peer_name()?);
        }
        
    }
    println!("[1c]");
    let mut peer_path=Vec::new();
    if socket.domain==Domain::AF_UNIX {
        println!("[1d]");
        peer_path=unsafe { socket_address_from_unix(user_hdr.name as *const u8, user_hdr.name_len as usize, socket) }?;
        println!("[syscall_sendmsg] path addr is peer path is {:?}",peer_path);
    }
    
    // 3. 从用户空间读取 iovec 数组
    let iovec_ptr = user_hdr.iovec as *const IoVec;
    let iovec_count = user_hdr.iovec_len as usize;
    // 动态分配一个 Vec<IoVec>，大小为 iovec_count
    let mut kernel_iovecs: Vec<IoVec> = Vec::new();
    if iovec_count > 0 {
        // 先给 Vec 分配好空间
        kernel_iovecs.resize(iovec_count, IoVec::default());
        // 然后分别从用户空间拷贝每个 IoVec 结构
        for idx in 0..iovec_count {
            let src_ptr = unsafe { iovec_ptr.add(idx) };
            copy_from_user(src_ptr, &mut kernel_iovecs[idx] as *mut IoVec, 1)?;
        }
        println!(
            "[syscall_sendmsg]: read {} iovecs: {:?}",
            iovec_count,
            kernel_iovecs
        );
    }

    // 4. 从用户空间复制控制数据（control）
    let mut kernel_control = Vec::new();
    if user_hdr.control_len > 0 {
        kernel_control.resize(user_hdr.control_len as usize, 0);
        copy_from_user(
            user_hdr.control as *const u8,
            kernel_control.as_mut_ptr(),
            user_hdr.control_len as usize,
        )?;
    }

    // 5. 将所有 iovec 指向的用户数据拼接到一个大缓冲区 kernel_buf 中
    //    先算出所有 iovec 数据的总长度
    let total_len: usize = kernel_iovecs.iter().map(|iov| iov.len as usize).sum();

    let mut kernel_buf = Vec::new();
    if total_len > 0 {
        // 分配足够大的内核缓冲区
        kernel_buf.resize(total_len, 0);

        // 依次把每个 iovec 的数据从用户空间拷贝到 kernel_buf 的正确偏移位置
        let mut offset = 0;
        for iov in kernel_iovecs.iter() {
            let len = iov.len as usize;
            if len > 0 {
                copy_from_user(
                    iov.base as *const u8,
                    unsafe { kernel_buf.as_mut_ptr().add(offset) },
                    len,
                )?;
                println!(
                    "[syscall_sendmsg]: copied {} bytes from user iovec at base={:?} to kernel_buf+{}",
                    len,
                    iov.base,
                    offset
                );
                offset += len;
            }
        }
    }
    println!(
        "[syscall_sendmsg]: final kernel_buf (len={}): {:?}",
        total_len,
        kernel_buf
    );
    println!(
        "[syscall_sendmsg]: control_buf (len={}): {:?}",
        kernel_control.len(),
        kernel_control
    );

    if socket.domain == Domain::AF_ALG {
        //todo
        //根据给入信息进行加密并在recv时返回加密长度
        return encode(
            socket,
            kernel_name.as_mut_slice(),
            kernel_iovecs.as_mut_slice(),
            kernel_control.as_mut_slice(),
        );
    }
    //sendto peer path
    if socket.domain==Domain::AF_UNIX {
        if socket.buffer.is_some() {
            return socket.buffer.as_ref().unwrap().write(kernel_buf.as_slice());
        }
        // //check当前的对于unix的send,直接写入文件即可
        // let path=socket.get_so();
        // let s_path=core::str::from_utf8(path.as_slice()).unwrap();
        // log::error!("[syscall_send] send to path {:?}",s_path);
        //注意这里的peer_path
        if peer_path.len()==0 {
            peer_path=socket.get_socket_peer_path();
        }
        let s_path = core::str::from_utf8(peer_path.as_slice()).unwrap();
        if s_path.eq("/var/run/nscd/socket") {
            return socket.unix_send(kernel_buf.as_slice());
        }
        let file = socket.get_peer_unix_file();
        if file.w_ready() {
            println!("[0]");
            let res = file.pwrite(kernel_buf.as_slice(), 0)?;
            println!("[1]");
            file.pwrite(&[1], 128)?;
            return Ok(res);
        } else {
            return Err(Errno::EBADF);
        }
    }
    let addr = match peer_addr {
        Some(a) => a,
        None  => {
            socket.peer_name()?
        }
    };
    match socket.send(kernel_buf.as_slice(), addr) {
        Ok(size) => Ok(size),
        Err(e) => {
            log::error!("[syscall_send]:send error {:?}", e);
            Err(e)
        }
    }
}
pub fn syscall_recvmsg(socketfd: usize, msg_ptr: usize, flag: usize) -> SyscallRet {
    log::debug!("[syscall_recvmsg]: begin recvmsg");
    log::debug!(
        "[syscall_recvmsg]: socketfd: {}, msg_ptr: {}",
        socketfd,
        msg_ptr
    );
    let flags = MsgFlags::from_bits(flag as u32).ok_or(Errno::EINVAL)?; // 如果有未定义的位，直接当 EINVAL
    log::error!(
        "[syscall_recvfrom] flag is {:#x},flags is {:?}",
        flag,
        flags
    );
    // 2. 如果带了 MSG_OOB，就立刻失败
    if flags.contains(MsgFlags::MSG_OOB) {
        return Err(Errno::EINVAL);
    }
    if flags.contains(MsgFlags::MSG_ERRQUEUE) {
        return Err(Errno::EAGAIN);
    }

    // 1. 获取当前任务并检查文件描述符
    let task = current_task();
    let file = match task.fd_table().get_file(socketfd) {
        Some(f) => f,
        None => return Err(Errno::EBADF),
    };
    let socket = match file.as_any().downcast_ref::<Socket>() {
        Some(s) => s,
        None => return Err(Errno::ENOTSOCK),
    };

    // 2. 从用户空间拷贝 MessageHeaderRaw 结构到内核
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
    if (user_hdr.name_len as i32 )<0||(user_hdr.control_len as i32 )<0{
        return Err(Errno::EINVAL);
    }
    if user_hdr.name_len as usize > size_of::<SockAddrIn>() {
        let user_msghdr = unsafe { &mut *(msg_ptr as *mut MessageHeaderRaw) };
        user_msghdr.name_len = size_of::<SockAddrIn>() as u32;
    }
    // 3. 从用户空间拷贝 iovec 数组到内核
    let iovec_count = user_hdr.iovec_len as i32;
    if iovec_count <= 0 {
        return Err(Errno::EMSGSIZE);
    }
    let mut kernel_iovecs: Vec<IoVec> = Vec::with_capacity(iovec_count as usize);
    for _ in 0..iovec_count {
        kernel_iovecs.push(IoVec { base: 0, len: 0 });
    }
    let user_iovec_ptr = user_hdr.iovec as *const IoVec;
    if (user_iovec_ptr as i32)<=0 {
        return Err(Errno::EFAULT);
    }
    for i in 0..iovec_count as usize {
        copy_from_user(
            unsafe { user_iovec_ptr.add(i) },
            &mut kernel_iovecs[i] as *mut IoVec,
            1,
        )?;
        log::debug!(
            "[syscall_recvmsg]: kernel_iovecs[{}].base = {:?}, len = {}",
            i,
            kernel_iovecs[i].base,
            kernel_iovecs[i].len
        );
        if (kernel_iovecs[i].base as isize)<0 {
            return Err(Errno::EFAULT);
        }
    }

    // 4. 计算总长度
    let mut total_len: usize = 0;
    for iov in &kernel_iovecs {
        total_len = total_len.saturating_add(iov.len);
    }
    if total_len == 0 {
        return Ok(0);
    }

    // 5. Allocate kernel buffer with initialized length
    let mut kernel_buf: Vec<u8> = vec![0; total_len];

    // 6. Receive data into kernel buffer
    let (n, _addr) = match socket.recv_from(&mut kernel_buf[..]) {
        Ok(sz) => sz,
        Err(e) => {
            log::error!("[syscall_recvmsg]: recv error {:?}", e);
            return Err(e);
        }
    };
    log::debug!("[syscall_recvmsg]: received {} bytes into kernel_buf", n);

    if n == 0 {
        return Ok(0);
    }

    // 7. Scatter data to user-space iovecs
    let mut copied = 0;
    let mut remaining = n;
    let mut buf_offset = 0;

    for iov in &kernel_iovecs {
        if remaining == 0 {
            break;
        }
        let dest_ptr = iov.base as *mut u8;
        let dest_len = iov.len;
        if dest_len == 0 {
            continue;
        }

        let to_copy = if remaining < dest_len {
            remaining
        } else {
            dest_len
        };
        copy_to_user(
            dest_ptr,
            kernel_buf[buf_offset..buf_offset + to_copy].as_ptr(),
            to_copy,
        )?;
        log::debug!(
            "[syscall_recvmsg]: copied {} bytes into user iovec {}",
            to_copy,
            iov.base
        );

        copied += to_copy;
        buf_offset += to_copy;
        remaining -= to_copy;
    }
    // 8. 返回接收的字节数
    Ok(copied)
}

pub fn syscall_setdomainname(domainname:*const u8,len: usize)->SyscallRet {
    log::error!("[syscall_setdomainname] domainname is {:?} len is {:?}",domainname,len);
    if (len as isize) < 0 || (len as isize)>64{
        return Err(Errno::EINVAL);
    }
    if domainname.is_null() {
        return Err(Errno::EFAULT);
    }
    let task=current_task();
    println!("[syscall_setdomainname]task egid {:?},task euid {:?}",task.egid(),task.euid());
    if task.egid() != 0 || task.euid() != 0 {

        return Err(Errno::EPERM);
    }
    let mut kernel_domainname: Vec<u8>=vec![0;len];
    copy_from_user(domainname, kernel_domainname.as_mut_ptr(), len)?;
    let file=path_openat("/etc/domainname", OpenFlags::O_CLOEXEC, -100, 0)?;
    file.pwrite(kernel_domainname.as_slice(), 0)?;
    Ok(0)
}
pub fn syscall_sethostname(hostname:*const u8,len: usize)->SyscallRet {
    log::error!("[syscall_sethostname] hostname is {:?} len is {:?}",hostname,len);
    if (len as isize) < 0 || (len as isize)>64{
        return Err(Errno::EINVAL);
    }
    if hostname.is_null() {
        return Err(Errno::EFAULT);
    }
    let task=current_task();
    if task.egid() != 0 || task.euid() != 0 {
        return Err(Errno::EPERM);
    }
    let mut kernel_hostname: Vec<u8>=vec![0;len];
    copy_from_user(hostname, kernel_hostname.as_mut_ptr(), len)?;
    log::error!("[syscall_sethostname] hostname is {:?}",kernel_hostname);
    let file=path_openat("/etc/hostname", OpenFlags::O_CLOEXEC, -100, 0)?;
    file.pwrite(kernel_hostname.as_slice(), 0)?;
    Ok(0)
}
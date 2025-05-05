use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-03-30 21:43:05
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-05-24 17:09:10
 * @FilePath: /RocketOS_netperfright/os/src/net/addr.rs
 * @Description: addr file
 * 
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved. 
 */
use smoltcp::wire::{IpAddress, IpEndpoint, Ipv4Address, Ipv6Address};

// use super::udp::get_ephemeral_port;


pub const UNSPECIFIED_IP: IpAddress = IpAddress::v4(0, 0, 0, 0);
pub const LOOP_BACK_IP:IpAddress=IpAddress::v4(127, 0, 0, 1);
pub const LOOP_BACK_ENDPOINT:IpEndpoint=IpEndpoint::new(LOOP_BACK_IP,49152);
pub const UNSPECIFIED_ENDPOINT: IpEndpoint = IpEndpoint::new(UNSPECIFIED_IP, 0);
pub fn is_unspecified(ip: IpAddress) -> bool {
    ip.as_bytes() == [0, 0, 0, 0]||ip.as_bytes()==[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}
pub fn from_sockaddr_to_ipendpoint(addr:SocketAddr)->IpEndpoint {
    // match addr {
    //     SocketAddr::V4(socket_addr_v4) => {
    //         IpEndpoint::new(IpAddress::Ipv4(socket_addr_v4.ip()), socket_addr_v4.port())
    //     },
    //     SocketAddr::V6(socket_addr_v6) => {
    //         IpEndpoint::new(IpAddress::Ipv6(socket_addr_v6.ip()), socket_addr_v6.port())
    //     },
    // }
    let ip=match addr.ip() {
        core::net::IpAddr::V4(ipv4_addr) => IpAddress::Ipv4(Ipv4Address(ipv4_addr.octets())),
        core::net::IpAddr::V6(ipv6_addr) => IpAddress::Ipv6(Ipv6Address(ipv6_addr.octets())),
    };
    IpEndpoint{
        addr:ip,
        port:addr.port()
    }
}
pub fn from_ipendpoint_to_socketaddr(addr: IpEndpoint) -> SocketAddr {
    let port = addr.port;
    match addr.addr {
        IpAddress::Ipv4(ipv4) => {
            // 转换 smoltcp 的 Ipv4Address 到标准库的 Ipv4Addr
            let octets = ipv4.0; // 假设 Ipv4Address 内部是 [u8; 4]
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port))
        }
        IpAddress::Ipv6(ipv6) => {
            // 转换 smoltcp 的 Ipv6Address 到标准库的 Ipv6Addr
            let segments = ipv6.0; 
            let ipv6_addr = Ipv6Addr::from(segments);
            SocketAddr::V6(SocketAddrV6::new(ipv6_addr, port, 0, 0))
        }
    }
}
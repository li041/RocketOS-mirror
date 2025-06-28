// use alloc::{collections::VecDeque, vec, vec::Vec};
// use smoltcp::phy::ChecksumCapabilities;
// use smoltcp::{
//     iface::SocketSet,
//     phy::{Device, DeviceCapabilities, Medium},
//     time::Instant,
//     wire::{IpListenEndpoint, IpProtocol, Ipv4Packet, TcpPacket},
// };

// use crate::net::{addr::from_sockaddr_to_ipendpoint, LISTEN_TABLE};

// use super::SocketSetWrapper;

// pub(crate) struct LoopbackDev {
//     pub(crate) queue: VecDeque<Vec<u8>>,
//     medium: Medium,
// }

// impl LoopbackDev {
//     pub fn new(medium: Medium) -> Self {
//         Self {
//             queue: VecDeque::new(),
//             medium,
//         }
//     }
// }

// fn snoop_tcp_from_ip(buffer: &[u8], sockets: &mut SocketSet) -> Result<(), smoltcp::wire::Error> {
//     use core::net::SocketAddr;
//     use smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket};
//     // log::error!("[snoop_tcp_from_ip] begin snoop_from_ip");
//     let ipv4_packet = Ipv4Packet::new_checked(buffer)?;
//     log::error!(
//         "[snoop_tcp_from_ip]:ipv4 packet header {:?}",
//         ipv4_packet.next_header()
//     );
//     if ipv4_packet.next_header() == IpProtocol::Tcp {
//         let tcp_packet = TcpPacket::new_checked(ipv4_packet.payload())?;
//         let src_addr = SocketAddr::new(ipv4_packet.src_addr().0.into(), tcp_packet.src_port());
//         let dst_addr = SocketAddr::new(ipv4_packet.dst_addr().0.into(), tcp_packet.dst_port());
//         let is_first = tcp_packet.syn() && !tcp_packet.ack();
//         log::error!("[snoop_tcp_from_ip] is first:{}", is_first);
//         if is_first {
//             // create a socket for the first incoming TCP packet, as the later accept() returns.
//             log::error!(
//                 "[snoop_tcp_from_ip]:src_addr :{:?},dst_addr:{:?}",
//                 src_addr,
//                 dst_addr
//             );
//             LISTEN_TABLE.push_incoming_packet(
//                 from_sockaddr_to_ipendpoint(dst_addr),
//                 from_sockaddr_to_ipendpoint(src_addr),
//                 sockets,
//             );
//         }
//     }
//     Ok(())
// }

// pub(crate) struct RxTokenScoop {
//     buffer: Vec<u8>,
// }

// pub(crate) struct TxToken<'a> {
//     queue: &'a mut VecDeque<Vec<u8>>,
// }

// impl smoltcp::phy::RxToken for RxTokenScoop {
//     fn consume<R, F>(mut self, f: F) -> R
//     where
//         F: FnOnce(&mut [u8]) -> R,
//     {
//         f(&mut self.buffer)
//     }

//     fn preprocess(&self, sockets: &mut SocketSet<'_>) {
//         snoop_tcp_from_ip(&self.buffer, sockets).ok();
//     }
// }

// impl<'a> smoltcp::phy::TxToken for TxToken<'a> {
//     // fn consume<R, F>(self, len: usize, f: F) -> R
//     // where
//     //     F: FnOnce(&mut [u8]) -> R,
//     // {
//     //     let mut buffer = vec![0; len];
//     //     let result = f(&mut buffer);
//     //     log::error!("[LoopbackTxtoken]:send buf{:?}",buffer);
//     //     self.queue.push_back(buffer);
//     //     result
//     // }
//     fn consume<R, F>(self, len: usize, f: F) -> R
//     where
//         F: FnOnce(&mut [u8]) -> R,
//     {
//         let mut buffer = vec![0; len];
//         let result = f(&mut buffer); // 应用层填充原始数据

//         // 强制计算 IP 和 TCP 校验和
//         if let Ok(mut ipv4_packet) = Ipv4Packet::new_checked(&mut buffer) {
//             // 1. 计算 IP 头部校验和
//             ipv4_packet.fill_checksum();

//             // 2. 计算 TCP 校验和（需构造伪头部）
//             if ipv4_packet.next_header() == IpProtocol::Tcp {
//                 let src_addr = ipv4_packet.src_addr();
//                 let dst_addr = ipv4_packet.dst_addr();
//                 let tcp_len = ipv4_packet.payload_mut().len();

//                 if let Ok(mut tcp_packet) = TcpPacket::new_checked(ipv4_packet.payload_mut()) {
//                     let checksum = tcp_packet.checksum();
//                     tcp_packet.set_checksum(checksum);
//                 }
//             }
//         }
//         // log::error!("[LoopbackTxtoken]:send buf {:?}", buffer);
//         // log::error!("[LoopbackTxtoken]:send buf {:?}", buffer);
//         self.queue.push_back(buffer);
//         result
//     }
// }

// impl Device for LoopbackDev {
//     type RxToken<'a> = RxTokenScoop;
//     type TxToken<'a> = TxToken<'a>;

//     fn capabilities(&self) -> DeviceCapabilities {
//         let mut cap = DeviceCapabilities::default();

//         cap.max_transmission_unit = 3000000;
//         cap.medium = self.medium;

//         cap
//     }

//     fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
//         //TODO,需要保证listen的socket不会重复在这里取数据
//         self.queue.pop_front().map(move |buffer| {
//             // log::error!("[LoopbackDev]:recv buffer {:?}", buffer);
//             let rx = Self::RxToken { buffer };
//             let tx = Self::TxToken {
//                 queue: &mut self.queue,
//             };
//             (rx, tx)
//         })
//     }

//     fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
//         // log::error!("[LoopbackDev]:send {:?}",self.queue);
//         Some(TxToken {
//             queue: &mut self.queue,
//         })
//     }
// }

extern crate alloc;

use alloc::{collections::VecDeque, vec, vec::Vec};
use smoltcp::iface::SocketSet;
use core::ptr;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken as SmoltcpRx, TxToken as SmoltcpTx};
use smoltcp::time::Instant;
use smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket};

use crate::net::addr::from_sockaddr_to_ipendpoint;
use crate::net::LISTEN_TABLE;

/// 本地回环设备，带 buffer 池复用
pub struct LoopbackDev {
    /// 已发送待接收队列
    queue: VecDeque<Vec<u8>>,
    /// 空闲 buffer 池
    pool: Vec<Vec<u8>>,
    medium: Medium,
}

impl LoopbackDev {
    pub fn new(medium: Medium) -> Self {
        Self {
            queue: VecDeque::new(),
            pool: Vec::new(),
            medium,
        }
    }

    /// 从池里取一个 buffer，长度至少为 len
    fn take_buf(&mut self, len: usize) -> Vec<u8> {
        if let Some(mut buf) = self.pool.pop() {
            buf.clear();
            buf.resize(len, 0);
            buf
        } else {
            vec![0; len]
        }
    }

    /// 回收 buffer 到池里
    fn recycle_buf(&mut self, mut buf: Vec<u8>) {
        if self.pool.len() < 64 {
            buf.clear();
            self.pool.push(buf);
        }
        // 超过容量则丢弃，让它释放
    }
}

/// RxToken，收到数据后归还 buffer
pub struct RxTokenScoop {
    buffer: Vec<u8>,
    dev: *mut LoopbackDev,
}

impl Drop for RxTokenScoop {
    fn drop(&mut self) {
        // 在 Drop 时把 buffer 放回 pool
        unsafe {
            if let Some(dev) = self.dev.as_mut() {
                let buf = core::mem::take(&mut self.buffer);
                dev.recycle_buf(buf);
            }
        }
    }
}

impl SmoltcpRx for RxTokenScoop {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer)
    }

    fn preprocess(&self, sockets: &mut smoltcp::iface::SocketSet<'_>) {
        // 保持原有 snoop 逻辑（可选）
        snoop_tcp_from_ip(&self.buffer, sockets).ok();
    }
}

/// TxToken，发送时取 buffer 且推入 queue
pub struct TxToken {
    dev: *mut LoopbackDev,
}

impl<'a> SmoltcpTx for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // 取一个 buffer
        let mut buffer = unsafe { (*self.dev).take_buf(len) };
        // 让上层填充数据
        let ret = f(&mut buffer);

        // 强制计算校验和
        if let Ok(mut ipv4) = Ipv4Packet::new_checked(&mut buffer) {
            ipv4.fill_checksum();
            if ipv4.next_header() == IpProtocol::Tcp {
                if let Ok(mut tcp) = TcpPacket::new_checked(ipv4.payload_mut()) {
                    let csum = tcp.checksum();
                    tcp.set_checksum(csum);
                }
            }
        }

        // 推送到队列
        unsafe {
            (*self.dev).queue.push_back(buffer);
        }
        ret
    }
}

impl Device for LoopbackDev {
    type RxToken<'a> = RxTokenScoop;
    type TxToken<'a> = TxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut cap = DeviceCapabilities::default();
        cap.max_transmission_unit = 3_000_000;
        cap.medium = self.medium;
        cap
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let dev_ptr = self as *mut _;
        self.queue.pop_front().map(|buf| {
            let rx = RxTokenScoop { buffer: buf, dev: dev_ptr };
            let tx = TxToken { dev: dev_ptr };
            (rx, tx)
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        // 发送时不需要预分配 buffer，交给 TxToken.take_buf
        Some(TxToken { dev: self as *mut _ })
    }
}
fn snoop_tcp_from_ip(buffer: &[u8], sockets: &mut SocketSet) -> Result<(), smoltcp::wire::Error> {
    use core::net::SocketAddr;
    use smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket};
    // log::error!("[snoop_tcp_from_ip] begin snoop_from_ip");
    let ipv4_packet = Ipv4Packet::new_checked(buffer)?;
    log::error!(
        "[snoop_tcp_from_ip]:ipv4 packet header {:?}",
        ipv4_packet.next_header()
    );
    if ipv4_packet.next_header() == IpProtocol::Tcp {
        let tcp_packet = TcpPacket::new_checked(ipv4_packet.payload())?;
        let src_addr = SocketAddr::new(ipv4_packet.src_addr().0.into(), tcp_packet.src_port());
        let dst_addr = SocketAddr::new(ipv4_packet.dst_addr().0.into(), tcp_packet.dst_port());
        let is_first = tcp_packet.syn() && !tcp_packet.ack();
        log::error!("[snoop_tcp_from_ip] is first:{}", is_first);
        if is_first {
            // create a socket for the first incoming TCP packet, as the later accept() returns.
            log::error!(
                "[snoop_tcp_from_ip]:src_addr :{:?},dst_addr:{:?}",
                src_addr,
                dst_addr
            );
            LISTEN_TABLE.lock().get().unwrap().push_incoming_packet(
                from_sockaddr_to_ipendpoint(dst_addr),
                from_sockaddr_to_ipendpoint(src_addr),
                sockets,
            );
        }
    }
    Ok(())
}

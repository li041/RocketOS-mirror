/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-03-30 16:26:05
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-06-25 11:05:18
 * @FilePath: /RocketOS_netperfright/os/src/net/mod.rs
 * @Description: net mod for interface wrapper,socketset
 *
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved.
 */
use alloc::{boxed::Box, vec};
use core::{cell::RefCell, ops::DerefMut, panic};
use lazyinit::LazyInit;
use listentable::ListenTable;
use loopback::LoopbackDev;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{tcp::SocketBuffer, AnySocket, Socket},
    storage::{PacketBuffer, PacketMetadata},
    wire::{
        EthernetAddress, EthernetFrame, HardwareAddress, IpCidr, IpProtocol, Ipv4Packet, TcpPacket,
    },
};
// use socket::Socket;
use crate::arch::virtio_blk::HalImpl;
use crate::{
    arch::timer::get_time,
    drivers::net::{
        netdevice::{NetBufPtr, NetDevice},
        VirtioNetDevice,
    },
    syscall::errno::Errno,
    task::{current_task, yield_current_task},
};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::IpAddress;
use spin::Mutex;
use virtio_drivers::transport::{mmio::MmioTransport, pci::PciTransport, Transport};

pub mod addr;
pub mod alg;
mod listentable;
mod loopback;
pub mod socket;
pub mod tcp;
pub mod udp;
pub mod unix;
pub mod socketpair;

///用于在使用函数返回错误时返回，如果是true可以yield_now,反之必须退出，可能等待没有意义
/// 任何使用block_on返回是如果是err必须返回是否需要继续阻塞
// #[derive(Debug)]
// pub struct IsBlock{
//     pub block:bool
// }

//需要定义一个全局socketset控制全局socket
//使用懒初始化全局变量，无法知道变量大小
static SOCKET_SET: LazyInit<SocketSetWrapper> = LazyInit::new();
static RANDOM_SEED: u64 = 0xA2CE_05A2_CE05_A2CE;
static ETH0: LazyInit<InterfaceWrapper> = LazyInit::new();
static LOOPBACK_DEV: LazyInit<Mutex<LoopbackDev>> = LazyInit::new();
static LOOPBACK: LazyInit<Mutex<Interface>> = LazyInit::new();
static LISTEN_TABLE: LazyInit<ListenTable> = LazyInit::new();
const TCP_RX_BUF_LEN_IPERF: usize = 128 * 1024;
const TCP_TX_BUF_LEN_IPERF: usize = 128 * 1024;
const UDP_RX_BUF_LEN: usize = 64 * 1024;
const UDP_TX_BUF_LEN: usize = 64 * 1024;
const DNS_SEVER: &str = "8.8.8.8";
const LISTEN_QUEUE_SIZE: usize = 512;
//qemu默认ipv4的网关和ipv4地址
const GATEWAY: &str = "10.0.2.2";
const IP: &str = "10.0.2.15";
const GATEWAY_V6: &str = "fe00::2"; // IPv6 网关
const IP_V6: &str = "fe00::15"; // Guest 的 IPv6 地址
const DNS_V6: &str = "fe00::3"; // IPv6 DNS 服务器
const PREFIX_V6: u8 = 64; // IPv6 子网前缀长度（默认 /64）

//net 网络初始化
#[cfg(target_arch = "riscv64")]
pub fn init(net_device: Option<VirtioNetDevice<32, HalImpl, MmioTransport>>) {
    //初始化网卡
    if let Some(dev) = net_device {
        log::error!("[init_net]:begin init virtionetdevice");
        let ether_addr = dev.mac_address();
        let eth0 = InterfaceWrapper::new(
            "eth0",
            ether_addr,
            NetDeviceWrapper {
                inner: RefCell::new(Box::new(dev)),
            },
        );
        let gateway_ipv4 = GATEWAY.parse().expect("invalid gateway");
        let gateway_ipv6 = GATEWAY_V6.parse().expect("invalid gateway");
        eth0.set_gatway(gateway_ipv4, gateway_ipv6);
        let ip_ipv4 = IP.parse().expect("invalid ip address");
        let ip_ipv6 = IP_V6.parse().expect("invalid ip address");
        eth0.set_ip_addr(ip_ipv4, 24);
        eth0.set_ip_addr(ip_ipv6, PREFIX_V6);
        ETH0.init_once(eth0);
        SOCKET_SET.init_once(SocketSetWrapper::new());
        LISTEN_TABLE.init_once(ListenTable::new());
        let mut device = LoopbackDev::new(Medium::Ip);
        let config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        let mut iface = Interface::new(
            config,
            &mut device,
            SmolInstant::from_micros_const((get_time() / 1000) as i64),
        );
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
                .unwrap();
        });
        LOOPBACK.init_once(Mutex::new(iface));
        LOOPBACK_DEV.init_once(Mutex::new(device));
    }
    // else {
    //     panic!("currently not support loopback");
    //     //loopbackdev
    //     // let mut local_device=LoopBackDevWrapper::new(smoltcp::phy::Medium::Ip);
    //     // let config=Config::new(smoltcp::wire::HardwareAddress::Ip);
    //     // let mut iface=Interface::new(config, &mut local_device, SmolInstant::from_micros_const(get_time() as i64));
    //     // iface.update_ip_addrs(|ipaddrs|{
    //     //     ipaddrs.push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)).unwrap();
    //     // });
    //     // LOOPBACK.init_once(Mutex::new(iface));
    //     // LOOPBACK_DEV.init_once(Mutex::new(local_device));
    // }
}
pub fn init_la<T: Transport + 'static>(net_device: Option<VirtioNetDevice<32, HalImpl, T>>) {
    //初始化网卡
    //需要添加这个trace 否则会panic在uninit lazyinit
    log::trace!("[init_la]");
    log::trace!("[init_la]");
    log::trace!("[init_la]");
    log::trace!("[init_la]");
    SOCKET_SET.init_once(SocketSetWrapper::new());
    log::trace!("[init_la]");
    if let Some(dev) = net_device {
        log::error!("[init_net]:begin init virtionetdevice");
        let ether_addr = dev.mac_address();
        let eth0 = InterfaceWrapper::new(
            "eth0",
            ether_addr,
            NetDeviceWrapper {
                inner: RefCell::new(Box::new(dev)),
            },
        );
        let gateway_ipv4 = GATEWAY.parse().expect("invalid gateway");
        let gateway_ipv6 = GATEWAY_V6.parse().expect("invalid gateway");
        eth0.set_gatway(gateway_ipv4, gateway_ipv6);
        let ip_ipv4 = IP.parse().expect("invalid ip address");
        let ip_ipv6 = IP_V6.parse().expect("invalid ip address");
        eth0.set_ip_addr(ip_ipv4, 24);
        eth0.set_ip_addr(ip_ipv6, PREFIX_V6);
        ETH0.init_once(eth0);
        // SOCKET_SET.init_once(SocketSetWrapper::new());
        LISTEN_TABLE.init_once(ListenTable::new());
        let mut device = LoopbackDev::new(Medium::Ip);
        let config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        let mut iface = Interface::new(
            config,
            &mut device,
            SmolInstant::from_micros_const((get_time() / 1000) as i64),
        );
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
                .unwrap();
        });
        LOOPBACK.init_once(Mutex::new(iface));
        LOOPBACK_DEV.init_once(Mutex::new(device));
    }
    // else {
    //     panic!("currently not support loopback");
    //     //loopbackdev
    //     // let mut local_device=LoopBackDevWrapper::new(smoltcp::phy::Medium::Ip);
    //     // let config=Config::new(smoltcp::wire::HardwareAddress::Ip);
    //     // let mut iface=Interface::new(config, &mut local_device, SmolInstant::from_micros_const(get_time() as i64));
    //     // iface.update_ip_addrs(|ipaddrs|{
    //     //     ipaddrs.push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)).unwrap();
    //     // });
    //     // LOOPBACK.init_once(Mutex::new(iface));
    //     // LOOPBACK_DEV.init_once(Mutex::new(local_device));
    // }
}
pub fn add_membership(multicast_addr: IpAddress, _interface_addr: IpAddress) {
    // println!("[add_membership]add membership");
    let timestamp = SmolInstant::from_micros_const((get_time() / 1000) as i64);
    let _ = LOOPBACK.lock().join_multicast_group(
        LOOPBACK_DEV.lock().deref_mut(),
        multicast_addr,
        timestamp,
    );
}
pub fn remove_membership(multicast_addr: IpAddress, _interface_addr: IpAddress) {
    // println!("[remove_membership]remove membership");
    let timestamp = SmolInstant::from_micros_const((get_time() / 1000) as i64);
    let _ = LOOPBACK.lock().leave_multicast_group(
        LOOPBACK_DEV.lock().deref_mut(),
        multicast_addr,
        timestamp,
    );
}

//注意这里h生命周期a确保从ig地一个socket开始到最后一个socket结束，socketset均有效
struct SocketSetWrapper<'a>(Mutex<SocketSet<'a>>);
impl<'a> SocketSetWrapper<'a> {
    fn new() -> Self {
        SocketSetWrapper(Mutex::new(SocketSet::new(vec![])))
    }
    ///将根据sockethandle获得一个socket并执行对这个socket的处理
    pub fn with_socket<F, T: AnySocket<'a>, R>(&self, handle: SocketHandle, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        let binding = self.0.lock();
        let socket = binding.get(handle);
        f(socket)
    }
    pub fn with_socket_mut<F, T: AnySocket<'a>, R>(&self, handle: SocketHandle, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        let mut binding = self.0.lock();
        let socket = binding.get_mut(handle);
        f(socket)
    }
    pub fn new_tcp_socket() -> smoltcp::socket::tcp::Socket<'a> {
        let task = current_task();
        if task.exe_path().contains("iperf") {
            let tcp_recv_buffer = SocketBuffer::new(vec![0; TCP_RX_BUF_LEN_IPERF]);
            let tcp_send_buffer = SocketBuffer::new(vec![0; TCP_TX_BUF_LEN_IPERF]);
            smoltcp::socket::tcp::Socket::new(tcp_recv_buffer, tcp_send_buffer)
        } else if task.exe_path().contains("netperf") {
            let tcp_recv_buffer = SocketBuffer::new(vec![0; 4 * 1024]);
            let tcp_send_buffer = SocketBuffer::new(vec![0; 4 * 1024]);
            smoltcp::socket::tcp::Socket::new(tcp_recv_buffer, tcp_send_buffer)
        } else {
            let tcp_recv_buffer = SocketBuffer::new(vec![0; TCP_RX_BUF_LEN_IPERF]);
            let tcp_send_buffer = SocketBuffer::new(vec![0; TCP_TX_BUF_LEN_IPERF]);
            smoltcp::socket::tcp::Socket::new(tcp_recv_buffer, tcp_send_buffer)
        }
    }
    pub fn new_udp_socket() -> smoltcp::socket::udp::Socket<'a> {
        //这里udp初始化需要2个参数，一个是meta_storage:用于处理一个socketa最大可以发送的数据包个数，这里全部先初始化为empty，一共最对发送256个
        // 第二个参数指定了每个数据包最大数据量
        let udp_recv_buffer =
            PacketBuffer::new(vec![PacketMetadata::EMPTY; 256], vec![0; UDP_RX_BUF_LEN]);
        let udp_send_buffer =
            PacketBuffer::new(vec![PacketMetadata::EMPTY; 256], vec![0; UDP_TX_BUF_LEN]);
        smoltcp::socket::udp::Socket::new(udp_recv_buffer, udp_send_buffer)
    }
    pub fn new_dns_socket() -> smoltcp::socket::dns::Socket<'a> {
        //servers:ipaddress,Q:Q: Into<ManagedSlice<'a, Option<DnsQuery>>>,
        //Panics if `servers.len() > MAX_SERVER_COUNT`
        let server = DNS_SEVER.parse().expect("invalid DNS server address");
        smoltcp::socket::dns::Socket::new(&[server], vec![])
    }
    //这里允许sockset承接任何socket
    pub fn add<T:AnySocket<'a>>(&self,socket:T)->SocketHandle {
        let handle=self.0.lock().add(socket);
        log::error!("[socketsetwrapper_add]:socket handle is {:?}",handle);
        handle
    }
    pub fn remove(&self, handle: SocketHandle) {
        let socket=self.0.lock().remove(handle);
        drop(socket);
    }
    //todo 判断到底是哪个网卡poll
    pub fn poll_interfaces(&self) {
        // if LISTEN_TABLE.isipv4_ipv6(5555);
        // if LISTEN_TABLE.is_local(5555) {
        // yield_current_task();s

        let b = LOOPBACK.lock().poll(
            SmolInstant::from_micros_const((get_time() / 1000) as i64),
            LOOPBACK_DEV.lock().deref_mut(),
            &mut self.0.lock(),
        );
        // log::error!("[poll_interfaces]:LoopbackDev may readiness {}",b);
    }

    pub fn bind_check(&self, addr: IpAddress, port: u16) -> Result<usize, Errno> {
        let mut sockets = self.0.lock();
        for item in sockets.iter_mut() {
            match item.1 {
                Socket::Tcp(socket) => {
                    let local_addr = socket.get_bound_endpoint();
                    if local_addr.addr == Some(addr) && local_addr.port == port {
                        return Err(Errno::EADDRINUSE);
                    }
                }
                Socket::Udp(socket) => {
                    if socket.endpoint().addr == Some(addr) && socket.endpoint().port == port {
                        return Err(Errno::EADDRINUSE);
                    }
                }
                _ => {
                    continue;
                }
            };
        }
        Ok(0)
    }
}

///建立这个为了可以创建iface,要求必须实现device trait and size (size由box保证)
/// 这里基本后面i使用的dyn device就是virtionetdevice
pub struct NetDeviceWrapper {
    inner: RefCell<Box<dyn NetDevice>>,
}

//token是令牌机制，用于判断当前网卡是否需要发送数据，发送或者接受均需要消耗一个token
impl Device for NetDeviceWrapper {
    type RxToken<'a> = NetRecvToken<'a>;
    type TxToken<'a> = NetSendToken<'a>;
    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut dev = self.inner.borrow_mut();
        // if !dev.isok_recv() {
        //     return None;
        // }
        if dev.recycle_send_buffer().is_err() {
            return None;
        }
        if !dev.isok_send() {
            return None;
        }
        let buf = match dev.recv() {
            Some(buf) => buf,
            None => return None,
        };
        log::error!("[NetDeviceWrapper_receive]: has receive success");
        // log::error!("[NetDeviceWrapper_receive]: receive buffer is {:?}",buf.packet());
        // dev.recycle_recv_buffer(buf);
        Some((NetRecvToken(&self.inner, buf), NetSendToken(&self.inner)))
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        let mut dev = self.inner.borrow_mut();
        if dev.recycle_send_buffer().is_err() {
            return None;
        }
        if !dev.isok_send() {
            None
        } else {
            Some(NetSendToken(&self.inner))
        }
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1514;
        caps.max_burst_size = None;
        caps.medium = Medium::Ethernet;
        caps
    }
}

pub struct NetRecvToken<'a>(&'a RefCell<Box<dyn NetDevice>>, NetBufPtr);
pub struct NetSendToken<'a>(&'a RefCell<Box<dyn NetDevice>>);
impl<'a> RxToken for NetRecvToken<'a> {
    /// This method receives a packet and then calls the given closure `f` with the raw
    /// packet bytes as argument.
    /// 接受数据，token会自动计算？
    fn consume<R, F>(self, f: F) -> R
    //consum这里使用self确保每个令牌只会消耗一次
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        log::error!("[NetRecvToken]:begin recv");
        let recv_buf = self.1;
        // log::error!("[NetRecvToken]:recv buffer :{:?}",recv_buf.packet());

        let result = f(recv_buf.packet_mut());
        let mut dev = self.0.borrow_mut();
        dev.recycle_recv_buffer(recv_buf);
        result
    }

    fn preprocess(&self, sockets: &mut smoltcp::iface::SocketSet<'_>) {
        // let medium = self.0.borrow().capabilities().medium;
        // let is_ethernet = medium == Medium::Ethernet;
        // log::error!("[preprocess]:buf is {:?}",self.1.packet());
        snoop_tcp_packet(self.1.packet(), sockets).ok();
    }
}
impl<'a> TxToken for NetSendToken<'a> {
    //同样令牌消耗一次并发送数据常为len，并调用f
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // log::error!("[NetSendToken]:begin send");
        let mut dev = self.0.borrow_mut();
        // log::error!("1");
        let send_buffer = dev.alloc_send_buffer(len);
        // log::error!("2");
        let data = send_buffer.packet_mut();
        // log::error!("3");
        let res = f(data);
        // log::error!("4");
        dev.send(send_buffer);
        // log::error!("5");
        //利用virtionetdevice的free_device来push回收
        // if dev.recycle_send_buffer().is_err(){
        //     return None;
        // }
        // dev.recycle_send_buffer().err();
        // log::error!("6");
        res
    }
}

//服务器嗅探tcp packet
fn snoop_tcp_packet(buf: &[u8], sockets: &mut SocketSet<'_>) -> Result<(), smoltcp::wire::Error> {
    use smoltcp::wire::{EthernetFrame, IpProtocol, Ipv4Packet, TcpPacket};

    let ether_frame = EthernetFrame::new_checked(buf)?;
    let ipv4_packet = Ipv4Packet::new_checked(ether_frame.payload())?;

    if ipv4_packet.next_header() == IpProtocol::Tcp {
        let tcp_packet = TcpPacket::new_checked(ipv4_packet.payload())?;
        // log::error!("[snoop_tcp_packet] ipv4_packet is {:?}",ipv4_packet);
        let src_addr = (ipv4_packet.src_addr(), tcp_packet.src_port()).into();
        let dst_addr = (ipv4_packet.dst_addr(), tcp_packet.dst_port()).into();
        log::error!("[snoop_tcp_packet]:src_addr is {:?}", src_addr);
        log::error!("[snoop_tcp_packet]:dst_addr is {:?}", dst_addr);
        let is_first = tcp_packet.syn() && !tcp_packet.ack();
        log::error!(
            "[snoop_tcp_packet]:tcp_packet syn is {:?},ack is {:?}",
            tcp_packet.syn(),
            tcp_packet.ack()
        );
        if is_first {
            // create a socket for the first incoming TCP packet, as the later accept() returns.
            LISTEN_TABLE.push_incoming_packet(dst_addr, src_addr, sockets);
        }
    }
    Ok(())
}
pub fn poll_interfaces() {
    log::trace!("[udp_block_on] loop");
    SOCKET_SET.poll_interfaces();
}

//connect 时需要1使用网卡抽象
pub struct InterfaceWrapper {
    //smoltcp网卡抽象
    iface: Mutex<Interface>,
    //网卡ethenet地址
    address: EthernetAddress,
    //名字eth0
    name: &'static str,
    dev: Mutex<NetDeviceWrapper>,
}

unsafe impl Send for InterfaceWrapper {}
unsafe impl Sync for InterfaceWrapper {}

impl<'a> InterfaceWrapper {
    fn new(name: &'static str, address: EthernetAddress, mut dev: NetDeviceWrapper) -> Self {
        let mut config = Config::new(HardwareAddress::Ethernet(address));
        config.random_seed = RANDOM_SEED;
        // let mut dev=VirtioNetDevice::new(transport)

        //这里dev要求有trait device+sized,而size可以由boxa承担，但device必须实现,让这里的netwrapper实现
        //Safety
        //这个函数可能会panic 如果config和dev的capability中的介质不同，传入的virtionetdevice中必须是ethernet
        let iface = Mutex::new(Interface::new(
            config,
            &mut dev,
            SmolInstant::from_micros_const(get_time() as i64),
        ));
        InterfaceWrapper {
            iface: iface,
            address: address,
            name: name,
            dev: Mutex::new(dev),
        }
    }
    fn name(&self) -> &str {
        self.name
    }
    fn ethernet_address(&self) -> EthernetAddress {
        self.address
    }

    //IpAddress 有两个Ipaddressv4,Ipaddressv6
    //已经支持ipv6
    pub fn set_ip_addr(&self, ip: IpAddress, prefix_len: u8) {
        //这个函数可能会panic,如果地址不是单播地址
        //函数会设置inner中接口ip地址
        self.iface.lock().update_ip_addrs(|ipvec| {
            ipvec.push(IpCidr::new(ip, prefix_len)).unwrap();
        });
    }
    //支持设置ipv4,ipv6的网关
    pub fn set_gatway(&self, gateway_ipv4: IpAddress, gateway_ipv6: IpAddress) {
        if let IpAddress::Ipv4(v4) = gateway_ipv4 {
            self.iface
                .lock()
                .routes_mut()
                .add_default_ipv4_route(v4)
                .unwrap();
        }
        if let IpAddress::Ipv6(v6) = gateway_ipv6 {
            self.iface
                .lock()
                .routes_mut()
                .add_default_ipv6_route(v6)
                .unwrap();
        }
    }
    //sockets中保存的是待发送的socket，而待接收的socket存在dev的recv——buffer中
    pub fn poll(&self, sockets: &Mutex<SocketSet>) -> bool {
        // println!("1");
        let mut iface = self.iface.lock();
        // println!("2");
        let timestamp = SmolInstant::from_micros_const((get_time() / 1000) as i64);
        // println!("3");
        let mut dev = self.dev.lock();
        // println!("4");
        let mut sockets = sockets.lock();
        // println!("5");
        let res = iface.poll(timestamp, dev.deref_mut(), &mut sockets);
        // log::error!("[poll_interfaces]:{}",res);
        // println!("6");
        res
    }
}

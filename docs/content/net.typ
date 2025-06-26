#import "../components/prelude.typ": *

= 网络系统模块
 网络系统基于 smoltcp 协议栈实现，旨在构建高效灵活的网络通信能力。本系统支持 AF_INET、AF_INET6、AF_UNIX 及 AF_ALG 等多种地址族的套接字操作，具备 IPv4 与 IPv6 双协议栈处理能力，并完整实现了 TCP 与 UDP 传输协议。其功能性已通过 iperf、netperf 及 LTP 相关测试验证。网络系统通过统一的抽象接口管理所有网络设备与套接字资源。

== 网络系统概述
 网络工作模式如下:
#figure(
  align(center,   image("./img/net.png",   width: 75%)),  
  caption: [net工作模式],  
)
 网络系统包括以下几个主要组件:
- *NetDevice*: 定义网络设备基本操作与特性的抽象接口`NetDevice`。基于该接口可实现异构网络设备，包括虚拟本地设备`VirtioNetDevice`和虚拟本地回环设备`LoopbackDev`。

- *InterfaceWrapper*: 网络系统的网卡抽象，该组件封装 _smoltcp_的`Interface`接口和`NetDeviceWrapper`，提供对网卡设备的统一管理机制，支持多硬件网卡在操作系统内的映射实例化。与 Linux 架构类似，系统分别管理 lo 回环设备与 eth33 虚拟网卡设备。其中 eth33 通过 QEMU 的 10.0.2.15 地址映射至主机 10.0.2.2 接口。

- *ListenTable*: 全局端口监听表。维护端口至关联套接字的映射关系，通过访问套接字状态判定连接许可性。

- *Socket*: `Socket`内核套接字的封装实现，遵循`FileOp` 接口规范，支持通过文件描述符进行访问控制与操作。

== 网络Device设备--物理层
=== 多架构适配机制 <arch_network>
 网络系统支持 `LoongArch` 与 `RISC-V` 双架构，通过设备树解析实现设备至内核地址空间的映射。在` RISC-V `架构中，网络设备通过内存映射 I/O（MMIO）映射至设备地址空间；在 `LoongArch` 架构中，则通过`PCI`总线挂载设备。网络系统 采用条件编译策略实现架构差异的设备树解析。
#code-figure(
```make
#riscv qemu网络配置
-device virtio-net-device,  netdev=net -netdev user,  id=net,  hostfwd=tcp::5555-:5555,  hostfwd=udp::5555-:5555\
#loongarch qemu网络配置
-device virtio-net-pci,  netdev=net -netdev user,  id=net,  hostfwd=tcp::5556-:5555,  hostfwd=udp::5556-:5555 \
```,
caption: [网络配置],
label-name: "网络配置",
)


#h(2em)在RISC-V中，通过 `rust_main` 入口的 `dtb_address` 参数定位设备树基址，遍历设备树节点并筛选 `compatible` 属性为 `virtio-net` 的节点，解析其 `reg` 属性获取 MMIO 地址完成内核映射。
    #algorithm-figure(
        pseudocode(
            no-number, 
            [*input:* dtb_addr], 
            no-number, 
            [*output:* initialized net device], 
            [*let* dev_tree $<-$ Fdt::from_ptr(dtb_addr + KERNEL_BASE)],  
            [address_cells $<-$ dev_tree.root().prop("address-cells").value[3]],  
            [size_cells $<-$ dev_tree.root().prop("size-cells").value[3]],  
            [*for* node *in* dev_tree.all_nodes() *do*], 
            ind, 
            [*for* prop *in* node.properties() *do*], 
            ind,  
                [log(prop.name)],  
            ded,  
            ded,  
            [*for* node *in* dev_tree.all_nodes() *do*],  
            ind,  
            [*if* node.name == "soc" *then*],  
            ind,  
                [*for* child *in* node.children() *do*],  
                ind,  
                [*if* child.name == "virtio_mmio@10008000" *then*],  
                ind,  
                    [reg $<-$ parse_reg(child,   address_cells,   size_cells)],  
                    [mmio_base $<-$ reg[0].start],  
                    [mmio_size $<-$ reg[0].length],  
                    [map_area $<-$ MapArea::new(
                        VPNRange(KERNEL_BASE+mmio_base,   KERNEL_BASE+mmio_base+mmio_size),  
                        Linear,   R|W
                    )],  
                    [KERNEL_SPACE.lock().push(map_area)],  
                    [sfence.vma()],  
                    [NET_DEVICE_ADDR.lock().replace(KERNEL_BASE+mmio_base)],  
                    [header $<-$ NonNull((KERNEL_BASE+mmio_base) as mut VirtIOHeader)],  
                    [transport $<-$ MmioTransport::new(header)],  
                    [log("vendor=",   transport.vendor_id(),  
                        "version=",   transport.version(),  
                        "type=",   transport.device_type())],  
                    [dev $<-$ VirtioNetDevice::new(transport)],  
                    [net::init(Some(dev))],  
                    [*return*],  
                ded,  
                ded,  
            ded,  
            ded,  
            [*log*("not find a net device")],  
        ),  
        caption: [riscv 网络设备初始化流程],  
        label-name: "riscv_net_device_init",  
    )

#h(2em)而在Loongarch中，遍历 PCI 总线设备，筛选 `device_type` 为 `network` 的节点，解析其 BAR 寄存器完成设备地址映射。
    #algorithm-figure(
    pseudocode(
        no-number,  
        [*input:* pci_root,   allocator],  
        no-number,  
        [*output:* 初始化并启动 VirtIO 设备],  
        [*for* (device_fn,   info) *in* pci_root.enumerate_bus(0) *do*],  
        ind,  
        [status,   command $<-$ pci_root.get_status_command(device_fn)],  
        [log("Found",   info,   "at",   device_fn,   "status",   status,   "command",   command)],  
        [*if* virtio_device_type(&info) *then* virtio_type],  
        ind,  
            [log("  VirtIO",   virtio_type)],  
            [allocate_bars(&mut pci_root,   device_fn,   &mut allocator)],  
            [dump_bar_contents(&mut pci_root,   device_fn,   4)],  
            [transport $<-$ PciTransport::new::<HalImpl>(&mut pci_root,   device_fn).unwrap()],  
            [log(
            "Detected virtio PCI device with type",   transport.device_type(),  
            "features",   transport.read_device_features()
            )],  
            [virtio_device(transport)],  
        ded,  
        ded,  
        [*fn* virtio_device(transport) *do*],  
        ind,  
        [*match* transport.device_type() *with*],  
        ind,  
            [DeviceType::Block => virtio_blk(transport)],  
            [DeviceType::Network =>],  
            ind,  
            [log("[initialize net]")],  
            [virtio_net(transport)],  
            ded,  
            [t => log("Unsupported VirtIO device type",   t)],  
        ded,  
        ded,  
    ),  
        caption: [基于 PCI 的 VirtIO 设备初始化流程],  
        label-name: "pci_virtio_init",  
    )

=== NetDevice封装
  网络设备封装层实现 _smoltcp_ 的 `Device` 接口，通过 `NetDeviceWrapper` 完成对底层设备的统一抽象，支持虚拟网卡与回环设备等异构设备接入，其逻辑关系如下：
#figure(
  align(center,   image("./img/netdevice.png",   width: 100%)),  
  caption: [Netdeivce],  
)


 #h(2em)为实现与 _smoltcp_ `Device` 接口的兼容性，定义 `NetDeviceWrapper` 结构体。该结构体通过 `RefCell` 封装 `Box<dyn NetDevice>`，在实现 trait 时提供内部可变性访问支持。
#code-figure(
    ```rs
    pub struct NetDeviceWrapper {
        inner: RefCell<Box<dyn NetDevice>>,  
    }
    // 网络设备管理,  实现sync和send特性,  以便在多线程环境中安全使用
    pub trait NetDevice:Sync + Send {
        //获取设备容量
        fn capabilities(&self)->smoltcp::phy::DeviceCapabilities;
        //获取设备mac地址
        fn mac_address(&self)->EthernetAddress;
        //是否可以发送数据
        fn isok_send(&self)->bool;
        //是否可以接收数据
        fn isok_recv(&self)->bool;
        //一次最多可以发送报文数量
        fn max_send_buf_num(&self)->usize;
        //一次最多可以发送报文数量
        fn max_recv_buf_num(&self)->usize;
        //回收接收buffer
        fn recycle_recv_buffer(&mut self,  recv_buf:NetBufPtr);
        //回收发送buffer
        fn recycle_send_buffer(&mut self)->Result<(),  ()>;
        //发送数据
        fn send(&mut self,  ptr:NetBufPtr);
        //接收数据
        fn recv(&mut self)->Option<NetBufPtr>;
        //分配一个发送的网络缓冲区
        fn alloc_send_buffer(&mut self,  size:usize)->NetBufPtr;
    }
    ```,  
    caption: [NetDeviceWrapper],  
    label-name: "NetDevice及其封装",  
)


 #h(2em)系统通过 `NetBufPool` 实现网络缓冲区的统一管理，采用预分配策略优化动态内存分配效率。设备在 `recycle_recv_buffer` 与 `recycle_send_buffer` 操作中调用 `alloc` 与 `dealloc` 方法，显著提升网络通信效率并降低内存碎片化概率。
#code-figure(
    ```rs
    pub struct NetBufPool {
        //可以存储的netbuf个数
        capacity: usize,  
        //每个netbuf的长度
        buf_len: usize,  
        pool: Vec<u8>,  
        //用于存储每个待分配的netbuf的offset
        free_list: Mutex<Vec<usize>>,  
    }
    ```,  
    caption: [NetBufPool],  
    label-name: "NetBufPool",  
)
#algorithm-figure(
  pseudocode(
    no-number,  
    [*fn* alloc(self: Arc<Self>) → NetBuf],  
    no-number,  
    [*output:* 新分配的 NetBuf],  
    [offset $<-$ self.free_list.lock().pop().unwrap()],  
    [buf_ptr $<-$ NonNull(self.pool.as_ptr().add(offset) as *mut u8*)],  
    [*return* NetBuf {
      header_len: 0,  
      packet_len: 0,  
      capacity: self.buf_len,  
      buf_ptr: buf_ptr,  
      pool_offset: offset,  
      pool: Arc::clone(self),  
    }],  
    v(.5em),  
    no-number,  
    [*fn* dealloc(self,   offset: usize) → ()],  
    no-number,  
    [*precondition:* offset % self.buf_len == 0],  
    [assert(offset % self.buf_len == 0)],  
    [self.free_list.lock().push(offset)],  
  ),  
  caption: [NetBuf 缓冲区分配与回收],  
  label-name: "netbuf_alloc_dealloc",  
)


 #h(2em)系统为具体网络设备实现 _smoltcp_ 的 `Device` trait。该实现使得 _smoltcp_ 的 `poll` 轮询机制可通过 trait 方法调用 `NetDeviceWrapper` 的底层操作，完成网络数据包的收发处理。

 如代码与图示，_smoltcp_ 采用*环形令牌网络*实现设备轮询。实现的 `Device trait` 在轮询过程中管理令牌分配，当 `NetDeviceWrapper` 持有令牌时，通过 `NetDevice` 接口触发数据包处理。
 #figure(
  align(center,   image("./img/TokenRing.png",   width: 60%)),  
  caption: [环形令牌网络],  
)
#algorithm-figure(
  pseudocode(
    no-number,  
    [*impl* Device *for* NetDeviceWrapper],  
    no-number,  
    [*output:* Rx/Tx 令牌或设备能力],  
    [*fn* receive(self,   timestamp: Instant) → Option<(RxToken,   TxToken)>],  
    ind,  
      [dev $<-$ self.inner.borrow_mut()],  
      [*if* let Err(e) = dev.recycle_tx_buffers() *then*],  
      ind,  
        [warn("recycle_tx_buffers failed:",   e)],  
        [*return* None],  
      ded,  
      [*if* ¬dev.can_transmit() *then* *return* None],  
      [*match* dev.receive() *with*],  
      ind,  
        [Ok(buf)    => rx_buf $<-$ buf],  
        [Err(DevError::Again) => *return* None],  
        [Err(err)  =>],  
        ind,  
          [warn("receive failed:",   err)],  
          [*return* None],  
        ded,  
      ded,  
      [*return* Some((NetRxToken(&self.inner,   rx_buf),   NetTxToken(&self.inner)))],  
    ded,  
    v(.5em),  
    [*fn* transmit(self,   timestamp: Instant) → Option<TxToken>],  
    ind,  
      [dev $<-$ self.inner.borrow_mut()],  
      [*if* let Err(e) = dev.recycle_tx_buffers() *then*],  
      ind,  
        [warn("recycle_tx_buffers failed:",   e)],  
        [*return* None],  
      ded,  
      [*if* dev.can_transmit() *then*],  
      ind,  
        [*return* Some(AxNetTxToken(&self.inner))],  
      ded,  
      [*else* *return* None],  
    ded,  
    v(.5em),  
    [*fn* capabilities(self) → DeviceCapabilities],  
    ind,  
      [caps $<-$ DeviceCapabilities::default()],  
      [caps.max_transmission_unit $<-$ 1514],  
      [caps.max_burst_size $<-$ None],  
      [caps.medium $<-$ Medium::Ethernet],  
      [*return* caps],  
    ded,  
  ),  
  caption: [NetDeviceWrapper 驱动接口实现伪代码],  
  label-name: "netdevicewrapper_methods",  
)

== Interface设备--数据链路层
 网络接口设备通过 `InterfaceWrapper` 封装 _smoltcp_ 的 `Interface` 与 `NetDeviceWrapper`，提供网卡设备的统一管理接口。
 该封装实现双重功能：
 - 通过 _smoltcp_ 的 `poll` 轮询机制监听网络事件;
 - 当事件触发时，通过 `NetDevice` 接口执行数据包收发操作。
#code-figure(
    ```rs
    pub struct InterfaceWrapper {
        //smoltcp网卡抽象
        iface: Mutex<Interface>,  
        //网卡ethenet地址
        address: EthernetAddress,  
        //名字eth0
        name: &'static str,  
        dev: Mutex<NetDeviceWrapper>,  
    }
    ```,  
    caption: [InterfaceWrapper结构体],  
    label-name: "InterfaceWrapper",  
)

 #h(2em)系统通过 `poll_interfaces` 方法实现多网卡设备的协同轮询。轮询过程中，依托实现的 `Device trait` 对存在网络事件的设备执行数据收发操作。
#code-figure(
    ```rs
    pub fn poll_interfaces(&self) {
        //对本地回环设备轮询
        LOOPBACK.lock().poll(
            Instant::from_micros_const((current_time_nanos() / NANOS_PER_MICROS) as i64),  
            LOOPBACK_DEV.lock().deref_mut(),  
            &mut self.0.lock(),  
        );
        //对ens0设备轮询
        ETH0.poll(&self.0);
    }
    ```,  
    caption: [poll_interfaces],  
    label-name: "poll_interfaces函数",  
)
== ListenTable监听表--网络层
 网络系统通过全局单例 `LISTENTABLE` 管理所有监听端口及其关联套接字。该表维护端口到套接字的映射关系，并通过套接字状态机实施连接许可控制，其逻辑架构如下：
 #figure(
  align(center,   image("./img/listentable.png",   width: 100%)),  
  caption: [listentable],  
)
#code-figure(
    ```rs
    static LISTEN_TABLE: LazyInit<ListenTable> = LazyInit::new();
    pub struct ListenTable{
        //是由listenentry构建的监听表
        //监听表的表项个数与端口个数有关, 每个端口只允许一个地址使用
        table:Box<[Mutex<Option<Box<ListenTableEntry>>>]>,  
    }
    #[derive(Clone)]
    struct ListenTableEntry{
        //表示监听的server地址addr
        listen_endpoint:IpListenEndpoint,  
        task_id:usize,  
        //这里由于sockethandle与socket存在RAII特性, 因而可以保存sockethandle
        syn_queue:VecDeque<SocketHandle>
    }
    ```,  
    caption: [ListenTablei结构体],  
    label-name: "ListenTable",  
)
== Socket封装--传输层

  网络系统采用三层封装实现套接字管理，支持 AF_UNIX、AF_INET、AF_ALG 及 AF_INET6 地址族，兼容 TCP/UDP 协议。套接字实现 `FileOp` 接口，支持通过文件描述符进行标准化访问。

内核套接字定义如下。`Socket` 结构体封装协议类 `SocketInner`、套接字类型及具体实现，包含状态信息与缓冲区元数据。所有字段均通过原子操作或互斥锁（Mutex）保护，确保多线程环境下的状态一致性。`SocketInner` 进一步封装 TCP、UDP、UNIX 及 ALG 等协议的具体实现。
#code-figure(
    ```rs
    pub struct Socket {
        pub domain: Domain,  
        pub socket_type: SocketType,  
        inner: SocketInner,  
        recvtimeout: Mutex<Option<TimeSpec>>,  
        dont_route: bool,  
        ...
    }
    pub enum SocketInner {
        Tcp(TcpSocket),  
        Udp(UdpSocket),  
        Unix(UnixSocket),  
        Alg(AlgSocket),  
    }
    ```,  
    caption: [InterfaceWrapper],  
    label-name: "InterfaceWrapper",  
)

 #h(2em)套接字作为文件描述符的载体，通过实现 `FileOp` 接口支持标准文件操作语义。这使得套接字可无缝集成至文件描述符系统调用（如 read/write）的上下文中。

 网络系统的套接字管理遵循*资源获取即初始化*（RAII）原则。为 `Socket` 实现 Drop trait，确保当套接字关闭（shutdown）时，自动释放关联资源并从全局 `SocketSetWrapper` 中移除其句柄。
#code-figure(
    ```rs
    pub fn remove(&self,   handle: SocketHandle) {
        let socket=self.0.lock().remove(handle);
        drop(socket);
    }
    ```,  
    caption: [Socket remove],  
    label-name: "Socket-remove",  
)

#h(2em)通过上述设计，网络系统实现以下核心特性：  
  1.  **异构设备统一封装**：支持物理与虚拟网卡（Virtio、回环设备）的透明接入  
  2.  **多协议栈支持**：完整实现 IPv4/IPv6、TCP/UDP、AF_UNIX、AF_ALG 协议族  
  3.  **跨架构兼容**：在 RISC-V64 与 LoongArch 平台高效运行  
  4.  **分层管理机制**：严格分离设备轮询、端口监听与套接字操作关注点  
  5.  **资源安全模型**：基于 RAII 与原子操作保障资源生命周期与线程安全

#pagebreak()
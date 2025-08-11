#import "../components/cover.typ": *
#import "../components/figure.typ": *
#import "../components/prelude.typ": *
= 驱动适配


== 网卡驱动适配
  通过借鉴linux，rt_thread相关开源实现和官方文档，RocketOS实现了对于Visionfive2和龙芯2k1000的网卡驱动适配，并支持内核通过轮询方式进行报文收发。目前，RocketOS已经完成对在2款开发板上进行curl和git相关网络操作的支持。
=== VisionFive2网卡驱动适配
  内核对于Visionfive2网卡驱动适配位于/os/driver/starfive,其文件结构如下：
  #code-figure(
  ```shell-unix-generic
  │  │  ├─ drivers
  │  │  │  └─ net
  │  │  │     ├─ mod.rs
  │  │  │     ├─ netdevice.rs   ---内核对网络设备统一抽象
  │  │  │     └─ starfive
  │  │  │        ├─ drv_eth.rs  ---网卡核心控制文件
  │  │  │        ├─ eth_def.rs  ---网卡相关寄存器与结构体定义
  │  │  │        ├─ eth_dev.rs  ---网卡gmac协议配置
  │  │  │        ├─ eth_phy.rs  ---网卡phy设备配置
  │  │  │        ├─ mod.rs
  │  │  │        ├─ platform.rs ---网卡与内核协议栈适配
  │  │  │        └─ ytphy.rs    ---Visionfive2-yt8531芯片配置
  ```,
  caption: [visionfive2网络驱动文件结构],
  label-name: "visionfive2网络驱动文件结构",
  )
  #h(2em)内核在启动时便会通过设备树获取设备配置和属性并进入驱动完成初始化，而对于Visionfive2网卡驱动配置，核心函数是`eth_init`，具体如下：
  #algorithm-figure(
    ```rs
    Input: gmacdev
    Output: gmacdev (configured)

    1: gmac1_clk_init()                           # 时钟配置
    2: gmacdev.MacBase ← gmacdev.iobase + (EQOS_MAC_BASE) 
    3: gmacdev.DmaBase ← gmacdev.iobase + (EQOS_DMA_BASE) 
    4: gmacdev.MtlBase ← gmacdev.iobase + (EQOS_MTL_BASE) 
    5: gmacdev.PhyBase ← 0
    6: genric_gmac_phy_init(gmacdev)              # PHY设备初始化
    7: eth_dma_reset(gmacdev)
    8: eth_set_mac_addr(gmacdev)                  # MAC地址设置
    9: eth_set_speed_duplex(gmacdev)              # Speed 和工作模式设置
    10: eth_set_mtl(gmacdev)                      # MTL初始化
    11: eth_set_mac(gmacdev)                      # MAC初始化
    12: eth_set_dma(gmacdev)                      # DMA初始化
    13: eth_set_tx_desc(gmacdev, GMAC_DESC_NUM as u32)
    14: eth_set_rx_desc(gmacdev, GMAC_DESC_NUM as u32)
    15: eth_mac_set_bits(gmacdev.DmaBase, TX_CONTROL, TX_CONTROL_ST)
    16: eth_mac_set_bits(gmacdev.DmaBase, RX_CONTROL, RX_CONTROL_SR)
    17: eth_mac_set_bits(gmacdev.MacBase, MAC_CONFIG, CONFIG_TE | CONFIG_RE)
    18: return gmacdev
    ```,
    caption: [visionfive2网络驱动init函数],
    label-name: "visionfive2-network-driver-init-function",
  )


  #h(2em)在`eth_init`中，将自上而下完成对clk，phy，gmac和DMA的初始化以及相关寄存器的配置和中断的注册，其中`VisionfiveGmac`是驱动核心结构体，存储着各类寄存器基地址、dma描述符信息、网络包收发状态、物理链路状态，网络收发速度与模式等信息。
  而在`genric_gmac_phy_init`对phy设备的初始化中，根据官方文档和linux设计，驱动实现了对2种phy设备的初始化，包括通用phy设备与YT8531芯片的初始化，驱动将根据从寄存器`MII_PHYSID1`和`MII_PHYSID2`读入的数值判断初始化的方式。
  经过`eth_init`初始化，网卡将默认支持IEEE 802.3协议，支持timestamp、jumbo frame等特性，dma队列仅支持ring模式，默认支持1000 Mbps / Full duplex的链路。
  而在驱动与内核适配方面，秉持着与内核低耦合度的理念，适配核心函数均位于`platform.rs`中，具体如下：
  #code-figure(
    ```rs
    pub fn plat_mdelay(m_times: usize);
    pub fn plat_malloc_align(size:u64,align:u32)->u64;
    pub fn plat_phys_to_virt(pa:u64)->u64;
    pub fn plat_virt_to_phys(va:u64)->u32;
    pub fn plat_fence();
    pub fn plat_handle_tx_buffer(p: NetBufPtr, buffer: u64) -> u32;
    pub fn  plat_handle_rx_buffer(buffer: u64, length: u32) -> u64;
    ```,
  caption: [visionfive2网络驱动与内核适配函数],
  label-name: "visionfive2网络驱动与内核适配函数",
  )
  #h(2em)开发者只需要根据内核设计实现这些函数，并将网络设备抽象进入内核协议栈控制，便可以使用`eth_rx`和`eth_tx`进行网络收发，这也让此驱动拥有适配更多内核的可能。而得益于RocketOS网络模块对于所有网络设备的统一抽象，这里只需要实现`NetDevice` trait即可利用协议栈控制设备。



=== 龙芯2k1000网卡驱动适配
  内核对于龙芯2k1000网卡驱动适配位于/os/driver/la2000,其文件结构如下：
    #code-figure(
  ```shell-unix-generic
  │  │  ├─ drivers
  │  │  │  └─ net
  │  │  │     ├─ mod.rs
  │  │  │     ├─ netdevice.rs   ---内核对网络设备统一抽象
  │  │  │     └─ la2000
  │  │  │        ├─ drv_eth.rs  ---网卡核心控制文件
  │  │  │        ├─ eth_def.rs  ---网卡相关寄存器与结构体定义
  │  │  │        ├─ eth_dev.rs  ---网卡gmac协议配置
  │  │  │        ├─ mod.rs
  │  │  │        ├─ platform.rs ---网卡与内核协议栈适配
  ```,
  caption: [龙芯2k1000网络驱动文件结构],
  label-name: "龙芯2k1000网络驱动文件结构",
  )
  #h(2em)内核对于龙芯2k1000网络驱动适配主要来自开源库(https://github.com/Tikifire/ls2k1000la_driver)的支持。在适配内核过程中，我们对驱动进行了相关修改以便与内核网络模块轮询模式适配，并重新设计了驱动对于描述符的分配逻辑以防止对于错误地址访问导致总线卡死。

  #pagebreak()
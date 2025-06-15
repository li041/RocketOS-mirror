use crate::mm::VirtAddr;
use core::ptr::NonNull;

use crate::arch::virtio_blk::HalImpl;
use alloc::vec;
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use fdt::{self, node::FdtNode};
use netdevice::{NetBufPtr, NetDevice};
use smoltcp::{
    phy::{DeviceCapabilities, Medium},
    wire::EthernetAddress,
};
use spin::Mutex;
use virtio_drivers::device::net::VirtIONetRaw;
use virtio_drivers::transport::Transport;
use virtio_drivers::Hal;
const NET_BUF_LEN: usize = 1536;
const BUF_LEN: usize = 1 << 12;
const QUEUE_SIZE: usize = 16;
pub mod netdevice;

static NET_DEVICE_ADDR: Mutex<Option<VirtAddr>> = Mutex::new(None);
#[cfg(target_arch = "riscv64")]
pub fn init_net_device(dtb_addr: usize) {
    // let data=unsafe{core::slice::from_raw_parts((KERNEL_BASE+0xbfe00000) as *const u8, 0x20)};
    // log::error!("{:?}",data);
    // println!("11111");
    // log::error!("{:?}",KERNEL_SPACE.lock().page_table.translate_va_to_pa((0xbfe00000+KERNEL_BASE).into()));

    use core::arch::asm;

    use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};

    use crate::{
        arch::config::KERNEL_BASE,
        mm::{MapArea, MapPermission, MapType, VPNRange, KERNEL_SPACE},
    };
    let dev_tree = unsafe { fdt::Fdt::from_ptr((dtb_addr + KERNEL_BASE) as *const u8).unwrap() };

    //获取节点存储设备reg的地址
    //表示设备地址和长度占用32字长个数
    // println!("fjisof");
    let address_cells = dev_tree
        .root()
        .properties()
        .find(|prop| prop.name == "#address-cells")
        .unwrap()
        .value[3];
    let size_cells = dev_tree
        .root()
        .properties()
        .find(|prop| prop.name == "#size-cells")
        .unwrap()
        .value[3];
    println!("{:?}", address_cells);
    // println!("{:?}",size_cells);
    for node in dev_tree.all_nodes() {
        for prop in node.properties() {
            log::error!("{},{}", node.name, prop.name);
        }
    }

    for node in dev_tree.all_nodes() {
        if node.name == "soc" {
            for node_t in node.children() {
                if node_t.name == "virtio_mmio@10008000" {
                    //414BE00 4K reg
                    let reg = parse_reg(&node_t, address_cells as usize, size_cells as usize);
                    let mmio_base = reg.get(0).unwrap().0;
                    let mmio_size = reg.get(0).unwrap().1;
                    println!("[init_net_device]:net device reg is {:?}", reg);
                    //map device to kernel
                    KERNEL_SPACE.lock().push_with_offset(
                        MapArea::new(
                            VPNRange::new(
                                VirtAddr::from(KERNEL_BASE + mmio_base).floor(),
                                VirtAddr::from(KERNEL_BASE + mmio_base + mmio_size).ceil(),
                            ),
                            MapType::Linear,
                            MapPermission::R | MapPermission::W,
                            None,
                            0,
                            false,
                        ),
                        None,
                        0,
                    );
                    unsafe {
                        asm!("sfence.vma");
                    }
                    NET_DEVICE_ADDR
                        .lock()
                        .replace((KERNEL_BASE + mmio_base).into());
                    // todo!("need to create a virtio net device control");
                    // todo use virtioNetdevice mmiotransport to initilize a device
                    // 下面需要获得一个可以使用的设备，由于得到了mmio,故而可以使用mmiotransport来建立一个transport用于建立VirioNetDevice
                    let header =
                        NonNull::new((KERNEL_BASE + mmio_base) as *mut VirtIOHeader).unwrap();
                    // log::error!("[init_net_device]:addr:{:?}",unsafe{core::slice::from_raw_parts((KERNEL_BASE+mmio_base) as *const usize, 0x20)});
                    let transport = unsafe { MmioTransport::new(header).unwrap() };
                    log::error!("[init_net_device]:the transport vendor_id is {:#x},version is {:?},device_type:{:?}",transport.vendor_id(),transport.version(),transport.device_type());
                    let dev = VirtioNetDevice::<32, HalImpl, MmioTransport>::new(transport);
                    log::error!("[init_net_device]:the dev has built");
                    crate::net::init(Some(dev));
                    return;
                    // todo init net
                }
            }
        }
    }
    log::error!("not find a net device");
    // crate::net::init(None);
    // ///能到这里必然不是virtionetdevice
    // return None;
}
#[cfg(target_arch = "loongarch64")]
pub fn init_net_dev_la<T: Transport + 'static>(transport: T) {
    log::error!(
        "[init_net_dev_la]:the transport device_type is {:?}",
        transport.device_type()
    );
    let dev = VirtioNetDevice::<32, HalImpl, T>::new(transport);
    log::trace!("[init_net_dev_la] must init net la");
    crate::net::init_la(Some(dev));
}

//解析设备 compatibel中的reg中的mmio_base mmio_size，基本返回的就是2各元素
fn parse_reg(node: &FdtNode, addr_cells: usize, size_cells: usize) -> Vec<(usize, usize)> {
    let reg = node
        .properties()
        .find(|prop| prop.name == "reg")
        .unwrap()
        .value;
    let reg: &[u32] = bytemuck::cast_slice(reg); // Big endian
    let mut res = Vec::new();
    for pos in (0..reg.len()).step_by(addr_cells + size_cells) {
        let phys_start = reg[pos..pos + addr_cells]
            .iter()
            .fold(0, |acc, &x| acc << 32 | x.swap_bytes() as usize);
        let size = reg[pos + addr_cells..pos + addr_cells + size_cells]
            .iter()
            .fold(0, |acc, &x| acc << 32 | x.swap_bytes() as usize);
        res.push((phys_start, size));
    }
    res
}

//需要将硬件可以虚拟化介入内核中控制
//transport trait可以提供一个统一的接口控制MMIO,PCI设备
//QS是单次可以发送或者接受的最大buf个数
pub struct VirtioNetDevice<const QS: usize, H: Hal, T: Transport> {
    //发送的netbuf package
    recv_buffers: [Option<NetBufBox>; QS],
    //接受的netbuf package
    send_buffers: [Option<NetBufBox>; QS],
    /// Raw driver for a VirtIO network device.
    ///
    /// This is a raw version of the VirtIONet driver. It provides non-blocking
    /// methods for transmitting and receiving raw slices, without the buffer
    /// management. For more higher-level functions such as receive buffer backing,
    /// see [`VirtIONet`].
    ///
    /// [`VirtIONet`]: super::VirtIONet
    // pub struct VirtIONetRaw<H: Hal, T: Transport, const QUEUE_SIZE: usize> {
    //     transport: T,
    //     mac: EthernetAddress,
    //     recv_queue: VirtQueue<H, QUEUE_SIZE>,
    //     send_queue: VirtQueue<H, QUEUE_SIZE>,
    // }
    //这个inner用于使用virtio_drivers中net virtionetdevice的定义
    inner: VirtIONetRaw<H, T, QS>,
    pool: Arc<NetBufPool>,
    ///需要注意pool负责的是e整个所有buf的分配，而free_send_buffers负责的则是已经分配的send_buf中send_complete的，
    ///这个里面增加的唯一方式是ryclcye send buf
    free_send_buffers: Vec<NetBufBox>,
}

unsafe impl<H: Hal, T: Transport, const QS: usize> Send for VirtioNetDevice<QS, H, T> {}
unsafe impl<H: Hal, T: Transport, const QS: usize> Sync for VirtioNetDevice<QS, H, T> {}

impl<const QS: usize, H: Hal, T: Transport> VirtioNetDevice<QS, H, T> {
    ///创建一个虚拟net设备返回
    pub fn new(transport: T) -> Self {
        //定义pool用于分配存储netbuf，capacity,buf_len,Vec pool ,free_list
        let pool = NetBufPool::new(2 * QS, NET_BUF_LEN);
        log::error!("[VirtioNetDevice]:pool build complete");
        let inner = VirtIONetRaw::<H, T, QS>::new(transport)
            .map_err(|e| log::error!("Failed to create VirtIONetRaw: {:?}", e))
            .unwrap();
        log::error!("[VirtioNetDevice]:VirtioNetRaw build complete");
        //定义可供分配的sendbuffer
        let free_send_buffers = Vec::with_capacity(QS);
        let recv_buffers = [const { None }; QS];
        let send_buffers = [const { None }; QS];
        let mut net_dev = VirtioNetDevice {
            recv_buffers: recv_buffers,
            send_buffers: send_buffers,
            pool: pool,
            free_send_buffers: free_send_buffers,
            inner: inner,
        };
        // 使用poll alloc为recv_buffer分配，为send_buffer分配
        for (i, buf) in net_dev.recv_buffers.iter_mut().enumerate() {
            let mut alloc_buf = Box::new(net_dev.pool.alloc());
            //这个函数将提交一个receive请求，receive的buffer放到参数alloc_buf地址中，其中返回的token是inner(ViitioNetDevice)自带的一个receive buffer的id,意味着将alloc_buf
            //放入inner的token地方，由于我们是在初始化一个dev,每个token应该和i一样
            //here we have already push all buf in used ring
            let token = unsafe {
                net_dev
                    .inner
                    .receive_begin(alloc_buf.get_raw_mut_buf())
                    .unwrap()
            };
            assert_eq!(token, i as u16);
            *buf = Some(alloc_buf);
        }

        // log::error!("22222222222");
        for _ in 0..QS {
            //分配sendbuf
            let mut alloc_buf = Box::new(net_dev.pool.alloc());
            // Fill the header of the `buffer` with [`VirtioNetHdr`].
            // If the `buffer` is not large enough, it returns [`Error::InvalidParam`]这里我们定义长度为1536
            let header_len = net_dev
                .inner
                .fill_buffer_header(alloc_buf.get_raw_mut_buf())
                .unwrap();
            alloc_buf.set_header_len(header_len);
            net_dev.free_send_buffers.push(alloc_buf);
        }
        // log::error!("3333333333");
        net_dev
    }
}

//todo
impl<const QS: usize, H: Hal, T: Transport> NetDevice for VirtioNetDevice<QS, H, T> {
    fn isok_send(&self) -> bool {
        //要求free_send_buf不可为空，这里应当是在init时创建的
        self.inner.can_send() && !self.free_send_buffers.is_empty()
    }

    fn isok_recv(&self) -> bool {
        //init时每个recv_buffer经过分配后便与inner中的recv_buffer进行绑定，通过tokena绑定
        //recv_begin是提交请求
        //poll_recvive是查看inner中的receive_ring中是否有buf已经传输完成，如果有传输完成，则返回token即receive buffer index
        self.inner.poll_receive().is_some()
    }

    fn max_send_buf_num(&self) -> usize {
        QS
    }

    fn max_recv_buf_num(&self) -> usize {
        QS
    }

    //这个函数目的是为一个新的netbuf分配token等待接收，相当于回收了buf
    fn recycle_recv_buffer(&mut self, recv_buf_ptr: NetBufPtr) {
        let mut recv_buf = NetBuf::from_ptr_into_netbuf(recv_buf_ptr);
        //为这个buf_ptr对应的netbuf提交接收请求，返回一个token,相当于将这个buf加入到inner中
        let token = unsafe {
            self.inner
                .receive_begin(recv_buf.get_raw_mut_buf())
                .unwrap()
        };
        log::error!("[recycle_recv_buffer]:token{}", token);
        //这个地方先前的buf必须清空，不然inner无法将packet放入这指针地方
        assert!(self.recv_buffers[token as usize].is_none());
        log::error!(
            "[recycle_recv_buffer]:after recyble recv buf is {:?}",
            recv_buf.get_packet()
        );
        self.recv_buffers[token as usize] = Some(recv_buf);
    }

    //这个函数用于回收发送package，利用Netdevice中的free_send_buf回收
    fn recycle_send_buffer(&mut self) -> Result<(), ()> {
        while let Some(token) = self.inner.poll_transmit() {
            log::error!("[recycle_send_buffer]:token is {}", token);
            //意味这有token已经完成发送了
            if let Some(send_buf) = self.send_buffers[token as usize].take() {
                unsafe {
                    let _ = self
                        .inner
                        .transmit_complete(token, send_buf.get_packet_with_header());
                };
                self.free_send_buffers.push(send_buf);
            } else {
                return Err(());
            }
        }
        Ok(())
    }

    fn send(&mut self, ptr: NetBufPtr) {
        // log::error!("[VirtioNetDevice_send]:send begin");
        let send_netbuf = NetBuf::from_ptr_into_netbuf(ptr);
        // log::error!("[VirtioNetDevice_send]:{:?}",send_netbuf.capacity);
        // log::error!("[VirtioNetDevice_send]:{:?}",send_netbuf.buf_ptr);
        // log::error!("-----");
        //使用inner中的transmit_begin同样申请一个token进入准备发送队列
        let token = unsafe {
            self.inner
                .transmit_begin(send_netbuf.get_packet_with_header())
                .unwrap()
        };
        log::error!(
            "[VirtioNetDev_send]:send buf {:?}",
            send_netbuf.get_packet()
        );
        self.send_buffers[token as usize] = Some(send_netbuf);
    }

    fn recv(&mut self) -> Option<NetBufPtr> {
        //使用poll_receive得到已经发送完成的token
        if let Some(token) = self.inner.poll_receive() {
            //所有的recv_buf要么在init初始化，要么通过recycle重新传入一个netbuf
            //用take将原有的定位None,之后将其中的net_bufg放入recv_buf
            let mut recv_buf = self.recv_buffers[token as usize].take().unwrap();
            let (header_len, packet_len) = unsafe {
                self.inner
                    .receive_complete(token, recv_buf.get_raw_mut_buf())
                    .unwrap()
            };
            recv_buf.set_header_len(header_len);
            recv_buf.set_packet_len(packet_len);
            log::error!(
                "[VirtioNetDevice_recv]:recv_buf is {:?}",
                recv_buf.get_packet()
            );
            Some(recv_buf.into_buf_ptr())
        } else {
            log::error!("[VirtioNetDevice_recv]:recv none");
            None
        }
    }

    fn alloc_send_buffer(&mut self, size: usize) -> NetBufPtr {
        //不使用Pool分配，而是通过free_send_bufn分配
        let mut send_buf = self.free_send_buffers.pop().unwrap();
        let header_len = send_buf.header_len;
        assert!(header_len + size < send_buf.capacity);
        send_buf.set_packet_len(size);
        send_buf.into_buf_ptr()
    }
    fn mac_address(&self) -> EthernetAddress {
        EthernetAddress(self.inner.mac_address())
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut cap = DeviceCapabilities::default();
        cap.max_transmission_unit = 1514;
        cap.max_burst_size = None;
        cap.medium = Medium::Ethernet;
        cap
    }
}

///符合RAII
pub type NetBufBox = Box<NetBuf>;

///定义每次发送网络数据包格式
/// A RAII network buffer.
///
/// It should be allocated from the [`NetBufPool`], and it will be
/// deallocated into the pool automatically when dropped.
///
/// The layout of the buffer is:
///
/// ```text
///   ______________________ capacity ______________________
///  /                                                      \
/// +------------------+------------------+------------------+
/// |      Header      |      Packet      |      Unused      |
/// +------------------+------------------+------------------+
/// |\__ header_len __/ \__ packet_len __/
/// |
/// buf_ptr
/// ```
/// 每个netbuf均应该通过netpool的alloc啦分配
pub struct NetBuf {
    header_len: usize,
    packet_len: usize,
    capacity: usize,
    ///保证这个地址不为空！此地址是netbuf根据netpool和自己的偏移得到的i地址
    buf_ptr: NonNull<u8>,
    ///offset是在pool中的偏移，每个netbuf均存于offset
    pool_offset: usize,
    //用于存储netbuf的pool池
    pool: Arc<NetBufPool>,
}
unsafe impl Send for NetBuf {}
unsafe impl Sync for NetBuf {}

impl NetBuf {
    ///得到这个报文的不可变引用中的某一个start开始长len的数据，用于后面确定其中header等部分
    fn get_with_slice(&self, start: usize, len: usize) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.buf_ptr.as_ptr().add(start), len) }
    }
    fn get_with_mut_slice(&mut self, start: usize, len: usize) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.buf_ptr.as_ptr().add(start), len) }
    }

    fn get_capacity(&self) -> usize {
        self.capacity
    }
    fn get_header_len(&self) -> usize {
        self.header_len
    }
    fn get_packet_len(&self) -> usize {
        self.packet_len
    }
    fn get_header(&self) -> &[u8] {
        self.get_with_slice(0, self.header_len)
    }
    fn get_mut_header(&mut self) -> &mut [u8] {
        self.get_with_mut_slice(0, self.header_len)
    }
    fn get_packet(&self) -> &[u8] {
        self.get_with_slice(self.header_len, self.packet_len)
    }
    fn get_mut_packet(&mut self) -> &mut [u8] {
        self.get_with_mut_slice(self.header_len, self.packet_len)
    }
    fn get_packet_with_header(&self) -> &[u8] {
        self.get_with_slice(0, self.header_len + self.packet_len)
    }
    fn get_raw_buf(&self) -> &[u8] {
        self.get_with_slice(0, self.capacity)
    }
    fn get_raw_mut_buf(&mut self) -> &mut [u8] {
        self.get_with_mut_slice(0, self.capacity)
    }
    fn set_header_len(&mut self, header_len: usize) {
        assert!(header_len + self.packet_len <= self.capacity);
        self.header_len = header_len;
    }
    fn set_packet_len(&mut self, packet_len: usize) {
        assert!(packet_len + self.header_len <= self.capacity);
        self.packet_len = packet_len;
    }
    pub fn from_ptr_into_netbuf(ptr: NetBufPtr) -> Box<Self> {
        unsafe { Box::from_raw(ptr.raw_ptr::<Self>()) }
    }
    pub fn into_buf_ptr(mut self: Box<Self>) -> NetBufPtr {
        let buf_ptr = self.get_mut_packet().as_mut_ptr();
        let len = self.packet_len;
        NetBufPtr {
            netbuf_ptr: NonNull::new(Box::into_raw(self) as *mut u8).unwrap(),
            packet_ptr: NonNull::new(buf_ptr).unwrap(),
            packcet_len: len,
        }
    }
    // pub fn NetBuf_to_NetBufPtr(&mut self)->NetBufPtr {
    //     let packet_len=self.packet_len;
    //     let packet_ptr=self.get_mut_packet().as_mut_ptr();
    //     let net_buf_ptr=self.get_raw_mut_buf().as_mut_ptr();
    //     NetBufPtr::new(packet_len, NonNull::new(net_buf_ptr).unwrap(), NonNull::new(packet_ptr).unwrap())

    // }
}

/// A pool of [`NetBuf`]s to speed up buffer allocation.
///
/// It divides a large memory into several equal parts for each buffer.
pub struct NetBufPool {
    //可以存储的netbuf个数
    capacity: usize,
    //每个netbuf的长度
    buf_len: usize,
    pool: Vec<u8>,
    //用于存储每个待分配的netbuf的offset
    free_list: Mutex<Vec<usize>>,
}

impl NetBufPool {
    ///定义一个buf，capacity表示其中可以存储的buf个数，buf_len则是用于定义netbuf中的capacity
    pub fn new(capacity: usize, buf_len: usize) -> Arc<Self> {
        assert!(capacity > 0, "netbufpool capacity must bigger than 0");
        //定义capacity个长度为buf_len用于存储buf的poll,每个可以用于分配的offset由free_list存储
        let pool = vec![0; capacity * buf_len];
        //定义free_list,其中元素表示可以分配的buf位置offset
        let mut free_list = Vec::with_capacity(capacity);
        for i in 0..capacity {
            // store offset
            free_list.push(i * buf_len);
        }
        Arc::new(NetBufPool {
            capacity: capacity,
            buf_len: buf_len,
            pool: pool,
            free_list: Mutex::new(free_list),
        })
    }
    pub fn get_capacity(&self) -> usize {
        self.capacity
    }
    pub fn get_buf_len(&self) -> usize {
        self.buf_len
    }
    //这个函数将从free_list得到一个free的offset，用于存储新分配的netbuf数据包
    pub fn alloc(self: &Arc<Self>) -> NetBuf {
        let offset = self.free_list.lock().pop().unwrap();
        let buf_ptr = NonNull::new(unsafe { self.pool.as_ptr().add(offset) as *mut u8 }).unwrap();
        NetBuf {
            header_len: 0,
            packet_len: 0,
            capacity: self.buf_len,
            buf_ptr: buf_ptr,
            pool_offset: offset,
            pool: Arc::clone(self),
        }
    }
    //这个函数将回收一个netbuf,offset是这个netbuf在pool中的偏移
    pub fn dealloc(&self, offset: usize) {
        assert!(offset % self.buf_len == 0);
        self.free_list.lock().push(offset);
    }
}

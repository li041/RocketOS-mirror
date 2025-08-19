/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-03-30 16:26:09
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-08-19 20:03:25
 * @FilePath: /RocketOS-mirror/os/src/net/tcp.rs
 * @Description: tcp file 
 * 
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved. 
 */


//本文将主要用于tcp的连接，按照linux中内容，主要状态转换为socket->bind(to a addr)->listen(listentable)->connect->send/recv

use core::{cell::UnsafeCell, net::SocketAddr, ptr::copy_nonoverlapping, sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering}, time};
use alloc::vec;
use smoltcp::{iface::SocketHandle, socket::tcp::{self, ConnectError, RecvError, SendError, State}, wire::{IpEndpoint, IpListenEndpoint, Ipv4Address}};
use spin::Mutex;

#[cfg(feature="la2000")]
use crate::net::ETH0_LA2000;
use crate::{arch::timer::get_time, net::{addr::{from_sockaddr_to_ipendpoint, is_unspecified, LOOP_BACK_ENDPOINT}, ETH0, LOOPBACK}, syscall::errno::{Errno, SyscallRet}, task::{current_task, yield_current_task}};

use super::{addr::UNSPECIFIED_ENDPOINT, listentable::ListenTable, poll_interfaces, SocketSetWrapper, LISTEN_TABLE, SOCKET_SET};
pub struct PollState{
    //g用于表示当前是否可以继续发送和接受，受制于socketa状态和当下eth0中recv_buffer,send_buffer中已经有的个数
    pub readable:bool,
    pub writeable:bool
}

/// TcpSocket结构体
pub struct TcpSocket{
    //state用于表示tcp的状态，这里的状态不是linux中定义的状态，那些状态有smoltcp维护，这里只维护closed,connecting,connected,listening,busy,
    //为了方便多线程操作，使用原子定义，任何状态转换之间使用busy状态代替
    // 所有存在的状态变化：
    // connect: closed->busy->connecting->busy->connected->shutdown->busy->closed
    // listening:closed->busy->listening->shutdown->busy->closed
    state:AtomicU8,
    //todo handle需要定义为一个符合RAII的变量，需要可以alloc,dealloc
    handle:UnsafeCell<Option<SocketHandle>>,
    loacl_addr:UnsafeCell<IpEndpoint>,
    remote_addr:UnsafeCell<IpEndpoint>,
    nonblock:AtomicBool,
    reuse_addr:AtomicBool,
    tcp_keepidle: AtomicU64,
    tcp_keepintvl: AtomicU64,
    tcp_keepcnt: AtomicU64,
}
//这几个状态i定义用于控制状态切换时的动作
const STATE_CLOSED:u8=0;
const STATE_BUSY:u8=1;
const STATE_CONNECTED:u8=2;
const STATE_CONNECTING:u8=3;
const STATE_LISTENING:u8=4;



unsafe impl Sync for TcpSocket {}

//私有函数
impl TcpSocket {
    fn get_state(&self)->u8 {
        self.state.load(Ordering::Acquire)
    }
    fn set_state(&self,state:u8) {
        self.state.store(state, Ordering::Release);
    }
    pub fn is_closed(&self)->bool {
        self.state.load(Ordering::Acquire)==STATE_CLOSED
    }
    pub fn is_connected(&self)->bool {
        self.state.load(Ordering::Acquire)==STATE_CONNECTED
    }
    fn is_connecting(&self)->bool {
        self.state.load(Ordering::Acquire)==STATE_CONNECTING
    }
    fn is_listening(&self)->bool {
        self.state.load(Ordering::Acquire) ==STATE_LISTENING       
    }
    pub fn set_tcp_keepcnt(&self, value: u64) {
        self.tcp_keepcnt.store(value, Ordering::Release);
    }
    pub fn set_tcp_keepidle(&self, value: u64) {
        self.tcp_keepidle.store(value, Ordering::Release);
    }
    pub fn set_tcp_keepintvl(&self, value: u64) {
        self.tcp_keepintvl.store(value, Ordering::Release);
    }
    pub fn get_tcp_keepcnt(&self)->u64{
        self.tcp_keepcnt.load(Ordering::Acquire)
    }
    pub fn get_tcp_keepidle(&self)->u64{
        self.tcp_keepidle.load(Ordering::Acquire)
    }
    pub fn get_tcp_keepintvl(&self)->u64{
        self.tcp_keepintvl.load(Ordering::Acquire)
    }
    ///这里函数比较当前状态i是否为u8,如果是则执行f动作并切换到busy，直到f返回ok再切换为new,
    /// 如果f返回T,则同样返回T,反之返回当前current状态
    /// function change state from current to new if current is true,and do f
    /// if f reture ok then return ok set state to new else set state to current
    /// attention the function f will do in state busy this will make sure only one thread work in busy state
    fn update_state<F,T>(&self,current:u8,new:u8,f:F)->Result<T,Errno>
    where F:FnOnce()->Result<T,Errno>
    {
        //busy状态只可能在这里定义
        match self.state.compare_exchange(current, STATE_BUSY, Ordering::Acquire, Ordering::Acquire) {
            Ok(_) => {
                //ok,state切换为busy
                let res=f();
                if res.is_ok() {
                    self.state.store(new, Ordering::Release);
                }
                else {
                    self.state.store(current, Ordering::Release);
                }
                res
            },
            Err(old) => {
                Err(Errno::EISCONN)
            },
        }
        //返回是状态依然为state_busy
    }
    /// 这个函数通过self的local_addr返回listenendpoint
    fn bound_endpoint(&self)->IpListenEndpoint {
        let local_addr=unsafe { self.loacl_addr.get().read() };
        //确保port不是0
        let port=if local_addr.port!=0 {
            local_addr.port
        }else{
            //分配一个可用的
            get_ephemeral_port()
        };
        let task=current_task();
        debug_assert!(port!=0);
        //确保addr不是0.0.0.0
        // println!("[bound_endpoint] task exe_path is {:?}",task.exe_path());
        let addr=if is_unspecified(local_addr.addr) {
            #[cfg(feature="vf2")]
            if task.exe_path().contains("curl")||task.exe_path().contains("ssh"){
                Some(smoltcp::wire::IpAddress::Ipv4(Ipv4Address::new(192, 168, 5, 100)))
            }
            else {
                Some(smoltcp::wire::IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)))
            }
            #[cfg(feature = "la2000")]
            if task.exe_path().contains("curl")||task.exe_path().contains("ssh"){
                Some(smoltcp::wire::IpAddress::Ipv4(Ipv4Address::new(192, 168, 5, 100)))
            }
            else {
                Some(smoltcp::wire::IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)))
            }
            // #[cfg(feature="git")]
            // {Some(smoltcp::wire::IpAddress::Ipv4(Ipv4Address::new(10, 0, 2, 15)))}
            #[cfg(feature="virt")]
            if task.exe_path().contains("ssh")||task.exe_path().contains("curl"){
                Some(smoltcp::wire::IpAddress::Ipv4(Ipv4Address::new(10, 0, 2, 15)))
            }
            else {
                Some(smoltcp::wire::IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)))
            }
        }else{
            Some(local_addr.addr)
        };
        IpListenEndpoint{addr,port}
    }
    //client发送syn之后如果接收到server的syn ack则返回connected,这个设置似乎是由smoltcp完成
    //connect一般只发送而不recv
    //connecting时1使用
    fn poll_connect(&self,handle:SocketHandle)->PollState {
        // let handle=unsafe { self.handle.get().read().unwrap() };
        let writable =SOCKET_SET.lock().get().unwrap().with_socket::<_,tcp::Socket,_>(handle,|socket|{
            log::error!("[poll_connect]:socket state is {:?}",socket.state());
            match socket.state() {
                tcp::State::SynSent => false,
                tcp::State::Established => {
                    self.set_state(STATE_CONNECTED);
                    true
                },
                _=>{
                    unsafe { self.loacl_addr.get().write(UNSPECIFIED_ENDPOINT) };
                    unsafe { self.remote_addr.get().write(UNSPECIFIED_ENDPOINT) };
                    self.set_state(STATE_CLOSED);
                    true
                },
            }
        });
        PollState { readable: false, writeable: writable }
    }
    fn poll_stream(&self,isread:bool)->PollState {
        let handle=unsafe { self.handle.get().read().unwrap() };
        let mut readable=false;
        let mut writeable=false;
        // let mut looptime=0;
        // loop {
        log::error!("[poll_stream] local addr is {:?} remote_addr is {:?}",self.local_addr().unwrap(),self.remote_addr().unwrap());
            SOCKET_SET.lock().get().unwrap().with_socket::<_,tcp::Socket,_>(handle, |socket|{
                log::error!("[poll_stream]:socket may recv {},can recv{},can send {}",socket.may_recv(),socket.can_recv(),socket.can_send());
                readable=!socket.may_recv() || socket.can_recv();
                writeable=!socket.may_send() || socket.can_send();
            });
            if readable==false&&writeable==false {
                readable=true;
            }
            PollState { readable: readable, writeable: writeable }
    }
    //listening应该readable,writealbe均是false
    fn poll_listening(&self)->PollState {
        // poll_interfaces();
        let port=unsafe { self.loacl_addr.get().read().port };
        let mut readable=LISTEN_TABLE.lock().get().unwrap().can_accept(port);
        log::error!("[poll_listening]:readable is {:?}",readable);
        PollState { readable: readable
            , writeable: false }        
    }

    ///这个函数将阻塞当前进程知道执行完f函数返回ok
    fn block_on<F,T>(&self,mut f:F)->Result<T,Errno>
    where F:FnMut()->Result<T,Errno>
    {
        if self.is_block() {
            //如果不是阻塞，则立刻返回
            f()
        }
        else {
            loop {
                // yield_current_task();
                poll_interfaces();
                // println!("----");
                match f() {
                    //如果返回err呢，阻塞应该循环直到返回ok,这里应该执行其他线程
                    Ok(res)=>return Ok(res),
                    // 不应该阻塞所有err，todo创建error分类？
                    //todo,后续改进，这里暂时先这样
                    Err(res)=>{
                        if res==Errno::EAGAIN {
                            // let task=current_task();
                            // let tid=task.tid();
                            // log::error!("[block_on] the current task is {:?}",tid);
                            // drop(task);
                            log::trace!("[tcp_block_on]");
                            yield_current_task();
                            log::trace!("[tcp_block_on]");
                            // println!("[tcp_block_on]");
                            // log::trace!("[tcp_block_on]");
                        }
                        else {
                            return Err(res);
                        }
                    },
                }
                
            }
        }
    }
    //todo
    // fn poll_listener(&self)->PollState {
    // }
    
}
//公有函数
impl TcpSocket {
    pub const fn new()->Self {
        TcpSocket { state: AtomicU8::new(STATE_CLOSED),
            handle: UnsafeCell::new(None), 
            loacl_addr: UnsafeCell::new(UNSPECIFIED_ENDPOINT), 
            remote_addr: UnsafeCell::new(UNSPECIFIED_ENDPOINT), 
            nonblock: AtomicBool::new(false), 
            reuse_addr: AtomicBool::new(false),
            tcp_keepidle: AtomicU64::new(0),
            tcp_keepintvl: AtomicU64::new(0),
            tcp_keepcnt: AtomicU64::new(0),
        }
    }
    pub fn new_connected(handle:SocketHandle,local_endpoint:IpEndpoint,remote_endpoint:IpEndpoint)->Self {
        TcpSocket { state: AtomicU8::new(STATE_CONNECTED),
             handle: UnsafeCell::new(Some(handle)), 
             loacl_addr: UnsafeCell::new(local_endpoint), 
             remote_addr: UnsafeCell::new(remote_endpoint), nonblock: AtomicBool::new(false), reuse_addr: AtomicBool::new(false),
             tcp_keepidle: AtomicU64::new(0),
             tcp_keepintvl: AtomicU64::new(0),
             tcp_keepcnt: AtomicU64::new(0),
            }
    }
    pub fn local_addr(&self)->Result<IpEndpoint, Errno> {
        match self.get_state() {
            STATE_CONNECTED|STATE_LISTENING|STATE_CLOSED=>{
                let local=unsafe { self.loacl_addr.get().read() };
                Ok(unsafe { self.loacl_addr.get().read() })
            }
            _=>{
                Err(Errno::ENOTCONN)
            }
        }
    }
    pub fn remote_addr(&self)->Result<IpEndpoint,Errno>{
        match self.get_state() {
            STATE_CONNECTED|STATE_LISTENING=>{
                Ok(unsafe { self.remote_addr.get().read() })
            }
            _=>Err(Errno::ENOTCONN)
        }
    }
    pub fn is_block(&self)->bool {
        //如果是非阻塞则返回false
        false
    }
    pub fn is_nonblocking(&self)->bool {
        self.nonblock.load(Ordering::Acquire)
    }
    pub fn set_nonblocking(&self,block:bool) {
        self.nonblock.store(block, Ordering::Release);
    }
    pub fn is_reuse_addr(&self)->bool {
        self.reuse_addr.load(Ordering::Acquire)
    }
    pub fn set_reuse_addr(&self,reuse:bool) {
        self.reuse_addr.store(reuse, Ordering::Release);
    }

    //tcpsocket 连接到remoteaddr
    //state从closed->connecting在poll_connect之后如果返回writeable=true,说明连接建立
    pub fn connect(&self,remote_addr:SocketAddr)->Result<(),Errno> {
        //step1 获得local_addr remote_addr
        //step2 发送syn
        //step3 等待synack,yield_task在返回的时候可以继续向下执行，poll_connect检查esocket状态
        //step4 如果状态不对，则继续yield_taska直到得到syn_ack（当然这只是对于某些错误而言）
        // yield_current_task();
        self.update_state(STATE_CLOSED, STATE_CONNECTING, ||{
            //busy状态
            let handle=unsafe { self.handle.get().read()}.unwrap_or_else(||{
                SOCKET_SET.lock().get().unwrap().add(SocketSetWrapper::new_tcp_socket())
            });
            unsafe { self.handle.get().write(Some(handle)) };
            // println!("[tcpsocket_connect]handle is {:?}",unsafe{self.handle.get().read()});
            let bound_endpoint=self.bound_endpoint();
            let remote_ipendpoint=from_sockaddr_to_ipendpoint(remote_addr);
            log::error!("[TcpSocket:connect]:connect from {:?} to {:?}",bound_endpoint,remote_ipendpoint);
            if bound_endpoint.port==remote_ipendpoint.port {
                return Err(Errno::ECONNREFUSED);
            }
            //需要判断连接的remote_addr是否是127.0.0.1,这将决定使用什么网卡
            #[cfg(not(feature = "la2000"))]
            let iface = if remote_ipendpoint.addr.as_bytes()[0] == 127 {
                LOOPBACK.get().unwrap()
            } else {
                &ETH0.iface
            };
            #[cfg(feature="la2000")]
            let mut binding = ETH0_LA2000.lock();
            #[cfg(feature="la2000")]
            let iface=binding.get_mut().unwrap();
            // let (local_endpoint,remote_endpoint)=SOCKET_SET.with_socket_mut::<_,tcp::Socket,_>(handle, |socket|{
            //     //发送SYN等待syn ack
            //     socket.connect(iface.lock().context(), remote_ipendpoint, bound_endpoint).map_err(|e|match e {
            //         ConnectError::InvalidState=>{
            //             Err(Errno::ECONNREFUSED);
            //         }
            //         ConnectError::Unaddressable=>{
            //             Err(Errno::ECONNREFUSED);
            //         }
            //     })?;
            //     //如果没有错误这里remote_addr应该是remote_endpoint,local_addr:bound_endpoint
            //     Ok::<(IpEndpoint, IpEndpoint), Errno>((socket.local_endpoint().unwrap(),socket.remote_endpoint().unwrap()))
            // }).unwrap();
            log::trace!("[tcp_connect]");
            let (local_endpoint, remote_endpoint) =
                SOCKET_SET.lock().get_mut().unwrap().with_socket_mut::<_, tcp::Socket, Result<(IpEndpoint, IpEndpoint), Errno>>(handle, |socket| {
                    socket
                        .connect(iface.lock().context(),remote_ipendpoint, bound_endpoint)
                        .map_err(|e| match e {
                            ConnectError::InvalidState  => Errno::ECONNREFUSED,
                            ConnectError::Unaddressable => Errno::ECONNREFUSED,
                        })?;
                    Ok::<(IpEndpoint, IpEndpoint), Errno>((
                        socket.local_endpoint().unwrap(),
                        socket.remote_endpoint().unwrap(),
                    ))
            })?;
            //需要注意socketset中socket和这里的socket不一样
            unsafe { self.loacl_addr.get().write(local_endpoint) };
            unsafe { self.remote_addr.get().write(remote_endpoint) };
            unsafe { self.handle.get().write(Some(handle)) };
            Ok(())
        })?;
        //等待server返回synack
        yield_current_task();
        if false {
            //非阻塞等待
            Err(Errno::EAGAIN)
        }
        else {
            self.block_on(||{
                //这里阻塞的轮询访问对于socket的i砸smoltcp中的状态，除了synsend之外均是说明connected,如果是synackrecived或者
                //connected则说明连接建立，可以传输数据了
                let handle=unsafe { self.handle.get().read().unwrap() };
                log::error!("[Tcpsocket_connect]:still in block on connect");
                let PollState{readable,writeable}=self.poll_connect(handle);
                if !writeable {
                    // let _ = self.connect(remote_addr);
                    Err(Errno::EAGAIN)
                }
                else if self.get_state()==STATE_CONNECTED {
                    // log::error!("has connect success");
                    Ok(())
                }
                else {
                    println!("[tcpconnect]:connect failed");
                    println!("state is {:?}",self.get_state());
                    Err(Errno::ECONNREFUSED)
                }
            })
        }
    }
    /// 函数将绑定传入的local_addr到自己的local_addr中
    /// 需要判断local_addrport,addr是否是无效的
    pub fn bind(&self,mut local_addr:SocketAddr) {
        self.update_state(STATE_CLOSED, STATE_CLOSED, ||{
            if local_addr.port()==0 {
                local_addr.set_port(get_ephemeral_port());
            }
            if !self.is_reuse_addr() {
                let l=from_sockaddr_to_ipendpoint(local_addr);
                match  SOCKET_SET.lock().get().unwrap().bind_check(l.addr, l.port){
                    Ok(_) => {},
                    Err(e) => {
                    },
                }
            }
            // log::error!("[Tcpsocket_bind]:socket state:{}",self.get_state());
            // log::error!("[Tcpsocket_bind]: socket local_addr:{:?}",self.local_addr().unwrap());
            let old=unsafe { self.loacl_addr.get().read() };
            if old!=UNSPECIFIED_ENDPOINT {
                //说明已经绑定其他地址了
                log::error!("[TcpSocket_bind] this socket has bind to other addr");
            }
            else {
                unsafe { self.loacl_addr.get().write(from_sockaddr_to_ipendpoint(local_addr)) };
            }

            //如果刚开始的socket可能没有handle,通过add来alloc一个
            let handle=unsafe { self.handle.get().read()}.unwrap_or_else(||{
                SOCKET_SET.lock().get().unwrap().add(SocketSetWrapper::new_tcp_socket())
            });
            unsafe { *self.handle.get()=Some(handle) };
            //把local_endpoint写到socketset中的socket中
            SOCKET_SET.lock().get_mut().unwrap().with_socket_mut::<_,smoltcp::socket::tcp::Socket,_>(handle, |socket|{
                socket.set_bound_endpoint(self.bound_endpoint());
            });
            
            Ok(())
        }).unwrap_or_else(|_|{
            log::error!("[Tcpsocket_bind]:bound failed");
        })
    }


    //函数将会监听一个地址并写回listentable
    pub fn listen(&self)->SyscallRet {
        self.update_state(STATE_CLOSED, STATE_LISTENING,||{
            let bound_endpoint=self.bound_endpoint();
            log::error!("[TcpSocket]:listen on bound_endpoint {:?}",bound_endpoint);
            unsafe { (*self.loacl_addr.get()).port=bound_endpoint.port };
            //listentable会判断对应的port的entry是否为空，如果为空，创建一个entry进入
            //entry:listen_endpoint/handle_queue
            // let handle=unsafe { self.handle.get().read().unwrap() };
            // SOCKET_SET.with_socket_mut::<_,tcp::Socket,_>(handle, |socket|{
            //     //listens
            //     let _ = socket.listen(bound_endpoint);
            // });
            LISTEN_TABLE.lock().get().unwrap().listen(bound_endpoint)
        })
    }
    
    //函数将会阻塞线程，要求服务端必须处于listen中，listentable.accept接受
    //最后返回一个新的socket
    pub fn accept(&self)->Result<TcpSocket,Errno> {
        if !self.is_listening() {
            log::error!("[Tcp_accept]:the socket state is not in listening");
            return Err(Errno::EINVAL);
        }
        let local_port=unsafe { self.loacl_addr.get().read().port };
        // ListenTable::push_incoming_packet(&self, dst, src, sockets);
        // LISTEN_TABLE.push_incoming_packet(dst, src, SOCKET_SET);
        let mut times=0;
        self.block_on(||{
            //返回T/isblock
            // log::error!("is check is ok to accept");
            // let state=self.poll_stream();
            // if state. {
                
            // }
            // if let Ok((handle,(local_endpoint,remote_endpoint))) = LISTEN_TABLE.accept(local_port) {
            //     //说明底层i已经连接上了
            //     Ok(TcpSocket::new_connected(handle, local_endpoint, remote_endpoint))
            // }
            // else {
            //     if Err(Errno::ECONNRESET) {
            //         self.shutdown();
            //     }
            //     Err(Errno::EAGAIN)
            // }
            if times>20 {
                return Err(Errno::EINTR)
            }
            times+=1;
            match LISTEN_TABLE.lock().get().unwrap().accept(local_port) {
                Ok((handle,(local_endpoint,remote_endpoint))) => {
                    // println!("[TcpSocket]:accept local endpoint is {:?}",local_endpoint);
                    // println!("[TcpSocket]:accept remote endpoint is {:?}",remote_endpoint);
                    // println!("[TcpSocket]:accept handle is {:?}",handle);
                    Ok(TcpSocket::new_connected(handle, local_endpoint, remote_endpoint))
                }
                Err(e) => {
                    if e == (Errno::ECONNRESET){
                        self.shutdown();
                        Err(Errno::ECONNRESET)
                    }
                    else if e == (Errno::ECONNREFUSED){
                        self.shutdown();
                        Err(Errno::ECONNREFUSED)
                    }
                    else {
                        Err(Errno::EAGAIN)
                    }
                }
                
            }
        })
    }
    
    //函数会注销一个socket
    pub fn shutdown(&self){
        // stream
        // 已经建立连接的socket断开连接
        let _ = self.update_state(STATE_CONNECTED, STATE_CLOSED, || {
            // SAFETY: `self.handle` should be initialized in a connected socket, and
            // no other threads can read or write it.
            let handle = unsafe { self.handle.get().read().unwrap() };
            SOCKET_SET.lock().get_mut().unwrap().with_socket_mut::<_,tcp::Socket,_>(handle, |socket| {
                // debug!("TCP socket {}: shutting down", handle);
                socket.close();
            });
            unsafe { self.loacl_addr.get().write(UNSPECIFIED_ENDPOINT) }; // clear bound address
            SOCKET_SET.lock().get().unwrap().poll_interfaces();
            Ok(())
        });

        // listener
        // 监听者断开连接
        let _ = self.update_state(STATE_LISTENING, STATE_CLOSED, || {
            // SAFETY: `self.local_addr` should be initialized in a listening socket,
            // and no other threads can read or write it.
            let local_port = unsafe { self.loacl_addr.get().read().port };
            unsafe { self.loacl_addr.get().write(UNSPECIFIED_ENDPOINT) }; // clear bound address
            LISTEN_TABLE.lock().get().unwrap().unlisten(local_port);
            SOCKET_SET.lock().get().unwrap().poll_interfaces();
            Ok(())
        });
    }

    pub fn close(&self) {
        let handle=match unsafe { self.handle.get().read() }{
            Some(h) => h,
            None => return,
        };
        log::error!("[Tcp_close] close socket local_addr is {:?},remote addr is {:?}",self.local_addr().unwrap(),self.remote_addr().unwrap());
        SOCKET_SET.lock().get().unwrap().poll_interfaces();
        SOCKET_SET.lock().get_mut().unwrap().with_socket_mut::<_,tcp::Socket,_>(handle, |socket|{
            socket.close();
            log::error!("[Tcp_close] state is {:?}",socket.state());
        });
        // SOCKET_SET.poll_interfaces();
    }


    //函数将确保进入s接受状态的socket使用recv_slice来接受
    pub fn recv(&self,buf:&mut [u8])->Result<usize,Errno> {
        log::error!("[Tcp_recv]begin recv");
        if self.is_connecting(){
            return Err(Errno::EAGAIN);
        }else if !self.is_connected() {
            return Err(Errno::ENOTCONN)
        }
        let handle=unsafe { self.handle.get().read().unwrap() };
        let mut times=0;
        let task=current_task();
        self.block_on(||{
            log::trace!("[block_on]");
            // log::error!("[]")
            SOCKET_SET.lock().get_mut().unwrap().with_socket_mut::<_,tcp::Socket,_>(handle,|socket|{
                log::error!("[Tcp recv] recv queue len is{:?}",socket.recv_queue());
                log::error!("[Tcp recv] socket state is {:?}",socket.state());
                // if times>10 {
                //     // socket.close();
                //     return Ok(0);
                // }
                // times+=1;
                if socket.recv_queue()>0 {
                    let len=socket.recv_slice(buf).map_err(|e|{
                        match e {
                            RecvError::Finished=>{
                                panic!("[Tcpsocket]:recv failed");
    
                            },
                            RecvError::InvalidState=>{
                                panic!("[Tcpsocket]:recv failed");
                            },
                        }
                    }).unwrap();
                    Ok(len)
                }
                else if !socket.is_active() {
                    log::trace!("[Tcpsocket]:connection is not active");
                    if task.exe_path().contains("iperf"){
                        Err(Errno::EINTR)
                    }
                    else{
                        Err(Errno::ECONNREFUSED)
                    }

                }
                else if !socket.may_recv() {
                    // println!("[Tcp_recv] socket state is {:?}",socket.state());
                    // println!("connecting closed");
                    // socket.close();
                    Ok(0)
                }
                else if (socket.recv_queue()==0)&&(task.exe_path().contains("git")||task.exe_path().contains("ssh")||task.exe_path().contains("curl")){
                    Ok(0)
                }
                else{
                    // log::trace!("[recv again]");
                    Err(Errno::EAGAIN)
                }
            })
        })
    }
    pub fn recv_timeout(&self, buf: &mut [u8], ticks: u64) -> Result<usize,Errno> {
        log::error!("[Tcp_recvtimeout]begin recvtimeout");
        if self.is_connecting() {
            return Err(Errno::EAGAIN);
        } else if !self.is_connected() {
            panic!("socket recv() failed");
        }

        let expire_at = get_time() as u64 + ticks;

        // SAFETY: `self.handle` should be initialized in a connected socket.
        let handle = unsafe { self.handle.get().read().unwrap() };
        self.block_on(|| {
            SOCKET_SET.lock().get_mut().unwrap().with_socket_mut::<_,tcp::Socket, _>(handle, |socket| {
                if socket.recv_queue() > 0 {
                    // data available
                    // TODO: use socket.recv(|buf| {...})
                    let len = socket
                        .recv_slice(buf)
                        .map_err(|_| panic!("socket recv() failed"))?;
                    Ok(len)
                } else if !socket.is_active() {
                    log::error!("[Tcpsocket]:connection is not active");
                    Err(Errno::ECONNREFUSED)
                } else if !socket.may_recv() {
                    // println!("[Tcp_recv] socket state is {:?}",socket.state());
                    // println!("connecting closed");
                    socket.close();
                    Ok(0)
                }
                else {
                    // no more data
                    if get_time() as u64 > expire_at {
                        Err(Errno::ETIMEDOUT)
                    } else {
                        Err(Errno::EAGAIN)
                    }
                }
            })
        })
    }

    pub fn send(&self,buf:&[u8])->Result<usize,Errno> {
        log::error!("[Tcp_socket]:begin send,send len is {:?}",buf.len());
        if self.is_connecting() {
            return Err(Errno::EAGAIN);
        }
        else if !self.is_connected() {
            //必然在前面判断之后,此时不需要阻塞
            return Err(Errno::ENOTCONN);
        }
        let handle=unsafe { self.handle.get().read().unwrap() };
        self.block_on(||{
            SOCKET_SET.lock().get_mut().unwrap().with_socket_mut::<_,tcp::Socket,_>(handle, |socket|{
                if !socket.is_active() || !socket.may_send() {
                    // closed by remote
                    Err(Errno::EPIPE)
                }
                else if socket.can_send() {
                    // log::error!("[Tcp_socket]:send_buf:{:?}",buf);
                    let len=socket.send_slice(buf).map_err(|e|{
                        match e {
                            SendError::InvalidState=>{
                                panic!("[Tcpsocket_send]:send failed because of invalidstate");
                            },
                        }
                    }).unwrap();
                    Ok(len)
                }
                else if socket.send_queue()==socket.send_capacity() {
                    //send buffer full
                    Err(Errno::EAGAIN)
                }
                else{
                    Err(Errno::EAGAIN)
                }
            })
        })
    }

    pub fn poll(&self,isread:bool)->PollState {
        // log::error!("[Tcp_socket]:poll state is {:?}",self.get_state());
        // log::error!("[Tcp_socket]:poll socket addr is {:?}",self.local_addr().unwrap());
        match self.get_state() {
            STATE_LISTENING=>self.poll_listening(),
            STATE_CONNECTING=>{
                let handle=unsafe { self.handle.get().read().unwrap() };
                self.poll_connect(handle)},
            STATE_CONNECTED=>self.poll_stream(isread),
            _=>{
                PollState{
                    //不能发送
                    writeable:false,
                    //不能接受
                    readable:false
                }
            }
        }
    }


    pub fn set_nagle_enabled(&self,enable:bool) {
        let handle=unsafe { self.handle.get().read().unwrap_or_else(||{
            SOCKET_SET.lock().get().unwrap().add(SocketSetWrapper::new_tcp_socket())
        }) };
        SOCKET_SET.lock().get_mut().unwrap().with_socket_mut::<_,tcp::Socket,_>(handle, |socket|{
            socket.set_nagle_enabled(enable);
        })
    }
    pub fn set_keep_alive(&self) {
        let handle = unsafe { self.handle.get().read().unwrap_or_else(||{
            SOCKET_SET.lock().get().unwrap().add(SocketSetWrapper::new_tcp_socket())
        }) };
        SOCKET_SET.lock().get_mut().unwrap().with_socket_mut::<_,tcp::Socket,_>(handle, |socket| {
            socket.keep_alive();
        });
    }
    pub fn nagle_enabled(&self)->bool {
        let handle=unsafe { self.handle.get().read().unwrap() };
        SOCKET_SET.lock().get_mut().unwrap().with_socket_mut::<_,tcp::Socket,_>(handle, |socket|{
            socket.nagle_enabled()
        })
    }

    pub fn with_socket<F,T>(&self,f:F)->T
    where F:FnOnce(&tcp::Socket)->T
    {
        let handle=unsafe { self.handle.get().read().unwrap() };
        SOCKET_SET.lock().get().unwrap().with_socket::<_,tcp::Socket,_>(handle, |socket|{
            f(socket)
        })
    }

    pub fn with_socket_mut<R>(&self, f: impl FnOnce(Option<&mut tcp::Socket>) -> R) -> R {
        let handle = unsafe { self.handle.get().read() };

        match handle {
            Some(handle) => {
                SOCKET_SET.lock().get_mut().unwrap().with_socket_mut::<_, tcp::Socket, _>(handle, |socket| f(Some(socket)))
            }
            None => f(None),
        }
    }
    pub fn set_hop_limit(&self,limit:u8) {
        let handle=unsafe { self.handle.get().read().unwrap() };
        SOCKET_SET.lock().get_mut().unwrap().with_socket_mut::<_,tcp::Socket,_>(handle,|socket|{
            socket.set_hop_limit(Some(limit));
        });
    }
}


//分配可用的端口，u16,端口从0xc000到0xffff
fn get_ephemeral_port() -> u16 {
    const PORT_START: u16 = 0xc000;
    const PORT_END: u16 = 0xffff;
    static CURR: Mutex<u16> = Mutex::new(PORT_START);

    let mut curr = CURR.lock();
    let mut tries = 0;
    // TODO: more robust
    while tries <= PORT_END - PORT_START {
        let port = *curr;
        if *curr == PORT_END {
            *curr = PORT_START;
        } else {
            *curr += 1;
        }
        if LISTEN_TABLE.lock().get().unwrap().can_listen(port) {
            return port;
        }
        tries += 1;
    }
    panic!("no avaliable port");
}
impl Drop for TcpSocket {
    fn drop(&mut self) {
        // println!("drop tcp socket");
        self.shutdown();
        // Safe because we have mut reference to `self`.
        if let Some(handle) = unsafe { self.handle.get().read() } {
            SOCKET_SET.lock().get().unwrap().remove(handle);
        }
    }
}
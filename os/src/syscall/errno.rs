/// 系统调用返回类型，成功时为 `usize`，失败时为 `Errno`
pub type SyscallRet = Result<usize, Errno>;

/// Linux 特定的错误码，定义在 `errno.h` 中。
/// 源码参考：
/// <asm-generic/errno-base.h> 和 <asm-generic/errno.h>
/// https://elixir.bootlin.com/linux/v6.8.9/source/include/uapi/asm-generic/errno.h#L71
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)] // 确保枚举值以 i32 类型表示（与 C 的 errno 兼容）
pub enum Errno {
    /// 操作不允许（无权限）
    EPERM = -1,
    /// 文件或目录不存在
    ENOENT = -2,
    /// 进程不存在
    ESRCH = -3,
    /// 系统调用被信号中断
    EINTR = -4,
    /// 输入/输出错误（底层硬件或设备故障）
    EIO = -5,
    /// 设备或地址不存在
    ENXIO = -6,
    /// 参数列表过长（如 execve 的参数）
    E2BIG = -7,
    /// 可执行文件格式错误
    ENOEXEC = -8,
    /// 错误的文件描述符（未打开或无效）
    EBADF = -9,
    /// 无子进程（如 waitpid 无目标）
    ECHILD = -10,
    /// 资源暂时不可用（非阻塞操作未就绪）
    /// 等同于 EWOULDBLOCK（通常用于非阻塞 I/O）
    EAGAIN = -11,
    /// 内存不足
    ENOMEM = -12,
    /// 权限不足（文件访问被拒绝）
    EACCES = -13,
    /// 错误的地址（用户空间指针无效）
    EFAULT = -14,
    /// 需要块设备（如对字符设备执行块操作）
    ENOTBLK = -15,
    /// 设备或资源忙（如文件被锁定）
    EBUSY = -16,
    /// 文件已存在（如创建已存在的文件）
    EEXIST = -17,
    /// 跨设备链接（不允许跨文件系统硬链接）
    EXDEV = -18,
    /// 设备不存在
    ENODEV = -19,
    /// 不是目录（期望目录但提供的是文件）
    ENOTDIR = -20,
    /// 是目录（期望文件但提供的是目录）
    EISDIR = -21,
    /// 无效参数（如错误的标志值）
    EINVAL = -22,
    /// 系统文件表溢出（全局文件描述符耗尽）
    ENFILE = -23,
    /// 进程打开文件数超出限制
    EMFILE = -24,
    /// 不是终端设备（如对非终端调用 ioctl）
    ENOTTY = -25,
    /// 文本文件忙（如正在执行的共享库被修改）
    ETXTBSY = -26,
    /// 文件过大（超出文件大小限制）
    EFBIG = -27,
    /// 设备空间不足（如磁盘写满）
    ENOSPC = -28,
    /// 非法寻址（如对管道调用 lseek）
    ESPIPE = -29,
    /// 只读文件系统（尝试修改只读挂载的文件系统）
    EROFS = -30,
    /// 链接数过多（文件系统限制）
    EMLINK = -31,
    /// 管道破裂（写入无读取端的管道）
    EPIPE = -32,
    /// 数学参数超出函数定义域
    EDOM = -33,
    /// 数学结果不可表示（如溢出）
    ERANGE = -34,
    /// 资源死锁可能发生（如线程锁顺序问题）
    EDEADLK = -35,
    /// 文件名过长（超出文件系统限制）
    ENAMETOOLONG = -36,
    /// 无可用记录锁（文件锁资源耗尽）
    ENOLCK = -37,
    /// 无效的系统调用号（如不存在的 syscall）
    ENOSYS = -38,
    /// 目录非空（如删除非空目录）
    ENOTEMPTY = -39,
    /// 符号链接嵌套过深（可能形成环路）
    ELOOP = -40,
    // 没有数据可读（如管道已读完）
    ENODATA = -61,
    /// 对非套接字执行套接字操作
    ENOTSOCK = -88,
    /// 发送信息超过一次message最大内容
    EMSGSIZE = -90,
    ENOPROTOOPT = -92,
    ///EPROTONOSUPPORT表示不支持所选的套接字协议
    EPROTONOSUPPORT = -93,
    /// 操作不支持（如对普通文件调用套接字操作）
    EOPNOTSUPP = -95,
    // address family 不支持
    EAFNOSUPPORT = -97,
    /// 套接字地址已在使用中（如端口被占用）
    EADDRINUSE = -98,
    /// 地址不可用（如绑定到不存在的 IP）
    EADDRNOTAVAIL = -99,
    ECONNABORTED = -103,
    /// 连接被重置（对端强制关闭）
    ECONNRESET = -104,
    /// 传输端点已连接（如重复调用 connect）
    EISCONN = -106,
    /// 套接字未连接（如未 connect 就 send）
    ENOTCONN = -107,
    /// 操作超时（如网络请求未在指定时间内响应）
    ETIMEDOUT = -110,
    /// 连接被拒绝（对端无监听服务）
    ECONNREFUSED = -111,
    /// 套接字为非阻塞模式且连接无法立即完成
    /// （通常需要配合 select/poll 检查可写性）
    EINPROGRESS = -115,
    /// 内核自动重启系统调用
    ERESTARTSYS = -512,
}

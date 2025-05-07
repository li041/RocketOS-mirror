use crate::timer::TimeVal;

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Rusage {
    pub utime: TimeVal,  // 用户态执行的总时间
    pub stime: TimeVal,  // 内核态执行的总时间
    pub maxrss: usize,   // 最大常驻集大小（内存使用峰值）
    pub ixrss: usize,    // 共享内存大小（现代系统中通常已废弃）
    pub idrss: usize,    // 未共享数据段大小（现代系统中通常已废弃）
    pub isrss: usize,    // 未共享堆栈大小（现代系统中通常已废弃）
    pub minflt: usize,   // 页面回收次数（软缺页）
    pub majflt: usize,   // 页面错误次数（硬缺页）
    pub nswap: usize,    // 交换次数（swap out 页面的次数）
    pub inblock: usize,  // 块输入操作次数（例如读取磁盘块）
    pub oublock: usize,  // 块输出操作次数（例如写入磁盘块）
    pub msgsnd: usize,   // 发送消息次数（现代系统中通常已废弃）
    pub msgrcv: usize,   // 接收消息次数（现代系统中通常已废弃）
    pub nsignals: usize, // 接收到的信号数（现代系统中通常已废弃）
    pub nvcsw: usize,    // 主动上下文切换次数（进程自愿让出 CPU）
    pub nivcsw: usize,   // 被动上下文切换次数（进程被调度器抢占）
}

use crate::timer::TimeVal;

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct RUsage {
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

#[derive(Default)]
pub struct TimeStat {
    user_time: TimeVal,
    system_time: TimeVal,
    wait_time: TimeVal,

    system_time_start: TimeVal,
    user_time_start: TimeVal,
    wait_time_start: TimeVal,

    child_user_time: TimeVal,
    child_system_stime: TimeVal,
}

impl TimeStat {
    pub fn thread_us_time(&self) -> (TimeVal, TimeVal) {
        (self.user_time, self.system_time)
    }

    pub fn child_user_system_time(&self) -> (TimeVal, TimeVal) {
        (self.child_user_time, self.child_system_stime)
    }

    pub fn user_time(&self) -> TimeVal {
        self.user_time
    }

    pub fn sys_time(&self) -> TimeVal {
        self.system_time
    }

    pub fn cpu_time(&self) -> TimeVal {
        self.user_time + self.system_time
    }

    pub fn wait_time(&self) -> TimeVal {
        self.wait_time
    }

    pub fn update_child_time(&mut self, (utime, stime): (TimeVal, TimeVal)) {
        self.child_user_time = self.child_user_time + utime;
        self.child_system_stime = self.child_system_stime + stime;
    }

    pub fn record_switch_in(&mut self) {
        let current_time = TimeVal::new_machine_time();
        self.system_time_start = current_time;
    }

    pub fn record_switch_out(&mut self) {
        let slice = TimeVal::new_machine_time() - self.system_time_start;
        self.system_time = self.system_time + slice;
    }

    pub fn record_ecall(&mut self) {
        let current_time = TimeVal::new_machine_time();
        self.system_time_start = current_time;

        let utime_slice = current_time - self.user_time_start;
        self.user_time = self.user_time + utime_slice;
    }

    pub fn record_sret(&mut self) {
        let current_time = TimeVal::new_machine_time();

        let stime_slice = current_time - self.user_time_start;
        self.system_time = self.system_time + stime_slice;

        self.user_time_start = current_time;
    }

    pub fn record_wait_start(&mut self) {
        let current_time = TimeVal::new_machine_time();
        self.wait_time_start = current_time;
    }

    pub fn record_wait_end(&mut self) {
        let slice = TimeVal::new_machine_time() - self.wait_time_start;
        self.wait_time = self.wait_time + slice;
    }

    pub fn wait_time_clear(&mut self) {
        self.wait_time = TimeVal::default();
        self.wait_time_start = TimeVal::new_machine_time();
    }
}

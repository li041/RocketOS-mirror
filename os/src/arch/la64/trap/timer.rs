use crate::arch::{
    timer::{get_clock_freq, get_timer_freq_first_time},
    CrMd, ECfg, LineBasedInterrupt, TCfg,
};

pub const TICKS_PER_SEC: usize = 100;

pub fn enable_timer_interrupt() {
    get_timer_freq_first_time();
    let timer_freq = get_clock_freq();
    // 使能定时器局部中断
    ECfg::empty()
        .set_line_based_interrupt_vector(LineBasedInterrupt::TIMER)
        .write();
}

pub fn set_next_trigger() {
    TCfg::read()
        .set_enable(true)
        .set_periodic(false)
        .set_init_val(get_clock_freq() / TICKS_PER_SEC)
        .write();
}

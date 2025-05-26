use bitflags::bitflags;

use crate::syscall::errno::Errno;

bitflags! {
    /// Modes for adjtimex()/clock_adjtime()/ntp_adjtime()
    #[derive(Clone, Copy, Debug)]
    pub struct TimexModes: u32 {
        const ADJ_OFFSET           = 0x0001;
        const ADJ_FREQUENCY        = 0x0002;
        const ADJ_MAXERROR         = 0x0004;
        const ADJ_ESTERROR         = 0x0008;
        const ADJ_STATUS           = 0x0010;
        const ADJ_TIMECONST        = 0x0020;
        const ADJ_TAI              = 0x0080;
        const ADJ_SETOFFSET        = 0x0100;
        const ADJ_MICRO            = 0x1000;
        const ADJ_NANO             = 0x2000;
        const ADJ_TICK             = 0x4000;

        // Userland only
        const ADJ_OFFSET_SINGLESHOT = 0x8001;
        const ADJ_OFFSET_SS_READ    = 0xa001;
    }
}

bitflags! {
    /// Status bits for struct timex.status
    pub struct TimexStatus: u32 {
        const STA_PLL        = 0x0001;
        const STA_PPSFREQ    = 0x0002;
        const STA_PPSTIME    = 0x0004;
        const STA_FLL        = 0x0008;
        const STA_INS        = 0x0010;
        const STA_DEL        = 0x0020;
        const STA_UNSYNC     = 0x0040;
        const STA_FREQHOLD   = 0x0080;
        const STA_PPSSIGNAL  = 0x0100;
        const STA_PPSJITTER  = 0x0200;
        const STA_PPSWANDER  = 0x0400;
        const STA_PPSERROR   = 0x0800;
        const STA_CLOCKERR   = 0x1000;
        const STA_NANO       = 0x2000;
        const STA_MODE       = 0x4000;
        const STA_CLK        = 0x8000;

        /// Read-only bits mask
        const STA_RONLY = Self::STA_PPSSIGNAL.bits()
                         | Self::STA_PPSJITTER.bits()
                         | Self::STA_PPSWANDER.bits()
                         | Self::STA_PPSERROR.bits()
                         | Self::STA_CLOCKERR.bits()
                         | Self::STA_NANO.bits()
                         | Self::STA_MODE.bits()
                         | Self::STA_CLK.bits();
    }
}

pub const NSEC_PER_SEC: usize = 1_000_000_000;
/// Supported clock IDs for clock_adjtime and related syscalls
bitflags! {
    pub struct ClockIdFlags: u32 {
        /// System-wide realtime clock
        const REALTIME               = 1 << 0;  // CLOCK_REALTIME = 0
        /// Monotonic system-wide clock (cannot go backward)
        const MONOTONIC              = 1 << 1;  // CLOCK_MONOTONIC = 1
        /// High-resolution process CPU-time clock
        const PROCESS_CPUTIME_ID     = 1 << 2;  // CLOCK_PROCESS_CPUTIME_ID = 2
        /// Thread-specific CPU-time clock
        const THREAD_CPUTIME_ID      = 1 << 3;  // CLOCK_THREAD_CPUTIME_ID = 3
        /// Raw hardware-based monotonic clock
        const MONOTONIC_RAW          = 1 << 4;  // CLOCK_MONOTONIC_RAW = 4
        /// Coarse & fast realtime clock
        const REALTIME_COARSE        = 1 << 5;  // CLOCK_REALTIME_COARSE = 5
        /// Coarse & fast monotonic clock
        const MONOTONIC_COARSE       = 1 << 6;  // CLOCK_MONOTONIC_COARSE = 6
        /// Boot-time clock, includes suspend time
        const BOOTTIME               = 1 << 7;  // CLOCK_BOOTTIME = 7
        /// Alarm variant of realtime clock
        const REALTIME_ALARM         = 1 << 8;  // CLOCK_REALTIME_ALARM = 8
        /// Alarm variant of boottime clock
        const BOOTTIME_ALARM         = 1 << 9;  // CLOCK_BOOTTIME_ALARM = 9
        /// International Atomic Time clock
        const TAI                    = 1 << 10; // CLOCK_TAI = 11 (using next bit)
    }
}

impl ClockIdFlags {
    /// Test if a clockid_t (integer) is supported and return its flag
    pub fn from_clockid(clockid: i32) -> Result<Self, Errno> {
        match clockid {
            0 => Ok(ClockIdFlags::REALTIME),
            1 => Ok(ClockIdFlags::MONOTONIC),
            2 => Ok(ClockIdFlags::PROCESS_CPUTIME_ID),
            3 => Ok(ClockIdFlags::THREAD_CPUTIME_ID),
            4 => Ok(ClockIdFlags::MONOTONIC_RAW),
            5 => Ok(ClockIdFlags::REALTIME_COARSE),
            6 => Ok(ClockIdFlags::MONOTONIC_COARSE),
            7 => Ok(ClockIdFlags::BOOTTIME),
            8 => Ok(ClockIdFlags::REALTIME_ALARM),
            9 => Ok(ClockIdFlags::BOOTTIME_ALARM),
            11 => Ok(ClockIdFlags::TAI),
            _ => Err(Errno::EINVAL),
        }
    }
}

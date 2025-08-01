use crate::index_list::ListIndex;

// mod cfs;
#[cfg(feature = "cfs")]
mod cfs;
mod fifo;
mod prio;
mod idle;

#[cfg(feature = "cfs")]
pub use cfs::{CFSScheduler, LoadWeight, CFSSchedEntity, check_slice, update_curr};
pub use fifo::{FIFOScheduler, add_rt_task, fetch_rt_task, remove_rt_task};
pub use idle::{get_idle_scheduler, idle_task};

//! NICE_TO_PRIO: nice + DEFAULT_PRIO
//! PRIO_TO_NICE: prio - DEFAULT_PRIO
//! Priority of a process goes from 0..MAX_PRIO-1, valid RT
//! priority is 0..MAX_RT_PRIO-1, and SCHED_NORMAL/SCHED_BATCH
//! tasks are in the range MAX_RT_PRIO..MAX_PRIO-1. Priority
//! values are inverted: lower p->prio value means higher priority.
//! prio越低，优先级越高 

// the range of nice value: -20 ~ 19
const MAX_NICE: i32 = 19;
const MIN_NICE: i32 = -20;
const NICE_WIDTH: i32 = MAX_NICE - MIN_NICE + 1;


const MAX_RT_PRIO: i32 = 100;

const MAX_PRIO: i32 = MAX_RT_PRIO + NICE_WIDTH;
const DEFAULT_PRIO: i32 = MAX_RT_PRIO + NICE_WIDTH / 2;

pub const WMULT_SHIFT: i32 = 32;

/*
 * Nice levels are multiplicative, with a gentle 10% change for every
 * nice level changed. I.e. when a CPU-bound task goes from nice 0 to
 * nice 1, it will get ~10% less CPU time than another CPU-bound task
 * that remained on nice 0.
 *
 * The "10% effect" is relative and cumulative: from _any_ nice level,
 * if you go up 1 level, it's -10% CPU usage, if you go down 1 level
 * it's +10% CPU usage. (to achieve that we use a multiplier of 1.25.
 * If a task goes up by ~10% and another task goes down by ~10% then
 * the relative distance between them is ~25%.)
 */
pub const SCHED_PRIO_TO_WEIGHT : [i32; 40] = [
 /* -20 */     88761,     71755,     56483,     46273,     36291,
 /* -15 */     29154,     23254,     18705,     14949,     11916,
 /* -10 */      9548,      7620,      6100,      4904,      3906,
 /*  -5 */      3121,      2501,      1991,      1586,      1277,
 /*   0 */      1024,       820,       655,       526,       423,
 /*   5 */       335,       272,       215,       172,       137,
 /*  10 */       110,        87,        70,        56,        45,
 /*  15 */        36,        29,        23,        18,        15,
];


/*
 * Inverse (2^32/x) values of the sched_prio_to_weight[] array, precalculated.
 *
 * In cases where the weight does not change often, we can use the
 * precalculated inverse to speed up arithmetics by turning divisions
 * into multiplications:
 */
pub const SCHED_PRIO_TO_WMULT: [u32; 40] = [
 /* -20 */     48388,     59856,     76040,     92818,    118348,
 /* -15 */    147320,    184698,    229616,    287308,    360437,
 /* -10 */    449829,    563644,    704093,    875809,   1099582,
 /*  -5 */   1376151,   1717300,   2157191,   2708050,   3363326,
 /*   0 */   4194304,   5237765,   6557202,   8165337,  10153587,
 /*   5 */  12820798,  15790321,  19976592,  24970740,  31350126,
 /*  10 */  39045157,  49367440,  61356676,  76695844,  95443717,
 /*  15 */ 119304647, 148102320, 186737708, 238609294, 286331153,
];

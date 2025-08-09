use core::{any::Any, fmt::Debug};

use alloc::{boxed::Box, string::String, vec::Vec};

use crate::{bpf::syscall::bpf_call, fs::file::FileOp, syscall::errno::Errno};

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct BpfInsn {
    pub code: u8, /* opcode */
    // 注意dst_reg和src_reg各是4位, packed在一个字节中
    dst_src_reg: u8, /* dest register + src_reg */
    pub off: i16,    /* signed offset */
    pub imm: i32,    /* signed immediate constant */
}

impl Debug for BpfInsn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BpfInsn")
            .field("code", &self.code)
            .field("dst_reg", &(self.dst_reg()))
            .field("src_reg", &(self.src_reg()))
            .field("off", &self.off)
            .field("imm", &self.imm)
            .finish()
    }
}

impl BpfInsn {
    pub fn dst_reg(&self) -> usize {
        (self.dst_src_reg & 0xF) as usize // 只取低4位
    }
    pub fn src_reg(&self) -> usize {
        (self.dst_src_reg >> 4 & 0xF) as usize // 只取高4位
    }
}

// BPF程序类型
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BpfProgType {
    SocketFilter = 1,
    Kprobe = 2,
    SchedCls = 3,
    SchedAct = 4,
    Tracepoint = 5,
    Xdp = 6,
    PerfEvent = 7,
    CgroupSkb = 8,
    CgroupSock = 9,
    LwtIn = 10,
    LwtOut = 11,
    LwtXmit = 12,
    SockOps = 13,
    SkSkb = 14,
    CgroupDevice = 15,
    SkMsg = 16,
    RawTracepoint = 17,
    CgroupSockAddr = 18,
    LwtSeg6local = 19,
    LircMode2 = 20,
    SkReuseport = 21,
    FlowDissector = 22,
    CgroupSysctl = 23,
    RawTracepointWritable = 24,
    CgroupSockopt = 25,
    Tracing = 26,
    StructOps = 27,
    Ext = 28,
    Lsm = 29,
    SkLookup = 30,
    Syscall = 31,
}

impl TryFrom<u32> for BpfProgType {
    type Error = Errno;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(BpfProgType::SocketFilter),
            2 => Ok(BpfProgType::Kprobe),
            3 => Ok(BpfProgType::SchedCls),
            4 => Ok(BpfProgType::SchedAct),
            5 => Ok(BpfProgType::Tracepoint),
            6 => Ok(BpfProgType::Xdp),
            7 => Ok(BpfProgType::PerfEvent),
            8 => Ok(BpfProgType::CgroupSkb),
            9 => Ok(BpfProgType::CgroupSock),
            10 => Ok(BpfProgType::LwtIn),
            11 => Ok(BpfProgType::LwtOut),
            12 => Ok(BpfProgType::LwtXmit),
            13 => Ok(BpfProgType::SockOps),
            14 => Ok(BpfProgType::SkSkb),
            15 => Ok(BpfProgType::CgroupDevice),
            16 => Ok(BpfProgType::SkMsg),
            17 => Ok(BpfProgType::RawTracepoint),
            18 => Ok(BpfProgType::CgroupSockAddr),
            19 => Ok(BpfProgType::LwtSeg6local),
            20 => Ok(BpfProgType::LircMode2),
            21 => Ok(BpfProgType::SkReuseport),
            22 => Ok(BpfProgType::FlowDissector),
            23 => Ok(BpfProgType::CgroupSysctl),
            24 => Ok(BpfProgType::RawTracepointWritable),
            25 => Ok(BpfProgType::CgroupSockopt),
            26 => Ok(BpfProgType::Tracing),
            27 => Ok(BpfProgType::StructOps),
            28 => Ok(BpfProgType::Ext),
            29 => Ok(BpfProgType::Lsm),
            30 => Ok(BpfProgType::SkLookup),
            31 => Ok(BpfProgType::Syscall),
            _ => Err(Errno::EINVAL), // 无效的BPF程序类型
        }
    }
}

// BPF Token结构（权限委托）
#[allow(unused)]
pub struct BpfToken {
    pub allowed_cmds: u64,
    pub allowed_prog_types: u64,
    pub allowed_attach_types: u64,
}

// BPF程序结构
#[allow(unused)]
pub struct BpfProg {
    pub id: u32,
    pub prog_type: BpfProgType,
    pub expected_attach_type: u32,
    pub sleepable: bool,
    pub gpl_compatible: bool,
    pub jited: bool,
    pub insns_ptr: u64,   // 指令指针
    pub insns_count: u32, // 指令数量
    pub instructions: Vec<BpfInsn>,
    pub license: String,
    pub name: String,
    pub load_time: u64,
    pub attach_btf_id: u32,
    pub ifindex: Option<u32>,
    pub xdp_has_frags: bool,
    pub dev_bound: bool,
    pub refcount: u32,
    // 附加的目标程序
    pub dst_prog: Option<Box<BpfProg>>,
    // Token用于权限验证
    pub token: Option<BpfToken>,
}

// 为了分配fd给BPF程序
impl FileOp for BpfProg {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl BpfProg {
    pub fn new(prog_type: BpfProgType, insns_ptr: u64, insns_count: u32) -> Self {
        BpfProg {
            id: 0,
            prog_type,
            expected_attach_type: 0,
            sleepable: false,
            gpl_compatible: false,
            jited: false,
            insns_ptr,
            insns_count,
            instructions: Vec::new(),
            license: String::new(),
            name: String::new(),
            load_time: 0,
            attach_btf_id: 0,
            ifindex: None,
            xdp_has_frags: false,
            dev_bound: false,
            refcount: 1, // 初始引用计数为1
            dst_prog: None,
            token: None, // 初始没有Token
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum BpfInsnClass {
    BpfLd = 0x00,    // Load
    BpfLdx = 0x01,   // Load Index
    BpfSt = 0x02,    // Store
    BpfStx = 0x03,   // Store Index
    BpfAlu = 0x04,   // ALU Operations
    BpfJmp = 0x05,   // Jump
    BpfRet = 0x06,   // Return
    BpfAlu64 = 0x07, // Miscellaneous
}

impl Debug for BpfInsnClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BpfInsnClass::BpfLd => write!(f, "BPF_LD"),
            BpfInsnClass::BpfLdx => write!(f, "BPF_LDX"),
            BpfInsnClass::BpfSt => write!(f, "BPF_ST"),
            BpfInsnClass::BpfStx => write!(f, "BPF_STX"),
            BpfInsnClass::BpfAlu => write!(f, "BPF_ALU"),
            BpfInsnClass::BpfJmp => write!(f, "BPF_JMP"),
            BpfInsnClass::BpfRet => write!(f, "BPF_RET"),
            BpfInsnClass::BpfAlu64 => write!(f, "BPF_ALU64"),
        }
    }
}

impl From<u8> for BpfInsnClass {
    fn from(value: u8) -> Self {
        match value & 0x07 {
            0x00 => BpfInsnClass::BpfLd,
            0x01 => BpfInsnClass::BpfLdx,
            0x02 => BpfInsnClass::BpfSt,
            0x03 => BpfInsnClass::BpfStx,
            0x04 => BpfInsnClass::BpfAlu,
            0x05 => BpfInsnClass::BpfJmp,
            0x06 => BpfInsnClass::BpfRet,
            0x07 => BpfInsnClass::BpfAlu64,
            _ => unreachable!(),
        }
    }
}

// BPF指令码定义
pub const BPF_LD: u8 = 0x00; // Load
pub const BPF_LDX: u8 = 0x01; // Load Index
#[allow(unused)]
pub const BPF_ST: u8 = 0x02; // Store
pub const BPF_STX: u8 = 0x03; // Store Index
pub const BPF_ALU: u8 = 0x04; // ALU Operations
pub const BPF_JMP: u8 = 0x05; // Jump
#[allow(unused)]
pub const BPF_RET: u8 = 0x06; // Return
pub const BPF_ALU64: u8 = 0x07; // ALU Operations 64-bit

const BPF_CLASS_MASK: u8 = 0x07; // BPF指令类别掩码
const BPF_OP_MASK: u8 = 0xF0; // BPF操作码掩码
const BPF_SRC_REG: u8 = 0x08; // opcode第4位, 为1, 表示使用源寄存器src_reg作为源操作数, 为0, 表示使用imm32作为源操作数

// BPF算数指令
const BPF_ADD: u8 = 0x00; // 加法
const BPF_SUB: u8 = 0x10; // 减法
const BPF_MUL: u8 = 0x20; // 乘法
const BPF_DIV: u8 = 0x30; // 除法
const BPF_OR: u8 = 0x40; // 按位或
const BPF_AND: u8 = 0x50; // 按位与
const BPF_LSH: u8 = 0x60; // 左移
const BPF_RSH: u8 = 0x70; // 右移
const BPF_NEG: u8 = 0x80; // 取反
const BPF_MOD: u8 = 0x90; // 取模
const BPF_XOR: u8 = 0xA0; // 按位异或
const BPF_MOV: u8 = 0xB0; // 移动
const BPF_ARSH: u8 = 0xC0; // 算术右移
#[allow(unused)]
const BPF_END: u8 = 0xD0; // 结束

// BPF跳转指令
const BPF_JA: u8 = 0x00;
const BPF_JEQ: u8 = 0x10;
const BPF_JGT: u8 = 0x20;
const BPF_JGE: u8 = 0x30;
const BPF_JLT: u8 = 0xa0;
const BPF_JLE: u8 = 0xb0;
const BPF_JNE: u8 = 0x50;
const BPF_JSGT: u8 = 0x60;
const BPF_JSET: u8 = 0x40;
const BPF_EXIT: u8 = 0x90;
const BPF_CALL: u8 = 0x80;

pub fn interpret(insns: &[BpfInsn], bpf_itet_task_ptr: usize) -> u64 {
    const BPF_STACK_SIZE: usize = 512; // 模拟栈大小
    let mut regs = [0u64; 11]; // R0~R10
    let stack = [0u8; BPF_STACK_SIZE]; // 模拟栈
    regs[10] = stack.as_ptr() as u64 + BPF_STACK_SIZE as u64; // R10指向栈顶
    regs[1] = bpf_itet_task_ptr as u64; // R1指向BPF迭代器任务指针

    let mut pc = 0;

    while pc < insns.len() {
        let insn = insns[pc];
        let class = insn.code & BPF_CLASS_MASK;
        let dst = insn.dst_reg() as usize;
        let src = insn.src_reg() as usize;
        let op = insn.code & BPF_OP_MASK;
        let class_debug = BpfInsnClass::from(insn.code & BPF_CLASS_MASK);

        // 源操作数
        let val = if (insn.code & BPF_SRC_REG) != 0 {
            regs[src]
        } else {
            insn.imm as u64
        };
        // 7.27 Debug
        log::info!(
            "BPF Instruction: pc={}, code={:#x}, dst={}, src={}, off={}, imm={}, op={}, class={:?}",
            pc,
            insn.code,
            dst,
            src,
            insn.off,
            insn.imm,
            op,
            class_debug
        );

        match class {
            BPF_ALU => match op {
                BPF_ADD => regs[dst] = regs[dst].wrapping_add(val),
                BPF_SUB => regs[dst] = regs[dst].wrapping_sub(val),
                BPF_MUL => regs[dst] = regs[dst].wrapping_mul(val),
                BPF_DIV => {
                    if val != 0 {
                        regs[dst] /= val
                    }
                }
                BPF_OR => regs[dst] |= val,
                BPF_AND => regs[dst] &= val,
                BPF_LSH => regs[dst] <<= val,
                BPF_RSH => regs[dst] >>= val,
                BPF_MOD => {
                    if val != 0 {
                        regs[dst] %= val
                    }
                }
                BPF_XOR => regs[dst] ^= val,
                BPF_MOV => regs[dst] = val,
                BPF_ARSH => regs[dst] = (regs[dst] as i64 >> val) as u64,
                BPF_NEG => regs[dst] = -(regs[dst] as i64) as u64,
                _ => unimplemented!("ALU opcode {:x}", op),
            },

            BPF_ALU64 => match op {
                BPF_ADD => regs[dst] = regs[dst].wrapping_add(val),
                BPF_SUB => regs[dst] = regs[dst].wrapping_sub(val),
                BPF_MUL => regs[dst] = regs[dst].wrapping_mul(val),
                BPF_DIV => {
                    if val != 0 {
                        regs[dst] /= val
                    }
                }
                BPF_OR => regs[dst] |= val,
                BPF_AND => regs[dst] &= val,
                BPF_LSH => regs[dst] <<= val,
                BPF_RSH => regs[dst] >>= val,
                BPF_MOD => {
                    if val != 0 {
                        regs[dst] %= val
                    }
                }
                BPF_XOR => regs[dst] ^= val,
                BPF_MOV => regs[dst] = val,
                BPF_ARSH => regs[dst] = (regs[dst] as i64 >> val) as u64,
                BPF_NEG => regs[dst] = -(regs[dst] as i64) as u64,
                _ => unimplemented!("ALU64 opcode {:x}", op),
            },

            BPF_JMP => {
                let dst_val = regs[dst];
                match op {
                    BPF_JA => {
                        pc = ((pc as isize) + 1 + insn.off as isize) as usize;
                        continue;
                    }
                    BPF_JEQ => {
                        if dst_val == val {
                            pc = ((pc as isize) + 1 + insn.off as isize) as usize;
                            continue;
                        }
                    }
                    BPF_JNE => {
                        if dst_val != val {
                            pc = ((pc as isize) + 1 + insn.off as isize) as usize;
                            continue;
                        }
                    }
                    BPF_JSGT => {
                        if (dst_val as i64) > (val as i64) {
                            pc = ((pc as isize) + 1 + insn.off as isize) as usize;
                            continue;
                        }
                    }
                    BPF_JGT => {
                        if dst_val > val {
                            pc = ((pc as isize) + 1 + insn.off as isize) as usize;
                            continue;
                        }
                    }
                    BPF_JGE => {
                        if dst_val >= val {
                            pc = ((pc as isize) + 1 + insn.off as isize) as usize;
                            continue;
                        }
                    }
                    BPF_JLT => {
                        if dst_val < val {
                            pc = ((pc as isize) + 1 + insn.off as isize) as usize;
                            continue;
                        }
                    }
                    BPF_JLE => {
                        if dst_val <= val {
                            pc = ((pc as isize) + 1 + insn.off as isize) as usize;
                            continue;
                        }
                    }
                    BPF_JSET => {
                        if (dst_val & val) != 0 {
                            pc = ((pc as isize) + 1 + insn.off as isize) as usize;
                            continue;
                        }
                    }
                    BPF_CALL => {
                        // helper call stub — return 0
                        bpf_call(insn.imm as u32, &mut regs);
                        log::info!("BPF_CALL: imm={:#x}, reg[0]={:#x}", insn.imm, regs[0]);
                    }
                    BPF_EXIT => return regs[0],
                    _ => panic!("Unknown JMP opcode: {:x}", op),
                }
            }
            BPF_LD => {
                //  宽指令, 从`imm64`加载数据到寄存器
                // let imm64 = unsafe { (&insns[pc + 1] as *const _ as *const u64).read() };
                let imm64 = insn.imm as u64 | ((insns[pc + 1].imm as u64) << 32);
                regs[dst] = imm64;
                pc += 1; // 跳过下一个指令
            }
            BPF_LDX => {
                let addr = regs[src].wrapping_add(insn.off as u64);
                let val = unsafe { (addr as *const u64).read() };
                log::info!(
                    "BPF_LDX: src={}, insn.off={}, addr={:#x}, val=0x{:#x}",
                    src,
                    insn.off,
                    addr,
                    val
                );
                regs[dst] = val;
            }

            BPF_STX => {
                let addr = regs[dst].wrapping_add(insn.off as u64);
                let val = regs[src].to_le_bytes();
                log::info!(
                    "BPF_STX: dst={}, src={}, insn.off={}, addr={:#x}, val=0x{:x?}",
                    dst,
                    src,
                    insn.off,
                    addr,
                    val
                );
                unsafe {
                    let ptr = addr as *mut u64;
                    *ptr = u64::from_le_bytes(val);
                }
            }

            _ => unimplemented!("Unsupported class {:x}", class),
        }

        pc += 1;
    }

    regs[0]
}

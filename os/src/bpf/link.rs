use alloc::sync::Arc;

use crate::{fs::file::FileOp, syscall::errno::Errno};

use super::insn::{BpfProg, BpfProgType};

pub enum BpfLinkType {
    Unspec,
    RawTracePoint,
    Tracing,
    Cgroup,
    Iter,
    Netns,
    Xdp,
    PerfEvent,
}

impl TryFrom<u32> for BpfLinkType {
    type Error = Errno;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(BpfLinkType::Unspec),
            1 => Ok(BpfLinkType::RawTracePoint),
            2 => Ok(BpfLinkType::Tracing),
            3 => Ok(BpfLinkType::Cgroup),
            4 => Ok(BpfLinkType::Iter),
            5 => Ok(BpfLinkType::Netns),
            6 => Ok(BpfLinkType::Xdp),
            7 => Ok(BpfLinkType::PerfEvent),
            _ => Err(Errno::EINVAL), // 无效的BPF链接类型
        }
    }
}

pub struct BpfLink {
    pub prog: Arc<dyn FileOp>,
    pub attach_type: BpfProgType,
    pub attach_btf_id: u32,
}

impl BpfLink {
    pub fn new(prog: Arc<dyn FileOp>, attach_type: BpfProgType, attach_btf_id: u32) -> Self {
        BpfLink {
            prog,
            attach_type,
            attach_btf_id,
        }
    }
}

impl FileOp for BpfLink {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

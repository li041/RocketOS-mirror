#[repr(C)]
#[repr(align(8))]
#[derive(Default, Copy, Clone)]
pub struct BpfProcLoadAttr {
    pub prog_type: u32,
    pub insn_cnt: u32,
    pub insns: u64,   // 指向指令的指针
    pub license: u64, // 指向许可证字符串的指针
    pub log_level: u32,
    pub log_size: u32,
    pub log_buf: u64,
    pub kern_version: u32,
    // ... 其他属性
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct BpfMapCreateAttr {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub flags: u32,
    // ... 其他属性
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct BpfMapElemAttr {
    pub map_fd: u32,
    pub key: u64,   // 指向键的指针
    pub value: u64, // 指向值的指针
    pub flags: u32,
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct BpfAttrBtfLoad {
    pub btf_ptr: u64,
    pub btf_log_buf: u64,
    pub btf_size: u32,
    pub btf_log_size: u32,
    pub btf_log_level: u32,
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct BpfAttrLinkCreate {
    pub prog_fd: u32,
    pub target_fd: u32, // 或者target_ifindex, 这里原来是union
    pub attach_type: u32,
    pub flags: u32,
    pub attach_btf_id: u32,
    pub attach_prog_fd: u32,
    // ... 其他属性
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct BpfAttrIterCreate {
    pub link_fd: u32,
    pub flags: u32,
}

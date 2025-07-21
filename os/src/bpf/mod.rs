use alloc::vec;
use alloc::{sync::Arc, vec::Vec};
use attr::{BpfAttrBtfLoad, BpfAttrLinkCreate, BpfMapElemAttr, BpfProcLoadAttr};
use insn::{BpfInsn, BpfProg, BpfProgType};
use iter::Iterator;
use link::{BpfLink, BpfLinkType};
use map::{BpfMap, BpfMapType, BPF_OBJECT_TABLE};
use uapi::BtfObject;

use crate::arch::mm::copy_to_user;
use crate::syscall::errno::SyscallRet;
use crate::{
    arch::mm::copy_from_user, fs::fdtable::FdFlags, syscall::errno::Errno, task::current_task,
};

mod attr;
mod insn;
mod iter;
mod link;
mod map;
mod syscall;
pub mod uapi;

// helper
fn vec_to_u64(vec: &[u8]) -> Option<u64> {
    if vec.len() > 8 {
        return None;
    }

    let mut result = 0u64;
    for (i, &byte) in vec.iter().enumerate() {
        result |= (byte as u64) << (8 * i);
    }
    Some(result)
}

pub fn bpf_prog_load(bpf_attr_ptr: usize, size: usize) -> Result<usize, Errno> {
    if size < core::mem::size_of::<BpfProcLoadAttr>() {
        return Err(Errno::EINVAL);
    }
    let mut attr = BpfProcLoadAttr::default();
    copy_from_user(bpf_attr_ptr as *mut BpfProcLoadAttr, &mut attr, 1)?;

    // Todo: 验证属性和标志
    // Todo: 处理Token权限机制
    // Todo: 权限检查

    // 获取指令长度和偏移
    let insn_cnt = attr.insn_cnt as usize;
    let insn_size = insn_cnt * core::mem::size_of::<u64>();

    // Todo: 加载prog
    let prog_type = BpfProgType::try_from(attr.prog_type).map_err(|_| Errno::EINVAL)?;
    let mut prog = BpfProg::new(prog_type, attr.insns, attr.insn_cnt);

    // Todo: 复制指令
    prog.instructions = copy_instructions_from_user(attr.insns, attr.insn_cnt)?;

    // 7.21 Debug 打印指令信息
    log::info!(
        "Loading BPF program: type={:?}, insn_cnt={}",
        prog.prog_type,
        insn_cnt
    );
    for insn in &prog.instructions {
        println!("BPF Instruction: {:?}", insn);
    }
    current_task()
        .fd_table()
        .alloc_fd(Arc::new(prog), FdFlags::empty())
}

pub fn bpf_map_create(bpf_attr_ptr: usize, size: usize) -> Result<usize, Errno> {
    if size < core::mem::size_of::<attr::BpfMapCreateAttr>() {
        log::error!("[bpf_map_create]: size too small");
        return Err(Errno::EINVAL);
    }
    let mut attr = attr::BpfMapCreateAttr::default();
    copy_from_user(bpf_attr_ptr as *mut attr::BpfMapCreateAttr, &mut attr, 1)?;

    let map = BpfMap::new(
        attr.map_type,
        attr.key_size,
        attr.value_size,
        attr.max_entries,
    );
    log::info!("[bpf_map_create]: Created BPF map with type: {}, key_size: {}, value_size: {}, max_entries: {}",
        attr.map_type, attr.key_size, attr.value_size, attr.max_entries);
    let map_type = BpfMapType::try_from(attr.map_type).map_err(|_| Errno::EINVAL)?;
    match map_type {
        BpfMapType::Array | BpfMapType::PerCpuArray => {
            log::info!("[bpf_map_create]: Created an Array map");
            for i in 0..attr.max_entries {
                // 初始化map的每个entry
                let key = (i as u32).to_le_bytes()[..attr.key_size as usize].to_vec();
                let value = vec![0u8; attr.value_size as usize];
                map.data.write().insert(key, value);
            }
            for (key, value) in map.data.read().iter() {
                log::info!("[bpf_map_create]: Initial entry: key={:?}, value={:?}", key, value);
            }
        }
        BpfMapType::StackTrace => {
            log::info!("[bpf_map_create]: Created a StackTrace map");
        }
        _ => {
            log::warn!("[bpf_map_create]: Unsupported map type: {:?}", map_type);
            return Err(Errno::ENOSYS);
        }
    }
    current_task()
        .fd_table()
        .alloc_fd(Arc::new(map), FdFlags::empty())
}

pub fn bpf_map_update_elem(bpf_attr_ptr: usize, size: usize) -> SyscallRet {
    if size < core::mem::size_of::<attr::BpfMapElemAttr>() {
        return Err(Errno::EINVAL);
    }
    let mut attr = attr::BpfMapElemAttr::default();
    copy_from_user(bpf_attr_ptr as *mut attr::BpfMapElemAttr, &mut attr, 1)?;
    // let key = unsafe { core::slice::from_raw_parts(attr.key, 32).to_vec() }; // 32: max key size
    let fd = attr.map_fd as usize;
    let task = current_task();
    if let Some(file) = task.fd_table().get_file(fd) {
        if let Some(map) = file.as_any().downcast_ref::<BpfMap>() {
            let key_size = map.key_size as usize;
            let mut key_buf = vec![0u8; key_size];
            copy_from_user(attr.key as *mut u8, key_buf.as_mut_ptr(), key_size)?;
            let val_size = map.value_size as usize;
            let mut value_buf = vec![0u8; val_size];
            copy_from_user(attr.value as *mut u8, value_buf.as_mut_ptr(), val_size)?;
            log::info!(
                "[bpf_map_update_elem]: Updating map with fd: {}, key: {:?}, value: {:?}",
                fd,
                key_buf,
                value_buf
            );
            // Todo: 根据attr.flags 处理不同的更新逻辑
            map.data.write().insert(key_buf, value_buf);
            return Ok(0);
        }
    }
    Err(Errno::EBADF)
}

// 参考linux/kernel/bpf/syscall.c::map_lookup_elem
pub fn bpf_map_lookup_elem(bpf_attr_ptr: usize, size: usize) -> Result<usize, Errno> {
    if size < core::mem::size_of::<attr::BpfMapElemAttr>() {
        return Err(Errno::EINVAL);
    }
    let mut attr = attr::BpfMapElemAttr::default();
    copy_from_user(bpf_attr_ptr as *mut attr::BpfMapElemAttr, &mut attr, 1)?;
    // let key = unsafe { core::slice::from_raw_parts(attr.key, 32).to_vec() }; // 32: max key size
    let fd = attr.map_fd as usize;
    let task = current_task();

    if let Some(file) = task.fd_table().get_file(fd) {
        if let Some(map) = file.as_any().downcast_ref::<BpfMap>() {
            let key_size = map.key_size as usize;
            let mut key_buf = vec![0u8; key_size];
            copy_from_user(attr.key as *mut u8, key_buf.as_mut_ptr(), key_size)?;
            match map.data.read().get(&key_buf) {
                Some(value) => {
                    // 将 value 复制到用户空间
                    copy_to_user(attr.value as *mut u8, value.as_ptr(), value.len())?;
                    return Ok(0);
                }
                None => return Err(Errno::ENOENT),
            }
        }
    }
    Err(Errno::EBADF)
}

pub fn bpf_btf_load(bpf_attr_ptr: usize, size: usize) -> Result<usize, Errno> {
    if size < core::mem::size_of::<BpfAttrBtfLoad>() {
        log::error!("[bpf_btf_load]: size too small");
        return Err(Errno::EINVAL);
    }
    let mut attr: BpfAttrBtfLoad = BpfAttrBtfLoad::default();
    copy_from_user(bpf_attr_ptr as *mut BpfAttrBtfLoad, &mut attr, 1)?;

    let mut btf_data = vec![0u8; attr.btf_size as usize];
    copy_from_user(
        attr.btf_ptr as *const u8,
        btf_data.as_mut_ptr(),
        attr.btf_size as usize,
    )?;

    // if !validate_btf_header(&btf_data) {
    //     return Err(Errno:EINVAL);
    // }
    let btf = BtfObject { data: btf_data };
    current_task()
        .fd_table()
        .alloc_fd(Arc::new(btf), FdFlags::empty())
}

pub fn bpf_btf_link_create(bpf_attr_ptr: usize, size: usize) -> Result<usize, Errno> {
    if size < core::mem::size_of::<attr::BpfAttrLinkCreate>() {
        log::error!("[bpf_btf_link_create]: size too small");
        return Err(Errno::EINVAL);
    }
    let mut attr = BpfAttrLinkCreate::default();
    copy_from_user(bpf_attr_ptr as *mut attr::BpfAttrLinkCreate, &mut attr, 1)?;
    log::info!("[bpf_btf_link_create]: Creating BPF link with prog_fd: {}, target_fd: {}, attach_type: {}, attach_btf_id: {}",
        attr.prog_fd, attr.target_fd, attr.attach_type, attr.attach_btf_id
    );
    if let Some(file) = current_task().fd_table().get_file(attr.prog_fd as usize) {
        // 确定文件类型是BpfProg
        if let Some(prog) = file.clone().as_any().downcast_ref::<BpfProg>() {
            // Todo: 验证attach_type和attach_btf_id
            let attach_type = BpfProgType::try_from(attr.attach_type)?;
            // match prog.prog_type {
            //     BpfProgType::Tracing => {
            //         // 7.24 Debug
            //         log::warn!(
            //             "[bpf_btf_link_create]: Creating BPF link for tracing program: {:?}",
            //             prog.name
            //         );
            //         let link = BpfLink::new(file, attach_type, attr.attach_btf_id);
            //     }
            //     _ => {
            //         log::error!("[bpf_btf_link_create]: Unsupported BPF program type for linking");
            //         return Err(Errno::ENOSYS);
            //     }
            // }
            let link = BpfLink::new(file, attach_type, attr.attach_btf_id);
            return current_task()
                .fd_table()
                .alloc_fd(Arc::new(link), FdFlags::empty());
        }
        // Todo: 核对errno是否为这个
        return Err(Errno::EINVAL);
    }
    log::error!("[bpf_btf_link_create]: Invalid program file descriptor");
    Err(Errno::EBADF)
}

pub fn bpf_iter_create(bpf_attr_ptr: usize, size: usize) -> Result<usize, Errno> {
    if size < core::mem::size_of::<attr::BpfAttrIterCreate>() {
        log::error!("[bpf_iter_create]: size too small");
        return Err(Errno::EINVAL);
    }
    let mut attr = attr::BpfAttrIterCreate::default();
    copy_from_user(bpf_attr_ptr as *mut attr::BpfAttrIterCreate, &mut attr, 1)?;
    log::info!(
        "[bpf_iter_create]: Creating BPF iterator with link_fd: {}, flags: {}",
        attr.link_fd,
        attr.flags
    );
    if let Some(file) = current_task().fd_table().get_file(attr.link_fd as usize) {
        // 确定文件类型是BpfLink
        if let Some(link) = file.clone().as_any().downcast_ref::<BpfLink>() {
            let iter = Iterator::new(file);
            return current_task()
                .fd_table()
                .alloc_fd(Arc::new(iter), FdFlags::empty());
        }
        return Err(Errno::EINVAL);
    }
    Err(Errno::EBADF)
}

pub fn copy_instructions_from_user(insns_ptr: u64, count: u32) -> Result<Vec<BpfInsn>, Errno> {
    // 从用户空间复制指令
    // 这里需要实现实际的内存复制逻辑
    let mut instructions = Vec::with_capacity(count as usize);

    for i in 0..count {
        let insn_ptr =
            (insns_ptr + (i as u64 * core::mem::size_of::<BpfInsn>() as u64)) as *const BpfInsn;
        // let insn = unsafe { *insn_ptr };
        let mut insn = BpfInsn::default();
        copy_from_user(insn_ptr, &mut insn, 1)?;
        // 7.30 Debug, 逐字节打印insn
        {
            let mut insn_vec = vec![0u8; 8];
            copy_from_user(insn_ptr as *const u8, insn_vec.as_mut_ptr(), 8)?;
            // let insn_ptr = insn_ptr as *const u8;
            // let insn_slice =
            //     unsafe { core::slice::from_raw_parts(insn_ptr, core::mem::size_of::<BpfInsn>()) };
            // print!("BPF Instruction Bytes: ");
            // for byte in insn_slice {
            //     print!("{:#x}", byte);
            //     print!(" ");
            // }
            // println!("");
            // 7.30 Debug, 逐字节打印insn_vec
            // print!("BPF Instruction Vec Bytes: ");
            // for byte in &insn_vec {
            //     print!("{:#x}", byte);
            //     print!(" ");
            // }
            // println!("");
        }
        instructions.push(insn);
    }
    Ok(instructions)
}

// pub fn copy_instructions_from_user(mut insns_ptr: u64, count: u32) -> Result<Vec<BpfInsn>, Errno> {
//     // 从用户空间复制指令
//     // 这里需要实现实际的内存复制逻辑
//     let mut instructions = Vec::with_capacity(count as usize);

//     for i in 0..count {
//         let mut insn = BpfInsn::default();
//         let mut code: u8 = 0;
//         let mut dst_src_reg: u8 = 0;
//         let mut off: i16 = 0;
//         let mut imm: i32 = 0;
//         copy_from_user(insns_ptr as *const u8, &mut code, 1)?;
//         insns_ptr += 8;
//         copy_from_user(insns_ptr as *const u8, &mut dst_src_reg, 1)?;
//         insns_ptr += 8;
//         copy_from_user(insns_ptr as *const i16, &mut off, 1);
//         insns_ptr += 16;
//         copy_from_user(insns_ptr as *const i32, &mut imm, 1)?;
//         log::info!(
//             "[copy_instructions_from_user]: Instruction {}: code: {:#x}, dst_src_reg: {:#x}, off: {}, imm: {}",
//             i,
//             code,
//             dst_src_reg,
//             off,
//             imm
//         );
//         let insn = BpfInsn::new(code, dst_src_reg, off, imm);

//         // 7.30 Debug, 逐字节打印insn, 好像复制有问题, 逐字节看看
//         let insn_ptr = &insn as *const BpfInsn as *const u8;
//         let insn_slice =
//             unsafe { core::slice::from_raw_parts(insn_ptr, core::mem::size_of::<BpfInsn>()) };
//         print!("BPF Instruction Bytes: ");
//         for byte in insn_slice {
//             print!("{:#x}", byte);
//             print!(" ");
//         }
//         println!("");

//         instructions.push(insn);
//     }
//     Ok(instructions)
// }

// 只看字节看看
// pub fn copy_instructions_from_user(mut insns_ptr: u64, count: u32) -> Result<Vec<BpfInsn>, Errno> {
//     // 从用户空间复制指令
//     // 这里需要实现实际的内存复制逻辑
//     let mut instructions = Vec::with_capacity(count as usize);

//     for i in 0..count {
//         let mut insn = BpfInsn::default();
//         let mut code: u8 = 0;
//         let mut dst_src_reg: u8 = 0;
//         let mut off: i16 = 0;
//         let mut imm: i32 = 0;
//         copy_from_user(insns_ptr as *const u8, &mut code, 1)?;
//         insns_ptr += 8;
//         copy_from_user(insns_ptr as *const u8, &mut dst_src_reg, 1)?;
//         insns_ptr += 8;
//         copy_from_user(insns_ptr as *const i16, &mut off, 1);
//         insns_ptr += 16;
//         copy_from_user(insns_ptr as *const i32, &mut imm, 1)?;
//         log::info!(
//             "[copy_instructions_from_user]: Instruction {}: code: {:#x}, dst_src_reg: {:#x}, off: {}, imm: {}",
//             i,
//             code,
//             dst_src_reg,
//             off,
//             imm
//         );
//         let insn = BpfInsn::new(code, dst_src_reg, off, imm);

//         // 7.30 Debug, 逐字节打印insn, 好像复制有问题, 逐字节看看
//         let insn_ptr = &insn as *const BpfInsn as *const u8;
//         let insn_slice =
//             unsafe { core::slice::from_raw_parts(insn_ptr, core::mem::size_of::<BpfInsn>()) };
//         print!("BPF Instruction Bytes: ");
//         for byte in insn_slice {
//             print!("{:#x}", byte);
//             print!(" ");
//         }

//         instructions.push(insn);
//     }
//     Ok(instructions)
// }

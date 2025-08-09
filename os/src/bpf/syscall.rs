use alloc::vec;
use num_enum::FromPrimitive;

use crate::task::current_task;

use super::{iter::LinuxTask, map::BpfMap, uapi::BpfFuncId};

pub fn bpf_call(func_id: u32, regs: &mut [u64; 11]) {
    let func_id = BpfFuncId::from_primitive(func_id);
    // 处理BPF调用
    match func_id {
        BpfFuncId::MapLookupElem => {
            // // 处理map lookup元素
            // // 这里可以添加具体的map lookup逻辑
            // regs[0] = 0; // 假设返回0表示成功
            let map_fd = regs[1] as usize; // 获取map的fd
            let key_fd = regs[2] as usize; // 获取key的fd
            let task = current_task();
            let map_file = task.fd_table().get_file(map_fd).unwrap();
            let map = map_file.as_any().downcast_ref::<BpfMap>().unwrap();
            // 获取map的key
            let key_file = task.fd_table().get_file(key_fd).unwrap();
            let key_map = key_file.as_any().downcast_ref::<BpfMap>().unwrap();
            let key_key = vec![0; key_map.key_size as usize]; // 创建一个空的key
            let key = key_map.get(key_key.as_slice()).unwrap();
            // log::info!(
            //     "[bpf_call]: MapLookupElem called with map_fd: {}, map: {:?}, key_fd: {}, key: {:?}",
            //     map_fd,
            //     map,
            //     key_fd,
            //     key_map,
            // );
            log::info!(
                "[bpf_call]: MapLookupElem called with map_fd: {}, key_fd: {}",
                map_fd,
                key_fd,
            );
            let map_data = map.data.read(); // 获取map的data
            let value_vec = map_data.get(&key); // 获取map中对应key的value
            if let Some(value_vec) = value_vec {
                // 将value转换为u64并返回
                regs[0] = value_vec.as_ptr() as *const _ as u64; // 假设value是u64类型
            } else {
                regs[0] = 0; // 未找到元素
            }
        }
        BpfFuncId::ProbeReadKernelStr => {
            // r1: dst, r2: size, r3: src
            let dst = regs[1] as *mut u8;
            let size = regs[2] as usize;
            let src = regs[3] as *const u8;
            log::info!(
                "[bpf_call]: ProbeReadKernelStr called with dst: {:p}, size: {}, src: {:p}",
                dst,
                size,
                src
            );

            let copied = unsafe {
                let mut i = 0;
                while i < size {
                    let c = *src.add(i);
                    *dst.add(i) = c;
                    i += 1;
                    if c == 0 {
                        break;
                    }
                }
                i
            };
            regs[0] = copied as u64;
        }
        BpfFuncId::SeqWrite => {
            // r1: struct seq_file *, r2: data ptr, r3: len
            let buf_ptr = regs[1] as *mut u8;
            let data = regs[2] as *const u8;
            let len = regs[3] as usize;
            log::info!(
                "[bpf_call]: SeqWrite called with buf_ptr: {:p}, data: {:p}, len: {}",
                buf_ptr,
                data,
                len
            );
            let res = unsafe {
                if !buf_ptr.is_null() {
                    let slice = core::slice::from_raw_parts(data, len);
                    core::ptr::copy_nonoverlapping(slice.as_ptr(), buf_ptr, len);
                    len
                } else {
                    0
                }
            };

            regs[0] = res as u64;
        }
        BpfFuncId::GetTaskStack => {
            // r1: task_struct *, r2: buf, r3: size, r4: flags
            let task = regs[1] as *const LinuxTask;
            let buf = regs[2] as *mut u8;
            let size = regs[3] as usize;
            let flags = regs[4];
            log::info!(
                "[bpf_call]: GetTaskStack called with task: {:p}, buf: {:p}, size: {}, flags: {}",
                task,
                buf,
                size,
                flags
            );

            let copied = unsafe {
                if let Some(task) = task.as_ref() {
                    task.copy_stack_trace(buf, size, flags)
                } else {
                    0
                }
            };
            regs[0] = copied as u64;
        }
        // 这里可以添加更多的BPF函数处理逻辑
        _ => {
            log::error!("Unsupported BPF function ID: {:?}", func_id);
        }
    }
}

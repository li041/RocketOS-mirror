use alloc::{format, string::{String, ToString}, vec::Vec};
use num_enum::TryFromPrimitive;
use spin::Mutex;

use crate::{fs::{file::{File, FileOp, OpenFlags}, namei::{filename_lookup, path_openat, Nameidata}, path::Path}, syscall::errno::Errno, task::current_task};
use alloc::vec;
use super::socket::Socket;
static LAST_DB: Mutex<Option<Database>> = Mutex::new(None);
/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-06-01 12:06:27
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-06-04 17:53:26
 * @FilePath: /RocketOS_netperfright/os/src/net/unix.rs
 * @Description: 
 * 
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved. 
 */
#[repr(u32)]
#[derive(Debug, Clone, Copy,TryFromPrimitive,PartialEq, Eq)]
pub enum RequestType {
    GetpwNam    = 2,   // 按用户名查 passwd 条目
    GetpwUid    = 3,   // 按 UID 查 passwd 条目
    GetgrNam    = 4,   // 按组名查 group 条目
    GetgrGid    = 5,   // 按 GID 查 group 条目
}
#[repr(u32)]
#[derive(Debug, Clone, Copy,TryFromPrimitive,PartialEq, Eq)]
pub enum Database {
    Passwd = 11,   // /etc/passwd 相应的编号
    Group  = 12,   // /etc/group 相应的编号（举例）
    Hosts  = 13,   // /etc/hosts 相应的编号（举例）

}
#[repr(C)]
#[derive(Debug, Clone)]
pub struct NscdRequest {
    pub req_type: RequestType,
    pub db:       Option<Database>, // 有时候第二字段为 0，表示“不切库，只给 key”           // key 的长度
    pub key:      String,           // 实际去查的字串，如 "passwd" 或 "nobody"
}
#[derive(Debug, Clone)]
pub struct PasswdEntry {
    pub pw_name: String,   // 用户名
    pub pw_passwd: String, // 密码字段（通常为 "x"）
    pub pw_uid: u32,       // 用户 UID
    pub pw_gid: u32,       // 用户 GID
    pub pw_gecos: String,  // 真实姓名（一般 Linux 默认等同用户名或为空）
    pub pw_dir: String,    // 主目录
    pub pw_shell: String,  // shell 路径
}


impl PasswdEntry {
    pub fn to_bytes(&self) -> Vec<u8> {
        // 1. 先把所有字符串的字节都准备好（末尾手动加 '\0'）
        let name_bytes   = self.pw_name.as_bytes();
        let passwd_bytes = self.pw_passwd.as_bytes();
        let gecos_bytes  = self.pw_gecos.as_bytes();
        let dir_bytes    = self.pw_dir.as_bytes();
        let shell_bytes  = self.pw_shell.as_bytes();

        // 各字符串 + 1 字节终结符
        let sz_name   = name_bytes.len()   + 1;
        let sz_passwd = passwd_bytes.len() + 1;
        let sz_gecos  = gecos_bytes.len()  + 1;
        let sz_dir    = dir_bytes.len()    + 1;
        let sz_shell  = shell_bytes.len()  + 1;

        // 2. 计算各个字段的偏移（从最开始算起）
        //    8×4 = 32 字节，紧跟在这 32 字节后面依次摆放字符串
        let off_pw_name   = 32;
        let off_pw_passwd = off_pw_name   + sz_name;
        let off_pw_gecos  = off_pw_passwd + sz_passwd;
        let off_pw_dir    = off_pw_gecos  + sz_gecos;
        let off_pw_shell  = off_pw_dir    + sz_dir;

        // 3. total_len = 32 字节头 + 所有字符串总和
        let total_len = 32 + sz_name + sz_passwd + sz_gecos + sz_dir + sz_shell;

        let mut buf = Vec::with_capacity(total_len);

        // 4. 先写 32 字节头部（8 个 u32，均小端）
        buf.extend_from_slice(&((total_len as u32).to_le_bytes()));    // [0..4)
        buf.extend_from_slice(&((off_pw_name   as u32).to_le_bytes())); // [4..8)
        buf.extend_from_slice(&((off_pw_passwd as u32).to_le_bytes())); // [8..12)
        buf.extend_from_slice(&(self.pw_uid.to_le_bytes()));           // [12..16)
        buf.extend_from_slice(&(self.pw_gid.to_le_bytes()));           // [16..20)
        buf.extend_from_slice(&((off_pw_gecos  as u32).to_le_bytes())); // [20..24)
        buf.extend_from_slice(&((off_pw_dir    as u32).to_le_bytes())); // [24..28)
        buf.extend_from_slice(&((off_pw_shell  as u32).to_le_bytes())); // [28..32)

        // 5. 再把每个字符串内容写进去，并在末尾加 '\0'
        buf.extend_from_slice(name_bytes);
        buf.push(0u8);

        buf.extend_from_slice(passwd_bytes);
        buf.push(0u8);

        buf.extend_from_slice(gecos_bytes);
        buf.push(0u8);

        buf.extend_from_slice(dir_bytes);
        buf.push(0u8);

        buf.extend_from_slice(shell_bytes);
        buf.push(0u8);

        buf
    }
 pub fn passwd_lookup(socket: &Socket, buf_len: usize) -> Result<Vec<u8>, Errno> {
    
    let nscdrequest=socket.socket_nscdrequest.lock().clone().unwrap();
    let key = nscdrequest.key;
    // if nscdrequest.req_type != RequestType::GetpwNam
    //     && nscdrequest.req_type != RequestType::GetpwUid
    // {
    //     return Err(Errno::EINVAL);
    // }
    let db: Database = {
        let mut last_db_lock = LAST_DB.lock();
        if let Some(d) = nscdrequest.db {
            // 本次请求有 db，就更新“上一次 db”的值
            *last_db_lock = Some(d);
            d
        } else {
            // 本次请求为 None，则尝试用上一次存的
            last_db_lock
                .clone()
                .ok_or(Errno::EINVAL)?  // 如果上一次也没有，就返回 EINVAL
        }
    };
    log::error!("[passwd_lookup] database is {:?}",db);
    if db == Database::Passwd {
        let file = path_openat("/etc/passwd", OpenFlags::O_CLOEXEC, -100, 0)?;
        let mut small_buf = [0u8; 128];
        let mut accu: Vec<u8> = Vec::new();

        loop {
            let n = file.read(&mut small_buf)?;
            if n == 0 {
                // 文件读完，检查最后是否还有残余没有 '\n'
                if !accu.is_empty() {
                    if let Some(line) = core::str::from_utf8(&accu).ok() {
                        log::error!("line: {}", line);
                        if let Some(entry) = PasswdEntry::parse_passwd_line(line) {
                            // 做匹配
                            if (nscdrequest.req_type == RequestType::GetpwNam)
                                || (nscdrequest.req_type == RequestType::GetpwUid
                                    && entry.pw_uid == key.parse::<u32>().unwrap_or(65534))
                            {
                                let blob = entry.to_bytes();
                                return Ok(blob);
                            }
                        }
                    }
                }
                break;
            }

            // 把读到的 n 字节追加到 accu
            accu.extend_from_slice(&small_buf[..n]);
            // 只要 accu 里出现 '\n'，就拆出一行来处理
            while let Some(pos) = accu.iter().position(|&b| b == b'\n') {
                // 拆出 [0..pos] 作一行
                let line_bytes = accu[..pos].to_vec();
                // 从 accu 中删掉这一行（包含 '\n'）
                accu.drain(..=pos);
                if let Ok(line) = core::str::from_utf8(&line_bytes) {
                    log::error!("line: {}", line);
                    if let Some(entry) = PasswdEntry::parse_passwd_line(line) {
                        // 匹配逻辑
                        let matches = if nscdrequest.req_type == RequestType::GetpwNam {
                            entry.pw_name == key
                        } else {
                            entry.pw_uid == key.parse::<u32>().unwrap_or(u32::MAX)
                        };
                        if matches {
                            let blob = entry.to_bytes();
                            return Ok(blob);
                        }
                    }
                }
            }
        }
        Err(Errno::ENOENT) // 没找到匹配的行
    }
    else if db== Database::Group {
        let file = path_openat("/etc/group", OpenFlags::O_CLOEXEC, -100, 0)?;
        let mut small_buf = [0u8; 128];
        let mut accu: Vec<u8> = Vec::new();

        loop {
            let n = file.read(&mut small_buf)?;
            if n == 0 {
                // 文件读完，检查最后是否还有残余没有 '\n'
                if !accu.is_empty() {
                    if let Some(line) = core::str::from_utf8(&accu).ok() {
                        log::error!("group line: {}", line);
                        if let Some(entry) = GroupEntry::parse_group_line(line) {
                            // 做匹配
                            let matches = if nscdrequest.req_type == RequestType::GetgrNam {
                                entry.gr_name == key
                            } else {
                                entry.gr_gid == key.parse::<u32>().unwrap_or(u32::MAX)
                            };
                            if matches {
                                let blob = entry.to_bytes();
                                return Ok(blob);
                            }
                        }
                    }
                }
                break;
            }

            // 把读到的 n 字节追加到 accu
            accu.extend_from_slice(&small_buf[..n]);
            // 只要 accu 里出现 '\n'，就拆出一行来处理
            while let Some(pos) = accu.iter().position(|&b| b == b'\n') {
                // 拆出 [0..pos] 作一行
                let line_bytes = accu[..pos].to_vec();
                // 从 accu 中删掉这一行（包含 '\n'）
                accu.drain(..=pos);
                if let Ok(line) = core::str::from_utf8(&line_bytes) {
                    log::error!("group line: {}", line);
                    if let Some(entry) = GroupEntry::parse_group_line(line) {
                        // 匹配逻辑
                        let matches = if nscdrequest.req_type == RequestType::GetpwNam {
                            entry.gr_name == key
                        } else {
                            entry.gr_gid == key.parse::<u32>().unwrap_or(u32::MAX)
                        };
                        if matches {
                            let blob = entry.to_bytes();
                            return Ok(blob);
                        }
                    }
                }
            }
        }
        Err(Errno::ENOENT) // 没找到匹配的行
    }
    else {
        Err(Errno::ENOENT)
    }
}

    fn parse_passwd_line(line: &str) -> Option<Self> {
    // 先去掉末尾的 '\n'
    let line = line.trim_end_matches('\n');
    // 用 ':' 拆成 7 段
    let parts: Vec<&str> = line.split(':').collect();
    assert!(parts.len() == 7, "passwd line should have 7 parts, got {}", parts.len());
    Some(PasswdEntry {
        pw_name:   parts[0].to_string(),
        pw_passwd: parts[1].to_string(),
        pw_uid:    parts[2].parse().ok()?,
        pw_gid:    parts[3].parse().ok()?,
        pw_gecos:  parts[4].to_string(),
        pw_dir:    parts[5].to_string(),
        pw_shell:  parts[6].to_string(),
    })
}

}
struct GroupEntry {
    gr_name: String,
    gr_passwd: String,
    gr_gid: u32,
    gr_mem: Vec<String>, // 可选，成员列表
}

impl GroupEntry {
    /// 将 "/etc/group" 的一行文本解析成 GroupEntry
    /// 例如 "wheel:x:10:root,alice" -> GroupEntry { gr_name: "wheel", gr_passwd: "x", gr_gid: 10, gr_mem: vec!["root","alice"] }
    fn parse_group_line(line: &str) -> Option<GroupEntry> {
        let parts: Vec<&str> = line.splitn(4, ':').collect();
        if parts.len() < 3 {
            return None;
        }
        let gr_name = parts[0].to_string();
        let gr_passwd = parts[1].to_string();
        let gr_gid = parts[2].parse::<u32>().ok()?;
        let gr_mem = if parts.len() == 4 && !parts[3].is_empty() {
            parts[3]
                .split(',')
                .map(|s| s.to_string())
                .collect::<Vec<String>>()
        } else {
            Vec::new()
        };
        Some(GroupEntry {
            gr_name,
            gr_passwd,
            gr_gid,
            gr_mem,
        })
    }

    /// 将 GroupEntry 序列化为字节流，供 NSCD 返回
    fn to_bytes(&self) -> Vec<u8> {
        // 这里的格式根据你的 NSCD 协议自行决定，
        // 比如可以按 struct group 的二进制布局来编码，或者按某种约定的文本格式打包。
        // 以下仅作示例：ascii 格式化一行，然后转成字节
        let mut s = format!("{}:{}:{}", self.gr_name, self.gr_passwd, self.gr_gid);
        if !self.gr_mem.is_empty() {
            s.push(':');
            s.push_str(&self.gr_mem.join(","));
        }
        s.push('\n');
        s.into_bytes()
    }
}

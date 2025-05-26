/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-05-31 18:01:34
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-06-01 11:09:01
 * @FilePath: /RocketOS_netperfright/os/src/net/alg.rs
 * @Description: 
 * 
 * Copyright (c) 2025 by peterluck2021@163.com, All Rights Reserved. 
 */
//文件将会维护一个列表和多个加密函数实现
//type = alg_get_type(sa->salg_type);
// alg_get_type("skcipher") 会在内核维护的 af_alg_type_list（一个链表）里，
// 查找有没有注册名为 "skcipher" 的类型驱动。
// 如果找不到，就尝试 request_module("algif-%s", "skcipher") 动态加载模块，然后再查一次。
//如果最终仍然没找到，就返回 ERR_PTR(-ENOENT)，然后 af_alg_bind() 将返回 -ENOENT 给用户。
//需要实现一个维护alg算法的列表和每个算法的实现函数
use alloc::{string::{String, ToString}};

use alloc::vec::Vec;

/// AF_ALG 底层的 sockaddr_alg 在内核里定义为：
///
///   struct sockaddr_alg {
///       __u16   salg_family;            // = AF_ALG
///       __u8    salg_type[14];          // 比如 "skcipher", "hash", "aead"
///       __u32   salg_feat;
///       __u32   salg_mask;
///       __u8    salg_name[64];          // 具体算法名，比如 "cbc(aes)"
///   };
///
/// 在 Rust 里先对应一个 `#[repr(C)]` 的结构体：
///
/// ```
#[repr(C)]
#[derive(Debug,Clone,Copy)]
pub struct SockAddrAlg {
     pub salg_family: u16,
     pub salg_type:   [u8; 14],
     pub salg_feat:   u32,
     pub salg_mask:   u32,
     pub salg_name:   [u8; 64],
     //linux中没有将密钥存入这里而是不同加密方法对应一个结构体，感觉有点复杂，这里就直接存在这了
     pub salg_key:    [u8; 100],
}
impl SockAddrAlg {
    pub fn set_alg_key(&mut self, raw_key: &[u8]) {
        for byte in &mut self.salg_key {
            *byte = 0;
        }
        // 2. 计算实际要拷贝的长度，不能超过固定数组长度 64
        let copy_len = core::cmp::min(raw_key.len(), self.salg_key.len());
        // 3. 将 raw_key 中的前 copy_len 字节拷贝到 salg_key 中
        self.salg_key[..copy_len].copy_from_slice(&raw_key[..copy_len]);
    }
}


#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum AlgType {
    /// 异步哈希 / HMAC / CMAC
    Hash,
    /// 对称加密（如 AES-CBC、AES-CTR、DES、SM4 等）
    Skcipher,
    /// AEAD（如 AES-GCM、AES-CCM、ChaCha20-Poly1305）
    Aead,
    /// 随机数生成（如 `urandom`、`hwrng` 等）
    Rng,
    /// 非对称加密（如 RSA／ElGamal）
    Akcipher,
    /// 密钥交换／派生（如 DH、ECDH、KDF 等）
    Kpp,
    /// 同步压缩（如 `deflate`、`zlib-deflate`、`lzo` 等）
    Scomp,
    /// 异步压缩（硬件加速压缩、ZIP 卡等）
    Acomp,
    /// 为了可扩展性，捕获所有未知或将来可能出现的新类型
    Unknown(String),
}

impl AlgType {
    pub fn from_raw_salg_type(raw: &[u8; 14]) -> AlgType {
        // 1. 找到第一个 NUL（0x00）位置，或者全长都没 NUL，就当它全是 14 字节
        let end = raw.iter().position(|&b| b == 0).unwrap_or(14);
        // 2. 把 &[u8] 转成 &str（假设内核里传过来的一定是 ASCII，不会出现非法 UTF-8）
        let s = core::str::from_utf8(&raw[..end]).unwrap_or("");
        log::error!("[from_raw_salg_type] raw is {:?}",s);
        // 3. 匹配或返回 Unknown
        match s {
            "hash"     => AlgType::Hash,       // :contentReference[oaicite:16]{index=16}
            "skcipher" => AlgType::Skcipher,   // :contentReference[oaicite:17]{index=17}
            "aead"     => AlgType::Aead,       // :contentReference[oaicite:18]{index=18}
            "rng"      => AlgType::Rng,        // :contentReference[oaicite:19]{index=19}
            "akcipher" => AlgType::Akcipher,   // :contentReference[oaicite:20]{index=20}
            "kpp"      => AlgType::Kpp,        // :contentReference[oaicite:21]{index=21}
            "scomp"    => AlgType::Scomp,      // :contentReference[oaicite:22]{index=22}
            "acomp"    => AlgType::Acomp,      // :contentReference[oaicite:23]{index=23}
            other => {
                // 其余的不在上述列表里的，全部归入 Unknown
                AlgType::Unknown(other.to_string())
            }
        }
    }
}
//下面是不同的算法加密函数


pub struct AlgSocket_Key{
    pub socketfd:usize,
    //密钥
    pub socket_key:Vec<u8>,
    //明文
    pub socket_raw:Vec<u8>,
    //密文
    pub socket_secret:Vec<u8>,
}

impl AlgSocket_Key {
}

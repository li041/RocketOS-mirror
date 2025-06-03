/*
 * @Author: Peter/peterluck2021@163.com
 * @Date: 2025-05-31 18:01:34
 * @LastEditors: Peter/peterluck2021@163.com
 * @LastEditTime: 2025-06-03 17:02:06
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
use alloc::{string::{String, ToString}, vec};
use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use polyval::{Polyval, Key as PolyvalKey};
use universal_hash::UniversalHash; 

use crate::{fs::uapi::IoVec, net::socket::Socket, syscall::errno::{Errno, SyscallRet}};
use alloc::vec::Vec;
use salsa20::{cipher::{KeyIvInit, StreamCipher}, Salsa20};
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
        log::error!("[set_alg_key] raw_key is {:?} len is {:?}",raw_key,raw_key.len());
        for byte in &mut self.salg_key {
            *byte = 0;
        }
        // 2. 计算实际要拷贝的长度，不能超过固定数组长度 64
        let copy_len = core::cmp::min(raw_key.len(), self.salg_key.len());
        // 3. 将 raw_key 中的前 copy_len 字节拷贝到 salg_key 中
        self.salg_key[..copy_len].copy_from_slice(&raw_key[..copy_len]);
    }
    pub fn get_name(&self)->&str {
        let end = self.salg_name.iter().position(|&b| b == 0).unwrap_or(14);
        // 2. 把 &[u8] 转成 &str（假设内核里传过来的一定是 ASCII，不会出现非法 UTF-8）
        let s = core::str::from_utf8(&self.salg_name[..end]).unwrap_or("");
        return s;
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
//直接加密
pub fn encode_text(socket:&Socket,text:&[u8])->SyscallRet {
    if !socket.get_is_af_alg() {
        return Err(Errno::EINVAL);
    }
    //不会panic
    let socket_alg=socket.socket_af_alg.lock().unwrap();
    let alg_type=AlgType::from_raw_salg_type(&socket_alg.salg_type);
    match alg_type {
        AlgType::Hash => {
            if socket_alg.get_name() == "vmac64(aes)" {
                let key = &socket_alg.salg_key;

                // AES key (前 16 字节)
                let aes_key: &[u8; 16] = key.get(..16)
                    .ok_or(Errno::EINVAL)?
                    .try_into()
                    .map_err(|_| Errno::EINVAL)?;

                // Polyval key (16-32 字节)
                let polyval_key: &[u8; 16] = key.get(16..32)
                    .ok_or(Errno::EINVAL)?
                    .try_into()
                    .map_err(|_| Errno::EINVAL)?;

                // 固定 nonce（为简化，此处用零 nonce，生产环境应确保唯一性）
                let nonce: [u8; 16] = [0u8; 16];

                // Step 1: 计算 hash(text)
                let mut polyval = Polyval::new(GenericArray::from_slice(polyval_key));
                polyval.update_padded(text);
                let hash_result = polyval.finalize();

                // Step 2: AES 加密 nonce
                let aes = Aes128::new(GenericArray::from_slice(aes_key));
                let mut block = GenericArray::clone_from_slice(&nonce);
                aes.encrypt_block(&mut block);
                let aes_output = block;

                // Step 3: XOR hash 与 AES(nonce)
                let mut tag = [0u8; 16];
                for i in 0..16 {
                    tag[i] = hash_result.as_slice()[i] ^ aes_output[i];
                }

                // 截断为 64-bit (VMAC64)
                let truncated = &tag[..8];
                log::error!("[encode_text] ciphertext is {:?}",truncated);
                socket.set_ciphertext(truncated);
                return Ok(truncated.len());
            }
        },
        AlgType::Skcipher => todo!(),
        AlgType::Aead => todo!(),
        AlgType::Rng => todo!(),
        AlgType::Akcipher => todo!(),
        AlgType::Kpp => todo!(),
        AlgType::Scomp => todo!(),
        AlgType::Acomp => todo!(),
        AlgType::Unknown(_) => todo!(),
    }
    Ok(0)
}
//下面是不同的算法加密函数
pub fn encode(socket:&Socket,name:&mut [u8],iovec:&mut [IoVec],control:&mut [u8])->SyscallRet {
    //iovec中存入明文,SockAddrAlg存入加密方式和密钥
    log::error!("[alg_encode] control:{:?}",control);
    if !socket.get_is_af_alg() {
        return Err(Errno::EINVAL);
    }
    //不会panic
    let socket_alg=socket.socket_af_alg.lock().unwrap();
    let alg_type=AlgType::from_raw_salg_type(&socket_alg.salg_type);
    log::error!("[alg_encode] alg type is {:?}",alg_type);

    let (cmsg,iv)=parse_cmsghdr_from_bytes(&control)?;
    log::error!("[alg_encode] iv is {:?}",iv);

    match alg_type {
        AlgType::Hash => todo!(),
        AlgType::Skcipher => {
            if socket_alg.get_name()=="salsa20" {
                log::error!("[alg_Skcipher] key is {:?},iv is {:?},plaintext is {:?}",socket_alg.salg_key,iv,iovec[0].base);
                let ciphertext = salsa20_encrypt(socket_alg.salg_key.as_slice(), &iv, Vec::new().as_slice())?;
                log::error!("[alg_Skcipher] ciphertext is {:?} len is {:?}",ciphertext,ciphertext.len());
                //设置密文准备返回
                socket.set_ciphertext(ciphertext.as_slice());
                return Ok(ciphertext.len());
            }
        },
        AlgType::Aead => todo!(),
        AlgType::Rng => todo!(),
        AlgType::Akcipher => todo!(),
        AlgType::Kpp => todo!(),
        AlgType::Scomp => todo!(),
        AlgType::Acomp => todo!(),
        AlgType::Unknown(_) => todo!(),
    }
    Ok(0)
}
fn salsa20_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Errno> {
    let short_key = match key.len() {
        l if l >= 32 => &key[..32], // 优先使用前 32 字节
        16 => key,
        _ => return Err(Errno::EINVAL),
    };
    let k_iv_slice: &[u8];
    let k_iv_vec;
    if iv.len() != 8 {
        k_iv_vec = vec![0u8; 8]; // Salsa20 要求 64-bit IV
        k_iv_slice = &k_iv_vec;
    } else {
        k_iv_slice = iv;
    }

    let mut cipher = Salsa20::new(short_key.into(), k_iv_slice.into());
    let mut ciphertext = plaintext.to_vec();
    cipher.apply_keystream(&mut ciphertext);
    Ok(ciphertext)
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmsgLevel {
    /// SOL_SOCKET 层 (Unix Domain Socket 通用 ancillary)
    SolSocket   = 1,
    /// IPPROTO_IP 层 (IPv4 相关 ancillary)
    IpProtoIp   = 0,
    /// IPPROTO_IPV6 层 (IPv6 相关 ancillary)
    IpProtoIpv6 = 41,
    /// SOL_ALG 层 (AF_ALG 加密子系统 ancillary)
    SolAlg      = 279,
    /// 未知的 level，将保留原始值（如将其存放在其他字段里）
    Unknown     = -1,
}

impl From<i32> for CmsgLevel {
    fn from(raw: i32) -> Self {
        match raw {
            1   => CmsgLevel::SolSocket,
            0   => CmsgLevel::IpProtoIp,
            41  => CmsgLevel::IpProtoIpv6,
            279 => CmsgLevel::SolAlg,
            _   => CmsgLevel::Unknown,
        }
    }
}

impl From<CmsgLevel> for i32 {
    fn from(level: CmsgLevel) -> i32 {
        match level {
            CmsgLevel::SolSocket   => 1,
            CmsgLevel::IpProtoIp   => 0,
            CmsgLevel::IpProtoIpv6 => 41,
            CmsgLevel::SolAlg      => 279,
            CmsgLevel::Unknown     => -1,
        }
    }
}

/// ------------------------------------------------------------------------
/// 第 2 步：给每个 level 定义独立的子枚举，避免重复 discriminant
/// ------------------------------------------------------------------------

/// (1) SOL_SOCKET (level=1) 下的 cmsg_type
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmsgTypeSolSocket {
    ScmRights       = 1,   // 传递/接收 file descriptors
    ScmCredentials  = 2,   // 传递/接收进程凭证 (pid/uid/gid)
    ScmTimestamp    = 29,  // SO_TIMESTAMP 时，接收时附带 timeval
    ScmTimestampNs  = 35,  // SO_TIMESTAMPNS 时，接收时附带 timespec
    ScmTimestamping = 37,  // SO_TIMESTAMPING 时，附带多组时间戳
    Unknown         = -1,  // 其他未知值
}

impl From<i32> for CmsgTypeSolSocket {
    fn from(raw: i32) -> Self {
        match raw {
            1   => CmsgTypeSolSocket::ScmRights,
            2   => CmsgTypeSolSocket::ScmCredentials,
            29  => CmsgTypeSolSocket::ScmTimestamp,
            35  => CmsgTypeSolSocket::ScmTimestampNs,
            37  => CmsgTypeSolSocket::ScmTimestamping,
            _   => CmsgTypeSolSocket::Unknown,
        }
    }
}

impl From<CmsgTypeSolSocket> for i32 {
    fn from(t: CmsgTypeSolSocket) -> i32 {
        match t {
            CmsgTypeSolSocket::ScmRights       => 1,
            CmsgTypeSolSocket::ScmCredentials  => 2,
            CmsgTypeSolSocket::ScmTimestamp    => 29,
            CmsgTypeSolSocket::ScmTimestampNs  => 35,
            CmsgTypeSolSocket::ScmTimestamping => 37,
            CmsgTypeSolSocket::Unknown         => -1,
        }
    }
}

/// (2) IPPROTO_IP (level=0) 下的 cmsg_type
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmsgTypeIpProtoIp {
    IpTtl      = 21,  // 接收时附带 IPv4 报文的 TTL
    IpTos      = 1,   // 接收时附带 IPv4 报文的 TOS
    IpPktInfo  = 8,   // 接收时附带 IPv4 in_pktinfo
    IpRecvTtl  = 12,  // 接收时附带 IPv4 原始 TTL
    IpRecvTos  = 13,  // 接收时附带 IPv4 原始 TOS
    Unknown    = -1,  // 其他未知值
}

impl From<i32> for CmsgTypeIpProtoIp {
    fn from(raw: i32) -> Self {
        match raw {
            21  => CmsgTypeIpProtoIp::IpTtl,
            1   => CmsgTypeIpProtoIp::IpTos,
            8   => CmsgTypeIpProtoIp::IpPktInfo,
            12  => CmsgTypeIpProtoIp::IpRecvTtl,
            13  => CmsgTypeIpProtoIp::IpRecvTos,
            _   => CmsgTypeIpProtoIp::Unknown,
        }
    }
}

impl From<CmsgTypeIpProtoIp> for i32 {
    fn from(t: CmsgTypeIpProtoIp) -> i32 {
        match t {
            CmsgTypeIpProtoIp::IpTtl     => 21,
            CmsgTypeIpProtoIp::IpTos     => 1,
            CmsgTypeIpProtoIp::IpPktInfo => 8,
            CmsgTypeIpProtoIp::IpRecvTtl => 12,
            CmsgTypeIpProtoIp::IpRecvTos => 13,
            CmsgTypeIpProtoIp::Unknown   => -1,
        }
    }
}

/// (3) IPPROTO_IPV6 (level=41) 下的 cmsg_type
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmsgTypeIpProtoIpv6 {
    Ipv6HopLimit     = 52,
    Ipv6Tclass       = 67,
    Ipv6PktInfo      = 50,
    Ipv6HopOpts      = 54,
    Ipv6RtHdr        = 51,
    Ipv6DstOpts      = 58,
    // Ipv6RecvHopLimit = 49,
    Ipv6RecvPktInfo  = 49,
    Ipv6RecvHopOpts  = 56,
    Ipv6RecvDstOpts  = 57,
    Ipv6RecvRtHdr    = 55,
    Unknown          = -1,
}

impl From<i32> for CmsgTypeIpProtoIpv6 {
    fn from(raw: i32) -> Self {
        match raw {
            52  => CmsgTypeIpProtoIpv6::Ipv6HopLimit,
            67  => CmsgTypeIpProtoIpv6::Ipv6Tclass,
            50  => CmsgTypeIpProtoIpv6::Ipv6PktInfo,
            54  => CmsgTypeIpProtoIpv6::Ipv6HopOpts,
            51  => CmsgTypeIpProtoIpv6::Ipv6RtHdr,
            58  => CmsgTypeIpProtoIpv6::Ipv6DstOpts,
            49  => CmsgTypeIpProtoIpv6::Ipv6RecvPktInfo,  // 注意：49 兼有两种含义，可按需要再细化
            56  => CmsgTypeIpProtoIpv6::Ipv6RecvHopOpts,
            57  => CmsgTypeIpProtoIpv6::Ipv6RecvDstOpts,
            55  => CmsgTypeIpProtoIpv6::Ipv6RecvRtHdr,
            _   => CmsgTypeIpProtoIpv6::Unknown,
        }
    }
}

impl From<CmsgTypeIpProtoIpv6> for i32 {
    fn from(t: CmsgTypeIpProtoIpv6) -> i32 {
        match t {
            CmsgTypeIpProtoIpv6::Ipv6HopLimit     => 52,
            CmsgTypeIpProtoIpv6::Ipv6Tclass       => 67,
            CmsgTypeIpProtoIpv6::Ipv6PktInfo      => 50,
            CmsgTypeIpProtoIpv6::Ipv6HopOpts      => 54,
            CmsgTypeIpProtoIpv6::Ipv6RtHdr        => 51,
            CmsgTypeIpProtoIpv6::Ipv6DstOpts      => 58,
            CmsgTypeIpProtoIpv6::Ipv6RecvPktInfo => 49,
            // CmsgTypeIpProtoIpv6::Ipv6RecvPktInfo  => 49,
            CmsgTypeIpProtoIpv6::Ipv6RecvHopOpts  => 56,
            CmsgTypeIpProtoIpv6::Ipv6RecvDstOpts  => 57,
            CmsgTypeIpProtoIpv6::Ipv6RecvRtHdr    => 55,
            CmsgTypeIpProtoIpv6::Unknown          => -1,
        }
    }
}

/// (4) SOL_ALG (level=279) 下的 cmsg_type
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmsgTypeSolAlg {
    AlgSetOp           = 3,
    AlgSetIv           = 2,
    AlgSetAeadAssoc    = 4,
    AlgSetAeadAuthSize = 5,
    Unknown            = -1,
}

impl From<i32> for CmsgTypeSolAlg {
    fn from(raw: i32) -> Self {
        match raw {
            3 => CmsgTypeSolAlg::AlgSetOp,
            2 => CmsgTypeSolAlg::AlgSetIv,
            4 => CmsgTypeSolAlg::AlgSetAeadAssoc,
            5 => CmsgTypeSolAlg::AlgSetAeadAuthSize,
            _ => CmsgTypeSolAlg::Unknown,
        }
    }
}

impl From<CmsgTypeSolAlg> for i32 {
    fn from(t: CmsgTypeSolAlg) -> i32 {
        match t {
            CmsgTypeSolAlg::AlgSetOp           => 3,
            CmsgTypeSolAlg::AlgSetIv           => 2,
            CmsgTypeSolAlg::AlgSetAeadAssoc    => 4,
            CmsgTypeSolAlg::AlgSetAeadAuthSize => 5,
            CmsgTypeSolAlg::Unknown            => -1,
        }
    }
}

/// 这样就能同时反映「cmsg_level」与「cmsg_type」之间的对应关系：
/// - 如果上层是 SOL_SOCKET，就只在 CmsgTypeSolSocket 分支里匹配；
/// - 如果是 IPPROTO_IP，就只在 CmsgTypeIpProtoIp 分支里匹配；
/// - …
/// - 否则都对应一个 Unknown 值。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmsgType {
    /// 当 cmsg_level = SOL_SOCKET 时，使用这个分支
    SolSocket(CmsgTypeSolSocket),
    /// 当 cmsg_level = IPPROTO_IP 时，使用这个分支
    IpProtoIp(CmsgTypeIpProtoIp),
    /// 当 cmsg_level = IPPROTO_IPV6 时，使用这个分支
    IpProtoIpv6(CmsgTypeIpProtoIpv6),
    /// 当 cmsg_level = SOL_ALG 时，使用这个分支
    SolAlg(CmsgTypeSolAlg),
    /// 其他 level 下的未知 type
    Unknown { level: CmsgLevel, raw: i32 },
}

impl CmsgType {
    /// 由「原始 cmsg_level (i32) + 原始 cmsg_type (i32)」构造一个对应的顶层枚举
    pub fn parse(level_raw: i32, type_raw: i32) -> Self {
        let level = CmsgLevel::from(level_raw);
        match level {
            CmsgLevel::SolSocket => {
                let t = CmsgTypeSolSocket::from(type_raw);
                CmsgType::SolSocket(t)
            }
            CmsgLevel::IpProtoIp => {
                let t = CmsgTypeIpProtoIp::from(type_raw);
                CmsgType::IpProtoIp(t)
            }
            CmsgLevel::IpProtoIpv6 => {
                let t = CmsgTypeIpProtoIpv6::from(type_raw);
                CmsgType::IpProtoIpv6(t)
            }
            CmsgLevel::SolAlg => {
                let t = CmsgTypeSolAlg::from(type_raw);
                CmsgType::SolAlg(t)
            }
            CmsgLevel::Unknown => {
                // level 本身未知，那么 type 当然也算未知
                CmsgType::Unknown { level, raw: type_raw }
            }
        }
    }
}

/// ------------------------------------------------------------------------
/// 第 4 步：把 Cmsghdr 里的字段类型替换为枚举
/// ------------------------------------------------------------------------
/// 这样在从字节流手动解析时，就能保持「level 与 type 的对应关系」在类型体系里得到体现。
#[repr(C)]
pub struct Cmsghdr {
    /// 整条 control message 的总长度 (包含头部 + payload)，在 x86_64 上等同于 usize。
    pub cmsg_len: usize,

    /// 消息所属协议层。使用 CmsgLevel 枚举替换原先的 i32。
    pub cmsg_level: CmsgLevel,

    /// 消息类型。顶层枚举 CmsgType 会根据 cmsg_level 把原始的 i32 映射到对应子枚举。
    pub cmsg_type:  CmsgType,

    // 注意：真正的 cmsg_data[] （payload）不写在这个 struct 里，而是紧跟其后，
    // 并且从下一个 8 字节对齐地址开始。
}
#[repr(C)]
pub struct AfAlgIv {
    /// IV 的长度 (单位：字节)。要注意这是紧跟在 Cmsghdr 对齐后、位于 cmsg_data 开始处的第一个字段。
    pub ivlen: u32,
    // 紧随其后的是长度为 ivlen 的原始 IV bytes，本 struct 中不显式声明,只需要读出即可
}

impl Cmsghdr {
    /// 返回这个 Cmsghdr 头占用的字节数 (不包含 payload)。
    /// 在 x86_64 / no-std 下，size_of::<Cmsghdr>() == 16。
    #[inline]
    pub const fn header_len() -> usize {
        size_of::<Cmsghdr>()
    }

    /// 根据 cmsg_len 字段判断整个消息 (包含头部和 payload) 是否满足最小长度
    #[inline]
    pub fn total_len(&self) -> usize {
        self.cmsg_len as usize
    }

}
impl AfAlgIv {
    /// 返回 ivlen 字段占用的字节数 (4 字节)。
    #[inline]
    pub const fn ivlen_field_size() -> usize {
        size_of::<u32>()
    }
}

//要求这里必须是内核空间
pub fn parse_cmsghdr_from_bytes(control_bytes: &[u8]) -> Result<(Cmsghdr, &[u8]), Errno> {
    // 1. 至少要能读出 Cmsghdr 头 (usize + i32 + i32 = 8 + 4 + 4 = 16 字节)
    if control_bytes.len() < size_of::<usize>() + 4 + 4 {
        return Err(Errno::EFAULT);
    }

    let mut offset = 0;

    // 2. 读取 cmsg_len (usize, 8 字节)
    let cmsg_len = {
        let mut buf = [0u8; size_of::<usize>()];
        buf.copy_from_slice(&control_bytes[offset..offset + size_of::<usize>()]);
        offset += size_of::<usize>();
        usize::from_ne_bytes(buf)
    };

    // 3. 读取原始 cmsg_level (i32, 4 字节)
    let raw_level = {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&control_bytes[offset..offset + 4]);
        offset += 4;
        i32::from_ne_bytes(buf)
    };

    // 4. 读取原始 cmsg_type (i32, 4 字节)
    let raw_type = {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&control_bytes[offset..offset + 4]);
        offset += 4;
        i32::from_ne_bytes(buf)
    };

    // 5. 把 raw_level/raw_type 转为枚举
    let level_enum = CmsgLevel::from(raw_level);
    let type_enum = CmsgType::parse(raw_level, raw_type);

    // 6. 构造 Cmsghdr
    let hdr = Cmsghdr {
        cmsg_len:   cmsg_len,
        cmsg_level: level_enum,
        cmsg_type:  type_enum,
    };

    // 如果不是 AF_ALG + ALG_SET_IV，就返回空 slice
    if hdr.cmsg_level != CmsgLevel::SolAlg {
        return Ok((hdr, &[]));
    }
    if let CmsgType::SolAlg(inner) = hdr.cmsg_type {
        if inner !=CmsgTypeSolAlg::AlgSetIv {
            return Ok((hdr, &[]));
        }
    } else {
        // level 是 SOL_ALG，但 type_enum 不属于 SolAlg 变体
        return Ok((hdr, &[]));
    }

    // 如果是 AF_ALG + ALG_SET_IV，接着解析后面的 IV
    // payload 从 Cmsghdr::header_len() 偏移开始
    let data_off = Cmsghdr::header_len();

    // 检查 cmsg_len 是否至少能容纳 ivlen_field_size
    if hdr.cmsg_len < data_off + AfAlgIv::ivlen_field_size() {
        return Err(Errno::EINVAL);
    }

    // 检查 control_bytes 整体长度是否至少到 ivlen 字段
    if control_bytes.len() < data_off + AfAlgIv::ivlen_field_size() {
        return Err(Errno::EFAULT);
    }

    // 读取 ivlen (u32)
    let ivlen = {
        let start = data_off;
        let end = start + AfAlgIv::ivlen_field_size();
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&control_bytes[start..end]);
        u32::from_ne_bytes(buf) as usize
    };

    // 计算 IV 本体总长度，并验证
    let iv_start = data_off + AfAlgIv::ivlen_field_size();
    let iv_end = iv_start + ivlen;

    // 验证 cmsg_len 以及 control_bytes.len()
    if hdr.cmsg_len < iv_end {
        return Err(Errno::EINVAL);
    }
    if control_bytes.len() < iv_end {
        return Err(Errno::EFAULT);
    }

    // 切片出 IV bytes
    let iv_slice = &control_bytes[iv_start..iv_end];
    Ok((hdr, iv_slice))
}

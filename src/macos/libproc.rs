//! # libproc FFI 封装
//!
//! 这个模块封装了 macOS libproc API，提供安全的 Rust 接口来：
//! - 列出所有进程 PID
//! - 获取进程名和路径
//! - 枚举进程的 TCP/UDP socket 连接
//!
//! ## 主要 API
//! - `list_all_pids()` - 获取系统中所有进程的 PID
//! - `get_process_name(pid)` - 获取进程名（最多 16 字符）
//! - `get_process_path(pid)` - 获取进程完整路径
//! - `list_process_sockets(pid)` - 获取进程的所有 socket 连接信息
//!
//! ## 错误处理
//! 所有函数在权限不足时会返回空结果而非 panic，确保扫描能继续进行。

use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Result};

// ========================================
// 引入 bindgen 生成的 FFI 绑定
// ========================================
// 这些绑定由 build.rs 在编译时生成，位于 OUT_DIR/libproc_bindings.rs
// 使用 #[allow(warnings)] 忽略 bindgen 生成代码的警告
#[allow(warnings)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/libproc_bindings.rs"));
}

// 导入需要的类型和常量
use bindings::*;

// ========================================
// 常量定义
// ========================================

/// 进程名最大长度（libproc 限制）
const PROC_NAME_MAX: usize = 256;

/// 进程路径最大长度
const PROC_PATH_MAX: usize = 4096;

/// 初始 PID 数组大小（动态增长）
const INITIAL_PID_COUNT: usize = 1024;

/// FD 数组初始大小
const INITIAL_FD_COUNT: usize = 256;

// ========================================
// Socket 协议类型
// ========================================

/// 表示 socket 使用的协议类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum SocketProtocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for SocketProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketProtocol::Tcp => write!(f, "TCP"),
            SocketProtocol::Udp => write!(f, "UDP"),
        }
    }
}

// ========================================
// TCP 连接状态
// ========================================

// TCP 状态常量（来自 BSD netinet/tcp_fsm.h）
// 这些常量在 sys/proc_info.h 中可能不会被 bindgen 导出，所以手动定义
const TCPS_CLOSED: i32 = 0;
const TCPS_LISTEN: i32 = 1;
const TCPS_SYN_SENT: i32 = 2;
const TCPS_SYN_RECEIVED: i32 = 3;
const TCPS_ESTABLISHED: i32 = 4;
const TCPS_CLOSE_WAIT: i32 = 5;
const TCPS_FIN_WAIT_1: i32 = 6;
const TCPS_CLOSING: i32 = 7;
const TCPS_LAST_ACK: i32 = 8;
const TCPS_FIN_WAIT_2: i32 = 9;
const TCPS_TIME_WAIT: i32 = 10;

/// TCP 连接状态枚举
///
/// 这些状态对应 TCP 状态机的各个阶段：
/// - LISTEN: 服务器等待连接
/// - ESTABLISHED: 连接已建立，可以传输数据
/// - 其他状态表示连接建立/关闭过程中的中间状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    CloseWait,
    FinWait1,
    Closing,
    LastAck,
    FinWait2,
    TimeWait,
    Unknown(i32),
}

impl TcpState {
    /// 从 libproc 的 TCP 状态常量转换
    fn from_raw(state: i32) -> Self {
        // 使用 BSD 标准 TCP 状态值
        match state {
            TCPS_CLOSED => TcpState::Closed,
            TCPS_LISTEN => TcpState::Listen,
            TCPS_SYN_SENT => TcpState::SynSent,
            TCPS_SYN_RECEIVED => TcpState::SynReceived,
            TCPS_ESTABLISHED => TcpState::Established,
            TCPS_CLOSE_WAIT => TcpState::CloseWait,
            TCPS_FIN_WAIT_1 => TcpState::FinWait1,
            TCPS_CLOSING => TcpState::Closing,
            TCPS_LAST_ACK => TcpState::LastAck,
            TCPS_FIN_WAIT_2 => TcpState::FinWait2,
            TCPS_TIME_WAIT => TcpState::TimeWait,
            other => TcpState::Unknown(other),
        }
    }

    /// 判断是否为监听状态（用于识别本地代理服务）
    pub fn is_listening(&self) -> bool {
        matches!(self, TcpState::Listen)
    }
}

impl std::fmt::Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpState::Closed => write!(f, "CLOSED"),
            TcpState::Listen => write!(f, "LISTEN"),
            TcpState::SynSent => write!(f, "SYN_SENT"),
            TcpState::SynReceived => write!(f, "SYN_RECV"),
            TcpState::Established => write!(f, "ESTABLISHED"),
            TcpState::CloseWait => write!(f, "CLOSE_WAIT"),
            TcpState::FinWait1 => write!(f, "FIN_WAIT1"),
            TcpState::Closing => write!(f, "CLOSING"),
            TcpState::LastAck => write!(f, "LAST_ACK"),
            TcpState::FinWait2 => write!(f, "FIN_WAIT2"),
            TcpState::TimeWait => write!(f, "TIME_WAIT"),
            TcpState::Unknown(n) => write!(f, "UNKNOWN({})", n),
        }
    }
}

// ========================================
// Socket 信息结构体
// ========================================

/// 表示一个 socket 连接的完整信息
#[derive(Debug, Clone, serde::Serialize)]
pub struct SocketInfo {
    /// 本地 IP 地址
    pub local_addr: IpAddr,
    /// 本地端口
    pub local_port: u16,
    /// 远端 IP 地址
    pub remote_addr: IpAddr,
    /// 远端端口
    pub remote_port: u16,
    /// 协议类型（TCP/UDP）
    pub protocol: SocketProtocol,
    /// TCP 状态（仅 TCP 有效）
    pub tcp_state: Option<TcpState>,
}

impl SocketInfo {
    /// 判断远端地址是否为本地回环（127.0.0.1 或 ::1）
    pub fn is_remote_loopback(&self) -> bool {
        self.remote_addr.is_loopback()
    }

    /// 判断是否为有效的远端连接（非本地回环、非未指定地址）
    pub fn is_valid_remote(&self) -> bool {
        !self.remote_addr.is_loopback() && !self.remote_addr.is_unspecified()
    }
}

// ========================================
// 公开 API 函数
// ========================================

/// 获取系统中所有进程的 PID 列表
///
/// ## 实现说明
/// - 使用 `proc_listpids(PROC_ALL_PIDS, ...)` 获取所有进程
/// - 返回值是字节数，需要除以 `sizeof(pid_t)` 得到 PID 数量
/// - 如果缓冲区不够大，会自动扩展并重试
///
/// ## 返回
/// - `Ok(Vec<i32>)`: PID 列表（可能为空）
/// - `Err(...)`: 系统调用失败
pub fn list_all_pids() -> Result<Vec<i32>> {
    // 初始缓冲区大小
    let mut pids: Vec<i32> = vec![0; INITIAL_PID_COUNT];

    loop {
        // 计算缓冲区字节大小
        // 使用 u32 是因为 API 期望 int 类型（macOS 上是 4 字节）
        let buf_size = (pids.len() * mem::size_of::<i32>()) as libc::c_int;

        // 调用 proc_listpids
        // 参数1: PROC_ALL_PIDS 表示获取所有进程
        // 参数2: 0 表示无额外过滤
        // 参数3: 缓冲区指针
        // 参数4: 缓冲区大小（字节）
        // 返回: 实际填充的字节数，或 -1 表示错误
        let ret = unsafe {
            proc_listpids(
                PROC_ALL_PIDS as u32,
                0,
                pids.as_mut_ptr() as *mut libc::c_void,
                buf_size,
            )
        };

        if ret < 0 {
            bail!("proc_listpids failed with error code: {}", ret);
        }

        // 计算实际 PID 数量
        let count = ret as usize / mem::size_of::<i32>();

        // 如果缓冲区满了，可能有更多 PID，扩展并重试
        if count >= pids.len() {
            pids.resize(pids.len() * 2, 0);
            continue;
        }

        // 截断到实际数量，过滤掉 PID 0（内核进程）
        pids.truncate(count);
        pids.retain(|&pid| pid > 0);

        return Ok(pids);
    }
}

/// 获取进程名
///
/// ## 参数
/// - `pid`: 进程 ID
///
/// ## 返回
/// - `Some(String)`: 进程名（最多约 16 字符）
/// - `None`: 获取失败（权限不足或进程不存在）
///
/// ## 注意
/// 进程名可能被截断，如需完整信息请使用 `get_process_path`
pub fn get_process_name(pid: i32) -> Option<String> {
    // 准备缓冲区存放进程名
    let mut name_buf = vec![0u8; PROC_NAME_MAX];

    // proc_name 返回实际长度，0 表示失败
    let ret = unsafe {
        proc_name(
            pid,
            name_buf.as_mut_ptr() as *mut libc::c_void,
            name_buf.len() as u32,
        )
    };

    if ret <= 0 {
        // 失败时返回 None（可能是权限问题）
        return None;
    }

    // 将 C 字符串转换为 Rust String
    // 使用 CStr::from_bytes_until_nul 安全地处理 null 结尾
    let name_slice = &name_buf[..ret as usize];
    String::from_utf8(name_slice.to_vec()).ok()
}

/// 获取进程完整路径
///
/// ## 参数
/// - `pid`: 进程 ID
///
/// ## 返回
/// - `Some(String)`: 进程可执行文件的完整路径
/// - `None`: 获取失败
pub fn get_process_path(pid: i32) -> Option<String> {
    let mut path_buf = vec![0u8; PROC_PATH_MAX];

    let ret = unsafe {
        proc_pidpath(
            pid,
            path_buf.as_mut_ptr() as *mut libc::c_void,
            path_buf.len() as u32,
        )
    };

    if ret <= 0 {
        return None;
    }

    // 截取有效部分并转换为 String
    let path_slice = &path_buf[..ret as usize];
    String::from_utf8(path_slice.to_vec()).ok()
}

/// 枚举进程的所有 socket 连接
///
/// ## 参数
/// - `pid`: 进程 ID
///
/// ## 返回
/// - `Ok(Vec<SocketInfo>)`: socket 连接列表（可能为空）
/// - `Err(...)`: 系统调用失败
///
/// ## 实现流程
/// 1. 使用 `proc_pidinfo(PROC_PIDLISTFDS)` 获取所有文件描述符
/// 2. 过滤出 socket 类型的 FD
/// 3. 对每个 socket FD，使用 `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` 获取详情
/// 4. 解析 socket_fdinfo 结构体，提取 IP/端口/状态信息
pub fn list_process_sockets(pid: i32) -> Result<Vec<SocketInfo>> {
    // ========================================
    // Step 1: 获取 FD 列表
    // ========================================
    let fds = list_process_fds(pid)?;

    let mut sockets = Vec::new();

    // ========================================
    // Step 2: 遍历每个 FD
    // ========================================
    for fd_info in fds {
        // 只处理 socket 类型的 FD
        // PROX_FDTYPE_SOCKET 在 macOS 上表示 socket
        if fd_info.proc_fdtype != PROX_FDTYPE_SOCKET as u32 {
            continue;
        }

        // ========================================
        // Step 3: 获取 socket 详细信息
        // ========================================
        if let Some(socket_info) = get_socket_info(pid, fd_info.proc_fd) {
            sockets.push(socket_info);
        }
    }

    Ok(sockets)
}

// ========================================
// 内部辅助函数
// ========================================

/// 获取进程的所有文件描述符
fn list_process_fds(pid: i32) -> Result<Vec<proc_fdinfo>> {
    let mut fds: Vec<proc_fdinfo> = Vec::with_capacity(INITIAL_FD_COUNT);

    // 先查询需要多大的缓冲区
    // 传入空缓冲区会返回需要的字节数
    let needed_size =
        unsafe { proc_pidinfo(pid, PROC_PIDLISTFDS as i32, 0, std::ptr::null_mut(), 0) };

    if needed_size < 0 {
        // 权限不足或进程不存在，返回空列表
        return Ok(Vec::new());
    }

    if needed_size == 0 {
        return Ok(Vec::new());
    }

    // 计算需要的 FD 数量
    let fd_count = needed_size as usize / mem::size_of::<proc_fdinfo>();
    fds.resize(fd_count + 16, proc_fdinfo::default()); // 留一些余量

    // 实际获取 FD 列表
    let buf_size = (fds.len() * mem::size_of::<proc_fdinfo>()) as i32;
    let ret = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDLISTFDS as i32,
            0,
            fds.as_mut_ptr() as *mut libc::c_void,
            buf_size,
        )
    };

    if ret < 0 {
        return Ok(Vec::new());
    }

    let actual_count = ret as usize / mem::size_of::<proc_fdinfo>();
    fds.truncate(actual_count);

    Ok(fds)
}

/// 获取单个 socket FD 的详细信息
fn get_socket_info(pid: i32, fd: i32) -> Option<SocketInfo> {
    // 准备 socket_fdinfo 结构体
    // 这个结构体由 bindgen 生成，包含完整的 socket 信息
    let mut sock_info: socket_fdinfo = unsafe { mem::zeroed() };

    let ret = unsafe {
        proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO as i32,
            &mut sock_info as *mut _ as *mut libc::c_void,
            mem::size_of::<socket_fdinfo>() as i32,
        )
    };

    if ret <= 0 {
        return None;
    }

    // 解析 socket 信息
    parse_socket_info(&sock_info)
}

/// 解析 socket_fdinfo 结构体
///
/// ## 结构说明
/// socket_fdinfo 包含一个 psi (proc_socketinfo) 成员，其中：
/// - psi.soi_kind: socket 类型 (SOCKINFO_TCP, SOCKINFO_IN 等)
/// - psi.soi_proto: 协议信息 (pri_tcp, pri_in 等，是 union)
///
/// 对于 TCP socket：
/// - soi_kind == SOCKINFO_TCP
/// - soi_proto.pri_tcp 包含 tcp_sockinfo
/// - tcp_sockinfo 包含 tcpsi_ini (in_sockinfo) 和 tcpsi_state (状态)
///
/// 对于 UDP socket：
/// - soi_kind == SOCKINFO_IN
/// - soi_proto.pri_in 包含 in_sockinfo
fn parse_socket_info(sock_info: &socket_fdinfo) -> Option<SocketInfo> {
    let psi = &sock_info.psi;

    match psi.soi_kind as u32 {
        SOCKINFO_TCP => {
            // TCP socket：从 pri_tcp 中获取 tcp_sockinfo
            let tcp_info = unsafe { &psi.soi_proto.pri_tcp };
            let in_info = &tcp_info.tcpsi_ini;

            let (local_addr, local_port, remote_addr, remote_port) = parse_in_sockinfo(in_info)?;

            Some(SocketInfo {
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                protocol: SocketProtocol::Tcp,
                tcp_state: Some(TcpState::from_raw(tcp_info.tcpsi_state as i32)),
            })
        }
        SOCKINFO_IN => {
            // UDP 或其他 INET socket
            let in_info = unsafe { &psi.soi_proto.pri_in };

            // 检查是否是 UDP
            if psi.soi_protocol != IPPROTO_UDP as i32 {
                return None;
            }

            let (local_addr, local_port, remote_addr, remote_port) = parse_in_sockinfo(in_info)?;

            Some(SocketInfo {
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                protocol: SocketProtocol::Udp,
                tcp_state: None,
            })
        }
        _ => None, // Unix socket 等，忽略
    }
}

/// 解析 in_sockinfo 结构体中的 IP 地址和端口
///
/// ## 地址结构说明
/// in_sockinfo 包含：
/// - insi_laddr: 本地地址 (union)
/// - insi_faddr: 远端地址 ("foreign" address)
/// - insi_lport: 本地端口（网络字节序）
/// - insi_fport: 远端端口（网络字节序）
/// - insi_vflag: 版本标志 (INI_IPV4=1, INI_IPV6=2)
fn parse_in_sockinfo(in_info: &in_sockinfo) -> Option<(IpAddr, u16, IpAddr, u16)> {
    // 版本标志常量
    const INI_IPV4: u8 = 0x1;
    const INI_IPV6: u8 = 0x2;

    let vflag = in_info.insi_vflag;

    // 根据版本标志解析地址
    if vflag & INI_IPV4 != 0 {
        // IPv4 地址
        // 使用 union 的 ina_46 字段（包含 IPv4 地址）
        let local = unsafe {
            let addr = in_info.insi_laddr.ina_46.i46a_addr4;
            ipv4_to_addr(&addr)
        };
        let remote = unsafe {
            let addr = in_info.insi_faddr.ina_46.i46a_addr4;
            ipv4_to_addr(&addr)
        };

        // 端口转换：网络字节序（大端）-> 主机字节序
        let local_port = u16::from_be(in_info.insi_lport as u16);
        let remote_port = u16::from_be(in_info.insi_fport as u16);

        Some((local, local_port, remote, remote_port))
    } else if vflag & INI_IPV6 != 0 {
        // IPv6 地址
        let local = unsafe {
            let addr = &in_info.insi_laddr.ina_6;
            ipv6_to_addr(addr)
        };
        let remote = unsafe {
            let addr = &in_info.insi_faddr.ina_6;
            ipv6_to_addr(addr)
        };

        let local_port = u16::from_be(in_info.insi_lport as u16);
        let remote_port = u16::from_be(in_info.insi_fport as u16);

        Some((local, local_port, remote, remote_port))
    } else {
        None
    }
}

/// 将 in_addr 结构转换为 Rust IpAddr
fn ipv4_to_addr(addr: &in_addr) -> IpAddr {
    // in_addr.s_addr 是 32 位地址，网络字节序
    // 注意：我们需要保持内存中的字节顺序，因此使用 to_ne_bytes
    // 之前使用 to_be_bytes 会导致在小端机器上地址反转（如 127.0.0.1 变成 1.0.0.127）
    let octets = addr.s_addr.to_ne_bytes();
    IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
}

/// 将 in6_addr 结构转换为 Rust IpAddr
fn ipv6_to_addr(addr: &in6_addr) -> IpAddr {
    // in6_addr.__u6_addr.__u6_addr8 是 16 字节数组
    let bytes: [u8; 16] = unsafe { addr.__u6_addr.__u6_addr8 };
    IpAddr::V6(Ipv6Addr::from(bytes))
}

// ========================================
// 测试模块
// ========================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_all_pids() {
        let pids = list_all_pids().expect("Should list PIDs");
        // 至少应该有一些进程
        assert!(!pids.is_empty(), "PID list should not be empty");
        // 不应该包含 PID 0
        assert!(!pids.contains(&0), "Should not contain PID 0");
        println!("Found {} processes", pids.len());
    }

    #[test]
    fn test_get_process_name() {
        // 获取当前进程的名字
        let pid = std::process::id() as i32;
        let name = get_process_name(pid);
        assert!(name.is_some(), "Should get current process name");
        println!("Current process name: {:?}", name);
    }

    #[test]
    fn test_get_process_path() {
        let pid = std::process::id() as i32;
        let path = get_process_path(pid);
        assert!(path.is_some(), "Should get current process path");
        println!("Current process path: {:?}", path);
    }
}

//! # 扫描编排模块
//!
//! 这个模块是核心业务逻辑所在，负责：
//! 1. 扫描所有进程及其 socket 连接
//! 2. 判断每个进程的代理使用模式
//! 3. 可选：探测本地代理的出口 IP
//! 4. 可选：使用 GeoIP 查询出口国家
//!
//! ## 代理模式判定逻辑（按优先级）
//! 1. SYSTEM_PROXY: 连接目标 IP:port 匹配系统代理服务器
//! 2. LOCAL_PROXY: 连接到 127.0.0.1/::1 的某个本地端口
//! 3. VPN_LIKELY: 默认路由接口为 utun* 且存在非本地连接
//! 4. DIRECT: 其他情况

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crate::geo::GeoDb;
use crate::macos::{self, SocketInfo};
use crate::proxy::{self, SystemProxy};
use anyhow::Result;
use rayon::prelude::*;
use serde::Serialize;

// ========================================
// 代理模式枚举
// ========================================

/// 进程的代理使用模式
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum ProxyMode {
    /// 通过系统代理（HTTP/HTTPS/SOCKS）
    SystemProxy,
    /// 通过本地代理（连接到 127.0.0.1 的某端口）
    LocalProxy,
    /// 可能通过 VPN（默认路由走 utun 接口）
    VpnLikely,
    /// 直连（未检测到代理）
    Direct,
}

impl std::fmt::Display for ProxyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyMode::SystemProxy => write!(f, "SYSTEM_PROXY"),
            ProxyMode::LocalProxy => write!(f, "LOCAL_PROXY"),
            ProxyMode::VpnLikely => write!(f, "VPN_LIKELY"),
            ProxyMode::Direct => write!(f, "DIRECT"),
        }
    }
}

// ========================================
// 进程扫描结果
// ========================================

/// 单个进程的扫描结果
#[derive(Debug, Clone, Serialize)]
pub struct ProcessResult {
    /// 进程 ID
    pub pid: i32,
    /// 进程名
    pub name: String,
    /// 进程完整路径
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// 代理模式
    pub mode: ProxyMode,
    /// 代理详情（如代理地址和端口）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    /// 出口国家/地区
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// 详细信息（如代理进程的 PID 和名称）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// 连接数量
    pub conns_count: usize,
}

// ========================================
// 扫描上下文
// ========================================

/// 扫描配置和上下文
pub struct ScanContext {
    /// 系统代理配置
    pub system_proxy: SystemProxy,
    /// 默认路由接口
    pub default_iface: String,
    /// 是否为 VPN 接口
    pub is_vpn: bool,
    /// 本地监听端口映射: port -> (pid, name)
    pub listen_ports: HashMap<u16, (i32, String)>,
    /// GeoIP 数据库（可选）
    pub geo_db: Option<GeoDb>,
    /// 是否探测出口
    pub probe_exit: bool,
    /// 只显示走代理的进程
    pub only_routed: bool,
    /// 过滤目标 PID
    pub target_pid: Option<i32>,
    /// 调试模式
    pub debug: bool,
    /// 出口 IP 缓存 (Proxy -> Exit IP)
    /// 使用 Arc<Mutex> 以支持多线程并行扫描
    pub exit_ip_cache: Arc<Mutex<HashMap<String, Option<IpAddr>>>>,
}

impl ScanContext {
    pub fn new(
        geo_db: Option<GeoDb>,
        probe_exit: bool,
        only_routed: bool,
        target_pid: Option<i32>,
        debug: bool,
    ) -> Result<Self> {
        // ... (reading steps 1-2 remain same)
        // 1. 读取系统代理配置
        let system_proxy = proxy::read_system_proxy().unwrap_or_default();

        // 2. 获取默认路由接口
        let default_iface =
            proxy::get_default_route_interface().unwrap_or_else(|_| "unknown".to_string());
        let is_vpn = proxy::scutil::is_vpn_interface(&default_iface);

        // 3. (已移除) 打开 GeoIP 数据库逻辑已移至外部

        // 4. 先留空 listen_ports，稍后填充
        let listen_ports = HashMap::new();

        Ok(Self {
            system_proxy,
            default_iface,
            is_vpn,
            listen_ports,
            geo_db, // 直接使用传入的实例
            probe_exit,
            only_routed,
            target_pid,
            debug,
            exit_ip_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// 构建本地监听端口映射
    ///
    /// 遍历所有进程，找出所有 TCP LISTEN 状态的端口
    pub fn build_listen_ports(&mut self, pids: &[i32]) {
        for &pid in pids {
            // 获取进程名
            let name = macos::get_process_name(pid).unwrap_or_else(|| "unknown".to_string());

            // 获取进程的 socket 列表
            if let Ok(sockets) = macos::list_process_sockets(pid) {
                for sock in sockets {
                    // 只记录 TCP LISTEN 状态的端口
                    if let Some(state) = &sock.tcp_state {
                        if state.is_listening() && sock.local_addr.is_loopback() {
                            self.listen_ports
                                .insert(sock.local_port, (pid, name.clone()));
                        }
                    }
                }
            }
        }
    }
}

// ========================================
// 核心扫描函数
// ========================================

/// 执行完整的进程扫描
///
/// ## 流程
/// 1. 获取所有进程 PID
/// 2. 构建本地监听端口映射
/// 3. 遍历每个进程，获取 socket 连接
/// 4. 判断代理模式
/// 5. 可选：探测出口 IP
/// 6. 可选：GeoIP 查询
///
/// ## 返回
/// 按 PID 排序的进程结果列表
pub fn scan_all_processes(ctx: &mut ScanContext) -> Result<Vec<ProcessResult>> {
    // 1. 获取所有进程 PID
    let pids = macos::list_all_pids()?;

    // 2. 构建监听端口映射
    ctx.build_listen_ports(&pids);

    // 3. 扫描每个进程（并行）
    let mut results: Vec<ProcessResult> = pids
        .into_par_iter()
        .filter_map(|pid| {
            // 如果指定了 PID，跳过不匹配的进程
            if let Some(target) = ctx.target_pid {
                if pid != target {
                    return None;
                }
            }

            // 获取进程信息（失败时继续下一个）
            let name = match macos::get_process_name(pid) {
                Some(n) => n,
                None => return None, // 权限不足，跳过
            };

            let path = macos::get_process_path(pid);

            // 获取 socket 连接
            let sockets = macos::list_process_sockets(pid).unwrap_or_default();

            // 调试模式：打印进程的所有 socket
            if ctx.debug {
                if !sockets.is_empty() {
                    println!("DEBUG: PID {} ({}) sockets:", pid, name);
                    for sock in &sockets {
                        println!(
                            "  {:?} {:?}:{} -> {:?}:{} ({:?})",
                            sock.protocol,
                            sock.local_addr,
                            sock.local_port,
                            sock.remote_addr,
                            sock.remote_port,
                            sock.tcp_state
                        );
                    }
                } else if ctx.target_pid.is_some() {
                    println!("DEBUG: PID {} ({}) has no sockets visible", pid, name);
                }
            }

            if sockets.is_empty() {
                // 没有连接的进程
                if !ctx.only_routed {
                    return Some(ProcessResult {
                        pid,
                        name,
                        path,
                        mode: ProxyMode::Direct,
                        proxy: None,
                        country: None,
                        detail: None,
                        conns_count: 0,
                    });
                }
                return None;
            }

            // 判断代理模式
            let (mode, proxy, detail, country) = determine_proxy_mode(ctx, &sockets);

            // 如果只显示走代理的，过滤掉 DIRECT
            if ctx.only_routed && mode == ProxyMode::Direct {
                return None;
            }

            Some(ProcessResult {
                pid,
                name,
                path,
                mode,
                proxy,
                country,
                detail,
                conns_count: sockets.len(),
            })
        })
        .collect();

    // 按 PID 排序
    results.sort_by_key(|r| r.pid);

    Ok(results)
}

/// 判断进程的代理模式
///
/// 遍历所有 socket 连接，按优先级判断：
/// 1. SYSTEM_PROXY: 匹配系统代理
/// 2. LOCAL_PROXY: 连接本地回环地址
/// 3. VPN_LIKELY: VPN 接口 + 有远端连接
/// 4. DIRECT: 默认
fn determine_proxy_mode(
    ctx: &ScanContext,
    sockets: &[SocketInfo],
) -> (ProxyMode, Option<String>, Option<String>, Option<String>) {
    let mut has_remote_conn = false;
    let mut system_proxy_conn: Option<(IpAddr, u16)> = None;
    let mut local_proxy_conn: Option<(IpAddr, u16)> = None;
    let mut tun_proxy_conn: Option<(IpAddr, u16)> = None;

    // 获取系统代理端口列表
    let proxy_ports: Vec<u16> = [
        ctx.system_proxy.http.as_ref().map(|p| p.port),
        ctx.system_proxy.https.as_ref().map(|p| p.port),
        ctx.system_proxy.socks.as_ref().map(|p| p.port),
    ]
    .into_iter()
    .flatten()
    .collect();

    for sock in sockets {
        // 跳过 LISTEN 状态的连接
        if let Some(state) = &sock.tcp_state {
            if state.is_listening() {
                continue;
            }
        }

        // 跳过未建立的连接（远端地址为 0.0.0.0）
        if sock.remote_addr.is_unspecified() {
            continue;
        }

        // 1. 检查是否连接到系统代理端口（127.0.0.1:7890 等）
        if sock.remote_addr.is_loopback() && check_port_match(sock.remote_port, &proxy_ports) {
            if system_proxy_conn.is_none() {
                system_proxy_conn = Some((sock.remote_addr, sock.remote_port));
            }
            continue;
        }

        // 2. 检查是否是 TUN 模式的虚拟 IP (198.18.0.0/16 - ClashX Pro 等)
        if is_tun_virtual_ip(&sock.remote_addr) || is_tun_virtual_ip(&sock.local_addr) {
            if tun_proxy_conn.is_none() {
                tun_proxy_conn = Some((sock.remote_addr, sock.remote_port));
            }
            continue;
        }

        // 3. 检查是否连接到其他本地回环端口（可能是其他本地代理）
        if sock.remote_addr.is_loopback() {
            if local_proxy_conn.is_none() {
                local_proxy_conn = Some((sock.remote_addr, sock.remote_port));
            }
            continue;
        }

        // 4. 存在非本地的远端连接
        has_remote_conn = true;
    }

    // 按优先级返回结果

    // 1. SYSTEM_PROXY: 连接到系统代理端口
    if let Some((ip, port)) = system_proxy_conn {
        let mut detail = None;
        let mut country = None;

        // 查找监听该端口的进程
        if let Some((proxy_pid, proxy_name)) = ctx.listen_ports.get(&port) {
            detail = Some(format!(
                "proxy_pid={} proxy_name=\"{}\"",
                proxy_pid, proxy_name
            ));

            // 如果启用了出口探测
            if ctx.probe_exit {
                let cache_key = format!("{}:{}", ip, port);

                // 1. 尝试从缓存读取
                let cached_ip = {
                    let cache = ctx.exit_ip_cache.lock().unwrap();
                    cache.get(&cache_key).cloned()
                };

                let exit_ip = if let Some(cached) = cached_ip {
                    cached
                } else {
                    // 2. 缓存未命中，进行探测
                    let result = probe_exit_ip(ip, port);
                    // 3. 写入缓存
                    let mut cache = ctx.exit_ip_cache.lock().unwrap();
                    cache.insert(cache_key, result);
                    result
                };

                if let Some(ip) = exit_ip {
                    // 这里由于有了 &mut ctx，不能直接调用 lookup_country(ctx, ...)，需要解耦
                    // 但我们可以只用 geo_db 部分。为了简单，我们先克隆 geo_db 的引用或者调整结构
                    // 实际上 ctx.geo_db 是 Option<GeoDb>，我们可以直接用
                    if let Some(geo) = &ctx.geo_db {
                        country = geo.lookup(ip).map(|r| format!("{} {}", r.iso_code, r.name));
                    }
                    if country.is_none() {
                        country = Some(format!("exit_ip={}", ip));
                    }
                }
            }
        }

        if ctx.debug {
            println!("  -> Detect: SYSTEM_PROXY (connects to {}:{})", ip, port);
        }

        return (
            ProxyMode::SystemProxy,
            Some(format!("{}:{}", ip, port)),
            detail,
            country,
        );
    }

    // 2. TUN_PROXY: 使用 TUN 模式透明代理 (198.18.x.x)
    if let Some((ip, port)) = tun_proxy_conn {
        if ctx.debug {
            println!("  -> Detect: VPN_LIKELY (TUN mode to {}:{})", ip, port);
        }

        let mut country = None;
        // 如果启用了出口探测，且存在系统代理，尝试通过系统代理探测出口 IP
        // 假设 TUN 模式的流量最终也是通过同一个代理节点出去的
        if ctx.probe_exit {
            let proxy_candidate = ctx
                .system_proxy
                .socks
                .as_ref()
                .or(ctx.system_proxy.http.as_ref())
                .or(ctx.system_proxy.https.as_ref());

            if let Some(proxy) = proxy_candidate {
                // 尝试将 host 解析为 IP (通常是 127.0.0.1)
                if let Ok(proxy_ip) = proxy.host.parse::<std::net::IpAddr>() {
                    let cache_key = format!("{}:{}", proxy_ip, proxy.port);

                    // 1. 尝试从缓存读取
                    let cached_ip = {
                        let cache = ctx.exit_ip_cache.lock().unwrap();
                        cache.get(&cache_key).cloned()
                    };

                    let exit_ip = if let Some(cached) = cached_ip {
                        cached
                    } else {
                        // 2. 缓存未命中，进行探测
                        let result = probe_exit_ip(proxy_ip, proxy.port);
                        // 3. 写入缓存
                        let mut cache = ctx.exit_ip_cache.lock().unwrap();
                        cache.insert(cache_key, result);
                        result
                    };

                    if let Some(ip) = exit_ip {
                        // 复用 Geo 查询逻辑
                        if let Some(geo) = &ctx.geo_db {
                            country = geo.lookup(ip).map(|r| format!("{} {}", r.iso_code, r.name));
                        }
                        if country.is_none() {
                            country = Some(format!("exit_ip={}", ip));
                        }
                    }
                }
            }
        }

        return (
            ProxyMode::VpnLikely, // TUN 模式类似 VPN
            Some(format!("TUN:{}:{}", ip, port)),
            Some("tun_mode=true".to_string()),
            country,
        );
    }

    // 3. LOCAL_PROXY: 连接到其他本地端口
    if let Some((ip, port)) = local_proxy_conn {
        let mut country = None;
        let mut detail = None;

        // 查找监听该端口的进程
        if let Some((proxy_pid, proxy_name)) = ctx.listen_ports.get(&port) {
            detail = Some(format!(
                "proxy_pid={} proxy_name=\"{}\"",
                proxy_pid, proxy_name
            ));

            // 如果启用了出口探测
            if ctx.probe_exit {
                let cache_key = format!("{}:{}", ip, port);

                // 1. 尝试从缓存读取
                let cached_ip = {
                    let cache = ctx.exit_ip_cache.lock().unwrap();
                    cache.get(&cache_key).cloned()
                };

                let exit_ip = if let Some(cached) = cached_ip {
                    cached
                } else {
                    // 2. 缓存未命中，进行探测
                    let result = probe_exit_ip(ip, port);
                    // 3. 写入缓存
                    let mut cache = ctx.exit_ip_cache.lock().unwrap();
                    cache.insert(cache_key, result);
                    result
                };

                if let Some(ip) = exit_ip {
                    if let Some(geo) = &ctx.geo_db {
                        country = geo.lookup(ip).map(|r| format!("{} {}", r.iso_code, r.name));
                    }
                    if country.is_none() {
                        country = Some(format!("exit_ip={}", ip));
                    }
                }
            }
        }

        if ctx.debug {
            println!("  -> Detect: LOCAL_PROXY (connects to {}:{})", ip, port);
        }

        return (
            ProxyMode::LocalProxy,
            Some(format!("{}:{}", ip, port)),
            detail,
            country,
        );
    }

    // 4. VPN_LIKELY: 默认路由走 VPN 且有远端连接
    if ctx.is_vpn && has_remote_conn {
        if ctx.debug {
            println!("  -> Detect: VPN_LIKELY (Default Route is VPN)");
        }
        return (
            ProxyMode::VpnLikely,
            Some(ctx.default_iface.clone()),
            None,
            None,
        );
    }

    // 5. DIRECT: 默认
    if ctx.debug {
        println!("  -> Detect: DIRECT");
    }
    (ProxyMode::Direct, None, None, None)
}

/// 检查端口是否匹配（尝试两种字节序）
fn check_port_match(port: u16, targets: &[u16]) -> bool {
    if targets.contains(&port) {
        return true;
    }
    // 尝试字节交换（处理可能的大小写端问题）
    let swapped = port.swap_bytes();
    if targets.contains(&swapped) {
        return true;
    }
    false
}

/// 检查 IP 是否是 TUN 模式的虚拟 IP
///
/// 常见的 TUN 代理虚拟网段：
/// - 198.18.0.0/15 (ClashX Pro, Surge 等)
/// - 10.255.x.x (某些 VPN)
/// - 172.16-31.x.x (某些 VPN)
fn is_tun_virtual_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // 198.18.0.0/15 (198.18.x.x 和 198.19.x.x)
            if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
                return true;
            }
            // 可以添加更多虚拟网段检测
            false
        }
        IpAddr::V6(_) => false,
    }
}

/// 使用 GeoIP 查询 IP 对应的国家
fn lookup_country(ctx: &ScanContext, ip: &IpAddr) -> Option<String> {
    ctx.geo_db
        .as_ref()
        .and_then(|db| db.lookup(*ip).map(|r| r.to_string()))
}

/// 探测本地代理的出口 IP
///
/// 尝试通过代理访问 https://api.ipify.org?format=json
/// 返回解析到的出口 IP
fn probe_exit_ip(proxy_ip: IpAddr, proxy_port: u16) -> Option<IpAddr> {
    let addr = format!("{}:{}", proxy_ip, proxy_port);

    // 先尝试 SOCKS5 代理
    let socks_proxy = format!("socks5h://{}", addr);
    if let Some(ip) = try_probe_with_proxy(&socks_proxy) {
        return Some(ip);
    }

    // 再尝试 HTTP 代理
    let http_proxy = format!("http://{}", addr);
    if let Some(ip) = try_probe_with_proxy(&http_proxy) {
        return Some(ip);
    }

    None
}

/// 尝试通过指定代理探测出口 IP
fn try_probe_with_proxy(proxy_url: &str) -> Option<IpAddr> {
    use std::time::Duration;

    // 构建带代理的 HTTP 客户端
    let proxy = reqwest::Proxy::all(proxy_url).ok()?;
    let client = reqwest::blocking::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;

    // 请求 IP 检测服务
    #[derive(serde::Deserialize)]
    struct IpifyResponse {
        ip: String,
    }

    let resp: IpifyResponse = client
        .get("https://api.ipify.org?format=json")
        .send()
        .ok()?
        .json()
        .ok()?;

    resp.ip.parse().ok()
}

// ========================================
// 测试模块
// ========================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_mode_display() {
        assert_eq!(ProxyMode::SystemProxy.to_string(), "SYSTEM_PROXY");
        assert_eq!(ProxyMode::LocalProxy.to_string(), "LOCAL_PROXY");
        assert_eq!(ProxyMode::VpnLikely.to_string(), "VPN_LIKELY");
        assert_eq!(ProxyMode::Direct.to_string(), "DIRECT");
    }
}

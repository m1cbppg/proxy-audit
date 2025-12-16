//! # scutil 代理配置解析
//!
//! 这个模块通过执行 `scutil --proxy` 命令读取 macOS 系统代理配置。
//!
//! ## 支持的代理类型
//! - HTTP 代理 (HTTPProxy/HTTPPort)
//! - HTTPS 代理 (HTTPSProxy/HTTPSPort)  
//! - SOCKS 代理 (SOCKSProxy/SOCKSPort)
//! - PAC 自动配置 (ProxyAutoConfigURLString)
//!
//! ## 使用示例
//! ```rust
//! let proxy = read_system_proxy()?;
//! if let Some(http) = &proxy.http {
//!     println!("HTTP proxy: {}:{}", http.host, http.port);
//! }
//! ```

use std::collections::HashSet;
use std::net::{IpAddr, ToSocketAddrs};
use std::process::Command;

use anyhow::{Context, Result};

// ========================================
// 代理服务器结构体
// ========================================

/// 表示一个代理服务器的配置
#[derive(Debug, Clone)]
pub struct ProxyServer {
    /// 代理服务器主机名或 IP
    pub host: String,
    /// 代理端口
    pub port: u16,
    /// 解析后的 IP 地址集合（一个主机名可能解析到多个 IP）
    pub resolved_ips: HashSet<IpAddr>,
}

impl ProxyServer {
    /// 创建新的代理服务器配置
    ///
    /// 会尝试 DNS 解析主机名，如果解析失败则 resolved_ips 为空
    pub fn new(host: String, port: u16) -> Self {
        // 尝试解析主机名为 IP 地址
        // 使用 ToSocketAddrs trait 进行标准 DNS 解析
        let resolved_ips = format!("{}:{}", host, port)
            .to_socket_addrs()
            .map(|addrs| addrs.map(|addr| addr.ip()).collect())
            .unwrap_or_else(|_| {
                // 解析失败时，尝试直接解析为 IP
                host.parse::<IpAddr>()
                    .map(|ip| {
                        let mut set = HashSet::new();
                        set.insert(ip);
                        set
                    })
                    .unwrap_or_default()
            });

        Self {
            host,
            port,
            resolved_ips,
        }
    }

    /// 检查指定的 IP:端口 是否匹配此代理服务器
    pub fn matches(&self, ip: &IpAddr, port: u16) -> bool {
        self.port == port && self.resolved_ips.contains(ip)
    }
}

// ========================================
// 系统代理配置结构体
// ========================================

/// 系统代理配置
#[derive(Debug, Default)]
pub struct SystemProxy {
    /// HTTP 代理
    pub http: Option<ProxyServer>,
    /// HTTPS 代理
    pub https: Option<ProxyServer>,
    /// SOCKS 代理
    pub socks: Option<ProxyServer>,
    /// PAC 自动配置 URL（仅记录，不用于匹配）
    pub pac_url: Option<String>,
}

impl SystemProxy {
    /// 检查指定的 IP:端口 是否匹配任意系统代理
    ///
    /// 返回匹配的代理类型名称，如 "HTTP", "HTTPS", "SOCKS"
    pub fn matches(&self, ip: &IpAddr, port: u16) -> Option<&'static str> {
        if let Some(ref proxy) = self.http {
            if proxy.matches(ip, port) {
                return Some("HTTP");
            }
        }
        if let Some(ref proxy) = self.https {
            if proxy.matches(ip, port) {
                return Some("HTTPS");
            }
        }
        if let Some(ref proxy) = self.socks {
            if proxy.matches(ip, port) {
                return Some("SOCKS");
            }
        }
        None
    }

    /// 判断是否有任何代理配置
    pub fn has_any(&self) -> bool {
        self.http.is_some() || self.https.is_some() || self.socks.is_some()
    }

    /// 获取所有配置的代理端口（用于检测本地代理）
    pub fn all_proxy_addresses(&self) -> Vec<(IpAddr, u16)> {
        let mut addrs = Vec::new();

        // 遍历所有配置的代理
        let proxies = [&self.http, &self.https, &self.socks];
        for proxy_opt in proxies {
            if let Some(proxy) = proxy_opt {
                for ip in &proxy.resolved_ips {
                    addrs.push((*ip, proxy.port));
                }
            }
        }

        addrs
    }
}

// ========================================
// 公开 API 函数
// ========================================

/// 读取 macOS 系统代理配置
///
/// ## 实现说明
/// 执行 `scutil --proxy` 并解析其输出。
///
/// 输出格式示例：
/// ```text
/// <dictionary> {
///   HTTPEnable : 1
///   HTTPProxy : 127.0.0.1
///   HTTPPort : 7890
///   HTTPSEnable : 1
///   HTTPSProxy : 127.0.0.1
///   HTTPSPort : 7890
///   SOCKSEnable : 0
///   ProxyAutoConfigEnable : 0
/// }
/// ```
///
/// ## 注意
/// - 只有当 XXXEnable = 1 时才解析对应的代理
/// - 端口可能是字符串或数字形式
pub fn read_system_proxy() -> Result<SystemProxy> {
    // 执行 scutil --proxy 命令
    let output = Command::new("scutil")
        .arg("--proxy")
        .output()
        .context("Failed to execute scutil --proxy")?;

    if !output.status.success() {
        anyhow::bail!("scutil --proxy failed with status: {}", output.status);
    }

    let output_str = String::from_utf8_lossy(&output.stdout);

    parse_scutil_output(&output_str)
}

/// 解析 scutil --proxy 的输出
fn parse_scutil_output(output: &str) -> Result<SystemProxy> {
    let mut proxy = SystemProxy::default();

    // 使用简单的键值解析
    // 每行格式: "  KeyName : Value"
    let mut http_enable = false;
    let mut http_host = None;
    let mut http_port = None;

    let mut https_enable = false;
    let mut https_host = None;
    let mut https_port = None;

    let mut socks_enable = false;
    let mut socks_host = None;
    let mut socks_port = None;

    for line in output.lines() {
        // 去除前后空白
        let line = line.trim();

        // 跳过非键值行
        if !line.contains(" : ") {
            continue;
        }

        // 分割键值
        let parts: Vec<&str> = line.splitn(2, " : ").collect();
        if parts.len() != 2 {
            continue;
        }

        let key = parts[0].trim();
        let value = parts[1].trim();

        // 解析各个字段
        match key {
            // HTTP 代理
            "HTTPEnable" => http_enable = value == "1",
            "HTTPProxy" => http_host = Some(value.to_string()),
            "HTTPPort" => http_port = value.parse().ok(),

            // HTTPS 代理
            "HTTPSEnable" => https_enable = value == "1",
            "HTTPSProxy" => https_host = Some(value.to_string()),
            "HTTPSPort" => https_port = value.parse().ok(),

            // SOCKS 代理
            "SOCKSEnable" => socks_enable = value == "1",
            "SOCKSProxy" => socks_host = Some(value.to_string()),
            "SOCKSPort" => socks_port = value.parse().ok(),

            // PAC 自动配置
            "ProxyAutoConfigURLString" => {
                if !value.is_empty() {
                    proxy.pac_url = Some(value.to_string());
                }
            }

            _ => {}
        }
    }

    // 组装代理配置
    if http_enable {
        if let (Some(host), Some(port)) = (http_host, http_port) {
            proxy.http = Some(ProxyServer::new(host, port));
        }
    }

    if https_enable {
        if let (Some(host), Some(port)) = (https_host, https_port) {
            proxy.https = Some(ProxyServer::new(host, port));
        }
    }

    if socks_enable {
        if let (Some(host), Some(port)) = (socks_host, socks_port) {
            proxy.socks = Some(ProxyServer::new(host, port));
        }
    }

    Ok(proxy)
}

/// 获取默认路由接口名称
///
/// ## 用途
/// 用于检测是否在使用 VPN（如果接口名称以 utun 开头）
///
/// ## 实现说明
/// 执行 `/sbin/route -n get default` 并解析 `interface:` 行
///
/// 输出格式示例：
/// ```text
///    route to: default
/// destination: default
///        mask: default
///     gateway: 192.168.1.1
///   interface: en0
///       flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
/// ```
pub fn get_default_route_interface() -> Result<String> {
    let output = Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .context("Failed to execute route -n get default")?;

    // 即使命令失败也尝试解析（可能只是警告）
    let output_str = String::from_utf8_lossy(&output.stdout);

    // 查找 interface: 行
    for line in output_str.lines() {
        let line = line.trim();
        if line.starts_with("interface:") {
            // 提取接口名
            if let Some(iface) = line.strip_prefix("interface:") {
                return Ok(iface.trim().to_string());
            }
        }
    }

    // 如果没找到，返回默认值
    Ok("unknown".to_string())
}

/// 判断接口是否为 VPN 隧道接口
///
/// macOS 上 VPN 通常使用 utun* 接口
pub fn is_vpn_interface(iface: &str) -> bool {
    iface.starts_with("utun")
}

// ========================================
// 测试模块
// ========================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scutil_output() {
        let output = r#"<dictionary> {
  HTTPEnable : 1
  HTTPPort : 7890
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  HTTPSPort : 7890
  HTTPSProxy : 127.0.0.1
  ProxyAutoConfigEnable : 0
  SOCKSEnable : 0
}"#;

        let proxy = parse_scutil_output(output).unwrap();

        assert!(proxy.http.is_some());
        let http = proxy.http.unwrap();
        assert_eq!(http.host, "127.0.0.1");
        assert_eq!(http.port, 7890);

        assert!(proxy.https.is_some());
        assert!(proxy.socks.is_none());
    }

    #[test]
    fn test_get_default_route_interface() {
        // 这个测试依赖系统状态，只验证不 panic
        let result = get_default_route_interface();
        println!("Default interface: {:?}", result);
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_vpn_interface() {
        assert!(is_vpn_interface("utun0"));
        assert!(is_vpn_interface("utun1"));
        assert!(!is_vpn_interface("en0"));
        assert!(!is_vpn_interface("lo0"));
    }
}

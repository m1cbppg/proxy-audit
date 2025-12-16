//! # proxy-audit
//!
//! macOS CLI 工具，用于审计进程是否走代理。
//!
//! ## 功能
//! - 扫描所有运行中的进程
//! - 枚举每个进程的 TCP/UDP socket 连接
//! - 判断进程的代理使用模式:
//!   - SYSTEM_PROXY: 通过系统代理
//!   - LOCAL_PROXY: 通过本地代理（如 Clash、V2Ray）
//!   - VPN_LIKELY: 可能通过 VPN
//!   - DIRECT: 直连
//!
//! ## 使用
//! ```bash
//! # 基础扫描（需要 sudo 以读取其他进程的信息）
//! sudo proxy-audit scan
//!
//! # 只显示走代理的进程
//! sudo proxy-audit scan --only-routed
//!
//! # JSON 格式输出
//! sudo proxy-audit scan --json
//!
//! # 使用 GeoIP 显示出口国家
//! sudo proxy-audit scan --geo-db /path/to/GeoLite2-Country.mmdb
//!
//! # 探测本地代理的出口 IP
//! sudo proxy-audit scan --probe-exit --geo-db /path/to/GeoLite2-Country.mmdb
//! ```

use std::process;

use anyhow::Result;
use clap::{Parser, Subcommand};

// 导入我们的模块
use std::env;
mod geo;
mod macos;
mod proxy;
mod scan;

/// 默认 GeoIP 数据库下载地址 (GitHub Mirror)
/// 用户可以 fork 自己的仓库并在构建时修改此常量
const DEFAULT_GEOIP_MIRROR: &str =
    "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb";

// ========================================
// CLI 参数定义
// ========================================

/// macOS 进程代理审计工具
#[derive(Parser)]
#[command(name = "proxy-audit")]
#[command(author = "Your Name")]
#[command(version = "0.1.0")]
#[command(about = "macOS CLI tool to audit whether processes are using proxies")]
struct Cli {
    /// 子命令
    #[command(subcommand)]
    command: Commands,
}

/// 支持的子命令
#[derive(Subcommand)]
enum Commands {
    /// 扫描所有进程的代理使用情况
    Scan {
        /// 指定 PID 进行扫描 (可选)
        pid: Option<i32>,

        /// 扫描所有进程 (默认只显示走代理的进程)
        #[arg(long, short = 'a')]
        all: bool,

        /// 指定 GeoIP 数据库路径 (可选，默认使用桌面路径)
        #[arg(long, value_name = "PATH")]
        geo_db: Option<String>,

        /// 是否禁用出口探测 (默认开启)
        #[arg(long)]
        no_probe: bool,

        /// JSON 格式输出
        #[arg(long)]
        json: bool,

        /// 显示调试信息
        #[arg(long)]
        debug: bool,
    },
    /// 更新 GeoIP 数据库
    #[command(name = "update-geo")]
    UpdateGeo {
        /// 指定下载 URL (可选，默认使用 GitHub Mirror)
        #[arg(long)]
        url: Option<String>,

        /// 强制更新 (即使文件已存在)
        #[arg(long)]
        force: bool,
    },
}

// ========================================
// 主函数
// ========================================

fn main() {
    // 解析命令行参数
    let cli = Cli::parse();

    // 确定配置目录: ~/.config/proxy-audit/
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let config_dir = format!("{}/.config/proxy-audit", home);
    let default_geo_path = format!("{}/GeoLite2-Country.mmdb", config_dir);

    // 执行对应的子命令
    let result = match cli.command {
        Commands::Scan {
            pid,
            all,
            geo_db,
            no_probe,
            json,
            debug,
        } => {
            // 路径优先级: 1. CLI 参数  2. 环境变量 (TODO)  3. 默认配置路径  4. (Dev) 桌面路径
            // 5. 最终 Fallback: 嵌入在二进制文件中的数据库

            // 尝试查找外部文件
            let dev_path = format!("{}/Desktop/backend/net_check/proxy-audit/GeoLite2-Country_20251212/GeoLite2-Country.mmdb", home);

            let file_path = if let Some(p) = geo_db {
                Some(p)
            } else if std::path::Path::new(&default_geo_path).exists() {
                Some(default_geo_path)
            } else if std::path::Path::new(&dev_path).exists() {
                Some(dev_path)
            } else {
                None
            };

            // 加载数据库实例
            let geo_instance = if let Some(path) = file_path {
                match geo::GeoDb::open(&path) {
                    Ok(db) => Some(db),
                    Err(e) => {
                        eprintln!("Warning: Failed to open GeoDB at {}: {}", path, e);
                        // 尝试使用嵌入版本
                        load_embedded_geodb()
                    }
                }
            } else {
                // 没有外部文件，直接使用嵌入版本
                load_embedded_geodb()
            };

            run_scan(geo_instance, !no_probe, !all, json, pid, debug)
        }
        Commands::UpdateGeo { url, force } => {
            run_update_geo(&config_dir, &default_geo_path, url, force)
        }
    };

    // 处理错误
    if let Err(e) = result {
        eprintln!("Error: {:#}", e);
        process::exit(1);
    }
}

/// 加载嵌入的 GeoIP 数据库
fn load_embedded_geodb() -> Option<geo::GeoDb> {
    // 编译时嵌入文件
    const GEO_DB_BYTES: &[u8] =
        include_bytes!("../GeoLite2-Country_20251212/GeoLite2-Country.mmdb");

    match geo::GeoDb::from_bytes(GEO_DB_BYTES) {
        Ok(db) => Some(db),
        Err(e) => {
            eprintln!("Warning: Failed to load embedded GeoDB: {}", e);
            None
        }
    }
}

/// 执行 GeoIP 数据库更新
fn run_update_geo(
    config_dir: &str,
    target_path: &str,
    url: Option<String>,
    force: bool,
) -> Result<()> {
    use std::fs;
    use std::io::Write;
    use std::path::Path;

    if !force && Path::new(target_path).exists() {
        println!("GeoIP database already exists at: {}", target_path);
        println!("Use --force to overwrite.");
        return Ok(());
    }

    // 确保目录存在
    fs::create_dir_all(config_dir)?;

    let download_url = url.as_deref().unwrap_or(DEFAULT_GEOIP_MIRROR);

    println!("Downloading GeoIP database...");
    println!("From: {}", download_url);
    println!("To:   {}", target_path);

    // 使用 reqwest 下载
    // 注意：reqwest blocking feature 必须开启
    let response = reqwest::blocking::get(download_url)?;
    let content = response.bytes()?;

    let mut file = fs::File::create(target_path)?;
    file.write_all(&content)?;

    println!("Successfully updated GeoIP database!");
    Ok(())
}

// ========================================
// 扫描命令实现
// ========================================

/// 执行扫描命令
fn run_scan(
    geo_db: Option<geo::GeoDb>,
    probe_exit: bool,
    only_routed: bool,
    json_output: bool,
    target_pid: Option<i32>,
    debug: bool,
) -> Result<()> {
    // 1. 创建扫描上下文
    let mut ctx = scan::ScanContext::new(geo_db, probe_exit, only_routed, target_pid, debug)?;

    // 2. 输出头部信息（非 JSON 模式）
    if !json_output {
        // 显示默认路由接口
        println!("Default route iface: {}", ctx.default_iface);
        if ctx.is_vpn {
            println!("VPN detected: interface starts with 'utun'");
        }

        // 显示系统代理信息
        if ctx.system_proxy.has_any() {
            if let Some(ref http) = ctx.system_proxy.http {
                println!("System HTTP proxy: {}:{}", http.host, http.port);
            }
            if let Some(ref https) = ctx.system_proxy.https {
                println!("System HTTPS proxy: {}:{}", https.host, https.port);
            }
            if let Some(ref socks) = ctx.system_proxy.socks {
                println!("System SOCKS proxy: {}:{}", socks.host, socks.port);
            }
        }

        // 显示 PAC 信息（如果有）
        if let Some(ref pac_url) = ctx.system_proxy.pac_url {
            println!("PAC: {}", pac_url);
        }

        println!(); // 空行分隔
    }

    // 3. 执行扫描
    let results = scan::scan_all_processes(&mut ctx)?;

    // 4. 输出结果
    if json_output {
        // JSON 格式输出
        let json = serde_json::to_string_pretty(&results)?;
        println!("{}", json);
    } else {
        // 3. 打印表头
        println!(
            "{:<30}\t{:<15}\t{:<30}\t{:<15}",
            "NAME", "MODE", "PROXY", "REGION"
        );

        // 4. 打印每行数据
        let mut count_map = std::collections::HashMap::new();

        for res in &results {
            *count_map.entry(res.mode.clone()).or_insert(0) += 1;

            let mode_str = match res.mode {
                scan::ProxyMode::SystemProxy => "System",
                scan::ProxyMode::LocalProxy => "Local",
                scan::ProxyMode::VpnLikely => "VPN/TUN",
                scan::ProxyMode::Direct => "Direct",
            };

            // 优化代理显示
            // 如果有详细信息包含 proxy_name，优先显示名字
            let proxy_display = if let Some(detail) = &res.detail {
                if let Some(start) = detail.find("proxy_name=\"") {
                    let rest = &detail[start + 12..];
                    if let Some(end) = rest.find('"') {
                        format!("{}", &rest[..end])
                    } else {
                        res.proxy.clone().unwrap_or("-".to_string())
                    }
                } else if detail.contains("tun_mode=true") {
                    "Transparent".to_string()
                } else {
                    res.proxy.clone().unwrap_or("-".to_string())
                }
            } else {
                res.proxy.clone().unwrap_or("-".to_string())
            };

            // 如果是系统代理且显示为IP，尝试简码
            let proxy_final = if res.mode == scan::ProxyMode::SystemProxy
                && proxy_display.starts_with("127.0.0.1:")
            {
                // 如果没解析出名字，显示端口
                format!("Port {}", proxy_display.split(':').nth(1).unwrap_or("?"))
            } else {
                proxy_display
            };

            println!(
                "{:<30}\t{:<15}\t{:<30}\t{:<15}",
                &res.name,
                mode_str,
                &proxy_final,
                res.country.as_deref().unwrap_or("-")
            );
        }

        println!("\nTotal: {} processes scanned", results.len());
        for (mode, count) in count_map {
            println!("  {}: {}", mode, count);
        }
    }

    Ok(())
}

fn truncate(s: &str, max_width: usize) -> String {
    if s.len() > max_width {
        format!("{}..", &s[..max_width - 2])
    } else {
        s.to_string()
    }
}

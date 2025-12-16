//! # MaxMind mmdb GeoIP 查询
//!
//! 这个模块使用 MaxMind 的 GeoLite2-Country.mmdb 数据库
//! 将 IP 地址映射到国家/地区信息。
//!
//! ## 使用示例
//! ```rust
//! let db = GeoDb::open("/path/to/GeoLite2-Country.mmdb")?;
//! if let Some(result) = db.lookup("8.8.8.8".parse()?) {
//!     println!("{} {}", result.iso_code, result.name);
//!     // 输出: US United States
//! }
//! ```
//!
//! ## 如何获取数据库
//! 1. 访问 https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
//! 2. 注册账户并下载 GeoLite2-Country.mmdb

use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use maxminddb::geoip2;

// ========================================
// GeoIP 查询结果
// ========================================

/// GeoIP 查询结果
#[derive(Debug, Clone, serde::Serialize)]
pub struct GeoResult {
    /// 国家 ISO 代码（如 "US", "CN", "JP"）
    pub iso_code: String,
    /// 国家英文名称（如 "United States", "China", "Japan"）
    pub name: String,
}

impl std::fmt::Display for GeoResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.iso_code, self.name)
    }
}

// ========================================
// GeoIP 数据库封装
// ========================================

/// MaxMind GeoIP 数据库封装
pub struct GeoDb {
    /// 内部 Reader 实例
    /// 使用 Vec<u8> 作为某些场景下的所有权数据容器不太灵活，
    /// 这里为了同时支持文件读取（Vec<u8>）和嵌入（&[u8]），
    /// 我们简单地统一使用 Vec<u8>，虽然对 include_bytes 会有一次内存拷贝，但几MB数据可以接受。
    reader: maxminddb::Reader<Vec<u8>>,
}

impl GeoDb {
    /// 打开 GeoIP 数据库文件
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let reader = maxminddb::Reader::open_readfile(path)
            .with_context(|| format!("Failed to open GeoIP database: {}", path.display()))?;
        Ok(Self { reader })
    }

    /// 从字节数组加载数据库
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // 这里的 to_vec() 会发生一次内存拷贝
        let reader = maxminddb::Reader::from_source(bytes.to_vec())
            .context("Failed to parse embedded GeoIP database")?;
        Ok(Self { reader })
    }

    /// 查询 IP 地址对应的国家/地区
    ///
    /// ## 参数
    /// - `ip`: 要查询的 IP 地址
    ///
    /// ## 返回
    /// - `Some(GeoResult)`: 查询成功
    /// - `None`: IP 不在数据库中或查询失败
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoResult> {
        // 使用 geoip2::Country 类型进行类型化查询
        // 这是 maxminddb crate 预定义的结构体，匹配 GeoLite2-Country 数据库
        let country: geoip2::Country = self.reader.lookup(ip).ok()?;

        // 提取国家信息
        // country.country 是 Option<geoip2::country::Country>
        let country_info = country.country?;

        // 提取 ISO 代码
        let iso_code = country_info.iso_code?;

        // 提取英文名称
        // names 是 HashMap<&str, &str>，键是语言代码
        let name = country_info
            .names
            .as_ref()
            .and_then(|names| names.get("en").copied())
            .unwrap_or("Unknown");

        Some(GeoResult {
            iso_code: iso_code.to_string(),
            name: name.to_string(),
        })
    }
}

// ========================================
// 测试模块
// ========================================
#[cfg(test)]
mod tests {
    use super::*;

    // 注意：这个测试需要实际的 mmdb 文件
    // 如果没有文件，测试会跳过
    #[test]
    fn test_lookup() {
        // 尝试常见路径
        let paths = [
            "/usr/local/share/GeoIP/GeoLite2-Country.mmdb",
            "/opt/homebrew/share/GeoIP/GeoLite2-Country.mmdb",
            "GeoLite2-Country.mmdb",
        ];

        for path in &paths {
            if let Ok(db) = GeoDb::open(path) {
                // 测试 Google DNS
                let ip: IpAddr = "8.8.8.8".parse().unwrap();
                if let Some(result) = db.lookup(ip) {
                    println!("8.8.8.8 -> {}", result);
                    assert_eq!(result.iso_code, "US");
                    return;
                }
            }
        }

        println!("Skipping test: no GeoIP database found");
    }
}

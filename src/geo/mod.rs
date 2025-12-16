//! # GeoIP 模块
//!
//! 提供 GeoIP 查询功能，将 IP 地址映射到国家/地区。

pub mod mmdb;

// 重新导出常用类型
pub use mmdb::{GeoDb, GeoResult};

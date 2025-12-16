//! # 代理检测模块
//!
//! 这个模块负责检测系统代理配置和识别代理连接。

pub mod scutil;

// 重新导出常用类型
pub use scutil::{get_default_route_interface, read_system_proxy, ProxyServer, SystemProxy};

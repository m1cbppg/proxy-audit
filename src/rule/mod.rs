//! # 规则生成模块
//!
//! 此模块负责：
//! 1. 从进程连接信息生成代理分流规则
//! 2. 支持多种代理软件规则格式（Clash, Surge, Quantumult X, Sing-box）
//! 3. 管理规则文件的初始化和追加

pub mod formatter;
mod manager;

pub use formatter::{OutputFormat, RulePolicy};
pub use manager::RuleFileManager;

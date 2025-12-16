//! # macOS 模块
//!
//! 这个模块包含所有 macOS 特定的实现，主要是 libproc FFI 调用。
//! 通过模块化设计，未来如果要支持其他平台，可以添加对应的模块。

pub mod libproc;

// 重新导出常用类型，方便其他模块使用
pub use libproc::{get_process_name, get_process_path, list_all_pids, list_process_sockets};
pub use libproc::{SocketInfo, SocketProtocol, TcpState};

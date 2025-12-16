//! # build.rs - 构建脚本
//!
//! 这个脚本在 `cargo build` 时自动执行，用于：
//! 1. 使用 bindgen 从 C 头文件生成 Rust FFI 绑定
//! 2. 链接 macOS 系统的 libproc 库
//!
//! ## 为什么需要 bindgen？
//! macOS 的 libproc API 是 C 语言接口，包含复杂的结构体（如 socket_fdinfo）。
//! 手动编写这些结构体容易出错，bindgen 可以自动从头文件生成正确的 Rust 定义。
//!
//! ## 为什么需要 LIBCLANG_PATH？
//! bindgen 底层使用 libclang 解析 C 头文件，需要安装 LLVM 并设置路径。

use std::env;
use std::path::PathBuf;

fn main() {
    // ========================================
    // 1. 告诉 cargo 链接 libproc
    // ========================================
    // libproc 是 macOS 系统库，位于 /usr/lib/libproc.dylib
    // "dylib" 表示动态链接（macOS 的 .dylib 文件）
    println!("cargo:rustc-link-lib=dylib=proc");

    // ========================================
    // 2. 设置 rerun-if-changed
    // ========================================
    // 告诉 cargo：只有当这些文件变化时才需要重新运行 build.rs
    // 这样可以避免每次编译都重新生成 bindings
    println!("cargo:rerun-if-changed=native/wrapper.h");
    println!("cargo:rerun-if-changed=build.rs");

    // ========================================
    // 3. 配置 bindgen
    // ========================================
    let bindings = bindgen::Builder::default()
        // 输入：我们的包装头文件
        .header("native/wrapper.h")
        
        // 添加 clang 参数，确保能找到 macOS SDK 的头文件
        // 这个路径包含 <libproc.h> 和 <sys/proc_info.h>
        .clang_arg("-isysroot")
        .clang_arg("/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk")
        
        // 生成 Debug trait，方便调试输出
        .derive_debug(true)
        
        // 生成 Default trait，方便初始化结构体
        .derive_default(true)
        
        // 只生成我们需要的类型，减少编译时间
        // allowlist_type: 只包含匹配的类型
        .allowlist_type("proc_fdinfo")
        .allowlist_type("socket_fdinfo")
        .allowlist_type("in_sockinfo")
        .allowlist_type("tcp_sockinfo")
        .allowlist_type("sockaddr_in")
        .allowlist_type("sockaddr_in6")
        .allowlist_type("in_addr")
        .allowlist_type("in6_addr")
        
        // allowlist_function: 只包含匹配的函数
        .allowlist_function("proc_listpids")
        .allowlist_function("proc_pidinfo")
        .allowlist_function("proc_pidfdinfo")
        .allowlist_function("proc_name")
        .allowlist_function("proc_pidpath")
        
        // allowlist_var: 只包含匹配的常量
        // PROC_* 是进程信息类型常量
        // PROX_FD* 是文件描述符类型常量
        // SOCKINFO_* 是 socket 信息类型常量
        .allowlist_var("PROC_ALL_PIDS")
        .allowlist_var("PROC_PIDLISTFDS")
        .allowlist_var("PROC_PIDFDSOCKETINFO")
        .allowlist_var("PROX_FDTYPE_SOCKET")
        .allowlist_var("SOCKINFO_TCP")
        .allowlist_var("SOCKINFO_IN")
        // 注意：TCP 状态常量 (TCPS_*) 在 libproc.rs 中手动定义
        .allowlist_var("IPPROTO_TCP")
        .allowlist_var("IPPROTO_UDP")
        .allowlist_var("AF_INET")
        .allowlist_var("AF_INET6")
        
        // 使用 libc 的类型定义，避免重复定义
        .ctypes_prefix("libc")
        
        // 生成 bindings
        .generate()
        .expect("Unable to generate bindings");

    // ========================================
    // 4. 输出生成的代码到 OUT_DIR
    // ========================================
    // OUT_DIR 是 cargo 提供的构建目录，通常是 target/debug/build/xxx/out
    // 生成的 libproc_bindings.rs 会在编译时被 include! 宏引入
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("libproc_bindings.rs"))
        .expect("Couldn't write bindings!");
}

/**
 * wrapper.h - C 头文件包装器
 *
 * 这个文件被 bindgen 用来生成 Rust FFI 绑定。
 * 我们在这里 #include 所有需要的系统头文件。
 *
 * 为什么需要这个文件？
 * - bindgen 只能处理一个入口头文件
 * - 我们需要多个系统头文件的类型定义
 * - 通过这个包装文件，可以一次性引入所有需要的定义
 */

// libproc.h 提供进程信息 API：
// - proc_listpids: 列出所有进程 PID
// - proc_pidinfo: 获取进程信息（FD 列表等）
// - proc_pidfdinfo: 获取特定 FD 的详细信息
// - proc_name: 获取进程名
// - proc_pidpath: 获取进程完整路径
#include <libproc.h>

// sys/proc_info.h 提供数据结构定义：
// - proc_fdinfo: 文件描述符基本信息
// - socket_fdinfo: socket 文件描述符详细信息
// - in_sockinfo: IPv4/IPv6 socket 信息
// - tcp_sockinfo: TCP 连接信息（包含状态）
#include <sys/proc_info.h>

// netinet/in.h 提供网络地址结构：
// - sockaddr_in: IPv4 地址结构
// - sockaddr_in6: IPv6 地址结构
// - in_addr: IPv4 地址
// - in6_addr: IPv6 地址
#include <netinet/in.h>

// arpa/inet.h 提供地址转换函数：
// - inet_ntop: 将网络字节序的 IP 地址转换为字符串
// 注意：inet_ntop 我们在 Rust 中使用 libc crate 调用，不需要 bindgen
#include <arpa/inet.h>

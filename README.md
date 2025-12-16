# proxy-audit

macOS CLI 工具，用于审计运行中的进程是否走代理。

## 功能

- 📋 扫描所有运行中的进程（前台/后台）
- 🔌 枚举每个进程的 TCP/UDP socket 连接
- 🎯 判断进程的代理使用模式：
  - `SYSTEM_PROXY`: 通过系统代理（HTTP/HTTPS/SOCKS）
  - `LOCAL_PROXY`: 通过本地代理（如 Clash、V2Ray、Surge）
  - `VPN_LIKELY`: 可能通过 VPN（默认路由走 utun 接口）
  - `DIRECT`: 直连
- 🌍 可选：GeoIP 查询出口国家/地区
- 🔍 可选：探测本地代理的出口 IP

## 安装

### 前置条件

1. **安装 Xcode Command Line Tools**
   ```bash
   xcode-select --install
   ```

2. **安装 Rust**
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source ~/.cargo/env
   ```

3. **安装 LLVM（用于 bindgen）**
   ```bash
   brew install llvm
   ```

4. **设置 LIBCLANG_PATH 环境变量**

   **Apple Silicon (M1/M2/M3):**
   ```bash
   export LIBCLANG_PATH=/opt/homebrew/opt/llvm/lib
   ```

   **Intel Mac:**
   ```bash
   export LIBCLANG_PATH=/usr/local/opt/llvm/lib
   ```

   建议将上述 export 添加到 `~/.zshrc` 中。

### 编译

```bash
cd /path/to/proxy-audit
cargo build --release
```

编译后的二进制文件位于 `target/release/proxy-audit`。

## 使用

### 基础扫描

```bash
# 需要 sudo 权限以读取其他进程的 socket 信息
sudo ./target/release/proxy-audit scan
```

输出示例：
```
Default route iface: en0
System HTTP proxy: 127.0.0.1:7890
System HTTPS proxy: 127.0.0.1:7890
System SOCKS proxy: 127.0.0.1:7890

NAME                 MODE            PROXY                     REGION
syspolicyd           System          ClashX Pro                -
apsd                 VPN/TUN         Transparent               -
Postman Helper       System          ClashX Pro                -
hexhub-backend       Local           127.0.0.1:57294           -
GitHub Copilot       Local           language_server...        US

Total: 5 processes scanned
  SYSTEM_PROXY: 2
  VPN_LIKELY: 1
  LOCAL_PROXY: 2
```

## 输出字段说明

| 字段 | 说明 |
|------|------|
| **NAME** | 进程名称。通常是应用程序的主程序名。 |
| **MODE** | 代理模式，表示该进程的网络连接方式：<br> - `System`: 使用 macOS 系统代理设置（HTTP/SOCKS）<br> - `VPN/TUN`: 流量被虚拟网卡（TUN/TAP）接管，通常是透明代理模式 <br> - `Local`: 连接到了本地（127.0.0.1）的其他代理服务端口 <br> - `Direct`: 直连，未检测到代理特征 |
| **PROXY** | 代理详情：<br> - 显示具体的代理软件名称（如 `ClashX Pro`），如果能识别的话 <br> - 显示 `Transparent` 表示透明代理 <br> - 否则显示具体的 `IP:Port` |
| **REGION** | 目标服务器或代理出口的地理位置（需配合 `--geo-db` 和 `--probe-exit` 使用）。 |

### 只显示走代理的进程

```bash
sudo ./target/release/proxy-audit scan --only-routed
```

### JSON 格式输出

```bash
sudo ./target/release/proxy-audit scan --json
```

### 使用 GeoIP

需要先下载 GeoLite2-Country.mmdb:
1. 访问 https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
2. 注册账户并下载 GeoLite2-Country.mmdb

```bash
sudo ./target/release/proxy-audit scan --geo-db /path/to/GeoLite2-Country.mmdb
```

### 探测出口 IP

```bash
sudo ./target/release/proxy-audit scan --probe-exit --geo-db /path/to/GeoLite2-Country.mmdb
```

## 项目结构

```
proxy-audit/
├── Cargo.toml           # 项目配置
├── build.rs             # bindgen FFI 生成
├── native/
│   └── wrapper.h        # C 头文件
├── src/
│   ├── main.rs          # CLI 入口
│   ├── scan.rs          # 扫描逻辑
│   ├── macos/
│   │   ├── mod.rs
│   │   └── libproc.rs   # libproc FFI
│   ├── proxy/
│   │   ├── mod.rs
│   │   └── scutil.rs    # 系统代理检测
│   └── geo/
│       ├── mod.rs
│       └── mmdb.rs      # GeoIP 查询
└── README.md
```

## 常见问题

### Q: bindgen 报错找不到 libclang

确保已设置 `LIBCLANG_PATH` 环境变量：
```bash
# Apple Silicon
export LIBCLANG_PATH=/opt/homebrew/opt/llvm/lib

# Intel
export LIBCLANG_PATH=/usr/local/opt/llvm/lib
```

### Q: 扫描结果很多进程都是 DIRECT

这是正常的。只有主动建立外部连接的进程才会被标记为使用代理。
使用 `--only-routed` 可以过滤只显示走代理的进程。

### Q: 权限不足导致无法读取某些进程

需要使用 `sudo` 运行。即使有 sudo，某些系统进程可能仍然无法读取，程序会优雅跳过。

### Q: 如何判断是走的代理还是 VPN？

- `LOCAL_PROXY`: 进程连接到 127.0.0.1 的某个端口，该端口有本地代理在监听
- `VPN_LIKELY`: 默认路由接口是 utun*（VPN 隧道接口）

### Q: 没有检测到我开启的代理

检查以下几点：
1. 代理是否在系统设置中配置（而不仅仅是浏览器扩展）
2. 运行 `scutil --proxy` 查看系统代理配置
3. 某些应用可能使用自己的代理配置，不走系统代理

## License

MIT

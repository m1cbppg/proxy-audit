# proxy-audit

macOS CLI 工具，用于审计运行中的进程是否走代理。

## 功能

*   📋 **全量扫描**：瞬间扫描系统所有进程（前台/后台）
*   🎯 **代理识别**：精准识别进程的联网模式：
    *   `SYSTEM`: 走系统代理（如 Surge/Clash 的系统代理模式）
    *   `TUN`: 走虚拟网卡（如 Surge/Clash 增强模式/VPN）
    *   `LOCAL`: 连接本地代理端口（127.0.0.1）
*   🌍 **IP 归属**：内嵌 GeoIP 数据库，直接显示出口国家/地区

## 安装

### Homebrew (推荐)

无需手动下载文件，直接使用 Brew 安装：

```bash
# 1. 添加 Tap
brew tap m1cbppg/tap

# 2. 安装
brew install proxy-audit
```

> **注意**：如果安装时报错 `Command Line Tools are too outdated`，请先运行 `sudo rm -rf /Library/Developer/CommandLineTools && sudo xcode-select --install` 更新系统工具。

## 使用

**⚠️ 注意**：由于需要读取其他进程的网络信息，运行命令时需要 `sudo` 权限。

### 1. 基础扫描
扫描所有正在通过代理联网的进程：
```bash
sudo proxy-audit scan
```

### 2. 扫描所有进程
包括未联网或直连的进程：
```bash
sudo proxy-audit scan -a
```

### 3. 指定进程
查看特定进程（如 Chrome）的网络情况：
```bash
sudo proxy-audit scan <PID>
```

### 4. 更新数据库
工具虽然内置了数据库，但你也可以手动更新到最新版：
```bash
sudo proxy-audit update-geo --force
```

### 5. 规则生成器 (Smart Rule Generator)

自动为你的代理客户端生成基于进程的代理规则，实现单个进程代理模式的灵活切换。

**典型使用场景:**

*   **强制直连**: 当开启 TUN 模式导致国内应用网速变慢时，可强制将特定进程的代理模式切换为直连。
*   **强制代理**: 对于未按预期使用代理的进程，可强制将其代理模式切换为代理。

**核心机制 (Policy-Based Sets):**
我们将规则分散存储在 `rules-direct`, `rules-proxy`, `rules-reject` 三个独立文件中。
无论你如何调整单个进程的策略（例如从直连切换到代理），工具会自动在这些文件间迁移规则，确保策略精准生效。

**支持格式:**
*   **Clash**: 自动生成 `PROCESS-NAME` 规则
*   **Surge**: 自动生成 `PROCESS-NAME` 规则
*   **Sing-box**: 自动生成 `process_name` 规则集
*   *(Quantumult X 暂不支持进程名规则)*

**使用步骤:**

1.  **初始化 (仅需一次)**:
    ```bash
    proxy-audit rule init --format clash
    ```
    命令会生成 3 个规则文件，并输出**配置指南**。
    > **⚠️ 关键两点**:
    > 1. 请务必按照屏幕提示，在您的代理软件中注册这 3 个 Rule Provider。
    > 2. **Clash 用户注意**: 在配置 `rules` 时，请将示例中的 `PROXY` 替换为您配置文件中**实际存在的策略组名称**（例如 `Proxy`, `节点选择`, `🚀 节点选择` 等），否则会报错 "proxy not found"。

2.  **添加/修改规则**:
    当您发现某个应用（例如 Telegram）分流不正确时，运行：
    ```bash
    # 扫描 PID，检测进程名，并将其强制加入 PROXY 列表
    # (如果它之前在 DIRECT 列表中，会被自动移除，实现无缝切换)
    sudo proxy-audit rule add --pid <PID> --policy PROXY
    ```

3.  **生效**:
    *   **重载配置**: 在代理软件中点击 "Reload Config"。
    *   **重启应用 (重要)**: 对于 Telegram 等保持长连接的应用，重载配置**有时不会**切断旧连接。您必须**彻底退出并重启该应用**，新规则才会生效。

**常用命令:**

*   **设为直连**: `proxy-audit rule add --pid <PID> --policy DIRECT`
*   **设为拒绝**: `proxy-audit rule add --pid <PID> --policy REJECT`
*   **仅打印规则**: `proxy-audit rule print --pid <PID> --format clash` (不写入文件)


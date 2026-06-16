# WarpGo v2.0.1

一键部署 Cloudflare WARP / Zero Trust Proxy，让 VPS 通过 WARP 隧道改变出口 IP。

## 功能特性

- **WireGuard 模式** — 全局接管 VPS 网络流量
- **Zero Trust Proxy 模式** — SOCKS5 代理 + socat 反代 + 透明代理
- **SSH 保护** — 安装/运行全程保障 SSH 不中断
- **兼容 Debian 13** — 自动适配 nftables（无 iptables 环境）

## 快速开始

```bash
# 下载（Debian 13 / Ubuntu amd64）
wget https://github.com/CFM503/warp2/releases/download/v2.0.1/warpgo-linux-amd64
chmod +x warpgo-linux-amd64

# 运行交互菜单
./warpgo-linux-amd64
```

## 安装模式

### 模式 1：WARP（WireGuard）

全局模式，VPS 所有流量走 WARP 隧道，出口 IP 变为 Cloudflare IP。

```bash
./warpgo -4    # IPv4
./warpgo -6    # IPv6
./warpgo -d    # 双栈
```

### 模式 2：Zero Trust Proxy（推荐）

通过 Cloudflare Zero Trust 组织接入，使用 warp-cli proxy 模式。

**前置条件：**
- Cloudflare Zero Trust 组织（免费支持 50 人以内）
- Service Token（Service Auth 类型，非普通 Allow）

**获取路径：**
```
one.dash.cloudflare.com
  → Settings → WARP Client → Device enrollment    # 获取组织名称
  → Access → Service Auth → Service Tokens         # 创建 Token
```

**安装：**
```bash
./warpgo -z
```

交互菜单中依次输入：
1. 组织名称（Team Name）
2. Service Token 的 Client ID
3. Service Token 的 Client Secret
4. 外部代理端口（默认 40000）

**安装完成后提供三种使用方式：**

| 方式 | 说明 | 命令 |
|------|------|------|
| SOCKS5 代理 | 外部设备通过 VPS 代理上网 | 浏览器设置 `socks5://VPS_IP:40000` |
| 透明代理 | VPS 自身所有流量走 WARP | 菜单选 `t` 开启 |
| 直接验证 | 通过代理验证出口 IP | `curl --proxy socks5://127.0.0.1:40000 -4 ip.gs` |

### 模式 3：Zero Trust（WireGuard）

使用 WireGuard 协议接入 Zero Trust 组织网络，需要环境变量：

```bash
WARP_ORG=your-team WARP_CLIENT_ID=xxx WARP_CLIENT_SECRET=yyy ./warpgo -w
```

## 交互菜单

```
╔══════════════════════════════════════════╗
║  WarpGo v2.0.1                           ║
╚══════════════════════════════════════════╝

  系统: debian 13 (linux/amd64)
  接入: Zero Trust Proxy  组织: your-team | 端口: 40000

  ✓ Zero Trust Proxy: 已连接
    运行模式: WarpProxy on port 40000
    代理地址: socks5://127.0.0.1:40000 (本地)
    外部地址: socks5://<VPS_IP>:40000
    透明代理: 已开启 (VPS 流量走 WARP)

  1 | 连接/断开 Zero Trust
  t | 切换透明代理
  u | 完全卸载
  i | 刷新状态
  0 | 退出程序
```

## 透明代理说明

开启透明代理后，VPS 所有 TCP 流量通过 iptables/nftables → redsocks → warp-cli SOCKS5 → Cloudflare：

```bash
# 验证出口 IP（应显示 Cloudflare IP）
curl -4 ip.gs

# 验证 WARP 状态
curl -4 https://www.cloudflare.com/cdn-cgi/trace
```

**流量路径：**
```
VPS 应用 → iptables REDIRECT → redsocks (12345) → warp-cli (40000) → Cloudflare → 目标网站
```

## 状态说明

`curl https://www.cloudflare.com/cdn-cgi/trace` 返回值含义：

| 参数 | 值 | 含义 |
|------|-----|------|
| `warp=off` | 未连接 | WARP 隧道未建立 |
| `warp=on` | 已连接 | 普通 WARP 模式 |
| `warp=plus` | 已连接 | Zero Trust 注册 / WARP+ |
| `gateway=off` | 未过滤 | Gateway 策略未生效 |
| `gateway=on` | 已过滤 | Gateway 策略生效中 |

**关于 `gateway=off`：**

Proxy 模式下 `gateway=off` 是**正常状态**。Gateway 需要接管设备 DNS 或全部流量才能执行过滤策略，而 Proxy 模式只提供 SOCKS5 代理出口，不接管设备流量，所以 Gateway 无法介入。

| 模式 | warp= | gateway= | 用途 |
|------|-------|----------|------|
| Proxy 模式 | plus | off | 改 IP + SOCKS5 代理 |
| 全隧道模式 | plus | on | 全流量过滤 + 改 IP |

## 命令行参数

```
-v    显示版本信息
-4    安装 IPv4 WARP（WireGuard）
-6    安装 IPv6 WARP（WireGuard）
-d    安装双栈 WARP（WireGuard）
-z    配置 Zero Trust Proxy（warp-cli proxy + socat 反代）
-w    配置 Zero Trust（WireGuard，需要环境变量）
-u    完全卸载所有组件
```

## 卸载

```bash
./warpgo -u
```

卸载流程：
1. 停止所有 WARP 相关服务
2. 清理 iptables/nftables 规则
3. 删除配置文件
4. 卸载 cloudflare-warp、wireguard-tools、redsocks 包
5. 恢复 DNS 配置
6. 验证网络连通性

## SSH 安全保障

整个安装/运行/卸载过程中 SSH 连接不会中断：

| 阶段 | 保护机制 |
|------|----------|
| 安装时 | 先设置 split tunnel exclude 再连接 |
| 运行时 | VPS 出口 IP 加入 WARP exclude 列表（持久化） |
| 重启后 | warpgo-autoconnect.service 自动重新添加 exclude |
| 卸载时 | 停止 WARP → 恢复原始路由 → 验证连通性 |

## 系统要求

- Linux（amd64 / arm64）
- Debian 11+ / Ubuntu 20.04+
- root 权限
- 依赖：curl、jq、socat（自动安装）

## License

MIT

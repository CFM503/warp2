# WarpGo v2.0.1

一键部署 Cloudflare WARP / Zero Trust Proxy，让 VPS 通过 WARP 隧道改变出口 IP。

## 功能特性

- **WireGuard 模式** — 全局接管 VPS 网络流量
- **Zero Trust Proxy 模式** — SOCKS5 代理 + socat 反代 + 透明代理
- **SSH 保护** — 安装/运行全程保障 SSH 不中断
- **兼容 Debian 9-13** — 自动适配 nftables / iptables

## 快速开始

```bash
# 下载
wget https://github.com/CFM503/warp2/releases/download/v2.0.1/warpgo-linux-amd64
chmod +x warpgo-linux-amd64

# 运行交互菜单
./warpgo-linux-amd64
```

## 系统要求

- Linux（amd64 / arm64）
- Debian 9+ / Ubuntu 18.04+ / CentOS 7+
- root 权限
- 依赖：curl、jq（自动安装）
- 菜单 1/3 需要 WireGuard 内核模块（Debian 11+ 自带，旧版自动回退 wireguard-go）

---

## Cloudflare 前期准备

三种安装模式对 Cloudflare 账户的要求不同：

| 模式 | 需要 Cloudflare 账户？ | 需要 Zero Trust？ | 需要手动获取 Key？ |
|------|:---:|:---:|:---:|
| 菜单 1：WARP（WireGuard） | ❌ 不需要 | ❌ | ❌ 不需要，全自动 |
| 菜单 2：Zero Trust Proxy | ✅ 需要 | ✅ 需要创建 | ✅ 需要 Service Token |
| 菜单 3：Zero Trust（WireGuard） | ✅ 需要 | ✅ 需要创建 | ✅ 需要 Service Token |

---

### 菜单 1：WARP（WireGuard）— 无需任何准备

菜单 1 不需要 Cloudflare 账户，程序自动注册一个免费的 Cloudflare WARP 账号并生成 WireGuard 配置。直接运行即可。

---

### 菜单 2 和菜单 3 共同的准备工作

菜单 2 和菜单 3 都需要以下两样东西：

| 需要获取的内容 | 说明 | 示例 |
|---|---|---|
| **组织名称** (Team Name) | 你在 Cloudflare Zero Trust 中创建的组织名 | `mycompany` |
| **Service Token** | 由 Client ID + Client Secret 组成的一对密钥 | `Client ID: 1234abcd...` `Client Secret: 5678efgh...` |

以下是详细的获取步骤：

#### 第一步：注册 Cloudflare 账户

1. 打开 https://dash.cloudflare.com 注册（已有账号直接登录）
2. Cloudflare 免费计划即可，不需要绑定信用卡

#### 第二步：创建 Zero Trust 组织

1. 登录后，访问 https://one.dash.cloudflare.com
2. 首次进入会提示创建组织，选择 **免费计划**（Free Plan，支持最多 50 个用户）
3. 输入一个 **组织名称**（Team Name），例如 `mycompany`
   - 这个名称会变成你的组织域名：`mycompany.cloudflareaccess.com`
   - 只能用小写字母、数字和连字符，不能有空格或中文
   - **记下这个名称，后面要用**
4. 按提示完成创建（可能需要验证邮箱）

#### 第三步：获取设备注册密钥（Device enrollment 配置）

这一步的目的是确认组织名称是否正确，同时为后续步骤做准备。

1. 在 https://one.dash.cloudflare.com 左侧菜单找到：
   ```
   Settings → WARP Client → Device enrollment
   ```
2. 在 **Device enrollment permissions** 页面，你可以看到当前的注册策略
3. 确认你的组织名称显示在页面顶部
   - 如果需要修改注册策略（例如允许特定邮箱注册），可以在这里配置
   - 对于菜单 2 和菜单 3，我们使用 Service Token 认证，不依赖这里的邮箱策略

#### 第四步：创建 Service Token（关键步骤）

Service Token 是菜单 2 和菜单 3 必须的认证凭据。创建步骤如下：

1. 在 https://one.dash.cloudflare.com 左侧菜单找到：
   ```
   Access → Service Auth → Service Tokens
   ```

   > **注意：** 不同版本的 Cloudflare Dashboard 菜单路径可能略有不同，也可能是：
   > `Access → Service credentials → Service Tokens`

2. 点击 **Create Service Token** 按钮

3. 填写表单：
   - **Token name**：给 Token 起个名字，例如 `warpgo-vps`（方便日后识别）
   - **Duration**：Token 有效期，选择 `Non-expiring`（永不过期）或选择一个较长的时间

4. 点击 **Next** / **Generate token**

5. 页面会显示生成的 Token 信息：
   ```
   Client ID:     1234567890abcdef1234567890abcdef.access
   Client Secret: 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
   ```
   - **Client ID** 通常以 `.access` 结尾
   - **Client Secret** 是一长串随机字符串

6. ⚠️ **务必立即复制保存！** 页面关闭后 Client Secret 将无法再次查看，只能重新生成

   建议保存格式：
   ```
   组织名称: mycompany
   Client ID: 1234567890abcdef1234567890abcdef.access
   Client Secret: 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
   ```

#### 第五步：配置 Access Application（Service Token 授权）

创建 Service Token 后，还需要配置一条 Access Policy 让它能用于 WARP 设备注册：

1. 在 https://one.dash.cloudflare.com 左侧菜单找到：
   ```
   Access → Applications
   ```

2. 点击 **Add an application**，选择 **Self-hosted**

3. 填写应用信息：
   - **Application name**：`warp-enroll`（或任意名称）
   - **Session duration**：随意
   - **Application domain**：
     - 填入 `your-team.cloudflareaccess.com`（将 `your-team` 替换为你的实际组织名称）
     - 或填入 `dash.cloudflare.com`（如果上面的不行）

4. 在 **Identity providers** 页面，直接点 Next（不需要选择）

5. 在 **Policy** 页面：
   - **Policy name**：`allow-service-token`（或任意名称）
   - **Action**：选择 `Service Auth`
   - **Include** 规则选择：`Service Token`
   - 在出现的下拉框中选择你刚才创建的 Token 名称（如 `warpgo-vps`）

6. 点击 **Next** → **Add application** 完成创建

> ⚠️ **这一步非常关键！** 如果只创建了 Service Token 但没有配置 Access Application 和 Policy，程序会报错 `ZT 注册成功但未关联到组织`。

---

### 菜单 2：Zero Trust Proxy — 安装步骤

完成上述准备工作后，运行程序选择菜单 2，依次输入：

| 输入项 | 来源 | 示例 |
|---|---|---|
| 组织名称 | 第二步创建的 Team Name | `mycompany` |
| Client ID | 第四步生成的 Token | `1234567890abcdef...access` |
| Client Secret | 第四步生成的 Token | `abcdef1234567890...` |
| 外部代理端口 | 自定义或留空用默认值 | 默认 `40000` |

**安装完成后提供三种使用方式：**

| 方式 | 说明 | 命令 |
|------|------|------|
| SOCKS5 代理 | 外部设备通过 VPS 代理上网 | 浏览器设置 `socks5://VPS_IP:40000` |
| 透明代理 | VPS 自身所有流量走 WARP | 菜单选 `t` 开启 |
| 直接验证 | 通过代理验证出口 IP | `curl --proxy socks5://127.0.0.1:40000 -4 ip.gs` |

**命令行方式（跳过交互菜单）：**
```bash
./warpgo -z
# 会依次提示输入上述信息
```

---

### 菜单 3：Zero Trust（WireGuard）— 安装步骤

完成上述准备工作后，运行程序选择菜单 3，依次输入：

| 输入项 | 来源 | 示例 |
|---|---|---|
| 组织名称 | 第二步创建的 Team Name | `mycompany` |
| Client ID | 第四步生成的 Token | `1234567890abcdef...access` |
| Client Secret | 第四步生成的 Token | `abcdef1234567890...` |
| 优选 IP | 可选，留空使用默认值 | `162.159.192.2:2408` |

**命令行方式（通过环境变量传入）：**
```bash
WARP_ORG=mycompany \
WARP_CLIENT_ID=1234567890abcdef.access \
WARP_CLIENT_SECRET=abcdef1234567890... \
./warpgo -w
```

**优选 IP 说明：**

可填入 Cloudflare WARP 优选 IP，留空则使用默认值。常用参数：
- 端口：`2408`、`500`、`1701`、`4500`
- 优选段：`162.159.192.0/24`、`162.159.204.0/24`
- 格式：`IP:端口`，例如 `162.159.192.2:2408`

---

### 常见问题排查

#### "ZT 注册成功但未关联到组织"

原因：Service Token 没有 WARP enrollment 权限。

解决：回到第五步，确认已创建 Access Application 并将 Service Token 加入 Policy。

#### "注册超时（30秒）"

可能原因：
1. 组织名称拼写错误（不含 `.cloudflareaccess.com` 后缀，只填 Team Name 部分）
2. Client ID 或 Client Secret 复制不完整（注意前后不要有空格）
3. Service Token 已过期或被删除

#### "warp-cli: command not found"

原因：Cloudflare WARP 客户端安装失败。

解决：检查 VPS 是否在 Cloudflare WARP 支持的发行版列表中（Debian 10+、Ubuntu 20.04+）。

#### Service Token 的 Client ID 和 Client Secret 在哪看？

创建后只显示一次。如果丢失，需要在：
```
Access → Service Auth → Service Tokens
```
找到对应 Token，点击 **Revoke** 后重新创建。

---

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
| 菜单 2 Proxy 模式 | plus | off（固定） | 改 IP + SOCKS5 代理 |
| 菜单 3 WireGuard 模式 | plus | 取决于 Dashboard 配置 | 全流量接入 Zero Trust |

## Gateway 过滤层说明

Gateway 是 Zero Trust 的安全策略引擎，在流量到达目标网站之前进行检查和过滤。

### 过滤层级

```
DNS 请求  →  [Gateway DNS 策略]  →  放行 / 拦截
HTTP 请求 →  [Gateway HTTP 策略] →  放行 / 拦截 / 改写
TCP/UDP   →  [Gateway 网络策略]  →  放行 / 拦截
```

### 能做什么

| 功能 | 说明 |
|------|------|
| 屏蔽恶意网站 | 自动拦截钓鱼、恶意软件域名 |
| 屏蔽广告 | 按域名/分类拦截广告追踪器 |
| 内容过滤 | 屏蔽特定类别（赌博、成人、社交等） |
| 域名黑白名单 | 只允许访问特定网站，或屏蔽特定网站 |
| DLP 数据防泄漏 | 阻止敏感数据（信用卡号、身份证号）外传 |
| 文件扫描 | 检测上传/下载文件中的恶意内容 |
| 日志审计 | 记录所有 DNS/HTTP 请求，事后追溯 |

### 菜单 2 vs 菜单 3 的 Gateway 行为

```
菜单 2（Proxy 模式）：
  VPS → WARP 隧道（加密）→ 互联网
       ↓
    没有 Gateway 检查，纯粹改 IP + 加密
    gateway=off 是固定状态，无法开启

菜单 3（WireGuard 全隧道）：
  VPS → WARP 隧道 → Gateway 策略引擎 → 互联网
                          ↓
                   检查每个请求：恶意域名？敏感数据？违规内容？
    gateway=on/off 取决于 Zero Trust Dashboard 是否配置了策略
```

### VPS 场景下要不要开 Gateway

| 场景 | 建议 |
|------|------|
| 只想改 IP | 不需要，用菜单 2（gateway=off） |
| VPS 跑爬虫/代理 | 不需要，反而可能误拦截 |
| VPS 跑企业应用 | 可以用菜单 3 开 Gateway，防数据泄露 + 审计 |
| VPS 做反代给团队用 | 值得开，可以过滤恶意请求保护用户 |
| VPS 做 API 网关 | 可以开，限流 + 防滥用 |

### 结论

Gateway 的核心价值是**在 WARP 隧道加密之上再加一层策略过滤**。对大多数改 IP 的用法，`gateway=off` 完全够用，开了反而可能影响代理的兼容性。需要安全过滤能力时，使用菜单 3 并在 Dashboard 配置 Gateway 策略。

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

| 阶段 | 菜单 1/3（WireGuard）保护机制 | 菜单 2（Proxy）保护机制 |
|------|------|------|
| 安装时 | PreUp 捕获原始 IP → PostUp 添加 ip rule + nft 豁免 | 先设置 split tunnel exclude 再 connect |
| 运行时 | SSH 回包不被 nft 标记，走原始路由出站 | VPS 出口 IP 在 WARP exclude 列表（持久化） |
| 重启后 | wg-quick 自动加载含保护规则的配置 | warpgo-autoconnect.service 自动重新添加 exclude |
| 卸载时 | 停止 WARP → 删除 nft 表 → 清理 ip 规则 → 验证连通性 | 停止 warp-cli → 清理规则 → 验证连通性 |

## License

MIT

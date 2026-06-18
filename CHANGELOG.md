# WarpGo 修改日志

## v2.0.4 (2026-06-18) - 清理与修复

### 🐛 Bug 修复

#### 1. stdin 缓冲区丢失 - 交互式菜单输入错乱

**问题描述**：
- 交互式菜单中，子菜单读取不到用户输入，反复提示"无效选项"
- 通过管道输入（`printf "2\n1\n..." | warpgo`）时，第一个菜单读取正确，后续菜单读取空字符串

**原因分析**：
- `readInput()` 每次调用都创建新的 `bufio.NewReader(os.Stdin)`
- `bufio.NewReader` 有内部缓冲区（默认 4096 字节），首次创建时会预读一批数据
- 第二次创建的 reader 无法读取已被前一个 reader 缓冲的数据，导致丢失

**修复方案**：
```go
// 全局 stdin reader（避免每次 readInput 创建新 bufio.Reader 导致缓冲区丢失）
var stdinReader = bufio.NewReader(os.Stdin)

func readInput(prompt string) string {
	fmt.Printf("  %s%s%s ", colorCyan, prompt, colorReset)
	input, _ := stdinReader.ReadString('\n')
	return strings.TrimSpace(input)
}
```

**修改函数**：
- `readInput()` - 改用全局 `stdinReader`

---

#### 2. 反代端口冲突 - socat 绑定失败

**问题描述**：
- Zero Trust Proxy 安装后，反代服务 `warpgo-reverse-proxy` 启动失败
- 日志报错：`bind(5, {AF=2 0.0.0.0:40000}, 16): Address already in use`

**原因分析**：
- warp-svc 的 SOCKS5 代理监听在 `127.0.0.1:40000`
- socat 反代尝试绑定 `0.0.0.0:40000`（同一端口），产生冲突
- 默认外部端口和 SOCKS5 端口都是 40000

**修复方案**：
```go
func setupExternalProxy(externalPort int) {
	if externalPort <= 0 || externalPort > 65535 {
		externalPort = defaultSocks5Port + 1  // 改为 40001
	}
	// 避免与 warp-svc 的 SOCKS5 端口冲突
	if externalPort == defaultSocks5Port {
		externalPort = defaultSocks5Port + 1
	}
	// ... socat 绑定 0.0.0.0:40001 → 127.0.0.1:40000
}
```

**同步修改**：
- `installZeroTrustMode()` - 默认 extPort 改为 `defaultSocks5Port + 1`
- `installZeroTrustMenu()` - 菜单默认端口提示改为 40001
- 主菜单外部地址显示 - 默认回退改为 `defaultSocks5Port + 1`

**修改函数**：
- `setupExternalProxy()` - 端口冲突检测
- `installZeroTrustMode()` - 默认端口
- `installZeroTrustMenu()` - 默认端口提示
- 主菜单显示逻辑 - 外部地址默认端口

---

#### 3. enrollServiceToken 覆盖 ExternalPort - 配置丢失

**问题描述**：
- 菜单2安装时用户输入外部端口 40001，但安装完成后显示 40000
- `enrollServiceToken()` 重新保存 ZT 配置时，`ExternalPort` 字段被重置为 0

**原因分析**：
- `installZeroTrustMenu()` 先保存配置（含 ExternalPort=40001）
- `doInstall()` → `installZeroTrustMode()` → `enrollServiceToken()` 再次保存配置（无 ExternalPort）
- 后者覆盖了前者，ExternalPort 丢失

**修复方案**：
```go
// enrollServiceToken 中，更新已有配置而非覆盖
if existingCfg, err := loadZTConfig(); err == nil {
	existingCfg.OrgName = orgName
	existingCfg.ClientID = clientID
	existingCfg.ClientSecret = clientSecret
	existingCfg.UseProxyMode = true
	existingCfg.Socks5Port = defaultSocks5Port
	saveZTConfig(existingCfg)
} else {
	// 首次保存
	saveZTConfig(&ZeroTrustConfig{...})
}
```

**修改函数**：
- `enrollServiceToken()` - 保留已有配置字段

---

#### 4. 透明代理缺少 iptables 安装 - 依赖缺失

**问题描述**：
- 在新 VPS 上开启透明代理失败，`iptables` 命令不存在
- Debian 13 默认只有 nftables，无 iptables 二进制

**修复方案**：
```go
func setupTransparentProxy(socks5Port int) {
	exec.Command("apt-get", "install", "-y", "redsocks").Run()
	// 确保 iptables 已安装（透明代理依赖）
	if _, err := exec.LookPath("iptables"); err != nil {
		uiInfo("安装 iptables...")
		exec.Command("apt-get", "install", "-y", "iptables").Run()
	}
	// ...
}
```

**修改函数**：
- `setupTransparentProxy()` - 添加 iptables 安装

---

#### 5. Zero Trust WireGuard 注册失败 - API 不处理 CF-Access headers

**问题描述**：
- 菜单3（Zero Trust WireGuard）注册时，`api.cloudflareclient.com/v0a2158/reg` 忽略 CF-Access headers
- 发送真实 Curve25519 公钥 + CF-Access headers，API 不返回 WireGuard 账号

**原因分析**：
- `api.cloudflareclient.com` 官方 API 不支持 CF-Access 认证
- 参考 warpGO 项目发现：第三方代理 URL `warp.cloudflare.nyc.mn/?run=register` 接受 ZT 凭据
- 代理 URL 将 ZT 凭据放在请求 body 中（`organization`, `auth_client_id`, `auth_client_secret`），返回完整 WireGuard 账号

**修复方案**：
```go
func registerWARPZeroTrust(team *teamRegistration) (*Account, error) {
	payload := fmt.Sprintf(`{
		"key": "",
		"organization": "%s",
		"auth_client_id": "%s",
		"auth_client_secret": "%s",
		"tos": "%s",
		"model": "Android",
		"app_name": "1.1.1.1",
		"app_version": "6.10",
		"partner_id": "warp-go"
	}`, team.orgName, team.clientID, team.clientSecret, ...)

	req, _ := http.NewRequest("POST", warpRegisterURL, strings.NewReader(payload))
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("CF-Client-Version", "a-6.10-2158")
	// ...
}
```

**修改函数**：
- `registerWARPZeroTrust()` - 完全重写，使用代理 URL

---

#### 6. saveToFile 目录不存在 - 写入失败

**问题描述**：
- 新 VPS 上 `/etc/wireguard/` 目录不存在，`saveToFile()` 失败

**修复方案**：
```go
func (a *Account) saveToFile(path string) error {
	os.MkdirAll("/etc/wireguard", 0700)  // 新增
	return os.WriteFile(path, data, 0600)
}
```

**修改函数**：
- `saveToFile()` - 添加目录创建

---

#### 7. protectSSHForZT CIDR 格式错误 - warp-cli 拒绝

**问题描述**：
- `warp-cli tunnel ip add 192.3.152.210/32` 失败
- 错误：`invalid value '192.3.152.210/32' for '<ADDRESS>': invalid IP address syntax`

**修复方案**：
```go
// 旧代码
exec.Command("warp-cli", "--accept-tos", "tunnel", "ip", "add", vpsIP+"/32")
// 新代码
exec.Command("warp-cli", "--accept-tos", "tunnel", "ip", "add", vpsIP)
```

**修改函数**：
- `protectSSHForZT()` - 移除 `/32` 后缀

---

#### 8. WireGuard IPv4 握手失败 - VPS UDP 出站受限

**问题描述**：
- VPS IPv4 网络无法完成 WireGuard 握手（UDP 出站被封或限速）
- 仅 IPv4 endpoint `162.159.192.1:2408` 无法连接

**修复方案**：
- 在 `verifyConnectionWithFallback()` 中添加 IPv6 endpoint `2606:4700:d0::a`
- IPv6 通道通常不受 IPv4 UDP 限制

**修改函数**：
- `verifyConnectionWithFallback()` - 添加 IPv6 fallback endpoint

---

### 📝 修改文件清单

| 文件 | 函数 | 修改类型 |
|------|------|----------|
| `warp2.go` | `readInput()` | 重写 - 全局 stdin reader |
| `warp2.go` | `setupExternalProxy()` | 修复 - 端口冲突检测 |
| `warp2.go` | `installZeroTrustMode()` | 修复 - 默认端口 |
| `warp2.go` | `installZeroTrustMenu()` | 修复 - 默认端口提示 |
| `warp2.go` | `enrollServiceToken()` | 修复 - 保留已有配置 |
| `warp2.go` | `setupTransparentProxy()` | 修复 - 添加 iptables 安装 |
| `warp2.go` | `registerWARPZeroTrust()` | 重写 - 使用代理 URL |
| `warp2.go` | `saveToFile()` | 修复 - 添加目录创建 |
| `warp2.go` | `protectSSHForZT()` | 修复 - 移除 CIDR 后缀 |
| `warp2.go` | `verifyConnectionWithFallback()` | 修复 - 添加 IPv6 endpoint |
| `warp2.go` | 主菜单显示逻辑 | 修复 - 外部地址默认端口 |

---

### 🧪 测试验证

**测试环境**：
- VPS: 192.3.152.210 (Debian 13, Linux 6.12.41+)
- Go: 1.26.0 (交叉编译 linux/amd64)

**菜单2 (Zero Trust Proxy) 测试**：
- ✅ 安装流程 7 步全部成功（warp-cli 安装 → SSH 保护 → 注册 → 自启 → 连接 → 反代）
- ✅ 连接/断开切换正常
- ✅ 透明代理 IP 变化验证（192.3.152.210 → 104.28.154.33 warp=plus）
- ✅ 刷新状态、帮助显示正确
- ✅ 卸载清理完整（warp-cli 删除、配置清理、IP 恢复）
- ✅ 交互式菜单输入流程正确

**菜单3 (Zero Trust WireGuard) 测试**：
- ✅ 注册成功（Team: icoco，通过代理 URL）
- ✅ WireGuard 接口启动、握手完成
- ✅ warp=on 确认，IPv4 变为 Cloudflare IP (104.28.213.36)
- ✅ SSH 保持连接

---

## v2.0.3 (2026-06-17)

### 🐛 Bug 修复

#### 1. SSH 保护机制重写 - 解决 WARP 安装后断联问题

**问题描述**：
- 安装 WARP (WireGuard) 后，VPS SSH 连接立即断开
- 原因：wg-quick 创建 WireGuard 接口时立即接管路由，PostUp 中的 SSH 保护来不及生效
- wg-quick 在 PostUp 执行完毕后才添加 `suppress_prefixlength 0` 规则（优先级 1），覆盖了 PostUp 中添加的 SSH 保护规则

**原方案（失败）**：
```go
// PostUp 中添加 ip rule（优先级 10）
ip -4 rule add from "192.3.152.210" table main priority 10

// 问题：wg-quick 后续添加的规则优先级更高（1），覆盖了 SSH 保护
```

**新方案（成功）**：
```go
// PreUp 中添加 ip rule（优先级 0，最高优先级）
// 在接口创建前生效，wg-quick 无法覆盖
ip -4 rule add from "192.3.152.210" table main priority 0
```

**技术细节**：
- PreUp 时机：接口未建立，路由规则未变，是添加保护规则的最佳时机
- 优先级 0 > 优先级 1（wg-quick 的 suppress_prefixlength 0 规则）
- SSH 流量匹配 `from 192.3.152.210 lookup main` 规则，从原始网关出站

**修改函数**：
- `globalPreUpScript()` - 添加 SSH 保护规则
- `globalPostUpScript()` - 简化为 `true`（SSH 保护已在 PreUp 完成）
- `globalPostDownScript()` - 清理 PreUp 添加的规则

---

#### 2. 账号文件保存缺失 - 导致 WARP 握手失败

**问题描述**：
- WARP 注册成功后，账号信息未保存到 `/etc/wireguard/warp-account.conf`
- 导致 WireGuard 接口无法完成握手（缺少 PrivateKey）

**原因分析**：
- `registerWARPPlainOfficial()` 构造账号后直接返回，未调用 `saveToFile()`
- `parseWARPAccount()` 中有保存逻辑，但仅在代理注册路径中调用
- Zero Trust 注册路径有显式保存，但普通注册路径缺失

**修复方案**：
```go
// installWireGuardMode() 中，注册成功后显式保存账号
account, err := registerWARP(nil)
if err := account.saveToFile(warpAccountPath); err != nil {
    return fmt.Errorf("保存账号信息失败: %v", err)
}
```

**修改函数**：
- `installWireGuardMode()` - 添加账号文件保存

---

#### 3. 卸载清理不完整 - 残留 ip rule 和临时文件

**问题描述**：
- 卸载后残留 SSH 保护规则（priority 0）
- `/run/warp-ssh` 临时目录未清理
- `warpgo-autoconnect.service` 服务文件未清理

**修复方案**：
```go
// cleanupNetworkRules() 中更新规则清理逻辑
// 旧代码：查找 priority 10 规则（已不存在）
// 新代码：查找 priority 0 规则（SSH 保护）

// 新增清理
exec.Command("ip", "rule", "del", "table", "main", "suppress_prefixlength", "0").Run()
os.RemoveAll("/run/warp-ssh")
```

**修改函数**：
- `cleanupNetworkRules()` - 更新规则清理逻辑，添加临时目录清理
- `cleanupConfigFiles()` - 添加 `warpgo-autoconnect.service` 清理

---

### 📝 修改文件清单

| 文件 | 函数 | 修改类型 |
|------|------|----------|
| `warp2.go` | `globalPreUpScript()` | 重写 - 添加 SSH 保护规则 |
| `warp2.go` | `globalPostUpScript()` | 简化 - 移除冗余逻辑 |
| `warp2.go` | `globalPostDownScript()` | 更新 - 清理 PreUp 规则 |
| `warp2.go` | `installWireGuardMode()` | 修复 - 添加账号保存 |

---

### 🧪 测试验证

**测试环境**：
- VPS: 192.3.152.210 (Debian 13, Linux 6.12.41+)
- Go: 1.26.0
- WireGuard: 1.0.20210914-3

**测试步骤**：
1. `warpgo -u` 卸载旧版本
2. `warpgo -4` 安装 IPv4 WARP
3. 验证 SSH 连接未断开
4. 验证账号文件已保存
5. 验证 IP 规则正确

**测试结果**：
- ✅ SSH 连接全程保持（多次 WireGuard 接口启停）
- ✅ 账号文件 `/etc/wireguard/warp-account.conf` 正确保存
- ✅ IP 规则 `from 192.3.152.210 lookup main` 优先级 0
- ⚠️ WARP 握手失败（VPS UDP 出站可能被封，非代码问题）

---

### 🔧 技术笔记

#### wg-quick 规则执行顺序

```
1. PreUp          ← 接口创建前执行（SSH 保护在这里添加）
2. ip link add    ← 创建 WireGuard 接口
3. ip addr add    ← 添加地址
4. ip route add   ← 添加路由
5. ip rule add    ← wg-quick 添加自己的规则
6. nft -f         ← 添加 nft 规则
7. PostUp         ← 接口创建后执行
```

#### ip rule 优先级

```
0:  from all lookup local                    ← 最高优先级
0:  from 192.3.152.210 lookup main           ← SSH 保护（我们的规则）
0:  not from all fwmark 0xca6c lookup 51820  ← wg-quick 规则
0:  from all lookup main suppress_prefixlength 0  ← wg-quick 规则
32766: from all lookup main                  ← 默认规则
32767: from all lookup default               ← 默认规则
```

#### 为什么 PostUp 方案失败

wg-quick 在 PostUp 执行完毕后，才添加 `suppress_prefixlength 0` 规则。即使 PostUp 中添加了优先级 0 的规则，也会被 wg-quick 后续添加的规则覆盖。

**时序问题**：
```
PostUp: ip rule add from 192.3.152.210 table main priority 0  ← 添加成功
wg-quick: ip rule add table main suppress_prefixlength 0      ← 覆盖了我们的规则
```

**解决方案**：在 PreUp 中添加规则，此时 wg-quick 还未开始添加自己的规则。

---

## v2.0.2 (2026-06-17)

### 初始版本

- 基础 WARP WireGuard 安装功能
- Zero Trust Proxy 模式支持
- 多端点自动切换
- 诊断工具

---

## 后续计划

- [x] 测试 Zero Trust Proxy 模式（菜单 2）— 2026-06-18 完成
- [x] 测试 Zero Trust WireGuard 模式（菜单 3）— 2026-06-18 完成
- [x] 测试优选 IP 功能（菜单 e）— 菜单1已测试
- [x] 验证开机自启服务 — warp-svc 已验证
- [ ] 优化 WARP 握手超时逻辑

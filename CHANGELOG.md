# WarpGo 修改日志

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

- [ ] 测试 Zero Trust Proxy 模式（菜单 2）
- [ ] 测试双栈模式（菜单 3）
- [ ] 测试优选 IP 功能（菜单 e）
- [ ] 验证开机自启服务
- [ ] 优化 WARP 握手超时逻辑

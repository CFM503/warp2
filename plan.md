# Plan: Zero Trust Proxy 模式改造 + Bug 修复

## Context

当前"菜单2"（Zero Trust warp-cli）使用 warp-cli 的默认模式（full tunnel），会接管 VPS 全部流量。
用户需求：**只能使用 proxy 模式接入**，warp-cli 以 SOCKS5 本地代理运行，再通过反代（socat）暴露给外部设备使用。
同时修复代码中发现的 bug。

## Bug 清单

1. **MDM XML 缺少 proxy 模式参数** — `enrollServiceToken()` 生成的 mdm.xml 没有 `service_mode` 和 `proxy_port`，导致 warp-cli 以默认 full tunnel 模式运行
2. **默认端口不一致** — 常量 `defaultSocks5Port = 40001`，但 warp-cli proxy 模式默认端口是 `40000`，MDM 中也没有指定端口
3. **红袜子代理是多余的** — proxy 模式下 warp-cli 本身就是 SOCKS5 代理，不需要 redsocks 做二次转换
4. **重连后恢复逻辑错误** — `ztConnect()` 恢复透明代理时调用 `setupTransparentProxy()`，但 proxy 模式不需要 redsocks/iptables
5. **代理端口配置不一致** — `saveTransparentProxyConfig()` 使用 `defaultSocks5Port` 但没有和 MDM 中的端口同步

## 修改方案

### 1. 扩展 ZeroTrustConfig 结构体

```go
type ZeroTrustConfig struct {
    OrgName          string `json:"org_name"`
    ClientID         string `json:"client_id"`
    ClientSecret     string `json:"client_secret"`
    ProxyEnabled     bool   `json:"proxy_enabled"`
    Socks5Port       int    `json:"socks5_port"`
    ExternalPort     int    `json:"external_port"`      // 新增：外部反代端口
    UseProxyMode     bool   `json:"use_proxy_mode"`     // 新增：是否使用 proxy 模式
}
```

### 2. 修复 MDM XML 生成 — `enrollServiceToken()`

在 mdm.xml 中加入 `service_mode=proxy` 和 `proxy_port`：

```xml
<dict>
  <key>organization</key>
  <string>%s</string>
  <key>auth_client_id</key>
  <string>%s</string>
  <key>auth_client_secret</key>
  <string>%s</string>
  <key>service_mode</key>
  <string>proxy</string>
  <key>proxy_port</key>
  <integer>40000</integer>
</dict>
```

### 3. 修改安装流程 — `installZeroTrustMode()`

安装步骤改为：
1. 安装系统依赖
2. 安装 warp-cli
3. 注册 Zero Trust（含 proxy 模式 MDM）
4. 配置 SSH 保护 & 开机自启
5. 连接 Zero Trust（proxy 模式）
6. 设置反代（socat，可选外部端口）
7. 验证连接

### 4. 新增反代功能 — socat 转发

新增函数 `setupExternalProxy(externalPort int)`：
- 用 socat 将外部 TCP 端口转发到 localhost:40000（warp-cli SOCKS5）
- 创建 systemd 服务 `warpgo-reverse-proxy.service`
- 支持自定义外部端口（默认 40000）

新增函数 `cleanupExternalProxy()`：停止并删除 socat 服务。

### 5. 修改连接/断开逻辑

- `ztConnect()` — proxy 模式下不需要恢复 redsocks/iptables，只需检查 socat 服务
- `ztDisconnect()` — 清理 socat 反代服务，不清理 redsocks
- `shouldRestoreTransparentProxy()` — 改为检查 proxy 模式配置

### 6. 修改菜单

主菜单选项2改为：`"配置 Zero Trust Proxy"` — 描述改为 `"proxy 模式接入，SOCKS5 代理 + 反代"`

`installZeroTrustMenu()` 增加交互：
- 提示用户输入外部代理端口（默认 40000，留空使用默认值）
- 显示最终代理地址 `socks5://<VPS_IP>:<端口>`

### 7. 修改开机自启 — `setupWarpAutoConnect()`

proxy 模式下，自启服务不需要设置 exclude 列表（proxy 模式不接管路由），只需：
1. 等待 warp-svc 就绪
2. warp-cli connect
3. 等待连接成功
4. 启动 socat 反代服务

### 8. 状态面板显示

在主菜单状态面板中，Zero Trust proxy 模式时显示：
```
  ● Zero Trust Proxy: 已连接
    运行模式: WarpProxy on port 40000
    代理地址: socks5://<VPS_IP>:40000
```

## 涉及文件

- `warp2.go` — 唯一源文件，所有修改都在此

## 修改的函数清单

| 函数 | 操作 |
|------|------|
| `ZeroTrustConfig` 结构体 | 新增字段 |
| `enrollServiceToken()` | 修复 MDM XML |
| `installZeroTrustMode()` | 重写流程 |
| `ztConnect()` | 适配 proxy 模式 |
| `ztDisconnect()` | 适配 proxy 模式 |
| `shouldRestoreTransparentProxy()` | 改为 proxy 模式检查 |
| `setupExternalProxy()` | **新增** — socat 反代 |
| `cleanupExternalProxy()` | **新增** — 清理反代 |
| `installProxyService()` | 改为 proxy 模式服务 |
| `removeProxyService()` | 适配 |
| `setupWarpAutoConnect()` | 简化为 proxy 模式 |
| `installZeroTrustMenu()` | 增加端口输入 |
| `showMainMenu()` | 状态显示适配 |
| 常量 `defaultSocks5Port` | 改为 40000 |

## 验证

1. 编译：`go build -o warpgo warp2.go` 确认无语法错误
2. 功能检查：所有修改的函数逻辑完整性
3. 端口一致性：MDM、常量、配置、显示全部统一为 40000

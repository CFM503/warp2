package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ════════════════════════════════════════════════════════════════════════════════
// 常量与类型定义
// ════════════════════════════════════════════════════════════════════════════════

const (
	appVersion = "2.0.2"

	// Cloudflare WARP API
	warpRegisterURL    = "https://warp.cloudflare.nyc.mn/?run=register"
	warpCFAPIBase      = "https://api.cloudflareclient.com/v0a2158" // 官方 API（用于 ZT 注册）
	warpPublicKey      = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	warpEndpointV4     = "162.159.192.1:2408"

	// WireGuard 默认配置
	warpConfPath    = "/etc/wireguard/warp.conf"
	warpAccountPath = "/etc/wireguard/warp-account.conf"
	warpIfName      = "warp"
	warpDNS         = "1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001"
	defaultMTU      = 1280

	// Zero Trust
	zeroTrustConfigPath = "/etc/wireguard/zerotrust.conf"
	defaultSocks5Port   = 40000
	defaultRedsocksPort = 12345

	// 路径
	wireguardGoPath = "/usr/bin/wireguard-go"

	// Cloudflare WARP 客户端 APT 源
	warpClientRepoDebian = "https://pkg.cloudflareclient.com/pubkey.gpg"
	warpClientAptList    = "https://pkg.cloudflareclient.com"
)

// 安装模式
type installMode int

const (
	modeWireGuardV4   installMode = iota // WireGuard IPv4
	modeWireGuardV6                      // WireGuard IPv6
	modeWireGuardDual                    // WireGuard 双栈
	modeZeroTrust                        // Cloudflare Zero Trust (warp-cli)
	modeZeroTrustWG                      // Cloudflare Zero Trust (WireGuard)
)

// IP 栈类型
type stackMode int

const (
	stackIPv4 stackMode = iota
	stackIPv6
	stackDual
)

// Zero Trust 接入模式
type ztEnrollMode int

const (
	enrollModeServiceToken ztEnrollMode = iota // 非交互：Service Token
)

// SysInfo 系统信息
type SysInfo struct {
	OS         string
	Arch       string
	Distro     string
	Version    string
	Codename   string
	PkgManager string
}

func (s *SysInfo) String() string {
	return fmt.Sprintf("%s %s (%s/%s)", s.Distro, s.Version, s.OS, s.Arch)
}

// NetworkStatus 网络状态
type NetworkStatus struct {
	IPv4           string
	IPv6           string
	WarpEnabled    bool
	GatewayEnabled bool
	WarpIPv4       string
}

func (s *NetworkStatus) String() string {
	var parts []string
	if s.IPv4 != "" {
		label := fmt.Sprintf("IPv4: %s", s.IPv4)
		if s.WarpEnabled && s.WarpIPv4 == "" {
			label += " [WARP]"
		}
		parts = append(parts, label)
	}
	if s.WarpIPv4 != "" && s.WarpIPv4 != s.IPv4 {
		parts = append(parts, fmt.Sprintf("WARP IPv4: %s [WARP]", s.WarpIPv4))
	}
	if s.IPv6 != "" {
		parts = append(parts, fmt.Sprintf("IPv6: %s", s.IPv6))
	} else {
		parts = append(parts, "IPv6: 无")
	}
	return strings.Join(parts, "  |  ")
}

// MenuItem 菜单项
type MenuItem struct {
	Key         string
	Label       string
	Description string
}

// Account WARP 注册账号信息
type Account struct {
	ID         string `json:"id"`
	Token      string `json:"token"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	IPv4       string `json:"ipv4"`
	IPv6       string `json:"ipv6"`
	IsTeams    bool   `json:"is_teams"`
	OrgName    string `json:"org_name"`
}

// teamRegistration Zero Trust 团队注册参数
type teamRegistration struct {
	orgName      string
	clientID     string
	clientSecret string
}

// WgConfigOptions WireGuard 配置选项
type WgConfigOptions struct {
	Account  *Account
	Stack    stackMode
	Endpoint string
}

// WgConfigStatus WireGuard 配置状态
type WgConfigStatus struct {
	StackMode stackMode
}

// ZeroTrustStatus Zero Trust 连接状态
type ZeroTrustStatus struct {
	Connected bool
	Mode      string
}

// ZeroTrustConfig Zero Trust 配置
type ZeroTrustConfig struct {
	OrgName      string `json:"org_name"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	ProxyEnabled bool   `json:"proxy_enabled"`
	Socks5Port   int    `json:"socks5_port"`
	ExternalPort int    `json:"external_port"`  // 外部反代端口（socat 监听）
	UseProxyMode bool   `json:"use_proxy_mode"` // 是否使用 proxy 模式
}

// InstallOptions 安装配置选项
type InstallOptions struct {
	Mode     installMode
	Endpoint string

	ZeroTrustOrg          string
	ZeroTrustEnrollMode   ztEnrollMode
	ZeroTrustClientID     string
	ZeroTrustClientSecret string
}

// ════════════════════════════════════════════════════════════════════════════════
// 共享工具函数
// ════════════════════════════════════════════════════════════════════════════════

// getSSHPort 获取 SSH 端口（统一实现，消除原三处重复）
func getSSHPort() string {
	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return "22"
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Port ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return "22"
}

// checkWarpEnabled 检查 WARP 是否已激活（统一实现，消除原两处重复）
// getTraceStatus 从 Cloudflare trace 接口获取 warp 和 gateway 状态
func getTraceStatus() (warpOn, gatewayOn bool) {
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
	}
	resp, err := client.Get("https://www.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, false
	}
	content := string(body)
	warpOn = strings.Contains(content, "warp=on") || strings.Contains(content, "warp=plus")
	gatewayOn = strings.Contains(content, "gateway=on")
	return
}

func checkWarpEnabled() bool {
	warpOn, _ := getTraceStatus()
	return warpOn
}

// ════════════════════════════════════════════════════════════════════════════════
// UI 终端输出
// ════════════════════════════════════════════════════════════════════════════════

const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
	colorReset  = "\033[0m"
)

func uiHeader(title string) {
	fmt.Printf("\n%s%s══ %s ══%s\n", colorBold, colorCyan, title, colorReset)
}

func uiSeparator() {
	fmt.Printf("%s%s%s\n", colorGray, strings.Repeat("─", 50), colorReset)
}

func uiInfo(msg string) {
	fmt.Printf("  %s●%s %s\n", colorGreen, colorReset, msg)
}

func uiWarning(msg string) {
	fmt.Printf("  %s⚠%s %s\n", colorYellow, colorReset, msg)
}

func uiError(msg string) {
	fmt.Printf("  %s✗%s %s\n", colorRed, colorReset, msg)
	os.Exit(1)
}

func uiStep(current, total int, msg string) {
	fmt.Printf("  %s[%d/%d]%s %s\n", colorBlue, current, total, colorReset, msg)
}

func uiHint(msg string) {
	fmt.Printf("  %s%s%s\n", colorGray, msg, colorReset)
}

func uiBlank() {
	fmt.Println()
}

func printStatusPanel(ver, sysInfoStr, connectionType, connectionInfo, networkInfo string) {
	fmt.Println()
	fmt.Printf("  %s%s╔══════════════════════════════════════════╗%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("  %s%s║  WarpGo v%-33s║%s\n", colorBold, colorCyan, ver, colorReset)
	fmt.Printf("  %s%s╚══════════════════════════════════════════╝%s\n", colorBold, colorCyan, colorReset)
	fmt.Println()
	fmt.Printf("  %s系统%s: %s\n", colorGray, colorReset, sysInfoStr)
	if connectionType != "" {
		fmt.Printf("  %s接入%s: %s", colorGray, colorReset, connectionType)
		if connectionInfo != "" {
			fmt.Printf("  (%s)", connectionInfo)
		}
		fmt.Println()
	}
	if networkInfo != "" {
		fmt.Printf("  %s网络%s: %s\n", colorGray, colorReset, networkInfo)
	}
	fmt.Println()
}

func printStatusLine(label, status string, running bool) {
	if running {
		fmt.Printf("  %s✓%s %s: %s\n", colorGreen, colorReset, label, status)
	} else {
		fmt.Printf("  %s✗%s %s: %s\n", colorRed, colorReset, label, status)
	}
}

func printInfoLine(label, value string) {
	fmt.Printf("  %s%s%s: %s\n", colorGray, label, colorReset, value)
}

func showMenu(title string, items []MenuItem) string {
	uiSeparator()
	for _, item := range items {
		if item.Description != "" {
			fmt.Printf("  %s%s%s %s| %s %s %s— %s%s\n",
				colorBold, item.Key, colorReset,
				colorGray, colorReset,
				item.Label,
				colorGray, item.Description, colorReset)
		} else {
			fmt.Printf("  %s%s%s %s| %s %s\n",
				colorBold, item.Key, colorReset,
				colorGray, colorReset, item.Label)
		}
	}
	uiSeparator()
	return readInput("请输入选项: ")
}

func readInput(prompt string) string {
	fmt.Printf("  %s%s%s ", colorCyan, prompt, colorReset)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func confirm(prompt string) bool {
	input := readInput(fmt.Sprintf("%s (y/n): ", prompt))
	return strings.ToLower(input) == "y" || strings.ToLower(input) == "yes"
}

// ════════════════════════════════════════════════════════════════════════════════
// 系统检测
// ════════════════════════════════════════════════════════════════════════════════

func detectSystem() (*SysInfo, error) {
	info := &SysInfo{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}
	if info.OS != "linux" {
		return info, fmt.Errorf("仅支持 Linux 系统")
	}
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return info, fmt.Errorf("无法读取系统信息: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		val := strings.Trim(parts[1], "\"")
		switch key {
		case "ID":
			info.Distro = val
		case "VERSION_ID":
			info.Version = val
		case "VERSION_CODENAME":
			info.Codename = val
		}
	}
	if _, err := exec.LookPath("apt-get"); err == nil {
		info.PkgManager = "apt"
	} else if _, err := exec.LookPath("dnf"); err == nil {
		info.PkgManager = "dnf"
	} else if _, err := exec.LookPath("yum"); err == nil {
		info.PkgManager = "yum"
	}
	return info, nil
}

func checkRoot() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("请使用 root 权限运行")
	}
	return nil
}

// ════════════════════════════════════════════════════════════════════════════════
// 网络状态检测
// ════════════════════════════════════════════════════════════════════════════════

func getNetworkStatus() *NetworkStatus {
	status := &NetworkStatus{}
	status.WarpEnabled, status.GatewayEnabled = getTraceStatus()
	status.IPv4 = getIP("https://api4.ipify.org")
	status.IPv6 = getIP("https://api6.ipify.org")
	status.WarpIPv4 = getWarpInterfaceIP()
	return status
}

func getIP(url string) string {
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

// getWarpInterfaceIP 通过 WARP 接口获取出口 IP（修复：使用 curl --interface 绑定接口）
func getWarpInterfaceIP() string {
	out, err := exec.Command("curl", "-s", "--max-time", "5", "--interface", warpIfName, "https://api4.ipify.org").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ════════════════════════════════════════════════════════════════════════════════
// WARP 账号注册
// ════════════════════════════════════════════════════════════════════════════════

// registerWARP 注册 WARP 账号。
// - team == nil：使用第三方代理注册普通 WARP（无需 ZT）
// - team != nil：直接调用 Cloudflare 官方 API 注册并关联 Zero Trust 组织
//   第三方代理无法保证转发 CF-Access headers，gateway 会停留在 off 状态，
//   必须直连官方 API 才能让 gateway=on。
func registerWARP(team *teamRegistration) (*Account, error) {
	if team != nil {
		return registerWARPZeroTrust(team)
	}
	return registerWARPPlain()
}

// registerWARPPlain 注册普通 WARP。优先使用官方 API（本地生成密钥对），失败则回退第三方代理。
func registerWARPPlain() (*Account, error) {
	// 方式 1：官方 API（本地生成 Curve25519 密钥对，POST /reg）
	account, err := registerWARPPlainOfficial()
	if err == nil {
		return account, nil
	}
	uiHint(fmt.Sprintf("  官方 API 注册失败: %v，尝试第三方代理...", err))

	// 方式 2：第三方代理
	return registerWARPPlainProxy()
}

// registerWARPPlainOfficial 直接调用 Cloudflare 官方 API 注册普通 WARP。
// 本地生成密钥对 → POST /reg → 解析 peer/地址信息。无需第三方代理。
func registerWARPPlainOfficial() (*Account, error) {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成密钥对失败: %v", err)
	}
	pubKeyB64 := base64.StdEncoding.EncodeToString(privKey.PublicKey().Bytes())
	privKeyB64 := base64.StdEncoding.EncodeToString(privKey.Bytes())

	installID := newUUID()
	body := map[string]interface{}{
		"key":           pubKeyB64,
		"install_id":    installID,
		"fcm_token":     newUUID(),
		"tos":           time.Now().UTC().Format(time.RFC3339),
		"model":         "Linux",
		"serial_number": installID,
		"locale":        "zh-CN",
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %v", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("POST", warpCFAPIBase+"/reg", bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("构造请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "1.1.1.1/6.29 CFNetwork/1408.0.4 Darwin/22.5.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody[:min(200, len(respBody))]))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	account := parseWARPAccount(result, false, "")
	// 官方 API 不在响应中返回 private_key，使用本地生成的
	account.PrivateKey = privKeyB64
	account.PublicKey = pubKeyB64

	if err := validateAccount(account); err != nil {
		return nil, fmt.Errorf("注册数据无效: %v", err)
	}
	return account, nil
}

// registerWARPPlainProxy 通过第三方代理注册（回退方案）。
func registerWARPPlainProxy() (*Account, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", warpRegisterURL, nil)
	if err != nil {
		return nil, fmt.Errorf("构造请求失败: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("注册请求失败: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("注册失败 (HTTP %d): %s", resp.StatusCode, string(body))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}
	account := parseWARPAccount(result, false, "")
	if err := validateAccount(account); err != nil {
		return nil, fmt.Errorf("注册数据无效: %v\n原始响应: %s", err, string(body))
	}
	return account, nil
}

// registerWARPZeroTrust 直接调用 Cloudflare 官方 API 注册并关联 Zero Trust 组织。
// 流程：本地生成 Curve25519 密钥对 → POST /reg 携带 CF-Access headers → 解析 peer/地址信息。
// 这是让 gateway=on 的唯一正确路径。
func registerWARPZeroTrust(team *teamRegistration) (*Account, error) {
	// Step 1: 本地生成 Curve25519 密钥对
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成密钥对失败: %v", err)
	}
	pubKeyB64 := base64.StdEncoding.EncodeToString(privKey.PublicKey().Bytes())
	privKeyB64 := base64.StdEncoding.EncodeToString(privKey.Bytes())

	// Step 2: 构造注册 body
	installID := newUUID()
	body := map[string]interface{}{
		"key":           pubKeyB64,
		"install_id":    installID,
		"fcm_token":     newUUID(),
		"tos":           time.Now().UTC().Format(time.RFC3339),
		"model":         "Linux",
		"serial_number": installID,
		"locale":        "zh-CN",
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %v", err)
	}

	// Step 3: 发送注册请求，带 CF-Access headers 关联 ZT 组织
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("POST", warpCFAPIBase+"/reg", bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("构造请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "1.1.1.1/6.29 CFNetwork/1408.0.4 Darwin/22.5.0")
	req.Header.Set("CF-Access-Client-Id", team.clientID)
	req.Header.Set("CF-Access-Client-Secret", team.clientSecret)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("注册请求失败: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ZT 注册失败 (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	// Step 4: 解析响应，官方 API 不返回 private_key，需用本地生成的
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	// 验证是否成功关联 ZT 组织（account.team 字段存在）
	teamName := ""
	if acc, ok := result["account"].(map[string]interface{}); ok {
		if t, ok := acc["team"].(string); ok && t != "" {
			teamName = t
		}
	}
	if teamName == "" {
		// 兼容不同版本 API 字段位置
		if t, ok := result["team_name"].(string); ok && t != "" {
			teamName = t
		}
	}
	if teamName == "" {
		return nil, fmt.Errorf("ZT 注册成功但未关联到组织，请检查 CF-Access-Client-Id/Secret 是否正确，以及该 Service Token 是否有 WARP enrollment 权限")
	}

	account := parseWARPAccount(result, true, teamName)
	// 官方 API 不返回 private_key，填入本地生成的
	account.PrivateKey = privKeyB64
	account.PublicKey = pubKeyB64

	if err := validateAccount(account); err != nil {
		return nil, fmt.Errorf("ZT 注册数据无效: %v", err)
	}

	if err := account.saveToFile(warpAccountPath); err != nil {
		return nil, fmt.Errorf("保存账号信息失败: %v", err)
	}
	return account, nil
}

// parseWARPAccount 从 API 响应 map 中提取账号字段（供 plain 和 ZT 两个路径共用）
func parseWARPAccount(result map[string]interface{}, isTeams bool, orgName string) *Account {
	account := &Account{IsTeams: isTeams, OrgName: orgName}
	if id, ok := result["id"].(string); ok {
		account.ID = id
	}
	if token, ok := result["token"].(string); ok {
		account.Token = token
	}
	if privKey, ok := result["private_key"].(string); ok {
		account.PrivateKey = privKey
	}
	if pubKey, ok := result["public_key"].(string); ok {
		account.PublicKey = pubKey
	}
	if cfg, ok := result["config"].(map[string]interface{}); ok {
		if iface, ok := cfg["interface"].(map[string]interface{}); ok {
			if addrs, ok := iface["addresses"].(map[string]interface{}); ok {
				if v4, ok := addrs["v4"].(string); ok {
					account.IPv4 = v4
				}
				if v6, ok := addrs["v6"].(string); ok {
					account.IPv6 = v6
				}
			}
		}
	}
	if account.PrivateKey != "" {
		_ = account.saveToFile(warpAccountPath)
	}
	return account
}

// validateAccount 检查注册返回的账号数据是否完整，缺少关键字段时返回错误。
func validateAccount(account *Account) error {
	if account.PrivateKey == "" {
		return fmt.Errorf("注册返回的 PrivateKey 为空，第三方注册服务可能不可用")
	}
	if account.IPv4 == "" && account.IPv6 == "" {
		return fmt.Errorf("注册返回的 IP 地址为空（v4=%q v6=%q），第三方注册服务可能不可用", account.IPv4, account.IPv6)
	}
	return nil
}

// newUUID 生成随机 UUID v4 字符串（不依赖外部包）
func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%12x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (a *Account) saveToFile(path string) error {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func loadAccountFromFile(path string) (*Account, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var account Account
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, err
	}
	return &account, nil
}

// ════════════════════════════════════════════════════════════════════════════════
// WireGuard 管理
// ════════════════════════════════════════════════════════════════════════════════

func installWireguardTools(sysInfo *SysInfo) error {
	if wgIsInstalled() {
		uiInfo("WireGuard 已安装，跳过")
		return nil
	}
	switch sysInfo.PkgManager {
	case "apt":
		cmd := exec.Command("apt-get", "install", "-y", "wireguard-tools")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
	case "yum", "dnf":
		cmd := exec.Command(sysInfo.PkgManager, "install", "-y", "wireguard-tools")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("不支持的包管理器: %s", sysInfo.PkgManager)
	}
	installWireguardGo()
	return nil
}

func installWireguardGo() {
	if _, err := exec.Command("modprobe", "wireguard").CombinedOutput(); err == nil {
		return
	}
	arch := runtime.GOARCH
	dlURL := fmt.Sprintf("https://github.com/pzeus/warpgo/releases/download/deps/wireguard-go-%s", arch)
	uiInfo("内核不支持 WireGuard，安装 wireguard-go...")
	resp, err := http.Get(dlURL)
	if err != nil {
		uiWarning(fmt.Sprintf("下载 wireguard-go 失败: %v", err))
		return
	}
	defer resp.Body.Close()
	out, err := os.Create(wireguardGoPath)
	if err != nil {
		uiWarning(fmt.Sprintf("创建 wireguard-go 文件失败: %v", err))
		return
	}
	defer out.Close()
	io.Copy(out, resp.Body)
	os.Chmod(wireguardGoPath, 0755)
}

func wgIsInstalled() bool {
	if _, err := exec.LookPath("wg"); err == nil {
		return true
	}
	if _, err := os.Stat(warpConfPath); err == nil {
		return true
	}
	return false
}

func wgIsRunning() bool {
	out, err := exec.Command("wg", "show", warpIfName).CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "public key")
}

func wgStart() error {
	// 确保旧接口已清理，忽略错误（接口不存在时 wg-quick down 会报错属正常）
	exec.Command("wg-quick", "down", warpIfName).Run()
	time.Sleep(500 * time.Millisecond)
	cmd := exec.Command("wg-quick", "up", warpIfName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func wgStop() error {
	cmd := exec.Command("wg-quick", "down", warpIfName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run() // 接口不存在时返回错误属正常，调用方无需感知
	return nil
}

func wgToggle() error {
	if wgIsRunning() {
		uiInfo("正在停止 WARP...")
		if err := wgStop(); err != nil {
			return err
		}
		uiInfo("✓ WARP 已停止")
	} else {
		uiInfo("正在启动 WARP...")
		if err := wgStart(); err != nil {
			return err
		}
		uiInfo("✓ WARP 已启动")
	}
	return nil
}

func generateWgConfig(opts WgConfigOptions) error {
	account := opts.Account
	endpoint := warpEndpointV4
	if opts.Endpoint != "" {
		endpoint = opts.Endpoint
	}

	var addresses []string
	switch opts.Stack {
	case stackIPv4:
		addresses = append(addresses, account.IPv4+"/32")
	case stackIPv6:
		addresses = append(addresses, account.IPv6+"/128")
	case stackDual:
		addresses = append(addresses, account.IPv4+"/32", account.IPv6+"/128")
	}

	var allowedIPs []string
	switch opts.Stack {
	case stackIPv4:
		allowedIPs = append(allowedIPs, "0.0.0.0/0")
	case stackIPv6:
		allowedIPs = append(allowedIPs, "::/0")
	case stackDual:
		allowedIPs = append(allowedIPs, "0.0.0.0/0", "::/0")
	}

	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = %s\nMTU = %d\n",
		account.PrivateKey, strings.Join(addresses, ","), warpDNS, defaultMTU)

	// SSH 保护：用 PreUp 在路由被 wg-quick 接管之前捕获 VPS 原始出口 IP，
	// 写入临时文件；PostUp 读取该文件，添加高优先级 ip rule 让原始 IP 的流量
	// 继续走 main 表（原始网关），确保 SSH 连接不中断。
	// PreUp 必须在路由切换前执行，是唯一能拿到正确原始 IP 的时机。
	conf += fmt.Sprintf("PreUp = %s\n", globalPreUpScript(opts.Stack))
	conf += fmt.Sprintf("PostUp = %s\n", globalPostUpScript())
	conf += fmt.Sprintf("PostDown = %s\n", globalPostDownScript())

	conf += fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\nEndpoint = %s\n",
		warpPublicKey, strings.Join(allowedIPs, ","), endpoint)

	os.MkdirAll("/etc/wireguard", 0700)
	return os.WriteFile(warpConfPath, []byte(conf), 0600)
}

// globalPreUpScript 在 wg-quick 修改路由之前执行，捕获 VPS 原始出口 IP。
// PreUp 时机：接口未建立，路由规则未变，ip route get 返回的 src 是真实 VPS IP。
func globalPreUpScript(stack stackMode) string {
	var cmds []string
	cmds = append(cmds, "mkdir -p /run/warp-ssh")
	if stack == stackIPv4 || stack == stackDual {
		cmds = append(cmds,
			`ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' > /run/warp-ssh/orig_ip4 || true`,
		)
	}
	if stack == stackIPv6 || stack == stackDual {
		cmds = append(cmds,
			`ip -6 route get 2606:4700::1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' > /run/warp-ssh/orig_ip6 || true`,
		)
	}
	return strings.Join(cmds, "; ")
}

// globalPostUpScript 在 wg-quick 路由设置完成后执行：
// 1) 读取 PreUp 保存的原始 IP，添加高优先级（10）ip rule，让原始 IP 的出站流量走 main 表。
// 2) 在 wg-quick 创建的 nft 表中插入 SSH 豁免规则，防止 nft 给 SSH 回包打 fwmark。
//    wg-quick 的 nft 会给所有本机发出的包打 fwmark 0xca6c，导致包匹配 suppress_prefixlength 0
//    规则时默认路由被抑制、无可用路由而丢包。豁免规则让已建立的 SSH 连接不被标记。
func globalPostUpScript() string {
	sshNft := `nft list table ip wg-quick-warp >/dev/null 2>&1 && { ` +
		`SP=$(grep -i "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2; exit}'); ` +
		`SP=${SP:-22}; ` +
		`nft insert rule ip wg-quick-warp output ct state established,related tcp sport "$SP" accept 2>/dev/null || true; } || true`
	// 注意：用 ; 分隔且每条命令都以 || true 结尾，因为 wg-quick 以 set -e 运行 PostUp，
	// 任何命令返回非零（如 [ -s file ] 文件不存在、IPv6 不可用）都会导致接口被 tear down。
	return strings.Join([]string{
		`([ -s /run/warp-ssh/orig_ip4 ] && ip -4 rule add from "$(cat /run/warp-ssh/orig_ip4)" table main priority 10 || true) 2>/dev/null`,
		`([ -s /run/warp-ssh/orig_ip6 ] && ip -6 rule add from "$(cat /run/warp-ssh/orig_ip6)" table main priority 10 || true) 2>/dev/null`,
		sshNft,
	}, "; ")
}

// globalPostDownScript 撤销 PostUp 添加的规则，清理临时文件。
func globalPostDownScript() string {
	return strings.Join([]string{
		`([ -s /run/warp-ssh/orig_ip4 ] && ip -4 rule del from "$(cat /run/warp-ssh/orig_ip4)" table main priority 10 || true) 2>/dev/null`,
		`([ -s /run/warp-ssh/orig_ip6 ] && ip -6 rule del from "$(cat /run/warp-ssh/orig_ip6)" table main priority 10 || true) 2>/dev/null`,
		`rm -f /run/warp-ssh/orig_ip4 /run/warp-ssh/orig_ip6`,
	}, "; ")
}

func getWgConfigStatus() *WgConfigStatus {
	status := &WgConfigStatus{StackMode: stackDual}
	data, err := os.ReadFile(warpConfPath)
	if err != nil {
		return status
	}
	content := string(data)
	if strings.Contains(content, "0.0.0.0/0") && strings.Contains(content, "::/0") {
		status.StackMode = stackDual
	} else if strings.Contains(content, "::/0") {
		status.StackMode = stackIPv6
	} else {
		status.StackMode = stackIPv4
	}
	return status
}

func switchStack(stack stackMode) error {
	backupWgConfig()
	account, err := loadAccountFromFile(warpAccountPath)
	if err != nil {
		return fmt.Errorf("读取账号信息失败: %v", err)
	}
	opts := WgConfigOptions{Account: account, Stack: stack, Endpoint: getCurrentEndpoint()}
	wasRunning := wgIsRunning()
	if wasRunning {
		wgStop()
	}
	if err := generateWgConfig(opts); err != nil {
		restoreWgConfig()
		return fmt.Errorf("生成配置失败: %v", err)
	}
	if wasRunning {
		if err := wgStart(); err != nil {
			restoreWgConfig()
			wgStart()
			return fmt.Errorf("重启失败: %v", err)
		}
	}
	stackNames := map[stackMode]string{stackIPv4: "IPv4", stackIPv6: "IPv6", stackDual: "双栈"}
	uiInfo(fmt.Sprintf("✓ 已切换为 %s", stackNames[stack]))
	return nil
}

func getCurrentEndpoint() string {
	data, err := os.ReadFile(warpConfPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Endpoint") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func switchEndpoint(newEndpoint string) error {
	backupWgConfig()
	data, err := os.ReadFile(warpConfPath)
	if err != nil {
		return fmt.Errorf("读取配置失败: %v", err)
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "Endpoint") {
			lines[i] = fmt.Sprintf("Endpoint = %s", newEndpoint)
		}
	}
	if err := os.WriteFile(warpConfPath, []byte(strings.Join(lines, "\n")), 0600); err != nil {
		return fmt.Errorf("写入配置失败: %v", err)
	}
	wasRunning := wgIsRunning()
	if wasRunning {
		wgStop()
		time.Sleep(1 * time.Second)
		if err := wgStart(); err != nil {
			uiWarning("新 Endpoint 启动失败，回滚...")
			restoreWgConfig()
			wgStart()
			return fmt.Errorf("切换失败，已恢复原配置: %v", err)
		}
		time.Sleep(10 * time.Second)
		for attempt := 0; attempt < 3; attempt++ {
			if checkWarpEnabled() {
				return nil
			}
			if attempt < 2 {
				time.Sleep(3 * time.Second)
			}
		}
		uiWarning("新 Endpoint 连接验证失败，回滚...")
		wgStop()
		restoreWgConfig()
		wgStart()
		return fmt.Errorf("新 Endpoint 无法建立 WARP 连接，已恢复原配置")
	}
	return nil
}

func backupWgConfig() {
	if data, err := os.ReadFile(warpConfPath); err == nil {
		os.WriteFile(warpConfPath+".bak", data, 0600)
	}
	if data, err := os.ReadFile(warpAccountPath); err == nil {
		os.WriteFile(warpAccountPath+".bak", data, 0600)
	}
}

func restoreWgConfig() {
	if data, err := os.ReadFile(warpConfPath + ".bak"); err == nil {
		os.WriteFile(warpConfPath, data, 0600)
	}
}

// ════════════════════════════════════════════════════════════════════════════════
// Zero Trust 管理
// ════════════════════════════════════════════════════════════════════════════════

func isWarpCLIInstalled() bool {
	_, err := exec.LookPath("warp-cli")
	return err == nil
}

func getZTStatus() (*ZeroTrustStatus, error) {
	status := &ZeroTrustStatus{}
	out, err := exec.Command("warp-cli", "--accept-tos", "status").CombinedOutput()
	if err != nil {
		return status, err
	}
	output := string(out)
	status.Connected = strings.Contains(output, "Connected")
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "Mode:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				status.Mode = strings.TrimSpace(parts[1])
			}
		}
	}
	return status, nil
}

func enrollServiceToken(orgName, clientID, clientSecret string) error {
	mdmXML := fmt.Sprintf(`<dict>
  <key>organization</key>
  <string>%s</string>
  <key>auth_client_id</key>
  <string>%s</string>
  <key>auth_client_secret</key>
  <string>%s</string>
  <key>service_mode</key>
  <string>proxy</string>
  <key>proxy_port</key>
  <integer>%d</integer>
</dict>`, orgName, clientID, clientSecret, defaultSocks5Port)

	os.MkdirAll("/var/lib/cloudflare-warp", 0755)
	if err := os.WriteFile("/var/lib/cloudflare-warp/mdm.xml", []byte(mdmXML), 0644); err != nil {
		return fmt.Errorf("写入 MDM 配置失败: %v", err)
	}

	ztConfig := &ZeroTrustConfig{
		OrgName: orgName, ClientID: clientID, ClientSecret: clientSecret,
		UseProxyMode: true, Socks5Port: defaultSocks5Port,
	}
	saveZTConfig(ztConfig)

	// 重启前先断开连接，防止 warp-svc 重启后自动重连（全隧道模式）导致 SSH 中断
	exec.Command("warp-cli", "--accept-tos", "disconnect").Run()
	exec.Command("systemctl", "restart", "warp-svc").Run()
	uiInfo("正在等待 warp-svc 读取 MDM 配置...")

	for i := 0; i < 30; i++ {
		time.Sleep(1 * time.Second)
		out, err := exec.Command("warp-cli", "--accept-tos", "registration", "show").CombinedOutput()
		if err == nil && strings.Contains(string(out), "Organization") {
			uiInfo("✓ 注册成功")
			return nil
		}
	}
	return fmt.Errorf("注册超时（30秒），请检查 Service Token 和组织名称是否正确")
}

func ztConnect() error {
	uiInfo("正在连接 Zero Trust...")
	if err := exec.Command("warp-cli", "--accept-tos", "connect").Run(); err != nil {
		return fmt.Errorf("连接命令失败: %v", err)
	}
	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		st, _ := getZTStatus()
		if st.Connected {
			uiInfo("✓ Zero Trust 已连接")
			// 恢复反代服务
			if shouldRestoreProxy() {
				uiInfo("正在恢复反代服务...")
				cfg, _ := loadZTConfig()
				extPort := defaultSocks5Port
				if cfg != nil && cfg.ExternalPort > 0 {
					extPort = cfg.ExternalPort
				}
				setupExternalProxy(extPort)
			}
			// 恢复透明代理（如果之前启用过）
			if cfg, err := loadZTConfig(); err == nil && cfg.ProxyEnabled {
				uiInfo("正在恢复透明代理...")
				setupTransparentProxy(defaultSocks5Port)
			}
			return nil
		}
	}
	return fmt.Errorf("连接超时（10秒）")
}

func ztDisconnect() error {
	uiInfo("正在断开 Zero Trust...")
	// 清理透明代理（如果启用）
	if isTransparentProxyRunning() {
		cleanupTransparentProxy()
		saveTransparentProxyConfig(false)
	}
	cleanupExternalProxy()
	removeReverseProxyService()
	if err := exec.Command("warp-cli", "--accept-tos", "disconnect").Run(); err != nil {
		return fmt.Errorf("断开命令失败: %v", err)
	}
	uiInfo("✓ Zero Trust 已断开")
	return nil
}

func shouldRestoreProxy() bool {
	cfg, err := loadZTConfig()
	if err == nil && cfg.ProxyEnabled {
		uiHint("  [调试] 配置文件标记代理已启用")
		return true
	}
	if _, err := os.Stat("/etc/systemd/system/warpgo-reverse-proxy.service"); err == nil {
		uiHint("  [调试] 检测到反代服务配置")
		return true
	}
	return false
}

// isTransparentProxyRunning 检查透明代理（redsocks + iptables）是否正在运行
func isTransparentProxyRunning() bool {
	// 检查 redsocks 是否运行
	out, err := exec.Command("systemctl", "is-active", "redsocks").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "active" {
		return false
	}
	// 优先检查 iptables WARP_PROXY 链
	if _, err := exec.LookPath("iptables"); err == nil {
		checkOut, err := exec.Command("iptables", "-t", "nat", "-L", "WARP_PROXY").CombinedOutput()
		if err == nil && !strings.Contains(string(checkOut), "No chain") {
			return true
		}
	}
	// 回退检查 nftables warp_proxy 表（Debian 13 等无 iptables 的系统）
	if _, err := exec.LookPath("nft"); err == nil {
		checkOut, err := exec.Command("nft", "list", "table", "ip", "warp_proxy").CombinedOutput()
		if err == nil && !strings.Contains(string(checkOut), "No such file") {
			return true
		}
	}
	return false
}

// toggleTransparentProxy 切换透明代理状态
// 启用时：VPS 所有 TCP 流量通过 redsocks → warp-cli SOCKS5 → Cloudflare
// 禁用时：恢复 VPS 原始网络
func toggleTransparentProxy() {
	if isTransparentProxyRunning() {
		uiInfo("正在关闭透明代理...")
		cleanupTransparentProxy()
		saveTransparentProxyConfig(false)
		uiInfo("✓ 透明代理已关闭，VPS 恢复原始网络")
		// 显示当前 IP
		ip := getIP("https://api4.ipify.org")
		if ip != "" {
			uiInfo(fmt.Sprintf("  当前 IPv4: %s", ip))
		}
	} else {
		uiInfo("正在开启透明代理...")
		// 确保 warp-cli 已连接
		st, _ := getZTStatus()
		if !st.Connected {
			uiWarning("warp-cli 未连接，请先连接 Zero Trust")
			return
		}
		setupTransparentProxy(defaultSocks5Port)
		// 验证 IP 是否改变
		uiInfo("验证出口 IP...")
		time.Sleep(2 * time.Second)
		proxyIP := getIP("https://api4.ipify.org")
		if proxyIP != "" {
			uiInfo(fmt.Sprintf("✓ 出口 IP 已改变: %s", proxyIP))
		}
		uiInfo("  验证命令: curl -4 ip.gs")
	}
}

func setupTransparentProxy(socks5Port int) {
	exec.Command("apt-get", "install", "-y", "redsocks").Run()
	redsocksConf := fmt.Sprintf("base {\n\tlog_debug = off;\n\tlog_info = on;\n\tdaemon = on;\n\tredirector = iptables;\n}\n\nredsocks {\n\tlocal_ip = 127.0.0.1;\n\tlocal_port = %d;\n\tip = 127.0.0.1;\n\tport = %d;\n\ttype = socks5;\n}\n", defaultRedsocksPort, socks5Port)
	os.WriteFile("/etc/redsocks.conf", []byte(redsocksConf), 0644)
	exec.Command("systemctl", "stop", "redsocks").Run()
	exec.Command("systemctl", "enable", "redsocks").Run()
	exec.Command("systemctl", "start", "redsocks").Run()
	setupIptablesRules(defaultRedsocksPort)
	saveTransparentProxyConfig(true)
	installProxyService(socks5Port)
	uiInfo("✓ 透明代理已启用")
}

func setupIptablesRules(redsocksPort int) {
	sshPort := getSSHPort()
	hasIptables := exec.Command("iptables", "-V").Run() == nil
	hasIp6tables := exec.Command("ip6tables", "-V").Run() == nil

	if hasIptables {
		exec.Command("iptables", "-t", "nat", "-F", "WARP_PROXY").Run()
		exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-j", "WARP_PROXY").Run()
		exec.Command("iptables", "-t", "nat", "-X", "WARP_PROXY").Run()
		exec.Command("iptables", "-t", "nat", "-N", "WARP_PROXY").Run()
		exec.Command("iptables", "-t", "nat", "-A", "WARP_PROXY", "-d", "127.0.0.0/8", "-j", "RETURN").Run()
		exec.Command("iptables", "-t", "nat", "-A", "WARP_PROXY", "-d", "10.0.0.0/8", "-j", "RETURN").Run()
		exec.Command("iptables", "-t", "nat", "-A", "WARP_PROXY", "-d", "172.16.0.0/12", "-j", "RETURN").Run()
		exec.Command("iptables", "-t", "nat", "-A", "WARP_PROXY", "-d", "192.168.0.0/16", "-j", "RETURN").Run()
		exec.Command("iptables", "-t", "nat", "-A", "WARP_PROXY", "-p", "tcp", "--dport", sshPort, "-j", "RETURN").Run()
		exec.Command("iptables", "-t", "nat", "-A", "WARP_PROXY", "-p", "tcp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", redsocksPort)).Run()
		exec.Command("iptables", "-t", "nat", "-A", "OUTPUT", "-j", "WARP_PROXY").Run()
	}
	if hasIp6tables {
		exec.Command("ip6tables", "-t", "nat", "-F", "WARP_PROXY").Run()
		exec.Command("ip6tables", "-t", "nat", "-D", "OUTPUT", "-j", "WARP_PROXY").Run()
		exec.Command("ip6tables", "-t", "nat", "-X", "WARP_PROXY").Run()
		exec.Command("ip6tables", "-t", "nat", "-N", "WARP_PROXY").Run()
		exec.Command("ip6tables", "-t", "nat", "-A", "WARP_PROXY", "-d", "::1/128", "-j", "RETURN").Run()
		exec.Command("ip6tables", "-t", "nat", "-A", "WARP_PROXY", "-d", "fc00::/7", "-j", "RETURN").Run()
		exec.Command("ip6tables", "-t", "nat", "-A", "WARP_PROXY", "-p", "tcp", "--dport", sshPort, "-j", "RETURN").Run()
		exec.Command("ip6tables", "-t", "nat", "-A", "WARP_PROXY", "-p", "tcp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", redsocksPort)).Run()
		exec.Command("ip6tables", "-t", "nat", "-A", "OUTPUT", "-j", "WARP_PROXY").Run()
	}
	if !hasIptables {
		nftRules := fmt.Sprintf("table ip warp_proxy {\n\tchain output {\n\t\ttype nat hook output priority -100;\n\t\tip daddr 127.0.0.0/8 return\n\t\tip daddr 10.0.0.0/8 return\n\t\tip daddr 172.16.0.0/12 return\n\t\tip daddr 192.168.0.0/16 return\n\t\ttcp dport %s return\n\t\ttcp flags & (fin|syn|rst|ack) == syn redirect to %d\n\t}\n}", sshPort, redsocksPort)
		nftFile := "/tmp/warp-proxy.nft"
		os.WriteFile(nftFile, []byte(nftRules), 0644)
		exec.Command("nft", "-f", nftFile).Run()
		os.Remove(nftFile)
	}
}

func cleanupTransparentProxy() {
	exec.Command("systemctl", "stop", "redsocks").Run()
	exec.Command("iptables", "-t", "nat", "-F", "WARP_PROXY").Run()
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-j", "WARP_PROXY").Run()
	exec.Command("iptables", "-t", "nat", "-X", "WARP_PROXY").Run()
	exec.Command("ip6tables", "-t", "nat", "-F", "WARP_PROXY").Run()
	exec.Command("ip6tables", "-t", "nat", "-D", "OUTPUT", "-j", "WARP_PROXY").Run()
	exec.Command("ip6tables", "-t", "nat", "-X", "WARP_PROXY").Run()
	exec.Command("nft", "delete", "table", "ip", "warp_proxy").Run()
	exec.Command("nft", "delete", "table", "ip6", "warp_proxy").Run()
}

func installProxyService(socks5Port int) {
	serviceContent := fmt.Sprintf("[Unit]\nDescription=WarpGo Transparent Proxy\nAfter=warp-svc.service\nWants=warp-svc.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/bash -c 'warp-cli --accept-tos connect; for i in $(seq 1 60); do warp-cli --accept-tos status 2>/dev/null | grep -q Connected && break; sleep 1; done; systemctl start redsocks; %s'\nExecStop=/bin/bash -c 'systemctl stop redsocks; iptables -t nat -F WARP_PROXY 2>/dev/null; iptables -t nat -D OUTPUT -j WARP_PROXY 2>/dev/null; iptables -t nat -X WARP_PROXY 2>/dev/null; nft delete table ip warp_proxy 2>/dev/null; nft delete table ip6 warp_proxy 2>/dev/null'\n\n[Install]\nWantedBy=multi-user.target\n", generateIptablesCommands(defaultRedsocksPort))
	os.WriteFile("/etc/systemd/system/warpgo-proxy.service", []byte(serviceContent), 0644)
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "warpgo-proxy").Run()
	exec.Command("systemctl", "start", "warpgo-proxy").Run()
}

func generateIptablesCommands(redsocksPort int) string {
	sshPort := getSSHPort()
	cmds := []string{
		"iptables -t nat -N WARP_PROXY 2>/dev/null",
		"iptables -t nat -F WARP_PROXY",
		"iptables -t nat -A WARP_PROXY -d 127.0.0.0/8 -j RETURN",
		"iptables -t nat -A WARP_PROXY -d 10.0.0.0/8 -j RETURN",
		"iptables -t nat -A WARP_PROXY -d 172.16.0.0/12 -j RETURN",
		"iptables -t nat -A WARP_PROXY -d 192.168.0.0/16 -j RETURN",
		fmt.Sprintf("iptables -t nat -A WARP_PROXY -p tcp --dport %s -j RETURN", sshPort),
		fmt.Sprintf("iptables -t nat -A WARP_PROXY -p tcp -j REDIRECT --to-ports %d", redsocksPort),
		"iptables -t nat -D OUTPUT -j WARP_PROXY 2>/dev/null",
		"iptables -t nat -A OUTPUT -j WARP_PROXY",
	}
	return strings.Join(cmds, "; ")
}

func removeProxyService() {
	exec.Command("systemctl", "stop", "warpgo-proxy").Run()
	exec.Command("systemctl", "disable", "warpgo-proxy").Run()
	os.Remove("/etc/systemd/system/warpgo-proxy.service")
	exec.Command("systemctl", "daemon-reload").Run()
}

// setupExternalProxy 使用 socat 将 warp-cli 的 SOCKS5 代理暴露到外部端口。
// warp-cli proxy 模式在 127.0.0.1:40000 监听，socat 做 TCP 转发让外部设备可连接。
func setupExternalProxy(externalPort int) {
	if externalPort <= 0 || externalPort > 65535 {
		externalPort = defaultSocks5Port
	}
	// 确保 socat 已安装
	if _, err := exec.LookPath("socat"); err != nil {
		uiInfo("安装 socat...")
		exec.Command("apt-get", "install", "-y", "socat").Run()
	}
	serviceContent := fmt.Sprintf(`[Unit]
Description=WarpGo Reverse Proxy (SOCKS5)
After=warp-svc.service
Wants=warp-svc.service

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP-LISTEN:%d,bind=0.0.0.0,fork,reuseaddr TCP:127.0.0.1:%d
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
`, externalPort, defaultSocks5Port)
	os.WriteFile("/etc/systemd/system/warpgo-reverse-proxy.service", []byte(serviceContent), 0644)
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "warpgo-reverse-proxy").Run()
	exec.Command("systemctl", "restart", "warpgo-reverse-proxy").Run()
	uiInfo(fmt.Sprintf("✓ 反代已启动: socks5://0.0.0.0:%d → 127.0.0.1:%d", externalPort, defaultSocks5Port))
}

// cleanupExternalProxy 停止 socat 反代服务，清理 iptables 和 nft 规则
func cleanupExternalProxy() {
	exec.Command("systemctl", "stop", "warpgo-reverse-proxy").Run()
	exec.Command("iptables", "-t", "nat", "-F", "WARP_PROXY").Run()
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-j", "WARP_PROXY").Run()
	exec.Command("iptables", "-t", "nat", "-X", "WARP_PROXY").Run()
	exec.Command("nft", "delete", "table", "ip", "warp_proxy").Run()
	exec.Command("nft", "delete", "table", "ip6", "warp_proxy").Run()
}

// removeReverseProxyService 移除 socat 反代 systemd 服务
func removeReverseProxyService() {
	exec.Command("systemctl", "stop", "warpgo-reverse-proxy").Run()
	exec.Command("systemctl", "disable", "warpgo-reverse-proxy").Run()
	os.Remove("/etc/systemd/system/warpgo-reverse-proxy.service")
	exec.Command("systemctl", "daemon-reload").Run()
}

// installReverseProxyService 创建开机自启的反代服务（与 warp-svc 联动）
func installReverseProxyService(externalPort int) {
	if externalPort <= 0 || externalPort > 65535 {
		externalPort = defaultSocks5Port
	}
	serviceContent := fmt.Sprintf(`[Unit]
Description=WarpGo Reverse Proxy (SOCKS5)
After=warp-svc.service
Wants=warp-svc.service

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP-LISTEN:%d,bind=0.0.0.0,fork,reuseaddr TCP:127.0.0.1:%d
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
`, externalPort, defaultSocks5Port)
	os.WriteFile("/etc/systemd/system/warpgo-reverse-proxy.service", []byte(serviceContent), 0644)
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "warpgo-reverse-proxy").Run()
}

func saveTransparentProxyConfig(enabled bool) {
	cfg, err := loadZTConfig()
	if err != nil {
		cfg = &ZeroTrustConfig{}
	}
	cfg.ProxyEnabled = enabled
	cfg.UseProxyMode = enabled
	if enabled {
		cfg.Socks5Port = defaultSocks5Port
	}
	saveZTConfig(cfg)
}

func saveZTConfig(cfg *ZeroTrustConfig) {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return
	}
	os.MkdirAll("/etc/wireguard", 0700)
	os.WriteFile(zeroTrustConfigPath, data, 0600)
}

func loadZTConfig() (*ZeroTrustConfig, error) {
	data, err := os.ReadFile(zeroTrustConfigPath)
	if err != nil {
		return nil, err
	}
	var cfg ZeroTrustConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ════════════════════════════════════════════════════════════════════════════════
// 安装 / 卸载
// ════════════════════════════════════════════════════════════════════════════════

func doInstall(sysInfo *SysInfo, opts *InstallOptions) error {
	switch opts.Mode {
	case modeWireGuardV4, modeWireGuardV6, modeWireGuardDual:
		return installWireGuardMode(sysInfo, opts)
	case modeZeroTrust:
		return installZeroTrustMode(sysInfo, opts)
	case modeZeroTrustWG:
		return installZeroTrustWGMode(sysInfo, opts)
	default:
		return fmt.Errorf("不支持的安装模式")
	}
}

func installWireGuardMode(sysInfo *SysInfo, opts *InstallOptions) error {
	uiHeader("开始安装 WARP (WireGuard)")
	uiSeparator()
	uiStep(1, 6, "安装系统依赖")
	if err := installDependencies(sysInfo); err != nil {
		return fmt.Errorf("安装依赖失败: %v", err)
	}
	uiStep(2, 6, "安装 WireGuard")
	if err := installWireguardTools(sysInfo); err != nil {
		return fmt.Errorf("安装 WireGuard 失败: %v", err)
	}
	uiStep(3, 6, "注册 Cloudflare WARP 账号")
	account, err := registerWARP(nil)
	if err != nil {
		return fmt.Errorf("注册 WARP 失败: %v", err)
	}
	uiInfo(fmt.Sprintf("注册成功 (ID: %s)", account.ID[:8]))
	var stack stackMode
	switch opts.Mode {
	case modeWireGuardV4:
		stack = stackIPv4
	case modeWireGuardV6:
		stack = stackIPv6
	case modeWireGuardDual:
		stack = stackDual
	}
	uiStep(4, 6, "生成 WireGuard 配置")
	if err := generateWgConfig(WgConfigOptions{Account: account, Stack: stack, Endpoint: opts.Endpoint}); err != nil {
		return fmt.Errorf("生成配置失败: %v", err)
	}
	uiStep(5, 6, "启动 WARP 接口")
	if err := wgStart(); err != nil {
		return fmt.Errorf("启动失败: %v", err)
	}
	// 开机自启：启用 wg-quick@warp 服务，重启后自动恢复隧道
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "wg-quick@warp").Run()
	uiStep(6, 6, "验证连接")
	if !verifyConnectionWithFallback(opts.Endpoint) {
		return fmt.Errorf("WARP 连接失败，请运行 ./warpgo -diag 查看详情")
	}
	return nil
}

// protectSSHForZT 在 warp-cli connect 之前，把 VPS 自身出口 IP 加入
// split tunnel exclude 列表，确保 SSH 回包不走 WARP 隧道。
// warp-cli 把 exclude 列表持久化到 local_settings.json，
// 重启后 warp-svc 读取该文件，connect 时自动应用，无需重复设置。
// warpgo-autoconnect.service 也会在每次开机时重新添加，防止 IP 变化后失效。
func protectSSHForZT() {
	// 获取 VPS 当前出口 IPv4（在 connect 前执行，路由未被接管）
	out, err := exec.Command("ip", "-4", "route", "get", "1.1.1.1").Output()
	if err != nil {
		uiHint("  无法获取出口 IP，跳过 SSH exclude 设置")
		return
	}
	vpsIP := ""
	fields := strings.Fields(string(out))
	for i, v := range fields {
		if v == "src" && i+1 < len(fields) {
			vpsIP = fields[i+1]
			break
		}
	}
	if vpsIP == "" {
		uiHint("  无法解析出口 IP，跳过 SSH exclude 设置")
		return
	}

	// 确认 split tunnel 为 exclude mode（默认，不走 WARP 的白名单）
	exec.Command("warp-cli", "--accept-tos", "tunnel", "ip", "set-mode", "default").Run()

	// 将 VPS 自身 IP exclude：SSH 回包从原始网关出，不走 WARP
	cidr := vpsIP + "/32"
	if err := exec.Command("warp-cli", "--accept-tos", "tunnel", "ip", "add", cidr).Run(); err != nil {
		uiHint(fmt.Sprintf("  添加 SSH exclude 失败（%s）: %v", cidr, err))
	} else {
		uiInfo(fmt.Sprintf("✓ SSH 保护：%s 已加入 WARP exclude 列表（持久化）", cidr))
	}

	// 同时 exclude 私有地址，防止内网访问被 WARP 接管
	for _, private := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		exec.Command("warp-cli", "--accept-tos", "tunnel", "ip", "add", private).Run()
	}
	uiHint("  私有地址段（10/8、172.16/12、192.168/16）已加入 exclude")
}

// setupWarpAutoConnect 创建开机自动连接的 systemd 服务。
// warp-svc 本身不自动 connect，需要额外服务在 warp-svc 启动后执行 connect。
// 每次启动时重新添加 exclude（VPS IP 可能因重启而变化），确保 SSH 不断。
// Proxy 模式下，连接成功后自动启动 socat 反代服务。
func setupWarpAutoConnect() error {
	serviceContent := `[Unit]
Description=WarpGo Auto Connect (with SSH protection)
After=network-online.target warp-svc.service
Wants=network-online.target warp-svc.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c '\
  for i in $(seq 1 30); do \
    warp-cli --accept-tos status 2>/dev/null | grep -qE "Connected|Disconnected" && break; \
    sleep 1; \
  done; \
  VPS_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}'); \
  [ -n "$VPS_IP" ] && warp-cli --accept-tos tunnel ip add "$VPS_IP/32" 2>/dev/null || true; \
  warp-cli --accept-tos tunnel ip add 10.0.0.0/8 2>/dev/null || true; \
  warp-cli --accept-tos tunnel ip add 172.16.0.0/12 2>/dev/null || true; \
  warp-cli --accept-tos tunnel ip add 192.168.0.0/16 2>/dev/null || true; \
  warp-cli --accept-tos connect; \
  for i in $(seq 1 30); do \
    warp-cli --accept-tos status 2>/dev/null | grep -q Connected && break; \
    sleep 1; \
  done; \
  systemctl start warpgo-reverse-proxy 2>/dev/null || true'
ExecStop=/bin/bash -c 'warp-cli --accept-tos disconnect 2>/dev/null || true; systemctl stop warpgo-reverse-proxy 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
`
	if err := os.WriteFile("/etc/systemd/system/warpgo-autoconnect.service", []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("写入 autoconnect 服务失败: %v", err)
	}
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "warpgo-autoconnect").Run()
	return nil
}

func removeWarpAutoConnect() {
	exec.Command("systemctl", "stop", "warpgo-autoconnect").Run()
	exec.Command("systemctl", "disable", "warpgo-autoconnect").Run()
	os.Remove("/etc/systemd/system/warpgo-autoconnect.service")
	exec.Command("systemctl", "daemon-reload").Run()
}

func installZeroTrustMode(sysInfo *SysInfo, opts *InstallOptions) error {
	uiHeader("开始配置 Zero Trust Proxy")
	uiSeparator()
	uiStep(1, 7, "安装系统依赖")
	if err := installDependencies(sysInfo); err != nil {
		return fmt.Errorf("安装依赖失败: %v", err)
	}
	uiStep(2, 7, "安装 Cloudflare WARP 客户端")
	if err := installWarpCLI(sysInfo); err != nil {
		return fmt.Errorf("安装 warp-cli 失败: %v", err)
	}
	uiStep(3, 7, "配置 SSH 保护")
	// 先设置 SSH exclude 规则（持久化），确保后续 connect 不会中断 SSH
	protectSSHForZT()
	uiStep(4, 7, "注册 Zero Trust (Proxy 模式)")
	if err := enrollServiceToken(opts.ZeroTrustOrg, opts.ZeroTrustClientID, opts.ZeroTrustClientSecret); err != nil {
		return fmt.Errorf("注册失败: %v", err)
	}
	uiStep(5, 7, "配置开机自启")
	if err := setupWarpAutoConnect(); err != nil {
		uiHint(fmt.Sprintf("  警告: 开机自启配置失败: %v", err))
	}
	uiStep(6, 7, "连接 Zero Trust")
	if err := ztConnect(); err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}
	uiStep(7, 7, "配置反代 & 验证")
	extPort := defaultSocks5Port
	if cfg, err := loadZTConfig(); err == nil && cfg.ExternalPort > 0 {
		extPort = cfg.ExternalPort
	}
	setupExternalProxy(extPort)
	installReverseProxyService(extPort)
	verifyProxyConnection(extPort)

	// 询问是否开启透明代理（改变 VPS 出口 IP）
	uiBlank()
	if confirm("是否开启透明代理？开启后 VPS 所有流量走 WARP，出口 IP 会改变") {
		setupTransparentProxy(defaultSocks5Port)
		uiInfo("✓ 透明代理已开启")
		proxyIP := getIP("https://api4.ipify.org")
		if proxyIP != "" {
			uiInfo(fmt.Sprintf("  VPS 出口 IP 已变为: %s", proxyIP))
		}
	}
	return nil
}

func installZeroTrustWGMode(sysInfo *SysInfo, opts *InstallOptions) error {
	uiHeader("开始配置 Zero Trust (WireGuard)")
	uiSeparator()
	uiStep(1, 7, "安装系统依赖")
	if err := installDependencies(sysInfo); err != nil {
		return fmt.Errorf("安装依赖失败: %v", err)
	}
	uiStep(2, 7, "安装 WireGuard")
	if err := installWireguardTools(sysInfo); err != nil {
		return fmt.Errorf("安装 WireGuard 失败: %v", err)
	}
	uiStep(3, 7, "注册 Cloudflare WARP 并关联 Zero Trust Team")
	account, err := registerWARP(&teamRegistration{orgName: opts.ZeroTrustOrg, clientID: opts.ZeroTrustClientID, clientSecret: opts.ZeroTrustClientSecret})
	if err != nil {
		return fmt.Errorf("注册 WARP 失败: %v", err)
	}
	uiInfo(fmt.Sprintf("注册成功 (ID: %s, Team: %s)", account.ID[:8], opts.ZeroTrustOrg))
	uiStep(4, 7, "生成 WireGuard 配置")
	if err := generateWgConfig(WgConfigOptions{Account: account, Stack: stackDual, Endpoint: opts.Endpoint}); err != nil {
		return fmt.Errorf("生成配置失败: %v", err)
	}
	uiStep(5, 7, "启动 WARP 接口")
	if err := wgStart(); err != nil {
		return fmt.Errorf("启动失败: %v", err)
	}
	// 开机自启
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "wg-quick@warp").Run()
	uiStep(6, 7, "验证连接")
	if !verifyConnectionWithFallback(opts.Endpoint) {
		return fmt.Errorf("WARP 连接失败，请运行 ./warpgo -diag 查看详情")
	}
	uiStep(7, 7, "完成")
	uiInfo("✓ Zero Trust (WireGuard) 配置完成")
	return nil
}

// verifyConnectionWithFallback 验证 WARP 连接，如果握手失败则自动尝试其他 Endpoint 端口。
// 部分 VPS 机房会封 UDP 2408，但 500/1701/4500/8443 仍可用。
func verifyConnectionWithFallback(userEndpoint string) bool {
	// 第一次验证：用当前 Endpoint
	if checkWarpConnection() {
		return true
	}

	// 握手未完成，尝试自动切换 Endpoint
	uiWarning("默认 Endpoint 握手超时，尝试自动切换端口...")

	// 从当前配置提取 IP，尝试不同端口
	currentEP := getCurrentEndpoint()
	host, _, _ := net.SplitHostPort(currentEP)
	if host == "" {
		host = "162.159.192.1"
	}

	// 如果用户指定了 Endpoint，只试那个，不自动切换
	if userEndpoint != "" {
		uiHint("  用户指定了 Endpoint，不自动切换")
		printDiagnostics()
		return false
	}

	fallbackPorts := []string{"500", "1701", "4500", "8443"}
	// 如果默认 IP 的所有端口都失败，换一个 IP 段
	fallbackIPs := []string{"162.159.192.1", "162.159.204.1"}

	tried := map[string]bool{currentEP: true}

	for _, ip := range fallbackIPs {
		for _, port := range fallbackPorts {
			ep := net.JoinHostPort(ip, port)
			if tried[ep] {
				continue
			}
			tried[ep] = true

			uiInfo(fmt.Sprintf("  尝试 %s ...", ep))
			wgStop()
			time.Sleep(500 * time.Millisecond)
			if err := switchEndpoint(ep); err != nil {
				uiHint(fmt.Sprintf("    配置更新失败: %v", err))
				continue
			}
			if err := wgStart(); err != nil {
				uiHint(fmt.Sprintf("    启动失败: %v", err))
				continue
			}

			if checkWarpConnection() {
				uiInfo(fmt.Sprintf("✓ 切换到 %s 成功，WARP 已连接", ep))
				return true
			}
			uiHint("    握手未完成")
		}
	}

	// 所有 Endpoint 都失败
	uiWarning("所有 Endpoint 均无法建立连接")
	printDiagnostics()
	return false
}

// checkWarpConnection 等待握手并检查 WARP 状态，返回是否成功。
func checkWarpConnection() bool {
	for i := 0; i < 3; i++ {
		time.Sleep(5 * time.Second)
		if checkWarpEnabled() {
			return true
		}
	}
	return false
}

// printDiagnostics 打印诊断提示信息。
func printDiagnostics() {
	uiHint("  诊断建议:")
	uiHint("    1. 运行 ./warpgo -diag 查看详细诊断")
	uiHint("    2. VPS 可能封了所有 UDP 出站（常见于国内机房）")
	uiHint("    3. 尝试菜单 e 手动指定优选 IP:端口")
}

func verifyConnection() {
	uiInfo("等待 WARP 握手建立...")
	var status *NetworkStatus
	for i := 0; i < 4; i++ {
		time.Sleep(5 * time.Second)
		status = getNetworkStatus()
		if status.WarpEnabled {
			break
		}
		if i < 3 {
			uiInfo(fmt.Sprintf("  等待中... (%d/4)", i+1))
		}
	}
	if status.WarpEnabled {
		uiInfo(fmt.Sprintf("✓ WARP 已激活 — IPv4: %s", status.IPv4))
		if status.IPv6 != "" {
			uiInfo(fmt.Sprintf("  IPv6: %s", status.IPv6))
		}
		// 检查是否成功接入 Zero Trust Gateway
		if status.GatewayEnabled {
			uiInfo("✓ Zero Trust Gateway 已接入 (gateway=on)")
		} else {
			uiHint("  提示: gateway=off，当前为普通 WARP 模式（非 Zero Trust）")
		}
	} else {
		uiWarning("WARP 连接验证超时")
		// 诊断握手状态
		if out, err := exec.Command("wg", "show", warpIfName, "latest-handshakes").Output(); err == nil {
			hs := strings.TrimSpace(string(out))
			if hs == "" || strings.HasSuffix(hs, "0") {
				uiWarning("  原因: WireGuard 握手未完成（Endpoint 无法到达或密钥无效）")
				uiHint("  可能原因:")
				uiHint("    1. VPS 出口 UDP 被封（部分机房封 UDP 2408）")
				uiHint("    2. 第三方注册服务返回了无效的密钥/IP")
				uiHint("    3. Endpoint IP 不可达")
				uiHint("  建议: 菜单选 e 切换优选 IP，或检查 UDP 连通性")
			} else {
				uiHint("  WireGuard 握手已完成，但 Cloudflare trace 验证失败")
				uiHint("  可能是 DNS 解析问题，请检查 /etc/resolv.conf")
			}
		}
		uiHint(fmt.Sprintf("  当前 IPv4: %s", status.IPv4))
		uiHint("  手动验证: curl https://www.cloudflare.com/cdn-cgi/trace | grep -E 'warp|gateway'")
		uiHint("  查看握手: wg show warp")
	}
}

// verifyProxyConnection 验证 proxy 模式连接：通过 SOCKS5 代理访问 Cloudflare trace 确认 warp=on
func verifyProxyConnection(externalPort int) {
	uiInfo("等待 Zero Trust Proxy 就绪...")
	for i := 0; i < 3; i++ {
		time.Sleep(3 * time.Second)
		// 检查 warp-cli 状态
		st, err := getZTStatus()
		if err == nil && st.Connected {
			uiInfo(fmt.Sprintf("✓ Zero Trust Proxy 已连接 (模式: %s)", st.Mode))
			// 通过本地 SOCKS5 验证 WARP 是否生效
			proxyURL := fmt.Sprintf("socks5://127.0.0.1:%d", defaultSocks5Port)
			out, err := exec.Command("curl", "-s", "--max-time", "10", "--proxy", proxyURL, "https://www.cloudflare.com/cdn-cgi/trace").CombinedOutput()
			if err == nil && strings.Contains(string(out), "warp=on") {
				uiInfo("✓ SOCKS5 代理验证通过 (warp=on)")
				// 显示代理出口 IP
				proxyIP, _ := exec.Command("curl", "-s", "--max-time", "10", "--proxy", proxyURL, "-4", "ip.gs").CombinedOutput()
				if ip := strings.TrimSpace(string(proxyIP)); ip != "" {
					uiInfo(fmt.Sprintf("  代理出口 IP: %s", ip))
				}
				uiInfo(fmt.Sprintf("  外部代理地址: socks5://<你的VPS_IP>:%d", externalPort))
				uiInfo("  开启透明代理后 VPS 自身流量也会走 WARP（菜单选 t）")
				return
			}
			uiHint("  SOCKS5 代理验证中...")
			if i < 2 {
				continue
			}
			uiInfo(fmt.Sprintf("  代理地址: socks5://<你的VPS_IP>:%d", externalPort))
			uiHint("  提示: 代理可能需要几秒钟生效，请稍后验证")
			return
		}
		if i < 2 {
			uiInfo(fmt.Sprintf("  等待中... (%d/3)", i+1))
		}
	}
	uiWarning("Zero Trust Proxy 连接验证超时")
	uiHint("  验证命令: curl --proxy socks5://127.0.0.1:40000 https://www.cloudflare.com/cdn-cgi/trace")
}

func installDependencies(sysInfo *SysInfo) error {
	packages := []string{"curl", "jq"}
	if sysInfo.PkgManager == "apt" {
		// resolvconf 提供 DNS 管理（wg-quick 用它设置 DNS），
		// 但 Ubuntu 24.04+ 已移除 openresolv，改用 systemd-resolved。
		// 如果 resolvconf 命令已存在则跳过安装。
		if _, err := exec.LookPath("resolvconf"); err != nil {
			if err := installPackages("apt", []string{"openresolv"}); err != nil {
				// openresolv 不可用时尝试 resolvconf 包
				if err := installPackages("apt", []string{"resolvconf"}); err != nil {
					uiHint("  resolvconf/openresolv 均不可用，DNS 由 systemd-resolved 管理")
				}
			}
		}
	}
	return installPackages(sysInfo.PkgManager, packages)
}

func installPackages(pkgManager string, packages []string) error {
	for _, pkg := range packages {
		if _, err := exec.LookPath(pkg); err == nil {
			continue
		}
		uiInfo(fmt.Sprintf("安装 %s...", pkg))
		if err := waitForDpkgLock(pkgManager); err != nil {
			return err
		}
		var cmd *exec.Cmd
		switch pkgManager {
		case "apt":
			cmd = exec.Command("apt-get", "install", "-y", pkg)
		case "yum":
			cmd = exec.Command("yum", "install", "-y", pkg)
		case "dnf":
			cmd = exec.Command("dnf", "install", "-y", pkg)
		default:
			return fmt.Errorf("不支持的包管理器: %s", pkgManager)
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("安装 %s 失败: %v", pkg, err)
		}
	}
	return nil
}

func installWarpCLI(sysInfo *SysInfo) error {
	if isWarpCLIInstalled() {
		uiInfo("warp-cli 已安装，跳过")
		return nil
	}
	if sysInfo.PkgManager != "apt" {
		return fmt.Errorf("暂不支持 %s 安装 warp-cli", sysInfo.PkgManager)
	}
	if err := waitForDpkgLock("apt"); err != nil {
		return err
	}
	cmd := exec.Command("bash", "-c", fmt.Sprintf("curl -fsSL %s | gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg", warpClientRepoDebian))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("添加 GPG key 失败: %v", err)
	}
	aptLine := fmt.Sprintf("deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] %s/ %s main", warpClientAptList, sysInfo.Codename)
	if err := os.WriteFile("/etc/apt/sources.list.d/cloudflare-client.list", []byte(aptLine+"\n"), 0644); err != nil {
		return err
	}
	if err := waitForDpkgLock("apt"); err != nil {
		return err
	}
	if err := exec.Command("apt-get", "update").Run(); err != nil {
		return fmt.Errorf("apt update 失败: %v", err)
	}
	if err := waitForDpkgLock("apt"); err != nil {
		return err
	}
	if err := exec.Command("apt-get", "install", "-y", "cloudflare-warp").Run(); err != nil {
		return fmt.Errorf("安装 cloudflare-warp 失败: %v", err)
	}
	exec.Command("systemctl", "enable", "--now", "warp-svc").Run()
	time.Sleep(2 * time.Second)
	// 安装后立即断开，防止 warp-svc 自动连接导致 SSH 中断
	exec.Command("warp-cli", "--accept-tos", "disconnect").Run()
	return nil
}

func doUninstall() (bool, error) {
	uiHeader("开始卸载 WARP")
	uiSeparator()
	hasWG := wgIsInstalled()
	hasZT := isWarpCLIInstalled()
	if !hasWG && !hasZT {
		uiInfo("未检测到已安装的组件")
		return false, nil
	}
	uiStep(1, 7, "停止所有服务")
	if hasWG {
		wgStop()
		exec.Command("systemctl", "stop", "wg-quick@warp").Run()
		exec.Command("systemctl", "disable", "wg-quick@warp").Run()
	}
	if hasZT {
		ztDisconnect()
		cleanupTransparentProxy()
		removeProxyService()
		removeReverseProxyService()
		removeWarpAutoConnect()
		exec.Command("systemctl", "stop", "warp-svc").Run()
	}
	uiStep(2, 7, "清理网络规则")
	cleanupNetworkRules()
	uiStep(3, 7, "清理配置文件")
	cleanupConfigFiles()
	uiStep(4, 7, "卸载软件包")
	if hasZT {
		removeZeroTrustPackage()
	}
	removeWgPackages()
	removeRedsocksPackage()
	uiStep(5, 7, "恢复 DNS 配置")
	restoreDNS()
	uiStep(6, 7, "验证网络连通性")
	verifyNetworkAfterUninstall()
	uiStep(7, 7, "卸载完成")
	uiInfo("✓ 所有 WARP 组件已卸载")
	return true, nil
}

func cleanupNetworkRules() {
	for i := 0; i < 3; i++ {
		exec.Command("ip", "rule", "del", "not", "fwmark", "51820", "table", "51820").Run()
		exec.Command("ip", "rule", "del", "table", "51820").Run()
		exec.Command("ip", "-6", "rule", "del", "not", "fwmark", "51820", "table", "51820").Run()
		exec.Command("ip", "-6", "rule", "del", "table", "51820").Run()
	}
	// 清理 PostUp 添加的 "from <VPS-IP> table main priority 10" 规则
	for _, proto := range []string{"-4", "-6"} {
		out, _ := exec.Command("ip", proto, "rule", "show", "priority", "10").Output()
		for _, line := range strings.Split(string(out), "\n") {
			if idx := strings.Index(line, "from "); idx >= 0 {
				rest := strings.Fields(line[idx:])
				if len(rest) >= 2 {
					exec.Command("ip", proto, "rule", "del", "from", rest[1], "table", "main", "priority", "10").Run()
				}
			}
		}
	}
	exec.Command("ip", "route", "flush", "table", "51820").Run()
	exec.Command("ip", "-6", "route", "flush", "table", "51820").Run()
	exec.Command("iptables", "-t", "nat", "-F", "WARP_PROXY").Run()
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-j", "WARP_PROXY").Run()
	exec.Command("iptables", "-t", "nat", "-X", "WARP_PROXY").Run()
	exec.Command("ip6tables", "-t", "nat", "-F", "WARP_PROXY").Run()
	exec.Command("ip6tables", "-t", "nat", "-D", "OUTPUT", "-j", "WARP_PROXY").Run()
	exec.Command("ip6tables", "-t", "nat", "-X", "WARP_PROXY").Run()
	exec.Command("nft", "delete", "table", "ip", "warp_proxy").Run()
	exec.Command("nft", "delete", "table", "ip6", "warp_proxy").Run()
}

func cleanupConfigFiles() {
	for _, f := range []string{warpConfPath, warpAccountPath, warpConfPath + ".bak", warpAccountPath + ".bak", zeroTrustConfigPath, "/var/lib/cloudflare-warp/mdm.xml", "/var/lib/cloudflare-warp/reg.json", "/var/lib/cloudflare-warp/config.json", "/etc/systemd/system/warpgo-reverse-proxy.service"} {
		os.Remove(f)
	}
}

func removeZeroTrustPackage() {
	uiInfo("  卸载 cloudflare-warp...")
	waitForDpkgLock("apt")
	exec.Command("apt-get", "purge", "-y", "cloudflare-warp").Run()
	os.RemoveAll("/var/lib/cloudflare-warp")
	os.RemoveAll("/etc/cloudflare-warp")
	os.Remove("/etc/apt/sources.list.d/cloudflare-client.list")
	os.Remove("/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg")
}

func removeWgPackages() {
	uiInfo("  清理 wireguard 相关...")
	waitForDpkgLock("apt")
	exec.Command("apt-get", "purge", "-y", "wireguard-tools").Run()
	os.Remove(wireguardGoPath)
}

func removeRedsocksPackage() {
	if _, err := exec.LookPath("redsocks"); err != nil {
		return // redsocks 未安装，跳过
	}
	uiInfo("  清理 redsocks...")
	exec.Command("systemctl", "stop", "redsocks").Run()
	exec.Command("systemctl", "disable", "redsocks").Run()
	waitForDpkgLock("apt")
	exec.Command("apt-get", "purge", "-y", "redsocks").Run()
	os.Remove("/etc/redsocks.conf")
}

// verifyNetworkAfterUninstall 卸载后验证网络连通性，确保 SSH 未中断
func verifyNetworkAfterUninstall() {
	// 检查默认路由是否存在
	out, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		uiWarning("⚠ 未检测到默认路由，网络可能异常")
		uiHint("  请手动检查: ip route show default")
		return
	}
	uiInfo("✓ 默认路由正常")

	// 尝试 DNS 解析
	if err := exec.Command("nslookup", "cloudflare.com").Run(); err != nil {
		uiWarning("⚠ DNS 解析异常，请检查 /etc/resolv.conf")
	} else {
		uiInfo("✓ DNS 解析正常")
	}

	// 尝试 ping 网关
	if err := exec.Command("ping", "-c", "1", "-W", "3", "1.1.1.1").Run(); err != nil {
		uiWarning("⚠ 外网连通性异常，请检查网络")
	} else {
		uiInfo("✓ 外网连通正常")
	}
}

func restoreDNS() {
	if data, err := os.ReadFile("/etc/resolv.conf.bak"); err == nil && len(data) > 0 {
		if err := os.WriteFile("/etc/resolv.conf", data, 0644); err == nil {
			uiInfo("  已从备份恢复 DNS 配置")
			return
		}
	}
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		content := strings.TrimSpace(string(data))
		if content != "" && strings.Contains(content, "nameserver") {
			return
		}
	}
	os.WriteFile("/etc/resolv.conf", []byte("nameserver 8.8.8.8\nnameserver 8.8.4.4\n"), 0644)
	uiInfo("  已创建默认 DNS 配置")
}

// runDiagnostics 诊断 WARP 连接问题，在 VPS 上运行 ./warpgo -diag 即可。
func runDiagnostics() {
	uiHeader("WARP 连接诊断")
	uiSeparator()

	// 1. 检查 WireGuard 工具
	uiStep(1, 7, "检查 WireGuard 工具")
	if _, err := exec.LookPath("wg"); err != nil {
		uiWarning("  wg 命令未找到")
	} else {
		uiInfo("  ✓ wg 已安装")
	}
	if _, err := exec.LookPath("wg-quick"); err != nil {
		uiWarning("  wg-quick 命令未找到")
	} else {
		uiInfo("  ✓ wg-quick 已安装")
	}

	// 2. 检查内核模块
	uiStep(2, 7, "检查 WireGuard 内核模块")
	if out, err := exec.Command("modprobe", "wireguard").CombinedOutput(); err != nil {
		uiWarning(fmt.Sprintf("  modprobe wireguard 失败: %s", strings.TrimSpace(string(out))))
		uiHint("  需要 Linux 5.6+ 内核或安装 wireguard-go")
	} else {
		uiInfo("  ✓ WireGuard 内核模块可用")
	}

	// 3. 检查配置文件
	uiStep(3, 7, "检查 WireGuard 配置")
	if _, err := os.Stat(warpConfPath); err != nil {
		uiWarning("  /etc/wireguard/warp.conf 不存在")
	} else {
		data, _ := os.ReadFile(warpConfPath)
		conf := string(data)
		uiInfo("  ✓ 配置文件存在")

		// 检查关键字段
		if !strings.Contains(conf, "PrivateKey") {
			uiWarning("  ❌ PrivateKey 缺失")
		}
		if !strings.Contains(conf, "Endpoint") {
			uiWarning("  ❌ Endpoint 缺失")
		}
		if !strings.Contains(conf, "PublicKey") {
			uiWarning("  ❌ Peer PublicKey 缺失")
		}
		// 提取 endpoint
		for _, line := range strings.Split(conf, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "Endpoint") {
				uiInfo(fmt.Sprintf("  Endpoint: %s", strings.TrimSpace(strings.SplitN(line, "=", 2)[1])))
			}
		}
	}

	// 4. 检查账号数据
	uiStep(4, 7, "检查注册数据")
	if acc, err := loadAccountFromFile(warpAccountPath); err != nil {
		uiWarning(fmt.Sprintf("  账号文件读取失败: %v", err))
	} else {
		uiInfo(fmt.Sprintf("  ID: %s", acc.ID[:min(8, len(acc.ID))]))
		if acc.PrivateKey == "" {
			uiWarning("  ❌ PrivateKey 为空")
		} else {
			uiInfo("  ✓ PrivateKey 已设置")
		}
		if acc.IPv4 == "" && acc.IPv6 == "" {
			uiWarning("  ❌ IPv4 和 IPv6 都为空")
		} else {
			uiInfo(fmt.Sprintf("  IPv4: %s  IPv6: %s", acc.IPv4, acc.IPv6))
		}
	}

	// 5. 检查接口状态
	uiStep(5, 7, "检查 WireGuard 接口")
	if out, err := exec.Command("wg", "show", warpIfName).CombinedOutput(); err != nil {
		uiWarning("  warp 接口不存在或未启动")
	} else {
		uiInfo("  ✓ warp 接口存在")
		output := string(out)
		if strings.Contains(output, "latest handshake") {
			uiInfo("  ✓ 已有握手记录")
		} else {
			uiWarning("  ⚠ 无握手记录 — Endpoint 可能不可达")
		}
		// 显示简要状态
		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				uiInfo(fmt.Sprintf("  %s", line))
			}
		}
	}

	// 6. 测试 UDP 连通性
	uiStep(6, 7, "测试 UDP 连通性")
	endpoints := []string{"162.159.192.1:2408", "162.159.193.1:2408", "162.159.204.1:2408"}
	// 从配置文件读取实际 endpoint
	if data, err := os.ReadFile(warpConfPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "Endpoint") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					ep := strings.TrimSpace(parts[1])
					if ep != "" {
						endpoints = append([]string{ep}, endpoints...)
					}
				}
			}
		}
	}
	seen := map[string]bool{}
	for _, ep := range endpoints {
		if seen[ep] {
			continue
		}
		seen[ep] = true
		conn, err := net.DialTimeout("udp", ep, 5*time.Second)
		if err != nil {
			uiWarning(fmt.Sprintf("  ❌ %s — %v", ep, err))
			continue
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = conn.Write([]byte{0x01})
		if err != nil {
			uiWarning(fmt.Sprintf("  ❌ %s — 发送失败: %v", ep, err))
			conn.Close()
			continue
		}
		buf := make([]byte, 64)
		_, err = conn.Read(buf)
		conn.Close()
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			uiInfo(fmt.Sprintf("  ✓ %s — 可达", ep))
		} else if err != nil {
			uiHint(fmt.Sprintf("  ⚠ %s — %v", ep, err))
		} else {
			uiInfo(fmt.Sprintf("  ✓ %s — 收到回复", ep))
		}
	}

	// 7. 测试 Cloudflare trace
	uiStep(7, 7, "测试 Cloudflare 连通性")
	uiInfo("  检测 warp 状态...")
	warpOn, gwOn := getTraceStatus()
	if warpOn {
		uiInfo("  ✓ warp=on — WARP 已激活")
	} else {
		uiWarning("  ❌ warp≠on — WARP 未激活")
	}
	uiInfo(fmt.Sprintf("  gateway=%v", gwOn))

	ip := getIP("https://api4.ipify.org")
	if ip != "" {
		uiInfo(fmt.Sprintf("  当前出口 IPv4: %s", ip))
	} else {
		uiWarning("  无法获取出口 IPv4（网络可能不通）")
	}

	uiSeparator()
	uiHint("诊断完成。如果 UDP 不可达，建议用菜单 e 切换优选 IP")
	uiHint("如需帮助，请把以上输出完整贴出")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func waitForDpkgLock(pkgManager string) error {
	if pkgManager != "apt" {
		return nil
	}
	lockFiles := []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock", "/var/lib/apt/lists/lock"}
	for i := 0; i < 30; i++ {
		locked := false
		for _, lf := range lockFiles {
			if _, err := exec.Command("fuser", lf).Output(); err == nil {
				locked = true
				break
			}
		}
		if !locked {
			return nil
		}
		if i == 0 {
			uiInfo("等待包管理器锁释放...")
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("等待 dpkg 锁超时（60秒）")
}

// ════════════════════════════════════════════════════════════════════════════════
// CLI 参数解析 + 交互菜单
// ════════════════════════════════════════════════════════════════════════════════

func execute() {
	var (
		optInstallV4   bool
		optInstallV6   bool
		optInstallDual bool
		optZeroTrust   bool
		optZeroTrustWG bool
		optUninstall   bool
		optVersion     bool
	)

	flag.BoolVar(&optInstallV4, "4", false, "安装 IPv4 WARP")
	flag.BoolVar(&optInstallV6, "6", false, "安装 IPv6 WARP")
	flag.BoolVar(&optInstallDual, "d", false, "安装双栈 WARP")
	flag.BoolVar(&optZeroTrust, "z", false, "配置 Zero Trust Proxy (warp-cli proxy + socat)")
	flag.BoolVar(&optZeroTrustWG, "w", false, "配置 Zero Trust (WireGuard)")
	flag.BoolVar(&optUninstall, "u", false, "卸载所有 WARP 组件")
	flag.BoolVar(&optVersion, "v", false, "显示版本")
	flag.BoolVar(&optVersion, "version", false, "显示版本")
	optDiag := flag.Bool("diag", false, "诊断 WARP 连接问题")
	flag.Parse()

	if optVersion {
		fmt.Printf("WarpGo v%s\n", appVersion)
		return
	}

	sysInfo, err := detectSystem()
	if err != nil {
		uiError(fmt.Sprintf("系统检测失败: %v", err))
	}
	if err := checkRoot(); err != nil {
		uiError(err.Error())
	}

	if *optDiag {
		runDiagnostics()
		return
	}

	opts := &InstallOptions{}

	if optInstallV4 {
		opts.Mode = modeWireGuardV4
		if err := doInstall(sysInfo, opts); err != nil {
			uiError(fmt.Sprintf("安装失败: %v", err))
		}
		return
	}
	if optInstallV6 {
		opts.Mode = modeWireGuardV6
		if err := doInstall(sysInfo, opts); err != nil {
			uiError(fmt.Sprintf("安装失败: %v", err))
		}
		return
	}
	if optInstallDual {
		opts.Mode = modeWireGuardDual
		if err := doInstall(sysInfo, opts); err != nil {
			uiError(fmt.Sprintf("安装失败: %v", err))
		}
		return
	}
	if optZeroTrust {
		opts.Mode = modeZeroTrust
		if err := doInstall(sysInfo, opts); err != nil {
			uiError(fmt.Sprintf("安装失败: %v", err))
		}
		return
	}
	if optZeroTrustWG {
		opts.Mode = modeZeroTrustWG
		opts.ZeroTrustOrg = os.Getenv("WARP_ORG")
		opts.ZeroTrustClientID = os.Getenv("WARP_CLIENT_ID")
		opts.ZeroTrustClientSecret = os.Getenv("WARP_CLIENT_SECRET")
		if opts.ZeroTrustOrg == "" || opts.ZeroTrustClientID == "" || opts.ZeroTrustClientSecret == "" {
			uiError("请设置环境变量: WARP_ORG, WARP_CLIENT_ID, WARP_CLIENT_SECRET")
		}
		if err := doInstall(sysInfo, opts); err != nil {
			uiError(fmt.Sprintf("安装失败: %v", err))
		}
		return
	}
	if optUninstall {
		if _, err := doUninstall(); err != nil {
			uiError(fmt.Sprintf("卸载失败: %v", err))
		}
		return
	}

	showMainMenu(sysInfo)
}

func showMainMenu(sysInfo *SysInfo) {
	status := getNetworkStatus()

	for {
		wgInstalled := wgIsInstalled()
		wgRunning := wgIsRunning()
		ztInstalled := isWarpCLIInstalled()
		ztStatus, _ := getZTStatus()

		// 一次性检测 Teams 状态（消除原 4 处重复）
		var isTeams bool
		var teamName string
		if acc, err := loadAccountFromFile(warpAccountPath); err == nil && acc.IsTeams {
			isTeams = true
			teamName = acc.OrgName
		}

		connectionType := ""
		connectionInfo := ""
		isConnected := false

		if ztInstalled && ztStatus.Connected {
			connectionType = "Zero Trust Proxy"
			isConnected = true
			if ztCfg, err := loadZTConfig(); err == nil {
				if ztCfg.OrgName != "" {
					connectionInfo = fmt.Sprintf("组织: %s", ztCfg.OrgName)
				}
				if ztCfg.ExternalPort > 0 {
					connectionInfo += fmt.Sprintf(" | 端口: %d", ztCfg.ExternalPort)
				}
			}
		} else if wgInstalled && wgRunning {
			if isTeams {
				connectionType = "Zero Trust (WireGuard)"
				isConnected = true
				if teamName != "" {
					connectionInfo = fmt.Sprintf("组织: %s", teamName)
				}
			} else {
				connectionType = "WARP WireGuard"
				isConnected = true
			}
		} else if wgInstalled {
			if isTeams {
				connectionType = "Zero Trust (WireGuard) (已停止)"
			} else {
				connectionType = "WARP WireGuard (已停止)"
			}
		} else if ztInstalled {
			connectionType = "Zero Trust Proxy (已断开)"
		} else {
			connectionType = "未安装"
		}

		printStatusPanel(appVersion, sysInfo.String(), connectionType, connectionInfo, status.String())

		// 显示详细状态
		if isConnected {
			if ztInstalled && ztStatus.Connected {
				printStatusLine("Zero Trust Proxy", "已连接", true)
				if ztStatus.Mode != "" {
					printInfoLine("运行模式", ztStatus.Mode)
				}
				if ztCfg, err := loadZTConfig(); err == nil {
					extPort := ztCfg.ExternalPort
					if extPort <= 0 {
						extPort = defaultSocks5Port
					}
					printInfoLine("代理地址", fmt.Sprintf("socks5://127.0.0.1:%d (本地)", defaultSocks5Port))
					printInfoLine("外部地址", fmt.Sprintf("socks5://<VPS_IP>:%d", extPort))
				}
				if isTransparentProxyRunning() {
					printStatusLine("透明代理", "已开启 (VPS 流量走 WARP)", true)
				} else {
					printInfoLine("透明代理", "未开启 (VPS 流量直连，菜单选 t 开启)")
				}
			} else if wgInstalled && wgRunning {
				cfgStatus := getWgConfigStatus()
				stackStr := "双栈"
				if cfgStatus.StackMode == stackIPv4 {
					stackStr = "IPv4"
				} else if cfgStatus.StackMode == stackIPv6 {
					stackStr = "IPv6"
				}
				if isTeams {
					printStatusLine("Zero Trust (WG)", fmt.Sprintf("全局 %s", stackStr), true)
				} else {
					printStatusLine("WARP", fmt.Sprintf("全局 %s", stackStr), true)
				}
			}
		} else if wgInstalled {
			if isTeams {
				printStatusLine("Zero Trust (WG)", "已停止", false)
			} else {
				printStatusLine("WARP", "已停止", false)
			}
		} else if ztInstalled {
			printStatusLine("Zero Trust Proxy", "已断开", false)
		}

		// 动态菜单
		var items []MenuItem
		if !wgInstalled && !ztInstalled {
			items = append(items,
				MenuItem{Key: "1", Label: "安装 WARP", Description: "使用 WireGuard 内核运行，全局接管所有网络流量"},
				MenuItem{Key: "2", Label: "配置 Zero Trust Proxy", Description: "proxy 模式接入，SOCKS5 代理 + socat 反代"},
				MenuItem{Key: "3", Label: "配置 Zero Trust (WireGuard)", Description: "使用 WireGuard 接入 Cloudflare Teams 组织网络"},
			)
		} else if wgInstalled {
			items = append(items,
				MenuItem{Key: "1", Label: "启停 WARP", Description: "开关 WireGuard 接口"},
				MenuItem{Key: "2", Label: "切换 IPv4/IPv6/双栈", Description: "修改出口网络类型"},
				MenuItem{Key: "e", Label: "切换优选 IP", Description: "自定义 Cloudflare WARP Endpoint"},
			)
		} else if ztInstalled {
			items = append(items,
				MenuItem{Key: "1", Label: "连接/断开 Zero Trust", Description: "控制 warp-cli 连接状态"},
				MenuItem{Key: "t", Label: "切换透明代理", Description: "开启/关闭 VPS 全局流量走 WARP（改变出口 IP）"},
			)
		}
		if wgInstalled || ztInstalled {
			items = append(items, MenuItem{Key: "u", Label: "完全卸载", Description: "清理所有已安装的组件和配置"})
		}
		items = append(items,
			MenuItem{Key: "i", Label: "刷新状态", Description: "重新获取网络状态和 IP 信息"},
			MenuItem{Key: "h", Label: "帮助", Description: "显示命令行参数和使用说明"},
			MenuItem{Key: "0", Label: "退出程序"},
		)

		choice := showMenu("请选择你要执行的操作", items)

		switch choice {
		case "1":
			if !wgInstalled && !ztInstalled {
				installWarpMenu(sysInfo)
			} else if wgInstalled {
				if err := wgToggle(); err != nil {
					uiWarning(fmt.Sprintf("操作失败: %v", err))
				}
			} else if ztInstalled {
				st, _ := getZTStatus()
				if st.Connected {
					if err := ztDisconnect(); err != nil {
						uiWarning(fmt.Sprintf("断开连接失败: %v", err))
					}
				} else {
					if err := ztConnect(); err != nil {
						uiWarning(fmt.Sprintf("连接失败: %v", err))
					}
				}
			}
		case "2":
			if !wgInstalled && !ztInstalled {
				installZeroTrustMenu(sysInfo)
			} else if wgInstalled {
				stackMenu()
			}
		case "3":
			if !wgInstalled && !ztInstalled {
				installZeroTrustWGMenu(sysInfo)
			}
		case "e", "E":
			if wgInstalled {
				switchEndpointMenu()
			}
		case "t", "T":
			if ztInstalled {
				toggleTransparentProxy()
			}
		case "i", "I":
			uiInfo("正在刷新网络状态...")
			status = getNetworkStatus()
			uiInfo("✓ 网络状态已更新")
		case "h", "H":
			showHelp()
		case "u", "U":
			if confirm("确定要完全卸载所有 WARP 相关组件吗？") {
				if _, err := doUninstall(); err != nil {
					uiWarning(fmt.Sprintf("卸载失败: %v", err))
				}
			}
		case "0":
			uiInfo("感谢使用 WarpGo！再见！")
			os.Exit(0)
		default:
			uiWarning("无效选项，请重新输入")
		}

		readInput("按回车键继续...")
	}
}

func installWarpMenu(sysInfo *SysInfo) {
	items := []MenuItem{
		{Key: "1", Label: "安装 WARP IPv4", Description: "仅分配 IPv4 出口"},
		{Key: "2", Label: "安装 WARP IPv6", Description: "仅分配 IPv6 出口"},
		{Key: "3", Label: "安装 WARP 双栈", Description: "同时拥有 IPv4/IPv6 出口"},
		{Key: "0", Label: "返回上级目录"},
	}
	choice := showMenu("选择 WARP 网络模式", items)
	opts := &InstallOptions{}
	switch choice {
	case "1":
		opts.Mode = modeWireGuardV4
	case "2":
		opts.Mode = modeWireGuardV6
	case "3":
		opts.Mode = modeWireGuardDual
	case "0":
		return
	default:
		uiWarning("无效选项，返回主菜单")
		return
	}
	opts.Endpoint = readAndValidateEndpoint()
	if err := doInstall(sysInfo, opts); err != nil {
		uiWarning(fmt.Sprintf("安装失败: %v", err))
	}
}

func stackMenu() {
	items := []MenuItem{
		{Key: "1", Label: "切换为 IPv4 优先"},
		{Key: "2", Label: "切换为 IPv6 优先"},
		{Key: "3", Label: "切换为双栈均使用"},
		{Key: "0", Label: "返回上级"},
	}
	choice := showMenu("切换路由协议栈", items)
	switch choice {
	case "1":
		if err := switchStack(stackIPv4); err != nil {
			uiWarning(fmt.Sprintf("切换失败: %v", err))
		}
	case "2":
		if err := switchStack(stackIPv6); err != nil {
			uiWarning(fmt.Sprintf("切换失败: %v", err))
		}
	case "3":
		if err := switchStack(stackDual); err != nil {
			uiWarning(fmt.Sprintf("切换失败: %v", err))
		}
	}
}

func installZeroTrustMenu(sysInfo *SysInfo) {
	uiBlank()
	uiHint("【Zero Trust Proxy 配置说明】")
	uiHint("  使用 warp-cli proxy 模式接入，本地 SOCKS5 代理 + socat 反代")
	uiHint("  需要 Cloudflare 组织（Team）和 Service Token")
	uiHint("  获取路径: one.dash.cloudflare.com → Settings → WARP Client → Device enrollment")
	uiHint("  创建 Service Token: Access controls → Service credentials → Service Tokens")
	uiBlank()
	items := []MenuItem{
		{Key: "1", Label: "开始配置", Description: "输入组织名称、Service Token 和反代端口"},
		{Key: "0", Label: "返回上级菜单"},
	}
	choice := showMenu("Zero Trust Proxy 配置", items)
	switch choice {
	case "1":
		org := readInput("请输入 Zero Trust 组织名称 (Team Name): ")
		if org == "" {
			uiWarning("组织名称不能为空")
			return
		}
		clientID := readInput("请输入 Service Token 的 Client ID: ")
		if clientID == "" {
			uiWarning("Client ID 不能为空")
			return
		}
		clientSecret := readInput("请输入 Service Token 的 Client Secret: ")
		if clientSecret == "" {
			uiWarning("Client Secret 不能为空")
			return
		}
		extPortStr := readInput(fmt.Sprintf("请输入外部代理端口 (留空使用默认 %d): ", defaultSocks5Port))
		extPort := defaultSocks5Port
		if strings.TrimSpace(extPortStr) != "" {
			if p, err := strconv.Atoi(strings.TrimSpace(extPortStr)); err == nil && p > 0 && p <= 65535 {
				extPort = p
			} else {
				uiWarning(fmt.Sprintf("端口无效，使用默认值 %d", defaultSocks5Port))
			}
		}
		// 预先保存外部端口到配置
		cfg := &ZeroTrustConfig{
			OrgName: org, ClientID: clientID, ClientSecret: clientSecret,
			UseProxyMode: true, Socks5Port: defaultSocks5Port, ExternalPort: extPort,
		}
		saveZTConfig(cfg)
		opts := &InstallOptions{
			Mode: modeZeroTrust, ZeroTrustOrg: org,
			ZeroTrustEnrollMode: enrollModeServiceToken, ZeroTrustClientID: clientID, ZeroTrustClientSecret: clientSecret,
		}
		if err := doInstall(sysInfo, opts); err != nil {
			uiWarning(fmt.Sprintf("安装失败: %v", err))
		}
	case "0":
		return
	default:
		uiWarning("无效选项，返回主菜单")
	}
}

func installZeroTrustWGMenu(sysInfo *SysInfo) {
	uiBlank()
	uiHint("【Zero Trust (WireGuard) 配置说明】")
	uiHint("  使用 WireGuard 直接接入 Cloudflare Zero Trust 组织网络")
	uiHint("  需要: 组织名称 (Team Name)、CF-Access-Client-Id、CF-Access-Client-Secret")
	uiHint("  获取路径: one.dash.cloudflare.com → Settings → WARP Client → Device enrollment")
	uiHint("  创建 Service Token: Access controls → Service credentials → Service Tokens")
	uiBlank()
	items := []MenuItem{
		{Key: "1", Label: "开始配置", Description: "输入组织名称和 Service Token"},
		{Key: "0", Label: "返回上级菜单"},
	}
	choice := showMenu("Zero Trust (WireGuard) 配置", items)
	switch choice {
	case "1":
		org := readInput("请输入 Zero Trust 组织名称 (Team Name): ")
		if org == "" {
			uiWarning("组织名称不能为空")
			return
		}
		clientID := readInput("请输入 Service Token 的 Client ID: ")
		if clientID == "" {
			uiWarning("Client ID 不能为空")
			return
		}
		clientSecret := readInput("请输入 Service Token 的 Client Secret: ")
		if clientSecret == "" {
			uiWarning("Client Secret 不能为空")
			return
		}
		endpoint := readAndValidateEndpoint()
		opts := &InstallOptions{
			Mode: modeZeroTrustWG, Endpoint: endpoint,
			ZeroTrustOrg: org, ZeroTrustEnrollMode: enrollModeServiceToken,
			ZeroTrustClientID: clientID, ZeroTrustClientSecret: clientSecret,
		}
		if err := doInstall(sysInfo, opts); err != nil {
			uiWarning(fmt.Sprintf("安装失败: %v", err))
		}
	case "0":
		return
	default:
		uiWarning("无效选项，返回主菜单")
	}
}

func readAndValidateEndpoint() string {
	uiBlank()
	uiHint("【优选 IP 说明】")
	uiHint("  可填入 Cloudflare WARP 优选 IP，留空则使用默认值")
	uiHint("  格式: IP:端口  例如: 162.159.192.2:2408")
	uiHint("  常用端口: 2408、500、1701、4500")
	uiHint("  常用优选段: 162.159.192.0/24、162.159.204.0/24")
	uiBlank()
	input := readInput("请输入优选 IP (留空使用默认值): ")
	if strings.TrimSpace(input) == "" {
		return ""
	}
	endpoint := strings.TrimSpace(input)
	if !validateEndpoint(endpoint) {
		uiWarning(fmt.Sprintf("Endpoint 格式无效: %s，将使用默认值", endpoint))
		return ""
	}
	uiInfo(fmt.Sprintf("使用自定义 Endpoint: %s", endpoint))
	return endpoint
}

func validateEndpoint(endpoint string) bool {
	if strings.HasPrefix(endpoint, "[") {
		idx := strings.LastIndex(endpoint, "]:")
		if idx < 0 {
			return false
		}
		return validateIPAndPort(endpoint[1:idx], endpoint[idx+2:])
	}
	idx := strings.LastIndex(endpoint, ":")
	if idx <= 0 {
		return false
	}
	return validateIPAndPort(endpoint[:idx], endpoint[idx+1:])
}

func validateIPAndPort(ipStr, portStr string) bool {
	if net.ParseIP(ipStr) == nil {
		return false
	}
	port, err := strconv.Atoi(portStr)
	return err == nil && port >= 1 && port <= 65535
}

func switchEndpointMenu() {
	currentEP := getCurrentEndpoint()
	if currentEP == "" {
		currentEP = "162.159.192.1:2408"
	}
	uiBlank()
	uiHint("【切换优选 IP】")
	uiHint(fmt.Sprintf("  当前 Endpoint: %s", currentEP))
	uiHint("  可填入 Cloudflare WARP 优选 IP，留空则取消")
	uiHint("  格式: IP:端口  例如: 162.159.192.2:2408")
	uiHint("  常用端口: 2408、500、1701、4500")
	uiHint("  常用优选段: 162.159.192.0/24、162.159.204.0/24")
	uiHint("  连接失败会自动恢复原 Endpoint")
	uiBlank()
	input := readInput("请输入新的优选 IP (留空取消): ")
	if strings.TrimSpace(input) == "" {
		uiInfo("已取消")
		return
	}
	endpoint := strings.TrimSpace(input)
	if !validateEndpoint(endpoint) {
		uiWarning(fmt.Sprintf("Endpoint 格式无效: %s", endpoint))
		return
	}
	uiInfo(fmt.Sprintf("正在切换到 %s ...", endpoint))
	if err := switchEndpoint(endpoint); err != nil {
		uiWarning(fmt.Sprintf("切换失败: %v", err))
	} else {
		uiInfo(fmt.Sprintf("✓ 优选 IP 已切换为: %s", endpoint))
	}
}

func showHelp() {
	uiBlank()
	uiHeader("WarpGo 命令行参数")
	uiSeparator()
	uiHint("  -v    显示版本信息")
	uiHint("  -4    安装 IPv4 WARP（WireGuard）")
	uiHint("  -6    安装 IPv6 WARP（WireGuard）")
	uiHint("  -d    安装双栈 WARP（WireGuard）")
	uiHint("  -z    配置 Zero Trust Proxy（warp-cli proxy 模式 + socat 反代）")
	uiHint("  -w    配置 Zero Trust（WireGuard，需要环境变量）")
	uiHint("  -u    完全卸载所有组件")
	uiBlank()
	uiHeader("使用示例")
	uiSeparator()
	uiHint("  ./warpgo -4          # 安装 IPv4 WARP")
	uiHint("  ./warpgo -d          # 安装双栈 WARP")
	uiHint("  ./warpgo -z          # 配置 Zero Trust Proxy (SOCKS5 + 反代)")
	uiHint("  WARP_ORG=team WARP_CLIENT_ID=xxx WARP_CLIENT_SECRET=yyy ./warpgo -w")
	uiHint("  ./warpgo -u          # 完全卸载")
	uiBlank()
	uiHeader("交互模式")
	uiSeparator()
	uiHint("  直接运行 ./warpgo 进入交互菜单")
	uiHint("  支持 WARP 安装/管理、Zero Trust 配置、卸载等功能")
	uiBlank()
}

// ════════════════════════════════════════════════════════════════════════════════
// 入口
// ════════════════════════════════════════════════════════════════════════════════

func main() {
	execute()
}

package cli

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/ssl"
)

type statusOutput struct {
	Version    string                 `json:"version"`
	Build      string                 `json:"build"`
	ConfigFile string                 `json:"config_file"`
	Server     map[string]interface{} `json:"server"`
	Counts     map[string]int         `json:"counts"`
	SSL        map[string]interface{} `json:"ssl"`
	MCP        map[string]interface{} `json:"mcp"`
}

type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type doctorOutput struct {
	ConfigFile string         `json:"config_file"`
	Checks     []doctorCheck  `json:"checks"`
	Summary    map[string]int `json:"summary"`
}

// RegisterOpsCommands 注册运维类 CLI 命令。
func (m *Manager) RegisterOpsCommands() {
	m.RegisterCommand(&Command{
		Name:        "status",
		Description: "Show current config and runtime-oriented summary",
		Handler: func(args []string) error {
			return m.showStatus(args)
		},
	})
	m.RegisterCommand(&Command{
		Name:        "doctor",
		Description: "Run local diagnostics for config, certs, sites, and MCP",
		Handler: func(args []string) error {
			return m.runDoctor(args)
		},
	})
}

func (m *Manager) showStatus(args []string) error {
	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}
	out := m.buildStatusOutput()
	if hasFlag(args, "--json", "-json") {
		return printJSON(out)
	}

	fmt.Printf("SSLcat v%s (build: %s)\n", strings.TrimPrefix(out.Version, "v"), out.Build)
	fmt.Printf("配置文件: %s\n", out.ConfigFile)
	fmt.Printf("监听地址: %s:%d (HTTPS: %v, HTTP/2: %v, HTTP/3: %v)\n",
		out.Server["host"], out.Server["port"], out.Server["https"], out.Server["http2"], out.Server["http3"])
	fmt.Printf("代理规则: %d（启用 %d）\n", out.Counts["proxy_rules"], out.Counts["enabled_proxy_rules"])
	fmt.Printf("静态站点: %d（启用 %d）\n", out.Counts["static_sites"], out.Counts["enabled_static_sites"])
	fmt.Printf("PHP 站点: %d（启用 %d）\n", out.Counts["php_sites"], out.Counts["enabled_php_sites"])
	fmt.Printf("磁盘证书: %d（30 天内到期 %d）\n", out.Counts["certificates"], out.Counts["certs_expiring_30d"])
	fmt.Printf("MCP: enabled=%v, tokens=%d\n", out.MCP["enabled"], out.Counts["mcp_tokens"])
	return nil
}

func (m *Manager) buildStatusOutput() statusOutput {
	cfg := m.config
	certs := listCertsQuiet(cfg)
	expiring := 0
	now := time.Now()
	for _, cert := range certs {
		if !cert.SelfSigned && cert.ExpiresAt.After(now) && cert.ExpiresAt.Sub(now) <= 30*24*time.Hour {
			expiring++
		}
	}

	return statusOutput{
		Version:    nonEmptyString(m.version, "dev"),
		Build:      nonEmptyString(m.build, "dev"),
		ConfigFile: effectiveConfigFile(m.configFile),
		Server: map[string]interface{}{
			"host":          cfg.Server.Host,
			"port":          effectiveServerPort(cfg),
			"https":         cfg.Server.EnableHTTPS,
			"http2":         cfg.Server.HTTP2Enabled,
			"http3":         cfg.Server.HTTP3Enabled,
			"admin_prefix":  cfg.AdminPrefix,
			"log_level":     cfg.Server.LogLevel,
			"data_dir":      cfg.Server.DataDir,
			"access_log":    cfg.Server.AccessLogEnabled,
			"error_log":     cfg.Server.ErrorLogEnabled,
			"session_store": cfg.Server.SessionStorage,
		},
		Counts: map[string]int{
			"proxy_rules":          len(cfg.Proxy.Rules),
			"enabled_proxy_rules":  countEnabledProxyRules(cfg),
			"static_sites":         len(cfg.StaticSites),
			"enabled_static_sites": countEnabledStaticSites(cfg),
			"php_sites":            len(cfg.PHPSites),
			"enabled_php_sites":    countEnabledPHPSites(cfg),
			"certificates":         len(certs),
			"certs_expiring_30d":   expiring,
			"mcp_tokens":           len(cfg.MCP.Tokens),
		},
		SSL: map[string]interface{}{
			"email_configured": strings.TrimSpace(cfg.SSL.Email) != "",
			"staging":          cfg.SSL.Staging,
			"cert_dir":         cfg.SSL.CertDir,
			"key_dir":          cfg.SSL.KeyDir,
			"auto_renew":       cfg.SSL.IsAutoRenewEnabled(),
		},
		MCP: map[string]interface{}{
			"enabled":      cfg.MCP.Enabled,
			"path_prefix":  cfg.GetMCPPathPrefix(),
			"audit_file":   cfg.GetMCPAuditFile(),
			"audit_enable": cfg.MCP.Audit.Enabled,
		},
	}
}

func (m *Manager) runDoctor(args []string) error {
	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}
	out := m.buildDoctorOutput()
	if hasFlag(args, "--json", "-json") {
		return printJSON(out)
	}

	fmt.Println("sslcat doctor")
	fmt.Printf("配置文件: %s\n\n", out.ConfigFile)
	for _, check := range out.Checks {
		fmt.Printf("[%s] %-18s %s\n", strings.ToUpper(check.Status), check.Name, check.Detail)
	}
	fmt.Printf("\n汇总: ok=%d warn=%d error=%d\n", out.Summary["ok"], out.Summary["warn"], out.Summary["error"])
	if out.Summary["error"] > 0 {
		return fmt.Errorf("doctor found %d error(s)", out.Summary["error"])
	}
	return nil
}

func (m *Manager) buildDoctorOutput() doctorOutput {
	cfg := m.config
	checks := []doctorCheck{}
	add := func(name, status, detail string) {
		checks = append(checks, doctorCheck{Name: name, Status: status, Detail: detail})
	}

	configFile := effectiveConfigFile(m.configFile)
	if _, err := os.Stat(configFile); err != nil {
		add("config_file", "warn", fmt.Sprintf("配置文件不可直接访问: %v", err))
	} else {
		add("config_file", "ok", "配置文件存在")
	}

	if result, err := config.ValidateConfigFile(configFile); err != nil {
		add("config_validate", "error", err.Error())
	} else if !result.Valid {
		add("config_validate", "error", fmt.Sprintf("%d 个错误，%d 个警告", len(result.Errors), len(result.Warnings)))
	} else if len(result.Warnings) > 0 {
		add("config_validate", "warn", fmt.Sprintf("配置有效，但有 %d 个警告", len(result.Warnings)))
	} else {
		add("config_validate", "ok", "配置校验通过")
	}

	port := effectiveServerPort(cfg)
	if port <= 0 || port > 65535 {
		add("server_port", "error", fmt.Sprintf("端口无效: %d", port))
	} else {
		add("server_port", "ok", fmt.Sprintf("%s:%d", nonEmptyString(cfg.Server.Host, "0.0.0.0"), port))
	}

	if os.Geteuid() != 0 && port < 1024 {
		add("privilege", "warn", "当前非 root 用户，绑定 1024 以下端口通常会失败")
	} else {
		add("privilege", "ok", "权限与端口配置未发现明显冲突")
	}

	checkDir(add, "ssl_cert_dir", cfg.SSL.CertDir)
	checkDir(add, "ssl_key_dir", cfg.SSL.KeyDir)
	checkDir(add, "data_dir", cfg.Server.DataDir)

	brokenProxy := countProxyRulesWithoutBackends(cfg)
	if brokenProxy > 0 {
		add("proxy_backends", "warn", fmt.Sprintf("%d 条代理规则没有可用后端", brokenProxy))
	} else {
		add("proxy_backends", "ok", fmt.Sprintf("%d 条代理规则后端配置可读", len(cfg.Proxy.Rules)))
	}

	missingStaticRoots := countMissingStaticRoots(cfg)
	if missingStaticRoots > 0 {
		add("static_sites", "warn", fmt.Sprintf("%d 个静态站点根目录不存在", missingStaticRoots))
	} else {
		add("static_sites", "ok", fmt.Sprintf("%d 个静态站点", len(cfg.StaticSites)))
	}

	missingPHPRoots := countMissingPHPRoots(cfg)
	if missingPHPRoots > 0 {
		add("php_sites", "warn", fmt.Sprintf("%d 个 PHP 站点根目录不存在", missingPHPRoots))
	} else {
		add("php_sites", "ok", fmt.Sprintf("%d 个 PHP 站点", len(cfg.PHPSites)))
	}

	if cfg.MCP.Enabled && len(cfg.MCP.Tokens) == 0 {
		add("mcp", "warn", "MCP 已启用但没有 token，请运行 sslcat mcp token create")
	} else {
		add("mcp", "ok", fmt.Sprintf("enabled=%v, tokens=%d", cfg.MCP.Enabled, len(cfg.MCP.Tokens)))
	}

	summary := map[string]int{"ok": 0, "warn": 0, "error": 0}
	for _, check := range checks {
		summary[check.Status]++
	}
	return doctorOutput{ConfigFile: configFile, Checks: checks, Summary: summary}
}

func listCertsQuiet(cfg *config.Config) []ssl.CertificateInfo {
	entries, err := os.ReadDir(cfg.SSL.CertDir)
	if err != nil {
		return nil
	}
	certs := []ssl.CertificateInfo{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".crt") {
			continue
		}
		certPath := filepath.Join(cfg.SSL.CertDir, entry.Name())
		pemBytes, err := os.ReadFile(certPath)
		if err != nil {
			continue
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil || block.Type != "CERTIFICATE" {
			continue
		}
		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		domain := strings.TrimSuffix(entry.Name(), ".crt")
		status := "有效"
		if time.Now().After(x509Cert.NotAfter) {
			status = "过期"
		} else if time.Now().Add(30 * 24 * time.Hour).After(x509Cert.NotAfter) {
			status = "即将过期"
		}
		selfSigned := x509Cert.Issuer.String() == x509Cert.Subject.String()
		issuer := "未知"
		if selfSigned {
			issuer = "自签名证书"
		} else if len(x509Cert.Issuer.Organization) > 0 {
			issuer = x509Cert.Issuer.Organization[0]
		} else if x509Cert.Issuer.CommonName != "" {
			issuer = x509Cert.Issuer.CommonName
		}
		certs = append(certs, ssl.CertificateInfo{
			Domain:     domain,
			IssuedAt:   x509Cert.NotBefore,
			ExpiresAt:  x509Cert.NotAfter,
			Status:     status,
			IsWildcard: strings.HasPrefix(domain, "*."),
			SelfSigned: selfSigned,
			Issuer:     issuer,
		})
	}
	return certs
}

func printJSON(v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func parseLooseFlags(args []string) map[string]string {
	flags := map[string]string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		key := strings.TrimLeft(arg, "-")
		if key == "" {
			continue
		}
		if eq := strings.IndexByte(key, '='); eq > 0 {
			flags[key[:eq]] = key[eq+1:]
			continue
		}
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			flags[key] = args[i+1]
			i++
		} else {
			flags[key] = "true"
		}
	}
	return flags
}

func hasFlag(args []string, names ...string) bool {
	for _, arg := range args {
		for _, name := range names {
			if arg == name {
				return true
			}
		}
	}
	return false
}

func nonEmptyString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func effectiveConfigFile(configFile string) string {
	if strings.TrimSpace(configFile) == "" {
		return "sslcat.conf"
	}
	return configFile
}

func effectiveServerPort(cfg *config.Config) int {
	if cfg.Server.PortMode == "custom" && cfg.Server.CustomPort > 0 {
		return cfg.Server.CustomPort
	}
	if cfg.Server.Port > 0 {
		return cfg.Server.Port
	}
	return 443
}

func countEnabledProxyRules(cfg *config.Config) int {
	count := 0
	for _, rule := range cfg.Proxy.Rules {
		if rule.Enabled {
			count++
		}
	}
	return count
}

func countEnabledStaticSites(cfg *config.Config) int {
	count := 0
	for _, site := range cfg.StaticSites {
		if site.Enabled {
			count++
		}
	}
	return count
}

func countEnabledPHPSites(cfg *config.Config) int {
	count := 0
	for _, site := range cfg.PHPSites {
		if site.Enabled {
			count++
		}
	}
	return count
}

func countProxyRulesWithoutBackends(cfg *config.Config) int {
	count := 0
	for i := range cfg.Proxy.Rules {
		rule := &cfg.Proxy.Rules[i]
		backends := rule.GetEffectiveBackends()
		enabled := 0
		for _, backend := range backends {
			if backend.Enabled && backend.Host != "" && backend.Port > 0 {
				enabled++
			}
		}
		if enabled == 0 {
			count++
		}
	}
	return count
}

func countMissingStaticRoots(cfg *config.Config) int {
	count := 0
	for _, site := range cfg.StaticSites {
		if site.Root != "" && !pathExists(site.Root) {
			count++
		}
	}
	return count
}

func countMissingPHPRoots(cfg *config.Config) int {
	count := 0
	for _, site := range cfg.PHPSites {
		if site.Root != "" && !pathExists(site.Root) {
			count++
		}
	}
	return count
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func checkDir(add func(string, string, string), name, path string) {
	if strings.TrimSpace(path) == "" {
		add(name, "warn", "未配置路径")
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		add(name, "warn", fmt.Sprintf("%s 不可访问: %v", path, err))
		return
	}
	if !info.IsDir() {
		add(name, "warn", fmt.Sprintf("%s 不是目录", path))
		return
	}
	add(name, "ok", path)
}

func parsePort(value string, fallback int) (int, error) {
	if value == "" {
		return fallback, nil
	}
	port, err := strconv.Atoi(value)
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("invalid port: %s", value)
	}
	return port, nil
}

func normalizeHostPort(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		if _, _, err := net.SplitHostPort(host); err == nil {
			return host
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func cleanPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	return filepath.Clean(path)
}

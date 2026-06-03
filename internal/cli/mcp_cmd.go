package cli

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/mcp"
)

// RegisterMCPCommands 注册 MCP 管理命令：
//   sslcat mcp token create --name <n> [--scopes read,site:write] [--expires-at RFC3339] [--ip-allowlist cidr,...] [--rate-limit 60/min] [--desc "..."]
//   sslcat mcp token list
//   sslcat mcp token revoke --name <n>
//   sslcat mcp doctor
//   sslcat mcp enable
//   sslcat mcp disable
func (m *Manager) RegisterMCPCommands() {
	m.RegisterCommand(&Command{
		Name:        "mcp",
		Description: "MCP 服务管理（token 颁发、状态检查等）",
		Handler: func(args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("mcp subcommand required: token | doctor | enable | disable")
			}
			switch args[0] {
			case "token":
				return m.mcpToken(args[1:])
			case "doctor":
				return m.mcpDoctor()
			case "enable":
				return m.mcpToggle(true)
			case "disable":
				return m.mcpToggle(false)
			default:
				return fmt.Errorf("unknown mcp subcommand: %s", args[0])
			}
		},
	})
}

func (m *Manager) mcpToken(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("mcp token subcommand required: create | list | revoke")
	}
	switch args[0] {
	case "create":
		return m.mcpTokenCreate(args[1:])
	case "list":
		return m.mcpTokenList()
	case "revoke":
		return m.mcpTokenRevoke(args[1:])
	default:
		return fmt.Errorf("unknown mcp token subcommand: %s", args[0])
	}
}

func (m *Manager) mcpTokenCreate(args []string) error {
	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}
	flags := parseKVFlags(args)
	name := flags["name"]
	if name == "" {
		return fmt.Errorf("--name required")
	}
	for _, t := range m.config.MCP.Tokens {
		if t.Name == name {
			return fmt.Errorf("token name %q already exists; use a different name or revoke first", name)
		}
	}
	scopes := splitCSV(flags["scopes"])
	if len(scopes) == 0 {
		scopes = []string{"read"}
	}
	if err := validateScopes(scopes); err != nil {
		return err
	}
	ipList := splitCSV(flags["ip-allowlist"])
	expires := flags["expires-at"]
	if expires != "" {
		if _, err := time.Parse(time.RFC3339, expires); err != nil {
			return fmt.Errorf("--expires-at must be RFC3339, e.g. 2027-01-01T00:00:00Z: %w", err)
		}
	}
	rate := flags["rate-limit"]

	plain, err := mcp.GenerateToken()
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}
	hash, err := mcp.HashToken(plain)
	if err != nil {
		return fmt.Errorf("hash token: %w", err)
	}
	entry := config.MCPToken{
		Name:        name,
		TokenHash:   hash,
		Scopes:      scopes,
		IPAllowlist: ipList,
		ExpiresAt:   expires,
		RateLimit:   rate,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		Description: flags["desc"],
	}
	m.config.MCP.Tokens = append(m.config.MCP.Tokens, entry)

	if err := m.config.Save(m.configFile); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Println("✅ MCP token 创建成功（此 token 仅在本次输出，请立刻保存）：")
	fmt.Println()
	fmt.Printf("  Name        : %s\n", name)
	fmt.Printf("  Token       : %s\n", plain)
	fmt.Printf("  Scopes      : %s\n", strings.Join(scopes, ", "))
	if len(ipList) > 0 {
		fmt.Printf("  IP Allowlist: %s\n", strings.Join(ipList, ", "))
	}
	if expires != "" {
		fmt.Printf("  Expires At  : %s\n", expires)
	}
	if rate != "" {
		fmt.Printf("  Rate Limit  : %s\n", rate)
	}
	fmt.Println()
	fmt.Println("接入示例（Cherry Studio / Cursor / Claude Desktop 等 MCP 客户端）：")
	fmt.Printf("  URL    : https://<your-host>%s%s/stream\n", m.config.AdminPrefix, m.config.GetMCPPathPrefix())
	fmt.Printf("  Header : Authorization: Bearer %s\n", plain)
	return nil
}

func (m *Manager) mcpTokenList() error {
	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}
	if len(m.config.MCP.Tokens) == 0 {
		fmt.Println("（暂无 MCP token，运行 `sslcat mcp token create --name <n>` 创建）")
		return nil
	}
	fmt.Printf("%-24s  %-30s  %-20s  %s\n", "NAME", "SCOPES", "EXPIRES", "CREATED")
	for _, t := range m.config.MCP.Tokens {
		expires := t.ExpiresAt
		if expires == "" {
			expires = "(never)"
		}
		fmt.Printf("%-24s  %-30s  %-20s  %s\n",
			truncate(t.Name, 24),
			truncate(strings.Join(t.Scopes, ","), 30),
			truncate(expires, 20),
			t.CreatedAt,
		)
	}
	return nil
}

func (m *Manager) mcpTokenRevoke(args []string) error {
	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}
	flags := parseKVFlags(args)
	name := flags["name"]
	if name == "" {
		return fmt.Errorf("--name required")
	}
	idx := -1
	for i, t := range m.config.MCP.Tokens {
		if t.Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("token %q not found", name)
	}
	m.config.MCP.Tokens = append(m.config.MCP.Tokens[:idx], m.config.MCP.Tokens[idx+1:]...)
	if err := m.config.Save(m.configFile); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	fmt.Printf("✅ MCP token %q 已吊销\n", name)
	return nil
}

func (m *Manager) mcpToggle(enable bool) error {
	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}
	m.config.MCP.Enabled = enable
	if err := m.config.Save(m.configFile); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	if enable {
		fmt.Println("✅ MCP 服务已启用。下次启动 sslcat 主进程后生效。")
	} else {
		fmt.Println("✅ MCP 服务已禁用。下次启动 sslcat 主进程后生效。")
	}
	return nil
}

func (m *Manager) mcpDoctor() error {
	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}
	fmt.Println("🩺 sslcat MCP 自检")
	fmt.Printf("  config_file        : %s\n", m.configFile)
	fmt.Printf("  mcp.enabled        : %v\n", m.config.MCP.Enabled)
	fmt.Printf("  admin_prefix       : %s\n", m.config.AdminPrefix)
	fmt.Printf("  mcp.path_prefix    : %s\n", m.config.GetMCPPathPrefix())
	fmt.Printf("  audit.enabled      : %v\n", m.config.MCP.Audit.Enabled)
	fmt.Printf("  audit.file         : %s\n", m.config.GetMCPAuditFile())
	fmt.Printf("  tokens             : %d\n", len(m.config.MCP.Tokens))

	if len(m.config.MCP.Tokens) == 0 && m.config.MCP.Enabled {
		fmt.Println("  ⚠ 已启用但未配置 token，所有请求都会被拒绝。")
	}
	for _, t := range m.config.MCP.Tokens {
		issues := []string{}
		if len(t.Scopes) == 0 {
			issues = append(issues, "no scope")
		} else if err := validateScopes(t.Scopes); err != nil {
			issues = append(issues, err.Error())
		}
		if t.ExpiresAt != "" {
			if exp, err := time.Parse(time.RFC3339, t.ExpiresAt); err != nil {
				issues = append(issues, "bad expires_at: "+err.Error())
			} else if time.Now().After(exp) {
				issues = append(issues, "expired")
			}
		}
		status := "ok"
		if len(issues) > 0 {
			status = "⚠ " + strings.Join(issues, "; ")
		}
		fmt.Printf("    - %-24s [%s]\n", t.Name, status)
	}

	// 试探性 ping 本地实例（仅当用户传了 SSLCAT_LOCAL_URL 时）。
	if url := os.Getenv("SSLCAT_LOCAL_URL"); url != "" {
		full := strings.TrimRight(url, "/") + m.config.AdminPrefix + m.config.GetMCPPathPrefix() + "/health"
		client := http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get(full)
		if err != nil {
			fmt.Printf("  health check (%s) : ❌ %v\n", full, err)
		} else {
			fmt.Printf("  health check (%s) : %d %s\n", full, resp.StatusCode, resp.Status)
			_ = resp.Body.Close()
		}
	}

	return nil
}

// ----- helpers -----

// parseKVFlags 解析 ["--key", "val", "--flag"] 形式。--flag 单独存在视为 true（值为 ""）。
func parseKVFlags(args []string) map[string]string {
	out := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			continue
		}
		key := strings.TrimPrefix(a, "--")
		// 支持 --key=value 形式
		if eq := strings.IndexByte(key, '='); eq > 0 {
			out[key[:eq]] = key[eq+1:]
			continue
		}
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
			out[key] = args[i+1]
			i++
		} else {
			out[key] = ""
		}
	}
	return out
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func validateScopes(scopes []string) error {
	allowed := map[string]bool{
		"read":            true,
		"site:write":      true,
		"cert:write":      true,
		"proxy:write":     true,
		"security:write":  true,
		"ops:write":       true,
		"admin":           true,
	}
	for _, s := range scopes {
		if !allowed[s] {
			return fmt.Errorf("invalid scope %q (allowed: read, site:write, cert:write, proxy:write, security:write, ops:write, admin)", s)
		}
	}
	return nil
}


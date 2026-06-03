package config

// MCPConfig 内置 MCP（Model Context Protocol）服务的配置。
//
// MCP 是 sslcat 的"第二个管理面"，与现有 /sslcat-panel/api/* 并列。
// 默认关闭；启用后挂在 admin server 同端口的 PathPrefix 下。
type MCPConfig struct {
	Enabled    bool   `json:"enabled"`               // 是否启用 MCP 服务
	PathPrefix string `json:"path_prefix,omitempty"` // 相对 admin_prefix 的路径，默认 "/mcp"

	Tokens []MCPToken `json:"tokens,omitempty"` // 访问令牌列表（仅存哈希）

	Audit MCPAuditConfig `json:"audit,omitempty"`
}

// MCPToken 一个 MCP 访问令牌。明文 token 仅在创建时一次性返回，本结构只存哈希。
type MCPToken struct {
	Name        string   `json:"name"`                   // 令牌名称（唯一）
	TokenHash   string   `json:"token_hash"`             // argon2id 哈希（不可逆）
	Scopes      []string `json:"scopes"`                 // 授权范围：read / site:write / cert:write / proxy:write / admin
	IPAllowlist []string `json:"ip_allowlist,omitempty"` // 调用方 IP 白名单（CIDR 或单 IP），空表示不限制
	ExpiresAt   string   `json:"expires_at,omitempty"`   // RFC3339；空表示永不过期
	RateLimit   string   `json:"rate_limit,omitempty"`   // 如 "60/min"，空表示不限速
	CreatedAt   string   `json:"created_at,omitempty"`
	Description string   `json:"description,omitempty"`
}

// MCPAuditConfig MCP 工具调用审计日志配置。
type MCPAuditConfig struct {
	Enabled bool   `json:"enabled"` // 默认开启
	File    string `json:"file"`    // 审计日志路径，默认 ./data/mcp_audit.log
}

// IsMCPEnabled 是否启用 MCP 服务。
func (c *Config) IsMCPEnabled() bool {
	if c == nil {
		return false
	}
	return c.MCP.Enabled
}

// GetMCPPathPrefix 返回相对 admin_prefix 的 MCP 路径前缀，默认 "/mcp"。
func (c *Config) GetMCPPathPrefix() string {
	if c == nil || c.MCP.PathPrefix == "" {
		return "/mcp"
	}
	return c.MCP.PathPrefix
}

// GetMCPAuditFile 返回审计日志文件路径，未配置时使用默认值。
func (c *Config) GetMCPAuditFile() string {
	if c == nil || c.MCP.Audit.File == "" {
		return "./data/mcp_audit.log"
	}
	return c.MCP.Audit.File
}

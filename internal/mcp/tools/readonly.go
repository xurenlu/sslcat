package tools

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/mcp"
	"github.com/xurenlu/sslcat/internal/proxy"
	"github.com/xurenlu/sslcat/internal/ssl"
)

// Deps 工具依赖。所有 tool 都通过它访问 sslcat 内部 service，
// 不直接 import web.Server，避免循环依赖。
type Deps struct {
	Version    string
	BuildID    string
	Config     *config.Config
	ConfigFile string
	SSL        *ssl.Manager
	Proxy      *proxy.Manager

	// SaveConfig 持久化当前 *config.Config。nil 时 fallback 到 cfg.Save(ConfigFile)。
	// 写类 tool 必须通过它持久化，便于 web.Server 在保存同时触发其它后续逻辑（如证书预取）。
	SaveConfig func() error
	// EnsureCert 在新增/启用 ssl_only 站点时异步预取证书。可选。
	EnsureCert func(domain string)
}

// saveConfig 内部辅助：优先用 Deps.SaveConfig，否则裸调 cfg.Save。
func (d *Deps) saveConfig() error {
	if d.SaveConfig != nil {
		return d.SaveConfig()
	}
	if d.Config == nil {
		return nil
	}
	return d.Config.Save(d.ConfigFile)
}

// RegisterReadOnly 注册 P1 的 4 个只读 tool。
func RegisterReadOnly(reg *mcp.Registry, d *Deps) error {
	if err := reg.RegisterTool(versionInfoTool(d)); err != nil {
		return err
	}
	if err := reg.RegisterTool(siteListTool(d)); err != nil {
		return err
	}
	if err := reg.RegisterTool(certListTool(d)); err != nil {
		return err
	}
	if err := reg.RegisterTool(proxyRouteListTool(d)); err != nil {
		return err
	}
	return nil
}

// emptyObjectSchema 没有参数的 input schema。
var emptyObjectSchema = json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)

// ----- version_info -----

func versionInfoTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "version_info",
		Title:       "sslcat 版本信息",
		Description: "返回 sslcat 当前版本号、构建标识、MCP 协议版本，以及节点角色（standalone/master/slave）。",
		InputSchema: emptyObjectSchema,
		Scope:       mcp.ScopeRead,
		Handler: func(ctx context.Context, args json.RawMessage, caller *mcp.CallContext) (mcp.ToolResult, error) {
			payload := map[string]any{
				"app":              "sslcat",
				"version":          d.Version,
				"build":            d.BuildID,
				"mcp_protocol":     mcp.ProtocolVersion,
				"cluster_mode":     d.Config.GetClusterMode(),
				"node_id":          d.Config.GetNodeID(),
				"node_name":        d.Config.GetNodeName(),
				"server_time":      time.Now().Format(time.RFC3339),
				"admin_prefix":     d.Config.AdminPrefix,
				"config_file_path": d.ConfigFile,
			}
			if d.Proxy != nil {
				payload["proxy_stats"] = d.Proxy.GetProxyStats()
			}
			return mcp.TextResult(payload), nil
		},
	}
}

// ----- site_list -----

var siteListSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "keyword": {"type": "string", "description": "按域名子串过滤（可选）"},
    "enabled_only": {"type": "boolean", "description": "仅返回启用的站点"}
  },
  "additionalProperties": false
}`)

type siteListArgs struct {
	Keyword     string `json:"keyword"`
	EnabledOnly bool   `json:"enabled_only"`
}

type siteSummary struct {
	Domain      string   `json:"domain"`
	Enabled     bool     `json:"enabled"`
	SSLOnly     bool     `json:"ssl_only"`
	Backends    []string `json:"backends"`
	WAFEnabled  *bool    `json:"waf_enabled,omitempty"`
	HasCert     bool     `json:"has_cert"`
	BotEnabled  bool     `json:"bot_detection_enabled"`
	HTTP2       *bool    `json:"http2_enabled,omitempty"`
	HealthCheck bool     `json:"health_check_enabled"`
}

func siteListTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "site_list",
		Title:       "列出站点（反向代理规则）",
		Description: "返回当前所有反向代理站点（即 proxy.rules），可按 keyword 子串过滤、按启用状态过滤。",
		InputSchema: siteListSchema,
		Scope:       mcp.ScopeRead,
		Handler: func(ctx context.Context, args json.RawMessage, caller *mcp.CallContext) (mcp.ToolResult, error) {
			var p siteListArgs
			if len(args) > 0 {
				_ = json.Unmarshal(args, &p)
			}
			rules := d.Config.Proxy.Rules
			out := make([]siteSummary, 0, len(rules))
			for i := range rules {
				r := &rules[i]
				if p.EnabledOnly && !r.Enabled {
					continue
				}
				if p.Keyword != "" && !substr(r.Domain, p.Keyword) {
					continue
				}
				out = append(out, siteSummary{
					Domain:      r.Domain,
					Enabled:     r.Enabled,
					SSLOnly:     r.SSLOnly,
					Backends:    summarizeBackends(r),
					WAFEnabled:  r.WAFEnabled,
					HasCert:     d.SSL != nil && d.SSL.HasValidCertificate(r.Domain),
					BotEnabled:  r.BotDetectionEnabled,
					HTTP2:       r.HTTP2Enabled,
					HealthCheck: r.HealthCheckEnabled,
				})
			}
			return mcp.TextResult(map[string]any{
				"total": len(out),
				"sites": out,
			}), nil
		},
	}
}

func summarizeBackends(r *config.ProxyRule) []string {
	eff := r.GetEffectiveBackends()
	if len(eff) == 0 {
		// 旧字段兜底
		if r.Target != "" && r.Port > 0 {
			return []string{joinHostPort(r.Target, r.Port)}
		}
		return nil
	}
	out := make([]string, 0, len(eff))
	for _, b := range eff {
		out = append(out, joinHostPort(b.Host, b.Port))
	}
	return out
}

// ----- cert_list -----

var certListSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "domain": {"type": "string", "description": "按域名子串过滤（可选）"},
    "expiring_within_days": {"type": "integer", "minimum": 0, "description": "仅返回 N 天内到期的证书"}
  },
  "additionalProperties": false
}`)

type certListArgs struct {
	Domain             string `json:"domain"`
	ExpiringWithinDays int    `json:"expiring_within_days"`
}

type certSummary struct {
	Domain        string    `json:"domain"`
	Issuer        string    `json:"issuer"`
	Status        string    `json:"status"`
	SelfSigned    bool      `json:"self_signed"`
	IsWildcard    bool      `json:"is_wildcard"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	DaysRemaining int       `json:"days_remaining"`
}

func certListTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "cert_list",
		Title:       "列出证书",
		Description: "返回 sslcat 当前管理的所有 SSL 证书（含自签和 ACME 签发），含到期时间和剩余天数。",
		InputSchema: certListSchema,
		Scope:       mcp.ScopeRead,
		Handler: func(ctx context.Context, args json.RawMessage, caller *mcp.CallContext) (mcp.ToolResult, error) {
			var p certListArgs
			if len(args) > 0 {
				_ = json.Unmarshal(args, &p)
			}
			if d.SSL == nil {
				return mcp.TextResult(map[string]any{"total": 0, "certs": []certSummary{}}), nil
			}
			now := time.Now()
			list := d.SSL.GetCertificateList()
			out := make([]certSummary, 0, len(list))
			for _, c := range list {
				if p.Domain != "" && !substr(c.Domain, p.Domain) {
					continue
				}
				days := int(c.ExpiresAt.Sub(now).Hours() / 24)
				if p.ExpiringWithinDays > 0 && days > p.ExpiringWithinDays {
					continue
				}
				out = append(out, certSummary{
					Domain:        c.Domain,
					Issuer:        c.Issuer,
					Status:        c.Status,
					SelfSigned:    c.SelfSigned,
					IsWildcard:    c.IsWildcard,
					IssuedAt:      c.IssuedAt,
					ExpiresAt:     c.ExpiresAt,
					DaysRemaining: days,
				})
			}
			return mcp.TextResult(map[string]any{
				"total": len(out),
				"certs": out,
			}), nil
		},
	}
}

// ----- proxy_route_list -----

var proxyRouteListSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "domain": {"type": "string", "description": "按域名精确匹配"}
  },
  "additionalProperties": false
}`)

type proxyRouteListArgs struct {
	Domain string `json:"domain"`
}

type proxyRouteDetail struct {
	Domain          string                 `json:"domain"`
	Enabled         bool                   `json:"enabled"`
	SSLOnly         bool                   `json:"ssl_only"`
	Backends        []map[string]any       `json:"backends"`
	PathPrefixes    []string               `json:"path_prefixes,omitempty"`
	PathPrefixRules []map[string]any       `json:"path_prefix_rules,omitempty"`
	HealthCheck     map[string]any         `json:"health_check,omitempty"`
	SessionAffinity map[string]any         `json:"session_affinity,omitempty"`
	WAFEnabled      *bool                  `json:"waf_enabled,omitempty"`
	Bot             map[string]any         `json:"bot_detection,omitempty"`
	Timeouts        map[string]any         `json:"timeouts,omitempty"`
	GitDeploy       map[string]any         `json:"git_deploy,omitempty"`
	Extra           map[string]any         `json:"extra,omitempty"`
}

func proxyRouteListTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "proxy_route_list",
		Title:       "列出代理路由详情",
		Description: "返回反向代理路由的完整详情（含路径前缀规则、健康检查、会话保持、超时等）。比 site_list 更详细，适合 AI 诊断转发问题。",
		InputSchema: proxyRouteListSchema,
		Scope:       mcp.ScopeRead,
		Handler: func(ctx context.Context, args json.RawMessage, caller *mcp.CallContext) (mcp.ToolResult, error) {
			var p proxyRouteListArgs
			if len(args) > 0 {
				_ = json.Unmarshal(args, &p)
			}
			rules := d.Config.Proxy.Rules
			out := make([]proxyRouteDetail, 0, len(rules))
			for i := range rules {
				r := &rules[i]
				if p.Domain != "" && r.Domain != p.Domain {
					continue
				}
				out = append(out, buildRouteDetail(r))
			}
			return mcp.TextResult(map[string]any{
				"total":               len(out),
				"unmatched_behavior":  d.Config.Proxy.UnmatchedBehavior,
				"unmatched_redirect":  d.Config.Proxy.UnmatchedRedirectURL,
				"default_resp_header_timeout_sec": d.Config.Proxy.DefaultResponseHeaderTimeoutSec,
				"routes":              out,
			}), nil
		},
	}
}

func buildRouteDetail(r *config.ProxyRule) proxyRouteDetail {
	backends := []map[string]any{}
	for _, b := range r.GetEffectiveBackends() {
		backends = append(backends, map[string]any{
			"id":       b.ID,
			"host":     b.Host,
			"port":     b.Port,
			"weight":   b.Weight,
			"priority": b.Priority,
			"enabled":  b.Enabled,
		})
	}
	pathRules := []map[string]any{}
	for _, pr := range r.PathPrefixRules {
		pathRules = append(pathRules, map[string]any{
			"name":     pr.Name,
			"prefixes": pr.Prefixes,
			"exact":    pr.Exact,
			"enabled":  pr.Enabled,
			"backend_count": len(pr.Backends),
		})
	}
	d := proxyRouteDetail{
		Domain:          r.Domain,
		Enabled:         r.Enabled,
		SSLOnly:         r.SSLOnly,
		Backends:        backends,
		PathPrefixes:    r.PathPrefixes,
		PathPrefixRules: pathRules,
		WAFEnabled:      r.WAFEnabled,
	}
	if r.HealthCheckEnabled {
		d.HealthCheck = map[string]any{
			"enabled":             true,
			"path":                r.HealthCheckPath,
			"interval_sec":        r.HealthCheckInterval,
			"timeout_sec":         r.HealthCheckTimeout,
			"method":              r.HealthCheckMethod,
			"expected_status":     r.ExpectedStatusCode,
		}
	}
	if r.SessionAffinityEnabled {
		d.SessionAffinity = map[string]any{
			"enabled": true,
			"method":  r.SessionAffinityMethod,
			"cookie":  r.SessionAffinityCookie,
			"header":  r.SessionAffinityHeader,
			"ttl_sec": r.SessionAffinityTTL,
		}
	}
	if r.BotDetectionEnabled {
		d.Bot = map[string]any{"enabled": true}
	}
	d.Timeouts = map[string]any{
		"connect_sec":            r.ConnectTimeoutSec,
		"response_header_sec":    r.ResponseHeaderTimeoutSec,
		"tls_handshake_sec":      r.TLSHandshakeTimeoutSec,
		"idle_sec":               r.IdleTimeoutSec,
		"expect_continue_sec":    r.ExpectContinueTimeoutSec,
		"keep_alive_sec":         r.KeepAliveTimeoutSec,
		"upstream_http2_enabled": r.UpstreamHTTP2Enabled,
	}
	if r.ManagedByGitDeploy {
		d.GitDeploy = map[string]any{
			"managed":  true,
			"app_name": r.GitDeployAppName,
			"app_id":   r.GitDeployAppID,
		}
	}
	return d
}

// ----- helpers -----

func substr(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	// 简单大小写不敏感子串。
	hl := lower(haystack)
	nl := lower(needle)
	for i := 0; i+len(nl) <= len(hl); i++ {
		if hl[i:i+len(nl)] == nl {
			return true
		}
	}
	return false
}

func lower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func joinHostPort(host string, port int) string {
	// 不引 net 包，简单格式化即可。
	return host + ":" + itoa(port)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

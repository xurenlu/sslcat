package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/mcp"
)

// RegisterSiteWriters 注册 P2 的 5 个站点写类 tool。
func RegisterSiteWriters(reg *mcp.Registry, d *Deps) error {
	for _, t := range []*mcp.Tool{
		siteAddTool(d),
		siteUpdateTool(d),
		siteEnableTool(d),
		siteDisableTool(d),
		siteDeleteTool(d),
	} {
		if err := reg.RegisterTool(t); err != nil {
			return err
		}
	}
	return nil
}

// ---------- 共用 ----------

// domainRe 简单合法性校验：不带协议、不带路径、长度 1~253，标签满足 LDH，可含通配 *.
var domainRe = regexp.MustCompile(`^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)

func validateDomain(domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	if len(domain) > 253 {
		return fmt.Errorf("domain too long (>253)")
	}
	if !domainRe.MatchString(domain) {
		return fmt.Errorf("invalid domain format: %s", domain)
	}
	return nil
}

func findRuleIndex(rules []config.ProxyRule, domain string) int {
	for i := range rules {
		if rules[i].Domain == domain {
			return i
		}
	}
	return -1
}

// backendArg 给写类 tool 用的 backend 入参形态（host+port，可选 weight/enabled）。
type backendArg struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Weight  int    `json:"weight,omitempty"`
	Enabled *bool  `json:"enabled,omitempty"`
}

func validateBackend(b backendArg) error {
	if strings.TrimSpace(b.Host) == "" {
		return fmt.Errorf("backend host is required")
	}
	if b.Port <= 0 || b.Port > 65535 {
		return fmt.Errorf("backend port must be 1..65535")
	}
	// host 允许 IP 或 hostname
	if ip := net.ParseIP(b.Host); ip == nil {
		if !domainRe.MatchString(b.Host) && b.Host != "localhost" {
			// 不严格——hostname 可能是单标签如 "redis"，放宽：只要不含空格/冒号
			if strings.ContainsAny(b.Host, " :/") {
				return fmt.Errorf("invalid backend host: %s", b.Host)
			}
		}
	}
	return nil
}

func toProxyBackends(in []backendArg) []config.ProxyBackend {
	out := make([]config.ProxyBackend, 0, len(in))
	for i, b := range in {
		enabled := true
		if b.Enabled != nil {
			enabled = *b.Enabled
		}
		w := b.Weight
		if w <= 0 {
			w = 1
		}
		out = append(out, config.ProxyBackend{
			ID:      fmt.Sprintf("b%d", i+1),
			Host:    b.Host,
			Port:    b.Port,
			Weight:  w,
			Enabled: enabled,
		})
	}
	return out
}

// summarizeRule 在响应里展示给 AI 的简化形态。
func summarizeRule(r *config.ProxyRule) map[string]any {
	return map[string]any{
		"domain":   r.Domain,
		"enabled":  r.Enabled,
		"ssl_only": r.SSLOnly,
		"backends": summarizeBackends(r),
	}
}

// ---------- site_add ----------

var siteAddSchema = json.RawMessage(`{
  "type": "object",
  "required": ["domain"],
  "properties": {
    "domain": {"type": "string", "description": "站点域名（如 api.example.com，支持通配 *.example.com）"},
    "backend": {
      "type": "object",
      "description": "单个后端（host+port）。与 backends 二选一。",
      "properties": {
        "host": {"type": "string"},
        "port": {"type": "integer", "minimum": 1, "maximum": 65535}
      }
    },
    "backends": {
      "type": "array",
      "description": "多个后端（用于负载均衡）",
      "items": {
        "type": "object",
        "required": ["host","port"],
        "properties": {
          "host": {"type": "string"},
          "port": {"type": "integer", "minimum": 1, "maximum": 65535},
          "weight": {"type": "integer", "minimum": 1},
          "enabled": {"type": "boolean"}
        }
      }
    },
    "enabled": {"type": "boolean", "description": "是否启用（默认 true）"},
    "ssl_only": {"type": "boolean", "description": "是否强制 HTTPS"},
    "optimize_host_header": {"type": "boolean"},
    "health_check": {
      "type": "object",
      "properties": {
        "enabled": {"type": "boolean"},
        "path": {"type": "string"},
        "interval_sec": {"type": "integer", "minimum": 1},
        "timeout_sec": {"type": "integer", "minimum": 1},
        "method": {"type": "string"},
        "expected_status": {"type": "integer"}
      }
    }
  },
  "additionalProperties": false
}`)

type siteAddArgs struct {
	Domain             string       `json:"domain"`
	Backend            *backendArg  `json:"backend,omitempty"`
	Backends           []backendArg `json:"backends,omitempty"`
	Enabled            *bool        `json:"enabled,omitempty"`
	SSLOnly            bool         `json:"ssl_only,omitempty"`
	OptimizeHostHeader bool         `json:"optimize_host_header,omitempty"`
	HealthCheck        *struct {
		Enabled        bool   `json:"enabled"`
		Path           string `json:"path"`
		IntervalSec    int    `json:"interval_sec"`
		TimeoutSec     int    `json:"timeout_sec"`
		Method         string `json:"method"`
		ExpectedStatus int    `json:"expected_status"`
	} `json:"health_check,omitempty"`
}

func siteAddTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "site_add",
		Title:       "新增反向代理站点",
		Description: "新增一个反向代理站点（即 proxy rule）。域名已存在时会返回 conflict 错误——改用 site_update。新增后会异步预取证书。",
		InputSchema: siteAddSchema,
		Scope:       mcp.ScopeSiteWrite,
		Handler: func(ctx context.Context, args json.RawMessage, caller *mcp.CallContext) (mcp.ToolResult, error) {
			var p siteAddArgs
			if err := json.Unmarshal(args, &p); err != nil {
				return mcp.ErrorResult("invalid params: " + err.Error()), nil
			}
			if err := validateDomain(p.Domain); err != nil {
				return mcp.ErrorResult(err.Error()), nil
			}
			// 收敛 backend / backends 二选一
			backends := p.Backends
			if len(backends) == 0 && p.Backend != nil {
				backends = []backendArg{*p.Backend}
			}
			if len(backends) == 0 {
				return mcp.ErrorResult("either 'backend' or 'backends' is required"), nil
			}
			for i, b := range backends {
				if err := validateBackend(b); err != nil {
					return mcp.ErrorResult(fmt.Sprintf("backend[%d]: %v", i, err)), nil
				}
			}
			if d.Config == nil {
				return mcp.ErrorResult("config not loaded"), nil
			}
			if findRuleIndex(d.Config.Proxy.Rules, p.Domain) >= 0 {
				return mcp.ErrorResult(fmt.Sprintf("domain %q already exists; use site_update", p.Domain)), nil
			}

			enabled := true
			if p.Enabled != nil {
				enabled = *p.Enabled
			}
			rule := config.ProxyRule{
				Domain:             p.Domain,
				Enabled:            enabled,
				SSLOnly:            p.SSLOnly,
				OptimizeHostHeader: p.OptimizeHostHeader,
				Backends:           toProxyBackends(backends),
			}
			// 兼容旧字段：单后端时同步 Target/Port
			if len(rule.Backends) == 1 {
				rule.Target = rule.Backends[0].Host
				rule.Port = rule.Backends[0].Port
			}
			if p.HealthCheck != nil && p.HealthCheck.Enabled {
				rule.HealthCheckEnabled = true
				rule.HealthCheckPath = nonEmpty(p.HealthCheck.Path, "/")
				rule.HealthCheckInterval = orDefault(p.HealthCheck.IntervalSec, 30)
				rule.HealthCheckTimeout = orDefault(p.HealthCheck.TimeoutSec, 5)
				rule.HealthCheckMethod = nonEmpty(p.HealthCheck.Method, "GET")
				rule.ExpectedStatusCode = orDefault(p.HealthCheck.ExpectedStatus, 200)
			}

			d.Config.Proxy.Rules = append(d.Config.Proxy.Rules, rule)
			if err := d.saveConfig(); err != nil {
				// 回滚内存
				d.Config.Proxy.Rules = d.Config.Proxy.Rules[:len(d.Config.Proxy.Rules)-1]
				return mcp.ErrorResult("save config failed: " + err.Error()), nil
			}
			if d.EnsureCert != nil && rule.Enabled {
				d.EnsureCert(rule.Domain)
			}
			return mcp.TextResult(map[string]any{
				"ok":   true,
				"site": summarizeRule(&rule),
			}), nil
		},
	}
}

// ---------- site_update ----------

var siteUpdateSchema = json.RawMessage(`{
  "type": "object",
  "required": ["domain"],
  "properties": {
    "domain":   {"type": "string", "description": "要修改的站点域名"},
    "enabled":  {"type": "boolean"},
    "ssl_only": {"type": "boolean"},
    "optimize_host_header": {"type": "boolean"},
    "backend":  {
      "type": "object",
      "properties": {
        "host": {"type": "string"},
        "port": {"type": "integer", "minimum": 1, "maximum": 65535}
      }
    },
    "backends": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["host","port"],
        "properties": {
          "host": {"type": "string"},
          "port": {"type": "integer"},
          "weight": {"type": "integer"},
          "enabled": {"type": "boolean"}
        }
      }
    }
  },
  "additionalProperties": false
}`)

type siteUpdateArgs struct {
	Domain             string       `json:"domain"`
	Enabled            *bool        `json:"enabled,omitempty"`
	SSLOnly            *bool        `json:"ssl_only,omitempty"`
	OptimizeHostHeader *bool        `json:"optimize_host_header,omitempty"`
	Backend            *backendArg  `json:"backend,omitempty"`
	Backends           []backendArg `json:"backends,omitempty"`
}

func siteUpdateTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "site_update",
		Title:       "修改站点（部分字段 patch）",
		Description: "按 domain 找到现有站点，对传入的字段做 patch。未传字段不动。修改 backends 会整体替换。",
		InputSchema: siteUpdateSchema,
		Scope:       mcp.ScopeSiteWrite,
		Handler:     siteUpdateHandler(d),
	}
}

func siteUpdateHandler(d *Deps) mcp.ToolHandler {
	return func(ctx context.Context, args json.RawMessage, caller *mcp.CallContext) (mcp.ToolResult, error) {
		var p siteUpdateArgs
		if err := json.Unmarshal(args, &p); err != nil {
			return mcp.ErrorResult("invalid params: " + err.Error()), nil
		}
		if err := validateDomain(p.Domain); err != nil {
			return mcp.ErrorResult(err.Error()), nil
		}
		if d.Config == nil {
			return mcp.ErrorResult("config not loaded"), nil
		}
		idx := findRuleIndex(d.Config.Proxy.Rules, p.Domain)
		if idx < 0 {
			return mcp.ErrorResult(fmt.Sprintf("site %q not found", p.Domain)), nil
		}
		// 备份用于回滚
		backup := d.Config.Proxy.Rules[idx]
		r := &d.Config.Proxy.Rules[idx]

		if p.Enabled != nil {
			r.Enabled = *p.Enabled
		}
		if p.SSLOnly != nil {
			r.SSLOnly = *p.SSLOnly
		}
		if p.OptimizeHostHeader != nil {
			r.OptimizeHostHeader = *p.OptimizeHostHeader
		}
		// 后端：传 backends 用之；否则 backend 单后端；都不传不动
		var newBackends []backendArg
		if len(p.Backends) > 0 {
			newBackends = p.Backends
		} else if p.Backend != nil {
			newBackends = []backendArg{*p.Backend}
		}
		if newBackends != nil {
			for i, b := range newBackends {
				if err := validateBackend(b); err != nil {
					d.Config.Proxy.Rules[idx] = backup
					return mcp.ErrorResult(fmt.Sprintf("backend[%d]: %v", i, err)), nil
				}
			}
			r.Backends = toProxyBackends(newBackends)
			// 旧字段兼容
			if len(r.Backends) == 1 {
				r.Target = r.Backends[0].Host
				r.Port = r.Backends[0].Port
			} else {
				r.Target = ""
				r.Port = 0
			}
			// 清掉旧 LB 兼容字段，避免混乱
			r.LoadBalancerBackends = nil
			r.LoadBalancerEnabled = false
		}

		if err := d.saveConfig(); err != nil {
			d.Config.Proxy.Rules[idx] = backup
			return mcp.ErrorResult("save config failed: " + err.Error()), nil
		}
		return mcp.TextResult(map[string]any{
			"ok":   true,
			"site": summarizeRule(r),
		}), nil
	}
}

// ---------- site_enable / site_disable ----------

var siteToggleSchema = json.RawMessage(`{
  "type": "object",
  "required": ["domain"],
  "properties": {"domain": {"type": "string"}},
  "additionalProperties": false
}`)

func siteEnableTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "site_enable",
		Title:       "启用站点",
		Description: "启用一个站点（设置 enabled=true）。等价于 site_update 只改 enabled 字段。",
		InputSchema: siteToggleSchema,
		Scope:       mcp.ScopeSiteWrite,
		Handler:     siteToggleHandler(d, true),
	}
}

func siteDisableTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "site_disable",
		Title:       "禁用站点",
		Description: "禁用一个站点（设置 enabled=false）。站点配置仍保留，但反向代理不再生效。",
		InputSchema: siteToggleSchema,
		Scope:       mcp.ScopeSiteWrite,
		Handler:     siteToggleHandler(d, false),
	}
}

func siteToggleHandler(d *Deps, enable bool) mcp.ToolHandler {
	return func(ctx context.Context, args json.RawMessage, caller *mcp.CallContext) (mcp.ToolResult, error) {
		var p struct {
			Domain string `json:"domain"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return mcp.ErrorResult("invalid params: " + err.Error()), nil
		}
		if err := validateDomain(p.Domain); err != nil {
			return mcp.ErrorResult(err.Error()), nil
		}
		if d.Config == nil {
			return mcp.ErrorResult("config not loaded"), nil
		}
		idx := findRuleIndex(d.Config.Proxy.Rules, p.Domain)
		if idx < 0 {
			return mcp.ErrorResult(fmt.Sprintf("site %q not found", p.Domain)), nil
		}
		old := d.Config.Proxy.Rules[idx].Enabled
		if old == enable {
			return mcp.TextResult(map[string]any{
				"ok":      true,
				"no_op":   true,
				"site":    summarizeRule(&d.Config.Proxy.Rules[idx]),
			}), nil
		}
		d.Config.Proxy.Rules[idx].Enabled = enable
		if err := d.saveConfig(); err != nil {
			d.Config.Proxy.Rules[idx].Enabled = old
			return mcp.ErrorResult("save config failed: " + err.Error()), nil
		}
		if enable && d.EnsureCert != nil {
			d.EnsureCert(p.Domain)
		}
		return mcp.TextResult(map[string]any{
			"ok":   true,
			"site": summarizeRule(&d.Config.Proxy.Rules[idx]),
		}), nil
	}
}

// ---------- site_delete (destructive) ----------

var siteDeleteSchema = json.RawMessage(`{
  "type": "object",
  "required": ["domain"],
  "properties": {
    "domain":  {"type": "string"},
    "confirm": {"type": "string", "description": "第一次调用留空，server 会返回 confirm_token；第二次调用把它放进来才真正执行。"}
  },
  "additionalProperties": false
}`)

func siteDeleteTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "site_delete",
		Title:       "删除站点（destructive）",
		Description: "按 domain 删除站点。该操作不可逆。第一次调用返回预演 + confirm_token，把 token 放进 'confirm' 字段再调一次才真正执行。注意：本工具只删反代路由，不会删除已签发的证书（如需一并删除请使用 cert_delete）。",
		InputSchema: siteDeleteSchema,
		Scope:       mcp.ScopeSiteWrite,
		Destructive: true,
		Handler: func(ctx context.Context, args json.RawMessage, caller *mcp.CallContext) (mcp.ToolResult, error) {
			var p struct {
				Domain  string `json:"domain"`
				Confirm string `json:"confirm,omitempty"`
			}
			if err := json.Unmarshal(args, &p); err != nil {
				return mcp.ErrorResult("invalid params: " + err.Error()), nil
			}
			if err := validateDomain(p.Domain); err != nil {
				return mcp.ErrorResult(err.Error()), nil
			}
			if d.Config == nil {
				return mcp.ErrorResult("config not loaded"), nil
			}
			idx := findRuleIndex(d.Config.Proxy.Rules, p.Domain)
			if idx < 0 {
				return mcp.ErrorResult(fmt.Sprintf("site %q not found", p.Domain)), nil
			}
			rule := d.Config.Proxy.Rules[idx]

			// 未确认：返回 dry-run 预演 + confirm_token
			if !caller.Confirmed {
				return mcp.TextResult(map[string]any{
					"requires_confirmation": true,
					"confirm_token":         caller.ConfirmToken,
					"message":               fmt.Sprintf("即将删除站点 %q。这是 dry-run 预演——若确定执行，请再次调用本工具，并在 arguments 中加入 \"confirm\": \"<token>\"（token 见下方 confirm_token 字段，60 秒内有效）。", p.Domain),
					"preview": map[string]any{
						"action":  "delete",
						"site":    summarizeRule(&rule),
						"note":    "本操作不会删除证书。如需一并清理，调用 cert_delete。",
					},
				}), nil
			}

			// 已确认：真正执行
			d.Config.Proxy.Rules = append(d.Config.Proxy.Rules[:idx], d.Config.Proxy.Rules[idx+1:]...)
			if err := d.saveConfig(); err != nil {
				// 回滚
				newRules := make([]config.ProxyRule, 0, len(d.Config.Proxy.Rules)+1)
				newRules = append(newRules, d.Config.Proxy.Rules[:idx]...)
				newRules = append(newRules, rule)
				newRules = append(newRules, d.Config.Proxy.Rules[idx:]...)
				d.Config.Proxy.Rules = newRules
				return mcp.ErrorResult("save config failed: " + err.Error()), nil
			}
			return mcp.TextResult(map[string]any{
				"ok":           true,
				"deleted_site": summarizeRule(&rule),
			}), nil
		},
	}
}

// ---------- 小工具 ----------

func nonEmpty(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func orDefault(n, def int) int {
	if n <= 0 {
		return def
	}
	return n
}

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/mcp"
)

// RegisterProxyTools 注册 P4 的路由 + 健康检查工具。
func RegisterProxyTools(reg *mcp.Registry, d *Deps) error {
	for _, t := range []*mcp.Tool{
		proxyRouteAddTool(d),
		proxyRouteUpdateTool(d),
		proxyRouteDeleteTool(d),
		upstreamHealthCheckTool(d),
	} {
		if err := reg.RegisterTool(t); err != nil {
			return err
		}
	}
	return nil
}

// ---------- 共用 ----------

// findPathRuleIndex 在 site 上按 name 找 PathPrefixRule，返回 -1 表示没找到。
func findPathRuleIndex(site *config.ProxyRule, name string) int {
	for i := range site.PathPrefixRules {
		if site.PathPrefixRules[i].Name == name {
			return i
		}
	}
	return -1
}

// validatePathPrefix 简单校验：必须 / 开头，不允许 .. 之类的杂质。
func validatePathPrefix(p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return fmt.Errorf("path prefix is required")
	}
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("path prefix must start with /: %q", p)
	}
	if strings.Contains(p, "..") {
		return fmt.Errorf("path prefix must not contain ..")
	}
	return nil
}

// pathRuleArg P4 工具传入的路径前缀规则形态。
type pathRuleArg struct {
	Name     string       `json:"name"`
	Prefixes []string     `json:"prefixes"`
	Exact    bool         `json:"exact"`
	Backends []backendArg `json:"backends"`
	Enabled  *bool        `json:"enabled"`
}

func (p *pathRuleArg) validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if len(p.Prefixes) == 0 {
		return fmt.Errorf("prefixes is required")
	}
	for i, pre := range p.Prefixes {
		if err := validatePathPrefix(pre); err != nil {
			return fmt.Errorf("prefixes[%d]: %w", i, err)
		}
	}
	if len(p.Backends) == 0 {
		return fmt.Errorf("backends is required")
	}
	for i, b := range p.Backends {
		if err := validateBackend(b); err != nil {
			return fmt.Errorf("backends[%d]: %w", i, err)
		}
	}
	return nil
}

func (p *pathRuleArg) toConfig() config.PathPrefixRule {
	enabled := true
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	return config.PathPrefixRule{
		Name:     p.Name,
		Prefixes: append([]string{}, p.Prefixes...),
		Exact:    p.Exact,
		Backends: toProxyBackends(p.Backends),
		Enabled:  enabled,
	}
}

// summarizePathRule 给响应用的精简形态。
func summarizePathRule(r *config.PathPrefixRule) map[string]any {
	bs := []map[string]any{}
	for _, b := range r.Backends {
		bs = append(bs, map[string]any{
			"host": b.Host, "port": b.Port, "weight": b.Weight, "enabled": b.Enabled,
		})
	}
	return map[string]any{
		"name":     r.Name,
		"prefixes": r.Prefixes,
		"exact":    r.Exact,
		"enabled":  r.Enabled,
		"backends": bs,
	}
}

// ---------- proxy_route_add ----------

var proxyRouteAddSchema = json.RawMessage(`{
  "type": "object",
  "required": ["domain", "rule"],
  "properties": {
    "domain": {"type": "string", "description": "已存在的站点域名（先用 site_add 建好站点再来加路由）"},
    "rule": {
      "type": "object",
      "required": ["name", "prefixes", "backends"],
      "properties": {
        "name":     {"type": "string", "description": "路由名（站点内唯一）"},
        "prefixes": {"type": "array",  "items": {"type": "string"}, "description": "路径前缀列表，如 [\"/api/v1/\"]"},
        "exact":    {"type": "boolean", "description": "是否精确匹配"},
        "enabled":  {"type": "boolean"},
        "backends": {
          "type": "array",
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
        }
      }
    }
  },
  "additionalProperties": false
}`)

type proxyRouteAddArgs struct {
	Domain string      `json:"domain"`
	Rule   pathRuleArg `json:"rule"`
}

func proxyRouteAddTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "proxy_route_add",
		Title:       "新增路径前缀路由",
		Description: "在已有站点上新增一条 PathPrefixRule。同站内路由 name 必须唯一；prefix 必须以 / 开头。需先用 site_add 建好站点。",
		InputSchema: proxyRouteAddSchema,
		Scope:       mcp.ScopeProxyWrite,
		Handler: func(ctx context.Context, args json.RawMessage, caller *mcp.CallContext) (mcp.ToolResult, error) {
			var p proxyRouteAddArgs
			if err := json.Unmarshal(args, &p); err != nil {
				return mcp.ErrorResult("invalid params: " + err.Error()), nil
			}
			if err := validateDomain(p.Domain); err != nil {
				return mcp.ErrorResult(err.Error()), nil
			}
			if err := p.Rule.validate(); err != nil {
				return mcp.ErrorResult(err.Error()), nil
			}
			if d.Config == nil {
				return mcp.ErrorResult("config not loaded"), nil
			}
			idx := findRuleIndex(d.Config.Proxy.Rules, p.Domain)
			if idx < 0 {
				return mcp.ErrorResult(fmt.Sprintf("site %q not found; create it with site_add first", p.Domain)), nil
			}
			site := &d.Config.Proxy.Rules[idx]
			if findPathRuleIndex(site, p.Rule.Name) >= 0 {
				return mcp.ErrorResult(fmt.Sprintf("route name %q already exists on site %q", p.Rule.Name, p.Domain)), nil
			}
			pr := p.Rule.toConfig()
			site.PathPrefixRules = append(site.PathPrefixRules, pr)
			if err := d.saveConfig(); err != nil {
				site.PathPrefixRules = site.PathPrefixRules[:len(site.PathPrefixRules)-1]
				return mcp.ErrorResult("save config failed: " + err.Error()), nil
			}
			return mcp.TextResult(map[string]any{
				"ok":     true,
				"domain": p.Domain,
				"route":  summarizePathRule(&pr),
			}), nil
		},
	}
}

// ---------- proxy_route_update ----------

var proxyRouteUpdateSchema = json.RawMessage(`{
  "type": "object",
  "required": ["domain", "name"],
  "properties": {
    "domain":   {"type": "string"},
    "name":     {"type": "string", "description": "要修改的路由 name"},
    "prefixes": {"type": "array", "items": {"type": "string"}},
    "exact":    {"type": "boolean"},
    "enabled":  {"type": "boolean"},
    "backends": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["host","port"],
        "properties": {
          "host": {"type": "string"},
          "port": {"type": "integer", "minimum": 1, "maximum": 65535},
          "weight": {"type": "integer"},
          "enabled": {"type": "boolean"}
        }
      }
    }
  },
  "additionalProperties": false
}`)

type proxyRouteUpdateArgs struct {
	Domain   string       `json:"domain"`
	Name     string       `json:"name"`
	Prefixes []string     `json:"prefixes,omitempty"`
	Exact    *bool        `json:"exact,omitempty"`
	Enabled  *bool        `json:"enabled,omitempty"`
	Backends []backendArg `json:"backends,omitempty"`
}

func proxyRouteUpdateTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "proxy_route_update",
		Title:       "修改路径前缀路由（patch）",
		Description: "按 (domain, name) 定位路由，对传入字段做 patch。传 backends 会整体替换；未传字段不动。",
		InputSchema: proxyRouteUpdateSchema,
		Scope:       mcp.ScopeProxyWrite,
		Handler: func(ctx context.Context, args json.RawMessage, caller *mcp.CallContext) (mcp.ToolResult, error) {
			var p proxyRouteUpdateArgs
			if err := json.Unmarshal(args, &p); err != nil {
				return mcp.ErrorResult("invalid params: " + err.Error()), nil
			}
			if err := validateDomain(p.Domain); err != nil {
				return mcp.ErrorResult(err.Error()), nil
			}
			if strings.TrimSpace(p.Name) == "" {
				return mcp.ErrorResult("name is required"), nil
			}
			if d.Config == nil {
				return mcp.ErrorResult("config not loaded"), nil
			}
			siteIdx := findRuleIndex(d.Config.Proxy.Rules, p.Domain)
			if siteIdx < 0 {
				return mcp.ErrorResult(fmt.Sprintf("site %q not found", p.Domain)), nil
			}
			site := &d.Config.Proxy.Rules[siteIdx]
			rIdx := findPathRuleIndex(site, p.Name)
			if rIdx < 0 {
				return mcp.ErrorResult(fmt.Sprintf("route %q not found on site %q", p.Name, p.Domain)), nil
			}
			backup := site.PathPrefixRules[rIdx]
			r := &site.PathPrefixRules[rIdx]

			if len(p.Prefixes) > 0 {
				for i, pre := range p.Prefixes {
					if err := validatePathPrefix(pre); err != nil {
						return mcp.ErrorResult(fmt.Sprintf("prefixes[%d]: %v", i, err)), nil
					}
				}
				r.Prefixes = append([]string{}, p.Prefixes...)
			}
			if p.Exact != nil {
				r.Exact = *p.Exact
			}
			if p.Enabled != nil {
				r.Enabled = *p.Enabled
			}
			if len(p.Backends) > 0 {
				for i, b := range p.Backends {
					if err := validateBackend(b); err != nil {
						site.PathPrefixRules[rIdx] = backup
						return mcp.ErrorResult(fmt.Sprintf("backends[%d]: %v", i, err)), nil
					}
				}
				r.Backends = toProxyBackends(p.Backends)
			}

			if err := d.saveConfig(); err != nil {
				site.PathPrefixRules[rIdx] = backup
				return mcp.ErrorResult("save config failed: " + err.Error()), nil
			}
			return mcp.TextResult(map[string]any{
				"ok":     true,
				"domain": p.Domain,
				"route":  summarizePathRule(r),
			}), nil
		},
	}
}

// ---------- proxy_route_delete (destructive) ----------

var proxyRouteDeleteSchema = json.RawMessage(`{
  "type": "object",
  "required": ["domain", "name"],
  "properties": {
    "domain":  {"type": "string"},
    "name":    {"type": "string"},
    "confirm": {"type": "string", "description": "第一次留空 → dry-run；第二次带上 server 返回的 token 才真正执行。"}
  },
  "additionalProperties": false
}`)

func proxyRouteDeleteTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "proxy_route_delete",
		Title:       "删除路径前缀路由（destructive）",
		Description: "按 (domain, name) 删除站点内的某条 PathPrefixRule。不可逆。两阶段确认（同 site_delete）。注意：删除后该 path 前缀的请求会回落到站点默认后端（如有）。",
		InputSchema: proxyRouteDeleteSchema,
		Scope:       mcp.ScopeProxyWrite,
		Destructive: true,
		Handler: func(ctx context.Context, args json.RawMessage, caller *mcp.CallContext) (mcp.ToolResult, error) {
			var p struct {
				Domain  string `json:"domain"`
				Name    string `json:"name"`
				Confirm string `json:"confirm,omitempty"`
			}
			if err := json.Unmarshal(args, &p); err != nil {
				return mcp.ErrorResult("invalid params: " + err.Error()), nil
			}
			if err := validateDomain(p.Domain); err != nil {
				return mcp.ErrorResult(err.Error()), nil
			}
			if strings.TrimSpace(p.Name) == "" {
				return mcp.ErrorResult("name is required"), nil
			}
			if d.Config == nil {
				return mcp.ErrorResult("config not loaded"), nil
			}
			siteIdx := findRuleIndex(d.Config.Proxy.Rules, p.Domain)
			if siteIdx < 0 {
				return mcp.ErrorResult(fmt.Sprintf("site %q not found", p.Domain)), nil
			}
			site := &d.Config.Proxy.Rules[siteIdx]
			rIdx := findPathRuleIndex(site, p.Name)
			if rIdx < 0 {
				return mcp.ErrorResult(fmt.Sprintf("route %q not found on site %q", p.Name, p.Domain)), nil
			}
			snapshot := site.PathPrefixRules[rIdx]

			if !caller.Confirmed {
				return mcp.TextResult(map[string]any{
					"requires_confirmation": true,
					"confirm_token":         caller.ConfirmToken,
					"message":               fmt.Sprintf("即将删除站点 %q 的路由 %q（涉及前缀 %v）。dry-run。", p.Domain, p.Name, snapshot.Prefixes),
					"preview": map[string]any{
						"action": "delete_route",
						"domain": p.Domain,
						"route":  summarizePathRule(&snapshot),
					},
				}), nil
			}

			// 真正删除
			site.PathPrefixRules = append(site.PathPrefixRules[:rIdx], site.PathPrefixRules[rIdx+1:]...)
			if err := d.saveConfig(); err != nil {
				// 回滚
				newPRs := make([]config.PathPrefixRule, 0, len(site.PathPrefixRules)+1)
				newPRs = append(newPRs, site.PathPrefixRules[:rIdx]...)
				newPRs = append(newPRs, snapshot)
				newPRs = append(newPRs, site.PathPrefixRules[rIdx:]...)
				site.PathPrefixRules = newPRs
				return mcp.ErrorResult("save config failed: " + err.Error()), nil
			}
			return mcp.TextResult(map[string]any{
				"ok":            true,
				"deleted_route": summarizePathRule(&snapshot),
			}), nil
		},
	}
}

// ---------- upstream_health_check ----------

var upstreamHealthCheckSchema = json.RawMessage(`{
  "type": "object",
  "required": ["domain"],
  "properties": {
    "domain":         {"type": "string", "description": "要探测的站点域名"},
    "timeout_ms":     {"type": "integer", "minimum": 100, "maximum": 10000, "description": "每个后端 TCP 拨号超时（毫秒，默认 2000）"},
    "include_routes": {"type": "boolean", "description": "是否一并探测 PathPrefixRules 内的后端（默认 false）"}
  },
  "additionalProperties": false
}`)

type upstreamHealthArgs struct {
	Domain        string `json:"domain"`
	TimeoutMS     int    `json:"timeout_ms,omitempty"`
	IncludeRoutes bool   `json:"include_routes,omitempty"`
}

type backendHealthResult struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Reachable  bool   `json:"reachable"`
	LatencyMS  int64  `json:"latency_ms,omitempty"`
	Error      string `json:"error,omitempty"`
	RouteName  string `json:"route_name,omitempty"`
}

func upstreamHealthCheckTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "upstream_health_check",
		Title:       "主动探测站点后端可达性",
		Description: "对指定站点的所有后端做并发 TCP 拨号探测，返回每个后端可达性与响应时间。include_routes=true 时一并探测 PathPrefixRules 内的后端。注意：仅 TCP 拨号，不走 HTTP 健康检查路径。",
		InputSchema: upstreamHealthCheckSchema,
		Scope:       mcp.ScopeRead, // 主动探测是只读语义
		Handler: func(ctx context.Context, args json.RawMessage, caller *mcp.CallContext) (mcp.ToolResult, error) {
			var p upstreamHealthArgs
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
			site := &d.Config.Proxy.Rules[idx]

			timeout := time.Duration(p.TimeoutMS) * time.Millisecond
			if timeout <= 0 {
				timeout = 2 * time.Second
			}
			if timeout > 10*time.Second {
				timeout = 10 * time.Second
			}

			// 收集要探测的 backend
			type target struct {
				host  string
				port  int
				route string
			}
			targets := []target{}
			for _, b := range site.GetEffectiveBackends() {
				targets = append(targets, target{b.Host, b.Port, ""})
			}
			if p.IncludeRoutes {
				for _, pr := range site.PathPrefixRules {
					for _, b := range pr.Backends {
						targets = append(targets, target{b.Host, b.Port, pr.Name})
					}
				}
			}
			if len(targets) == 0 {
				return mcp.ErrorResult(fmt.Sprintf("site %q has no backends to probe", p.Domain)), nil
			}

			// 并发拨号
			results := make([]backendHealthResult, len(targets))
			var wg sync.WaitGroup
			for i := range targets {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					t := targets[i]
					r := backendHealthResult{Host: t.host, Port: t.port, RouteName: t.route}
					start := time.Now()
					conn, err := net.DialTimeout("tcp",
						net.JoinHostPort(t.host, strconv.Itoa(t.port)), timeout)
					r.LatencyMS = time.Since(start).Milliseconds()
					if err != nil {
						r.Reachable = false
						r.Error = err.Error()
					} else {
						r.Reachable = true
						_ = conn.Close()
					}
					results[i] = r
				}(i)
			}
			wg.Wait()

			reachable := 0
			for _, r := range results {
				if r.Reachable {
					reachable++
				}
			}
			return mcp.TextResult(map[string]any{
				"domain":          p.Domain,
				"timeout_ms":      timeout.Milliseconds(),
				"total":           len(results),
				"reachable":       reachable,
				"all_reachable":   reachable == len(results),
				"results":         results,
			}), nil
		},
	}
}

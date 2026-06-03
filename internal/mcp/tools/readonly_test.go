package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/mcp"
)

func newDeps() *Deps {
	cfg := &config.Config{
		AdminPrefix: "/sslcat-panel",
		Proxy: config.ProxyConfig{
			UnmatchedBehavior: "503",
			Rules: []config.ProxyRule{
				{
					Domain:  "a.example.com",
					Enabled: true,
					SSLOnly: true,
					Backends: []config.ProxyBackend{
						{ID: "b1", Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true},
					},
					HealthCheckEnabled:     true,
					HealthCheckPath:        "/healthz",
					HealthCheckInterval:    30,
					HealthCheckMethod:      "GET",
					SessionAffinityEnabled: true,
					SessionAffinityMethod:  "cookie",
					SessionAffinityCookie:  "JSESSIONID",
				},
				{
					Domain:   "b.example.com",
					Enabled:  false,
					Target:   "127.0.0.1",
					Port:     9000,
				},
			},
		},
		Cluster: config.ClusterConfig{
			Mode:     "standalone",
			NodeID:   "node-test",
			NodeName: "node-test",
		},
	}
	return &Deps{
		Version:    "0.0.0-test",
		BuildID:    "test",
		Config:     cfg,
		ConfigFile: "/tmp/sslcat.conf",
		// SSL/Proxy 故意留 nil：tool 都要能在没有真实管理器时工作（测试隔离）
	}
}

func callTool(t *testing.T, reg *mcp.Registry, name string, argsJSON string) mcp.ToolResult {
	t.Helper()
	tool, ok := reg.GetTool(name)
	if !ok {
		t.Fatalf("tool %s not registered", name)
	}
	res, err := tool.Handler(context.Background(), json.RawMessage(argsJSON), &mcp.CallContext{Scopes: []mcp.Scope{mcp.ScopeRead}})
	if err != nil {
		t.Fatalf("tool %s error: %v", name, err)
	}
	return res
}

func unmarshalText(t *testing.T, r mcp.ToolResult, out any) {
	t.Helper()
	if r.IsError {
		t.Fatalf("tool returned error: %+v", r)
	}
	if len(r.Content) == 0 {
		t.Fatal("empty content")
	}
	if err := json.Unmarshal([]byte(r.Content[0].Text), out); err != nil {
		t.Fatalf("unmarshal tool text: %v body=%s", err, r.Content[0].Text)
	}
}

func TestRegisterReadOnly_AllRegistered(t *testing.T) {
	reg := mcp.NewRegistry()
	if err := RegisterReadOnly(reg, newDeps()); err != nil {
		t.Fatalf("register: %v", err)
	}
	for _, name := range []string{"version_info", "site_list", "cert_list", "proxy_route_list"} {
		if _, ok := reg.GetTool(name); !ok {
			t.Errorf("tool %s missing", name)
		}
	}
}

func TestVersionInfoTool(t *testing.T) {
	reg := mcp.NewRegistry()
	_ = RegisterReadOnly(reg, newDeps())
	res := callTool(t, reg, "version_info", `{}`)
	var out map[string]any
	unmarshalText(t, res, &out)
	if out["app"] != "sslcat" {
		t.Errorf("expected app=sslcat, got %v", out["app"])
	}
	if out["version"] != "0.0.0-test" {
		t.Errorf("unexpected version: %v", out["version"])
	}
	if out["mcp_protocol"] == nil {
		t.Errorf("missing mcp_protocol")
	}
}

func TestSiteListTool(t *testing.T) {
	reg := mcp.NewRegistry()
	_ = RegisterReadOnly(reg, newDeps())

	t.Run("all sites", func(t *testing.T) {
		res := callTool(t, reg, "site_list", `{}`)
		var out struct {
			Total int           `json:"total"`
			Sites []map[string]any `json:"sites"`
		}
		unmarshalText(t, res, &out)
		if out.Total != 2 {
			t.Errorf("expected 2 sites, got %d", out.Total)
		}
	})

	t.Run("enabled only", func(t *testing.T) {
		res := callTool(t, reg, "site_list", `{"enabled_only":true}`)
		var out struct{ Total int `json:"total"` }
		unmarshalText(t, res, &out)
		if out.Total != 1 {
			t.Errorf("expected 1 enabled site, got %d", out.Total)
		}
	})

	t.Run("keyword filter", func(t *testing.T) {
		res := callTool(t, reg, "site_list", `{"keyword":"b.example"}`)
		var out struct {
			Total int `json:"total"`
			Sites []struct {
				Domain   string   `json:"domain"`
				Backends []string `json:"backends"`
			} `json:"sites"`
		}
		unmarshalText(t, res, &out)
		if out.Total != 1 || out.Sites[0].Domain != "b.example.com" {
			t.Fatalf("expected b.example.com only, got %+v", out)
		}
		// 旧字段 Target+Port 应该回退成单后端字符串
		if len(out.Sites[0].Backends) != 1 || !strings.Contains(out.Sites[0].Backends[0], "127.0.0.1:9000") {
			t.Errorf("legacy target/port fallback failed: %v", out.Sites[0].Backends)
		}
	})
}

func TestCertListTool_NilSSL(t *testing.T) {
	reg := mcp.NewRegistry()
	_ = RegisterReadOnly(reg, newDeps())
	res := callTool(t, reg, "cert_list", `{}`)
	var out struct {
		Total int `json:"total"`
	}
	unmarshalText(t, res, &out)
	if out.Total != 0 {
		t.Errorf("expected 0 certs when SSL manager is nil, got %d", out.Total)
	}
}

func TestProxyRouteListTool(t *testing.T) {
	reg := mcp.NewRegistry()
	_ = RegisterReadOnly(reg, newDeps())

	t.Run("all routes", func(t *testing.T) {
		res := callTool(t, reg, "proxy_route_list", `{}`)
		var out struct {
			Total             int    `json:"total"`
			UnmatchedBehavior string `json:"unmatched_behavior"`
			Routes            []struct {
				Domain          string                 `json:"domain"`
				HealthCheck     map[string]any         `json:"health_check"`
				SessionAffinity map[string]any         `json:"session_affinity"`
			} `json:"routes"`
		}
		unmarshalText(t, res, &out)
		if out.Total != 2 {
			t.Fatalf("expected 2 routes, got %d", out.Total)
		}
		if out.UnmatchedBehavior != "503" {
			t.Errorf("unexpected unmatched_behavior: %s", out.UnmatchedBehavior)
		}
		// a.example.com should expose health_check & session_affinity blocks
		var aRoute *struct {
			Domain          string                 `json:"domain"`
			HealthCheck     map[string]any         `json:"health_check"`
			SessionAffinity map[string]any         `json:"session_affinity"`
		}
		for i := range out.Routes {
			if out.Routes[i].Domain == "a.example.com" {
				aRoute = &out.Routes[i]
			}
		}
		if aRoute == nil {
			t.Fatal("a.example.com missing")
		}
		if aRoute.HealthCheck == nil {
			t.Errorf("expected health_check block")
		}
		if aRoute.SessionAffinity == nil {
			t.Errorf("expected session_affinity block")
		}
	})

	t.Run("domain filter", func(t *testing.T) {
		res := callTool(t, reg, "proxy_route_list", `{"domain":"b.example.com"}`)
		var out struct{ Total int `json:"total"` }
		unmarshalText(t, res, &out)
		if out.Total != 1 {
			t.Errorf("expected 1 route, got %d", out.Total)
		}
	})
}

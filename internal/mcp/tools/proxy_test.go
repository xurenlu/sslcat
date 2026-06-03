package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/mcp"
)

func newProxyDeps() (*Deps, *int32) {
	cfg := &config.Config{
		AdminPrefix: "/sslcat-panel",
		Proxy: config.ProxyConfig{
			Rules: []config.ProxyRule{
				{
					Domain:  "site.example.com",
					Enabled: true,
					Backends: []config.ProxyBackend{
						{ID: "b1", Host: "127.0.0.1", Port: 1, Weight: 1, Enabled: true},
					},
					PathPrefixRules: []config.PathPrefixRule{
						{
							Name:     "api-v1",
							Prefixes: []string{"/api/v1/"},
							Enabled:  true,
							Backends: []config.ProxyBackend{
								{ID: "x", Host: "10.0.0.10", Port: 8080, Weight: 1, Enabled: true},
							},
						},
					},
				},
			},
		},
	}
	var saveCount int32
	return &Deps{
		Config:     cfg,
		ConfigFile: "/tmp/sslcat-proxy-test.conf",
		SaveConfig: func() error { atomic.AddInt32(&saveCount, 1); return nil },
	}, &saveCount
}

func callProxyTool(t *testing.T, reg *mcp.Registry, name, argsJSON string, confirmed bool) mcp.ToolResult {
	t.Helper()
	tool, ok := reg.GetTool(name)
	if !ok {
		t.Fatalf("tool %s not registered", name)
	}
	caller := &mcp.CallContext{
		TokenName: "ut",
		Scopes:    []mcp.Scope{mcp.ScopeProxyWrite, mcp.ScopeRead},
		Confirmed: confirmed,
	}
	res, err := tool.Handler(context.Background(), json.RawMessage(argsJSON), caller)
	if err != nil {
		t.Fatalf("tool %s error: %v", name, err)
	}
	return res
}

func TestRegisterProxyTools(t *testing.T) {
	deps, _ := newProxyDeps()
	reg := mcp.NewRegistry()
	if err := RegisterProxyTools(reg, deps); err != nil {
		t.Fatalf("register: %v", err)
	}
	for _, n := range []string{"proxy_route_add", "proxy_route_update", "proxy_route_delete", "upstream_health_check"} {
		if _, ok := reg.GetTool(n); !ok {
			t.Errorf("tool %s missing", n)
		}
	}
	if del, _ := reg.GetTool("proxy_route_delete"); del != nil && !del.Destructive {
		t.Error("proxy_route_delete should be destructive")
	}
	if up, _ := reg.GetTool("upstream_health_check"); up != nil && up.Scope != mcp.ScopeRead {
		t.Errorf("upstream_health_check should be read scope, got %s", up.Scope)
	}
}

func TestProxyRouteAdd_Success(t *testing.T) {
	deps, saveCount := newProxyDeps()
	reg := mcp.NewRegistry()
	_ = RegisterProxyTools(reg, deps)
	args := `{"domain":"site.example.com","rule":{"name":"api-v2","prefixes":["/api/v2/"],"backends":[{"host":"10.0.0.11","port":8081}]}}`
	res := callProxyTool(t, reg, "proxy_route_add", args, true)
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	site := &deps.Config.Proxy.Rules[0]
	if len(site.PathPrefixRules) != 2 {
		t.Errorf("expected 2 path rules, got %d", len(site.PathPrefixRules))
	}
	if atomic.LoadInt32(saveCount) != 1 {
		t.Errorf("expected 1 save, got %d", *saveCount)
	}
}

func TestProxyRouteAdd_SiteNotFound(t *testing.T) {
	deps, _ := newProxyDeps()
	reg := mcp.NewRegistry()
	_ = RegisterProxyTools(reg, deps)
	args := `{"domain":"missing.example.com","rule":{"name":"r","prefixes":["/x"],"backends":[{"host":"1.2.3.4","port":80}]}}`
	res := callProxyTool(t, reg, "proxy_route_add", args, true)
	if !res.IsError || !strings.Contains(res.Content[0].Text, "site_add first") {
		t.Errorf("expected site-not-found hint, got %+v", res)
	}
}

func TestProxyRouteAdd_NameConflict(t *testing.T) {
	deps, _ := newProxyDeps()
	reg := mcp.NewRegistry()
	_ = RegisterProxyTools(reg, deps)
	args := `{"domain":"site.example.com","rule":{"name":"api-v1","prefixes":["/x"],"backends":[{"host":"1.2.3.4","port":80}]}}`
	res := callProxyTool(t, reg, "proxy_route_add", args, true)
	if !res.IsError || !strings.Contains(res.Content[0].Text, "already exists") {
		t.Errorf("expected name conflict, got %+v", res)
	}
}

func TestProxyRouteAdd_InvalidPrefix(t *testing.T) {
	deps, _ := newProxyDeps()
	reg := mcp.NewRegistry()
	_ = RegisterProxyTools(reg, deps)
	args := `{"domain":"site.example.com","rule":{"name":"bad","prefixes":["nope-no-slash"],"backends":[{"host":"1.2.3.4","port":80}]}}`
	res := callProxyTool(t, reg, "proxy_route_add", args, true)
	if !res.IsError || !strings.Contains(res.Content[0].Text, "/") {
		t.Errorf("expected prefix validation error, got %+v", res)
	}
}

func TestProxyRouteUpdate_Patch(t *testing.T) {
	deps, _ := newProxyDeps()
	reg := mcp.NewRegistry()
	_ = RegisterProxyTools(reg, deps)
	args := `{"domain":"site.example.com","name":"api-v1","enabled":false,"backends":[{"host":"10.0.0.99","port":9090}]}`
	res := callProxyTool(t, reg, "proxy_route_update", args, true)
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	r := deps.Config.Proxy.Rules[0].PathPrefixRules[0]
	if r.Enabled {
		t.Error("enabled patch not applied")
	}
	if len(r.Backends) != 1 || r.Backends[0].Port != 9090 {
		t.Errorf("backends replacement failed: %+v", r.Backends)
	}
}

func TestProxyRouteUpdate_NotFound(t *testing.T) {
	deps, _ := newProxyDeps()
	reg := mcp.NewRegistry()
	_ = RegisterProxyTools(reg, deps)
	res := callProxyTool(t, reg, "proxy_route_update",
		`{"domain":"site.example.com","name":"nope","enabled":false}`, true)
	if !res.IsError {
		t.Fatalf("expected error for missing route")
	}
}

func TestProxyRouteDelete_TwoPhase(t *testing.T) {
	deps, saveCount := newProxyDeps()
	reg := mcp.NewRegistry()
	_ = RegisterProxyTools(reg, deps)

	// 第一次：dry-run
	res := callProxyTool(t, reg, "proxy_route_delete",
		`{"domain":"site.example.com","name":"api-v1"}`, false)
	var dry struct {
		Requires bool `json:"requires_confirmation"`
		Preview  struct {
			Action string `json:"action"`
		} `json:"preview"`
	}
	if err := json.Unmarshal([]byte(res.Content[0].Text), &dry); err != nil {
		t.Fatalf("parse dry-run: %v", err)
	}
	if !dry.Requires || dry.Preview.Action != "delete_route" {
		t.Fatalf("unexpected dry-run: %+v", dry)
	}
	if len(deps.Config.Proxy.Rules[0].PathPrefixRules) != 1 {
		t.Error("dry-run should not actually delete")
	}
	if atomic.LoadInt32(saveCount) != 0 {
		t.Error("dry-run should not save")
	}

	// 第二次：confirmed
	res = callProxyTool(t, reg, "proxy_route_delete",
		`{"domain":"site.example.com","name":"api-v1","confirm":"whatever"}`, true)
	if res.IsError {
		t.Fatalf("confirmed delete error: %s", res.Content[0].Text)
	}
	if len(deps.Config.Proxy.Rules[0].PathPrefixRules) != 0 {
		t.Error("confirmed delete should remove route")
	}
	if atomic.LoadInt32(saveCount) != 1 {
		t.Errorf("expected 1 save, got %d", *saveCount)
	}
}

func TestUpstreamHealthCheck_LocalListener(t *testing.T) {
	// 起本地 listener 作为活后端
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	deps := &Deps{
		Config: &config.Config{
			AdminPrefix: "/sslcat-panel",
			Proxy: config.ProxyConfig{
				Rules: []config.ProxyRule{
					{
						Domain:  "probe.example.com",
						Enabled: true,
						Backends: []config.ProxyBackend{
							{ID: "alive", Host: "127.0.0.1", Port: port, Weight: 1, Enabled: true},
							{ID: "dead", Host: "127.0.0.1", Port: 1, Weight: 1, Enabled: true},
						},
					},
				},
			},
		},
	}
	reg := mcp.NewRegistry()
	_ = RegisterProxyTools(reg, deps)
	res := callProxyTool(t, reg, "upstream_health_check",
		fmt.Sprintf(`{"domain":"probe.example.com","timeout_ms":500}`), true)
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	var out struct {
		Total        int  `json:"total"`
		Reachable    int  `json:"reachable"`
		AllReachable bool `json:"all_reachable"`
		Results      []struct {
			Host      string `json:"host"`
			Port      int    `json:"port"`
			Reachable bool   `json:"reachable"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(res.Content[0].Text), &out); err != nil {
		t.Fatalf("parse: %v body=%s", err, res.Content[0].Text)
	}
	if out.Total != 2 {
		t.Errorf("expected 2 backends, got %d", out.Total)
	}
	if out.Reachable != 1 {
		t.Errorf("expected exactly 1 reachable (live listener), got %d (results=%+v)", out.Reachable, out.Results)
	}
	if out.AllReachable {
		t.Error("expected all_reachable=false")
	}
}

func TestUpstreamHealthCheck_NoBackends(t *testing.T) {
	deps := &Deps{
		Config: &config.Config{
			Proxy: config.ProxyConfig{
				Rules: []config.ProxyRule{{Domain: "empty.example.com", Enabled: true}},
			},
		},
	}
	reg := mcp.NewRegistry()
	_ = RegisterProxyTools(reg, deps)
	res := callProxyTool(t, reg, "upstream_health_check",
		`{"domain":"empty.example.com"}`, true)
	if !res.IsError || !strings.Contains(res.Content[0].Text, "no backends") {
		t.Errorf("expected no-backends error, got %+v", res)
	}
}

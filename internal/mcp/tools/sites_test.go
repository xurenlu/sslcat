package tools

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/mcp"
)

func newWritableDeps() (*Deps, *int32 /*saveCount*/, *int32 /*ensureCertCount*/) {
	cfg := &config.Config{
		AdminPrefix: "/sslcat-panel",
		Proxy: config.ProxyConfig{
			UnmatchedBehavior: "503",
			Rules: []config.ProxyRule{
				{
					Domain:  "exist.example.com",
					Enabled: true,
					Backends: []config.ProxyBackend{
						{ID: "b1", Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true},
					},
				},
			},
		},
	}
	var saveCount int32
	var ensureCount int32
	return &Deps{
		Version:    "0.0.0-test",
		Config:     cfg,
		ConfigFile: "/tmp/sslcat-test.conf",
		SaveConfig: func() error {
			atomic.AddInt32(&saveCount, 1)
			return nil
		},
		EnsureCert: func(domain string) {
			atomic.AddInt32(&ensureCount, 1)
		},
	}, &saveCount, &ensureCount
}

func callWriter(t *testing.T, reg *mcp.Registry, name string, argsJSON string, confirmed bool) mcp.ToolResult {
	t.Helper()
	tool, ok := reg.GetTool(name)
	if !ok {
		t.Fatalf("tool %s not registered", name)
	}
	caller := &mcp.CallContext{
		TokenName: "ut",
		Scopes:    []mcp.Scope{mcp.ScopeSiteWrite},
		Confirmed: confirmed,
	}
	res, err := tool.Handler(context.Background(), json.RawMessage(argsJSON), caller)
	if err != nil {
		t.Fatalf("tool %s error: %v", name, err)
	}
	return res
}

func parseToolJSON(t *testing.T, r mcp.ToolResult, out any) {
	t.Helper()
	if r.IsError {
		t.Fatalf("tool returned error: %+v", r)
	}
	if err := json.Unmarshal([]byte(r.Content[0].Text), out); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, r.Content[0].Text)
	}
}

func TestRegisterSiteWriters_AllRegistered(t *testing.T) {
	deps, _, _ := newWritableDeps()
	reg := mcp.NewRegistry()
	if err := RegisterSiteWriters(reg, deps); err != nil {
		t.Fatalf("register: %v", err)
	}
	for _, n := range []string{"site_add", "site_update", "site_enable", "site_disable", "site_delete"} {
		tool, ok := reg.GetTool(n)
		if !ok {
			t.Errorf("tool %s missing", n)
		} else if tool.Scope != mcp.ScopeSiteWrite {
			t.Errorf("tool %s scope=%s, want site:write", n, tool.Scope)
		}
	}
	if del, _ := reg.GetTool("site_delete"); del != nil && !del.Destructive {
		t.Error("site_delete should be destructive")
	}
}

func TestSiteAdd_Success(t *testing.T) {
	deps, saveCount, ensureCount := newWritableDeps()
	reg := mcp.NewRegistry()
	_ = RegisterSiteWriters(reg, deps)

	args := `{"domain":"new.example.com","backend":{"host":"127.0.0.1","port":8081},"ssl_only":true}`
	res := callWriter(t, reg, "site_add", args, true)
	var out struct {
		OK   bool `json:"ok"`
		Site struct {
			Domain  string `json:"domain"`
			Enabled bool   `json:"enabled"`
		} `json:"site"`
	}
	parseToolJSON(t, res, &out)
	if !out.OK || out.Site.Domain != "new.example.com" || !out.Site.Enabled {
		t.Fatalf("unexpected result: %+v", out)
	}
	if len(deps.Config.Proxy.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(deps.Config.Proxy.Rules))
	}
	if atomic.LoadInt32(saveCount) != 1 {
		t.Errorf("expected 1 save, got %d", *saveCount)
	}
	if atomic.LoadInt32(ensureCount) != 1 {
		t.Errorf("expected 1 EnsureCert call (enabled site), got %d", *ensureCount)
	}
}

func TestSiteAdd_DomainConflict(t *testing.T) {
	deps, _, _ := newWritableDeps()
	reg := mcp.NewRegistry()
	_ = RegisterSiteWriters(reg, deps)

	args := `{"domain":"exist.example.com","backend":{"host":"127.0.0.1","port":8000}}`
	res := callWriter(t, reg, "site_add", args, true)
	if !res.IsError {
		t.Fatalf("expected error result on conflict, got %+v", res)
	}
	if !strings.Contains(res.Content[0].Text, "already exists") {
		t.Errorf("expected 'already exists' message, got %s", res.Content[0].Text)
	}
}

func TestSiteAdd_InvalidDomain(t *testing.T) {
	deps, _, _ := newWritableDeps()
	reg := mcp.NewRegistry()
	_ = RegisterSiteWriters(reg, deps)

	cases := []string{
		`{"domain":"","backend":{"host":"1.2.3.4","port":80}}`,
		`{"domain":"http://x.com","backend":{"host":"1.2.3.4","port":80}}`,
		`{"domain":"x","backend":{"host":"1.2.3.4","port":80}}`,
	}
	for _, args := range cases {
		res := callWriter(t, reg, "site_add", args, true)
		if !res.IsError {
			t.Errorf("expected error for args=%s, got %+v", args, res)
		}
	}
}

func TestSiteAdd_BackendValidation(t *testing.T) {
	deps, _, _ := newWritableDeps()
	reg := mcp.NewRegistry()
	_ = RegisterSiteWriters(reg, deps)

	// 端口越界
	res := callWriter(t, reg, "site_add",
		`{"domain":"new.example.com","backend":{"host":"1.2.3.4","port":99999}}`, true)
	if !res.IsError {
		t.Errorf("expected port out-of-range error")
	}
	// 缺 backend
	res = callWriter(t, reg, "site_add", `{"domain":"new.example.com"}`, true)
	if !res.IsError {
		t.Errorf("expected backend required error")
	}
}

func TestSiteUpdate_PatchFields(t *testing.T) {
	deps, saveCount, _ := newWritableDeps()
	reg := mcp.NewRegistry()
	_ = RegisterSiteWriters(reg, deps)

	res := callWriter(t, reg, "site_update",
		`{"domain":"exist.example.com","ssl_only":true,"backends":[{"host":"10.0.0.2","port":9090,"weight":2}]}`, true)
	var out struct {
		OK bool `json:"ok"`
	}
	parseToolJSON(t, res, &out)
	if !out.OK {
		t.Fatalf("update should succeed")
	}
	r := deps.Config.Proxy.Rules[0]
	if !r.SSLOnly {
		t.Error("ssl_only patch not applied")
	}
	if len(r.Backends) != 1 || r.Backends[0].Port != 9090 || r.Backends[0].Weight != 2 {
		t.Errorf("backends replacement failed: %+v", r.Backends)
	}
	if atomic.LoadInt32(saveCount) != 1 {
		t.Errorf("expected 1 save, got %d", *saveCount)
	}
}

func TestSiteUpdate_NotFound(t *testing.T) {
	deps, _, _ := newWritableDeps()
	reg := mcp.NewRegistry()
	_ = RegisterSiteWriters(reg, deps)
	res := callWriter(t, reg, "site_update", `{"domain":"missing.example.com","ssl_only":true}`, true)
	if !res.IsError {
		t.Fatalf("expected error for missing domain")
	}
}

func TestSiteEnable_Disable(t *testing.T) {
	deps, saveCount, ensureCount := newWritableDeps()
	reg := mcp.NewRegistry()
	_ = RegisterSiteWriters(reg, deps)

	// disable
	callWriter(t, reg, "site_disable", `{"domain":"exist.example.com"}`, true)
	if deps.Config.Proxy.Rules[0].Enabled {
		t.Error("disable failed")
	}
	// enable (应触发一次 EnsureCert)
	callWriter(t, reg, "site_enable", `{"domain":"exist.example.com"}`, true)
	if !deps.Config.Proxy.Rules[0].Enabled {
		t.Error("enable failed")
	}
	if atomic.LoadInt32(ensureCount) != 1 {
		t.Errorf("enable should trigger 1 EnsureCert, got %d", *ensureCount)
	}
	// no-op (enable 已启用，不应再保存)
	before := atomic.LoadInt32(saveCount)
	res := callWriter(t, reg, "site_enable", `{"domain":"exist.example.com"}`, true)
	var out struct {
		NoOp bool `json:"no_op"`
	}
	parseToolJSON(t, res, &out)
	if !out.NoOp {
		t.Error("expected no_op when already enabled")
	}
	if atomic.LoadInt32(saveCount) != before {
		t.Error("no-op should not save")
	}
}

func TestSiteDelete_TwoPhase(t *testing.T) {
	deps, saveCount, _ := newWritableDeps()
	reg := mcp.NewRegistry()
	_ = RegisterSiteWriters(reg, deps)

	// 第一次：未 confirmed → dry-run
	res := callWriter(t, reg, "site_delete", `{"domain":"exist.example.com"}`, false)
	var dry struct {
		RequiresConfirmation bool `json:"requires_confirmation"`
		Preview              struct {
			Action string `json:"action"`
		} `json:"preview"`
	}
	parseToolJSON(t, res, &dry)
	if !dry.RequiresConfirmation || dry.Preview.Action != "delete" {
		t.Fatalf("expected dry-run preview, got %+v", dry)
	}
	if len(deps.Config.Proxy.Rules) != 1 {
		t.Error("dry-run should not actually delete")
	}
	if atomic.LoadInt32(saveCount) != 0 {
		t.Error("dry-run should not save")
	}

	// 第二次：confirmed=true → 真正删
	res = callWriter(t, reg, "site_delete", `{"domain":"exist.example.com","confirm":"whatever"}`, true)
	var done struct {
		OK bool `json:"ok"`
	}
	parseToolJSON(t, res, &done)
	if !done.OK {
		t.Fatalf("expected ok=true on confirmed delete")
	}
	if len(deps.Config.Proxy.Rules) != 0 {
		t.Error("confirmed delete should remove rule")
	}
	if atomic.LoadInt32(saveCount) != 1 {
		t.Errorf("expected 1 save, got %d", *saveCount)
	}
}

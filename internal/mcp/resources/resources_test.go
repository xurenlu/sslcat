package resources

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/mcp"
)

func newTestDeps(t *testing.T) *Deps {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		AdminPrefix: "/sslcat-panel",
		Admin: config.AdminConfig{
			Username: "admin",
			Password: "super-secret",
		},
		SSL: config.SSLConfig{
			Email: "user@example.com",
			DNSProviders: []config.DNSProvider{
				{Name: "cf", Type: "cloudflare", APIKey: "secret-key", APISecret: "secret-secret", Enabled: true},
			},
		},
		Server: config.ServerConfig{
			SecretKey:        "should-be-hidden",
			AccessLogEnabled: true,
			AccessLogPath:    filepath.Join(dir, "access.log"),
			ErrorLogEnabled:  true,
			ErrorLogPath:     filepath.Join(dir, "error.log"),
		},
		MCP: config.MCPConfig{
			Enabled: true,
			Tokens: []config.MCPToken{
				{Name: "tk1", TokenHash: "$argon2id$v=19$m=64,t=1,p=2$abc$def", Scopes: []string{"read"}},
			},
		},
		Proxy: config.ProxyConfig{
			Rules: []config.ProxyRule{
				{Domain: "a.example.com", Enabled: true},
				{Domain: "b.example.com", Enabled: false, ErrorLogPath: filepath.Join(dir, "b-error.log")},
			},
		},
		StaticSites: []config.StaticSite{
			{Domain: "static.example.com", Enabled: true, ErrorLogPath: filepath.Join(dir, "static-error.log")},
		},
		PHPSites: []config.PHPSite{
			{Domain: "php.example.com", Enabled: true, Root: filepath.Join(dir, "php-root")},
		},
		Cluster: config.ClusterConfig{Mode: "standalone"},
	}
	return &Deps{
		Version:    "0.0.0-test",
		Config:     cfg,
		ConfigFile: filepath.Join(dir, "sslcat.conf"),
		Tasks:      mcp.NewTaskRegistry(),
	}
}

func TestRegister_AllRegistered(t *testing.T) {
	d := newTestDeps(t)
	defer d.Tasks.Close()
	reg := mcp.NewResourceRegistry()
	if err := Register(reg, d); err != nil {
		t.Fatalf("register: %v", err)
	}
	if len(reg.ListResources()) != 3 {
		t.Errorf("expected 3 static resources, got %d", len(reg.ListResources()))
	}
	if len(reg.ListTemplates()) != 2 {
		t.Errorf("expected 2 templates, got %d", len(reg.ListTemplates()))
	}
	for _, uri := range []string{"sslcat://config/current", "sslcat://metrics/snapshot", "sslcat://logs/error-sources"} {
		if _, _, ok := reg.Resolve(uri); !ok {
			t.Errorf("resource %s not resolvable", uri)
		}
	}
	if _, _, ok := reg.Resolve("sslcat://logs/access?since=10m"); !ok {
		t.Error("logs template not resolvable with query")
	}
	if _, _, ok := reg.Resolve("sslcat://logs/error?id=internal&limit=20"); !ok {
		t.Error("error logs template not resolvable with query")
	}
}

func TestConfigCurrent_Redacted(t *testing.T) {
	d := newTestDeps(t)
	defer d.Tasks.Close()
	reg := mcp.NewResourceRegistry()
	_ = Register(reg, d)
	reader, _, _ := reg.Resolve("sslcat://config/current")
	_, body, err := reader(context.Background(), "sslcat://config/current", nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// 这些值必须不出现在脱敏输出里
	for _, naked := range []string{"super-secret", "secret-key", "secret-secret", "should-be-hidden"} {
		if strings.Contains(body, naked) {
			t.Errorf("sensitive value leaked: %q in body=%s", naked, body)
		}
	}
	// 普通字段应保留
	for _, kept := range []string{"a.example.com", "user@example.com"} {
		if !strings.Contains(body, kept) {
			t.Errorf("non-sensitive value missing: %q", kept)
		}
	}
	// 原始 config 没被修改（脱敏只动 clone）
	if d.Config.Admin.Password != "super-secret" {
		t.Error("redaction mutated original config")
	}
}

func TestConfigCurrent_NoConfig(t *testing.T) {
	d := &Deps{}
	reg := mcp.NewResourceRegistry()
	_ = Register(reg, d)
	reader, _, _ := reg.Resolve("sslcat://config/current")
	if _, _, err := reader(context.Background(), "sslcat://config/current", nil); err == nil {
		t.Error("expected error when config nil")
	}
}

func TestMetricsSnapshot(t *testing.T) {
	d := newTestDeps(t)
	defer d.Tasks.Close()
	d.Tasks.Create("cert_issue", "alice", nil)
	reg := mcp.NewResourceRegistry()
	_ = Register(reg, d)
	reader, _, _ := reg.Resolve("sslcat://metrics/snapshot")
	mime, body, err := reader(context.Background(), "sslcat://metrics/snapshot", nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if mime != "application/json" {
		t.Errorf("mime=%s", mime)
	}
	var snap map[string]any
	if err := json.Unmarshal([]byte(body), &snap); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if snap["sites_total"].(float64) != 2 {
		t.Errorf("sites_total=%v", snap["sites_total"])
	}
	if snap["sites_enabled"].(float64) != 1 {
		t.Errorf("sites_enabled=%v", snap["sites_enabled"])
	}
	if snap["mcp_tasks_total"].(float64) != 1 {
		t.Errorf("mcp_tasks_total=%v", snap["mcp_tasks_total"])
	}
}

func TestLogsAccess_TimeAndDomainFilter(t *testing.T) {
	d := newTestDeps(t)
	defer d.Tasks.Close()
	// 写一份日志：3 条早的、3 条新的
	old := time.Now().Add(-2 * time.Hour).Format("02/Jan/2006:15:04:05 -0700")
	now := time.Now().Add(-1 * time.Minute).Format("02/Jan/2006:15:04:05 -0700")
	lines := []string{
		`1.1.1.1 - - [` + old + `] "GET / HTTP/1.1" 200 0 "-" "-" "a.example.com"`,
		`1.1.1.1 - - [` + old + `] "GET / HTTP/1.1" 200 0 "-" "-" "b.example.com"`,
		`1.1.1.1 - - [` + old + `] "GET / HTTP/1.1" 200 0 "-" "-" "a.example.com"`,
		`2.2.2.2 - - [` + now + `] "GET / HTTP/1.1" 200 0 "-" "-" "a.example.com"`,
		`2.2.2.2 - - [` + now + `] "GET / HTTP/1.1" 200 0 "-" "-" "b.example.com"`,
		`2.2.2.2 - - [` + now + `] "GET / HTTP/1.1" 200 0 "-" "-" "a.example.com"`,
	}
	if err := os.WriteFile(d.Config.Server.AccessLogPath,
		[]byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	reg := mcp.NewResourceRegistry()
	_ = Register(reg, d)
	reader, _, _ := reg.Resolve("sslcat://logs/access?since=10m")

	// since 过滤：只剩 3 条新行
	_, body, err := reader(context.Background(), "sslcat://logs/access?since=10m", nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := countLogLines(body); got != 3 {
		t.Errorf("expected 3 log lines after since filter, got %d body=%s", got, body)
	}

	// 同时 since + domain：剩 2 条
	_, body, err = reader(context.Background(), "sslcat://logs/access?since=10m&domain=a.example.com", nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := countLogLines(body); got != 2 {
		t.Errorf("expected 2 log lines after since+domain filter, got %d body=%s", got, body)
	}
}

// countLogLines 排除 header 行（# 开头），返回剩余非空行数。
func countLogLines(body string) int {
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
	}
	return n
}

func TestLogsAccess_LimitCap(t *testing.T) {
	d := newTestDeps(t)
	defer d.Tasks.Close()
	// 写 30 行
	var sb strings.Builder
	for i := 0; i < 30; i++ {
		sb.WriteString("line ")
		sb.WriteString(time.Now().Format("02/Jan/2006:15:04:05 -0700"))
		sb.WriteString("\n")
	}
	if err := os.WriteFile(d.Config.Server.AccessLogPath, []byte(sb.String()), 0644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	reg := mcp.NewResourceRegistry()
	_ = Register(reg, d)
	reader, _, _ := reg.Resolve("sslcat://logs/access?limit=10")
	_, body, _ := reader(context.Background(), "sslcat://logs/access?limit=10", nil)
	if got := countLogLines(body); got != 10 {
		t.Errorf("expected 10 log lines (limit cap), got %d body=%s", got, body)
	}
}

func TestLogsAccess_InvalidSince(t *testing.T) {
	d := newTestDeps(t)
	defer d.Tasks.Close()
	_ = os.WriteFile(d.Config.Server.AccessLogPath, []byte{}, 0644)
	reg := mcp.NewResourceRegistry()
	_ = Register(reg, d)
	reader, _, _ := reg.Resolve("sslcat://logs/access?since=invalid")
	_, _, err := reader(context.Background(), "sslcat://logs/access?since=invalid", nil)
	if err == nil {
		t.Error("expected error for invalid since")
	}
}

func TestLogsErrorSources(t *testing.T) {
	d := newTestDeps(t)
	defer d.Tasks.Close()
	_ = os.WriteFile(d.Config.Server.ErrorLogPath, []byte("internal error\n"), 0644)
	_ = os.WriteFile(d.Config.Proxy.Rules[1].ErrorLogPath, []byte("b error\n"), 0644)
	reg := mcp.NewResourceRegistry()
	_ = Register(reg, d)
	reader, _, _ := reg.Resolve("sslcat://logs/error-sources")
	mime, body, err := reader(context.Background(), "sslcat://logs/error-sources", nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if mime != "application/json" {
		t.Errorf("mime=%s", mime)
	}
	if !strings.Contains(body, "internal") || !strings.Contains(body, "proxy:b.example.com") {
		t.Fatalf("expected internal and proxy sources, body=%s", body)
	}
}

func TestLogsErrorTail(t *testing.T) {
	d := newTestDeps(t)
	defer d.Tasks.Close()
	now := time.Now().Add(-1 * time.Minute).Format(time.RFC3339)
	old := time.Now().Add(-2 * time.Hour).Format(time.RFC3339)
	lines := []string{
		old + " ERROR old a.example.com",
		now + " ERROR fresh a.example.com backend failed",
		now + " WARN fresh b.example.com",
		now + " ERROR fresh a.example.com panic recovered",
	}
	if err := os.WriteFile(d.Config.Server.ErrorLogPath, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	reg := mcp.NewResourceRegistry()
	_ = Register(reg, d)
	reader, _, _ := reg.Resolve("sslcat://logs/error?id=internal&since=10m&domain=a.example.com&keyword=ERROR")
	_, body, err := reader(context.Background(), "sslcat://logs/error?id=internal&since=10m&domain=a.example.com&keyword=ERROR", nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := countLogLines(body); got != 2 {
		t.Errorf("expected 2 recent error lines, got %d body=%s", got, body)
	}
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, "ERROR old ") {
			t.Errorf("old line should be filtered, body=%s", body)
		}
	}
}

func TestParseSince(t *testing.T) {
	now := time.Date(2026, 6, 3, 10, 0, 0, 0, time.UTC)
	// duration
	got, err := parseSince("30m", now)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	want := now.Add(-30 * time.Minute)
	if !got.Equal(want) {
		t.Errorf("got=%v want=%v", got, want)
	}
	// RFC3339
	got, err = parseSince("2026-06-03T09:00:00Z", now)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got.Format(time.RFC3339) != "2026-06-03T09:00:00Z" {
		t.Errorf("rfc3339 parse failed: %v", got)
	}
}

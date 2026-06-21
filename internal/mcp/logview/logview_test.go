package logview

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

func boolPtr(v bool) *bool { return &v }

func TestListSourcesIncludesInternalAndAllSiteKinds(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		Server: config.ServerConfig{
			ErrorLogEnabled: true,
			ErrorLogPath:    filepath.Join(dir, "global-error.log"),
		},
		Proxy: config.ProxyConfig{Rules: []config.ProxyRule{
			{Domain: "proxy.example.com", ErrorLogPath: filepath.Join(dir, "proxy-error.log")},
		}},
		StaticSites: []config.StaticSite{
			{Domain: "static.example.com", ErrorLogEnabled: boolPtr(false)},
		},
		PHPSites: []config.PHPSite{
			{
				Domain: "php.example.com",
				Root:   filepath.Join(dir, "php-root"),
				MonitoringConfig: &config.PHPMonitoringConfig{
					LogFile: filepath.Join(dir, "php-monitor.log"),
				},
			},
		},
	}
	if err := os.WriteFile(cfg.Server.ErrorLogPath, []byte("global\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "php-monitor.log"), []byte("php\n"), 0644); err != nil {
		t.Fatal(err)
	}

	sources := ListSources(cfg)
	if len(sources) != 4 {
		t.Fatalf("got %d sources, want 4: %+v", len(sources), sources)
	}
	seen := map[string]Source{}
	for _, src := range sources {
		seen[src.ID] = src
	}
	if !seen["internal"].Exists {
		t.Errorf("internal source should exist: %+v", seen["internal"])
	}
	if seen["static:static.example.com"].Enabled {
		t.Errorf("static source should honor disabled override")
	}
	if got := seen["php:php.example.com"].Path; !strings.HasSuffix(got, "php-monitor.log") {
		t.Errorf("php source should prefer monitoring log file, got %s", got)
	}
	if !seen["php:php.example.com"].Exists {
		t.Errorf("php source should stat monitoring log file")
	}
}

func TestReadTailFiltersRecentErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "error.log")
	oldTS := time.Now().Add(-2 * time.Hour).Format(time.RFC3339)
	newTS := time.Now().Add(-2 * time.Minute).Format(time.RFC3339)
	lines := []string{
		oldTS + " ERROR old proxy.example.com",
		newTS + " ERROR fresh proxy.example.com db timeout",
		newTS + " WARN fresh other.example.com",
		newTS + " ERROR fresh proxy.example.com upstream failed",
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	res, err := ReadTail(Source{ID: "proxy:proxy.example.com", Kind: "proxy", Domain: "proxy.example.com", Path: path, Enabled: true}, TailOptions{
		Limit:   10,
		Since:   time.Now().Add(-10 * time.Minute),
		Domain:  "proxy.example.com",
		Keyword: "ERROR",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.LineCount != 2 {
		t.Fatalf("got %d lines, want 2: %+v", res.LineCount, res.Lines)
	}
	if strings.Contains(strings.Join(res.Lines, "\n"), "old") {
		t.Fatalf("old line should be filtered: %+v", res.Lines)
	}
}

func TestReadTailUsesBoundedFileTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.log")
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString("padding line that should be outside small tail window\n")
	}
	sb.WriteString("last visible error\n")
	if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		t.Fatal(err)
	}
	res, err := ReadTail(Source{ID: "internal", Kind: "internal", Path: path, Enabled: true}, TailOptions{
		Limit:    5,
		MaxBytes: 128,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated {
		t.Fatal("expected truncated tail read")
	}
	if res.LineCount == 0 || res.Lines[len(res.Lines)-1] != "last visible error" {
		t.Fatalf("tail should include last line, got %+v", res.Lines)
	}
}

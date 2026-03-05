package statistics

import (
	"testing"
	"time"
)

func TestParseDomainFromPath(t *testing.T) {
	tests := []struct {
		path      string
		wantDomain string
		wantPath  string
	}{
		{"", "", ""},
		{"/api/users", "", "/api/users"},
		{"example.com:/api/v1/*", "example.com", "/api/v1/*"},
		{"log.17push.com:/api/v1/ingest/*", "log.17push.com", "/api/v1/ingest/*"},
		{"/api/v1:xxx", "", "/api/v1:xxx"}, // path 含冒号但非 domain:path 格式
	}
	for _, tt := range tests {
		domain, pathPart := parseDomainFromPath(tt.path)
		if domain != tt.wantDomain || pathPart != tt.wantPath {
			t.Errorf("parseDomainFromPath(%q) = (%q, %q), want (%q, %q)",
				tt.path, domain, pathPart, tt.wantDomain, tt.wantPath)
		}
	}
}

func TestAPIPerformanceCollector_GetDomains(t *testing.T) {
	apc := NewAPIPerformanceCollector()
	defer apc.Stop()

	// 无数据时
	domains := apc.GetDomains()
	if len(domains) != 0 {
		t.Errorf("GetDomains() empty = %v, want []", domains)
	}

	// 记录带域名的请求
	apc.Record(APIPerformanceEntry{
		Path:         "a.example.com:/api/v1/users",
		Method:       "GET",
		Status:       200,
		ResponseTime: 10 * time.Millisecond,
		Timestamp:    time.Now(),
	})
	apc.Record(APIPerformanceEntry{
		Path:         "b.example.com:/api/v1/orders",
		Method:       "POST",
		Status:       200,
		ResponseTime: 20 * time.Millisecond,
		Timestamp:    time.Now(),
	})
	apc.Record(APIPerformanceEntry{
		Path:         "a.example.com:/api/v1/orders",
		Method:       "GET",
		Status:       200,
		ResponseTime: 15 * time.Millisecond,
		Timestamp:    time.Now(),
	})

	domains = apc.GetDomains()
	if len(domains) != 2 {
		t.Errorf("GetDomains() = %v, want 2 unique domains", domains)
	}
	// 应排序
	if domains[0] != "a.example.com" || domains[1] != "b.example.com" {
		t.Errorf("GetDomains() = %v, want [a.example.com, b.example.com]", domains)
	}
}

func TestAPIPerformanceCollector_DomainFilter(t *testing.T) {
	apc := NewAPIPerformanceCollector()
	defer apc.Stop()

	apc.Record(APIPerformanceEntry{
		Path:         "site1.com:/api/users",
		Method:       "GET",
		Status:       200,
		ResponseTime: 100 * time.Millisecond,
		Timestamp:    time.Now(),
	})
	apc.Record(APIPerformanceEntry{
		Path:         "site2.com:/api/orders",
		Method:       "GET",
		Status:       200,
		ResponseTime: 200 * time.Millisecond,
		Timestamp:    time.Now(),
	})

	// 不过滤
	stats := apc.GetStats("")
	if len(stats) != 2 {
		t.Errorf("GetStats(\"\") = %d, want 2", len(stats))
	}

	// 按 domain 过滤
	stats = apc.GetStats("site1.com")
	if len(stats) != 1 {
		t.Errorf("GetStats(\"site1.com\") = %d, want 1", len(stats))
	}
	if len(stats) > 0 && stats[0].Domain != "site1.com" {
		t.Errorf("GetStats domain = %q, want site1.com", stats[0].Domain)
	}

	// 不存在的 domain
	stats = apc.GetStats("nonexistent.com")
	if len(stats) != 0 {
		t.Errorf("GetStats(\"nonexistent.com\") = %d, want 0", len(stats))
	}
}

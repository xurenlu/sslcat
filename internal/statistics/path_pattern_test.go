package statistics

import (
	"net/http"
	"testing"
)

func TestBuildAPIPatternKey(t *testing.T) {
	tests := []struct {
		host, path string
		want       string
	}{
		{"", "/api/users/123", "/api/users/*"},
		{"log.17push.com", "/api/v1/ingest/123", "log.17push.com:/api/v1/ingest/*"},
		{"api.example.com:443", "/api/orders/1", "api.example.com:/api/orders/*"},
	}
	for _, tt := range tests {
		got := BuildAPIPatternKey(tt.host, tt.path)
		if got != tt.want {
			t.Errorf("BuildAPIPatternKey(%q, %q) = %q, want %q", tt.host, tt.path, got, tt.want)
		}
	}
}

func TestToPathPattern(t *testing.T) {
	tests := []struct {
		path    string
		want    string
	}{
		{"/api/users/123", "/api/users/*"},
		{"/api/users/456", "/api/users/*"},
		{"/api/v1/users", "/api/v1/users"},
		{"/api/orders/550e8400-e29b-41d4-a716-446655440000", "/api/orders/*"},
		{"/api/logs/abc123def4567890", "/api/logs/*"}, // 16+ hex chars
		{"/api/test", "/api/test"},
		{"/", "/"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := ToPathPattern(tt.path); got != tt.want {
				t.Errorf("ToPathPattern(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// TestSecondaryLearning 二次学习：不同 URL 归一化后共享学习结果
func TestSecondaryLearning(t *testing.T) {
	analyzer := NewResponseAnalyzer()

	// /api/users/1, /api/users/2, /api/users/3 归一化为 /api/users/*
	// 用 code=100 成功，各喂 5 次 2xx
	for _, id := range []string{"1", "2", "3"} {
		for i := 0; i < 5; i++ {
			resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}}
			analyzer.AnalyzeResponse(resp, []byte(`{"code": 100, "data": {}}`), "", "/api/users/"+id)
		}
	}
	// 再喂几次失败
	for i := 0; i < 5; i++ {
		resp := &http.Response{StatusCode: 500, Header: http.Header{"Content-Type": []string{"application/json"}}}
		analyzer.AnalyzeResponse(resp, []byte(`{"code": -1, "error": "err"}`), "", "/api/users/1")
	}

	// 新 ID /api/users/999 应直接受益，无需再学习
	resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}}
	status, _ := analyzer.AnalyzeResponse(resp, []byte(`{"code": 100}`), "", "/api/users/999")
	if status == nil {
		t.Fatal("AnalyzeResponse() = nil, want success (should inherit from /api/users/*)")
	}
	if !status.IsSuccess {
		t.Errorf("AnalyzeResponse() IsSuccess = false, want true (code=100 learned as success for /api/users/*)")
	}
}

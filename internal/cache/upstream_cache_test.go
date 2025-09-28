package cache

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

func TestUpstreamCache_ShouldCache(t *testing.T) {
	cfg := &config.Config{}
	uc := NewUpstreamCache(cfg)

	tests := []struct {
		name          string
		statusCode    int
		contentType   string
		contentLength int64
		cacheControl  string
		expected      bool
	}{
		{
			name:          "CSS file should be cached",
			statusCode:    200,
			contentType:   "text/css",
			contentLength: 2048,
			expected:      true,
		},
		{
			name:          "JavaScript file should be cached",
			statusCode:    200,
			contentType:   "application/javascript",
			contentLength: 5120,
			expected:      true,
		},
		{
			name:          "Image file should be cached",
			statusCode:    200,
			contentType:   "image/png",
			contentLength: 10240,
			expected:      true,
		},
		{
			name:          "JSON file should be cached",
			statusCode:    200,
			contentType:   "application/json",
			contentLength: 3072,
			expected:      true,
		},
		{
			name:          "File too small should not be cached",
			statusCode:    200,
			contentType:   "text/css",
			contentLength: 512,
			expected:      false,
		},
		{
			name:          "Non-200 status should not be cached",
			statusCode:    404,
			contentType:   "text/css",
			contentLength: 2048,
			expected:      false,
		},
		{
			name:          "No-cache directive should not be cached",
			statusCode:    200,
			contentType:   "text/css",
			contentLength: 2048,
			cacheControl:  "no-cache",
			expected:      false,
		},
		{
			name:          "Private directive should not be cached",
			statusCode:    200,
			contentType:   "text/css",
			contentLength: 2048,
			cacheControl:  "private",
			expected:      false,
		},
		{
			name:          "Max-age directive should be cached",
			statusCode:    200,
			contentType:   "text/css",
			contentLength: 2048,
			cacheControl:  "max-age=3600",
			expected:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建模拟响应
			resp := &http.Response{
				StatusCode:    tt.statusCode,
				ContentLength: tt.contentLength,
				Header:        make(http.Header),
			}

			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}

			if tt.cacheControl != "" {
				resp.Header.Set("Cache-Control", tt.cacheControl)
			}

			result := uc.ShouldCache(resp)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestUpstreamCache_CacheControlParsing(t *testing.T) {
	cfg := &config.Config{}
	uc := NewUpstreamCache(cfg)

	tests := []struct {
		cacheControl string
		expected     time.Duration
	}{
		{"max-age=3600", 3600 * time.Second},
		{"max-age=7200, must-revalidate", 7200 * time.Second},
		{"public, max-age=86400", 86400 * time.Second},
		{"no-cache", 0},
		{"invalid", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.cacheControl, func(t *testing.T) {
			result := uc.parseCacheControlMaxAge(tt.cacheControl)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestUpstreamCache_ExpirationCalculation(t *testing.T) {
	cfg := &config.Config{}
	uc := NewUpstreamCache(cfg)
	uc.defaultTTL = 1 * time.Hour

	now := time.Now()

	tests := []struct {
		name         string
		expires      string
		cacheControl string
		expectDiff   time.Duration
		tolerance    time.Duration
	}{
		{
			name:       "Explicit Expires header",
			expires:    now.Add(2 * time.Hour).Format(time.RFC1123),
			expectDiff: 2 * time.Hour,
			tolerance:  1 * time.Minute,
		},
		{
			name:         "Cache-Control max-age",
			cacheControl: "max-age=1800",
			expectDiff:   30 * time.Minute,
			tolerance:    1 * time.Minute,
		},
		{
			name:       "Default TTL",
			expectDiff: 1 * time.Hour,
			tolerance:  1 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Header: make(http.Header),
			}

			if tt.expires != "" {
				resp.Header.Set("Expires", tt.expires)
			}

			if tt.cacheControl != "" {
				resp.Header.Set("Cache-Control", tt.cacheControl)
			}

			expiresAt := uc.calculateExpiresAt(resp)
			actualDiff := expiresAt.Sub(now)

			if actualDiff < tt.expectDiff-tt.tolerance || actualDiff > tt.expectDiff+tt.tolerance {
				t.Errorf("Expected expiration ~%v, got %v", tt.expectDiff, actualDiff)
			}
		})
	}
}

func TestUpstreamCache_StoreAndRetrieve(t *testing.T) {
	// 创建临时目录
	tempDir, err := ioutil.TempDir("", "upstream_cache_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		CDNCache: config.CDNCacheConfig{
			CacheDir: tempDir,
		},
	}
	uc := NewUpstreamCache(cfg)

	// 创建测试请求和响应
	req := httptest.NewRequest("GET", "/test.css", nil)

	resp := &http.Response{
		StatusCode:    200,
		ContentLength: 1024,
		Header:        make(http.Header),
		Body:          ioutil.NopCloser(strings.NewReader("body { color: red; }")),
	}
	resp.Header.Set("Content-Type", "text/css")
	resp.Header.Set("Cache-Control", "max-age=3600")

	// 存储到缓存
	err = uc.Store(req, resp)
	if err != nil {
		t.Fatalf("Failed to store cache: %v", err)
	}

	// 从缓存检索
	entry, data, err := uc.Get(req)
	if err != nil {
		t.Fatalf("Failed to get from cache: %v", err)
	}

	if entry.StatusCode != 200 {
		t.Errorf("Expected status code 200, got %d", entry.StatusCode)
	}

	if entry.ContentType != "text/css" {
		t.Errorf("Expected content type text/css, got %s", entry.ContentType)
	}

	if string(data) != "body { color: red; }" {
		t.Errorf("Expected body content not matched")
	}

	// 测试缓存命中
	if !uc.Serve(httptest.NewRecorder(), req) {
		t.Error("Cache serve should succeed")
	}

	// 检查统计信息
	stats := uc.GetStats()
	hits := stats["hits"].(int64)
	if hits < 1 {
		t.Errorf("Expected at least 1 hit, got %v", hits)
	}
}

func TestUpstreamCache_Expiration(t *testing.T) {
	// 创建临时目录
	tempDir, err := ioutil.TempDir("", "upstream_cache_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := &config.Config{
		CDNCache: config.CDNCacheConfig{
			CacheDir: tempDir,
		},
	}
	uc := NewUpstreamCache(cfg)
	uc.defaultTTL = 100 * time.Millisecond // 很短的TTL用于测试

	// 创建测试请求和响应
	req := httptest.NewRequest("GET", "/test.js", nil)

	resp := &http.Response{
		StatusCode:    200,
		ContentLength: 1024,
		Header:        make(http.Header),
		Body:          ioutil.NopCloser(strings.NewReader("console.log('test');")),
	}
	resp.Header.Set("Content-Type", "application/javascript")

	// 存储到缓存
	err = uc.Store(req, resp)
	if err != nil {
		t.Fatalf("Failed to store cache: %v", err)
	}

	// 立即检索应该成功
	_, _, err = uc.Get(req)
	if err != nil {
		t.Fatalf("Failed to get from cache immediately: %v", err)
	}

	// 等待过期
	time.Sleep(200 * time.Millisecond)

	// 过期后检索应该失败
	_, _, err = uc.Get(req)
	if err == nil {
		t.Error("Expected cache miss after expiration")
	}
}

func TestUpstreamCache_ContentTypeDetection(t *testing.T) {
	cfg := &config.Config{}
	uc := NewUpstreamCache(cfg)

	cacheableTypes := []string{
		"text/css",
		"text/javascript",
		"application/javascript",
		"image/png",
		"image/jpeg",
		"image/gif",
		"image/webp",
		"image/svg+xml",
		"font/woff2",
		"application/json",
	}

	nonCacheableTypes := []string{
		"application/octet-stream",
		"video/mp4",
		"audio/mp3",
		"application/pdf",
	}

	for _, contentType := range cacheableTypes {
		if !uc.isCacheableContentType(contentType) {
			t.Errorf("Content type %s should be cacheable", contentType)
		}
	}

	for _, contentType := range nonCacheableTypes {
		if uc.isCacheableContentType(contentType) {
			t.Errorf("Content type %s should not be cacheable", contentType)
		}
	}
}

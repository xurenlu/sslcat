package cache

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestUpstreamCache_HotHitDoesNotRewriteMetadata(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		UpstreamCache: config.UpstreamCacheConfig{
			Enabled:     true,
			CacheDir:    tempDir,
			MinFileSize: 1,
			MaxFileSize: 1024 * 1024,
			DefaultTTL:  time.Hour,
			CacheableTypes: []string{
				"text/css",
			},
		},
	}
	uc := NewUpstreamCache(cfg)

	req := httptest.NewRequest("GET", "/hot.css", nil)
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		ContentLength: int64(len("body { color: blue; }")),
		Header:        make(http.Header),
		Body:          ioutil.NopCloser(strings.NewReader("body { color: blue; }")),
	}
	resp.Header.Set("Content-Type", "text/css")
	resp.Header.Set("Cache-Control", "max-age=3600")

	if err := uc.Store(req, resp); err != nil {
		t.Fatalf("store cache: %v", err)
	}

	metaPath := uc.getMetaPath(uc.generateCacheKey(req))
	before, err := os.Stat(metaPath)
	if err != nil {
		t.Fatalf("stat metadata before get: %v", err)
	}

	if _, _, err := uc.Get(req); err != nil {
		t.Fatalf("get cache: %v", err)
	}

	after, err := os.Stat(metaPath)
	if err != nil {
		t.Fatalf("stat metadata after get: %v", err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("hot cache hit should not rewrite metadata, before %v after %v", before.ModTime(), after.ModTime())
	}
}

func TestUpstreamCache_ConcurrentSameKeyStoreAndGet(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		UpstreamCache: config.UpstreamCacheConfig{
			Enabled:     true,
			CacheDir:    tempDir,
			MinFileSize: 1,
			MaxFileSize: 1024 * 1024,
			DefaultTTL:  time.Hour,
		},
	}
	uc := NewUpstreamCache(cfg)
	req := httptest.NewRequest("GET", "/asset.js", nil)
	body := bytes.Repeat([]byte("x"), 2048)

	newResp := func() *http.Response {
		resp := &http.Response{
			StatusCode:    http.StatusOK,
			ContentLength: int64(len(body)),
			Header:        make(http.Header),
			Body:          ioutil.NopCloser(bytes.NewReader(body)),
		}
		resp.Header.Set("Content-Type", "application/javascript")
		resp.Header.Set("Cache-Control", "max-age=3600")
		return resp
	}

	if err := uc.Store(req, newResp()); err != nil {
		t.Fatalf("initial store: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 64)
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := uc.Store(req, newResp()); err != nil {
				errCh <- err
			}
		}()
		go func() {
			defer wg.Done()
			_, data, err := uc.Get(req)
			if err != nil {
				errCh <- err
				return
			}
			if len(data) != len(body) {
				errCh <- os.ErrInvalid
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent cache operation failed: %v", err)
	}

	metaGlob, err := filepath.Glob(filepath.Join(tempDir, "meta", "*", "*.tmp"))
	if err != nil {
		t.Fatalf("glob temp metadata: %v", err)
	}
	dataGlob, err := filepath.Glob(filepath.Join(tempDir, "data", "*", "*.tmp"))
	if err != nil {
		t.Fatalf("glob temp data: %v", err)
	}
	if len(metaGlob)+len(dataGlob) != 0 {
		t.Fatalf("temporary cache files should be cleaned up, got meta=%v data=%v", metaGlob, dataGlob)
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

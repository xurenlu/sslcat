package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xurenlu/sslcat/internal/config"
)

func TestStaticFileHandler_DetectContentType(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "static_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 创建测试文件
	testFiles := map[string][]byte{
		"test.jpg":  {0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46},
		"test.png":  {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D},
		"test.gif":  {0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00},
		"test.html": []byte("<html><head><title>Test</title></head><body>Hello</body></html>"),
		"test.css":  []byte("body { color: red; }"),
		"test.js":   []byte("console.log('Hello');"),
		"test.pdf":  {0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34, 0x0A},
		"test.txt":  []byte("Hello World"),
	}

	// 写入测试文件
	for filename, content := range testFiles {
		filePath := filepath.Join(tempDir, filename)
		if err := os.WriteFile(filePath, content, 0644); err != nil {
			t.Fatalf("Failed to write test file %s: %v", filename, err)
		}
	}

	// 创建静态文件处理器
	cfg := &config.Config{}
	handler := NewStaticFileHandler(cfg)

	// 测试每个文件
	for filename := range testFiles {
		t.Run(filename, func(t *testing.T) {
			filePath := filepath.Join(tempDir, filename)
			file, err := os.Open(filePath)
			if err != nil {
				t.Fatalf("Failed to open file: %v", err)
			}
			defer file.Close()

			contentType := handler.detectContentType(filePath, file)

			// 验证Content-Type不为空
			if contentType == "" {
				t.Errorf("Expected non-empty Content-Type for %s", filename)
			}

			// 验证Content-Type格式
			if !strings.Contains(contentType, "/") {
				t.Errorf("Invalid Content-Type format: %s", contentType)
			}

			t.Logf("File: %s, Content-Type: %s", filename, contentType)
		})
	}
}

func TestStaticFileHandler_ServeFile(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "static_serve_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 创建测试文件
	testContent := []byte("Hello World")
	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// 创建静态文件处理器
	cfg := &config.Config{}
	handler := NewStaticFileHandler(cfg)

	// 创建测试请求
	req := httptest.NewRequest("GET", "/test.txt", nil)
	w := httptest.NewRecorder()

	// 服务文件
	err = handler.ServeFile(w, req, testFile)
	if err != nil {
		t.Fatalf("Failed to serve file: %v", err)
	}

	// 验证响应
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// 验证Content-Type
	contentType := w.Header().Get("Content-Type")
	if contentType == "" {
		t.Error("Expected Content-Type header")
	}

	// 验证Cache-Control
	cacheControl := w.Header().Get("Cache-Control")
	if cacheControl == "" {
		t.Error("Expected Cache-Control header")
	}

	// 验证ETag
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Error("Expected ETag header")
	}

	// 验证内容
	if w.Body.String() != string(testContent) {
		t.Errorf("Expected body %s, got %s", string(testContent), w.Body.String())
	}

	t.Logf("Response headers: %v", w.Header())
}

func TestStaticFileHandler_CacheHeaders(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "static_cache_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 创建不同类型的测试文件
	testFiles := map[string]string{
		"index.html":  "text/html",
		"style.css":   "text/css",
		"script.js":   "application/javascript",
		"image.jpg":   "image/jpeg",
		"font.woff":   "font/woff",
		"doc.pdf":     "application/pdf",
		"video.mp4":   "video/mp4",
		"archive.zip": "application/zip",
		"readme.txt":  "text/plain",
	}

	// 创建静态文件处理器
	cfg := &config.Config{}
	handler := NewStaticFileHandler(cfg)

	for filename := range testFiles {
		t.Run(filename, func(t *testing.T) {
			// 创建测试文件
			filePath := filepath.Join(tempDir, filename)
			if err := os.WriteFile(filePath, []byte("test content"), 0644); err != nil {
				t.Fatalf("Failed to write test file: %v", err)
			}

			// 获取文件信息
			fileInfo, err := os.Stat(filePath)
			if err != nil {
				t.Fatalf("Failed to get file info: %v", err)
			}

			// 创建测试请求和响应
			req := httptest.NewRequest("GET", "/"+filename, nil)
			w := httptest.NewRecorder()

			// 设置缓存头
			handler.setCacheHeaders(w, req, filePath, fileInfo)

			// 验证Cache-Control头
			cacheControl := w.Header().Get("Cache-Control")
			if cacheControl == "" {
				t.Error("Expected Cache-Control header")
			}

			// 验证不同文件类型的缓存策略
			ext := filepath.Ext(filename)
			switch ext {
			case ".html":
				if !strings.Contains(cacheControl, "max-age=300") {
					t.Errorf("Expected short cache for HTML, got: %s", cacheControl)
				}
			case ".css", ".js":
				if !strings.Contains(cacheControl, "max-age=31536000") {
					t.Errorf("Expected long cache for CSS/JS, got: %s", cacheControl)
				}
			case ".jpg", ".png", ".gif":
				if !strings.Contains(cacheControl, "max-age=31536000") {
					t.Errorf("Expected long cache for images, got: %s", cacheControl)
				}
			case ".pdf":
				if !strings.Contains(cacheControl, "max-age=3600") {
					t.Errorf("Expected medium cache for PDF, got: %s", cacheControl)
				}
			case ".mp4":
				if !strings.Contains(cacheControl, "max-age=7200") {
					t.Errorf("Expected medium cache for video, got: %s", cacheControl)
				}
			case ".zip":
				if !strings.Contains(cacheControl, "max-age=1800") {
					t.Errorf("Expected short cache for archive, got: %s", cacheControl)
				}
			case ".txt":
				if !strings.Contains(cacheControl, "max-age=1800") {
					t.Errorf("Expected short cache for text, got: %s", cacheControl)
				}
			}

			t.Logf("File: %s, Cache-Control: %s", filename, cacheControl)
		})
	}
}

func TestStaticFileHandler_ConditionalRequest(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "static_conditional_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 创建测试文件
	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("Hello World"), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// 获取文件信息
	fileInfo, err := os.Stat(testFile)
	if err != nil {
		t.Fatalf("Failed to get file info: %v", err)
	}

	handler := NewStaticFileHandler(&config.Config{})

	// 测试If-None-Match
	t.Run("If-None-Match", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test.txt", nil)
		req.Header.Set("If-None-Match", handler.generateETag(fileInfo))
		w := httptest.NewRecorder()

		if !handler.handleConditionalRequest(w, req, fileInfo) {
			t.Fatal("expected conditional request handler to short-circuit")
		}

		if w.Code != http.StatusNotModified {
			t.Errorf("expected status %d, got %d", http.StatusNotModified, w.Code)
		}
	})

	// 测试If-Modified-Since
	t.Run("If-Modified-Since", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test.txt", nil)
		req.Header.Set("If-Modified-Since", fileInfo.ModTime().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
		w := httptest.NewRecorder()

		if !handler.handleConditionalRequest(w, req, fileInfo) {
			t.Fatal("expected conditional request handler to short-circuit")
		}

		if w.Code != http.StatusNotModified {
			t.Errorf("expected status %d, got %d", http.StatusNotModified, w.Code)
		}
	})
}

func TestStaticFileHandler_ShouldCompress(t *testing.T) {
	// 创建静态文件处理器
	cfg := &config.Config{}
	handler := NewStaticFileHandler(cfg)

	tests := []struct {
		filePath       string
		fileSize       int64
		contentType    string
		shouldCompress bool
	}{
		{"test.html", 2048, "text/html", true},
		{"test.css", 1024, "text/css", true},
		{"test.js", 2048, "application/javascript", true},
		{"test.txt", 512, "text/plain", false},       // 太小
		{"test.jpg", 1024, "image/jpeg", false},      // 已压缩
		{"test.png", 2048, "image/png", false},       // 已压缩
		{"test.mp4", 1024, "video/mp4", false},       // 已压缩
		{"test.zip", 1024, "application/zip", false}, // 已压缩
	}

	for _, tt := range tests {
		t.Run(tt.filePath, func(t *testing.T) {
			result := handler.shouldCompress(tt.filePath, tt.fileSize, tt.contentType)
			if result != tt.shouldCompress {
				t.Errorf("shouldCompress(%s, %d, %s) = %v, want %v",
					tt.filePath, tt.fileSize, tt.contentType, result, tt.shouldCompress)
			}
		})
	}
}

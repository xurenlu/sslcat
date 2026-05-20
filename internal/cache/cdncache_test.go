package cache

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

func TestCDNCacheWriteMetaAtomically(t *testing.T) {
	c := NewCDNCache(&config.Config{
		CDNCache: config.CDNCacheConfig{
			Enabled:           true,
			CacheDir:          t.TempDir(),
			DefaultTTLSeconds: 60,
			MaxObjectBytes:    1024 * 1024,
		},
	})

	metaPath := filepath.Join(c.cfg.CDNCache.CacheDir, "meta", "entry.meta.json")
	err := c.writeMeta(metaPath, &objectMeta{
		Host:          "example.com",
		URL:           "/asset.css",
		Path:          "/asset.css",
		ContentType:   "text/css",
		TTLSeconds:    60,
		ExpiresAtUnix: time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(metaPath); err != nil {
		t.Fatal(err)
	}
	tmpFiles, err := filepath.Glob(filepath.Join(filepath.Dir(metaPath), "*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpFiles) != 0 {
		t.Fatalf("temporary meta files should be cleaned, got %v", tmpFiles)
	}
}

func TestCDNCachePrecompressionLimitDropsWhenBusy(t *testing.T) {
	c := NewCDNCache(&config.Config{
		CDNCache: config.CDNCacheConfig{
			Enabled:           true,
			CacheDir:          t.TempDir(),
			DefaultTTLSeconds: 60,
			MaxObjectBytes:    1024 * 1024,
		},
	})

	c.precompressSem <- struct{}{}
	c.precompressSem <- struct{}{}
	c.generatePrecompressedFiles(filepath.Join(c.cfg.CDNCache.CacheDir, "asset.css"), []byte(strings.Repeat("a", 2048)))

	if got := len(c.precompressSem); got != cap(c.precompressSem) {
		t.Fatalf("precompression should drop work when busy, sem len=%d cap=%d", got, cap(c.precompressSem))
	}
}

func TestCDNCacheMaybeStoreUsesAtomicFiles(t *testing.T) {
	c := NewCDNCache(&config.Config{
		CDNCache: config.CDNCacheConfig{
			Enabled:           true,
			CacheDir:          t.TempDir(),
			DefaultTTLSeconds: 60,
			MaxObjectBytes:    1024 * 1024,
		},
	})

	req := httptest.NewRequest(http.MethodGet, "https://example.com/static/app.css", nil)
	body := strings.Repeat("body{color:#111;}", 128)
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		ContentLength: int64(len(body)),
		Header:        make(http.Header),
		Body:          ioNopCloser{strings.NewReader(body)},
		Request:       req,
	}
	resp.Header.Set("Content-Type", "text/css")
	resp.Header.Set("Cache-Control", "max-age=60")

	c.MaybeStore(resp)
	filePath, metaPath := c.cachePaths(req)
	if _, err := os.Stat(filePath); err != nil {
		t.Fatalf("cache data file missing: %v", err)
	}
	if _, err := os.Stat(metaPath); err != nil {
		t.Fatalf("cache metadata file missing: %v", err)
	}
}

type ioNopCloser struct {
	*strings.Reader
}

func (c ioNopCloser) Close() error { return nil }

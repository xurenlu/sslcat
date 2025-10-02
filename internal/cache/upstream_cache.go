package cache

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/compression"
	"github.com/xurenlu/sslcat/internal/config"
)

// UpstreamCache 上游缓存管理器
type UpstreamCache struct {
	cfg          *config.Config
	log          *logrus.Entry
	compressor   *compression.Compressor
	mimeDetector *MIMEDetector
	mutex        sync.RWMutex

	// 缓存目录
	cacheDir string

	// 统计信息
	hits   int64
	misses int64
	stores int64

	// 缓存配置
	enabled         bool
	maxSizeBytes    int64
	defaultTTL      time.Duration
	respectUpstream bool  // 是否遵循上游的Cache-Control
	minFileSize     int64 // 最小缓存文件大小
	maxFileSize     int64 // 最大缓存文件大小
}

// UpstreamCacheConfig 上游缓存配置
type UpstreamCacheConfig struct {
	Enabled         bool          `json:"enabled"`
	CacheDir        string        `json:"cache_dir"`
	MaxSizeBytes    int64         `json:"max_size_bytes"`
	DefaultTTL      time.Duration `json:"default_ttl"`
	RespectUpstream bool          `json:"respect_upstream"`

	// 可缓存的文件类型
	CacheableTypes []string `json:"cacheable_types"`

	// 可缓存的Content-Type
	CacheableContentTypes []string `json:"cacheable_content_types"`

	// 最小缓存文件大小
	MinSize int64 `json:"min_size"`

	// 最大缓存文件大小
	MaxSize int64 `json:"max_size"`
}

// UpstreamCacheEntry 上游缓存条目
type UpstreamCacheEntry struct {
	Key            string            `json:"key"`
	URL            string            `json:"url"`
	StatusCode     int               `json:"status_code"`
	Headers        map[string]string `json:"headers"`
	ContentType    string            `json:"content_type"`
	ContentLength  int64             `json:"content_length"`
	ETag           string            `json:"etag"`
	LastModified   string            `json:"last_modified"`
	CacheControl   string            `json:"cache_control"`
	ExpiresAt      time.Time         `json:"expires_at"`
	CreatedAt      time.Time         `json:"created_at"`
	AccessedAt     time.Time         `json:"accessed_at"`
	AccessCount    int64             `json:"access_count"`
	FilePath       string            `json:"file_path"`
	Compressed     bool              `json:"compressed"`
	CompressionAlg string            `json:"compression_algorithm"`
}

// NewUpstreamCache 创建上游缓存管理器
func NewUpstreamCache(cfg *config.Config) *UpstreamCache {
	cacheDir := "./data/upstream-cache"
	if cfg.CDNCache.CacheDir != "" {
		cacheDir = filepath.Join(cfg.CDNCache.CacheDir, "upstream")
	}

	// 创建缓存目录和子目录
	os.MkdirAll(cacheDir, 0755)
	os.MkdirAll(filepath.Join(cacheDir, "meta"), 0755)
	os.MkdirAll(filepath.Join(cacheDir, "data"), 0755)

	return &UpstreamCache{
		cfg:             cfg,
		log:             logrus.WithFields(logrus.Fields{"component": "upstream_cache"}),
		compressor:      compression.NewCompressor(compression.FromConfig(cfg)),
		mimeDetector:    NewMIMEDetector(),
		cacheDir:        cacheDir,
		enabled:         true,               // 默认启用
		maxSizeBytes:    1024 * 1024 * 1024, // 默认1GB
		defaultTTL:      1 * time.Hour,      // 默认1小时
		respectUpstream: true,               // 默认遵循上游Cache-Control
		minFileSize:     1024,               // 默认1KB
		maxFileSize:     100 * 1024 * 1024,  // 默认100MB
	}
}

// NewUpstreamCacheWithConfig 创建带配置的上游缓存管理器
func NewUpstreamCacheWithConfig(cfg *config.Config, cacheConfig *UpstreamCacheConfig) *UpstreamCache {
	cacheDir := cacheConfig.CacheDir
	if cacheDir == "" {
		cacheDir = "./data/upstream-cache"
	}

	// 创建缓存目录和子目录
	os.MkdirAll(cacheDir, 0755)
	os.MkdirAll(filepath.Join(cacheDir, "meta"), 0755)
	os.MkdirAll(filepath.Join(cacheDir, "data"), 0755)

	// 设置默认值
	minSize := cacheConfig.MinSize
	if minSize <= 0 {
		minSize = 1024 // 默认1KB
	}

	maxSize := cacheConfig.MaxSize
	if maxSize <= 0 {
		maxSize = 100 * 1024 * 1024 // 默认100MB
	}

	maxSizeBytes := cacheConfig.MaxSizeBytes
	if maxSizeBytes <= 0 {
		maxSizeBytes = 1024 * 1024 * 1024 // 默认1GB
	}

	defaultTTL := cacheConfig.DefaultTTL
	if defaultTTL <= 0 {
		defaultTTL = 1 * time.Hour // 默认1小时
	}

	return &UpstreamCache{
		cfg:             cfg,
		log:             logrus.WithFields(logrus.Fields{"component": "upstream_cache"}),
		compressor:      compression.NewCompressor(compression.FromConfig(cfg)),
		mimeDetector:    NewMIMEDetector(),
		cacheDir:        cacheDir,
		enabled:         cacheConfig.Enabled,
		maxSizeBytes:    maxSizeBytes,
		defaultTTL:      defaultTTL,
		respectUpstream: cacheConfig.RespectUpstream,
		minFileSize:     minSize,
		maxFileSize:     maxSize,
	}
}

// ShouldCache 判断是否应该缓存响应
func (uc *UpstreamCache) ShouldCache(resp *http.Response) bool {
	if !uc.enabled {
		return false
	}

	// 只缓存成功的响应
	if resp.StatusCode != http.StatusOK {
		return false
	}

	// 检查Content-Type
	contentType := resp.Header.Get("Content-Type")
	if !uc.isCacheableContentType(contentType) {
		return false
	}

	// 检查Content-Length
	contentLength := resp.ContentLength
	if contentLength > 0 {
		// 文件太大不缓存（可配置，默认100MB）
		if contentLength > uc.maxFileSize {
			return false
		}

		// 文件太小不缓存（可配置，默认1KB）
		if contentLength < uc.minFileSize {
			return false
		}
	}

	// 检查Cache-Control指令
	cacheControl := resp.Header.Get("Cache-Control")
	if uc.respectUpstream && cacheControl != "" {
		// 如果上游明确指示不缓存，则不缓存
		if strings.Contains(strings.ToLower(cacheControl), "no-cache") ||
			strings.Contains(strings.ToLower(cacheControl), "no-store") ||
			strings.Contains(strings.ToLower(cacheControl), "private") {
			return false
		}
	}

	return true
}

// Get 从缓存获取响应
func (uc *UpstreamCache) Get(req *http.Request) (*UpstreamCacheEntry, []byte, error) {
	if !uc.enabled {
		return nil, nil, fmt.Errorf("cache disabled")
	}

	key := uc.generateCacheKey(req)
	metaPath := uc.getMetaPath(key)
	dataPath := uc.getDataPath(key)

	// 检查元数据文件是否存在
	if _, err := os.Stat(metaPath); os.IsNotExist(err) {
		uc.misses++
		return nil, nil, fmt.Errorf("cache miss")
	}

	// 读取元数据
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		uc.misses++
		return nil, nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	var entry UpstreamCacheEntry
	if err := json.Unmarshal(metaData, &entry); err != nil {
		uc.misses++
		return nil, nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	// 检查是否过期
	if time.Now().After(entry.ExpiresAt) {
		uc.misses++
		// 删除过期的缓存文件
		os.Remove(metaPath)
		os.Remove(dataPath)
		return nil, nil, fmt.Errorf("cache expired")
	}

	// 读取数据文件
	data, err := os.ReadFile(dataPath)
	if err != nil {
		uc.misses++
		return nil, nil, fmt.Errorf("failed to read data: %w", err)
	}

	// 更新访问统计
	entry.AccessedAt = time.Now()
	entry.AccessCount++

	// 保存更新的元数据
	updatedMeta, _ := json.Marshal(entry)
	os.WriteFile(metaPath, updatedMeta, 0644)

	uc.hits++
	uc.log.Debugf("Cache hit for %s", req.URL.String())

	return &entry, data, nil
}

// Store 存储响应到缓存
func (uc *UpstreamCache) Store(req *http.Request, resp *http.Response) error {
	if !uc.enabled || !uc.ShouldCache(resp) {
		return nil
	}

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// 重新设置响应体，因为ReadAll会消耗掉原始body
	resp.Body = io.NopCloser(bytes.NewReader(body))

	key := uc.generateCacheKey(req)
	metaPath := uc.getMetaPath(key)
	dataPath := uc.getDataPath(key)

	// 确保目录存在
	os.MkdirAll(filepath.Dir(metaPath), 0755)
	os.MkdirAll(filepath.Dir(dataPath), 0755)

	// 计算过期时间
	expiresAt := uc.calculateExpiresAt(resp)

	// 创建缓存条目
	entry := UpstreamCacheEntry{
		Key:           key,
		URL:           req.URL.String(),
		StatusCode:    resp.StatusCode,
		Headers:       uc.copyHeaders(resp.Header),
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: int64(len(body)),
		ETag:          resp.Header.Get("ETag"),
		LastModified:  resp.Header.Get("Last-Modified"),
		CacheControl:  resp.Header.Get("Cache-Control"),
		ExpiresAt:     expiresAt,
		CreatedAt:     time.Now(),
		AccessedAt:    time.Now(),
		AccessCount:   0,
		FilePath:      dataPath,
	}

	// 检查是否应该压缩存储
	var dataToStore []byte
	if uc.compressor != nil && uc.compressor.ShouldCompress(req.URL.Path, int64(len(body)), entry.ContentType) {
		result, err := uc.compressor.Compress(body, "br, gzip")
		if err == nil && result.Algorithm != compression.None {
			dataToStore = result.Data
			entry.Compressed = true
			entry.CompressionAlg = string(result.Algorithm)
			uc.log.Debugf("Compressed cache entry: %s (%d -> %d bytes)",
				key, len(body), len(dataToStore))
		} else {
			dataToStore = body
		}
	} else {
		dataToStore = body
	}

	// 保存数据文件
	if err := os.WriteFile(dataPath, dataToStore, 0644); err != nil {
		return fmt.Errorf("failed to write data file: %w", err)
	}

	// 保存元数据文件
	metaData, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := os.WriteFile(metaPath, metaData, 0644); err != nil {
		return fmt.Errorf("failed to write metadata file: %w", err)
	}

	uc.stores++
	uc.log.Debugf("Stored cache entry for %s (expires: %v)", req.URL.String(), expiresAt)

	return nil
}

// Serve 从缓存服务响应
func (uc *UpstreamCache) Serve(w http.ResponseWriter, req *http.Request) bool {
	entry, data, err := uc.Get(req)
	if err != nil {
		return false
	}

	// 设置响应头 - 智能Content-Type检测
	for key, value := range entry.Headers {
		// 跳过一些不应该从缓存设置的头部
		if !uc.shouldCopyHeader(key) {
			continue
		}
		w.Header().Set(key, value)
	}

	// 智能检测并设置Content-Type
	smartContentType := uc.getSmartContentType(entry, req.URL.Path)
	if smartContentType != "" {
		w.Header().Set("Content-Type", smartContentType)
	}

	// 添加缓存标识头部
	w.Header().Set("X-Cache", "HIT")
	w.Header().Set("X-Cache-Key", entry.Key)
	w.Header().Set("X-Cache-Created", entry.CreatedAt.Format(time.RFC3339))
	w.Header().Set("X-Cache-Expires", entry.ExpiresAt.Format(time.RFC3339))
	w.Header().Set("X-Cache-Access-Count", strconv.FormatInt(entry.AccessCount, 10))

	// 处理压缩
	if entry.Compressed {
		// 检查客户端是否支持压缩
		acceptEncoding := req.Header.Get("Accept-Encoding")
		if strings.Contains(strings.ToLower(acceptEncoding), entry.CompressionAlg) {
			// 客户端支持压缩，直接返回压缩数据
			w.Header().Set("Content-Encoding", entry.CompressionAlg)
			w.Header().Set("Vary", "Accept-Encoding")
			w.WriteHeader(entry.StatusCode)
			w.Write(data)
		} else {
			// 客户端不支持压缩，需要解压缩
			decompressed, err := uc.decompress(data, entry.CompressionAlg)
			if err != nil {
				uc.log.Errorf("Failed to decompress cache entry: %v", err)
				return false
			}
			w.WriteHeader(entry.StatusCode)
			w.Write(decompressed)
		}
	} else {
		// 未压缩数据，直接返回
		w.WriteHeader(entry.StatusCode)
		w.Write(data)
	}

	return true
}

// generateCacheKey 生成缓存键
func (uc *UpstreamCache) generateCacheKey(req *http.Request) string {
	// 使用URL和关键头部生成缓存键
	url := req.URL.String()

	// 添加一些可能影响响应的头部
	var keyParts []string
	keyParts = append(keyParts, url)

	// 添加Accept头部（影响内容协商）
	if accept := req.Header.Get("Accept"); accept != "" {
		keyParts = append(keyParts, "Accept:"+accept)
	}

	// 添加Accept-Language头部
	if acceptLang := req.Header.Get("Accept-Language"); acceptLang != "" {
		keyParts = append(keyParts, "Accept-Language:"+acceptLang)
	}

	keyString := strings.Join(keyParts, "|")

	// 生成SHA256哈希
	hash := sha256.Sum256([]byte(keyString))
	return hex.EncodeToString(hash[:])
}

// calculateExpiresAt 计算过期时间
func (uc *UpstreamCache) calculateExpiresAt(resp *http.Response) time.Time {
	now := time.Now()

	if !uc.respectUpstream {
		// 不遵循上游，使用默认TTL
		return now.Add(uc.defaultTTL)
	}

	// 首先检查Expires头部
	if expires := resp.Header.Get("Expires"); expires != "" {
		if expiresTime, err := time.Parse(time.RFC1123, expires); err == nil {
			// 限制最大缓存时间为24小时
			maxExpires := now.Add(24 * time.Hour)
			if expiresTime.Before(maxExpires) {
				return expiresTime
			}
			return maxExpires
		}
	}

	// 解析Cache-Control头部
	cacheControl := resp.Header.Get("Cache-Control")
	if cacheControl != "" {
		if maxAge := uc.parseCacheControlMaxAge(cacheControl); maxAge > 0 {
			// 限制最大缓存时间为24小时
			maxDuration := 24 * time.Hour
			if maxAge > maxDuration {
				maxAge = maxDuration
			}
			return now.Add(maxAge)
		}
	}

	// 如果没有明确的缓存指令，使用默认TTL
	return now.Add(uc.defaultTTL)
}

// parseCacheControlMaxAge 解析Cache-Control中的max-age
func (uc *UpstreamCache) parseCacheControlMaxAge(cacheControl string) time.Duration {
	// 使用正则表达式提取max-age值
	re := regexp.MustCompile(`max-age=(\d+)`)
	matches := re.FindStringSubmatch(cacheControl)
	if len(matches) >= 2 {
		if seconds, err := strconv.Atoi(matches[1]); err == nil {
			return time.Duration(seconds) * time.Second
		}
	}
	return 0
}

// isCacheableContentType 检查Content-Type是否可缓存
func (uc *UpstreamCache) isCacheableContentType(contentType string) bool {
	if contentType == "" {
		return false
	}

	contentType = strings.ToLower(strings.Split(contentType, ";")[0])

	// 静态资源类型
	cacheableTypes := []string{
		"text/css",
		"text/javascript",
		"application/javascript",
		"application/x-javascript",
		"text/plain",
		"application/json",
		"application/xml",
		"text/xml",
		"image/jpeg",
		"image/png",
		"image/gif",
		"image/webp",
		"image/svg+xml",
		"image/x-icon",
		"application/font-woff",
		"application/font-woff2",
		"font/woff",
		"font/woff2",
		"application/vnd.ms-fontobject",
		"application/x-font-ttf",
		"font/opentype",
	}

	for _, cacheableType := range cacheableTypes {
		if contentType == cacheableType {
			return true
		}
	}

	// 检查是否以text/开头，但排除HTML（通常是动态内容）
	if strings.HasPrefix(contentType, "text/") && !strings.Contains(contentType, "html") {
		return true
	}

	return false
}

// getSmartContentType 智能检测Content-Type
func (uc *UpstreamCache) getSmartContentType(entry *UpstreamCacheEntry, path string) string {
	// 1. 如果缓存条目中有Content-Type，优先使用
	if entry.ContentType != "" {
		uc.log.Debugf("使用缓存的Content-Type: %s", entry.ContentType)
		return entry.ContentType
	}

	// 2. 尝试从文件内容检测
	if uc.mimeDetector != nil {
		// 读取缓存文件进行检测
		if data, err := os.ReadFile(entry.FilePath); err == nil {
			detectedType := uc.mimeDetector.DetectMIME(path, data)
			if detectedType != "" && detectedType != "application/octet-stream" {
				uc.log.Debugf("通过文件内容检测到Content-Type: %s", detectedType)
				return detectedType
			}
		}
	}

	// 3. 通过扩展名猜测
	if uc.mimeDetector != nil {
		detectedType := uc.mimeDetector.DetectMIME(path, nil)
		if detectedType != "" && detectedType != "application/octet-stream" {
			uc.log.Debugf("通过扩展名检测到Content-Type: %s", detectedType)
			return detectedType
		}
	}

	// 4. 使用系统默认MIME类型
	if mimeType := mime.TypeByExtension(filepath.Ext(path)); mimeType != "" {
		uc.log.Debugf("使用系统默认MIME类型: %s", mimeType)
		return mimeType
	}

	// 5. 默认返回二进制类型
	uc.log.Debugf("使用默认Content-Type: application/octet-stream")
	return "application/octet-stream"
}

// shouldCopyHeader 检查是否应该复制头部到缓存响应
func (uc *UpstreamCache) shouldCopyHeader(headerName string) bool {
	headerName = strings.ToLower(headerName)

	// 不应该复制的头部
	skipHeaders := []string{
		"connection",
		"proxy-connection",
		"keep-alive",
		"proxy-authenticate",
		"proxy-authorization",
		"te",
		"trailers",
		"transfer-encoding",
		"upgrade",
		"date", // 使用缓存时的当前时间
		"server",
		"x-cache", // 我们自己会设置
	}

	for _, skip := range skipHeaders {
		if headerName == skip {
			return false
		}
	}

	return true
}

// copyHeaders 复制响应头部
func (uc *UpstreamCache) copyHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)
	for key, values := range headers {
		if len(values) > 0 && uc.shouldCopyHeader(key) {
			result[key] = values[0] // 只取第一个值
		}
	}
	return result
}

// getMetaPath 获取元数据文件路径
func (uc *UpstreamCache) getMetaPath(key string) string {
	return filepath.Join(uc.cacheDir, "meta", key[:2], key+".json")
}

// getDataPath 获取数据文件路径
func (uc *UpstreamCache) getDataPath(key string) string {
	return filepath.Join(uc.cacheDir, "data", key[:2], key+".dat")
}

// decompress 解压缩数据
func (uc *UpstreamCache) decompress(data []byte, algorithm string) ([]byte, error) {
	switch algorithm {
	case "gzip":
		return uc.decompressGzip(data)
	case "br":
		return uc.decompressBrotli(data)
	default:
		return data, nil
	}
}

// decompressGzip 解压缩gzip数据
func (uc *UpstreamCache) decompressGzip(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return io.ReadAll(reader)
}

// decompressBrotli 解压缩brotli数据
func (uc *UpstreamCache) decompressBrotli(data []byte) ([]byte, error) {
	reader := brotli.NewReader(bytes.NewReader(data))
	return io.ReadAll(reader)
}

// GetStats 获取缓存统计信息
func (uc *UpstreamCache) GetStats() map[string]interface{} {
	uc.mutex.RLock()
	defer uc.mutex.RUnlock()

	hitRate := float64(0)
	if uc.hits+uc.misses > 0 {
		hitRate = float64(uc.hits) / float64(uc.hits+uc.misses) * 100
	}

	return map[string]interface{}{
		"enabled":          uc.enabled,
		"cache_dir":        uc.cacheDir,
		"hits":             uc.hits,
		"misses":           uc.misses,
		"stores":           uc.stores,
		"hit_rate":         hitRate,
		"default_ttl":      uc.defaultTTL.String(),
		"respect_upstream": uc.respectUpstream,
		"max_size_bytes":   uc.maxSizeBytes,
	}
}

// Clean 清理过期的缓存条目
func (uc *UpstreamCache) Clean() error {
	uc.log.Info("Starting upstream cache cleanup")

	metaDir := filepath.Join(uc.cacheDir, "meta")
	
	// 检查meta目录是否存在，如果不存在则创建
	if _, err := os.Stat(metaDir); os.IsNotExist(err) {
		if err := os.MkdirAll(metaDir, 0755); err != nil {
			return fmt.Errorf("failed to create meta directory: %w", err)
		}
		uc.log.Info("Created meta directory for cache cleanup")
		return nil // 新创建的目录没有内容需要清理
	}

	cleaned := 0
	err := filepath.Walk(metaDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !strings.HasSuffix(path, ".json") {
			return nil
		}

		// 读取元数据
		metaData, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var entry UpstreamCacheEntry
		if err := json.Unmarshal(metaData, &entry); err != nil {
			// 元数据损坏，删除
			os.Remove(path)
			os.Remove(entry.FilePath)
			cleaned++
			return nil
		}

		// 检查是否过期
		if time.Now().After(entry.ExpiresAt) {
			os.Remove(path)
			os.Remove(entry.FilePath)
			cleaned++
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to clean cache: %w", err)
	}

	uc.log.Infof("Cleaned %d expired cache entries", cleaned)
	return nil
}

// StartCleaner 启动定期清理
func (uc *UpstreamCache) StartCleaner() {
	go func() {
		ticker := time.NewTicker(1 * time.Hour) // 每小时清理一次
		defer ticker.Stop()

		for range ticker.C {
			if err := uc.Clean(); err != nil {
				uc.log.Errorf("Cache cleanup failed: %v", err)
			}
		}
	}()
}

// PurgeAll 清除所有缓存
func (uc *UpstreamCache) PurgeAll() error {
	uc.log.Info("Purging all upstream cache")

	err := os.RemoveAll(uc.cacheDir)
	if err != nil {
		return fmt.Errorf("failed to purge cache: %w", err)
	}

	// 重新创建缓存目录和子目录
	os.MkdirAll(uc.cacheDir, 0755)
	os.MkdirAll(filepath.Join(uc.cacheDir, "meta"), 0755)
	os.MkdirAll(filepath.Join(uc.cacheDir, "data"), 0755)

	// 重置统计
	uc.mutex.Lock()
	uc.hits = 0
	uc.misses = 0
	uc.stores = 0
	uc.mutex.Unlock()

	uc.log.Info("All upstream cache purged")
	return nil
}

// PurgeByPattern 按模式清除缓存
func (uc *UpstreamCache) PurgeByPattern(pattern string) error {
	uc.log.Infof("Purging upstream cache by pattern: %s", pattern)

	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern: %w", err)
	}

	metaDir := filepath.Join(uc.cacheDir, "meta")
	
	// 检查meta目录是否存在
	if _, err := os.Stat(metaDir); os.IsNotExist(err) {
		uc.log.Info("Meta directory does not exist, nothing to purge")
		return nil
	}

	purged := 0
	err = filepath.Walk(metaDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !strings.HasSuffix(path, ".json") {
			return nil
		}

		// 读取元数据
		metaData, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var entry UpstreamCacheEntry
		if err := json.Unmarshal(metaData, &entry); err != nil {
			return nil
		}

		// 检查URL是否匹配模式
		if re.MatchString(entry.URL) {
			os.Remove(path)
			os.Remove(entry.FilePath)
			purged++
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to purge cache by pattern: %w", err)
	}

	uc.log.Infof("Purged %d cache entries matching pattern: %s", purged, pattern)
	return nil
}

package cache

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/compression"
	"github.com/xurenlu/sslcat/internal/config"
)

const cdnMetaTouchMinInterval = time.Minute

// processingEntry 处理中的请求条目（用于超时检测）
type processingEntry struct {
	ch        chan struct{}
	createdAt time.Time
}

// CDNCache 本地静态文件缓存管理器
type CDNCache struct {
	cfg          *config.Config
	log          *logrus.Entry
	compressor   *compression.Compressor
	mimeDetector *MIMEDetector
	mutex        sync.Mutex
	// 统计计数器（使用原子操作避免竞态条件）
	hits   atomic.Int64
	misses atomic.Int64
	// 正在处理的请求，避免相同URL并发穿透
	processing sync.Map // key: request_key, value: *processingEntry

	// 清理器控制
	stopProcessingCleaner  chan struct{}
	stopCleaner            chan struct{}
	cleanerStarted         bool
	periodicCleanerStarted bool
	cleanerMutex           sync.Mutex
}

type objectMeta struct {
	Host          string    `json:"host"`
	URL           string    `json:"url"`
	Path          string    `json:"path"`
	ContentType   string    `json:"content_type"`
	Encoding      string    `json:"encoding"`
	ETag          string    `json:"etag"`
	LastModified  time.Time `json:"last_modified"`
	TTLSeconds    int       `json:"ttl_seconds"`
	ExpiresAtUnix int64     `json:"expires_at_unix"`
	LastAccess    time.Time `json:"last_access"`
	SizeBytes     int64     `json:"size_bytes"`
}

func NewCDNCache(cfg *config.Config) *CDNCache {
	// 创建压缩器
	compressor := compression.NewCompressor(compression.FromConfig(cfg))

	// 创建MIME检测器
	mimeDetector := NewMIMEDetector()

	cache := &CDNCache{
		cfg:                   cfg,
		log:                   logrus.WithFields(logrus.Fields{"component": "cdn_cache"}),
		compressor:            compressor,
		mimeDetector:          mimeDetector,
		stopProcessingCleaner: make(chan struct{}),
		stopCleaner:           make(chan struct{}),
	}

	// 启动 processing map 清理器，防止内存泄漏
	cache.startProcessingCleaner()

	return cache
}

// ServeIfFresh 若命中缓存且未过期，直接回源本地文件
func (c *CDNCache) ServeIfFresh(w http.ResponseWriter, r *http.Request) bool {
	return c.ServeIfFreshWithConfig(w, r, false)
}

// ServeIfFreshWithConfig 带自定义启用状态的缓存服务
func (c *CDNCache) ServeIfFreshWithConfig(w http.ResponseWriter, r *http.Request, forceEnabled bool) bool {
	if c == nil || (!c.isEnabled() && !forceEnabled) {
		// 统计未命中（未启用）
		if c != nil {
			c.misses.Add(1)
			c.log.Debugf("CDN缓存未启用: url=%s", r.URL.Path)
		}
		return false
	}
	c.log.Debugf("CDN缓存查询: url=%s, isEnabled=%v, forceEnabled=%v", r.URL.Path, c.isEnabled(), forceEnabled)

	// 如果强制启用，但基本配置不可用，仍然返回false
	if forceEnabled && (c.cfg == nil || c.cfg.CDNCache.CacheDir == "") {
		c.misses.Add(1)
		c.log.Debugf("CDN缓存配置不可用: url=%s", r.URL.Path)
		return false
	}
	// 仅缓存 GET/HEAD
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}

	filePath, metaPath := c.cachePaths(r)
	c.log.Debugf("CDN缓存路径: filePath=%s, metaPath=%s", filePath, metaPath)

	meta, err := c.readMeta(metaPath)
	if err != nil || meta == nil {
		// 统计未命中（无元数据）
		c.misses.Add(1)
		c.log.Debugf("CDN缓存未命中(无元数据): url=%s, err=%v", r.URL.Path, err)

		// 检查是否有相同请求正在处理，避免并发穿透
		requestKey := c.getRequestKey(r)

		// 创建新的 processing entry
		newEntry := &processingEntry{
			ch:        make(chan struct{}),
			createdAt: time.Now(),
		}

		if existingValue, loaded := c.processing.LoadOrStore(requestKey, newEntry); loaded {
			// 有相同请求正在处理，等待其完成
			c.log.Debugf("CDN缓存等待相同请求完成: url=%s", r.URL.Path)

			// 获取已存在的 entry
			existingEntry, ok := existingValue.(*processingEntry)
			if !ok {
				// 旧格式或无效，直接返回
				c.log.Warnf("CDN缓存 processing entry 格式无效: url=%s", r.URL.Path)
				return false
			}

			// 使用 select 添加超时保护，防止永久阻塞
			select {
			case <-existingEntry.ch:
				// 等待完成
			case <-time.After(30 * time.Second):
				// 超时，直接返回
				c.log.Warnf("CDN缓存等待超时: url=%s", r.URL.Path)
				return false
			}
			// 重新尝试读取缓存
			if meta, err := c.readMeta(metaPath); err == nil && meta != nil {
				c.log.Debugf("CDN缓存等待后命中: url=%s", r.URL.Path)
				// 检查过期
				if meta.ExpiresAtUnix > 0 && time.Now().Unix() >= meta.ExpiresAtUnix {
					_ = os.Remove(filePath)
					_ = os.Remove(metaPath)
					return false
				}
				// 回写头并返回内容 - 智能Content-Type检测
				contentType := c.getSmartContentType(meta, r.URL.Path)
				if contentType != "" {
					w.Header().Set("Content-Type", contentType)
				}
				if meta.Encoding != "" {
					w.Header().Set("Content-Encoding", meta.Encoding)
				}
				if meta.ETag != "" {
					w.Header().Set("ETag", meta.ETag)
				}
				if r.Method == http.MethodHead {
					w.WriteHeader(http.StatusOK)
					c.touch(metaPath, meta)
					return true
				}
				if f, err := os.Open(filePath); err == nil {
					defer f.Close()
					w.WriteHeader(http.StatusOK)
					_, _ = io.Copy(w, f)
					c.touch(metaPath, meta)
					c.hits.Add(1)
					return true
				}
			}
		}
		return false
	}
	// 过期检查
	if meta.ExpiresAtUnix > 0 && time.Now().Unix() >= meta.ExpiresAtUnix {
		_ = os.Remove(filePath)
		_ = os.Remove(metaPath)
		// 统计未命中（已过期）
		c.misses.Add(1)
		return false
	}
	// 检查HTTP条件请求
	if c.checkConditionalRequest(w, r, meta) {
		// 返回304 Not Modified，不需要发送内容
		return true
	}

	// 回写头 - 智能Content-Type检测
	contentType := c.getSmartContentType(meta, r.URL.Path)
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	if meta.Encoding != "" {
		w.Header().Set("Content-Encoding", meta.Encoding)
	}
	if meta.ETag != "" {
		w.Header().Set("ETag", meta.ETag)
	}
	if !meta.LastModified.IsZero() {
		w.Header().Set("Last-Modified", meta.LastModified.UTC().Format(http.TimeFormat))
	}

	// HEAD 不需要写 body
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		c.touch(metaPath, meta)
		return true
	}

	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()

	// 修复：使用预压缩文件或流式处理，避免读取整个文件到内存
	if c.compressor != nil && c.compressor.ShouldCompress(meta.Path, meta.SizeBytes, meta.ContentType) {
		c.serveWithPrecompression(w, r, filePath, meta)
	} else {
		// 简单写回
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, f)
	}

	// 更新访问时间
	c.touch(metaPath, meta)
	// 统计命中
	c.hits.Add(1)
	return true
}

// MaybeStore 按规则存储响应
// 注意：该函数会读取 resp.Body 并重置
func (c *CDNCache) MaybeStore(resp *http.Response) {
	c.MaybeStoreWithConfig(resp, false)
}

// MaybeStoreWithConfig 带自定义启用状态的缓存存储
func (c *CDNCache) MaybeStoreWithConfig(resp *http.Response, forceEnabled bool) {
	if resp != nil && resp.Request != nil {
		c.log.Debugf("CDN缓存存储: url=%s, isEnabled=%v, forceEnabled=%v", resp.Request.URL.Path, c.isEnabled(), forceEnabled)
	}

	if c == nil || (!c.isEnabled() && !forceEnabled) || resp == nil || resp.Request == nil {
		if resp != nil && resp.Request != nil {
			c.log.Debugf("CDN缓存存储跳过: url=%s", resp.Request.URL.Path)
			c.cleanupProcessing(resp.Request)
		}
		return
	}

	// 如果强制启用，但基本配置不可用，仍然返回
	if forceEnabled && (c.cfg == nil || c.cfg.CDNCache.CacheDir == "") {
		c.log.Debugf("CDN缓存配置不可用，无法存储: url=%s", resp.Request.URL.Path)
		c.cleanupProcessing(resp.Request)
		return
	}
	req := resp.Request
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		c.cleanupProcessing(req)
		return
	}
	// 只缓存 200 OK 和 206 Partial Content 响应
	// 304 Not Modified 等其他状态码不缓存
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		if resp.StatusCode == http.StatusNotModified {
			c.log.Debugf("CDN缓存跳过存储(304响应): url=%s", req.URL.Path)
		}
		c.cleanupProcessing(req)
		return
	}
	// 遵循上游缓存控制
	cc := parseCacheControl(resp.Header.Get("Cache-Control"))
	if cc.noStore || cc.noCache || cc.private {
		c.cleanupProcessing(req)
		return
	}

	contentType := resp.Header.Get("Content-Type")

	// 不缓存动态API接口（application/json 和 API 路径）
	// 排除条件：
	// 1. Content-Type 是 application/json
	// 2. URL 路径包含 /api/
	if strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		c.log.Debugf("CDN缓存跳过存储(动态JSON API): url=%s, content-type=%s", req.URL.Path, contentType)
		c.cleanupProcessing(req)
		return
	}
	if strings.Contains(req.URL.Path, "/api/") {
		c.log.Debugf("CDN缓存跳过存储(API路径): url=%s", req.URL.Path)
		c.cleanupProcessing(req)
		return
	}

	// 规则 TTL 计算
	ttl := c.selectTTL(req.URL.Path, contentType)
	// 域名级默认 TTL 覆盖（由代理暂存至响应头）
	if v := strings.TrimSpace(resp.Header.Get("X-SSLcat-CDN-Default-TTL")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			ttl = n
		}
	}
	if ttl <= 0 {
		c.cleanupProcessing(req)
		return
	}
	if cc.maxAge >= 0 {
		// 如果上游攜帶 max-age，取兩者較小值
		if cc.maxAge < ttl {
			ttl = cc.maxAge
		}
	}

	maxObj := c.cfg.CDNCache.MaxObjectBytes
	if maxObj <= 0 {
		maxObj = 20 * 1024 * 1024
	}
	// 若 Content-Length 不可用或超出限制，直接跳過快取以避免讀取 resp.Body
	if resp.ContentLength <= 0 {
		c.cleanupProcessing(req)
		return
	}
	if resp.ContentLength > int64(maxObj) {
		c.cleanupProcessing(req)
		return
	}

	// 修復：使用流式處理 + 大小限制，避免大檔案占用過多記憶體
	filePath, metaPath := c.cachePaths(req)
	_ = os.MkdirAll(filepath.Dir(filePath), 0755)

	// 创建临时文件
	tempFile, err := os.CreateTemp(filepath.Dir(filePath), ".cdn-tmp-*")
	if err != nil {
		c.log.Debugf("create temp file failed: %v", err)
		c.cleanupProcessing(req)
		return
	}
	tempPath := tempFile.Name()
	defer func() {
		tempFile.Close()
		// 如果失败，清理临时文件
		if _, err := os.Stat(tempPath); err == nil {
			os.Remove(tempPath)
		}
	}()

	// 使用 LimitedReader 限制读取大小，防止超大文件
	limitedReader := &io.LimitedReader{R: resp.Body, N: maxObj + 1}

	// 流式写入临时文件，同时保存到缓冲区用于重置响应体
	var buf bytes.Buffer
	teeReader := io.TeeReader(limitedReader, &buf)

	written, err := io.Copy(tempFile, teeReader)
	if err != nil {
		c.log.Debugf("write temp file failed: %v", err)
		c.cleanupProcessing(req)
		return
	}

	// 检查是否超过限制
	if written > maxObj {
		c.log.Debugf("object too large: %d > %d", written, maxObj)
		c.cleanupProcessing(req)
		return
	}

	// 重置响应体给下游继续写
	data := buf.Bytes()
	resp.Body = io.NopCloser(bytes.NewReader(data))

	// 关闭临时文件，准备重命名
	tempFile.Close()

	// 重命名为正式缓存文件
	if err := os.Rename(tempPath, filePath); err != nil {
		c.log.Debugf("rename cache file failed: %v", err)
		c.cleanupProcessing(req)
		return
	}

	c.log.Debugf("CDN缓存写入成功: url=%s, filePath=%s, size=%d bytes", req.URL.Path, filePath, len(data))

	// 修复：生成预压缩文件，避免每次请求都压缩
	// 只对可压缩的文件类型生成预压缩版本
	if c.compressor != nil && c.compressor.ShouldCompress(req.URL.Path, int64(len(data)), contentType) {
		c.generatePrecompressedFiles(filePath, data)
	}

	encoding := resp.Header.Get("Content-Encoding")

	// 解析Last-Modified头部（仅保留原始响应中的，不自动添加）
	var lastModified time.Time
	if lastModifiedStr := resp.Header.Get("Last-Modified"); lastModifiedStr != "" {
		if parsedTime, err := http.ParseTime(lastModifiedStr); err == nil {
			lastModified = parsedTime
		}
	}
	// 注意：不再自动添加 Last-Modified，只保留原始响应中的
	// 这样可以避免给动态内容（如未被拦截的 JSON）添加不恰当的缓存头

	meta := &objectMeta{
		Host:          hostOnly(req.Host),
		URL:           req.URL.String(),
		Path:          req.URL.Path,
		ContentType:   contentType,
		Encoding:      encoding,
		ETag:          resp.Header.Get("ETag"),
		LastModified:  lastModified,
		TTLSeconds:    ttl,
		ExpiresAtUnix: time.Now().Add(time.Duration(ttl) * time.Second).Unix(),
		LastAccess:    time.Now(),
		SizeBytes:     int64(len(data)),
	}
	_ = c.writeMeta(metaPath, meta)

	// 通知等待的相同请求
	c.cleanupProcessing(req)

	// 触发一次清理（非阻塞）
	go c.CleanOnce()
}

// PurgeAll 清理全部缓存
func (c *CDNCache) PurgeAll() error {
	if !c.isEnabled() {
		return nil
	}
	return os.RemoveAll(c.cfg.CDNCache.CacheDir)
}

// PurgeByCondition 根据条件清理（prefix/suffix/media）
func (c *CDNCache) PurgeByCondition(matchType string, pattern string, mediaCSV string) error {
	if !c.isEnabled() {
		return nil
	}
	base := c.cfg.CDNCache.CacheDir
	var medias []string
	if mediaCSV != "" {
		for _, m := range strings.Split(mediaCSV, ",") {
			m = strings.TrimSpace(m)
			if m != "" {
				medias = append(medias, m)
			}
		}
	}
	return filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.IsDir() || strings.HasSuffix(path, ".meta.json") {
			return nil
		}
		meta, _ := c.readMeta(path + ".meta.json")
		rel, _ := filepath.Rel(base, path)
		rel = "/" + filepath.ToSlash(rel)
		if c.matchRule(matchType, pattern, medias, rel, meta) {
			_ = os.Remove(path)
			_ = os.Remove(path + ".meta.json")
		}
		return nil
	})
}

// CleanOnce 过期与配额清理
func (c *CDNCache) CleanOnce() {
	if !c.isEnabled() {
		return
	}
	base := c.cfg.CDNCache.CacheDir
	var total int64
	type rec struct {
		path string
		size int64
		last time.Time
	}
	var list []rec
	filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".meta.json") {
			return nil
		}
		meta, _ := c.readMeta(path + ".meta.json")
		// 过期删除
		if meta != nil && meta.ExpiresAtUnix > 0 && time.Now().Unix() >= meta.ExpiresAtUnix {
			_ = os.Remove(path)
			_ = os.Remove(path + ".meta.json")
			return nil
		}
		// 统计
		size := info.Size()
		total += size
		last := info.ModTime()
		if meta != nil && !meta.LastAccess.IsZero() {
			last = meta.LastAccess
		}
		list = append(list, rec{path: path, size: size, last: last})
		return nil
	})

	limit := c.cfg.CDNCache.MaxSizeBytes
	if limit <= 0 {
		return
	}
	if total <= limit {
		return
	}
	// 超限，按最久未访问清理
	sort.Slice(list, func(i, j int) bool { return list[i].last.Before(list[j].last) })
	for _, it := range list {
		if total <= limit {
			break
		}
		_ = os.Remove(it.path)
		_ = os.Remove(it.path + ".meta.json")
		total -= it.size
	}
}

// StartCleaner 启动定时清理
func (c *CDNCache) StartCleaner() {
	if !c.isEnabled() {
		return
	}
	c.cleanerMutex.Lock()
	if c.periodicCleanerStarted {
		c.cleanerMutex.Unlock()
		return
	}
	select {
	case <-c.stopCleaner:
		c.stopCleaner = make(chan struct{})
	default:
	}
	c.periodicCleanerStarted = true
	c.cleanerMutex.Unlock()

	interval := time.Duration(c.cfg.CDNCache.CleanIntervalSec)
	if interval <= 0 {
		interval = 60
	}
	// 使用质数间隔避免与其他定时器同时触发（53秒）
	if interval == 60 {
		interval = 53
	}
	go func() {
		ticker := time.NewTicker(interval * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.CleanOnce()
			case <-c.stopCleaner:
				c.log.Info("CDN Cache 定时清理器已停止")
				return
			}
		}
	}()
}

// Stats 返回缓存的详细统计
func (c *CDNCache) Stats() map[string]any {
	if !c.isEnabled() {
		return map[string]any{"enabled": false}
	}
	base := c.cfg.CDNCache.CacheDir
	var totalSize int64
	var objectCount int64
	_ = filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".meta.json") {
			return nil
		}
		totalSize += info.Size()
		objectCount++
		return nil
	})

	hitRate := float64(0)
	hits := c.hits.Load()
	misses := c.misses.Load()
	if hits+misses > 0 {
		hitRate = float64(hits) / float64(hits+misses) * 100
	}

	return map[string]any{
		"enabled":     true,
		"objects":     objectCount,
		"total_size":  totalSize,
		"hits":        hits,
		"misses":      misses,
		"hit_rate":    hitRate,
		"max_size":    c.cfg.CDNCache.MaxSizeBytes,
		"utilization": float64(totalSize) / float64(c.cfg.CDNCache.MaxSizeBytes) * 100,
	}
}

// 工具函数

func (c *CDNCache) isEnabled() bool {
	return c != nil && c.cfg != nil && c.cfg.CDNCache.Enabled && c.cfg.CDNCache.CacheDir != ""
}

func (c *CDNCache) selectTTL(path string, contentType string) int {
	if c.cfg == nil {
		return 0
	}
	// 规则优先
	for _, r := range c.cfg.CDNCache.Rules {
		switch strings.ToLower(strings.TrimSpace(r.MatchType)) {
		case "prefix":
			if r.Pattern != "" && strings.HasPrefix(path, r.Pattern) {
				return r.TTLSeconds
			}
		case "suffix":
			if r.Pattern != "" && strings.HasSuffix(path, r.Pattern) {
				return r.TTLSeconds
			}
		case "media":
			if contentType != "" {
				for _, m := range r.MediaTypes {
					m = strings.TrimSpace(m)
					if m != "" && strings.HasPrefix(strings.ToLower(contentType), strings.ToLower(m)) {
						return r.TTLSeconds
					}
				}
			}
		}
	}
	// 默认 TTL
	if c.cfg.CDNCache.DefaultTTLSeconds > 0 {
		return c.cfg.CDNCache.DefaultTTLSeconds
	}
	return 0
}

func (c *CDNCache) cachePaths(r *http.Request) (filePath, metaPath string) {
	base := c.cfg.CDNCache.CacheDir
	host := hostOnly(r.Host)
	var b strings.Builder
	b.WriteString(base)
	b.WriteString("/")
	b.WriteString(host)
	// 规范化路径
	cleanPath := filepath.Clean("/" + r.URL.Path)
	b.WriteString(filepath.ToSlash(cleanPath))
	// 查询串参与 key（哈希）
	if r.URL.RawQuery != "" {
		h := sha1.Sum([]byte(r.URL.RawQuery))
		b.WriteString("__q_")
		b.WriteString(hex.EncodeToString(h[:8]))
	}
	filePath = b.String()
	metaPath = filePath + ".meta.json"
	return
}

func (c *CDNCache) readMeta(metaPath string) (*objectMeta, error) {
	b, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}
	var m objectMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (c *CDNCache) writeMeta(metaPath string, m *objectMeta) error {
	m.LastAccess = time.Now()
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(metaPath, b, 0644)
}

func (c *CDNCache) touch(metaPath string, m *objectMeta) {
	if m == nil {
		return
	}
	if !m.LastAccess.IsZero() && time.Since(m.LastAccess) < cdnMetaTouchMinInterval {
		return
	}
	m.LastAccess = time.Now()
	_ = c.writeMeta(metaPath, m)
}

type cacheControl struct {
	noStore bool
	noCache bool
	private bool
	maxAge  int // -1 表示不存在
}

func parseCacheControl(v string) cacheControl {
	cc := cacheControl{maxAge: -1}
	if v == "" {
		return cc
	}
	parts := strings.Split(v, ",")
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		switch {
		case p == "no-store":
			cc.noStore = true
		case p == "no-cache":
			cc.noCache = true
		case p == "private":
			cc.private = true
		case strings.HasPrefix(p, "max-age="):
			val := strings.TrimPrefix(p, "max-age=")
			if n, err := strconv.Atoi(val); err == nil {
				cc.maxAge = n
			}
		}
	}
	return cc
}

// getRequestKey 生成请求的唯一标识用于并发控制
func (c *CDNCache) getRequestKey(r *http.Request) string {
	host := hostOnly(r.Host)
	key := host + ":" + r.URL.Path
	if r.URL.RawQuery != "" {
		h := sha1.Sum([]byte(r.URL.RawQuery))
		key += "__q_" + hex.EncodeToString(h[:8])
	}
	return key
}

// cleanupProcessing 清理processing标记，通知等待的请求
func (c *CDNCache) cleanupProcessing(req *http.Request) {
	if req != nil {
		requestKey := c.getRequestKey(req)
		if value, loaded := c.processing.LoadAndDelete(requestKey); loaded {
			// 支持两种格式：新的 *processingEntry 和旧的 chan struct{}
			switch v := value.(type) {
			case *processingEntry:
				if v != nil && v.ch != nil {
					// 安全关闭 channel
					select {
					case <-v.ch:
						// 已经关闭
					default:
						close(v.ch)
					}
				}
			case chan struct{}:
				// 旧格式，直接关闭
				select {
				case <-v:
					// 已经关闭
				default:
					close(v)
				}
			}
		}
	}
}

func (c *CDNCache) matchRule(matchType, pattern string, medias []string, relPath string, meta *objectMeta) bool {
	switch strings.ToLower(strings.TrimSpace(matchType)) {
	case "prefix":
		return pattern != "" && strings.HasPrefix(relPath, pattern)
	case "suffix":
		return pattern != "" && strings.HasSuffix(relPath, pattern)
	case "media":
		ct := ""
		if meta != nil {
			ct = meta.ContentType
		}
		for _, m := range medias {
			m = strings.TrimSpace(m)
			if m != "" && strings.HasPrefix(strings.ToLower(ct), strings.ToLower(m)) {
				return true
			}
		}
	}
	return false
}

func hostOnly(h string) string {
	if i := strings.Index(h, ":"); i >= 0 {
		return h[:i]
	}
	return h
}

// URL escape helper (not used but kept for future safety)
func safeSegment(s string) string {
	return url.PathEscape(s)
}

// checkConditionalRequest 检查HTTP条件请求，如果满足条件返回304
func (c *CDNCache) checkConditionalRequest(w http.ResponseWriter, r *http.Request, meta *objectMeta) bool {
	// 检查 If-None-Match (ETag验证)
	if ifNoneMatch := r.Header.Get("If-None-Match"); ifNoneMatch != "" {
		if meta.ETag != "" {
			// 支持弱ETag比较 (W/"etag")
			clientETag := strings.TrimSpace(ifNoneMatch)
			serverETag := strings.TrimSpace(meta.ETag)

			// 移除弱ETag标记进行比较
			if strings.HasPrefix(clientETag, "W/\"") && strings.HasSuffix(clientETag, "\"") {
				clientETag = clientETag[3 : len(clientETag)-1]
			}
			if strings.HasPrefix(serverETag, "W/\"") && strings.HasSuffix(serverETag, "\"") {
				serverETag = serverETag[3 : len(serverETag)-1]
			}

			if clientETag == serverETag {
				c.log.Debugf("ETag匹配，返回304: %s", r.URL.Path)
				w.WriteHeader(http.StatusNotModified)
				return true
			}
		}
	}

	// 检查 If-Modified-Since (时间验证)
	if ifModifiedSince := r.Header.Get("If-Modified-Since"); ifModifiedSince != "" {
		if !meta.LastModified.IsZero() {
			// 解析客户端发送的时间
			clientTime, err := http.ParseTime(ifModifiedSince)
			if err == nil {
				// 比较时间，如果客户端缓存的时间 >= 服务器最后修改时间，返回304
				if !clientTime.Before(meta.LastModified) {
					c.log.Debugf("Last-Modified匹配，返回304: %s", r.URL.Path)
					w.WriteHeader(http.StatusNotModified)
					return true
				}
			}
		}
	}

	return false
}

// shouldCompressFile 判断是否应该压缩文件
func (c *CDNCache) shouldCompressFile(filePath string, fileSize int64) bool {
	// 文件太小不压缩（小于1KB）
	if fileSize < 1024 {
		return false
	}

	// 检查文件类型
	ext := strings.ToLower(filepath.Ext(filePath))

	// 需要压缩的文件类型
	compressibleTypes := map[string]bool{
		".js":   true,
		".css":  true,
		".html": true,
		".htm":  true,
		".xml":  true,
		".json": true,
		".txt":  true,
		".svg":  true,
	}

	// 已经压缩的文件类型不再次压缩
	alreadyCompressed := map[string]bool{
		".gz":    true,
		".br":    true,
		".zip":   true,
		".rar":   true,
		".7z":    true,
		".jpg":   true,
		".jpeg":  true,
		".png":   true,
		".gif":   true,
		".webp":  true,
		".ico":   true,
		".woff":  true,
		".woff2": true,
		".ttf":   true,
		".eot":   true,
	}

	// 如果已经压缩，不再次压缩
	if alreadyCompressed[ext] {
		return false
	}

	// 如果是可压缩类型，且文件大小大于1KB，则压缩
	return compressibleTypes[ext] && fileSize >= 1024
}

// serveWithPrecompression 使用预压缩文件服务（避免内存泄漏）
// 修复：不再每次请求都读取整个文件到内存并压缩，而是使用预压缩文件
func (c *CDNCache) serveWithPrecompression(w http.ResponseWriter, r *http.Request, filePath string, meta *objectMeta) {
	acceptEncoding := r.Header.Get("Accept-Encoding")

	// 检查客户端支持的压缩算法（按优先级）
	supportsBr := strings.Contains(acceptEncoding, "br")
	supportsGzip := strings.Contains(acceptEncoding, "gzip")

	// 尝试使用预压缩文件
	if supportsBr {
		brPath := filePath + ".br"
		if stat, err := os.Stat(brPath); err == nil && stat.Size() > 0 {
			c.servePrecompressedFile(w, brPath, "br", meta)
			return
		}
	}

	if supportsGzip {
		gzPath := filePath + ".gz"
		if stat, err := os.Stat(gzPath); err == nil && stat.Size() > 0 {
			c.servePrecompressedFile(w, gzPath, "gzip", meta)
			return
		}
	}

	// 没有预压缩文件，返回原文件
	// 注意：不在请求时压缩，避免内存占用
	file, err := os.Open(filePath)
	if err != nil {
		c.log.Errorf("Failed to open cached file: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, file)
}

// servePrecompressedFile 服务预压缩文件
func (c *CDNCache) servePrecompressedFile(w http.ResponseWriter, compressedPath string, algorithm string, meta *objectMeta) {
	file, err := os.Open(compressedPath)
	if err != nil {
		c.log.Errorf("Failed to open precompressed file: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// 设置压缩相关头部
	w.Header().Set("Content-Encoding", algorithm)
	w.Header().Set("Vary", "Accept-Encoding")

	// 添加压缩统计信息（调试用）
	if c.log.Logger.IsLevelEnabled(logrus.DebugLevel) {
		stat, _ := file.Stat()
		w.Header().Set("X-CDN-Compression-Algorithm", algorithm)
		w.Header().Set("X-CDN-Original-Size", fmt.Sprintf("%d", meta.SizeBytes))
		w.Header().Set("X-CDN-Compressed-Size", fmt.Sprintf("%d", stat.Size()))
		if meta.SizeBytes > 0 {
			ratio := float64(stat.Size()) / float64(meta.SizeBytes)
			w.Header().Set("X-CDN-Compression-Ratio", fmt.Sprintf("%.2f", ratio))
		}
	}

	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, file)

	c.log.Debugf("CDN served precompressed %s: %s", algorithm, compressedPath)
}

// serveWithAdvancedCompression 使用高级压缩方式服务文件（已废弃，保留用于向后兼容）
// 警告：此方法会读取整个文件到内存，不推荐使用
// 请使用 serveWithPrecompression 代替
func (c *CDNCache) serveWithAdvancedCompression(w http.ResponseWriter, r *http.Request, file io.Reader, meta *objectMeta) {
	c.log.Warn("serveWithAdvancedCompression is deprecated and causes memory issues, please use serveWithPrecompression")

	// 读取文件内容
	content, err := io.ReadAll(file)
	if err != nil {
		c.log.Errorf("Failed to read cached file: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 使用压缩器压缩内容
	result, err := c.compressor.Compress(content, r.Header.Get("Accept-Encoding"))
	if err != nil {
		c.log.Errorf("Failed to compress content: %v", err)
		// 压缩失败，直接返回原内容
		w.WriteHeader(http.StatusOK)
		w.Write(content)
		return
	}

	// 设置压缩相关头部
	if result.Algorithm != compression.None {
		w.Header().Set("Content-Encoding", string(result.Algorithm))
		w.Header().Set("Vary", "Accept-Encoding")

		// 添加压缩统计信息（调试用）
		if c.log.Logger.IsLevelEnabled(logrus.DebugLevel) {
			w.Header().Set("X-CDN-Compression-Algorithm", string(result.Algorithm))
			w.Header().Set("X-CDN-Compression-Ratio", fmt.Sprintf("%.2f", result.Ratio))
			w.Header().Set("X-CDN-Original-Size", fmt.Sprintf("%d", result.OriginalSize))
			w.Header().Set("X-CDN-Compressed-Size", fmt.Sprintf("%d", result.CompressedSize))
		}

		c.log.Debugf("CDN compressed %s: %d -> %d bytes (%.1f%% reduction)",
			result.Algorithm, result.OriginalSize, result.CompressedSize, result.Ratio*100)
	}

	// 写入压缩后的内容
	w.WriteHeader(http.StatusOK)
	w.Write(result.Data)
}

// generatePrecompressedFiles 生成预压缩文件（gzip 和 brotli）
// 修复：在存储时生成，避免每次请求都压缩
func (c *CDNCache) generatePrecompressedFiles(filePath string, data []byte) {
	// 异步生成，不阻塞主流程
	go func() {
		// 生成 gzip 版本
		gzPath := filePath + ".gz"
		if result, err := c.compressor.Compress(data, "gzip"); err == nil && result.Algorithm == compression.Gzip {
			if err := os.WriteFile(gzPath, result.Data, 0644); err == nil {
				c.log.Debugf("Generated precompressed gzip: %s (%d -> %d bytes, %.1f%% reduction)",
					gzPath, result.OriginalSize, result.CompressedSize, result.Ratio*100)
			}
		}

		// 生成 brotli 版本
		brPath := filePath + ".br"
		if result, err := c.compressor.Compress(data, "br"); err == nil && result.Algorithm == compression.Brotli {
			if err := os.WriteFile(brPath, result.Data, 0644); err == nil {
				c.log.Debugf("Generated precompressed brotli: %s (%d -> %d bytes, %.1f%% reduction)",
					brPath, result.OriginalSize, result.CompressedSize, result.Ratio*100)
			}
		}
	}()
}

// serveWithCompression 使用压缩方式服务文件（保留用于向后兼容）
func (c *CDNCache) serveWithCompression(w http.ResponseWriter, r *http.Request, file io.Reader, meta *objectMeta) {
	// 使用新的高级压缩方法
	c.serveWithAdvancedCompression(w, r, file, meta)
}

// getSmartContentType 智能检测Content-Type
func (c *CDNCache) getSmartContentType(meta *objectMeta, path string) string {
	// 1. 如果元数据中有Content-Type，优先使用
	if meta.ContentType != "" {
		c.log.Debugf("使用存储的Content-Type: %s", meta.ContentType)
		return meta.ContentType
	}

	// 2. 尝试从文件内容检测
	if c.mimeDetector != nil {
		// 读取文件头进行检测
		filePath, _ := c.cachePaths(&http.Request{URL: &url.URL{Path: path}})
		if data, err := os.ReadFile(filePath); err == nil {
			detectedType := c.mimeDetector.DetectMIME(path, data)
			if detectedType != "" && detectedType != "application/octet-stream" {
				c.log.Debugf("通过文件内容检测到Content-Type: %s", detectedType)
				return detectedType
			}
		}
	}

	// 3. 通过扩展名猜测
	if c.mimeDetector != nil {
		detectedType := c.mimeDetector.DetectMIME(path, nil)
		if detectedType != "" && detectedType != "application/octet-stream" {
			c.log.Debugf("通过扩展名检测到Content-Type: %s", detectedType)
			return detectedType
		}
	}

	// 4. 使用系统默认MIME类型
	if mimeType := mime.TypeByExtension(filepath.Ext(path)); mimeType != "" {
		c.log.Debugf("使用系统默认MIME类型: %s", mimeType)
		return mimeType
	}

	// 5. 默认返回二进制类型
	c.log.Debugf("使用默认Content-Type: application/octet-stream")
	return "application/octet-stream"
}

// startProcessingCleaner 启动 processing map 清理器，防止内存泄漏
func (c *CDNCache) startProcessingCleaner() {
	c.cleanerMutex.Lock()
	defer c.cleanerMutex.Unlock()

	if c.cleanerStarted {
		return
	}
	c.cleanerStarted = true

	go func() {
		// 使用质数间隔避免与其他定时器同时触发（67秒）
		ticker := time.NewTicker(67 * time.Second)
		defer ticker.Stop()

		c.log.Info("CDN Cache processing map 清理器已启动")

		for {
			select {
			case <-ticker.C:
				c.cleanupStaleProcessingEntries()
			case <-c.stopProcessingCleaner:
				c.log.Info("CDN Cache processing map 清理器已停止")
				return
			}
		}
	}()
}

// cleanupStaleProcessingEntries 清理超时的 processing 条目
func (c *CDNCache) cleanupStaleProcessingEntries() {
	now := time.Now()
	timeout := 5 * time.Minute // 5分钟超时

	count := 0
	cleaned := 0

	c.processing.Range(func(key, value interface{}) bool {
		count++

		entry, ok := value.(*processingEntry)
		if !ok {
			// 旧格式或无效条目，直接删除
			c.processing.Delete(key)
			cleaned++
			c.log.Warnf("清理无效的 processing 条目: %v", key)
			return true
		}

		// 检查是否超时
		if now.Sub(entry.createdAt) > timeout {
			c.log.Warnf("清理超时的 processing 条目: %v (创建于 %v, 已存在 %v)",
				key, entry.createdAt, now.Sub(entry.createdAt))

			// 安全关闭 channel
			select {
			case <-entry.ch:
				// 已经关闭
			default:
				close(entry.ch)
			}

			c.processing.Delete(key)
			cleaned++
		}

		return true
	})

	// 如果 map 大小异常，记录警告
	if count > 1000 {
		c.log.Errorf("⚠️ CDN Cache processing map 大小异常: %d 个条目（已清理 %d 个）", count, cleaned)
	} else if count > 100 {
		c.log.Warnf("CDN Cache processing map 较大: %d 个条目（已清理 %d 个）", count, cleaned)
	} else if cleaned > 0 {
		c.log.Infof("CDN Cache processing map 清理完成: 总数 %d, 清理 %d", count, cleaned)
	}
}

// StopCleaner 停止清理器（在关闭时调用）
func (c *CDNCache) StopCleaner() {
	c.cleanerMutex.Lock()
	defer c.cleanerMutex.Unlock()

	if c.cleanerStarted && c.stopProcessingCleaner != nil {
		select {
		case <-c.stopProcessingCleaner:
			// 已经关闭
		default:
			close(c.stopProcessingCleaner)
		}
		c.cleanerStarted = false
	}

	if c.periodicCleanerStarted && c.stopCleaner != nil {
		select {
		case <-c.stopCleaner:
			// 已经关闭
		default:
			close(c.stopCleaner)
		}
		c.periodicCleanerStarted = false
	}
	c.log.Info("CDN Cache 清理器已停止")
}

// GetProcessingMapSize 获取 processing map 的大小（用于监控）
func (c *CDNCache) GetProcessingMapSize() int {
	count := 0
	c.processing.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

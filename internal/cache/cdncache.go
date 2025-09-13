package cache

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

// CDNCache 本地静态文件缓存管理器
type CDNCache struct {
	cfg   *config.Config
	log   *logrus.Entry
	mutex sync.Mutex
	// 统计计数器
	hits   int64
	misses int64
}

type objectMeta struct {
	Host          string    `json:"host"`
	URL           string    `json:"url"`
	Path          string    `json:"path"`
	ContentType   string    `json:"content_type"`
	Encoding      string    `json:"encoding"`
	ETag          string    `json:"etag"`
	TTLSeconds    int       `json:"ttl_seconds"`
	ExpiresAtUnix int64     `json:"expires_at_unix"`
	LastAccess    time.Time `json:"last_access"`
	SizeBytes     int64     `json:"size_bytes"`
}

func NewCDNCache(cfg *config.Config) *CDNCache {
	return &CDNCache{
		cfg: cfg,
		log: logrus.WithFields(logrus.Fields{"component": "cdn_cache"}),
	}
}

// ServeIfFresh 若命中缓存且未过期，直接回源本地文件
func (c *CDNCache) ServeIfFresh(w http.ResponseWriter, r *http.Request) bool {
	if c == nil || !c.isEnabled() {
		// 统计未命中（未启用）
		if c != nil {
			c.misses++
		}
		return false
	}
	// 仅缓存 GET/HEAD
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}

	filePath, metaPath := c.cachePaths(r)
	meta, err := c.readMeta(metaPath)
	if err != nil || meta == nil {
		// 统计未命中（无元数据）
		c.misses++
		return false
	}
	// 过期检查
	if meta.ExpiresAtUnix > 0 && time.Now().Unix() >= meta.ExpiresAtUnix {
		_ = os.Remove(filePath)
		_ = os.Remove(metaPath)
		// 统计未命中（已过期）
		c.misses++
		return false
	}
	// 回写头
	if meta.ContentType != "" {
		w.Header().Set("Content-Type", meta.ContentType)
	}
	if meta.Encoding != "" {
		w.Header().Set("Content-Encoding", meta.Encoding)
	}
	if meta.ETag != "" {
		w.Header().Set("ETag", meta.ETag)
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

	// 简单写回
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)

	// 更新访问时间
	c.touch(metaPath, meta)
	// 统计命中
	c.hits++
	return true
}

// MaybeStore 按规则存储响应
// 注意：该函数会读取 resp.Body 并重置
func (c *CDNCache) MaybeStore(resp *http.Response) {
	if c == nil || !c.isEnabled() || resp == nil || resp.Request == nil {
		return
	}
	req := resp.Request
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return
	}
	// 遵循上游缓存控制
	cc := parseCacheControl(resp.Header.Get("Cache-Control"))
	if cc.noStore || cc.noCache || cc.private {
		return
	}

	contentType := resp.Header.Get("Content-Type")
	// 规则 TTL 计算
	ttl := c.selectTTL(req.URL.Path, contentType)
	// 域名级默认 TTL 覆盖（由代理暂存至响应头）
	if v := strings.TrimSpace(resp.Header.Get("X-SSLcat-CDN-Default-TTL")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			ttl = n
		}
	}
	if ttl <= 0 {
		return
	}
	if cc.maxAge >= 0 {
		// 如果上游携带 max-age，取二者较小值
		if cc.maxAge < ttl {
			ttl = cc.maxAge
		}
	}

	maxObj := c.cfg.CDNCache.MaxObjectBytes
	if maxObj <= 0 {
		maxObj = 20 * 1024 * 1024
	}

	// 读取响应体
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		c.log.Debugf("read response body failed: %v", err)
		resp.Body = io.NopCloser(bytes.NewReader(nil))
		return
	}
	// 重置响应体给下游继续写
	resp.Body = io.NopCloser(bytes.NewReader(data))

	if int64(len(data)) > maxObj {
		return
	}

	filePath, metaPath := c.cachePaths(req)
	_ = os.MkdirAll(filepath.Dir(filePath), 0755)

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		c.log.Debugf("write cache failed: %v", err)
		return
	}

	encoding := resp.Header.Get("Content-Encoding")
	meta := &objectMeta{
		Host:          hostOnly(req.Host),
		URL:           req.URL.String(),
		Path:          req.URL.Path,
		ContentType:   contentType,
		Encoding:      encoding,
		ETag:          resp.Header.Get("ETag"),
		TTLSeconds:    ttl,
		ExpiresAtUnix: time.Now().Add(time.Duration(ttl) * time.Second).Unix(),
		LastAccess:    time.Now(),
		SizeBytes:     int64(len(data)),
	}
	_ = c.writeMeta(metaPath, meta)

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
	interval := time.Duration(c.cfg.CDNCache.CleanIntervalSec)
	if interval <= 0 {
		interval = 60
	}
	go func() {
		ticker := time.NewTicker(interval * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			c.CleanOnce()
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
	if c.hits+c.misses > 0 {
		hitRate = float64(c.hits) / float64(c.hits+c.misses) * 100
	}
	
	return map[string]any{
		"enabled":     true,
		"objects":     objectCount,
		"total_size":  totalSize,
		"hits":        c.hits,
		"misses":      c.misses,
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
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(metaPath, b, 0644)
}

func (c *CDNCache) touch(metaPath string, m *objectMeta) {
	if m == nil {
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

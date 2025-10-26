package cache

import (
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// MemoryCacheItem 统一的内存缓存项
type MemoryCacheItem struct {
	Data        []byte
	Metadata    map[string]interface{} // 额外元数据
	Size        int64
	CreatedAt   time.Time
	ExpiresAt   time.Time // TTL 过期时间
	LastAccess  time.Time
	AccessCount int64
}

// IsExpired 检查是否过期
func (item *MemoryCacheItem) IsExpired() bool {
	if item.ExpiresAt.IsZero() {
		return false // 永不过期
	}
	return time.Now().After(item.ExpiresAt)
}

// MemoryCacheConfig 统一的内存缓存配置
type MemoryCacheConfig struct {
	Name            string        // 缓存名称（用于日志）
	MaxEntries      int           // 最大条目数
	MaxSizeBytes    int64         // 最大总大小（字节）
	MaxItemSize     int64         // 单个项最大大小（字节）
	DefaultTTL      time.Duration // 默认 TTL（0 表示永不过期）
	CleanupInterval time.Duration // 清理间隔
}

// DefaultMemoryCacheConfig 默认配置
func DefaultMemoryCacheConfig(name string) *MemoryCacheConfig {
	return &MemoryCacheConfig{
		Name:            name,
		MaxEntries:      100,
		MaxSizeBytes:    100 * 1024 * 1024, // 100MB
		MaxItemSize:     10 * 1024 * 1024,  // 10MB
		DefaultTTL:      24 * time.Hour,    // 24小时
		CleanupInterval: 5 * time.Minute,   // 5分钟清理一次
	}
}

// MemoryCache 统一的内存缓存管理器
type MemoryCache struct {
	config    *MemoryCacheConfig
	cache     map[string]*MemoryCacheItem
	mutex     sync.RWMutex
	totalSize int64
	log       *logrus.Entry

	// 统计
	hits      uint64
	misses    uint64
	evictions uint64
	expired   uint64

	// 控制
	stopCleanup chan struct{}
}

// NewMemoryCache 创建统一的内存缓存管理器
func NewMemoryCache(config *MemoryCacheConfig) *MemoryCache {
	if config == nil {
		config = DefaultMemoryCacheConfig("default")
	}

	mc := &MemoryCache{
		config:      config,
		cache:       make(map[string]*MemoryCacheItem),
		stopCleanup: make(chan struct{}),
		log: logrus.WithFields(logrus.Fields{
			"component": "memory_cache",
			"name":      config.Name,
		}),
	}

	// 启动自动清理
	if config.CleanupInterval > 0 {
		go mc.cleanupLoop()
	}

	mc.log.Infof("Memory cache initialized: max_entries=%d, max_size=%d bytes, ttl=%v",
		config.MaxEntries, config.MaxSizeBytes, config.DefaultTTL)

	return mc
}

// Get 获取缓存项
func (mc *MemoryCache) Get(key string) (*MemoryCacheItem, bool) {
	mc.mutex.RLock()
	item, ok := mc.cache[key]
	mc.mutex.RUnlock()

	if !ok {
		mc.misses++
		return nil, false
	}

	// 检查是否过期
	if item.IsExpired() {
		mc.mutex.Lock()
		delete(mc.cache, key)
		mc.totalSize -= item.Size
		mc.mutex.Unlock()
		mc.misses++
		mc.expired++
		return nil, false
	}

	// 更新访问信息
	mc.mutex.Lock()
	item.LastAccess = time.Now()
	item.AccessCount++
	mc.mutex.Unlock()

	mc.hits++
	return item, true
}

// Set 设置缓存项
func (mc *MemoryCache) Set(key string, data []byte, ttl time.Duration) error {
	return mc.SetWithMetadata(key, data, nil, ttl)
}

// SetWithMetadata 设置带元数据的缓存项
func (mc *MemoryCache) SetWithMetadata(key string, data []byte, metadata map[string]interface{}, ttl time.Duration) error {
	size := int64(len(data))

	// 检查单个项大小
	if mc.config.MaxItemSize > 0 && size > mc.config.MaxItemSize {
		return fmt.Errorf("item too large: %d bytes (max: %d)", size, mc.config.MaxItemSize)
	}

	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	// 如果已存在，先减去旧的大小
	if old, exists := mc.cache[key]; exists {
		mc.totalSize -= old.Size
	}

	// 检查是否需要驱逐
	for mc.totalSize+size > mc.config.MaxSizeBytes || len(mc.cache) >= mc.config.MaxEntries {
		if !mc.evictOne() {
			return fmt.Errorf("failed to evict items to make space")
		}
	}

	// 确定过期时间
	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	} else if mc.config.DefaultTTL > 0 {
		expiresAt = time.Now().Add(mc.config.DefaultTTL)
	}
	// 否则 expiresAt 保持零值（永不过期）

	// 添加新项
	now := time.Now()
	mc.cache[key] = &MemoryCacheItem{
		Data:        data,
		Metadata:    metadata,
		Size:        size,
		CreatedAt:   now,
		ExpiresAt:   expiresAt,
		LastAccess:  now,
		AccessCount: 0,
	}
	mc.totalSize += size

	return nil
}

// Delete 删除缓存项
func (mc *MemoryCache) Delete(key string) bool {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	if item, ok := mc.cache[key]; ok {
		delete(mc.cache, key)
		mc.totalSize -= item.Size
		return true
	}
	return false
}

// Clear 清空所有缓存
func (mc *MemoryCache) Clear() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.cache = make(map[string]*MemoryCacheItem)
	mc.totalSize = 0
	mc.log.Info("Cache cleared")
}

// evictOne 驱逐一个最久未使用的项（需要持有锁）
func (mc *MemoryCache) evictOne() bool {
	if len(mc.cache) == 0 {
		return false
	}

	// 找到最久未访问的项
	var oldestKey string
	var oldestTime time.Time

	for key, item := range mc.cache {
		if oldestKey == "" || item.LastAccess.Before(oldestTime) {
			oldestKey = key
			oldestTime = item.LastAccess
		}
	}

	if oldestKey != "" {
		item := mc.cache[oldestKey]
		delete(mc.cache, oldestKey)
		mc.totalSize -= item.Size
		mc.evictions++
		mc.log.Debugf("Evicted item: key=%s, size=%d bytes, age=%v",
			oldestKey, item.Size, time.Since(item.CreatedAt))
		return true
	}

	return false
}

// cleanupLoop 定期清理过期项
func (mc *MemoryCache) cleanupLoop() {
	// 使用质数间隔避免与其他定时器同时触发（7分钟）
	cleanupInterval := mc.config.CleanupInterval
	if cleanupInterval == 5*time.Minute {
		cleanupInterval = 7 * time.Minute
	}

	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mc.cleanupExpired()
		case <-mc.stopCleanup:
			return
		}
	}
}

// cleanupExpired 清理过期项
func (mc *MemoryCache) cleanupExpired() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	var expiredKeys []string
	now := time.Now()

	for key, item := range mc.cache {
		if !item.ExpiresAt.IsZero() && now.After(item.ExpiresAt) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	if len(expiredKeys) > 0 {
		for _, key := range expiredKeys {
			if item, ok := mc.cache[key]; ok {
				delete(mc.cache, key)
				mc.totalSize -= item.Size
				mc.expired++
			}
		}
		mc.log.Infof("Cleaned up %d expired items", len(expiredKeys))
	}
}

// Stats 获取统计信息
func (mc *MemoryCache) Stats() map[string]interface{} {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	hitRate := float64(0)
	total := mc.hits + mc.misses
	if total > 0 {
		hitRate = float64(mc.hits) / float64(total) * 100
	}

	return map[string]interface{}{
		"name":        mc.config.Name,
		"entries":     len(mc.cache),
		"max_entries": mc.config.MaxEntries,
		"total_size":  mc.totalSize,
		"max_size":    mc.config.MaxSizeBytes,
		"hits":        mc.hits,
		"misses":      mc.misses,
		"hit_rate":    fmt.Sprintf("%.2f%%", hitRate),
		"evictions":   mc.evictions,
		"expired":     mc.expired,
	}
}

// Close 关闭缓存管理器
func (mc *MemoryCache) Close() {
	close(mc.stopCleanup)
	mc.Clear()
	mc.log.Info("Memory cache closed")
}

// GetKeys 获取所有键（用于调试）
func (mc *MemoryCache) GetKeys() []string {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	keys := make([]string, 0, len(mc.cache))
	for key := range mc.cache {
		keys = append(keys, key)
	}
	return keys
}

// GetSize 获取当前缓存大小
func (mc *MemoryCache) GetSize() int64 {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()
	return mc.totalSize
}

// GetCount 获取当前缓存项数量
func (mc *MemoryCache) GetCount() int {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()
	return len(mc.cache)
}

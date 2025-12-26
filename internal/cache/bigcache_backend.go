package cache

import (
	"context"
	"time"

	"github.com/allegro/bigcache/v3"
	"github.com/sirupsen/logrus"
)

// BigCacheBackend bigcache 后端实现
type BigCacheBackend struct {
	cache  *bigcache.BigCache
	config *bigcache.Config
	log    *logrus.Entry
}

// NewBigCacheBackend 创建 bigcache 后端
func NewBigCacheBackend(config *MemoryCacheConfig) (CacheBackend, error) {
	if config == nil {
		config = DefaultMemoryCacheConfig("bigcache")
	}

	// 转换配置为 BigCache 配置
	bigCacheConfig := bigcache.DefaultConfig(time.Duration(config.DefaultTTL))
	// 激进优化：大幅减少分片数，降低预分配内存
	// bigcache 使用 mmap，每个 shard 会预分配大量内存（可能几 GB）
	// 对于小缓存，使用最少的分片数（2-4 个）可以显著减少内存占用
	if config.MaxSizeBytes < 10*1024*1024 {
		bigCacheConfig.Shards = 2 // 极小缓存（<10MB）使用 2 个分片
	} else if config.MaxSizeBytes < 50*1024*1024 {
		bigCacheConfig.Shards = 4 // 小缓存（<50MB）使用 4 个分片
	} else {
		bigCacheConfig.Shards = 8 // 大缓存使用 8 个分片（从 16 减少）
	}
	bigCacheConfig.LifeWindow = time.Duration(config.DefaultTTL)
	bigCacheConfig.CleanWindow = time.Duration(config.CleanupInterval)
	// 大幅减少 MaxEntriesInWindow，降低预分配内存
	// 使用 1.2 倍而不是 1.5 倍，进一步减少内存占用
	// 注意：这可能会影响缓存性能，但对于低流量场景可以接受
	bigCacheConfig.MaxEntriesInWindow = int(float64(config.MaxEntries) * 1.2)
	bigCacheConfig.MaxEntrySize = int(config.MaxItemSize)
	bigCacheConfig.HardMaxCacheSize = int(config.MaxSizeBytes / (1024 * 1024)) // 转换为 MB
	bigCacheConfig.Verbose = false
	bigCacheConfig.Logger = logrus.New()

	// 创建 BigCache 实例
	cache, err := bigcache.New(context.Background(), bigCacheConfig)
	if err != nil {
		return nil, err
	}

	bc := &BigCacheBackend{
		cache:  cache,
		config: &bigCacheConfig,
		log: logrus.WithFields(logrus.Fields{
			"component": "bigcache_backend",
			"name":      config.Name,
		}),
	}

	bc.log.Infof("BigCache backend initialized: max_entries=%d, max_size=%d bytes, ttl=%v, shards=%d",
		config.MaxEntries, config.MaxSizeBytes, config.DefaultTTL, bigCacheConfig.Shards)

	return bc, nil
}

// Get 获取缓存值
func (bc *BigCacheBackend) Get(key string) ([]byte, error) {
	return bc.cache.Get(key)
}

// Set 设置缓存值
func (bc *BigCacheBackend) Set(key string, value []byte) error {
	return bc.cache.Set(key, value)
}

// Delete 删除缓存值
func (bc *BigCacheBackend) Delete(key string) error {
	return bc.cache.Delete(key)
}

// Len 获取缓存条目数
func (bc *BigCacheBackend) Len() int {
	return bc.cache.Len()
}

// Reset 清空所有缓存
func (bc *BigCacheBackend) Reset() error {
	return bc.cache.Reset()
}

// Close 关闭缓存
func (bc *BigCacheBackend) Close() error {
	return bc.cache.Close()
}


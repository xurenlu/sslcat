package cache

// CacheBackend 缓存后端接口
type CacheBackend interface {
	// Get 获取缓存值
	Get(key string) ([]byte, error)
	// Set 设置缓存值
	Set(key string, value []byte) error
	// Delete 删除缓存值
	Delete(key string) error
	// Len 获取缓存条目数
	Len() int
	// Reset 清空所有缓存
	Reset() error
	// Close 关闭缓存
	Close() error
}

// CacheBackendType 缓存后端类型
type CacheBackendType string

const (
	// CacheBackendBigCache 使用 bigcache（高性能，但内存占用高）
	CacheBackendBigCache CacheBackendType = "bigcache"
	// CacheBackendSimple 使用简单的 map-based 缓存（轻量级，按需分配）
	CacheBackendSimple CacheBackendType = "simple"
	// CacheBackendAuto 自动选择（小缓存用 simple，大缓存用 bigcache）
	CacheBackendAuto CacheBackendType = "auto"
)

// NewCacheBackend 根据类型创建缓存后端
func NewCacheBackend(backendType CacheBackendType, config *MemoryCacheConfig) (CacheBackend, error) {
	// 如果未指定类型，默认使用 simple（轻量级，适合低流量场景）
	if backendType == "" {
		backendType = CacheBackendSimple
	}

	// Auto 模式：根据缓存大小自动选择
	if backendType == CacheBackendAuto {
		// 小缓存（<10MB）使用 simple，大缓存使用 bigcache
		if config.MaxSizeBytes < 10*1024*1024 {
			backendType = CacheBackendSimple
		} else {
			backendType = CacheBackendBigCache
		}
	}

	switch backendType {
	case CacheBackendSimple:
		return NewSimpleCacheBackend(config)
	case CacheBackendBigCache:
		return NewBigCacheBackend(config)
	default:
		// 默认使用 simple（更轻量）
		return NewSimpleCacheBackend(config)
	}
}


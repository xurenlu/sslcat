package cache

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"github.com/allegro/bigcache/v3"
	"github.com/sirupsen/logrus"
)

// MemoryCacheItem 统一的内存缓存项
type MemoryCacheItem struct {
	Data        []byte                 `json:"data"`
	Metadata    map[string]interface{} `json:"metadata"`
	Size        int64                  `json:"size"`
	CreatedAt   time.Time              `json:"created_at"`
	ExpiresAt   time.Time              `json:"expires_at"`
	LastAccess  time.Time              `json:"last_access"`
	AccessCount int64                  `json:"access_count"`
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
		MaxEntries:      1000,             // 增加到1000，BigCache性能更好
		MaxSizeBytes:    25 * 1024 * 1024, // 25MB (从50MB减半)
		MaxItemSize:     5 * 1024 * 1024,  // 5MB (从10MB减半)
		DefaultTTL:      24 * time.Hour,   // 24小时
		CleanupInterval: 5 * time.Minute,  // 5分钟清理一次
	}
}

// MemoryCache 统一的内存缓存管理器（使用 BigCache 作为底层实现）
type MemoryCache struct {
	cache  *bigcache.BigCache
	config *bigcache.Config
	log    *logrus.Entry
	name   string

	// 统计信息（手动维护，因为 BigCache 不提供详细统计）
	hits      uint64
	misses    uint64
	evictions uint64
	expired   uint64
}

// NewMemoryCache 创建统一的内存缓存管理器
func NewMemoryCache(config *MemoryCacheConfig) *MemoryCache {
	if config == nil {
		config = DefaultMemoryCacheConfig("default")
	}

	// 转换配置为 BigCache 配置
	bigCacheConfig := bigcache.DefaultConfig(time.Duration(config.DefaultTTL))
	bigCacheConfig.Shards = 16 // 从32减少到16，减少内存开销（分片预分配）
	bigCacheConfig.LifeWindow = time.Duration(config.DefaultTTL)
	bigCacheConfig.CleanWindow = time.Duration(config.CleanupInterval)
	bigCacheConfig.MaxEntriesInWindow = config.MaxEntries * 2 // 从5倍减少到2倍
	bigCacheConfig.MaxEntrySize = int(config.MaxItemSize)
	bigCacheConfig.HardMaxCacheSize = int(config.MaxSizeBytes / (1024 * 1024)) // 转换为 MB
	bigCacheConfig.Verbose = false
	bigCacheConfig.Logger = logrus.New()

	// 创建 BigCache 实例
	cache, err := bigcache.New(context.Background(), bigCacheConfig)
	if err != nil {
		panic(fmt.Sprintf("Failed to create BigCache: %v", err))
	}

	mc := &MemoryCache{
		cache:  cache,
		config: &bigCacheConfig,
		name:   config.Name,
		log: logrus.WithFields(logrus.Fields{
			"component": "memory_cache",
			"name":      config.Name,
		}),
	}

	mc.log.Infof("Memory cache initialized with BigCache: max_entries=%d, max_size=%d bytes, ttl=%v",
		config.MaxEntries, config.MaxSizeBytes, config.DefaultTTL)

	return mc
}

// Get 获取缓存项
func (mc *MemoryCache) Get(key string) (*MemoryCacheItem, bool) {
	data, err := mc.cache.Get(key)
	if err != nil {
		mc.misses++
		return nil, false
	}

	// 反序列化缓存项
	item, err := unmarshalCacheItem(data)
	if err != nil {
		mc.misses++
		mc.log.Errorf("Failed to unmarshal cache item: %v", err)
		return nil, false
	}

	// 检查是否过期
	if item.IsExpired() {
		mc.cache.Delete(key)
		mc.misses++
		mc.expired++
		return nil, false
	}

	// 更新访问信息
	item.LastAccess = time.Now()
	item.AccessCount++

	// 重新序列化并存储（更新访问时间）
	if updatedData, err := marshalCacheItem(item); err == nil {
		_ = mc.cache.Set(key, updatedData)
	} else {
		mc.log.Errorf("Failed to re-marshal cache item: %v", err)
	}

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
	if size > int64(mc.config.MaxEntrySize) {
		return fmt.Errorf("item too large: %d bytes (max: %d)", size, mc.config.MaxEntrySize)
	}

	// 确定过期时间
	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	} else if mc.config.LifeWindow > 0 {
		expiresAt = time.Now().Add(mc.config.LifeWindow)
	}

	// 创建缓存项
	item := &MemoryCacheItem{
		Data:        data,
		Metadata:    metadata,
		Size:        size,
		CreatedAt:   time.Now(),
		ExpiresAt:   expiresAt,
		LastAccess:  time.Now(),
		AccessCount: 0,
	}

	// 序列化
	itemData, err := marshalCacheItem(item)
	if err != nil {
		return fmt.Errorf("failed to marshal cache item: %w", err)
	}

	// 存储到 BigCache
	return mc.cache.Set(key, itemData)
}

// Delete 删除缓存项
func (mc *MemoryCache) Delete(key string) bool {
	err := mc.cache.Delete(key)
	return err == nil
}

// Clear 清空所有缓存
func (mc *MemoryCache) Clear() {
	mc.cache.Reset()
	mc.log.Info("Cache cleared")
}

// Stats 获取统计信息
func (mc *MemoryCache) Stats() map[string]interface{} {
	stats := mc.cache.Len()
	totalRequests := mc.hits + mc.misses
	hitRate := 0.0
	if totalRequests > 0 {
		hitRate = float64(mc.hits) / float64(totalRequests) * 100
	}

	return map[string]interface{}{
		"entries":          stats,
		"hits":             mc.hits,
		"misses":           mc.misses,
		"evictions":        mc.evictions,
		"expired":          mc.expired,
		"hit_rate":         hitRate,
		"cache_size_bytes": int64(stats) * 1024, // 估算
	}
}

// GetSize 获取当前缓存大小（字节）
func (mc *MemoryCache) GetSize() int64 {
	// BigCache 不直接提供大小信息，我们通过条目数估算
	entries := mc.cache.Len()
	// 估算每个条目平均大小（包括序列化开销）
	avgSize := int64(1024) // 1KB 作为平均大小
	return int64(entries) * avgSize
}

// Close 关闭缓存
func (mc *MemoryCache) Close() {
	mc.cache.Close()
	mc.log.Info("Memory cache closed")
}

const cacheEncodingVersion = uint8(1)

func marshalCacheItem(item *MemoryCacheItem) ([]byte, error) {
	metaBytes := []byte{}
	if item.Metadata != nil && len(item.Metadata) > 0 {
		var err error
		metaBytes, err = json.Marshal(item.Metadata)
		if err != nil {
			return nil, err
		}
	}

	dataLen := uint32(len(item.Data))
	metaLen := uint32(len(metaBytes))

	// 预估容量：头部 1 + 4*3 + 8*4 + len(data) + len(meta)
	buf := bytes.NewBuffer(make([]byte, 0, int(dataLen)+int(metaLen)+64))
	if err := buf.WriteByte(cacheEncodingVersion); err != nil {
		return nil, err
	}

	// 写入固定字段
	if err := binary.Write(buf, binary.LittleEndian, item.Size); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, dataLen); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, metaLen); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, encodeTime(item.CreatedAt)); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, encodeTime(item.ExpiresAt)); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, encodeTime(item.LastAccess)); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, item.AccessCount); err != nil {
		return nil, err
	}

	if metaLen > 0 {
		if _, err := buf.Write(metaBytes); err != nil {
			return nil, err
		}
	}
	if dataLen > 0 {
		if _, err := buf.Write(item.Data); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func unmarshalCacheItem(data []byte) (*MemoryCacheItem, error) {
	reader := bytes.NewReader(data)

	versionByte, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if versionByte != cacheEncodingVersion {
		return nil, fmt.Errorf("unsupported cache item version: %d", versionByte)
	}

	var (
		size        int64
		dataLen     uint32
		metaLen     uint32
		createdNano int64
		expiresNano int64
		lastNano    int64
		accessCount int64
	)

	if err := binary.Read(reader, binary.LittleEndian, &size); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &dataLen); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &metaLen); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &createdNano); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &expiresNano); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &lastNano); err != nil {
		return nil, err
	}
	if err := binary.Read(reader, binary.LittleEndian, &accessCount); err != nil {
		return nil, err
	}

	if dataLen > uint32(len(data)) || metaLen > uint32(len(data)) {
		return nil, fmt.Errorf("invalid cache payload length")
	}

	metaBytes := make([]byte, metaLen)
	if metaLen > 0 {
		if _, err := reader.Read(metaBytes); err != nil {
			return nil, err
		}
	}

	itemData := make([]byte, dataLen)
	if dataLen > 0 {
		if _, err := reader.Read(itemData); err != nil {
			return nil, err
		}
	}

	var metadata map[string]interface{}
	if metaLen > 0 {
		if err := json.Unmarshal(metaBytes, &metadata); err != nil {
			return nil, err
		}
	}

	item := &MemoryCacheItem{
		Data:        itemData,
		Metadata:    metadata,
		Size:        size,
		CreatedAt:   decodeTime(createdNano),
		ExpiresAt:   decodeTime(expiresNano),
		LastAccess:  decodeTime(lastNano),
		AccessCount: accessCount,
	}

	// 保证 Size 与 Data 长度一致
	if item.Size == 0 && dataLen > 0 {
		item.Size = int64(dataLen)
	}

	return item, nil
}

func encodeTime(t time.Time) int64 {
	if t.IsZero() {
		return -1
	}
	return t.UnixNano()
}

func decodeTime(ts int64) time.Time {
	if ts <= 0 {
		return time.Time{}
	}
	return time.Unix(0, ts)
}

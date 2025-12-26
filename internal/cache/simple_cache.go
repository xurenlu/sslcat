package cache

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// simpleCacheItem 简单缓存的条目
type simpleCacheItem struct {
	data      []byte
	expiresAt time.Time
}

// SimpleCacheBackend 简单的 map-based 缓存实现（轻量级，按需分配）
type SimpleCacheBackend struct {
	items      map[string]*simpleCacheItem
	mu         sync.RWMutex
	maxEntries int
	maxSize    int64
	currentSize int64
	ttl        time.Duration
	log        *logrus.Entry
	stopChan   chan struct{}
}

// NewSimpleCacheBackend 创建简单的缓存后端
func NewSimpleCacheBackend(config *MemoryCacheConfig) (CacheBackend, error) {
	if config == nil {
		config = DefaultMemoryCacheConfig("simple")
	}

	sc := &SimpleCacheBackend{
		items:      make(map[string]*simpleCacheItem),
		maxEntries: config.MaxEntries,
		maxSize:    config.MaxSizeBytes,
		currentSize: 0,
		ttl:        config.DefaultTTL,
		log: logrus.WithFields(logrus.Fields{
			"component": "simple_cache",
			"name":      config.Name,
		}),
		stopChan: make(chan struct{}),
	}

	// 启动清理协程
	go sc.cleanupLoop(config.CleanupInterval)

	sc.log.Infof("Simple cache initialized: max_entries=%d, max_size=%d bytes, ttl=%v",
		config.MaxEntries, config.MaxSizeBytes, config.DefaultTTL)

	return sc, nil
}

// Get 获取缓存值
func (sc *SimpleCacheBackend) Get(key string) ([]byte, error) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	item, ok := sc.items[key]
	if !ok {
		return nil, ErrNotFound
	}

	// 检查是否过期
	if !item.expiresAt.IsZero() && time.Now().After(item.expiresAt) {
		// 异步删除过期项
		go sc.Delete(key)
		return nil, ErrNotFound
	}

	// 返回副本，避免外部修改
	result := make([]byte, len(item.data))
	copy(result, item.data)
	return result, nil
}

// Set 设置缓存值
func (sc *SimpleCacheBackend) Set(key string, value []byte) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	// 检查大小限制
	valueSize := int64(len(value))
	if valueSize > sc.maxSize {
		return ErrItemTooLarge
	}

	// 如果已存在，先删除旧项
	if oldItem, ok := sc.items[key]; ok {
		sc.currentSize -= int64(len(oldItem.data))
	}

	// 检查总大小限制
	if sc.currentSize+valueSize > sc.maxSize {
		// 尝试清理过期项
		sc.cleanupExpiredLocked()
		
		// 如果仍然超限，删除最旧的项（简单的 FIFO）
		if sc.currentSize+valueSize > sc.maxSize {
			sc.evictOldestLocked()
		}
	}

	// 检查条目数限制
	if len(sc.items) >= sc.maxEntries {
		// 如果已满，删除最旧的项
		if _, ok := sc.items[key]; !ok {
			sc.evictOldestLocked()
		}
	}

	// 计算过期时间
	var expiresAt time.Time
	if sc.ttl > 0 {
		expiresAt = time.Now().Add(sc.ttl)
	}

	// 存储新项
	sc.items[key] = &simpleCacheItem{
		data:      value,
		expiresAt: expiresAt,
	}
	sc.currentSize += valueSize

	return nil
}

// Delete 删除缓存值
func (sc *SimpleCacheBackend) Delete(key string) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if item, ok := sc.items[key]; ok {
		sc.currentSize -= int64(len(item.data))
		delete(sc.items, key)
	}

	return nil
}

// Len 获取缓存条目数
func (sc *SimpleCacheBackend) Len() int {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return len(sc.items)
}

// Reset 清空所有缓存
func (sc *SimpleCacheBackend) Reset() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.items = make(map[string]*simpleCacheItem)
	sc.currentSize = 0
	return nil
}

// Close 关闭缓存
func (sc *SimpleCacheBackend) Close() error {
	close(sc.stopChan)
	sc.Reset()
	return nil
}

// cleanupLoop 清理循环
func (sc *SimpleCacheBackend) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sc.cleanupExpired()
		case <-sc.stopChan:
			return
		}
	}
}

// cleanupExpired 清理过期项
func (sc *SimpleCacheBackend) cleanupExpired() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.cleanupExpiredLocked()
}

// cleanupExpiredLocked 清理过期项（需要持有锁）
func (sc *SimpleCacheBackend) cleanupExpiredLocked() {
	now := time.Now()
	for key, item := range sc.items {
		if !item.expiresAt.IsZero() && now.After(item.expiresAt) {
			sc.currentSize -= int64(len(item.data))
			delete(sc.items, key)
		}
	}
}

// evictOldestLocked 删除最旧的项（简单的 FIFO）
func (sc *SimpleCacheBackend) evictOldestLocked() {
	// 简单的实现：删除第一个项
	for key, item := range sc.items {
		sc.currentSize -= int64(len(item.data))
		delete(sc.items, key)
		return // 只删除一个
	}
}

// 错误定义
var (
	ErrNotFound    = &CacheError{Message: "key not found"}
	ErrItemTooLarge = &CacheError{Message: "item too large"}
)

// CacheError 缓存错误
type CacheError struct {
	Message string
}

func (e *CacheError) Error() string {
	return e.Message
}


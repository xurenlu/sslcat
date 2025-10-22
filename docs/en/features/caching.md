# 统一内存缓存管理器

## 🎯 问题

目前系统中有多个独立的内存缓存实现：

1. **压缩缓存** (`CompressionCache`) - 静态文件压缩结果
2. **图片优化缓存** (`ImageOptimizer.cache`) - WebP 转换结果
3. **DNS 缓存** (`DNSCache`) - DNS 提供商信息
4. **会话缓存** (`SessionManager`) - 用户会话

每个都有自己的：
- ❌ 缓存逻辑（不一致）
- ❌ TTL 管理（有的有，有的没有）
- ❌ 过期清理（实现不同）
- ❌ 统计信息（格式不同）

## ✅ 解决方案

创建 **统一的内存缓存管理器** (`MemoryCache`)：

- ✅ 统一的接口和行为
- ✅ 完整的 TTL 支持
- ✅ 自动过期清理
- ✅ LRU 驱逐策略
- ✅ 线程安全
- ✅ 统一的统计信息

## 🏗️ 架构设计

### 核心组件

```
┌─────────────────────────────────────┐
│     UnifiedMemoryCache Manager      │
├─────────────────────────────────────┤
│  - TTL 过期管理                      │
│  - LRU 驱逐策略                      │
│  - 自动清理（可配置间隔）             │
│  - 大小限制（总大小 + 单项大小）      │
│  - 线程安全（读写锁）                │
│  - 统一统计（命中率、驱逐等）         │
└─────────────────────────────────────┘
           ↓ 使用
    ┌──────┴──────┬──────────┬───────────┐
    │             │          │           │
┌───▼────┐  ┌────▼─────┐  ┌─▼──────┐  ┌─▼──────┐
│压缩缓存 │  │图片优化   │  │DNS缓存  │  │其他...  │
└────────┘  └──────────┘  └────────┘  └────────┘
```

### 数据结构

```go
// 缓存项
type MemoryCacheItem struct {
    Data        []byte                 // 实际数据
    Metadata    map[string]interface{} // 元数据
    Size        int64                  // 大小
    CreatedAt   time.Time              // 创建时间
    ExpiresAt   time.Time              // 过期时间
    LastAccess  time.Time              // 最后访问
    AccessCount int64                  // 访问次数
}

// 缓存管理器
type MemoryCache struct {
    config    *MemoryCacheConfig
    cache     map[string]*MemoryCacheItem
    mutex     sync.RWMutex
    totalSize int64
    
    // 统计
    hits, misses, evictions, expired uint64
}
```

## 🚀 使用方法

### 1. 创建缓存实例

```go
import "github.com/xurenlu/sslcat/internal/cache"

// 方法 1：使用默认配置
compressionCache := cache.NewMemoryCache(
    cache.DefaultMemoryCacheConfig("compression"),
)

// 方法 2：自定义配置
imageCache := cache.NewMemoryCache(&cache.MemoryCacheConfig{
    Name:            "image_optimization",
    MaxEntries:      200,                    // 最多 200 个条目
    MaxSizeBytes:    500 * 1024 * 1024,      // 500MB
    MaxItemSize:     10 * 1024 * 1024,       // 单个最大 10MB
    DefaultTTL:      24 * time.Hour,         // 默认 24 小时过期
    CleanupInterval: 5 * time.Minute,        // 5 分钟清理一次
})
```

### 2. 基本操作

```go
// 设置缓存（使用默认 TTL）
err := cache.Set("my-key", data, 0)

// 设置缓存（自定义 TTL）
err := cache.Set("my-key", data, 1*time.Hour)

// 设置带元数据的缓存
metadata := map[string]interface{}{
    "content_type": "image/webp",
    "original_size": 1024000,
}
err := cache.SetWithMetadata("my-key", data, metadata, 1*time.Hour)

// 获取缓存
if item, ok := cache.Get("my-key"); ok {
    // 使用 item.Data
    contentType := item.Metadata["content_type"].(string)
}

// 删除缓存
cache.Delete("my-key")

// 清空所有
cache.Clear()
```

### 3. 统计信息

```go
stats := cache.Stats()
/*
{
    "name": "compression",
    "entries": 45,
    "max_entries": 100,
    "total_size": 52428800,      // 50MB
    "max_size": 104857600,        // 100MB
    "hits": 15234,
    "misses": 156,
    "hit_rate": "98.98%",
    "evictions": 23,              // 驱逐次数
    "expired": 12                 // 过期清理次数
}
*/
```

## 🔄 迁移现有缓存

### 1. 压缩缓存迁移

**之前** (`internal/web/compression_cache.go`):
```go
type CompressionCache struct {
    cache      map[string]*CachedCompressedData
    mutex      sync.RWMutex
    maxEntries int
    maxTotal   int64
    // ... 自定义逻辑
}
```

**之后** (使用统一缓存):
```go
type CompressionCache struct {
    memCache *cache.MemoryCache  // 使用统一缓存
    log      *logrus.Entry
}

func NewCompressionCache() *CompressionCache {
    return &CompressionCache{
        memCache: cache.NewMemoryCache(&cache.MemoryCacheConfig{
            Name:            "compression",
            MaxEntries:      100,
            MaxSizeBytes:    100 * 1024 * 1024,
            MaxItemSize:     5 * 1024 * 1024,
            DefaultTTL:      24 * time.Hour,
            CleanupInterval: 5 * time.Minute,
        }),
    }
}

func (c *CompressionCache) Get(filepath string, algorithm CompressionAlgorithm) ([]byte, bool) {
    key := fmt.Sprintf("%s:%s", filepath, algorithm)
    if item, ok := c.memCache.Get(key); ok {
        return item.Data, true
    }
    return nil, false
}

func (c *CompressionCache) Set(filepath string, algorithm CompressionAlgorithm, data []byte) {
    key := fmt.Sprintf("%s:%s", filepath, algorithm)
    metadata := map[string]interface{}{
        "algorithm": string(algorithm),
        "filepath":  filepath,
    }
    c.memCache.SetWithMetadata(key, data, metadata, 24*time.Hour)
}
```

### 2. 图片优化缓存迁移

**之前** (`internal/imageopt/optimizer.go`):
```go
type Optimizer struct {
    Config *Config
    cache  map[string]*CacheItem  // 自定义缓存
    mu     sync.RWMutex
    // ... 自定义清理逻辑
}
```

**之后**:
```go
type Optimizer struct {
    Config   *Config
    memCache *cache.MemoryCache  // 使用统一缓存
    log      *logrus.Entry
}

func NewOptimizer(config *Config) *Optimizer {
    return &Optimizer{
        Config: config,
        memCache: cache.NewMemoryCache(&cache.MemoryCacheConfig{
            Name:            "image_optimization",
            MaxEntries:      200,
            MaxSizeBytes:    1 * 1024 * 1024 * 1024, // 1GB
            MaxItemSize:     10 * 1024 * 1024,        // 10MB
            DefaultTTL:      time.Duration(config.CacheTTL) * time.Second,
            CleanupInterval: 5 * time.Minute,
        }),
    }
}
```

## 📊 配置建议

### 压缩缓存配置

```go
&cache.MemoryCacheConfig{
    Name:            "compression",
    MaxEntries:      100,               // 静态资源通常不多
    MaxSizeBytes:    100 * 1024 * 1024, // 100MB
    MaxItemSize:     5 * 1024 * 1024,   // 5MB（单个文件）
    DefaultTTL:      24 * time.Hour,    // 静态资源24小时
    CleanupInterval: 5 * time.Minute,
}
```

**理由**：
- 静态资源数量有限（JS、CSS 文件）
- 文件较大，但数量少
- 长 TTL，因为静态资源不变

### 图片优化缓存配置

```go
&cache.MemoryCacheConfig{
    Name:            "image_optimization",
    MaxEntries:      500,                    // 图片数量多
    MaxSizeBytes:    500 * 1024 * 1024,      // 500MB
    MaxItemSize:     10 * 1024 * 1024,       // 10MB
    DefaultTTL:      24 * time.Hour,         // 24小时
    CleanupInterval: 10 * time.Minute,       // 10分钟
}
```

**理由**：
- 图片数量多，需要更多条目
- 单个图片可能较大
- 访问频率高，需要更大缓存

### DNS 缓存配置

```go
&cache.MemoryCacheConfig{
    Name:            "dns",
    MaxEntries:      50,                // DNS 提供商少
    MaxSizeBytes:    10 * 1024 * 1024,  // 10MB
    MaxItemSize:     1 * 1024 * 1024,   // 1MB
    DefaultTTL:      5 * time.Minute,   // 5分钟（更新频繁）
    CleanupInterval: 1 * time.Minute,
}
```

**理由**：
- 数据量小
- 需要较短 TTL 以保持更新
- 频繁访问

## 🎯 优势总结

### 1. 统一管理

| 特性 | 之前 | 之后 |
|------|------|------|
| **TTL 支持** | 部分有 | ✅ 统一支持 |
| **过期清理** | 实现不同 | ✅ 统一自动清理 |
| **驱逐策略** | 不一致 | ✅ 统一 LRU |
| **统计信息** | 格式不同 | ✅ 统一格式 |
| **线程安全** | 各自实现 | ✅ 统一读写锁 |

### 2. 功能完整

```go
✅ TTL 过期管理 - 每个项可设置不同 TTL
✅ 自动清理 - 可配置清理间隔
✅ LRU 驱逐 - 容量满时自动驱逐最久未用
✅ 大小限制 - 总大小 + 单项大小双重限制
✅ 元数据支持 - 存储额外信息
✅ 统计完整 - 命中率、驱逐、过期等
✅ 线程安全 - 读写锁保证并发安全
```

### 3. 易于使用

```go
// 创建
cache := cache.NewMemoryCache(config)

// 使用
cache.Set("key", data, ttl)
item, ok := cache.Get("key")

// 统计
stats := cache.Stats()

// 清理
cache.Clear()
cache.Close()
```

## 🔍 监控

### API 端点（建议添加）

```go
// GET /sslcat-panel/api/cache/stats
{
  "caches": [
    {
      "name": "compression",
      "entries": 45,
      "total_size": 52428800,
      "hit_rate": "98.98%",
      "evictions": 23,
      "expired": 12
    },
    {
      "name": "image_optimization",
      "entries": 156,
      "total_size": 204800000,
      "hit_rate": "95.23%",
      "evictions": 89,
      "expired": 34
    }
  ]
}
```

### 日志监控

```bash
# 查看缓存活动
journalctl -u sslcat | grep "memory_cache"

# 示例输出
INFO memory_cache name=compression: Memory cache initialized
DEBUG memory_cache name=compression: Evicted item: key=xxx, size=1024000 bytes
INFO memory_cache name=compression: Cleaned up 12 expired items
```

## 📝 迁移清单

### 阶段 1：创建统一缓存（✅ 已完成）
- [x] 实现 `MemoryCache` 核心功能
- [x] TTL 支持
- [x] LRU 驱逐
- [x] 自动清理
- [x] 统计信息

### 阶段 2：迁移现有缓存（建议）
- [ ] 迁移 `CompressionCache`
- [ ] 迁移 `ImageOptimizer.cache`
- [ ] 迁移 `DNSCache`（可选）
- [ ] 添加统一的缓存统计 API

### 阶段 3：优化（可选）
- [ ] 添加持久化支持（可选）
- [ ] 添加分布式缓存支持（集群环境）
- [ ] 添加缓存预热功能

## 💡 最佳实践

### 1. 合理设置 TTL

```go
// 静态资源 - 长 TTL
staticCache.Set(key, data, 24*time.Hour)

// 动态数据 - 短 TTL
apiCache.Set(key, data, 5*time.Minute)

// 永久缓存 - 无 TTL
permanentCache.Set(key, data, 0)
```

### 2. 监控命中率

```go
stats := cache.Stats()
hitRate := stats["hit_rate"].(string)

// 如果命中率 < 80%，考虑：
// 1. 增加缓存大小
// 2. 延长 TTL
// 3. 增加条目数
```

### 3. 处理缓存穿透

```go
// 使用布隆过滤器或空值缓存
if item, ok := cache.Get(key); !ok {
    data := fetchFromSource(key)
    if data == nil {
        // 缓存空值，避免穿透
        cache.Set(key, []byte("NULL"), 1*time.Minute)
    } else {
        cache.Set(key, data, ttl)
    }
}
```

## 🎉 总结

通过统一的内存缓存管理器：

1. ✅ **代码更简洁** - 不需要每个模块自己实现缓存逻辑
2. ✅ **行为一致** - 所有缓存都有相同的 TTL、驱逐、清理行为
3. ✅ **易于维护** - 缓存逻辑集中在一个地方
4. ✅ **统计统一** - 便于监控和调试
5. ✅ **性能更好** - 优化的 LRU 和清理策略

**建议**：逐步迁移现有缓存到统一管理器，优先迁移 `CompressionCache` 和 `ImageOptimizer.cache`。


# 漏斗算法和WebP转换内存泄漏分析

## 问题概述

分析两个潜在的内存暴增风险：
1. **漏斗算法统计高流量的 UA、IP 等**
2. **自动转 WebP 功能**

---

## 🔴 问题 1: 漏斗算法内存泄漏风险

### 当前实现分析

#### 数据结构
```go
// Collector 统计数据收集器
type Collector struct {
    // 实时数据缓存
    ipEntries   map[string]*FunnelEntry   // ⚠️ 无界 map
    uaEntries   map[string]*FunnelEntry   // ⚠️ 无界 map
    cityEntries map[string]*FunnelEntry   // ⚠️ 无界 map
    
    // 域名统计缓存
    domainStats map[string]map[TimeDimension]map[string]*RequestStats  // ⚠️ 三层嵌套 map
    
    // 内存泄漏防护（已有但不够）
    maxIPEntries   int  // 1000
    maxUAEntries   int  // 500
    maxCityEntries int  // 200
    maxDomainStats int  // 100
}
```

### 🚨 严重问题

#### 1. **高流量场景下的内存暴增**

**场景 A: DDoS 攻击或爬虫**
```
假设：每秒 10,000 个请求，每个请求不同 IP
- 1 分钟：600,000 个唯一 IP
- 每个 FunnelEntry 约 100 bytes
- 内存占用：600,000 * 100 = 60 MB（仅 IP）
- 加上 UA、City：180 MB/分钟

当前限制：maxIPEntries = 1000（远远不够！）
```

**场景 B: 正常高流量网站**
```
假设：每天 1,000,000 访问，50,000 唯一 IP
- 当前 maxIPEntries = 1000
- 但清理间隔是 1 小时
- 在清理前，map 可能增长到数万条
```

#### 2. **RecordAccess 函数无限制增长**

```go
// RecordAccess 记录访问数据
func (c *Collector) RecordAccess(record *AccessRecord) {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    // ⚠️ 问题：每次请求都会调用，没有速率限制
    c.ipFunnel.UpdateEntry(c.ipEntries, record.IP, now)
    c.uaFunnel.UpdateEntry(c.uaEntries, record.UserAgent, now)
    
    // ⚠️ 问题：UpdateEntry 会无限添加新条目
    if entry, exists := entries[key]; exists {
        entry.Count++
        entry.LastSeen = timestamp
    } else {
        entries[key] = &FunnelEntry{  // 新条目，无限增长！
            Key:       key,
            Count:     1,
            FirstSeen: timestamp,
            LastSeen:  timestamp,
        }
    }
}
```

#### 3. **domainStats 三层嵌套 map 爆炸**

```go
// 三层嵌套结构
domainStats[domain][dimension][timeKey] = &RequestStats{}

// 问题：
// - 每个域名 * 3 个维度 (hour/day/month) * N 个时间键
// - 假设 100 个域名，运行 30 天：
//   - Hour: 100 * 30 * 24 = 72,000 条
//   - Day:  100 * 30 = 3,000 条
//   - Month: 100 * 1 = 100 条
//   总计：75,100 个 RequestStats 对象
```

#### 4. **清理机制不足**

```go
// 当前清理逻辑
func (c *Collector) cleanup() {
    // 只清理过期数据（30天）
    c.ipFunnel.CleanupOldEntries(c.ipEntries, c.maxDataAge, now)
    
    // ⚠️ 问题：
    // 1. 清理间隔太长（1小时）
    // 2. 只基于时间，不基于数量
    // 3. 高流量时，1小时内可能积累数十万条目
    // 4. limitDataGrowth 只在超限后才触发
}
```

### 💥 内存暴增场景

**真实场景：高流量 API**
```
时间线：
00:00 - 服务启动，内存 100 MB
01:00 - 正常流量，收集 5,000 IP，内存 120 MB
02:00 - 流量高峰，收集 50,000 IP，内存 500 MB
02:30 - DDoS 攻击开始，每秒 10,000 请求
02:35 - 收集 300,000 IP，内存 2 GB
02:40 - 收集 600,000 IP，内存 4 GB
02:45 - OOM Killed！
```

---

## 🔴 问题 2: WebP 转换内存泄漏风险

### 当前实现分析

#### 配置
```go
type Config struct {
    MinSizeBytes int64  // 60KB - 最小文件
    MaxSizeBytes int64  // 5MB - 最大文件
    MaxCacheSize int64  // 1GB - 缓存大小
    CacheEnabled bool
}
```

### 🚨 严重问题

#### 1. **图片解码内存峰值**

```go
func (o *Optimizer) optimize(data []byte, sourceFormat ImageFormat, ...) {
    // ⚠️ 问题：解码会占用大量内存
    img, err := o.decodeImage(data, sourceFormat)  // 内存峰值！
    
    // 例子：5MB JPEG 图片
    // - 原始数据：5 MB
    // - 解码后（4000x3000 RGB）：4000 * 3000 * 3 = 36 MB
    // - 峰值内存：5 + 36 = 41 MB（单张图片）
}
```

#### 2. **并发请求内存爆炸**

```go
// 场景：100 个并发图片请求
// - 每个图片 5MB，解码后 36MB
// - 总内存峰值：100 * 41 MB = 4.1 GB
// - 加上缓存：4.1 GB + 1 GB = 5.1 GB

// ⚠️ 问题：没有并发限制！
func (o *Optimizer) OptimizeResponse(originalData []byte, ...) {
    // 每个请求都会立即处理，没有队列或限流
    img, err := o.decodeImage(data, sourceFormat)
}
```

#### 3. **缓存驱逐不及时**

```go
// 缓存配置
MaxCacheSize: 1GB
CleanupInterval: 10 * time.Minute  // ⚠️ 10分钟才清理一次

// 问题：
// - 高流量时，10分钟内可能缓存数千张图片
// - 缓存可能超过 1GB 限制，才触发驱逐
// - 驱逐过程本身也消耗内存
```

#### 4. **大图片没有尺寸限制**

```go
// 当前限制
MaxSizeBytes: 5 * 1024 * 1024  // 5MB 文件大小

// ⚠️ 问题：文件大小 ≠ 解码后大小
// 例子：
// - 5MB JPEG (4000x3000) → 36 MB 解码
// - 5MB PNG (8000x6000) → 144 MB 解码
// - 没有像素尺寸限制！
```

#### 5. **异步缓存可能失败**

```go
// 异步缓存
if o.Config.CacheEnabled && o.memCache != nil {
    go func() {
        o.memCache.Set(cacheKey, optimizedData, ...)
    }()
}

// ⚠️ 问题：
// - 异步 goroutine 可能积累
// - 没有 goroutine 数量限制
// - 缓存失败时没有重试或清理
```

---

## 🛠️ 修复方案

### 方案 1: 漏斗算法优化

#### 1.1 添加实时大小检查和限制

```go
// UpdateEntry 添加大小检查
func (fm *FunnelModel) UpdateEntry(entries map[string]*FunnelEntry, key string, timestamp time.Time, maxEntries int) bool {
    // 检查是否已存在
    if entry, exists := entries[key]; exists {
        entry.Count++
        entry.LastSeen = timestamp
        return true
    }
    
    // ⚠️ 新增：检查是否超过限制
    if len(entries) >= maxEntries {
        // 拒绝新条目，或删除最旧的
        return false
    }
    
    entries[key] = &FunnelEntry{
        Key:       key,
        Count:     1,
        FirstSeen: timestamp,
        LastSeen:  timestamp,
    }
    return true
}
```

#### 1.2 添加采样机制

```go
type Collector struct {
    // 新增：采样配置
    samplingRate float64  // 采样率（0.0-1.0）
    samplingCounter uint64
}

func (c *Collector) RecordAccess(record *AccessRecord) {
    if !c.enabled {
        return
    }
    
    // ⚠️ 新增：高流量时启用采样
    if c.shouldSample() {
        c.mu.Lock()
        defer c.mu.Unlock()
        
        c.ipFunnel.UpdateEntry(c.ipEntries, record.IP, now, c.maxIPEntries)
        c.uaFunnel.UpdateEntry(c.uaEntries, record.UserAgent, now, c.maxUAEntries)
        // ...
    }
}

func (c *Collector) shouldSample() bool {
    // 动态采样：当条目数接近限制时，降低采样率
    c.mu.RLock()
    ipCount := len(c.ipEntries)
    c.mu.RUnlock()
    
    if ipCount < c.maxIPEntries/2 {
        return true  // 未达到一半，全部记录
    }
    
    if ipCount >= c.maxIPEntries*9/10 {
        // 接近限制，采样 10%
        c.samplingCounter++
        return c.samplingCounter%10 == 0
    }
    
    // 中间状态，采样 50%
    c.samplingCounter++
    return c.samplingCounter%2 == 0
}
```

#### 1.3 缩短清理间隔

```go
// 当前：1小时清理一次
cleanupInterval: 1 * time.Hour

// 修改为：5分钟清理一次
cleanupInterval: 5 * time.Minute
```

#### 1.4 优化 domainStats 存储

```go
// 添加 domainStats 清理逻辑
func (c *Collector) cleanupDomainStats(now time.Time) {
    for domain, dimStats := range c.domainStats {
        for dim, timeStats := range dimStats {
            for timeKey, stats := range timeStats {
                // 根据维度清理过期数据
                var maxAge time.Duration
                switch dim {
                case DimensionHour:
                    maxAge = 7 * 24 * time.Hour  // 保留 7 天的小时数据
                case DimensionDay:
                    maxAge = 90 * 24 * time.Hour  // 保留 90 天的日数据
                case DimensionMonth:
                    maxAge = 365 * 24 * time.Hour  // 保留 1 年的月数据
                }
                
                // 解析 timeKey 并检查是否过期
                t, err := c.parseTimeKey(timeKey, dim)
                if err != nil || now.Sub(t) > maxAge {
                    delete(timeStats, timeKey)
                }
            }
            
            // 如果维度下没有数据了，删除维度
            if len(timeStats) == 0 {
                delete(dimStats, dim)
            }
        }
        
        // 如果域名下没有数据了，删除域名
        if len(dimStats) == 0 {
            delete(c.domainStats, domain)
        }
    }
}
```

### 方案 2: WebP 转换优化

#### 2.1 添加并发限制

```go
type Optimizer struct {
    Config   *Config
    memCache *cache.MemoryCache
    log      *logrus.Entry
    
    // ⚠️ 新增：并发控制
    concurrencySem chan struct{}  // 信号量
    maxConcurrent  int             // 最大并发数
}

func NewOptimizer(config *Config) *Optimizer {
    opt := &Optimizer{
        // ...
        maxConcurrent:  10,  // 最多 10 个并发转换
        concurrencySem: make(chan struct{}, 10),
    }
    return opt
}

func (o *Optimizer) OptimizeResponse(originalData []byte, ...) ([]byte, string, error) {
    // 获取信号量
    select {
    case o.concurrencySem <- struct{}{}:
        defer func() { <-o.concurrencySem }()
    default:
        // 并发已满，直接返回原图
        o.log.Warn("Image optimization concurrency limit reached, returning original")
        return originalData, contentType, nil
    }
    
    // 执行优化
    // ...
}
```

#### 2.2 添加像素尺寸限制

```go
type Config struct {
    // 新增：像素尺寸限制
    MaxPixels int64  // 最大像素数（宽*高）
}

func DefaultConfig() *Config {
    return &Config{
        // ...
        MaxPixels: 4000 * 3000,  // 1200万像素
    }
}

func (o *Optimizer) optimize(data []byte, ...) ([]byte, string, error) {
    // 解码前检查图片尺寸
    config, format, err := image.DecodeConfig(bytes.NewReader(data))
    if err != nil {
        return nil, "", err
    }
    
    // ⚠️ 新增：检查像素数
    pixels := int64(config.Width) * int64(config.Height)
    if o.Config.MaxPixels > 0 && pixels > o.Config.MaxPixels {
        o.log.Warnf("Image too large: %dx%d (%d pixels, max: %d), skipping",
            config.Width, config.Height, pixels, o.Config.MaxPixels)
        return data, contentTypeFromFormat(sourceFormat), nil
    }
    
    // 解码图片
    img, err := o.decodeImage(data, sourceFormat)
    // ...
}
```

#### 2.3 优化缓存策略

```go
// 缩短清理间隔
CleanupInterval: 2 * time.Minute  // 从 10 分钟改为 2 分钟

// 降低缓存大小
MaxCacheSize: 512 * 1024 * 1024  // 从 1GB 改为 512MB

// 降低单个缓存项大小
MaxItemSize: 5 * 1024 * 1024  // 从 10MB 改为 5MB
```

#### 2.4 添加内存监控

```go
type Optimizer struct {
    // ...
    
    // 新增：内存监控
    currentMemoryUsage int64
    maxMemoryUsage     int64
}

func (o *Optimizer) OptimizeResponse(originalData []byte, ...) ([]byte, string, error) {
    // 估算内存使用
    estimatedMemory := int64(len(originalData)) * 8  // 估算解码后大小
    
    // 检查内存限制
    if atomic.LoadInt64(&o.currentMemoryUsage)+estimatedMemory > o.maxMemoryUsage {
        o.log.Warn("Memory limit reached, skipping image optimization")
        return originalData, contentType, nil
    }
    
    // 增加内存计数
    atomic.AddInt64(&o.currentMemoryUsage, estimatedMemory)
    defer atomic.AddInt64(&o.currentMemoryUsage, -estimatedMemory)
    
    // 执行优化
    // ...
}
```

---

## 📊 预期效果

### 漏斗算法优化后

| 场景 | 优化前 | 优化后 |
|------|--------|--------|
| 正常流量（1000 req/s） | 120 MB | 80 MB |
| 高流量（10000 req/s） | 2 GB | 200 MB |
| DDoS 攻击（50000 req/s） | OOM (4GB+) | 300 MB |
| 长期运行（30天） | 1.5 GB | 150 MB |

### WebP 转换优化后

| 场景 | 优化前 | 优化后 |
|------|--------|--------|
| 单个大图转换 | 41 MB | 41 MB |
| 100 并发请求 | 4.1 GB | 410 MB |
| 缓存占用 | 1 GB | 512 MB |
| 超大图片（8000x6000） | 144 MB | 跳过转换 |

---

## 🎯 实施优先级

### P0 - 立即修复（内存暴增风险）
1. ✅ 漏斗算法添加实时大小检查
2. ✅ WebP 添加并发限制
3. ✅ WebP 添加像素尺寸限制

### P1 - 高优先级（性能优化）
4. ✅ 漏斗算法添加采样机制
5. ✅ 缩短清理间隔
6. ✅ 优化 domainStats 清理

### P2 - 中优先级（监控和告警）
7. ⬜ 添加内存监控和告警
8. ⬜ 添加性能指标收集

---

## 🚀 部署建议

1. **分阶段部署**
   - 第一阶段：部署 P0 修复（并发限制、大小检查）
   - 第二阶段：部署 P1 优化（采样、清理）
   - 第三阶段：部署 P2 监控

2. **配置建议**
   ```yaml
   statistics:
     enabled: true
     max_ip_entries: 5000      # 从 1000 提升到 5000
     max_ua_entries: 2000      # 从 500 提升到 2000
     cleanup_interval: 5m      # 从 1h 缩短到 5m
     sampling_enabled: true    # 启用采样
   
   image_optimization:
     enabled: true
     max_concurrent: 10        # 最大并发转换
     max_pixels: 12000000      # 1200万像素
     max_size_bytes: 5242880   # 5MB
     cache_size: 536870912     # 512MB
     cleanup_interval: 2m      # 2分钟清理
   ```

3. **监控指标**
   - 漏斗算法：ipEntries、uaEntries、cityEntries 的大小
   - WebP 转换：并发数、内存使用、缓存命中率
   - 系统：总内存使用、GC 频率

---

## ✅ 总结

**两个功能都存在严重的内存泄漏风险，必须立即修复！**

- **漏斗算法**：高流量下会导致 map 无限增长，可能在几分钟内耗尽内存
- **WebP 转换**：并发请求会导致内存峰值暴增，大图片可能占用数百 MB

修复后，系统可以安全处理高流量场景，内存使用可控。


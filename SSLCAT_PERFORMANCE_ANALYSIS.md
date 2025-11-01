# SSLcat 性能分析报告

**分析时间**: 2025-01-XX  
**服务器**: shifen.de  
**当前状态**:
- **内存占用**: 1.34 GB RSS (8.6% 系统内存)
- **CPU 占用**: 1.9% (累计 27分钟)
- **运行时间**: 23小时44分

## 📊 问题概述

作为 Web Server，sslcat 的内存和 CPU 占用相对较高。以下是详细分析：

## 🔴 主要问题原因

### 1. 内存占用分析 (1.34 GB)

#### 1.1 BigCache 内存预分配

**问题**:
- BigCache 使用 32 个分片（shards）
- 每个分片都会预分配内存空间
- 即使缓存未满，也会占用大量内存

**当前配置** (`internal/cache/memory_cache.go:76`):
```go
bigCacheConfig.Shards = 32                    // 32个分片
bigCacheConfig.MaxEntriesInWindow = config.MaxEntries * 2  // 窗口大小
bigCacheConfig.HardMaxCacheSize = int(config.MaxSizeBytes / (1024 * 1024)) // MB
```

**内存占用估算**:
- 压缩缓存：25MB 配置 × 32 分片 ≈ 800KB-1MB 开销
- 图片缓存：256MB 配置 × 32 分片 ≈ 8MB 开销
- 默认缓存：25MB 配置 × 32 分片 ≈ 800KB-1MB 开销
- **总计**: 每个缓存实例约 10-50MB 预分配内存

**影响**: 多个缓存实例 × BigCache 内部开销 ≈ **100-200MB**

#### 1.2 多个内存缓存实例

**当前缓存实例**:
1. **压缩缓存** (`internal/web/server.go:133`):
   - 200 条目，每个最大 2MB，总计 50MB
   - 使用 BigCache，32 分片

2. **图片优化缓存** (`internal/imageopt/optimizer.go:82`):
   - 最大 256MB
   - 使用 BigCache，32 分片

3. **默认内存缓存** (`internal/cache/memory_cache.go:47`):
   - 1000 条目，25MB 总大小
   - 使用 BigCache，32 分片

4. **CDN 缓存** (磁盘缓存，但需要内存管理):
   - 虽然未启用，但代码仍然加载

**内存占用**: 约 **300-400MB** (实际使用 + 预分配)

#### 1.3 41 个定时器叠加

**问题** (`TIMER_ANALYSIS.md`):
- 41 个 `time.NewTicker` 实例
- 分布在 35 个文件中
- 可能同时触发导致内存峰值

**典型场景**:
```
4:18:00.000 - 缓存清理（遍历大量缓存项）
4:18:00.100 - 内存监控（收集统计）
4:18:00.200 - Goroutine 监控（收集堆栈）
4:18:00.300 - 会话清理
4:18:00.400 - 统计清理
```

**影响**:
- 临时对象分配: **100-300MB**
- Goroutine 栈内存: **10-50MB**
- GC 压力导致内存峰值

#### 1.4 Go 运行时内存管理

**当前配置** (`/etc/systemd/system/sslcat.service`):
```ini
GOMEMLIMIT=800MiB
GOGC=100
GODEBUG=madvdontneed=1
```

**问题**:
- `GOMEMLIMIT=800MiB` 但实际 RSS 是 **1.34GB**
- 说明超过了限制，或者虚拟内存占用高
- Go 运行时可能保留了大量空闲内存

**分析**:
- **堆内存**: ~300-500MB (实际使用)
- **空闲堆内存**: ~300-500MB (Go 运行时保留)
- **栈内存**: ~50-100MB (goroutine 栈)
- **其他**: ~200-400MB (系统库、TLS 连接等)

### 2. CPU 占用分析

#### 2.1 定时器执行开销

**高频定时器**:
- 内存监控：1分钟
- Goroutine 监控：61秒
- 性能监控：31秒
- CDN 缓存清理：53秒
- 健康检查：60秒
- 其他：30-60秒间隔

**问题**:
- 定时器执行时需要进行锁竞争
- 大量 map 遍历操作
- JSON 序列化/反序列化

**CPU 占用估算**:
- 定时器执行: **0.5-1%**
- 缓存操作: **0.5-1%**
- 其他: **0.5-1%**

#### 2.2 锁竞争开销

**问题**:
- 多个定时器可能同时访问共享数据结构
- BigCache 分片锁竞争
- Map 读写锁竞争

**影响**: 轻微但持续的 CPU 开销

#### 2.3 HTTP 请求处理

**当前状态**: CPU 使用率低（1.9%），说明请求量不大

### 3. 虚拟内存占用高 (3.76 GB)

**问题**:
- RSS: 1.34 GB
- VSZ: 3.76 GB
- **差异**: 2.42 GB

**可能原因**:
1. **内存映射文件** (mmap)
2. **大块内存预分配** (BigCache)
3. **Go 运行时内存碎片**
4. **TLS 连接缓冲**

## 🎯 优化建议

### 优先级 1: 减少 BigCache 分片数 ⭐⭐⭐

**修改位置**: `internal/cache/memory_cache.go:76`

```go
// 优化前
bigCacheConfig.Shards = 32

// 优化后
bigCacheConfig.Shards = 16  // 减少到16个分片
```

**预期效果**: 减少 **50-100MB** 内存占用

### 优先级 2: 降低缓存大小 ⭐⭐⭐

**修改位置**: `internal/imageopt/optimizer.go:82`

```go
// 优化前
MaxCacheSize: 256 * 1024 * 1024, // 256MB

// 优化后
MaxCacheSize: 128 * 1024 * 1024, // 128MB (减少50%)
```

**预期效果**: 减少 **100-150MB** 内存占用

### 优先级 3: 优化定时器间隔 ⭐⭐

**当前状态**: 已使用质数间隔避免叠加

**建议**: 进一步优化定时器执行时间，错峰执行

### 优先级 4: 调整 GOMEMLIMIT ⭐⭐

**当前配置**: `GOMEMLIMIT=800MiB`

**建议**: 
- 如果内存充足，可以提高到 `1.2GiB`
- 如果内存紧张，降低到 `600MiB` 并监控性能

**权衡**:
- 提高: 减少 GC 频率，但可能占用更多内存
- 降低: 更多 GC，但内存使用更可控

### 优先级 5: 减少压缩缓存大小 ⭐

**修改位置**: `internal/web/server.go:133`

```go
// 优化前
compressionCache := NewCompressionCache(200, 2, 50)

// 优化后
compressionCache := NewCompressionCache(100, 1, 25)  // 减少50%
```

**预期效果**: 减少 **20-30MB** 内存占用

## 📈 预期优化效果

| 优化项 | 当前 | 优化后 | 节省 |
|--------|------|--------|------|
| BigCache 分片 | 32 | 16 | 50-100MB |
| 图片缓存 | 256MB | 128MB | 100-150MB |
| 压缩缓存 | 50MB | 25MB | 20-30MB |
| **总计** | **1.34GB** | **~1.0GB** | **~300MB** |

**目标**: 内存占用从 **1.34GB** 降至 **~1.0GB** (约 **25%** 降低)

## 🔍 进一步诊断建议

### 1. 启用 pprof 分析

```bash
# 在配置文件中启用
"server": {
  "enable_pprof": true
}

# 然后访问
curl http://localhost:8080/debug/pprof/heap
```

### 2. 检查 Goroutine 数量

```bash
curl http://localhost:8080/debug/pprof/goroutine?debug=1 | grep -c "goroutine"
```

### 3. 监控内存趋势

```bash
# 每30秒记录一次
watch -n 30 'ps -o pid,%mem,rss,vsz -p $(pgrep sslcat)'
```

## ✅ 总结

**主要问题**:
1. ✅ BigCache 分片数过多（32 → 16）
2. ✅ 图片缓存配置过大（256MB → 128MB）
3. ✅ 多个缓存实例叠加占用
4. ✅ 定时器叠加导致临时内存峰值

**优化预期**:
- 内存占用: **1.34GB → ~1.0GB** (降低 25%)
- CPU 占用: 基本不变（当前已很低）
- 性能影响: 轻微（缓存命中率可能略微下降）

**建议**: 优先实施 **优先级 1-2** 的优化，这些改动风险低、收益高。


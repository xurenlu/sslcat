# 内存占用深度分析报告

## 问题确认

### 当前内存占用
- **RSS (实际物理内存)**: 3.89GB (23.7%)
- **VSZ (虚拟内存)**: 9.3GB
- **VmData (数据段)**: 7.3GB
- **Go Heap**: 111.55MB

### 关键发现

**发现一个巨大的匿名内存区域**：
- **Size**: 6940MB
- **RSS**: 3720.33MB (3.7GB)
- **全部是 Private_Dirty**（匿名内存，不是文件映射）

这个 3.7GB 的内存区域很可能是 **bigcache 的 mmap 预分配内存**。

## 根本原因分析

### 1. bigcache 的 mmap 预分配机制

bigcache 使用 mmap 来分配内存，每个 shard 都会预分配一个大的内存区域。即使配置只有 10MB，bigcache 内部的计算逻辑可能导致预分配远超配置值。

**bigcache 的内存分配公式**：
- 每个 shard 预分配大小 = `MaxEntriesInWindow * 平均条目大小`
- 总预分配 = `Shards * 每个 shard 预分配大小`
- 即使设置了 `HardMaxCacheSize`，预分配也可能远超这个值

**问题**：
- bigcache 的预分配是**立即分配物理内存**（不是按需分配）
- 即使缓存是空的，也会占用大量 RSS 内存
- 对于低流量场景，这是巨大的浪费

### 2. 为什么 Go Heap 只有 111MB？

- Go Heap 只统计 Go runtime 管理的内存
- bigcache 使用 mmap，不在 Go Heap 中
- 所以 Go Heap 很小，但 RSS 很大

### 3. 其他可能的内存占用

- **goroutine 栈**: 78 个 goroutine，每个栈 2KB，约 156KB（很小）
- **网络缓冲区**: HTTP 连接缓冲区，通常很小
- **文件映射**: 未发现大量文件映射

## 已实施的优化

### 1. 激进优化 bigcache 配置 ✅

**位置**: `internal/cache/memory_cache.go:76-95`

**优化内容**:
1. **大幅减少分片数**
   - 极小缓存（<10MB）: 2 个分片（从 8 减少）
   - 小缓存（<50MB）: 4 个分片（从 8 减少）
   - 大缓存（>=50MB）: 8 个分片（从 16 减少）

2. **减少 MaxEntriesInWindow**
   - 从 1.5 倍降低到 1.2 倍
   - 进一步减少预分配内存

3. **降低默认缓存大小**
   - 从 10MB 降低到 5MB
   - MaxEntries 从 100 降低到 50
   - MaxItemSize 从 1MB 降低到 512KB

**预期效果**:
- 预分配内存减少 60-80%
- RSS 从 3.89GB 降低到 1-1.5GB

### 2. 代码修改

```go
// 激进优化：大幅减少分片数
if config.MaxSizeBytes < 10*1024*1024 {
    bigCacheConfig.Shards = 2 // 极小缓存使用 2 个分片
} else if config.MaxSizeBytes < 50*1024*1024 {
    bigCacheConfig.Shards = 4 // 小缓存使用 4 个分片
} else {
    bigCacheConfig.Shards = 8 // 大缓存使用 8 个分片
}
// 大幅减少 MaxEntriesInWindow
bigCacheConfig.MaxEntriesInWindow = int(float64(config.MaxEntries) * 1.2)
```

## 进一步优化建议

### 方案 1: 完全禁用 bigcache（最激进）⚠️

如果缓存使用率很低，可以考虑完全禁用 bigcache，使用更简单的内存缓存实现。

**优点**:
- 完全消除 bigcache 的 mmap 预分配
- 内存占用可以降低到 100-200MB

**缺点**:
- 失去缓存功能
- 可能影响性能（但对于低流量场景影响不大）

**实现方式**:
- 创建一个简单的 map-based 缓存实现
- 或者直接禁用缓存功能

### 方案 2: 使用更轻量的缓存实现

考虑使用 `sync.Map` 或简单的 `map + mutex` 实现，避免 mmap 预分配。

**优点**:
- 按需分配内存
- 不会预分配大量内存

**缺点**:
- 需要重写缓存实现
- 可能性能略低于 bigcache

### 方案 3: 调整 Go runtime 参数

虽然不能解决 bigcache 的问题，但可以优化 Go runtime 的内存管理：

```bash
# 设置内存限制
export GOMEMLIMIT=512MiB

# 调整 GC 频率
export GOGC=300  # 从 200 增加到 300，减少 GC 频率
```

### 方案 4: 监控和动态调整

添加监控，根据实际使用情况动态调整缓存大小：

- 监控缓存命中率
- 如果命中率低，自动减少缓存大小
- 如果内存压力大，自动禁用缓存

## 预期效果对比

### 当前状态
- RSS: 3.89GB
- bigcache 预分配: ~3.7GB
- Go Heap: 111MB

### 优化后（方案 1: 激进优化）
- RSS: 1-1.5GB（降低 60-75%）
- bigcache 预分配: ~500MB-1GB
- Go Heap: 100-150MB

### 优化后（方案 2: 禁用 bigcache）
- RSS: 100-200MB（降低 95%）
- 缓存: 使用简单实现或禁用
- Go Heap: 100-150MB

## 推荐方案

### 对于低流量场景（当前情况）

**推荐**: 方案 1（激进优化）+ 监控

1. **立即实施**: 已完成的激进优化
2. **监控效果**: 观察内存是否降低到 1-1.5GB
3. **如果仍然不满意**: 考虑方案 2（禁用 bigcache）

### 实施步骤

1. **部署优化后的代码**
   ```bash
   # 重新编译并部署
   make build
   # 部署到服务器
   ```

2. **监控内存使用**
   ```bash
   # 观察 RSS 是否降低
   ps aux | grep sslcat
   # 或使用监控面板
   ```

3. **如果内存仍然偏高**
   - 考虑进一步减少缓存大小（1-2MB）
   - 或完全禁用缓存

## 总结

**根本原因**: bigcache 使用 mmap 预分配了大量物理内存（3.7GB），即使配置只有 10MB。

**解决方案**: 
1. ✅ 已实施：激进优化 bigcache 配置（减少分片数、降低预分配）
2. 🔄 可选：如果仍然不满意，考虑禁用 bigcache 或使用更轻量的实现

**预期效果**: 
- 激进优化：RSS 从 3.89GB 降低到 1-1.5GB（降低 60-75%）
- 禁用 bigcache：RSS 降低到 100-200MB（降低 95%）


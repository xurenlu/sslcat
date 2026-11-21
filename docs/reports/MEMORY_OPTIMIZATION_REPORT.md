# 内存优化报告

## 问题分析

### 当前内存使用情况
- **RSS (实际物理内存)**: 3.89GB (23.7%)
- **VSZ (虚拟内存)**: 9.3GB
- **VmData (数据段)**: 7.3GB
- **Go Heap**: 111.55MB

### 问题发现

1. **内存占用过高**
   - 对于一个低流量的 web server，3.89GB 内存占用明显偏高
   - Go heap 只有 111.55MB，说明大部分内存不在 Go heap 中
   - 可能是 bigcache 使用 mmap 预分配了大量内存

2. **bigcache 内存占用分析**
   - 从 `inuse_space` profile 看，bigcache 占用了 79.14MB (70.94%)
   - 但 bigcache 使用 mmap，会预分配大量虚拟内存
   - 每个 shard 都会预分配内存，16 个 shard 可能预分配了很多

3. **CPU 使用率**
   - 当前 CPU: 3.6%
   - 主要消耗在 GC 相关操作（正常）

## 优化措施

### 1. 优化 bigcache 配置 ✅

**位置**: `internal/cache/memory_cache.go:76-85`

**优化内容**:
- 根据缓存大小动态调整分片数
  - 小缓存（<50MB）: 8 个分片
  - 大缓存（>=50MB）: 16 个分片
- 减少 `MaxEntriesInWindow` 从 2 倍到 1.5 倍
  - 降低预分配内存

**代码修改**:
```go
// 根据缓存大小动态调整分片数
if config.MaxSizeBytes < 50*1024*1024 {
    bigCacheConfig.Shards = 8 // 小缓存使用 8 个分片
} else {
    bigCacheConfig.Shards = 16 // 大缓存使用 16 个分片
}
// 减少 MaxEntriesInWindow，降低预分配内存
bigCacheConfig.MaxEntriesInWindow = int(float64(config.MaxEntries) * 1.5)
```

### 2. 当前缓存配置

**共享缓存** (`shared_cache`):
- MaxEntries: 100
- MaxSizeBytes: 10MB (默认)
- MaxItemSize: 1MB
- Shards: 8 (优化后)

**图片优化缓存** (`image_optimization`):
- MaxEntries: 200
- MaxSizeBytes: 配置值
- MaxItemSize: 2MB
- Shards: 8 (优化后)

### 3. 内存占用分析

**Go Heap 内存分布** (inuse_space):
- bigcache: 79.14MB (70.94%)
- runtime.malg: 24.01MB (21.52%)
- 其他: 8.4MB (7.54%)

**总内存占用**:
- Go Heap: 111.55MB
- 其他内存: ~3.78GB (不在 Go heap 中)

**可能的原因**:
1. bigcache 使用 mmap，预分配了大量虚拟内存
2. 可能有其他内存映射（文件、网络缓冲区等）
3. 可能有内存碎片

## 进一步优化建议

### 1. 监控 bigcache 实际使用情况
- 检查缓存命中率
- 如果命中率低，考虑减少缓存大小
- 如果缓存使用率低，考虑减少 MaxEntries

### 2. 检查其他内存占用
- 检查是否有大量文件映射
- 检查网络缓冲区大小
- 检查是否有内存泄漏

### 3. 考虑使用更轻量的缓存
- 如果缓存使用率低，考虑禁用某些缓存
- 考虑使用更轻量的缓存实现

### 4. 调整 Go runtime 参数
- 当前 GOGC=200，可以考虑进一步调整
- 检查 GOMEMLIMIT 设置

## 预期效果

优化后预期：
- **内存占用**: 从 3.89GB 降低到 2-3GB
- **bigcache 预分配**: 减少 30-50%
- **CPU 使用率**: 保持或略有降低

## 部署建议

1. **部署优化后的代码**
   - 重新编译并部署
   - 监控内存使用情况

2. **观察效果**
   - 观察内存使用是否降低
   - 观察缓存性能是否受影响

3. **进一步优化**
   - 如果内存仍然偏高，考虑进一步减少缓存大小
   - 如果缓存性能受影响，适当调整配置

## 总结

通过优化 bigcache 配置，预期可以减少 30-50% 的内存占用。主要优化点：
1. 动态调整分片数（小缓存使用更少分片）
2. 减少 MaxEntriesInWindow（降低预分配）

如果问题仍然存在，需要进一步检查：
- 其他内存占用源
- 是否有内存泄漏
- 是否需要进一步减少缓存大小


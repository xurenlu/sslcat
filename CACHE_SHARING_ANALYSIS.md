# 压缩缓存与图片优化缓存共用 BigCache 方案分析

## 📊 当前状态

### 压缩缓存 (`CompressionCache`)
- **配置**: 200条目，每个2MB，总计50MB
- **键格式**: `filepath:algorithm` (例如: `/static/js/app.js:gzip`)
- **清理间隔**: 5分钟
- **TTL**: 24小时

### 图片优化缓存 (`ImageOptimizer`)
- **配置**: 200条目，每个2MB，总计256MB
- **键格式**: `path_w{width}_h{height}_q{quality}_f{format}` (例如: `/images/photo.jpg_w800_h600_q80_f_webp`)
- **清理间隔**: 1分钟
- **TTL**: 24小时（可配置）

## ✅ 共用可行性分析

### 技术可行性：✅ **可以共用**

**理由**：
1. ✅ 两者都使用 `MemoryCache`，底层都是 BigCache
2. ✅ 键格式不同，不会冲突：
   - 压缩缓存：使用 `:` 分隔符 (`filepath:algorithm`)
   - 图片缓存：使用 `_` 分隔符 (`path_w..._h..._q..._f...`)
3. ✅ BigCache 支持任意键格式，只要有唯一性即可

### 潜在问题：⚠️ **需要注意**

1. **清理策略不同**
   - 压缩缓存：5分钟清理一次
   - 图片缓存：1分钟清理一次
   - **影响**: 如果共用，需要统一清理间隔

2. **统计信息混在一起**
   - 当前两个缓存各自有独立的统计
   - **影响**: 如果共用，统计会混合，需要分离统计逻辑

3. **清理时影响范围**
   - 如果调用 `Clear()` 会清空所有缓存
   - **影响**: 清空压缩缓存会影响图片缓存（反之亦然）

## 🎯 推荐方案

### 方案 1: 直接共用（简单，推荐）✅

**优点**：
- 减少一个 BigCache 实例，节省内存
- 减少分片预分配开销（32个分片 → 共享）
- 实现简单，只需修改初始化代码

**缺点**：
- 统计信息混合
- 清理时会影响所有缓存（但可以通过键前缀区分）

**实现要点**：
1. 在 `server.go` 中创建一个共享的 `MemoryCache` 实例
2. 压缩缓存和图片缓存都使用这个实例
3. 使用键前缀区分：`compression:` 和 `image:`
4. 统一清理间隔为 5 分钟（取较大值）

**内存节省**：
- 当前：两个 BigCache 实例，每个 32 分片 = **64 个分片预分配**
- 优化后：一个 BigCache 实例，32 分片 = **32 个分片预分配**
- **节省**: 约 **50-100MB** 内存（分片预分配 + 窗口内存）

### 方案 2: 保持独立但减少分片（保守）

**优点**：
- 保持统计独立
- 清理策略独立
- 风险较小

**缺点**：
- 内存节省较少
- 仍然有两个 BigCache 实例

## 💡 推荐：方案 1（直接共用）

### 实现步骤

1. **创建共享缓存实例** (`internal/web/server.go`)
```go
// 创建共享的内存缓存（合并压缩和图片缓存）
sharedCache := cache.NewMemoryCache(&cache.MemoryCacheConfig{
    Name:            "shared_cache",
    MaxEntries:      400,  // 200 + 200
    MaxSizeBytes:    300 * 1024 * 1024,  // 50MB + 256MB = 306MB，取300MB
    MaxItemSize:     2 * 1024 * 1024,   // 2MB
    DefaultTTL:      24 * time.Hour,
    CleanupInterval: 5 * time.Minute,    // 统一使用5分钟
})

// 压缩缓存使用共享实例
compressionCache := NewCompressionCacheWithCache(sharedCache)

// 图片优化器使用共享实例
imageOptimizer := imageopt.NewOptimizerWithCache(imageOptConfig, sharedCache)
```

2. **修改压缩缓存** - 添加键前缀 `compression:`
```go
func (c *CompressionCache) makeKey(filepath string, algorithm CompressionAlgorithm) string {
    return fmt.Sprintf("compression:%s:%s", filepath, algorithm)
}
```

3. **修改图片优化器** - 添加键前缀 `image:`
```go
func (o *Optimizer) buildCacheKey(r *http.Request, format ImageFormat) string {
    key := "image:" + r.URL.Path  // 添加前缀
    // ... 其余逻辑
}
```

4. **分离清理逻辑** - 按前缀清理
```go
// 只清理压缩缓存
func (s *Server) ClearCompressionCache() {
    // 遍历所有键，删除 compression: 前缀的
}

// 只清理图片缓存
func (s *Server) ClearImageCache() {
    // 遍历所有键，删除 image: 前缀的
}
```

## 📈 预期效果

| 项目 | 当前 | 优化后 | 节省 |
|------|------|--------|------|
| BigCache 实例数 | 2 | 1 | - |
| 分片总数 | 64 | 32 | 50% |
| 预分配内存 | ~200MB | ~100MB | **~100MB** |
| 总内存占用 | 1.34GB | ~1.24GB | **~100MB** |

## ⚠️ 注意事项

1. **统计信息**: 共用后统计会混合，如果需要分离统计，需要：
   - 在 `MemoryCache` 中添加按前缀统计的功能
   - 或者在 `CompressionCache` 和 `ImageOptimizer` 中维护独立的统计计数器

2. **清理策略**: 统一为 5 分钟，图片缓存清理频率降低（影响很小）

3. **键冲突**: 虽然键格式不同，但为了安全起见，建议添加前缀

4. **测试**: 需要充分测试确保：
   - 键不会冲突
   - 清理逻辑正确
   - 统计信息准确

## ✅ 结论

**可以共用**，推荐实施方案 1（直接共用），预计可节省 **~100MB** 内存。

**建议**: 先实施方案 1，如果统计信息分离需求强烈，再考虑在 `MemoryCache` 中添加按前缀统计的功能。


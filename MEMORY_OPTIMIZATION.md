# 内存优化配置调整

## 🎯 优化目标

进一步降低 sslcat 的内存使用，从当前的 2.2GB 降至 1.5GB 以下，减少 CPU 压力。

## 📊 当前内存使用分析

根据 pprof 分析，当前内存使用：
- **总内存**: 2.2GB (13.6%)
- **BigCache 占用**: 1.39GB (98.48% 的堆内存)
- **CPU 占用**: 3.8% (已大幅改善)

## 🔧 优化措施

### 1. 压缩缓存优化
**文件**: `internal/web/server.go:133`

```go
// 优化前
compressionCache := NewCompressionCache(500, 5, 100)  // 500条目, 5MB/项, 100MB总计

// 优化后  
compressionCache := NewCompressionCache(200, 2, 50)   // 200条目, 2MB/项, 50MB总计
```

**预期节省**: ~50MB

### 2. 图片优化缓存优化
**文件**: `internal/imageopt/optimizer.go:82`

```go
// 优化前
MaxCacheSize: 512 * 1024 * 1024, // 512MB

// 优化后
MaxCacheSize: 256 * 1024 * 1024, // 256MB
```

**预期节省**: ~256MB

### 3. 默认内存缓存优化
**文件**: `internal/cache/memory_cache.go:47`

```go
// 优化前
MaxSizeBytes: 100 * 1024 * 1024, // 100MB

// 优化后
MaxSizeBytes: 50 * 1024 * 1024,  // 50MB
```

**预期节省**: ~50MB

### 4. BigCache 内部参数优化
**文件**: `internal/cache/memory_cache.go:76-79`

```go
// 优化前
bigCacheConfig.Shards = 256                    // 分片数
bigCacheConfig.MaxEntriesInWindow = config.MaxEntries * 5  // 窗口内最大条目

// 优化后
bigCacheConfig.Shards = 64                     // 减少分片数，降低内存开销
bigCacheConfig.MaxEntriesInWindow = config.MaxEntries * 2  // 减少窗口大小
```

**预期节省**: ~200-400MB (BigCache 内部优化)

## 📈 预期效果

| 项目 | 优化前 | 优化后 | 节省 |
|------|--------|--------|------|
| **压缩缓存** | 100MB | 50MB | 50MB |
| **图片缓存** | 512MB | 256MB | 256MB |
| **默认缓存** | 100MB | 50MB | 50MB |
| **BigCache 内部** | ~600MB | ~300MB | 300MB |
| **总计** | ~1.3GB | ~650MB | **650MB** |

**预期总内存使用**: 从 2.2GB 降至 **1.5GB** 以下

## 🚀 部署建议

1. **编译新版本**:
   ```bash
   make build-linux
   ```

2. **部署到生产环境**:
   ```bash
   # 备份现有版本
   sudo cp /opt/sslcat/sslcat /opt/sslcat/sslcat.backup.$(date +%Y%m%d_%H%M%S)
   
   # 停止服务
   sudo systemctl stop sslcat
   
   # 部署新版本
   sudo cp build/sslcat-linux-amd64 /opt/sslcat/sslcat
   sudo chmod +x /opt/sslcat/sslcat
   
   # 启动服务
   sudo systemctl start sslcat
   ```

3. **验证效果**:
   ```bash
   # 观察内存使用
   ps aux | grep sslcat
   
   # 采集新的内存 profile
   curl http://localhost/debug/pprof/heap -o heap_optimized.pprof
   ```

## ⚠️ 注意事项

1. **缓存命中率可能下降**: 由于缓存大小减少，命中率可能略有下降
2. **性能影响**: 对于高并发场景，可能需要根据实际情况调整
3. **监控建议**: 部署后密切监控内存使用和缓存命中率

## 📝 版本信息

- 优化版本: v1.3.20-rc2
- 优化日期: 2025-10-28
- 优化类型: 内存优化 (Memory Optimization)
- 优先级: 🟡 中 (Medium Priority)

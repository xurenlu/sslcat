# 内存优化配置指南

## 概述

SSLcat 1.3.28+ 版本针对资源受限环境进行了大幅内存优化，默认内存占用从 560MB 降低到约 50-100MB。

## 默认内存配置（资源受限模式）

### 1. 共享缓存 (SharedCache)
- **默认大小**: 10MB（从 64MB 降低）
- **最小值**: 5MB
- **用途**: 压缩缓存 + 图片优化缓存
- **配置项**: `server.shared_cache_max_size_mb`

```yaml
server:
  shared_cache_max_size_mb: 10  # 默认 10MB，可根据需要调整
```

### 2. 上游缓存 (UpstreamCache)
- **默认状态**: 禁用（需要时手动启用）
- **默认大小**: 50MB（从 1GB 降低）
- **单文件最大**: 10MB（从 100MB 降低）
- **配置项**: `upstream_cache.*`

```yaml
upstream_cache:
  enabled: false          # 默认禁用，减少内存占用
  max_size_bytes: 52428800  # 50MB
  max_file_size: 10485760   # 10MB
```

### 3. 图片优化缓存 (ImageOptimization)
- **默认大小**: 20MB（从 200MB 降低）
- **配置项**: `image_optimization.max_cache_size`

```yaml
image_optimization:
  enabled: false          # 默认禁用
  max_cache_size: 20971520  # 20MB
```

### 4. 内存缓存 (MemoryCache)
- **默认大小**: 5MB（从 25MB 降低）
- **最大条目数**: 200（从 1000 降低）
- **单项最大**: 1MB（从 5MB 降低）

## 根据服务器资源调整

### 资源极度受限（< 512MB RAM）
保持默认配置即可，总内存占用约 50-100MB。

### 中等资源（512MB - 2GB RAM）
可适当增加缓存以提升性能：

```yaml
server:
  shared_cache_max_size_mb: 32  # 增加到 32MB

upstream_cache:
  enabled: true
  max_size_bytes: 104857600  # 100MB
  max_file_size: 20971520    # 20MB

image_optimization:
  enabled: true
  max_cache_size: 52428800  # 50MB
```

### 充足资源（> 2GB RAM）
可以启用完整缓存以获得最佳性能：

```yaml
server:
  shared_cache_max_size_mb: 128  # 128MB

upstream_cache:
  enabled: true
  max_size_bytes: 536870912  # 512MB
  max_file_size: 104857600   # 100MB

image_optimization:
  enabled: true
  max_cache_size: 209715200  # 200MB
```

## 监控内存使用

### 1. 查看当前内存占用
```bash
ps aux | grep sslcat
```

### 2. 启用内存监控
```yaml
monitoring:
  enabled: true
  memory_max_usage_percent: 20.0  # 当内存增长超过 20% 时警告
```

### 3. 查看监控日志
```bash
tail -f ./data/logs/monitor.log
```

## 优化建议

### 1. 按需启用功能
- 如果不使用 CDN 功能，保持 `upstream_cache.enabled: false`
- 如果不需要图片优化，保持 `image_optimization.enabled: false`
- 如果不需要压缩，可以禁用 `compression.enabled: false`

### 2. 调整缓存策略
- 减少缓存 TTL，更快释放内存
- 减少最大文件大小，避免缓存大文件
- 限制可缓存的文件类型

### 3. 定期清理
```bash
# 清理上游缓存
rm -rf ./data/upstream-cache/*

# 清理日志
rm -f ./data/logs/*.log.*
```

## 内存占用对比

| 版本 | 默认配置 | 启用所有功能 |
|------|---------|-------------|
| 1.3.27 及之前 | ~560MB | ~800MB+ |
| 1.3.28+ | ~50-100MB | ~300-400MB |

## 故障排查

### 内存占用仍然过高
1. 检查是否有大量并发请求
2. 检查是否缓存了大文件
3. 检查日志文件是否过大
4. 考虑减少 `shared_cache_max_size_mb`

### 性能下降
1. 适当增加缓存大小
2. 启用 `upstream_cache`
3. 调整 `max_entries` 增加缓存条目数

## 相关配置

完整配置示例请参考：
- [配置文件示例](../config-example.yaml)
- [性能优化指南](./performance-tuning.md)


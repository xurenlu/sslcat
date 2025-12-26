# 缓存后端选择

## 概述

SSLcat 现在支持可插拔的缓存后端，可以通过配置选择不同的缓存实现，以平衡性能和内存占用。

## 支持的缓存后端

### 1. `bigcache` - 高性能缓存（默认用于大缓存）

**特点**:
- ✅ 高性能，适合高并发场景
- ✅ 使用 mmap，预分配内存
- ❌ 内存占用较高（即使缓存为空也会占用大量内存）
- ❌ 对于小缓存，内存浪费严重

**适用场景**:
- 大缓存（>=10MB）
- 高并发场景
- 内存充足的环境

### 2. `simple` - 轻量级缓存（推荐用于小缓存）

**特点**:
- ✅ 按需分配内存，不会预分配
- ✅ 内存占用低，适合资源受限环境
- ✅ 实现简单，无外部依赖
- ⚠️ 性能略低于 bigcache（但对于低流量场景影响不大）

**适用场景**:
- 小缓存（<10MB）
- 低流量场景
- 内存受限环境
- 默认推荐

### 3. `auto` - 自动选择

**特点**:
- 根据缓存大小自动选择后端
- 小缓存（<10MB）: 使用 `simple`
- 大缓存（>=10MB）: 使用 `bigcache`

**注意**: 默认值是 `simple`，而不是 `auto`。如果需要自动选择，需要显式配置 `"cache_backend_type": "auto"`。

## 配置方法

### 在配置文件中设置

在 `sslcat.conf` 中添加：

```json
{
  "server": {
    "shared_cache_max_size_mb": 5,
    "cache_backend_type": "simple"
  }
}
```

### 配置选项

- `cache_backend_type`: 缓存后端类型
  - `"bigcache"`: 使用 bigcache
  - `"simple"`: 使用简单的 map-based 缓存（**默认**）
  - `"auto"`: 自动选择
  - 不设置或空字符串: 使用 `simple`（默认）

### 示例配置

#### 示例 1: 使用轻量级缓存（推荐）

```json
{
  "server": {
    "shared_cache_max_size_mb": 5,
    "cache_backend_type": "simple"
  }
}
```

**效果**:
- 内存占用: ~50-100MB（而不是几 GB）
- 适合低流量场景

#### 示例 2: 使用 bigcache（高并发场景）

```json
{
  "server": {
    "shared_cache_max_size_mb": 50,
    "cache_backend_type": "bigcache"
  }
}
```

**效果**:
- 高性能
- 内存占用: ~1-2GB（预分配）

#### 示例 3: 自动选择（默认）

```json
{
  "server": {
    "shared_cache_max_size_mb": 5,
    "cache_backend_type": "auto"
  }
}
```

**效果**:
- 缓存 <10MB: 自动使用 `simple`
- 缓存 >=10MB: 自动使用 `bigcache`

## 内存占用对比

### bigcache
- **小缓存（5MB）**: ~3-4GB RSS（预分配）
- **大缓存（50MB）**: ~3-4GB RSS（预分配）

### simple
- **小缓存（5MB）**: ~50-100MB RSS（按需分配）
- **大缓存（50MB）**: ~50-100MB RSS（按需分配，实际使用多少分配多少）

## 性能对比

### bigcache
- **读取性能**: ⭐⭐⭐⭐⭐（优秀）
- **写入性能**: ⭐⭐⭐⭐⭐（优秀）
- **内存效率**: ⭐⭐（预分配导致浪费）

### simple
- **读取性能**: ⭐⭐⭐⭐（良好，对于低流量足够）
- **写入性能**: ⭐⭐⭐⭐（良好，对于低流量足够）
- **内存效率**: ⭐⭐⭐⭐⭐（按需分配，高效）

## 推荐配置

### 低流量场景（推荐）

```json
{
  "server": {
    "shared_cache_max_size_mb": 5,
    "cache_backend_type": "simple"
  }
}
```

**优势**:
- 内存占用低（~50-100MB）
- 性能足够
- 适合资源受限环境

### 高并发场景

```json
{
  "server": {
    "shared_cache_max_size_mb": 50,
    "cache_backend_type": "bigcache"
  }
}
```

**优势**:
- 高性能
- 适合高并发

### 使用默认值（simple）

```json
{
  "server": {
    "shared_cache_max_size_mb": 5
    // 不设置 cache_backend_type，默认使用 simple
  }
}
```

**优势**:
- 内存占用低
- 适合低流量场景
- 无需手动配置

### 自动选择

```json
{
  "server": {
    "shared_cache_max_size_mb": 5,
    "cache_backend_type": "auto"
  }
}
```

**优势**:
- 自动根据缓存大小选择最优后端
- 小缓存用 simple，大缓存用 bigcache

## 迁移指南

### 从 bigcache 迁移到 simple

1. **修改配置文件**:
   ```json
   {
     "server": {
       "cache_backend_type": "simple"
     }
   }
   ```

2. **重启服务**:
   ```bash
   sudo systemctl restart sslcat
   ```

3. **观察效果**:
   - 内存占用应该显著降低
   - 性能可能略有下降（但对于低流量场景影响不大）

### 从 simple 迁移到 bigcache

1. **修改配置文件**:
   ```json
   {
     "server": {
       "cache_backend_type": "bigcache"
     }
   }
   ```

2. **重启服务**:
   ```bash
   sudo systemctl restart sslcat
   ```

3. **观察效果**:
   - 性能可能提升
   - 内存占用会增加

## 故障排查

### 问题: 内存占用仍然很高

**可能原因**:
- 使用了 `bigcache` 后端
- 缓存大小设置过大

**解决方案**:
1. 切换到 `simple` 后端
2. 减少缓存大小

### 问题: 缓存性能不佳

**可能原因**:
- 使用了 `simple` 后端
- 缓存大小设置过小

**解决方案**:
1. 切换到 `bigcache` 后端
2. 增加缓存大小

## 总结

- **默认值**: `simple`（轻量级，适合大多数场景）
- **低流量场景**: 使用默认的 `simple` 后端，内存占用低
- **高并发场景**: 使用 `bigcache` 后端，性能高
- **不确定**: 使用 `auto`，自动选择最优后端

**推荐**: 对于大多数场景，直接使用默认的 `simple` 后端即可，无需配置。只有在高并发场景或需要更高性能时，才考虑使用 `bigcache`。

通过合理选择缓存后端，可以在性能和内存占用之间找到最佳平衡点。


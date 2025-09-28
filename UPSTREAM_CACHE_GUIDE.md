# SSLcat 上游缓存使用指南

## 概述

SSLcat 现在支持智能的上游静态文件缓存功能，可以缓存从后端服务器返回的静态资源（如JS、CSS、图片等），显著提升访问速度并减少后端负载。

## 主要特性

### 🚀 **智能缓存策略**
- **Cache-Control遵循**: 自动解析和遵循上游服务器的Cache-Control指令
- **多种过期策略**: 支持Expires头部、max-age指令和默认TTL
- **文件类型识别**: 自动识别可缓存的静态资源类型
- **大小限制**: 支持最小和最大文件大小限制

### 📦 **压缩存储**
- **自动压缩**: 缓存时自动使用Brotli/Gzip压缩节省空间
- **智能解压**: 根据客户端支持自动解压或直接返回压缩数据
- **压缩统计**: 提供详细的压缩效果统计

### 🔄 **缓存管理**
- **自动清理**: 定期清理过期缓存文件
- **手动清理**: 支持通过API手动清理缓存
- **模式清理**: 支持按URL模式批量清理
- **统计监控**: 详细的缓存命中率和使用统计

## 缓存策略

### 🎯 **缓存条件**
只有同时满足以下条件的响应才会被缓存：

1. **HTTP状态码**: 200 OK
2. **请求方法**: GET 或 HEAD
3. **文件类型**: 静态资源类型（见下表）
4. **文件大小**: 1KB - 10MB 之间
5. **Cache-Control**: 不包含 no-cache、no-store、private 指令

### 📁 **可缓存文件类型**

| 类型 | Content-Type | 说明 |
|------|--------------|------|
| CSS | text/css | 样式表文件 |
| JavaScript | application/javascript, text/javascript | JS脚本文件 |
| 图片 | image/jpeg, image/png, image/gif, image/webp, image/svg+xml | 各种图片格式 |
| 字体 | font/woff, font/woff2, application/font-woff* | Web字体文件 |
| 数据 | application/json, application/xml, text/xml | 结构化数据 |
| 文本 | text/plain, text/csv | 纯文本文件 |

### ⏰ **过期时间计算**

缓存过期时间按以下优先级确定：

1. **Expires头部**: 如果存在有效的Expires头部
2. **Cache-Control max-age**: 解析max-age指令
3. **默认TTL**: 1小时（可配置）

**限制**: 最大缓存时间不超过24小时

## 配置示例

### 基本配置
```json
{
  "proxy": {
    "rules": [
      {
        "domain": "static.example.com",
        "target": "192.168.1.100",
        "port": 80,
        "enabled": true,
        "ssl_only": true
      }
    ]
  },
  "cdn_cache": {
    "enabled": true,
    "cache_dir": "./data/cache",
    "max_size_bytes": 1073741824,
    "default_ttl_seconds": 3600
  },
  "compression": {
    "enabled": true,
    "algorithms": ["br", "gzip"],
    "min_size": 1024
  }
}
```

### 高级配置
```json
{
  "proxy": {
    "rules": [
      {
        "domain": "assets.example.com",
        "load_balancer_enabled": true,
        "load_balancer_algorithm": "round_robin",
        "load_balancer_backends": [
          {
            "id": "assets-1",
            "host": "192.168.1.10",
            "port": 80,
            "enabled": true
          },
          {
            "id": "assets-2", 
            "host": "192.168.1.11",
            "port": 80,
            "enabled": true
          }
        ]
      }
    ]
  }
}
```

## API接口

### 1. 获取缓存统计
```bash
# GET /sslcat-panel/api/cache/upstream/stats
curl -H "Cookie: session=your_session_cookie" \
  http://localhost/sslcat-panel/api/cache/upstream/stats
```

**响应示例**:
```json
{
  "success": true,
  "timestamp": 1640995200,
  "data": {
    "enabled": true,
    "cache_dir": "./data/upstream-cache",
    "hits": 1250,
    "misses": 180,
    "stores": 200,
    "hit_rate": 87.4,
    "default_ttl": "1h0m0s",
    "respect_upstream": true,
    "max_size_bytes": 1073741824
  }
}
```

### 2. 清理所有缓存
```bash
# POST /sslcat-panel/api/cache/upstream/purge
curl -X POST \
  -H "Cookie: session=your_session_cookie" \
  -H "Content-Type: application/json" \
  -d '{"pattern": "all"}' \
  http://localhost/sslcat-panel/api/cache/upstream/purge
```

### 3. 按模式清理缓存
```bash
# 清理所有CSS文件缓存
curl -X POST \
  -H "Cookie: session=your_session_cookie" \
  -H "Content-Type: application/json" \
  -d '{"pattern": ".*\\.css"}' \
  http://localhost/sslcat-panel/api/cache/upstream/purge

# 清理特定域名的缓存
curl -X POST \
  -H "Cookie: session=your_session_cookie" \
  -H "Content-Type: application/json" \
  -d '{"pattern": "https://assets\\.example\\.com/.*"}' \
  http://localhost/sslcat-panel/api/cache/upstream/purge
```

## 缓存响应头

### 缓存命中时的响应头
```
X-Cache: HIT
X-Cache-Key: abc123def456...
X-Cache-Created: 2024-01-01T12:00:00Z
X-Cache-Expires: 2024-01-01T13:00:00Z
X-Cache-Access-Count: 15
Content-Encoding: br
Vary: Accept-Encoding
```

### 缓存未命中时
请求会正常转发到上游服务器，响应会异步存储到缓存中供后续请求使用。

## 使用场景

### 1. **静态资源站点**
适用于提供大量静态资源的站点：
- CSS/JS文件
- 图片资源
- 字体文件
- 图标文件

### 2. **CDN回源优化**
作为CDN的回源缓存：
- 减少回源请求
- 提升响应速度
- 降低带宽成本

### 3. **API响应缓存**
缓存相对静态的API响应：
- 配置数据
- 元数据信息
- 不频繁变化的数据

## 性能优势

### 📈 **性能提升**
- **响应时间**: 缓存命中时响应时间从几十毫秒降低到几毫秒
- **带宽节省**: 减少上游带宽使用，特别是图片等大文件
- **服务器负载**: 显著降低后端服务器负载

### 💾 **存储优化**
- **压缩存储**: 使用Brotli/Gzip压缩，节省60-90%存储空间
- **智能清理**: 自动清理过期文件，避免磁盘空间浪费
- **大小限制**: 避免缓存过大文件影响性能

## 监控和管理

### 📊 **统计指标**
- **命中率**: 缓存命中率百分比
- **请求统计**: 命中、未命中、存储次数
- **存储信息**: 缓存目录、最大大小等
- **配置状态**: 当前缓存配置信息

### 🔧 **管理操作**
- **查看统计**: 实时查看缓存使用情况
- **清理缓存**: 支持全量和模式清理
- **配置调整**: 通过配置热重载调整缓存策略

## 日志示例

### 缓存命中
```
DEBUG[2024-01-01T12:00:00Z] Served from upstream cache for GET /assets/app.js
DEBUG[2024-01-01T12:00:01Z] Cache hit for https://assets.example.com/style.css
```

### 缓存存储
```
DEBUG[2024-01-01T12:00:00Z] Stored cache entry for https://assets.example.com/app.js (expires: 2024-01-01T13:00:00Z)
DEBUG[2024-01-01T12:00:01Z] Compressed cache entry: abc123... (15360 -> 3072 bytes)
```

### 缓存清理
```
INFO[2024-01-01T12:00:00Z] Starting upstream cache cleanup
INFO[2024-01-01T12:00:01Z] Cleaned 25 expired cache entries
INFO[2024-01-01T12:00:02Z] Purged 10 cache entries matching pattern: .*\.css
```

## 最佳实践

### 1. **缓存策略配置**
- 为静态资源设置合适的Cache-Control头部
- 使用版本化的资源URL（如app.v1.2.3.js）
- 设置合理的max-age值

### 2. **监控和维护**
- 定期检查缓存命中率
- 监控缓存目录大小
- 根据需要调整缓存策略

### 3. **性能优化**
- 对于经常变化的资源，设置较短的缓存时间
- 对于很少变化的资源，设置较长的缓存时间
- 使用适当的压缩级别平衡CPU和存储

### 4. **故障处理**
- 缓存失败时自动降级到直接代理
- 定期清理避免磁盘空间不足
- 监控缓存错误日志

## 注意事项

### ⚠️ **重要提醒**
1. **动态内容**: HTML等动态内容默认不缓存
2. **认证内容**: 包含认证信息的响应不会缓存
3. **大文件**: 超过10MB的文件不会缓存
4. **磁盘空间**: 确保有足够的磁盘空间用于缓存

### 🔒 **安全考虑**
1. **敏感数据**: 确保不缓存包含敏感信息的响应
2. **访问控制**: 缓存的内容会绕过上游的访问控制
3. **数据一致性**: 缓存可能导致数据不一致，需要合理设置TTL

通过合理配置和使用上游缓存功能，SSLcat 可以显著提升静态资源的访问性能，为用户提供更好的体验。

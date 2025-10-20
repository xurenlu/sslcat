# SSLcat 智能Content-Type检测功能

## 概述

SSLcat现在支持智能的文件类型检测功能，可以在本地缓存服务时自动猜测并正确设置Content-Type头部，确保图片等文件能够正确显示而不是被下载。

## 主要特性

### 🎯 **多层级检测策略**
1. **存储的Content-Type优先**：如果缓存时保存了正确的Content-Type，优先使用
2. **文件头魔数检测**：通过分析文件头部的特定字节序列判断文件类型
3. **扩展名猜测**：根据文件扩展名推断MIME类型
4. **系统MIME类型**：使用系统默认的MIME类型映射
5. **默认二进制类型**：最后回退到`application/octet-stream`

### 🔍 **支持的文件类型**

#### 图片格式
- **JPEG**: `image/jpeg` (文件头: `FF D8 FF`)
- **PNG**: `image/png` (文件头: `89 50 4E 47 0D 0A 1A 0A`)
- **GIF**: `image/gif` (文件头: `47 49 46 38`)
- **WebP**: `image/webp` (文件头: `52 49 46 46` + `57 45 42 50`)
- **BMP**: `image/bmp` (文件头: `42 4D`)
- **TIFF**: `image/tiff` (文件头: `49 49 2A 00` 或 `4D 4D 00 2A`)
- **SVG**: `image/svg+xml` (通过扩展名)
- **ICO**: `image/x-icon` (通过扩展名)

#### 文档格式
- **PDF**: `application/pdf` (文件头: `25 50 44 46`)
- **ZIP**: `application/zip` (文件头: `50 4B 03 04`)
- **RAR**: `application/x-rar-compressed` (文件头: `52 61 72 21 1A 07 00`)
- **7Z**: `application/x-7z-compressed` (文件头: `37 7A BC AF 27 1C`)

#### 音频格式
- **MP3**: `audio/mpeg` (文件头: `FF FB`)
- **WAV**: `audio/wav` (文件头: `52 49 46 46`)
- **OGG**: `audio/ogg` (文件头: `4F 67 67 53`)

#### 视频格式
- **MP4**: `video/mp4` (文件头: `00 00 00 18 66 74 79 70`)
- **AVI**: `video/x-msvideo` (文件头: `52 49 46 46`)
- **WebM**: `video/webm` (通过扩展名)

#### 字体格式
- **WOFF**: `font/woff` (文件头: `77 4F 46 46`)
- **WOFF2**: `font/woff2` (文件头: `77 4F 46 32`)
- **TTF**: `font/ttf` (文件头: `00 01 00 00`)
- **OTF**: `font/otf` (文件头: `4F 54 54 4F`)

#### 文本格式
- **HTML**: `text/html` (文件头: `3C 68 74 6D 6C`)
- **CSS**: `text/css` (通过扩展名)
- **JavaScript**: `application/javascript` (通过扩展名)
- **JSON**: `application/json` (文件头: `7B` 或 `5B`)
- **XML**: `text/xml` (文件头: `3C 3F 78 6D 6C`)
- **纯文本**: `text/plain` (通过内容分析)

## 使用方法

### 自动启用
智能Content-Type检测功能在CDN缓存和上游缓存中自动启用，无需额外配置。

### 检测流程
```
1. 检查缓存元数据中的Content-Type
   ↓ (如果存在且有效)
   使用存储的Content-Type
   ↓ (如果不存在或无效)
2. 读取文件头部进行魔数检测
   ↓ (如果检测成功)
   使用检测到的MIME类型
   ↓ (如果检测失败)
3. 根据文件扩展名猜测
   ↓ (如果猜测成功)
   使用扩展名对应的MIME类型
   ↓ (如果猜测失败)
4. 使用系统默认MIME类型
   ↓ (如果系统无映射)
5. 使用默认二进制类型
```

## 配置选项

### CDN缓存配置
```json
{
  "cdn_cache": {
    "enabled": true,
    "cache_dir": "./data/cdn-cache",
    "default_ttl_seconds": 3600,
    "max_size_bytes": 1073741824,
    "rules": [
      {
        "match_type": "suffix",
        "pattern": ".jpg",
        "ttl_seconds": 86400
      }
    ]
  }
}
```

### 上游缓存配置
```json
{
  "upstream_cache": {
    "enabled": true,
    "cache_dir": "./data/upstream-cache",
    "max_size_bytes": 1073741824,
    "default_ttl": "1h",
    "respect_upstream": true,
    "min_size": 1024,
    "max_size": 104857600
  }
}
```

## 日志和调试

### 调试日志
启用调试日志可以看到Content-Type检测过程：

```bash
# 设置日志级别为debug
export SSL_LOG_LEVEL=debug

# 启动SSLcat
./sslcat
```

### 日志示例
```
[DEBUG] 使用存储的Content-Type: image/jpeg
[DEBUG] 通过文件内容检测到Content-Type: image/png
[DEBUG] 通过扩展名检测到Content-Type: text/css
[DEBUG] 使用系统默认MIME类型: application/octet-stream
[DEBUG] 使用默认Content-Type: application/octet-stream
```

## 性能优化

### 缓存策略
- **文件头检测**：只读取文件前32字节，性能开销极小
- **扩展名检测**：纯内存操作，几乎无性能影响
- **系统MIME**：使用Go标准库，性能优秀

### 内存使用
- **MIME检测器**：单例模式，内存占用约几KB
- **魔数映射**：预定义映射表，内存占用约1KB
- **扩展名映射**：预定义映射表，内存占用约2KB

## 故障排除

### 常见问题

#### 1. 图片仍然被下载
**原因**：文件头魔数检测失败，扩展名映射不正确
**解决**：检查文件是否损坏，确认扩展名正确

#### 2. Content-Type检测不准确
**原因**：文件头被截断或文件格式特殊
**解决**：增加更多文件头魔数支持，或手动设置Content-Type

#### 3. 性能影响
**原因**：频繁的文件读取操作
**解决**：确保缓存目录在SSD上，调整缓存策略

### 调试命令
```bash
# 检查缓存文件
ls -la ./data/cdn-cache/
ls -la ./data/upstream-cache/

# 查看缓存元数据
cat ./data/cdn-cache/*.meta.json

# 测试文件类型检测
curl -I http://localhost:8080/cached-image.jpg
```

## 最佳实践

### 1. 文件命名规范
- 使用标准的文件扩展名
- 避免使用非标准扩展名
- 确保文件扩展名与实际内容匹配

### 2. 缓存策略
- 为不同文件类型设置合适的TTL
- 定期清理过期缓存
- 监控缓存命中率

### 3. 性能监控
- 监控Content-Type检测耗时
- 关注缓存命中率
- 定期检查日志中的检测结果

## 技术实现

### 核心组件
- **MIMEDetector**: 文件类型检测器
- **CDNCache**: CDN缓存管理器
- **UpstreamCache**: 上游缓存管理器

### 检测算法
1. **魔数检测**：基于文件头字节序列的快速识别
2. **扩展名映射**：预定义的扩展名到MIME类型映射
3. **内容分析**：文本文件的内容特征分析
4. **系统集成**：与Go标准库MIME类型系统集成

### 扩展性
- 支持添加新的文件类型检测
- 支持自定义魔数映射
- 支持插件化检测器

## 总结

SSLcat的智能Content-Type检测功能通过多层级检测策略，确保缓存文件能够以正确的MIME类型提供给客户端，解决了图片等文件被错误下载的问题。该功能自动启用，无需额外配置，为CDN和上游缓存提供了强大的文件类型识别能力。

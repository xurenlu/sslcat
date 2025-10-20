# SSLcat 静态站点智能MIME类型和缓存策略指南

## 概述

SSLcat现在为静态站点服务提供了智能的MIME类型检测和优化的缓存策略，确保不同类型的文件能够正确显示并具有合适的缓存行为。

## 主要特性

### 🎯 **智能MIME类型检测**
1. **文件头魔数检测**：通过分析文件头部的特定字节序列判断文件类型
2. **扩展名猜测**：根据文件扩展名推断MIME类型
3. **系统MIME类型**：使用系统默认的MIME类型映射
4. **多层级回退策略**：确保所有文件都能获得正确的Content-Type

### 📦 **优化的缓存策略**
根据文件类型设置不同的Cache-Control策略：

#### HTML文件
- **缓存时间**：5分钟（短缓存）
- **策略**：`public, max-age=300, must-revalidate`
- **原因**：HTML文件可能经常更新，需要及时获取最新版本

#### CSS/JS文件
- **缓存时间**：1年（长缓存）
- **策略**：`public, max-age=31536000, immutable`
- **原因**：静态资源文件通常不会改变，可以长期缓存

#### 图片文件
- **缓存时间**：1年（长缓存）
- **策略**：`public, max-age=31536000, immutable`
- **支持格式**：JPEG、PNG、GIF、WebP、SVG、ICO、BMP、TIFF

#### 字体文件
- **缓存时间**：1年（长缓存）
- **策略**：`public, max-age=31536000, immutable`
- **支持格式**：WOFF、WOFF2、TTF、OTF、EOT

#### 文档文件
- **缓存时间**：1小时（中等缓存）
- **策略**：`public, max-age=3600`
- **支持格式**：PDF、DOC、DOCX、XLS、XLSX、PPT、PPTX

#### 媒体文件
- **视频缓存时间**：2小时
- **音频缓存时间**：2小时
- **策略**：`public, max-age=7200`

#### 压缩文件
- **缓存时间**：30分钟（短缓存）
- **策略**：`public, max-age=1800`
- **支持格式**：ZIP、RAR、7Z、TAR、GZ

#### 文本文件
- **缓存时间**：30分钟（短缓存）
- **策略**：`public, max-age=1800`
- **支持格式**：TXT、MD、JSON、XML、CSV

## 使用方法

### 自动启用
智能MIME类型检测和缓存策略在静态站点服务中自动启用，无需额外配置。

### 静态站点配置
```json
{
  "static_sites": [
    {
      "domain": "example.com",
      "root": "/var/www/example.com",
      "index": "index.html",
      "enabled": true
    }
  ]
}
```

## 技术实现

### 检测流程
```
1. 读取文件头32字节进行魔数检测
   ↓ (如果检测成功)
   使用检测到的MIME类型
   ↓ (如果检测失败)
2. 根据文件扩展名猜测
   ↓ (如果猜测成功)
   使用扩展名对应的MIME类型
   ↓ (如果猜测失败)
3. 使用系统默认MIME类型
   ↓ (如果系统无映射)
4. 使用默认二进制类型
```

### 缓存策略矩阵

| 文件类型 | 扩展名 | MIME类型 | 缓存时间 | Cache-Control |
|---------|--------|----------|----------|---------------|
| HTML | .html, .htm | text/html | 5分钟 | public, max-age=300, must-revalidate |
| CSS | .css | text/css | 1年 | public, max-age=31536000, immutable |
| JavaScript | .js | application/javascript | 1年 | public, max-age=31536000, immutable |
| 图片 | .jpg, .png, .gif, .webp, .svg, .ico | image/* | 1年 | public, max-age=31536000, immutable |
| 字体 | .woff, .woff2, .ttf, .otf | font/* | 1年 | public, max-age=31536000, immutable |
| 文档 | .pdf, .doc, .docx | application/* | 1小时 | public, max-age=3600 |
| 视频 | .mp4, .avi, .mov | video/* | 2小时 | public, max-age=7200 |
| 音频 | .mp3, .wav, .ogg | audio/* | 2小时 | public, max-age=7200 |
| 压缩 | .zip, .rar, .7z | application/* | 30分钟 | public, max-age=1800 |
| 文本 | .txt, .md, .json | text/* | 30分钟 | public, max-age=1800 |

## 性能优化

### 文件头检测
- **读取大小**：仅读取文件前32字节
- **性能开销**：极小，几乎无影响
- **准确性**：高，支持20+种文件格式

### 缓存策略
- **智能压缩**：自动检测可压缩文件类型
- **条件请求**：支持ETag和Last-Modified验证
- **安全头**：为HTML文件设置安全响应头

### 内存使用
- **MIME检测器**：单例模式，内存占用约几KB
- **扩展名映射**：预定义映射表，内存占用约2KB
- **无额外开销**：不影响现有性能

## 安全特性

### 安全响应头
为HTML文件自动设置安全头：
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`
- `Referrer-Policy: strict-origin-when-cross-origin`

### 可执行文件处理
自动为可执行文件设置下载头：
- `.exe`, `.msi`, `.dmg`, `.pkg`, `.deb`, `.rpm`
- `.bin`, `.run`, `.sh`, `.bat`, `.cmd`, `.com`, `.scr`

## 调试和监控

### 日志级别
启用调试日志查看检测过程：
```bash
export SSL_LOG_LEVEL=debug
./sslcat
```

### 日志示例
```
[DEBUG] 通过文件内容检测到Content-Type: image/png
[DEBUG] 通过扩展名检测到Content-Type: text/css
[DEBUG] 使用系统默认MIME类型: application/octet-stream
[DEBUG] 使用默认Content-Type: application/octet-stream
```

### 测试命令
```bash
# 测试静态文件服务
curl -I http://example.com/style.css
curl -I http://example.com/image.jpg
curl -I http://example.com/document.pdf

# 检查响应头
curl -v http://example.com/script.js
```

## 最佳实践

### 1. 文件命名规范
- 使用标准的文件扩展名
- 确保文件扩展名与实际内容匹配
- 避免使用非标准扩展名

### 2. 缓存策略优化
- 为不同文件类型设置合适的TTL
- 使用版本控制管理静态资源
- 定期清理过期缓存

### 3. 性能监控
- 监控Content-Type检测耗时
- 关注缓存命中率
- 定期检查日志中的检测结果

### 4. 安全考虑
- 确保HTML文件的安全头设置
- 定期检查可执行文件的安全性
- 监控异常的文件类型请求

## 故障排除

### 常见问题

#### 1. 文件仍然被下载
**原因**：MIME类型检测失败
**解决**：检查文件扩展名，确保文件未损坏

#### 2. 缓存策略不正确
**原因**：文件类型识别错误
**解决**：检查文件扩展名和内容是否匹配

#### 3. 性能影响
**原因**：频繁的文件读取操作
**解决**：确保静态文件目录在SSD上

### 调试步骤
1. 检查文件扩展名是否正确
2. 验证文件内容是否与扩展名匹配
3. 查看调试日志中的检测结果
4. 测试不同文件类型的响应头

## 配置示例

### 静态站点配置
```json
{
  "static_sites": [
    {
      "domain": "myblog.com",
      "root": "/var/www/blog",
      "index": "index.html",
      "enabled": true
    },
    {
      "domain": "docs.example.com",
      "root": "/var/www/docs",
      "index": "index.html",
      "enabled": true
    }
  ]
}
```

### 高级配置
```json
{
  "server": {
    "access_log_enabled": true,
    "access_log_format": "nginx",
    "access_log_path": "./data/access.log",
    "access_log_max_size": 10485760,
    "access_log_max_files": 5
  }
}
```

## 总结

SSLcat的静态站点智能MIME类型检测和缓存策略功能通过多层级检测策略和优化的缓存策略，确保静态文件能够正确显示并具有合适的缓存行为。该功能自动启用，无需额外配置，为静态站点提供了强大的文件类型识别和性能优化能力。

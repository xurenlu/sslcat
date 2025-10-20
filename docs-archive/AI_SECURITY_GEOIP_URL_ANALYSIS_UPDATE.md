# AI 安全分析增强：GeoIP 和 URL 分析功能

## 更新日期
2025-10-11

## 概述

本次更新为 AI 安全分析器添加了重要的增强功能，包括攻击来源国家/ISP 分析、目标 URL 统计、以及对静态资源请求的智能识别。

## 主要改进

### 1. GeoIP 信息集成

#### 数据结构增强
- **Attack 结构体**：新增字段
  - `Country` - 攻击来源国家
  - `CountryCode` - 国家代码
  - `ISP` - ISP/组织信息

- **IPSummary 结构体**：新增字段
  - `Country` - 国家
  - `CountryCode` - 国家代码
  - `ISP` - ISP/组织
  - `TargetURLs` - 该 IP 主要访问的 URL 列表

- **AttackSummary 结构体**：新增字段
  - `TopCountries` - 主要来源国家
  - `TopURLs` - 主要攻击目标 URL
  - `GeoDistrib` - 国家分布统计

#### 实时查询
- DDoS Protector 在记录攻击时自动查询 GeoIP 信息
- 支持从 GeoIP2 数据库获取国家、城市、ISP 等信息
- 查询结果会缓存，提高性能

### 2. URL 访问统计

#### 新增数据结构
- **URLSummary**：URL 访问统计摘要
  - `URL` - 访问的路径
  - `RequestCount` - 请求次数
  - `UniqueIPs` - 唯一 IP 数量
  - `TopIPs` - 主要访问 IP
  - `TopCountries` - 主要来源国家
  - `Suspicious` - 是否为可疑路径

- **SecurityData**：新增字段
  - `CountryDistrib` - 全局国家分布统计
  - `URLAccessPattern` - URL 访问模式统计
  - `TopTargetURLs` - 最常被访问的 URL 列表

#### 智能分析
- 自动识别可疑路径（如 admin、phpmyadmin、.env 等）
- 统计每个 URL 的访问来源国家和 IP
- 生成 Top 20 最常被访问的 URL

### 3. 静态资源路径放宽

#### 智能识别静态资源
新增 `isStaticResourcePath()` 函数，识别以下静态资源：

**路径前缀：**
- `/_next/` - Next.js 静态资源
- `/static/` - 通用静态资源
- `/assets/` - 资产文件
- `/public/` - 公开资源
- `/.well-known/` - 验证文件
- `/favicon.ico` - 网站图标
- `/robots.txt` - 爬虫文件
- `/sitemap.xml` - 站点地图
- `/sw.js` - Service Worker
- `/manifest.json` - PWA Manifest

**文件扩展名：**
- `.js`, `.css`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.svg`, `.ico`
- `.woff`, `.woff2`, `.ttf`, `.eot`, `.webp`, `.avif`
- `.map` - source maps

#### 差异化限流
- 对静态资源请求，速率限制阈值**提高 5 倍**
- 例如：正常限制 3000 次/分钟，静态资源允许 15000 次/分钟
- 避免误判正常的前端资源加载为 DDoS 攻击

### 4. AI Prompt 增强

#### 中文 Prompt
- 新增地理位置分析要求：识别攻击来源国家分布、ISP 信息
- 新增目标 URL 分析要求：识别攻击者试图访问的路径、漏洞探测模式
- 特别注意事项：明确指出静态资源请求属于正常现象
- 输出要求：在威胁描述中必须包含来源国家、ISP、目标 URL 等信息

#### 英文 Prompt
- Geographic analysis：识别攻击来源国家、是否集中式攻击、ISP 信息
- Target URL analysis：识别目标路径、特定漏洞、路径探测模式
- Special Notes：静态资源路径请求不应被标记为攻击
- Output requirements：威胁描述中包含国家、ISP、目标 URL 等信息

### 5. 数据收集器增强

#### 攻击事件统计
- 自动统计每个攻击类型的国家分布
- 统计每个攻击类型的 Top URL
- 提取 Top 5 来源国家和目标 URL

#### 高频攻击者统计
- 为每个攻击 IP 添加 GeoIP 信息
- 统计每个 IP 主要访问的 URL（Top 5）
- 如果有 SecurityManager，实时查询最新的 GeoIP 信息

#### URL 访问分析
- 统计所有 URL 的访问次数和来源
- 为每个 URL 生成详细的访问统计
- 识别可疑路径并标记

## 代码变更清单

### 修改的文件

1. **internal/ddos/protector.go**
   - 在 `Attack` 结构体添加 GeoIP 字段
   - 在 `Protector` 结构体添加 `geoIPService` 字段
   - 新增 `SetGeoIPService()` 方法
   - 修改 `recordAttack()` 方法，自动查询 GeoIP
   - 新增 `isStaticResourcePath()` 方法
   - 修改 `CheckRequest()` 方法，对静态资源放宽限制

2. **internal/ai/security_analyzer.go**
   - 修改 `SecurityData` 结构体，添加国家分布和 URL 统计字段
   - 修改 `AttackSummary` 结构体，添加 TopCountries 和 TopURLs
   - 修改 `IPSummary` 结构体，添加 Country、ISP、TargetURLs
   - 新增 `URLSummary` 结构体
   - 更新中文和英文 Prompt，强调地理位置和 URL 分析
   - 修改数据格式化方法，添加 GeoIP 和 URL 信息输出

3. **internal/ai/data_collector.go**
   - 修改 `collectDDoSData()` 方法
     - 添加国家分布统计
     - 添加 URL 访问统计
     - 为每个攻击类型统计 TopCountries 和 TopURLs
   - 修改高频攻击者统计，添加 GeoIP 和 TargetURLs
   - 新增 Top URL 访问统计生成
   - 新增 `isSuspiciousURL()` 方法

4. **internal/web/server.go**
   - 在 DDoS Protector 初始化后，设置 GeoIP 服务

## 使用说明

### 前置条件

1. **配置 GeoIP 数据库**
   ```json
   {
     "geo_blocking": {
       "enabled": true,
       "database_path": "/path/to/GeoLite2-City.mmdb"
     }
   }
   ```

2. **启用 AI 安全分析**
   ```json
   {
     "ai_security": {
       "enabled": true,
       "api_key": "your-api-key",
       "check_interval": "1h"
     }
   }
   ```

### AI 分析报告示例

现在 AI 分析报告会包含：

```json
{
  "threat_level": "high",
  "summary": "检测到来自美国和中国的大规模扫描攻击，主要针对管理后台和配置文件",
  "threats": [
    {
      "type": "port_scan",
      "severity": "high",
      "description": "检测到来自美国 (AWS) 的大规模端口扫描，主要针对 /admin、/wp-admin、/.env 等敏感路径",
      "indicators": [
        "IP: 52.xx.xx.xx (美国, Amazon Web Services)",
        "目标: /admin, /wp-admin, /.env",
        "请求量: 5000+ 次/小时"
      ],
      "confidence": 0.95,
      "action": "建议封禁来自 AWS 的可疑 IP，加强管理后台访问控制"
    }
  ],
  "recommendations": [
    "对来自美国和中国的请求加强监控",
    "考虑封禁云服务商 IP 段访问管理后台",
    "隐藏或重命名敏感路径"
  ]
}
```

## 性能影响

- **GeoIP 查询**：使用内存缓存，每个 IP 只查询一次，缓存 1 小时
- **静态资源识别**：简单的字符串匹配，性能损耗可忽略
- **数据统计**：仅在 AI 分析时进行，不影响请求处理性能

## 安全增强效果

1. **更精准的威胁识别**：通过国家和 ISP 信息，快速识别云服务器攻击、僵尸网络等
2. **减少误报**：智能识别静态资源请求，避免将正常前端加载判定为攻击
3. **更有针对性的防护**：了解攻击目标 URL，可以针对性地加强特定路径的防护
4. **更详细的攻击溯源**：完整的攻击来源（国家、ISP）和目标信息，便于事后分析

## 后续优化方向

1. 支持基于国家/ISP 的自动封禁规则
2. 添加 ASN 信息，识别特定网络运营商
3. URL 访问模式的时序分析
4. 攻击路径的关联分析（攻击链识别）

## 测试建议

1. 部署 GeoIP 数据库文件
2. 触发一些测试请求（包括静态资源和敏感路径）
3. 检查 AI 分析报告是否包含国家和 URL 信息
4. 验证静态资源请求不会被误判为攻击

---

**注意**：本次更新向后兼容，即使没有配置 GeoIP 数据库，系统也能正常运行，只是不会包含地理位置信息。


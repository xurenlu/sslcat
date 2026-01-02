# WAF 频率限制功能

## 功能概述

WAF 频率限制（Rate Limiting）功能可以自动检测和封禁频繁触发 WAF 规则的 IP 地址，有效防止恶意扫描和攻击行为。

## 工作原理

1. **触发记录**：每当一个 IP 触发任何 WAF 规则时，系统会记录该事件
2. **频率统计**：在指定的时间窗口内统计该 IP 的触发次数
3. **自动封禁**：当触发次数达到阈值时，自动封禁该 IP
4. **临时封禁**：封禁是临时的，到期后自动解除

## 配置参数

在配置文件的 `security` 部分添加以下配置：

```json
{
  "security": {
    "enable_waf": true,
    "waf_rate_limit_enabled": true,
    "waf_rate_limit_window": 60,
    "waf_rate_limit_max_hits": 10,
    "waf_rate_limit_block_sec": 3600
  }
}
```

### 参数说明

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `waf_rate_limit_enabled` | bool | false | 是否启用 WAF 频率限制 |
| `waf_rate_limit_window` | int | 60 | 时间窗口（秒），在此时间内统计触发次数 |
| `waf_rate_limit_max_hits` | int | 10 | 时间窗口内的最大触发次数 |
| `waf_rate_limit_block_sec` | int | 3600 | 封禁时长（秒），默认 1 小时 |

## 配置示例

### 示例 1：严格模式（推荐用于生产环境）

```json
{
  "waf_rate_limit_enabled": true,
  "waf_rate_limit_window": 60,
  "waf_rate_limit_max_hits": 5,
  "waf_rate_limit_block_sec": 7200
}
```

- 60 秒内触发 5 次 WAF 规则 → 封禁 2 小时
- 适用于：生产环境、高安全要求的应用

### 示例 2：宽松模式（推荐用于测试环境）

```json
{
  "waf_rate_limit_enabled": true,
  "waf_rate_limit_window": 120,
  "waf_rate_limit_max_hits": 20,
  "waf_rate_limit_block_sec": 1800
}
```

- 120 秒内触发 20 次 WAF 规则 → 封禁 30 分钟
- 适用于：测试环境、开发环境

### 示例 3：超严格模式（用于遭受攻击时）

```json
{
  "waf_rate_limit_enabled": true,
  "waf_rate_limit_window": 30,
  "waf_rate_limit_max_hits": 3,
  "waf_rate_limit_block_sec": 86400
}
```

- 30 秒内触发 3 次 WAF 规则 → 封禁 24 小时
- 适用于：正在遭受攻击、需要极高安全性

## 使用场景

### 场景 1：防止恶意扫描

攻击者使用自动化工具扫描网站漏洞，会在短时间内触发大量 WAF 规则：

```
时间 0s:  访问 /.git/config        → 触发 WAF (1/10)
时间 2s:  访问 /.env                → 触发 WAF (2/10)
时间 4s:  访问 /admin.php           → 触发 WAF (3/10)
...
时间 18s: 访问 /wp-admin/           → 触发 WAF (10/10) → 🚫 IP 被封禁
```

### 场景 2：防止暴力破解

攻击者尝试暴力破解登录接口，触发 SQL 注入或 XSS 检测规则：

```
连续尝试各种注入攻击 → 快速达到阈值 → 自动封禁
```

### 场景 3：防止分布式扫描

即使攻击者使用多个 IP，每个 IP 也会被独立追踪和封禁。

## 日志输出

### 触发记录

当 IP 触发 WAF 规则时，会记录日志（带限流）：

```
WAF检测到敏感文件访问: Git配置文件 from 192.168.1.100, 路径: /.git/config, 动作: block
```

### 封禁通知

当 IP 被频率限制封禁时，会输出警告日志：

```
WAF 频率限制：IP 192.168.1.100 在 1m0s 内触发 10 次规则，已封禁 1h0m0s
```

### 封禁拦截

被封禁的 IP 再次访问时：

```
WAF 频率限制：IP 192.168.1.100 已被自动封禁
```

## API 接口

### 获取被封禁的 IP 列表

```http
GET /sslcat-panel/api/waf/rate-limit/blocked-ips
```

响应示例：

```json
{
  "success": true,
  "data": {
    "192.168.1.100": "2024-12-31T15:30:00Z",
    "10.0.0.50": "2024-12-31T16:00:00Z"
  }
}
```

### 解除 IP 封禁

```http
POST /sslcat-panel/api/waf/rate-limit/unblock
Content-Type: application/json

{
  "ip": "192.168.1.100"
}
```

### 更新频率限制配置

```http
POST /sslcat-panel/api/waf/rate-limit/config
Content-Type: application/json

{
  "enabled": true,
  "window_sec": 60,
  "max_hits": 10,
  "block_duration_sec": 3600
}
```

## 技术实现

### 数据结构

```go
type wafRateLimiter struct {
    ipHits        map[string][]time.Time // IP -> 触发时间列表
    blockedIPs    map[string]time.Time   // IP -> 封禁到期时间
    enabled       bool
    window        time.Duration
    maxHits       int
    blockDuration time.Duration
}
```

### 核心逻辑

1. **记录触发**：`RecordHit(ip)` - 记录 IP 触发事件
2. **检查封禁**：`IsBlocked(ip)` - 检查 IP 是否被封禁
3. **解除封禁**：`UnblockIP(ip)` - 手动解除封禁
4. **自动清理**：定期清理过期的封禁记录和触发历史

### 并发安全

- 使用 `sync.RWMutex` 保护共享数据
- 读操作使用读锁，写操作使用写锁
- 定期清理协程独立运行

## 性能影响

### 内存占用

- 每个 IP 的触发历史：约 24 字节 × 触发次数
- 每个被封禁的 IP：约 40 字节
- 总内存占用：通常 < 1 MB

### CPU 占用

- 每次请求检查：< 0.1 ms
- 定期清理：每 5 分钟一次，< 1 ms

### 性能优化

- 使用读写锁减少锁竞争
- 定期清理过期数据，防止内存泄漏
- 触发历史只保留时间窗口的 2 倍时间

## 与现有安全功能的关系

### 与 IP 黑名单的区别

| 特性 | WAF 频率限制 | IP 黑名单 |
|------|-------------|-----------|
| 触发方式 | 自动（基于行为） | 手动配置 |
| 封禁时长 | 临时（可配置） | 永久 |
| 适用场景 | 防止自动化攻击 | 封禁已知恶意 IP |
| 维护成本 | 低（自动化） | 高（需手动维护） |

### 与 WAF 规则的关系

- WAF 规则：检测和拦截单次攻击请求
- 频率限制：基于 WAF 规则的触发次数，自动封禁频繁攻击的 IP
- 两者配合使用，形成多层防护

## 最佳实践

### 1. 合理设置阈值

- **生产环境**：建议 60 秒内 5-10 次
- **测试环境**：建议 120 秒内 15-20 次
- **高流量网站**：适当提高阈值，避免误封

### 2. 监控封禁情况

- 定期检查被封禁的 IP 列表
- 分析封禁原因，优化 WAF 规则
- 及时解除误封的 IP

### 3. 配合其他安全措施

- 启用 IP 白名单，保护内部 IP
- 配置地理位置过滤，阻止特定国家
- 使用威胁情报，识别已知恶意 IP

### 4. 日志分析

- 关注频繁被封禁的 IP
- 分析触发的 WAF 规则类型
- 识别攻击模式，改进防护策略

## 故障排除

### 问题 1：正常用户被误封

**原因**：阈值设置过低，或用户行为触发了 WAF 规则

**解决方案**：
1. 检查 WAF 规则，排除误报
2. 提高频率限制阈值
3. 将该 IP 加入白名单

### 问题 2：攻击者未被封禁

**原因**：阈值设置过高，或攻击者使用了多个 IP

**解决方案**：
1. 降低频率限制阈值
2. 缩短时间窗口
3. 启用地理位置过滤

### 问题 3：封禁记录过多

**原因**：遭受大规模攻击，或配置不当

**解决方案**：
1. 检查日志，确认攻击来源
2. 启用地理位置过滤，从源头阻止
3. 考虑使用 CDN 或 DDoS 防护服务

## 版本信息

- 引入版本：v1.3.31-rc17
- 依赖：WAF 引擎 v2.0+
- 兼容性：向后兼容，默认禁用

## 相关文档

- [WAF 多维度封禁](waf-multi-dim-blocking.md)
- [WAF 概述](waf-overview.md)
- [封禁管理](blocking-management.md)


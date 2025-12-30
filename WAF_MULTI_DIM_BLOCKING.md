# WAF 多维度封禁策略

## 功能概述

WAF 多维度封禁策略是一个强大的安全防护功能，可以从多个维度自动检测和封禁恶意攻击者，有效应对分布式攻击和高级威胁。

### 支持的封禁维度

1. **IP 地址封禁** - 封禁单个恶意 IP
2. **TLS 指纹封禁** - 封禁使用相同工具/脚本的所有连接
3. **IP 段封禁** - 当同一网段内多个 IP 被封禁时，自动封禁整个网段

## 工作原理

```
客户端请求
    ↓
提取信息（IP、TLS 指纹）
    ↓
检查是否已被封禁
    ├─ IP 已封禁？ → 返回 403
    ├─ TLS 指纹已封禁？ → 返回 403
    └─ IP 段已封禁？ → 返回 403
    ↓
执行 WAF 规则检查
    ↓
触发规则？
    ├─ 是 → 记录触发事件
    │       ├─ 更新 IP 频率统计
    │       ├─ 更新 TLS 指纹统计
    │       └─ 更新 IP 段统计
    │       ↓
    │       检查是否达到阈值
    │       ├─ IP 达到阈值 → 封禁 IP
    │       ├─ TLS 达到阈值 → 封禁 TLS 指纹
    │       └─ 同段 3 个 IP 被封 → 封禁整个 IP 段
    └─ 否 → 允许请求
```

## 配置说明

### 配置文件示例

在 `config.json` 的 `security` 部分添加以下配置：

```json
{
  "security": {
    "enable_waf": true,
    
    "// IP 频率限制（已有）": "",
    "waf_rate_limit_enabled": true,
    "waf_rate_limit_window": 60,
    "waf_rate_limit_max_hits": 10,
    "waf_rate_limit_block_sec": 3600,
    
    "// TLS 指纹封禁（新增）": "",
    "waf_tls_block_enabled": true,
    "waf_tls_block_window": 60,
    "waf_tls_block_max_hits": 10,
    "waf_tls_block_duration_sec": 3600,
    
    "// IP 段封禁（新增）": "",
    "waf_subnet_block_enabled": true,
    "waf_subnet_mask": 24,
    "waf_subnet_threshold": 3,
    "waf_subnet_block_duration_sec": 7200
  }
}
```

### 配置参数详解

#### IP 维度配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `waf_rate_limit_enabled` | bool | false | 是否启用 IP 频率限制 |
| `waf_rate_limit_window` | int | 60 | 时间窗口（秒） |
| `waf_rate_limit_max_hits` | int | 10 | 时间窗口内最大触发次数 |
| `waf_rate_limit_block_sec` | int | 3600 | 封禁时长（秒），默认 1 小时 |

#### TLS 指纹维度配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `waf_tls_block_enabled` | bool | false | 是否启用 TLS 指纹封禁 |
| `waf_tls_block_window` | int | 60 | 时间窗口（秒） |
| `waf_tls_block_max_hits` | int | 10 | 时间窗口内最大触发次数 |
| `waf_tls_block_duration_sec` | int | 3600 | 封禁时长（秒），默认 1 小时 |

#### IP 段维度配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `waf_subnet_block_enabled` | bool | false | 是否启用 IP 段封禁 |
| `waf_subnet_mask` | int | 24 | 网段掩码（/24 = 256 个 IP） |
| `waf_subnet_threshold` | int | 3 | 同段被封 IP 数量阈值 |
| `waf_subnet_block_duration_sec` | int | 7200 | 封禁时长（秒），默认 2 小时 |

## 使用场景

### 场景 1：单个 IP 攻击

**攻击行为**：
```
IP 192.168.1.100 在 60 秒内访问：
- /.git/config
- /.env
- /admin.php
- /wp-config.php
- ... (共 10 次触发 WAF 规则)
```

**系统响应**：
1. 检测到 IP 192.168.1.100 在 60 秒内触发 10 次 WAF 规则
2. 自动封禁该 IP 1 小时
3. 该 IP 后续所有请求返回 403 Forbidden

**日志输出**：
```
WAF 多维度封禁：IP 192.168.1.100 已被封禁，原因：在 1m0s 内触发 10 次 WAF 规则，到期时间：2024-01-01T15:00:00Z
```

### 场景 2：同网段多 IP 攻击

**攻击行为**：
```
攻击者使用同一网段的多个 IP 进行扫描：
- 192.168.1.100 → 被封禁
- 192.168.1.101 → 被封禁
- 192.168.1.102 → 被封禁
```

**系统响应**：
1. 检测到 192.168.1.0/24 段内 3 个 IP 被封禁
2. 自动封禁整个 192.168.1.0/24 网段 2 小时
3. 该网段内所有 IP（192.168.1.0 - 192.168.1.255）的请求都被拦截

**日志输出**：
```
WAF 多维度封禁：IP 段 192.168.1.0/24 已被封禁，原因：网段内 3 个 IP 被封禁，到期时间：2024-01-01T16:00:00Z
```

### 场景 3：相同 TLS 指纹攻击

**攻击行为**：
```
攻击者使用自动化工具（如 Python requests）从不同 IP 发起攻击：
- IP 10.0.0.1 (TLS 指纹: abc123...) → 触发 WAF
- IP 10.0.0.2 (TLS 指纹: abc123...) → 触发 WAF
- IP 10.0.0.3 (TLS 指纹: abc123...) → 触发 WAF
... (共 10 次)
```

**系统响应**：
1. 检测到 TLS 指纹 `abc123...` 在 60 秒内触发 10 次 WAF 规则
2. 自动封禁该 TLS 指纹 1 小时
3. 所有使用该 TLS 指纹的连接（无论来自哪个 IP）都被拦截

**日志输出**：
```
WAF 多维度封禁：TLS 指纹 abc123... 已被封禁，原因：TLS 指纹在 1m0s 内触发 10 次 WAF 规则，涉及 3 个 IP，到期时间：2024-01-01T15:00:00Z
```

**优势**：
- 有效对抗使用相同工具/脚本的分布式攻击
- 即使攻击者更换 IP，仍然会被拦截
- 识别并阻止自动化攻击工具

## API 接口

### 1. 获取封禁列表

**请求**：
```http
GET /sslcat-panel/api/waf/blocked-list?dimension=ip
```

**参数**：
- `dimension` (可选): 封禁维度
  - `ip` - 仅返回 IP 封禁列表
  - `tls` - 仅返回 TLS 指纹封禁列表
  - `subnet` - 仅返回 IP 段封禁列表
  - 不传 - 返回所有维度的封禁列表

**响应示例**：
```json
{
  "success": true,
  "data": [
    {
      "dimension": "ip",
      "value": "192.168.1.100",
      "reason": "在 1m0s 内触发 10 次 WAF 规则",
      "expire_time": "2024-01-01T15:00:00Z",
      "hit_count": 10,
      "first_seen": "2024-01-01T14:00:00Z",
      "last_seen": "2024-01-01T14:01:00Z"
    },
    {
      "dimension": "tls_fingerprint",
      "value": "abc123def456...",
      "reason": "TLS 指纹在 1m0s 内触发 10 次 WAF 规则，涉及 3 个 IP",
      "expire_time": "2024-01-01T15:00:00Z",
      "hit_count": 10,
      "first_seen": "2024-01-01T14:00:00Z",
      "last_seen": "2024-01-01T14:01:00Z"
    },
    {
      "dimension": "ip_subnet",
      "value": "192.168.1.0/24",
      "reason": "网段内 3 个 IP 被封禁",
      "expire_time": "2024-01-01T16:00:00Z",
      "hit_count": 3,
      "first_seen": "2024-01-01T14:00:00Z",
      "last_seen": "2024-01-01T14:05:00Z"
    }
  ]
}
```

### 2. 解除封禁

**请求**：
```http
POST /sslcat-panel/api/waf/unblock
Content-Type: application/json

{
  "dimension": "ip",
  "value": "192.168.1.100"
}
```

**参数**：
- `dimension`: 封禁维度 (`ip`, `tls_fingerprint`, `ip_subnet`)
- `value`: 要解除封禁的值（IP 地址、TLS 指纹或 CIDR）

**响应示例**：
```json
{
  "success": true,
  "message": "Successfully unblocked ip: 192.168.1.100"
}
```

### 3. 获取 IP 段统计

**请求**：
```http
GET /sslcat-panel/api/waf/subnet-stats
```

**响应示例**：
```json
{
  "success": true,
  "data": {
    "192.168.1.0/24": 3,
    "10.0.0.0/24": 2,
    "172.16.0.0/24": 1
  }
}
```

### 4. 获取 TLS 指纹统计

**请求**：
```http
GET /sslcat-panel/api/waf/tls-stats
```

**响应示例**：
```json
{
  "success": true,
  "data": {
    "abc123def456...": 15,
    "xyz789ghi012...": 8,
    "mno345pqr678...": 3
  }
}
```

## 推荐配置

### 生产环境（标准）

适用于大多数生产环境：

```json
{
  "waf_rate_limit_enabled": true,
  "waf_rate_limit_window": 60,
  "waf_rate_limit_max_hits": 10,
  "waf_rate_limit_block_sec": 3600,
  
  "waf_tls_block_enabled": true,
  "waf_tls_block_window": 60,
  "waf_tls_block_max_hits": 10,
  "waf_tls_block_duration_sec": 3600,
  
  "waf_subnet_block_enabled": true,
  "waf_subnet_mask": 24,
  "waf_subnet_threshold": 3,
  "waf_subnet_block_duration_sec": 7200
}
```

### 生产环境（严格）

适用于高安全要求的环境：

```json
{
  "waf_rate_limit_enabled": true,
  "waf_rate_limit_window": 60,
  "waf_rate_limit_max_hits": 5,
  "waf_rate_limit_block_sec": 7200,
  
  "waf_tls_block_enabled": true,
  "waf_tls_block_window": 60,
  "waf_tls_block_max_hits": 5,
  "waf_tls_block_duration_sec": 7200,
  
  "waf_subnet_block_enabled": true,
  "waf_subnet_mask": 24,
  "waf_subnet_threshold": 2,
  "waf_subnet_block_duration_sec": 14400
}
```

### 测试环境（宽松）

适用于开发和测试环境：

```json
{
  "waf_rate_limit_enabled": true,
  "waf_rate_limit_window": 120,
  "waf_rate_limit_max_hits": 20,
  "waf_rate_limit_block_sec": 1800,
  
  "waf_tls_block_enabled": false,
  
  "waf_subnet_block_enabled": false
}
```

### 遭受攻击时（超严格）

当正在遭受大规模攻击时的紧急配置：

```json
{
  "waf_rate_limit_enabled": true,
  "waf_rate_limit_window": 30,
  "waf_rate_limit_max_hits": 3,
  "waf_rate_limit_block_sec": 86400,
  
  "waf_tls_block_enabled": true,
  "waf_tls_block_window": 30,
  "waf_tls_block_max_hits": 3,
  "waf_tls_block_duration_sec": 86400,
  
  "waf_subnet_block_enabled": true,
  "waf_subnet_mask": 16,
  "waf_subnet_threshold": 2,
  "waf_subnet_block_duration_sec": 86400
}
```

## 技术实现

### TLS 指纹提取

系统使用简化的 JA3 风格指纹：

```go
// 提取 TLS 连接信息
version := r.TLS.Version
cipherSuite := r.TLS.CipherSuite
serverName := r.TLS.ServerName

// 构建指纹字符串
raw := fmt.Sprintf("v=%d;cs=%d;sni=%s", version, cipherSuite, serverName)

// 计算 SHA256 哈希
hash := sha256.Sum256([]byte(raw))
fingerprint := hex.EncodeToString(hash[:])
```

### IP 段计算

```go
// 获取 IP 所属的 /24 网段
func getIPSubnet(ip string, mask int) string {
    parsed := net.ParseIP(ip)
    ipv4 := parsed.To4()
    
    cidr := fmt.Sprintf("%s/%d", 
        ipv4.Mask(net.CIDRMask(mask, 32)).String(), 
        mask)
    return cidr
}

// 示例：
// getIPSubnet("192.168.1.100", 24) → "192.168.1.0/24"
```

### 并发安全

所有操作使用 `sync.RWMutex` 保护：

```go
type wafMultiDimBlocker struct {
    mu sync.RWMutex
    
    ipBlocked     map[string]*BlockRecord
    tlsBlocked    map[string]*BlockRecord
    subnetBlocked map[string]*BlockRecord
    // ...
}

// 读操作使用读锁
func (b *wafMultiDimBlocker) IsBlocked(ip, tls string) (bool, BlockDimension, string) {
    b.mu.RLock()
    defer b.mu.RUnlock()
    // ...
}

// 写操作使用写锁
func (b *wafMultiDimBlocker) RecordHit(ip, tls string) {
    b.mu.Lock()
    defer b.mu.Unlock()
    // ...
}
```

### 性能优化

1. **读写分离**：读多写少场景使用读写锁
2. **定期清理**：每 5 分钟清理过期记录
3. **快速查找**：使用哈希表存储封禁记录
4. **内存限制**：限制最大记录数量，防止内存泄漏

## 监控与日志

### 日志示例

**IP 封禁**：
```
WAF 多维度封禁：IP 192.168.1.100 已被封禁，原因：在 1m0s 内触发 10 次 WAF 规则，到期时间：2024-01-01T15:00:00Z
```

**TLS 指纹封禁**：
```
WAF 多维度封禁：TLS 指纹 abc123... 已被封禁，原因：TLS 指纹在 1m0s 内触发 10 次 WAF 规则，涉及 3 个 IP，到期时间：2024-01-01T15:00:00Z
```

**IP 段封禁**：
```
WAF 多维度封禁：IP 段 192.168.1.0/24 已被封禁，原因：网段内 3 个 IP 被封禁，到期时间：2024-01-01T16:00:00Z
```

**解除封禁**：
```
WAF 多维度封禁：已解除 IP 192.168.1.100 的封禁
```

## 故障排除

### 问题 1：正常用户被误封

**原因**：
- 阈值设置过低
- 用户行为触发了 WAF 规则
- 共享 IP（如公司网络、VPN）

**解决方案**：
1. 检查封禁列表：`GET /api/waf/blocked-list`
2. 查看封禁原因和触发次数
3. 如果确认误封，手动解除：`POST /api/waf/unblock`
4. 调整阈值配置，提高 `max_hits` 或延长 `window`
5. 将该 IP 加入白名单

### 问题 2：攻击者未被封禁

**原因**：
- 阈值设置过高
- 攻击者使用了大量不同的 IP 和 TLS 指纹
- 攻击频率低于检测阈值

**解决方案**：
1. 降低阈值：减少 `max_hits`，缩短 `window`
2. 启用所有维度的封禁
3. 启用地理位置过滤，从源头阻止
4. 考虑使用 CDN 或 DDoS 防护服务

### 问题 3：IP 段误封导致大量用户无法访问

**原因**：
- IP 段阈值设置过低
- 封禁了共享 IP 段（如移动网络、公司网络）

**解决方案**：
1. 立即解除 IP 段封禁：`POST /api/waf/unblock`
2. 提高 IP 段阈值：增加 `subnet_threshold`
3. 考虑禁用 IP 段封禁：`waf_subnet_block_enabled: false`
4. 使用更精确的封禁策略（仅 IP 和 TLS 指纹）

## 最佳实践

1. **分阶段启用**：
   - 第一阶段：仅启用 IP 封禁
   - 第二阶段：启用 TLS 指纹封禁
   - 第三阶段：启用 IP 段封禁

2. **监控封禁情况**：
   - 定期检查封禁列表
   - 分析封禁原因和模式
   - 及时解除误封

3. **配合其他安全措施**：
   - IP 白名单保护内部 IP
   - 地理位置过滤阻止特定国家
   - 威胁情报识别已知恶意 IP

4. **日志分析**：
   - 关注频繁被封禁的 IP 段
   - 分析 TLS 指纹分布
   - 识别攻击模式和趋势

## 版本信息

- 引入版本：v1.3.31-rc18
- 依赖：WAF 引擎 v2.0+
- 兼容性：向后兼容，默认禁用

## 相关文档

- [WAF 频率限制功能](./WAF_RATE_LIMITING.md)
- [WAF 事件统计修复](./WAF_EVENT_TRACKING_FIX.md)
- [按域名配置 WAF](./WAF_DOMAIN_CONFIG.md)


# v1.3.31-rc18 更新日志

## 🎯 重大功能：WAF 多维度封禁策略

本版本实现了完整的 WAF 多维度封禁策略，可以从 IP、TLS 指纹、IP 段三个维度自动检测和封禁恶意攻击者。

## ✨ 新增功能

### 1. 多维度封禁器核心逻辑

**文件**: `internal/waf/multi_dim_blocker.go` (新建)

实现了三个维度的封禁策略：

- **IP 维度**: 封禁单个恶意 IP 地址
- **TLS 指纹维度**: 封禁使用相同工具/脚本的所有连接（无论 IP）
- **IP 段维度**: 当同一网段内多个 IP 被封禁时，自动封禁整个网段

**核心功能**：
- `RecordHit()`: 记录触发事件，更新各维度统计
- `IsBlocked()`: 检查是否被封禁（支持三个维度）
- `UnblockByDimension()`: 解除指定维度的封禁
- `GetBlockedList()`: 获取封禁列表
- `GetSubnetStats()`: 获取 IP 段统计
- `GetTLSStats()`: 获取 TLS 指纹统计

### 2. TLS 指纹提取

**文件**: `internal/web/server.go`

新增 `extractTLSFingerprint()` 方法：
- 从 TLS 连接提取版本、密码套件、SNI 等信息
- 生成 SHA256 哈希作为指纹
- 用于识别使用相同工具的攻击者

### 3. WAF 引擎集成

**文件**: `internal/waf/engine.go`

- 替换原有的 `rateLimiter` 为 `multiDimBlocker`
- 新增 `CheckRequestWithTLS()` 方法，支持传递 TLS 指纹
- 保持向后兼容，原有 `CheckRequest()` 仍然可用
- 新增多维度封禁管理方法：
  - `GetMultiDimBlockedList()`
  - `UnblockMultiDim()`
  - `GetSubnetStats()`
  - `GetTLSStats()`

**文件**: `internal/waf/advanced_engine.go`

- 新增 `CheckRequestAdvancedWithTLS()` 方法
- 保持向后兼容，原有 `CheckRequestAdvanced()` 仍然可用

### 4. 配置扩展

**文件**: `internal/config/config.go`

在 `SecurityConfig` 中新增配置字段：

```go
// TLS 指纹封禁配置
WAFTLSBlockEnabled     bool `json:"waf_tls_block_enabled"`
WAFTLSBlockWindow      int  `json:"waf_tls_block_window"`
WAFTLSBlockMaxHits     int  `json:"waf_tls_block_max_hits"`
WAFTLSBlockDurationSec int  `json:"waf_tls_block_duration_sec"`

// IP 段封禁配置
WAFSubnetBlockEnabled      bool `json:"waf_subnet_block_enabled"`
WAFSubnetMask              int  `json:"waf_subnet_mask"`
WAFSubnetThreshold         int  `json:"waf_subnet_threshold"`
WAFSubnetBlockDurationSec  int  `json:"waf_subnet_block_duration_sec"`
```

### 5. 管理 API

**文件**: `internal/web/api_waf.go`

新增 4 个 API 端点：

1. **GET `/api/waf/blocked-list`** - 获取封禁列表
   - 参数: `dimension` (可选): `ip`, `tls`, `subnet`
   - 返回: 封禁记录列表（包含维度、值、原因、到期时间等）

2. **POST `/api/waf/unblock`** - 解除封禁
   - 参数: `dimension`, `value`
   - 功能: 手动解除指定维度的封禁

3. **GET `/api/waf/subnet-stats`** - 获取 IP 段统计
   - 返回: 各 IP 段的被封 IP 数量

4. **GET `/api/waf/tls-stats`** - 获取 TLS 指纹统计
   - 返回: 各 TLS 指纹的触发次数

**文件**: `internal/web/server.go`

- 注册新的 API 路由
- 修改 WAF 检查逻辑，传递 TLS 指纹
- 初始化多维度封禁配置

## 📝 配置示例

### 标准生产环境配置

```json
{
  "security": {
    "enable_waf": true,
    
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
}
```

## 🔧 技术实现

### 并发安全

- 使用 `sync.RWMutex` 保护所有共享数据
- 读多写少场景使用读写锁优化性能
- 定期清理过期数据（每 5 分钟）

### 性能优化

- 哈希表快速查找封禁记录
- IP 段使用 CIDR 匹配
- 内存限制，防止泄漏

### 向后兼容

- 保留原有 API 接口
- 自动转换旧配置到新配置
- 默认禁用新功能，不影响现有用户

## 📚 文档

新增文档：
- `WAF_MULTI_DIM_BLOCKING.md` - 完整功能文档
- `config.example.multi-dim-blocking.json` - 配置示例

## 🎯 使用场景

### 场景 1：单个 IP 攻击
```
IP 192.168.1.100 在 60 秒内触发 10 次 WAF 规则
→ 系统自动封禁该 IP 1 小时
```

### 场景 2：同网段多 IP 攻击
```
192.168.1.100 被封禁
192.168.1.101 被封禁
192.168.1.102 被封禁
→ 系统自动封禁整个 192.168.1.0/24 段 2 小时
```

### 场景 3：相同 TLS 指纹攻击
```
不同 IP 使用相同工具（TLS 指纹相同）触发 10 次 WAF 规则
→ 系统封禁该 TLS 指纹 1 小时
→ 所有使用该指纹的连接都被拦截（无论 IP）
```

## 🔍 监控与管理

### 查看封禁列表
```bash
curl http://localhost/sslcat-panel/api/waf/blocked-list?dimension=ip
```

### 解除封禁
```bash
curl -X POST http://localhost/sslcat-panel/api/waf/unblock \
  -H "Content-Type: application/json" \
  -d '{"dimension":"ip","value":"192.168.1.100"}'
```

### 查看 IP 段统计
```bash
curl http://localhost/sslcat-panel/api/waf/subnet-stats
```

### 查看 TLS 指纹统计
```bash
curl http://localhost/sslcat-panel/api/waf/tls-stats
```

## ⚠️ 注意事项

1. **默认禁用**: 所有新功能默认禁用，需要手动配置启用
2. **阈值调整**: 建议根据实际情况调整阈值，避免误封
3. **监控封禁**: 定期检查封禁列表，及时解除误封
4. **分阶段启用**: 建议先启用 IP 封禁，观察效果后再启用其他维度

## 🐛 Bug 修复

无

## 🔄 兼容性

- ✅ 向后兼容 v1.3.31-rc17 及之前版本
- ✅ 配置文件兼容（新增字段可选）
- ✅ API 接口兼容（新增端点不影响现有接口）

## 📦 构建信息

- Go 版本: 1.21+
- 编译成功: ✅ 后端
- 编译成功: ✅ 前端

## 🚀 升级指南

1. 备份配置文件
2. 更新二进制文件
3. 重启服务
4. （可选）在配置文件中添加多维度封禁配置
5. （可选）通过 API 或管理面板启用新功能

## 👥 贡献者

- 实现: AI Assistant
- 需求: @rocky

## 📅 发布日期

2024-12-31


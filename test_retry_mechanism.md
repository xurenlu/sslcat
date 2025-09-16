# SSL证书申请重试机制测试指南

## 🎯 重试机制功能概述

我们实现了一个智能的SSL证书申请重试机制，包含以下特性：

### ✅ 已实现的功能

1. **智能重试策略**
   - HTTP-01验证失败时自动切换到DNS-01验证
   - 最多重试3次（HTTP验证）+ 2次（DNS验证）
   - 递增等待时间：10s, 20s, 30s (HTTP) / 15s, 30s (DNS)

2. **域名解析预检查**
   - 申请前检查域名是否解析到当前服务器
   - 提供详细的解析状态信息
   - 提前预警可能的验证失败

3. **详细的错误处理和日志**
   - 每个步骤都有详细的日志记录
   - 区分不同类型的错误
   - 提供重试状态和进度信息

4. **API端点支持**
   - `/api/ssl/retry-config` - 获取重试配置信息
   - `/api/ssl/retry` - 手动触发重试
   - 增强的 `/api/ssl/generate` - 支持重试的批量申请

## 🧪 测试场景

### 场景1: 正常域名申请
```bash
# 测试域名正确解析到服务器的情况
curl -X POST http://localhost:8080/api/ssl/generate \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com"]}'
```

**预期结果**: 第一次HTTP-01验证成功，无需重试

### 场景2: 域名未解析到服务器
```bash
# 测试域名未解析到服务器的情况
curl -X POST http://localhost:8080/api/ssl/generate \
  -H "Content-Type: application/json" \
  -d '{"domains": ["unresolved-domain.com"]}'
```

**预期结果**: 
1. 域名解析预检查警告
2. HTTP-01验证失败
3. 自动切换到DNS-01验证（如果配置了DNS服务商）
4. 重试机制生效

### 场景3: 配置了DNS服务商的回退
```bash
# 先配置DNS服务商
curl -X POST http://localhost:8080/api/dns/providers/manage \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-cloudflare",
    "type": "cloudflare",
    "enabled": true,
    "api_key": "your-api-key",
    "zone_id": "your-zone-id"
  }'

# 然后申请证书
curl -X POST http://localhost:8080/api/ssl/generate \
  -H "Content-Type: application/json" \
  -d '{"domains": ["test-domain.com"]}'
```

**预期结果**: HTTP-01失败后自动使用DNS-01验证

### 场景4: 手动重试
```bash
# 手动触发重试
curl -X POST http://localhost:8080/api/ssl/retry \
  -H "Content-Type: application/json" \
  -d '{"domain": "failed-domain.com"}'
```

**预期结果**: 重新执行完整的重试流程

### 场景5: 获取重试配置
```bash
# 查看重试配置信息
curl -X GET http://localhost:8080/api/ssl/retry-config
```

**预期结果**: 返回重试配置和DNS服务商信息

## 📊 日志监控

### 关键日志信息
```bash
# 查看重试过程日志
tail -f data/audit.log | grep -E "(Certificate request|retry|validation|DNS)"

# 查看域名解析检查日志
tail -f data/audit.log | grep -E "(Domain resolution|resolves to)"
```

### 日志示例
```
[INFO] Certificate request attempt 1/3 for domain: example.com
[INFO] Domain resolution check for example.com: Domain correctly resolves to server IP: 192.168.1.100
[WARN] HTTP-01 validation failed for example.com (attempt 1): acme: authorization error
[INFO] Attempting DNS-01 validation for domain: example.com
[INFO] Using DNS provider: cloudflare for domain: example.com
[INFO] DNS certificate request attempt 1/2 for domain: example.com using provider: cloudflare
[INFO] Certificate request successful for domain: example.com (attempt 1)
```

## 🔧 配置验证

### 检查DNS服务商配置
```bash
curl -X GET http://localhost:8080/api/dns/providers
```

### 检查重试配置
```bash
curl -X GET http://localhost:8080/api/ssl/retry-config
```

**预期响应**:
```json
{
  "success": true,
  "config": {
    "retry_enabled": true,
    "max_retries": {
      "http_validation": 3,
      "dns_validation": 2
    },
    "retry_delays": {
      "http_validation": "10s, 20s, 30s",
      "dns_validation": "15s, 30s"
    },
    "fallback_strategy": "HTTP-01 -> DNS-01",
    "dns_providers": ["cloudflare"],
    "dns_available": true
  }
}
```

## 🎉 成功指标

重试机制成功的标志：
1. ✅ 编译无错误
2. ✅ API端点正常响应
3. ✅ 日志显示重试过程
4. ✅ 域名解析预检查工作
5. ✅ HTTP-01失败时自动切换到DNS-01
6. ✅ 重试次数和等待时间符合预期
7. ✅ 错误信息详细且有用

## 🚀 性能优化

重试机制的性能特点：
- **非阻塞**: 重试过程不会阻塞其他请求
- **智能等待**: 递增等待时间避免过度重试
- **资源清理**: 自动清理DNS挑战记录
- **并发安全**: 支持多个域名同时申请
- **内存友好**: 及时释放临时资源

## 📝 使用建议

1. **生产环境**: 建议配置DNS服务商作为备用验证方式
2. **监控**: 关注重试日志，及时发现问题
3. **域名准备**: 申请前确保域名正确解析
4. **批量申请**: 可以同时申请多个域名，系统会并行处理
5. **手动重试**: 失败后可以手动触发重试，无需重新配置

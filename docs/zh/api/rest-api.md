# REST API 文档

SSLcat 提供全面的 REST API，用于配置管理、监控和管理。

## 基本信息

- **基础 URL**: `http://localhost:18080/api/v1`
- **认证方式**: Bearer Token 或 Basic Auth
- **内容类型**: `application/json`
- **速率限制**: 每分钟 30 个请求（可配置）

## 认证

### Bearer Token 认证
```bash
curl -H "Authorization: Bearer your-api-key" \
     http://localhost:18080/api/v1/config
```

### 基本认证
```bash
curl -u username:password \
     http://localhost:18080/api/v1/config
```

## 配置管理

### 获取当前配置
```http
GET /api/v1/config
```

**响应:**
```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 80,
    "ssl_port": 443
  },
  "proxy": {
    "rules": [
      {
        "domain": "example.com",
        "target": "http://localhost:8080",
        "ssl": true
      }
    ]
  }
}
```

### 更新配置
```http
PUT /api/v1/config
Content-Type: application/json
```

**请求体:**
```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 80,
    "ssl_port": 443
  },
  "proxy": {
    "rules": [
      {
        "domain": "example.com",
        "target": "http://localhost:8080",
        "ssl": true
      }
    ]
  }
}
```

**响应:**
```json
{
  "status": "success",
  "message": "Configuration updated successfully"
}
```

## 代理规则管理

### 列出代理规则
```http
GET /api/v1/proxy/rules
```

**响应:**
```json
{
  "rules": [
    {
      "id": "rule-1",
      "domain": "example.com",
      "target": "http://localhost:8080",
      "ssl": true,
      "enabled": true
    }
  ]
}
```

### 创建代理规则
```http
POST /api/v1/proxy/rules
Content-Type: application/json
```

**请求体:**
```json
{
  "domain": "api.example.com",
  "target": "http://localhost:3000",
  "ssl": true,
  "load_balancing": {
    "enabled": true,
    "algorithm": "round_robin",
    "backends": [
      "http://localhost:3000",
      "http://localhost:3001"
    ]
  }
}
```

**响应:**
```json
{
  "id": "rule-2",
  "status": "created",
  "message": "Proxy rule created successfully"
}
```

### 更新代理规则
```http
PUT /api/v1/proxy/rules/{rule_id}
Content-Type: application/json
```

**请求体:**
```json
{
  "domain": "api.example.com",
  "target": "http://localhost:3000",
  "ssl": true,
  "load_balancing": {
    "enabled": true,
    "algorithm": "least_connections",
    "backends": [
      "http://localhost:3000",
      "http://localhost:3001",
      "http://localhost:3002"
    ]
  }
}
```

### 删除代理规则
```http
DELETE /api/v1/proxy/rules/{rule_id}
```

**响应:**
```json
{
  "status": "success",
  "message": "Proxy rule deleted successfully"
}
```

## SSL 证书管理

### 列出证书
```http
GET /api/v1/ssl/certificates
```

**响应:**
```json
{
  "certificates": [
    {
      "domain": "example.com",
      "provider": "letsencrypt",
      "status": "valid",
      "expires_at": "2024-12-31T23:59:59Z",
      "auto_renew": true
    }
  ]
}
```

### 创建证书
```http
POST /api/v1/ssl/certificates
Content-Type: application/json
```

**请求体:**
```json
{
  "domain": "api.example.com",
  "provider": "letsencrypt",
  "email": "admin@example.com",
  "auto_renew": true
}
```

### 续期证书
```http
POST /api/v1/ssl/certificates/{domain}/renew
```

**响应:**
```json
{
  "status": "success",
  "message": "Certificate renewal initiated"
}
```

## 负载均衡管理

### 列出后端
```http
GET /api/v1/load-balancer/backends
```

**响应:**
```json
{
  "backends": [
    {
      "id": "backend-1",
      "url": "http://localhost:8080",
      "status": "healthy",
      "response_time": "50ms",
      "last_check": "2024-01-01T12:00:00Z"
    }
  ]
}
```

### 添加后端
```http
POST /api/v1/load-balancer/backends
Content-Type: application/json
```

**请求体:**
```json
{
  "url": "http://localhost:8081",
  "weight": 1,
  "health_check": {
    "enabled": true,
    "path": "/health",
    "interval": 30
  }
}
```

### 更新后端状态
```http
PUT /api/v1/load-balancer/backends/{backend_id}/status
Content-Type: application/json
```

**请求体:**
```json
{
  "status": "disabled",
  "reason": "Maintenance"
}
```

## 监控和指标

### 获取指标
```http
GET /api/v1/metrics
```

**响应:**
```json
{
  "requests_total": 1000,
  "requests_per_second": 10.5,
  "response_time_avg": "50ms",
  "response_time_p95": "100ms",
  "response_time_p99": "200ms",
  "error_rate": 0.01,
  "active_connections": 50,
  "ssl_handshakes": 500,
  "cache_hits": 800,
  "cache_misses": 200
}
```

### 获取健康状态
```http
GET /api/v1/health
```

**响应:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
  "components": {
    "proxy": "healthy",
    "ssl": "healthy",
    "load_balancer": "healthy",
    "cache": "healthy"
  }
}
```

### 获取系统信息
```http
GET /api/v1/system/info
```

**响应:**
```json
{
  "version": "1.3.16-rc18",
  "uptime": "24h30m15s",
  "memory_usage": "128MB",
  "cpu_usage": "15%",
  "disk_usage": "2.1GB",
  "network_interfaces": [
    {
      "name": "eth0",
      "ip": "192.168.1.100",
      "status": "up"
    }
  ]
}
```

## 缓存管理

### 获取缓存统计
```http
GET /api/v1/cache/stats
```

**响应:**
```json
{
  "hits": 800,
  "misses": 200,
  "hit_rate": 0.8,
  "size": "50MB",
  "max_size": "100MB",
  "entries": 1000
}
```

### 清除缓存
```http
POST /api/v1/cache/clear
```

**响应:**
```json
{
  "status": "success",
  "message": "Cache cleared successfully"
}
```

### 按模式清除缓存
```http
POST /api/v1/cache/clear
Content-Type: application/json
```

**请求体:**
```json
{
  "pattern": "*.css",
  "domain": "example.com"
}
```

## 日志管理

### 获取日志
```http
GET /api/v1/logs
```

**查询参数:**
- `level`: 日志级别 (debug, info, warn, error)
- `limit`: 日志条目数量 (默认: 100)
- `since`: 开始时间 (ISO 8601 格式)

**响应:**
```json
{
  "logs": [
    {
      "timestamp": "2024-01-01T12:00:00Z",
      "level": "info",
      "message": "Request processed successfully",
      "fields": {
        "method": "GET",
        "url": "/api/users",
        "status": 200,
        "duration": "50ms"
      }
    }
  ]
}
```

### 设置日志级别
```http
PUT /api/v1/logs/level
Content-Type: application/json
```

**请求体:**
```json
{
  "level": "debug"
}
```

## 用户管理

### 列出用户
```http
GET /api/v1/users
```

**响应:**
```json
{
  "users": [
    {
      "id": "user-1",
      "username": "admin",
      "email": "admin@example.com",
      "role": "admin",
      "created_at": "2024-01-01T00:00:00Z",
      "last_login": "2024-01-01T12:00:00Z"
    }
  ]
}
```

### 创建用户
```http
POST /api/v1/users
Content-Type: application/json
```

**请求体:**
```json
{
  "username": "newuser",
  "email": "user@example.com",
  "password": "securepassword",
  "role": "user"
}
```

### 更新用户
```http
PUT /api/v1/users/{user_id}
Content-Type: application/json
```

**请求体:**
```json
{
  "email": "newemail@example.com",
  "role": "admin"
}
```

### 删除用户
```http
DELETE /api/v1/users/{user_id}
```

## 备份和恢复

### 创建备份
```http
POST /api/v1/backup
```

**响应:**
```json
{
  "backup_id": "backup-20240101-120000",
  "status": "created",
  "size": "1.2MB",
  "created_at": "2024-01-01T12:00:00Z"
}
```

### 列出备份
```http
GET /api/v1/backup
```

**响应:**
```json
{
  "backups": [
    {
      "id": "backup-20240101-120000",
      "size": "1.2MB",
      "created_at": "2024-01-01T12:00:00Z"
    }
  ]
}
```

### 恢复备份
```http
POST /api/v1/backup/{backup_id}/restore
```

**响应:**
```json
{
  "status": "success",
  "message": "Backup restored successfully"
}
```

## 错误响应

所有 API 端点都返回适当的 HTTP 状态码和错误消息：

### 400 Bad Request
```json
{
  "error": "bad_request",
  "message": "Invalid request parameters",
  "details": {
    "field": "domain",
    "issue": "Domain is required"
  }
}
```

### 401 Unauthorized
```json
{
  "error": "unauthorized",
  "message": "Authentication required"
}
```

### 403 Forbidden
```json
{
  "error": "forbidden",
  "message": "Insufficient permissions"
}
```

### 404 Not Found
```json
{
  "error": "not_found",
  "message": "Resource not found"
}
```

### 500 Internal Server Error
```json
{
  "error": "internal_error",
  "message": "Internal server error",
  "request_id": "req-123456"
}
```

## 速率限制

API 端点有速率限制以防止滥用：

- **认证端点**: 每分钟 5 个请求
- **配置端点**: 每分钟 10 个请求
- **监控端点**: 每分钟 60 个请求
- **其他端点**: 每分钟 30 个请求

响应中包含速率限制头部：
```
X-RateLimit-Limit: 30
X-RateLimit-Remaining: 25
X-RateLimit-Reset: 1640995200
```

## SDK 示例

### Python SDK
```python
import sslcat

client = sslcat.Client(
    base_url="http://localhost:18080/api/v1",
    api_key="your-api-key"
)

# 获取配置
config = client.get_config()

# 创建代理规则
rule = client.create_proxy_rule({
    "domain": "api.example.com",
    "target": "http://localhost:3000",
    "ssl": True
})

# 获取指标
metrics = client.get_metrics()
```

### Node.js SDK
```javascript
const SSLcat = require('sslcat-sdk');

const client = new SSLcat({
  baseUrl: 'http://localhost:18080/api/v1',
  apiKey: 'your-api-key'
});

// 获取配置
const config = await client.getConfig();

// 创建代理规则
const rule = await client.createProxyRule({
  domain: 'api.example.com',
  target: 'http://localhost:3000',
  ssl: true
});

// 获取指标
const metrics = await client.getMetrics();
```

### Go SDK
```go
package main

import (
    "github.com/xurenlu/sslcat-sdk-go"
)

func main() {
    client := sslcat.NewClient(
        "http://localhost:18080/api/v1",
        "your-api-key",
    )
    
    // 获取配置
    config, err := client.GetConfig()
    
    // 创建代理规则
    rule, err := client.CreateProxyRule(sslcat.ProxyRule{
        Domain: "api.example.com",
        Target: "http://localhost:3000",
        SSL: true,
    })
    
    // 获取指标
    metrics, err := client.GetMetrics()
}
```

## Webhook 集成

### 配置 Webhook
```http
POST /api/v1/webhooks
Content-Type: application/json
```

**请求体:**
```json
{
  "url": "https://your-app.com/webhook",
  "events": ["config_changed", "certificate_expired"],
  "secret": "webhook-secret"
}
```

### Webhook 负载示例
```json
{
  "event": "config_changed",
  "timestamp": "2024-01-01T12:00:00Z",
  "data": {
    "change_type": "proxy_rule_added",
    "rule_id": "rule-1",
    "domain": "example.com"
  }
}
```

## 相关文档

- [Web 界面](../administration/web-interface.md)
- [CLI 命令](../administration/cli-commands.md)
- [配置指南](../configuration/basic.md)
- [监控](../features/monitoring.md)

---

*这个 REST API 为 SSLcat 功能提供了全面的程序化访问，用于自动化和集成。*

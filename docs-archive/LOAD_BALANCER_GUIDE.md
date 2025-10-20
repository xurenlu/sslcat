# SSLcat 负载均衡器使用指南

## 概述

SSLcat 现在支持强大的负载均衡功能，可以将请求智能地分发到多个后端服务器，提供高可用性和更好的性能。

## 主要特性

### 🔄 负载均衡算法

- **Round Robin (轮询)**: 按顺序将请求分发到每个后端服务器
- **Weighted Round Robin (加权轮询)**: 根据权重分配请求，权重高的服务器处理更多请求
- **Least Connections (最少连接)**: 将请求发送到当前连接数最少的服务器
- **IP Hash (IP哈希)**: 基于客户端IP地址的哈希值选择服务器，确保同一客户端总是访问同一台服务器
- **Random (随机)**: 随机选择后端服务器
- **Consistent Hash (一致性哈希)**: 基于一致性哈希算法选择服务器

### 🏥 健康检查

- **自动健康检查**: 定期检查后端服务器的健康状态
- **多种检查方法**: 支持 GET、HEAD、POST 等HTTP方法
- **自定义检查路径**: 可为每个服务器配置不同的健康检查路径
- **状态码验证**: 验证返回的HTTP状态码
- **故障转移**: 自动将流量从不健康的服务器转移到健康的服务器

### 🔗 会话保持

- **Cookie会话保持**: 基于指定Cookie值保持会话
- **Header会话保持**: 基于HTTP头部保持会话
- **IP会话保持**: 基于客户端IP地址保持会话
- **TTL控制**: 可配置会话保持的时间

### 📊 监控和统计

- **实时统计**: 每个后端服务器的连接数、请求数、失败率等
- **响应时间监控**: 跟踪每个服务器的平均响应时间
- **健康状态监控**: 实时显示服务器健康状态

## 配置示例

### 基本负载均衡配置

```json
{
  "proxy": {
    "rules": [
      {
        "domain": "api.example.com",
        "enabled": true,
        "ssl_only": true,
        
        "load_balancer_enabled": true,
        "load_balancer_algorithm": "round_robin",
        "load_balancer_backends": [
          {
            "id": "api-server-1",
            "host": "192.168.1.10",
            "port": 8080,
            "weight": 1,
            "enabled": true
          },
          {
            "id": "api-server-2",
            "host": "192.168.1.11",
            "port": 8080,
            "weight": 1,
            "enabled": true
          }
        ]
      }
    ]
  }
}
```

### 带健康检查的配置

```json
{
  "proxy": {
    "rules": [
      {
        "domain": "web.example.com",
        "enabled": true,
        "ssl_only": true,
        
        "load_balancer_enabled": true,
        "load_balancer_algorithm": "weighted_round_robin",
        "load_balancer_backends": [
          {
            "id": "web-server-1",
            "host": "192.168.1.20",
            "port": 80,
            "weight": 3,
            "enabled": true,
            "health_check_enabled": true,
            "health_check_path": "/health",
            "health_check_method": "GET",
            "expected_status_code": 200
          },
          {
            "id": "web-server-2",
            "host": "192.168.1.21",
            "port": 80,
            "weight": 2,
            "enabled": true,
            "health_check_enabled": true,
            "health_check_path": "/health",
            "health_check_method": "GET",
            "expected_status_code": 200
          }
        ],
        
        "health_check_enabled": true,
        "health_check_interval": 30,
        "health_check_timeout": 5
      }
    ]
  }
}
```

### 会话保持配置

```json
{
  "proxy": {
    "rules": [
      {
        "domain": "app.example.com",
        "enabled": true,
        "ssl_only": true,
        
        "load_balancer_enabled": true,
        "load_balancer_algorithm": "least_conn",
        "load_balancer_backends": [
          {
            "id": "app-server-1",
            "host": "192.168.1.30",
            "port": 3000,
            "enabled": true
          },
          {
            "id": "app-server-2",
            "host": "192.168.1.31",
            "port": 3000,
            "enabled": true
          }
        ],
        
        "session_affinity_enabled": true,
        "session_affinity_method": "cookie",
        "session_affinity_cookie": "JSESSIONID",
        "session_affinity_ttl": 3600
      }
    ]
  }
}
```

## 配置参数详解

### 负载均衡器配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `load_balancer_enabled` | boolean | false | 是否启用负载均衡 |
| `load_balancer_algorithm` | string | "round_robin" | 负载均衡算法 |
| `load_balancer_backends` | array | [] | 后端服务器列表 |

### 后端服务器配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `id` | string | - | 后端服务器唯一标识 |
| `host` | string | - | 服务器地址 |
| `port` | number | - | 服务器端口 |
| `weight` | number | 1 | 权重（用于加权算法） |
| `enabled` | boolean | true | 是否启用此后端 |
| `priority` | number | 0 | 优先级（数字越小优先级越高） |

### 健康检查配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `health_check_enabled` | boolean | false | 是否启用健康检查 |
| `health_check_path` | string | "/" | 健康检查路径 |
| `health_check_interval` | number | 30 | 检查间隔（秒） |
| `health_check_timeout` | number | 5 | 检查超时（秒） |
| `health_check_method` | string | "GET" | HTTP方法 |
| `expected_status_code` | number | 200 | 期望的状态码 |

### 会话保持配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `session_affinity_enabled` | boolean | false | 是否启用会话保持 |
| `session_affinity_method` | string | "ip" | 会话保持方法 |
| `session_affinity_cookie` | string | - | Cookie名称（method为cookie时） |
| `session_affinity_header` | string | - | Header名称（method为header时） |
| `session_affinity_ttl` | number | 3600 | 会话保持时间（秒） |

### 故障转移配置

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `failover_enabled` | boolean | true | 是否启用故障转移 |
| `max_retries` | number | 3 | 最大重试次数 |
| `retry_interval` | number | 1 | 重试间隔（秒） |
| `failure_threshold` | number | 3 | 故障阈值 |
| `recovery_threshold` | number | 2 | 恢复阈值 |

## 负载均衡算法详解

### Round Robin (轮询)
```json
"load_balancer_algorithm": "round_robin"
```
按顺序将请求分发到每个后端服务器。这是最简单也是最常用的负载均衡算法。

### Weighted Round Robin (加权轮询)
```json
"load_balancer_algorithm": "weighted_round_robin"
```
根据服务器的权重分配请求。权重高的服务器会处理更多请求。适用于服务器性能不同的场景。

### Least Connections (最少连接)
```json
"load_balancer_algorithm": "least_conn"
```
将新请求发送到当前活跃连接数最少的服务器。适用于请求处理时间差异较大的场景。

### IP Hash (IP哈希)
```json
"load_balancer_algorithm": "ip_hash"
```
基于客户端IP地址的哈希值选择服务器。确保同一客户端总是访问同一台服务器。

### Random (随机)
```json
"load_balancer_algorithm": "random"
```
随机选择后端服务器。在服务器数量较多时，随机算法的效果接近轮询。

## 监控和管理

### 查看负载均衡状态

负载均衡器的状态信息会在响应头中包含：

```
X-Backend-ID: api-server-1
X-Backend-Address: 192.168.1.10:8080
X-Response-Time: 25ms
```

### 日志记录

负载均衡器会记录详细的日志信息：

```
INFO[2024-01-01T12:00:00Z] Selected backend api-server-1 (192.168.1.10:8080) for request to api.example.com
INFO[2024-01-01T12:00:01Z] Backend api-server-2 (192.168.1.11:8080) for domain api.example.com is now healthy
WARN[2024-01-01T12:00:02Z] Backend api-server-3 (192.168.1.12:8080) for domain api.example.com is now unhealthy
```

## 最佳实践

### 1. 健康检查配置
- 为所有后端服务器启用健康检查
- 使用专门的健康检查端点，如 `/health` 或 `/status`
- 设置合适的检查间隔，避免过于频繁的检查

### 2. 权重配置
- 根据服务器性能设置权重
- 高性能服务器设置更高的权重
- 定期评估和调整权重

### 3. 会话保持
- 对于有状态的应用启用会话保持
- 选择合适的会话保持方法
- 设置合理的TTL时间

### 4. 故障转移
- 启用故障转移确保高可用性
- 设置合适的重试次数和间隔
- 监控故障转移事件

### 5. 监控和告警
- 定期检查负载均衡器状态
- 监控后端服务器健康状态
- 设置告警机制

## 故障排除

### 常见问题

1. **后端服务器标记为不健康**
   - 检查健康检查路径是否正确
   - 验证期望的状态码
   - 检查网络连接

2. **负载分布不均匀**
   - 检查权重配置
   - 考虑使用不同的负载均衡算法
   - 监控连接数和响应时间

3. **会话保持不工作**
   - 验证Cookie或Header配置
   - 检查TTL设置
   - 确认客户端支持相应的会话机制

### 调试命令

查看负载均衡器状态：
```bash
curl -H "Host: api.example.com" http://localhost/health
```

查看详细日志：
```bash
tail -f ./data/access.log | grep "load_balancer"
```

## 性能优化

### 1. 连接池配置
- 设置合适的最大连接数
- 配置连接超时参数
- 启用长连接

### 2. 健康检查优化
- 使用轻量级的健康检查端点
- 设置合理的检查间隔
- 避免过于频繁的检查

### 3. 算法选择
- 根据应用特性选择合适的算法
- 对于无状态应用使用轮询或最少连接
- 对于有状态应用使用IP哈希或会话保持

通过合理配置和使用负载均衡功能，SSLcat 可以显著提高应用的可用性、性能和扩展性。

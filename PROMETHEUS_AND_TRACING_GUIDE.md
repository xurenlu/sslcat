# Prometheus 指标和请求追踪完整指南

> 📊 **版本**: v1.3.13-rc1  
> 📅 **最后更新**: 2024年10月12日  
> ✅ **状态**: 生产就绪

---

## 📋 目录

1. [功能概述](#功能概述)
2. [Prometheus 指标](#prometheus-指标)
3. [请求追踪](#请求追踪)
4. [使用指南](#使用指南)
5. [集成示例](#集成示例)
6. [最佳实践](#最佳实践)

---

## 🎯 功能概述

SSLcat 现在提供完整的可观测性支持：

### ✅ Prometheus 指标导出
- **标准格式**: 完全符合 Prometheus 标准
- **丰富指标**: HTTP、负载均衡、压缩、缓存、SSL、安全等全方位指标
- **自动记录**: 每个请求自动记录到 Prometheus
- **开箱即用**: 无需额外配置

### ✅ 分布式请求追踪
- **多标准支持**: W3C Trace Context、Zipkin B3、OpenTelemetry
- **完整追踪**: Request ID、Trace ID、Span ID、Parent ID
- **跨服务传播**: 自动传播追踪上下文到下游服务
- **灵活采样**: 支持100%或按比率采样

---

## 📊 Prometheus 指标

### 访问指标端点

```bash
# 访问 Prometheus 指标
curl http://your-server/metrics

# 示例输出
# HELP sslcat_http_requests_total Total number of HTTP requests
# TYPE sslcat_http_requests_total counter
sslcat_http_requests_total{domain="example.com",method="GET",status_code="200"} 1234

# HELP sslcat_http_request_duration_seconds HTTP request duration in seconds
# TYPE sslcat_http_request_duration_seconds histogram
sslcat_http_request_duration_seconds_bucket{domain="example.com",method="GET",le="0.005"} 100
sslcat_http_request_duration_seconds_bucket{domain="example.com",method="GET",le="0.01"} 250
...
```

### 可用指标列表

#### 1. HTTP 请求指标

| 指标名称 | 类型 | 标签 | 说明 |
|---------|------|------|------|
| `sslcat_http_requests_total` | Counter | domain, method, status_code | 总请求数 |
| `sslcat_http_request_duration_seconds` | Histogram | domain, method | 请求耗时 |
| `sslcat_http_response_size_bytes` | Histogram | domain, content_type | 响应大小 |

**示例查询 (PromQL)**:
```promql
# QPS (每秒请求数)
rate(sslcat_http_requests_total[5m])

# P95 响应时间
histogram_quantile(0.95, rate(sslcat_http_request_duration_seconds_bucket[5m]))

# 错误率
rate(sslcat_http_requests_total{status_code=~"5.."}[5m])
/ rate(sslcat_http_requests_total[5m])
```

#### 2. 负载均衡指标

| 指标名称 | 类型 | 标签 | 说明 |
|---------|------|------|------|
| `sslcat_backend_requests_total` | Counter | domain, backend_id, backend_address, status | 后端请求总数 |
| `sslcat_backend_request_duration_seconds` | Histogram | domain, backend_id | 后端请求耗时 |
| `sslcat_backend_healthy` | Gauge | domain, backend_id, backend_address | 后端健康状态 (1=健康, 0=不健康) |

**示例查询**:
```promql
# 各后端请求分布
sum by (backend_address) (rate(sslcat_backend_requests_total[5m]))

# 不健康的后端
sslcat_backend_healthy == 0

# 后端平均响应时间
avg by (backend_id) (rate(sslcat_backend_request_duration_seconds_sum[5m]))
/ avg by (backend_id) (rate(sslcat_backend_request_duration_seconds_count[5m]))
```

#### 3. 压缩指标

| 指标名称 | 类型 | 标签 | 说明 |
|---------|------|------|------|
| `sslcat_compression_ratio` | Histogram | algorithm, content_type | 压缩率 (原始大小/压缩后大小) |
| `sslcat_compression_total` | Counter | algorithm, result | 压缩操作总数 |

**示例查询**:
```promql
# 平均压缩率
avg(rate(sslcat_compression_ratio_sum[5m]))
/ avg(rate(sslcat_compression_ratio_count[5m]))

# Brotli vs Gzip 压缩率对比
avg by (algorithm) (rate(sslcat_compression_ratio_sum[5m])
/ rate(sslcat_compression_ratio_count[5m]))
```

#### 4. 缓存指标

| 指标名称 | 类型 | 标签 | 说明 |
|---------|------|------|------|
| `sslcat_cache_hits_total` | Counter | cache_type, domain | 缓存命中次数 |
| `sslcat_cache_misses_total` | Counter | cache_type, domain | 缓存未命中次数 |
| `sslcat_cache_size_bytes` | Gauge | cache_type | 缓存大小 |

**示例查询**:
```promql
# 缓存命中率
rate(sslcat_cache_hits_total[5m])
/ (rate(sslcat_cache_hits_total[5m]) + rate(sslcat_cache_misses_total[5m]))

# 缓存大小趋势
sslcat_cache_size_bytes
```

#### 5. SSL 证书指标

| 指标名称 | 类型 | 标签 | 说明 |
|---------|------|------|------|
| `sslcat_certificate_expiry` | Gauge | domain, issuer | 证书过期时间 (Unix timestamp) |
| `sslcat_certificate_status` | Gauge | domain, issuer | 证书状态 (1=有效, 0=无效) |

**示例查询**:
```promql
# 30天内即将过期的证书
(sslcat_certificate_expiry - time()) / 86400 < 30

# 无效的证书
sslcat_certificate_status == 0
```

#### 6. 安全指标

| 指标名称 | 类型 | 标签 | 说明 |
|---------|------|------|------|
| `sslcat_blocked_requests_total` | Counter | reason, source_ip | 被阻止的请求数 |
| `sslcat_security_events_total` | Counter | event_type, severity | 安全事件数 |

**示例查询**:
```promql
# 每秒阻止的请求数
rate(sslcat_blocked_requests_total[5m])

# 按原因统计被阻止的请求
sum by (reason) (rate(sslcat_blocked_requests_total[5m]))
```

#### 7. 系统指标

| 指标名称 | 类型 | 标签 | 说明 |
|---------|------|------|------|
| `sslcat_uptime_seconds` | Gauge | - | 服务运行时间 |
| `sslcat_config_reloads_total` | Counter | status | 配置重载次数 |

---

## 🔍 请求追踪

### 追踪信息

每个请求都会自动生成和传播以下追踪信息：

| Header | 说明 | 示例 |
|--------|------|------|
| `X-Request-ID` | 请求唯一标识 (16字符) | `a1b2c3d4e5f60708` |
| `X-Trace-ID` | 全局追踪ID (32字符) | `a1b2c3d4e5f60708090a0b0c0d0e0f10` |
| `X-Span-ID` | 当前Span ID (32字符) | `b2c3d4e5f6070809` |
| `X-Parent-ID` | 父Span ID (32字符) | `a1b2c3d4e5f60708` |
| `traceparent` | W3C Trace Context | `00-{trace-id}-{span-id}-01` |
| `X-B3-TraceId` | Zipkin B3 TraceId | `a1b2c3d4e5f60708090a0b0c0d0e0f10` |
| `X-B3-SpanId` | Zipkin B3 SpanId | `b2c3d4e5f6070809` |
| `X-B3-ParentSpanId` | Zipkin B3 ParentSpanId | `a1b2c3d4e5f60708` |

### 支持的追踪标准

#### 1. W3C Trace Context

```http
traceparent: 00-a1b2c3d4e5f60708090a0b0c0d0e0f10-b2c3d4e5f6070809-01
```

格式：`version-trace_id-span_id-flags`

#### 2. Zipkin B3

```http
X-B3-TraceId: a1b2c3d4e5f60708090a0b0c0d0e0f10
X-B3-SpanId: b2c3d4e5f6070809
X-B3-ParentSpanId: a1b2c3d4e5f60708
X-B3-Sampled: 1
```

#### 3. OpenTelemetry

```http
baggage: key1=value1,key2=value2
```

### Baggage 传播

Baggage 是可以跨服务传播的键值对，用于传递业务上下文：

```http
baggage: user_id=12345,tenant=acme,priority=high
```

---

## 📖 使用指南

### 1. Prometheus 配置

在 Prometheus 配置文件中添加 SSLcat 作为抓取目标：

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'sslcat'
    static_configs:
      - targets: ['localhost:80']  # SSLcat 服务地址
    metrics_path: '/metrics'
    scrape_interval: 15s
    scrape_timeout: 10s
```

### 2. Grafana 仪表板

#### 导入预配置仪表板

```bash
# 下载 SSLcat Grafana 仪表板（TODO: 创建）
curl -O https://example.com/sslcat-dashboard.json

# 在 Grafana 中导入
# Dashboards -> Import -> Upload JSON file
```

#### 常用面板

1. **QPS 和响应时间**
```promql
# QPS
rate(sslcat_http_requests_total[5m])

# P50/P90/P99 响应时间
histogram_quantile(0.50, rate(sslcat_http_request_duration_seconds_bucket[5m]))
histogram_quantile(0.90, rate(sslcat_http_request_duration_seconds_bucket[5m]))
histogram_quantile(0.99, rate(sslcat_http_request_duration_seconds_bucket[5m]))
```

2. **错误率**
```promql
sum(rate(sslcat_http_requests_total{status_code=~"5.."}[5m]))
/ sum(rate(sslcat_http_requests_total[5m]))
```

3. **负载均衡状态**
```promql
# 健康后端数量
sum(sslcat_backend_healthy)

# 各后端请求分布
sum by (backend_address) (rate(sslcat_backend_requests_total[5m]))
```

### 3. 告警规则

```yaml
# alerts.yml
groups:
  - name: sslcat_alerts
    interval: 30s
    rules:
      # 高错误率告警
      - alert: HighErrorRate
        expr: |
          (sum(rate(sslcat_http_requests_total{status_code=~"5.."}[5m]))
          / sum(rate(sslcat_http_requests_total[5m]))) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "SSLcat 错误率过高"
          description: "错误率: {{ $value | humanizePercentage }}"

      # 后端不健康告警
      - alert: BackendDown
        expr: sslcat_backend_healthy == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "后端服务器不健康"
          description: "{{ $labels.backend_address }} 不健康"

      # 证书即将过期告警
      - alert: CertificateExpiringSoon
        expr: (sslcat_certificate_expiry - time()) / 86400 < 7
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "SSL证书即将过期"
          description: "{{ $labels.domain }} 的证书将在 7 天内过期"

      # 慢请求告警
      - alert: SlowRequests
        expr: |
          histogram_quantile(0.99,
            rate(sslcat_http_request_duration_seconds_bucket[5m])
          ) > 2
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "请求响应时间过长"
          description: "P99 响应时间: {{ $value }}s"
```

### 4. 请求追踪集成

#### 从客户端发起追踪

```bash
# 客户端生成 Trace ID 并发送请求
curl -H "X-Trace-ID: $(uuidgen | tr -d '-')" \
     -H "X-Span-ID: $(uuidgen | tr -d '-' | cut -c1-16)" \
     -v https://example.com/api/users

# 响应头中会包含追踪信息
# X-Request-ID: a1b2c3d4e5f60708
# X-Trace-ID: a1b2c3d4e5f60708090a0b0c0d0e0f10
# X-Span-ID: b2c3d4e5f6070809
```

#### 在应用中使用追踪信息

**Go 示例**:
```go
func myHandler(w http.ResponseWriter, r *http.Request) {
    // 获取追踪信息
    traceID := r.Header.Get("X-Trace-ID")
    requestID := r.Header.Get("X-Request-ID")
    
    // 添加到日志
    log.WithFields(log.Fields{
        "trace_id":   traceID,
        "request_id": requestID,
    }).Info("Processing request")
    
    // 传播到下游服务
    req, _ := http.NewRequest("GET", "http://backend/api", nil)
    req.Header.Set("X-Trace-ID", traceID)
    req.Header.Set("X-Request-ID", requestID)
    req.Header.Set("X-Parent-ID", r.Header.Get("X-Span-ID"))
    
    resp, _ := http.DefaultClient.Do(req)
    // ...
}
```

**JavaScript/Node.js 示例**:
```javascript
const axios = require('axios');

async function makeRequest() {
    const traceId = require('crypto').randomBytes(16).toString('hex');
    const spanId = require('crypto').randomBytes(8).toString('hex');
    
    const response = await axios.get('https://example.com/api/data', {
        headers: {
            'X-Trace-ID': traceId,
            'X-Span-ID': spanId
        }
    });
    
    // 追踪信息在响应头中
    console.log('Request ID:', response.headers['x-request-id']);
    console.log('Trace ID:', response.headers['x-trace-id']);
}
```

---

## 🎯 集成示例

### 完整的监控栈

```yaml
version: '3.8'

services:
  # SSLcat
  sslcat:
    image: sslcat/sslcat:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./sslcat.conf:/etc/sslcat/sslcat.conf
      - ./data:/data

  # Prometheus
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/usr/share/prometheus/console_libraries'
      - '--web.console.templates=/usr/share/prometheus/consoles'

  # Grafana
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana-dashboards:/etc/grafana/provisioning/dashboards
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false

  # Alertmanager (可选)
  alertmanager:
    image: prom/alertmanager:latest
    ports:
      - "9093:9093"
    volumes:
      - ./alertmanager.yml:/etc/alertmanager/alertmanager.yml
      - alertmanager_data:/alertmanager

volumes:
  prometheus_data:
  grafana_data:
  alertmanager_data:
```

启动：
```bash
docker-compose up -d

# 访问服务
# Prometheus: http://localhost:9090
# Grafana: http://localhost:3000 (admin/admin)
# Alertmanager: http://localhost:9093
```

---

## 💡 最佳实践

### 1. Prometheus 指标

#### ✅ 推荐做法

- **合理的抓取间隔**: 15-30秒对大多数场景足够
- **使用标签过滤**: 避免高基数标签（如用户ID、请求路径）
- **设置告警**: 对关键指标设置告警规则
- **定期清理**: 配置合理的数据保留期限

```yaml
# 推荐的 Prometheus 配置
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'production'
    
# 数据保留
--storage.tsdb.retention.time=15d
--storage.tsdb.retention.size=10GB
```

#### ❌ 避免的做法

- ❌ 过短的抓取间隔（< 5秒）- 增加服务器负载
- ❌ 在标签中使用高基数值（如完整URL、IP地址）
- ❌ 暴露 `/metrics` 到公网（应该只允许内网访问）

### 2. 请求追踪

#### ✅ 推荐做法

- **统一追踪格式**: 在整个系统中使用相同的追踪标准
- **记录到日志**: 在应用日志中包含 trace_id 和 request_id
- **采样策略**: 生产环境使用 10-20% 采样率即可
- **保留上下文**: 在异步任务和消息队列中传递追踪ID

```go
// 在日志中包含追踪信息
log.WithFields(log.Fields{
    "trace_id":   span.Context.TraceID,
    "request_id": span.Context.RequestID,
    "span_id":    span.Context.SpanID,
}).Info("Processing order")
```

#### ❌ 避免的做法

- ❌ 100% 采样（除非在开发/测试环境）
- ❌ 忘记传播追踪上下文到下游服务
- ❌ 在错误消息中暴露内部追踪ID给最终用户

### 3. 性能考虑

- **指标记录**: 异步记录，不阻塞请求
- **采样率**: 根据流量调整（高流量 10%，低流量 100%）
- **内存限制**: Prometheus 需要足够内存（建议至少 2GB）
- **存储规划**: 每个时间序列约 1-2 bytes/sample

### 4. 安全建议

- **限制访问**: `/metrics` 端点应该只对内网或可信IP开放
- **敏感信息**: 不要在标签中包含密码、密钥等敏感信息
- **认证**: 如果暴露到公网，使用 HTTP Basic Auth 或 TLS 客户端证书

```nginx
# Nginx 反向代理示例
location /metrics {
    allow 10.0.0.0/8;      # 允许内网
    allow 192.168.0.0/16;  # 允许内网
    deny all;              # 拒绝其他
    
    proxy_pass http://sslcat:80/metrics;
}
```

---

## 🔧 故障排查

### 问题 1: Prometheus 无法抓取指标

**症状**: Prometheus targets 显示 "Down"

**解决方案**:
```bash
# 1. 检查 SSLcat /metrics 端点是否可访问
curl http://localhost/metrics

# 2. 检查网络连接
telnet localhost 80

# 3. 检查 Prometheus 日志
docker logs prometheus

# 4. 检查防火墙规则
sudo iptables -L | grep 80
```

### 问题 2: 追踪ID 不连续

**症状**: 上下游服务的 Trace ID 不一致

**解决方案**:
- 确保在所有HTTP请求中传播追踪头
- 检查中间件或网关是否覆盖了追踪头
- 使用标准的追踪头名称（X-Trace-ID, traceparent等）

### 问题 3: Grafana 无法查询数据

**症状**: Grafana 面板显示 "No data"

**解决方案**:
```bash
# 1. 测试 Prometheus 查询
curl 'http://localhost:9090/api/v1/query?query=sslcat_http_requests_total'

# 2. 检查 Grafana 数据源配置
# Settings -> Data Sources -> Prometheus

# 3. 检查时间范围是否正确
```

---

## 📚 相关资源

- [Prometheus 官方文档](https://prometheus.io/docs/)
- [Grafana 文档](https://grafana.com/docs/)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)
- [OpenTelemetry](https://opentelemetry.io/)
- [Zipkin B3 Propagation](https://github.com/openzipkin/b3-propagation)

---

## 🎉 总结

通过 Prometheus 指标和请求追踪，SSLcat 提供了企业级的可观测性能力：

✅ **完整指标**: 覆盖 HTTP、负载均衡、压缩、缓存、SSL、安全等所有维度  
✅ **标准追踪**: 支持 W3C、Zipkin B3、OpenTelemetry 等主流标准  
✅ **开箱即用**: 无需额外配置，自动记录所有请求  
✅ **生产就绪**: 10% 采样率，对性能影响极小

现在 SSLcat 在监控和追踪能力上**已与 Nginx 和 Caddy 持平甚至超越**！🚀

---

*最后更新: 2024年10月12日*


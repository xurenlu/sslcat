# 分布式追踪

SSLcat 提供全面的分布式追踪支持，让你能够跟踪整个微服务架构中的请求。

## 概述

分布式追踪允许你：
- **跟踪请求流**: 跟踪请求通过多个服务的路径
- **识别瓶颈**: 发现性能问题和慢操作
- **调试问题**: 理解复杂的请求路径和失败
- **监控依赖**: 跟踪服务间通信

## 支持的标准

SSLcat 支持多种追踪标准，确保与各种系统的兼容性：

### W3C Trace Context
- **头部**: `traceparent`, `tracestate`
- **格式**: `00-{trace-id}-{span-id}-{flags}`
- **示例**: `00-92ebd5e4a0c2befcaecd84569501ffab-7e9c28c5fcd62c065fbf1b6aa5b3e62a-01`

### Zipkin B3
- **头部**: `X-B3-TraceId`, `X-B3-SpanId`, `X-B3-ParentSpanId`
- **采样**: `X-B3-Sampled`, `X-B3-Flags`
- **示例**: `X-B3-TraceId: 92ebd5e4a0c2befcaecd84569501ffab`

### Google Cloud Trace
- **头部**: `X-Cloud-Trace-Context`
- **格式**: `{trace-id}/{span-id};o={options}`
- **示例**: `105445aa7843bc8bf206b120001000/0;o=1`

### AWS X-Ray
- **头部**: `X-Amzn-Trace-Id`
- **格式**: `Root={trace-id};Parent={span-id};Sampled={sampling}`
- **示例**: `Root=1-5e645f3e-1234567890abcdef;Parent=1234567890abcdef;Sampled=1`

### 自定义头部
- **追踪ID**: `X-Trace-ID`
- **Span ID**: `X-Span-ID`
- **请求ID**: `X-Request-ID`

## 配置

### 基础追踪设置

```yaml
# sslcat.conf
server:
  tracing:
    enabled: true
    service_name: "sslcat-proxy"
    sample_rate: 1.0  # 开发环境100%采样
```

### 高级配置

```yaml
server:
  tracing:
    enabled: true
    service_name: "sslcat-proxy"
    sample_rate: 0.1  # 生产环境10%采样
    
    # 导出配置
    exporters:
      jaeger:
        endpoint: "http://jaeger:14268/api/traces"
      zipkin:
        endpoint: "http://zipkin:9411/api/v2/spans"
      otlp:
        endpoint: "http://otel-collector:4317"
    
    # 保留的头部
    preserve_headers:
      - "traceparent"
      - "tracestate"
      - "X-B3-TraceId"
      - "X-B3-SpanId"
      - "X-Cloud-Trace-Context"
      - "X-Amzn-Trace-Id"
```

## 工作原理

### 1. 请求接收
当请求到达 SSLcat 时：
1. **提取追踪上下文**: 解析传入的追踪头部
2. **创建 Span**: 为 SSLcat 处理生成新的 span
3. **保持上下文**: 为上游请求维护追踪上下文

### 2. 上游传播
当转发到后端服务时：
1. **注入头部**: 向上游请求添加追踪头部
2. **维护上下文**: 确保追踪连续性
3. **记录操作**: 在 span 中记录代理操作

### 3. 响应处理
当处理响应时：
1. **完成 Span**: 用时间信息完成 SSLcat span
2. **添加属性**: 包含响应元数据
3. **错误处理**: 记录错误和异常

## 集成示例

### Spring Boot 集成

```java
@RestController
public class ApiController {
    
    @GetMapping("/users/{id}")
    public ResponseEntity<User> getUser(@PathVariable String id) {
        // Spring Boot 自动创建 span
        // SSLcat 追踪头部自动传播
        
        User user = userService.findById(id);
        return ResponseEntity.ok(user);
    }
}
```

### Node.js 集成

```javascript
const express = require('express');
const { trace } = require('@opentelemetry/api');

const app = express();

app.get('/api/users/:id', (req, res) => {
  const tracer = trace.getActiveSpan();
  
  // SSLcat 追踪头部在 req.headers 中可用
  console.log('Trace ID:', req.headers['x-trace-id']);
  
  // 你的业务逻辑
  res.json({ id: req.params.id, name: 'User' });
});
```

### Python 集成

```python
from flask import Flask, request
from opentelemetry import trace

app = Flask(__name__)

@app.route('/api/users/<user_id>')
def get_user(user_id):
    # SSLcat 追踪头部在 request.headers 中可用
    trace_id = request.headers.get('X-Trace-ID')
    
    # 你的业务逻辑
    return {'id': user_id, 'name': 'User'}
```

## 监控和可视化

### Jaeger 集成
```yaml
# Docker Compose 示例
version: '3.8'
services:
  sslcat:
    image: sslcat:latest
    environment:
      - JAEGER_ENDPOINT=http://jaeger:14268/api/traces
    depends_on:
      - jaeger
  
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"
```

### Zipkin 集成
```yaml
# Docker Compose 示例
version: '3.8'
services:
  sslcat:
    image: sslcat:latest
    environment:
      - ZIPKIN_ENDPOINT=http://zipkin:9411/api/v2/spans
    depends_on:
      - zipkin
  
  zipkin:
    image: openzipkin/zipkin:latest
    ports:
      - "9411:9411"
```

## 最佳实践

### 1. 采样配置
```yaml
# 开发环境
sample_rate: 1.0  # 100% 采样

# 生产环境
sample_rate: 0.1  # 10% 采样
```

### 2. 头部保留
```yaml
# 保留所有追踪头部
preserve_headers:
  - "traceparent"
  - "tracestate"
  - "X-B3-*"
  - "X-Cloud-Trace-Context"
  - "X-Amzn-Trace-Id"
```

### 3. 服务命名
```yaml
# 使用描述性服务名称
service_name: "sslcat-proxy-{environment}"
```

### 4. 错误处理
```yaml
# 配置错误跟踪
tracing:
  error_handling:
    record_exceptions: true
    record_errors: true
```

## 故障排除

### 常见问题

1. **缺少追踪头部**
   - 检查是否启用了追踪
   - 验证头部保留设置
   - 确保上游服务支持追踪

2. **采样问题**
   - 为生产环境调整采样率
   - 检查追踪导出器配置
   - 验证网络连接

3. **性能影响**
   - 监控 CPU 和内存使用
   - 根据需要调整采样率
   - 使用异步导出器

### 调试模式
```yaml
server:
  debug: true
  tracing:
    debug: true
    log_traces: true
```

## 示例

### 完整的 Spring Boot 设置
查看我们的 [Spring Boot 集成指南](../integration/spring-boot.md) 获取完整示例。

### 微服务架构
查看我们的 [微服务指南](../integration/microservices.md) 了解复杂架构中的分布式追踪。

## 相关文档

- [Spring Boot 集成](../integration/spring-boot.md)
- [微服务架构](../integration/microservices.md)
- [监控和指标](monitoring.md)
- [故障排除指南](../troubleshooting/debugging.md)

---

*分布式追踪是理解和调试复杂系统的强大工具。SSLcat 让实现和维护变得简单。*

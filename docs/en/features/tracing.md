# Distributed Tracing

SSLcat provides comprehensive support for distributed tracing, enabling you to track requests across your entire microservices architecture.

## Overview

Distributed tracing allows you to:
- **Track Request Flow**: Follow requests through multiple services
- **Identify Bottlenecks**: Find performance issues and slow operations
- **Debug Issues**: Understand complex request paths and failures
- **Monitor Dependencies**: Track service-to-service communication

## Supported Standards

SSLcat supports multiple tracing standards to ensure compatibility with various systems:

### W3C Trace Context
- **Header**: `traceparent`, `tracestate`
- **Format**: `00-{trace-id}-{span-id}-{flags}`
- **Example**: `00-92ebd5e4a0c2befcaecd84569501ffab-7e9c28c5fcd62c065fbf1b6aa5b3e62a-01`

### Zipkin B3
- **Headers**: `X-B3-TraceId`, `X-B3-SpanId`, `X-B3-ParentSpanId`
- **Sampling**: `X-B3-Sampled`, `X-B3-Flags`
- **Example**: `X-B3-TraceId: 92ebd5e4a0c2befcaecd84569501ffab`

### Google Cloud Trace
- **Header**: `X-Cloud-Trace-Context`
- **Format**: `{trace-id}/{span-id};o={options}`
- **Example**: `105445aa7843bc8bf206b120001000/0;o=1`

### AWS X-Ray
- **Header**: `X-Amzn-Trace-Id`
- **Format**: `Root={trace-id};Parent={span-id};Sampled={sampling}`
- **Example**: `Root=1-5e645f3e-1234567890abcdef;Parent=1234567890abcdef;Sampled=1`

### Custom Headers
- **Trace ID**: `X-Trace-ID`
- **Span ID**: `X-Span-ID`
- **Request ID**: `X-Request-ID`

## Configuration

### Basic Tracing Setup

```yaml
# sslcat.conf
server:
  tracing:
    enabled: true
    service_name: "sslcat-proxy"
    sample_rate: 1.0  # 100% sampling for development
```

### Advanced Configuration

```yaml
server:
  tracing:
    enabled: true
    service_name: "sslcat-proxy"
    sample_rate: 0.1  # 10% sampling for production
    
    # Export configuration
    exporters:
      jaeger:
        endpoint: "http://jaeger:14268/api/traces"
      zipkin:
        endpoint: "http://zipkin:9411/api/v2/spans"
      otlp:
        endpoint: "http://otel-collector:4317"
    
    # Headers to preserve
    preserve_headers:
      - "traceparent"
      - "tracestate"
      - "X-B3-TraceId"
      - "X-B3-SpanId"
      - "X-Cloud-Trace-Context"
      - "X-Amzn-Trace-Id"
```

## How It Works

### 1. Request Ingestion
When a request arrives at SSLcat:
1. **Extract Trace Context**: Parse incoming trace headers
2. **Create Span**: Generate new span for SSLcat processing
3. **Preserve Context**: Maintain trace context for upstream requests

### 2. Upstream Propagation
When forwarding to backend services:
1. **Inject Headers**: Add trace headers to upstream requests
2. **Maintain Context**: Ensure trace continuity
3. **Log Operations**: Record proxy operations in spans

### 3. Response Processing
When handling responses:
1. **Complete Spans**: Finish SSLcat spans with timing
2. **Add Attributes**: Include response metadata
3. **Error Handling**: Record errors and exceptions

## Integration Examples

### Spring Boot Integration

```java
@RestController
public class ApiController {
    
    @GetMapping("/users/{id}")
    public ResponseEntity<User> getUser(@PathVariable String id) {
        // Spring Boot automatically creates spans
        // SSLcat trace headers are automatically propagated
        
        User user = userService.findById(id);
        return ResponseEntity.ok(user);
    }
}
```

### Node.js Integration

```javascript
const express = require('express');
const { trace } = require('@opentelemetry/api');

const app = express();

app.get('/api/users/:id', (req, res) => {
  const tracer = trace.getActiveSpan();
  
  // SSLcat trace headers are available in req.headers
  console.log('Trace ID:', req.headers['x-trace-id']);
  
  // Your business logic here
  res.json({ id: req.params.id, name: 'User' });
});
```

### Python Integration

```python
from flask import Flask, request
from opentelemetry import trace

app = Flask(__name__)

@app.route('/api/users/<user_id>')
def get_user(user_id):
    # SSLcat trace headers are available in request.headers
    trace_id = request.headers.get('X-Trace-ID')
    
    # Your business logic here
    return {'id': user_id, 'name': 'User'}
```

## Monitoring and Visualization

### Jaeger Integration
```yaml
# Docker Compose example
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

### Zipkin Integration
```yaml
# Docker Compose example
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

## Best Practices

### 1. Sampling Configuration
```yaml
# Development
sample_rate: 1.0  # 100% sampling

# Production
sample_rate: 0.1  # 10% sampling
```

### 2. Header Preservation
```yaml
# Preserve all trace headers
preserve_headers:
  - "traceparent"
  - "tracestate"
  - "X-B3-*"
  - "X-Cloud-Trace-Context"
  - "X-Amzn-Trace-Id"
```

### 3. Service Naming
```yaml
# Use descriptive service names
service_name: "sslcat-proxy-{environment}"
```

### 4. Error Handling
```yaml
# Configure error tracking
tracing:
  error_handling:
    record_exceptions: true
    record_errors: true
```

## Troubleshooting

### Common Issues

1. **Missing Trace Headers**
   - Check if tracing is enabled
   - Verify header preservation settings
   - Ensure upstream services support tracing

2. **Sampling Issues**
   - Adjust sample rate for production
   - Check trace exporter configuration
   - Verify network connectivity

3. **Performance Impact**
   - Monitor CPU and memory usage
   - Adjust sampling rate if needed
   - Use async exporters

### Debug Mode
```yaml
server:
  debug: true
  tracing:
    debug: true
    log_traces: true
```

## Examples

### Complete Spring Boot Setup
See our [Spring Boot Integration Guide](../integration/spring-boot.md) for a complete example.

### Microservices Architecture
See our [Microservices Guide](../integration/microservices.md) for distributed tracing in complex architectures.

## Related Documentation

- [Spring Boot Integration](../integration/spring-boot.md)
- [Microservices Architecture](../integration/microservices.md)
- [Monitoring and Metrics](monitoring.md)
- [Troubleshooting Guide](../troubleshooting/debugging.md)

---

*Distributed tracing is a powerful tool for understanding and debugging complex systems. SSLcat makes it easy to implement and maintain.*

# 基础配置

本指南介绍 SSLcat 的基础配置，包括服务器设置、代理规则、SSL 证书和基本功能。

## 服务器配置

### 基本设置
```yaml
# sslcat.conf
server:
  host: "0.0.0.0"        # 监听地址
  port: 80               # HTTP 端口
  ssl_port: 443         # HTTPS 端口
  debug: false          # 调试模式
```

### 高级服务器设置
```yaml
server:
  host: "0.0.0.0"
  port: 80
  ssl_port: 443
  debug: false
  
  # 性能设置
  workers: 4             # 工作进程数
  max_connections: 1000  # 最大连接数
  keep_alive_timeout: 30s
  read_timeout: 30s
  write_timeout: 30s
  
  # 日志设置
  log_level: "info"     # debug, info, warn, error
  log_format: "json"    # json, text
```

## 代理规则配置

### 基本代理规则
```yaml
# sslcat.conf
proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:8080"
      ssl: true
```

### 高级代理规则
```yaml
proxy:
  rules:
    - domain: "api.example.com"
      target: "http://localhost:8080"
      ssl: true
      path: "/api"       # 路径匹配
      path_rewrite: "/v1" # 路径重写
      
      # 头部设置
      headers:
        pass_through: true
        add:
          X-Forwarded-Proto: "https"
          X-Real-IP: "$remote_addr"
        remove: ["X-Forwarded-For"]
```

### 多域名配置
```yaml
proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:8080"
      ssl: true
    
    - domain: "api.example.com"
      target: "http://localhost:3000"
      ssl: true
    
    - domain: "admin.example.com"
      target: "http://localhost:4000"
      ssl: true
```

## SSL 证书配置

### Let's Encrypt 自动证书
```yaml
# sslcat.conf
ssl:
  certificates:
    - domain: "example.com"
      provider: "letsencrypt"
      email: "admin@example.com"
      auto_renew: true
```

### 自定义证书
```yaml
ssl:
  certificates:
    - domain: "example.com"
      cert_file: "/path/to/cert.pem"
      key_file: "/path/to/key.pem"
      chain_file: "/path/to/chain.pem"
```

### 多域名证书
```yaml
ssl:
  certificates:
    - domain: "example.com"
      provider: "letsencrypt"
      email: "admin@example.com"
      auto_renew: true
      subdomains: ["www", "api", "admin"]
```

## 负载均衡配置

### 基本负载均衡
```yaml
proxy:
  rules:
    - domain: "api.example.com"
      target: "http://localhost:8080"
      ssl: true
      load_balancing:
        enabled: true
        algorithm: "round_robin"
        backends:
          - "http://localhost:8080"
          - "http://localhost:8081"
          - "http://localhost:8082"
```

### 高级负载均衡
```yaml
proxy:
  rules:
    - domain: "api.example.com"
      target: "http://localhost:8080"
      ssl: true
      load_balancing:
        enabled: true
        algorithm: "least_connections"
        backends:
          - url: "http://localhost:8080"
            weight: 3
            max_connections: 100
          - url: "http://localhost:8081"
            weight: 2
            max_connections: 50
          - url: "http://localhost:8082"
            weight: 1
            max_connections: 25
        
        # 健康检查
        health_check:
          enabled: true
          path: "/health"
          interval: 30s
          timeout: 5s
          retries: 3
```

## 缓存配置

### 基本缓存
```yaml
proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:8080"
      ssl: true
      caching:
        enabled: true
        ttl: 3600  # 1小时
        max_size: "100MB"
```

### 高级缓存
```yaml
proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:8080"
      ssl: true
      caching:
        enabled: true
        ttl: 3600
        max_size: "100MB"
        max_entries: 10000
        
        # 缓存策略
        policies:
          - path: "/static/*"
            ttl: 86400  # 24小时
          - path: "/api/cacheable/*"
            ttl: 300   # 5分钟
          - path: "/api/dynamic/*"
            ttl: 0     # 不缓存
```

## 压缩配置

### 基本压缩
```yaml
proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:8080"
      ssl: true
      compression:
        enabled: true
        types: ["text/html", "text/css", "application/javascript"]
```

### 高级压缩
```yaml
proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:8080"
      ssl: true
      compression:
        enabled: true
        algorithm: "gzip"
        min_size: 1024
        max_size: 10485760  # 10MB
        types: ["text/html", "text/css", "application/javascript", "application/json"]
```

## 监控配置

### 基本监控
```yaml
# sslcat.conf
monitoring:
  metrics:
    enabled: true
    endpoint: "/metrics"
    port: 8080
```

### 高级监控
```yaml
monitoring:
  metrics:
    enabled: true
    endpoint: "/metrics"
    port: 8080
    
    # Prometheus 指标
    prometheus:
      enabled: true
      path: "/metrics"
      format: "prometheus"
  
  # 分布式追踪
  tracing:
    enabled: true
    service_name: "sslcat-proxy"
    sample_rate: 0.1  # 10%采样
    
    # 追踪导出器
    exporters:
      jaeger:
        endpoint: "http://jaeger:14268/api/traces"
      zipkin:
        endpoint: "http://zipkin:9411/api/v2/spans"
```

## 安全配置

### 基本安全设置
```yaml
# sslcat.conf
security:
  # DDoS 防护
  ddos_protection:
    enabled: true
    rate_limit: 100  # 每秒请求数
    burst_size: 200  # 突发请求数
  
  # 访问控制
  access_control:
    enabled: true
    whitelist: ["192.168.1.0/24"]
    blacklist: ["192.168.1.100"]
```

### 高级安全设置
```yaml
security:
  # DDoS 防护
  ddos_protection:
    enabled: true
    rate_limiting:
      global:
        requests_per_second: 1000
        burst_size: 2000
      per_ip:
        requests_per_second: 10
        burst_size: 20
  
  # 访问控制
  access_control:
    enabled: true
    ip_filtering:
      whitelist: ["192.168.1.0/24", "10.0.0.0/8"]
      blacklist: ["192.168.1.100"]
      default_policy: "deny"
  
  # 安全头部
  security_headers:
    enabled: true
    hsts: true
    xss_protection: true
    content_type_options: true
    frame_options: "DENY"
```

## 日志配置

### 基本日志设置
```yaml
# sslcat.conf
logging:
  level: "info"
  format: "json"
  output: "stdout"
```

### 高级日志设置
```yaml
logging:
  level: "info"
  format: "json"
  
  # 日志输出
  outputs:
    - type: "file"
      path: "/var/log/sslcat/sslcat.log"
      max_size: "100MB"
      max_files: 5
      compress: true
    
    - type: "syslog"
      host: "localhost"
      port: 514
      facility: "local0"
  
  # 结构化日志
  structured:
    enabled: true
    fields:
      timestamp: true
      level: true
      message: true
      request_id: true
      trace_id: true
      span_id: true
```

## 完整配置示例

### 生产环境配置
```yaml
# sslcat.conf
server:
  host: "0.0.0.0"
  port: 80
  ssl_port: 443
  debug: false
  workers: 4
  max_connections: 1000

proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:8080"
      ssl: true
      load_balancing:
        enabled: true
        algorithm: "round_robin"
        backends:
          - "http://localhost:8080"
          - "http://localhost:8081"
          - "http://localhost:8082"
        health_check:
          enabled: true
          path: "/health"
          interval: 30s
      caching:
        enabled: true
        ttl: 3600
        max_size: "100MB"
      compression:
        enabled: true
        types: ["text/html", "text/css", "application/javascript"]

ssl:
  certificates:
    - domain: "example.com"
      provider: "letsencrypt"
      email: "admin@example.com"
      auto_renew: true

monitoring:
  metrics:
    enabled: true
    endpoint: "/metrics"
  tracing:
    enabled: true
    sample_rate: 0.1

security:
  ddos_protection:
    enabled: true
    rate_limit: 100
  access_control:
    enabled: true
    whitelist: ["192.168.1.0/24"]

logging:
  level: "info"
  format: "json"
```

## 配置验证

### 验证配置
```bash
# 验证配置文件
sslcat -config sslcat.conf -validate

# 测试配置
sslcat -config sslcat.conf -test

# 显示配置
sslcat -config sslcat.conf -show-config
```

### 启动服务
```bash
# 启动 SSLcat
sslcat -config sslcat.conf

# 后台运行
sslcat -config sslcat.conf -daemon

# 调试模式
sslcat -config sslcat.conf -debug
```

## 最佳实践

### 配置管理
1. **使用版本控制**: 将配置文件纳入版本控制
2. **环境分离**: 为不同环境使用不同的配置文件
3. **配置验证**: 部署前验证配置文件
4. **备份配置**: 定期备份配置文件
5. **文档化**: 记录配置变更和原因

### 性能优化
1. **调整工作进程**: 根据 CPU 核心数调整 workers
2. **优化连接数**: 根据负载调整 max_connections
3. **启用缓存**: 为静态内容启用缓存
4. **启用压缩**: 减少传输数据量
5. **监控性能**: 使用监控工具跟踪性能

### 安全考虑
1. **使用 HTTPS**: 为所有通信启用 SSL/TLS
2. **配置访问控制**: 限制访问来源
3. **启用 DDoS 防护**: 防止恶意攻击
4. **定期更新**: 保持 SSLcat 和证书更新
5. **监控安全事件**: 设置安全告警

## 相关文档

- [高级配置](advanced.md)
- [SSL 证书管理](ssl-certificates.md)
- [负载均衡](load-balancing.md)
- [缓存配置](caching.md)
- [安全设置](security.md)

---

*基础配置提供了 SSLcat 的核心功能。根据你的需求，可以进一步配置高级功能。*
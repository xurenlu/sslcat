# 配置参考

本指南提供 SSLcat 配置文件的完整参考，包括所有可用的配置选项和示例。

## 配置文件格式

SSLcat 使用 YAML 格式的配置文件，默认文件名为 `sslcat.conf`。

```yaml
# sslcat.conf
server:
  host: "0.0.0.0"
  port: 80
  ssl_port: 443

proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:8080"
      ssl: true

ssl:
  certificates:
    - domain: "example.com"
      provider: "letsencrypt"
      email: "admin@example.com"
```

## 服务器配置

### 基本设置
```yaml
server:
  host: "0.0.0.0"        # 监听地址
  port: 80              # HTTP 端口
  ssl_port: 443        # HTTPS 端口
  debug: false          # 调试模式
  workers: 4            # 工作进程数
  max_connections: 1000 # 最大连接数
```

### 高级设置
```yaml
server:
  # 基本设置
  host: "0.0.0.0"
  port: 80
  ssl_port: 443
  debug: false
  
  # 性能设置
  workers: 4
  max_connections: 1000
  max_connections_per_ip: 100
  
  # 超时设置
  keep_alive_timeout: 30s
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 120s
  
  # 缓冲区设置
  read_buffer_size: 4096
  write_buffer_size: 4096
  
  # 日志设置
  log_level: "info"     # debug, info, warn, error
  log_format: "json"   # json, text
  log_output: "stdout"  # stdout, file, syslog
```

### 管理界面
```yaml
server:
  admin:
    enabled: true
    host: "0.0.0.0"
    port: 8080
    path: "/admin"
    auth:
      username: "admin"
      password: "admin123"
```

## 代理配置

### 基本代理规则
```yaml
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
      
      # 请求/响应修改
      request_modification:
        enabled: true
        add_headers:
          X-Custom-Header: "value"
        remove_headers: ["X-Unwanted-Header"]
      
      response_modification:
        enabled: true
        add_headers:
          X-Response-Time: "$response_time"
        remove_headers: ["Server"]
```

### 负载均衡配置
```yaml
proxy:
  rules:
    - domain: "api.example.com"
      target: "http://localhost:8080"
      ssl: true
      load_balancing:
        enabled: true
        algorithm: "round_robin"  # round_robin, least_connections, ip_hash, weighted
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
          success_threshold: 2
          failure_threshold: 3
        
        # 熔断器
        circuit_breaker:
          enabled: true
          failure_threshold: 5
          recovery_timeout: 30s
          half_open_max_calls: 3
```

### 缓存配置
```yaml
proxy:
  rules:
    - domain: "api.example.com"
      target: "http://localhost:8080"
      ssl: true
      caching:
        enabled: true
        ttl: 3600  # 1小时
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
        
        # 缓存失效
        invalidation:
          enabled: true
          patterns: ["/api/users/*"]
          webhook_url: "http://backend:8080/cache/invalidate"
        
        # 缓存存储
        storage:
          type: "memory"  # memory, redis, file
          redis:
            host: "localhost"
            port: 6379
            password: "redis_password"
            db: 0
```

### 压缩配置
```yaml
proxy:
  rules:
    - domain: "api.example.com"
      target: "http://localhost:8080"
      ssl: true
      compression:
        enabled: true
        algorithm: "gzip"
        min_size: 1024
        max_size: 10485760  # 10MB
        types: ["text/html", "text/css", "application/javascript", "application/json"]
```

## SSL/TLS 配置

### 基本 SSL 设置
```yaml
ssl:
  certificates:
    - domain: "example.com"
      provider: "letsencrypt"
      email: "admin@example.com"
      auto_renew: true
```

### 高级 SSL 设置
```yaml
ssl:
  certificates:
    - domain: "example.com"
      provider: "letsencrypt"
      email: "admin@example.com"
      auto_renew: true
      renew_before_expiry: "30d"
      
      # 自定义证书设置
      key_size: 2048
      key_type: "RSA"  # RSA, ECDSA
      curve: "P-256"   # For ECDSA
      
      # 证书验证
      validation:
        method: "http-01"  # http-01, dns-01
        timeout: 30s
        retries: 3
  
  # TLS 配置
  tls:
    min_version: "1.2"
    max_version: "1.3"
    cipher_suites:
      - "TLS_AES_256_GCM_SHA384"
      - "TLS_CHACHA20_POLY1305_SHA256"
      - "TLS_AES_128_GCM_SHA256"
    
    # HSTS 设置
    hsts:
      enabled: true
      max_age: 31536000  # 1年
      include_subdomains: true
      preload: true
    
    # OCSP 装订
    ocsp_stapling:
      enabled: true
      cache_timeout: 3600s
```

### 自定义证书
```yaml
ssl:
  certificates:
    - domain: "example.com"
      cert_file: "/path/to/cert.pem"
      key_file: "/path/to/key.pem"
      chain_file: "/path/to/chain.pem"
      
      # 证书验证
      validation:
        enabled: true
        check_expiry: true
        check_revocation: true
        ocsp_check: true
```

## 监控配置

### 基本监控
```yaml
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
    
    # 自定义指标
    custom_metrics:
      enabled: true
      request_duration: true
      request_size: true
      response_size: true
      connection_count: true
      ssl_handshake_time: true
  
  # 分布式追踪
  tracing:
    enabled: true
    service_name: "sslcat-proxy"
    sample_rate: 0.1  # 10%采样
    
    # 追踪导出器
    exporters:
      jaeger:
        endpoint: "http://jaeger:14268/api/traces"
        timeout: 30s
        retry_on_failure: true
      
      zipkin:
        endpoint: "http://zipkin:9411/api/v2/spans"
        timeout: 30s
      
      otlp:
        endpoint: "http://otel-collector:4317"
        protocol: "grpc"
    
    # 追踪属性
    attributes:
      enabled: true
      request_headers: ["User-Agent", "X-Forwarded-For"]
      response_headers: ["Content-Type", "Content-Length"]
      custom_attributes:
        environment: "production"
        version: "1.3.16-rc18"
```

### 日志配置
```yaml
monitoring:
  logging:
    enabled: true
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
      
      - type: "elasticsearch"
        url: "http://elasticsearch:9200"
        index: "sslcat-logs"
        username: "elastic"
        password: "password"
    
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

## 安全配置

### DDoS 防护
```yaml
security:
  ddos_protection:
    enabled: true
    
    # 速率限制
    rate_limiting:
      global:
        requests_per_second: 1000
        burst_size: 2000
      
      per_ip:
        requests_per_second: 10
        burst_size: 20
      
      per_domain:
        requests_per_second: 100
        burst_size: 200
    
    # 连接限制
    connection_limiting:
      max_connections_per_ip: 50
      max_connections_per_domain: 500
      connection_timeout: 30s
    
    # 攻击检测
    attack_detection:
      enabled: true
      suspicious_patterns:
        - ".*\\.\\./.*"  # 路径遍历
        - ".*<script.*"  # XSS 尝试
        - ".*union.*select.*"  # SQL 注入
      
      response:
        block_duration: 300s  # 5分钟
        return_status: 429
        return_message: "Too Many Requests"
```

### 访问控制
```yaml
security:
  access_control:
    enabled: true
    
    # 基于 IP 的访问控制
    ip_filtering:
      whitelist: ["192.168.1.0/24", "10.0.0.0/8"]
      blacklist: ["192.168.1.100", "10.0.0.100"]
      default_policy: "deny"  # allow, deny
    
    # 地理位置过滤
    geo_filtering:
      enabled: true
      allowed_countries: ["US", "CA", "GB"]
      blocked_countries: ["CN", "RU"]
    
    # 基于时间的访问
    time_based_access:
      enabled: true
      allowed_hours: "09:00-17:00"
      allowed_days: ["monday", "tuesday", "wednesday", "thursday", "friday"]
      timezone: "UTC"
```

### 认证和授权
```yaml
security:
  authentication:
    enabled: true
    
    # 基本认证
    basic_auth:
      enabled: true
      users:
        - username: "admin"
          password: "$2a$10$..."  # bcrypt 哈希
          roles: ["admin"]
        - username: "user"
          password: "$2a$10$..."
          roles: ["user"]
    
    # JWT 认证
    jwt:
      enabled: true
      secret: "your-jwt-secret"
      issuer: "sslcat"
      audience: "sslcat-users"
      expiration: 3600s
    
    # OAuth2 集成
    oauth2:
      enabled: true
      provider: "google"  # google, github, microsoft
      client_id: "your-client-id"
      client_secret: "your-client-secret"
      redirect_url: "https://sslcat.example.com/auth/callback"
```

## 性能配置

### 缓存优化
```yaml
performance:
  caching:
    # 多级缓存
    levels:
      - type: "memory"
        size: "100MB"
        ttl: 300s
      
      - type: "redis"
        host: "localhost"
        port: 6379
        size: "1GB"
        ttl: 3600s
    
    # 缓存预热
    warming:
      enabled: true
      urls: ["/api/popular", "/api/trending"]
      interval: 300s
    
    # 缓存压缩
    compression:
      enabled: true
      algorithm: "gzip"
      min_size: 1024
      max_size: 10485760  # 10MB
```

### 连接优化
```yaml
performance:
  connections:
    # 连接池
    pooling:
      enabled: true
      max_idle: 100
      max_active: 200
      max_wait: 30s
      idle_timeout: 60s
    
    # HTTP/2 优化
    http2:
      enabled: true
      max_concurrent_streams: 100
      initial_window_size: 65535
      max_frame_size: 16384
    
    # Keep-alive 优化
    keep_alive:
      enabled: true
      timeout: 30s
      max_requests: 100
```

## 企业功能

### 多租户配置
```yaml
enterprise:
  multi_tenant:
    enabled: true
    
    # 租户隔离
    isolation:
      level: "domain"  # domain, subdomain, path
      default_tenant: "default"
    
    # 租户特定配置
    tenants:
      - name: "tenant1"
        domains: ["tenant1.example.com"]
        resources:
          max_connections: 1000
          max_bandwidth: "100Mbps"
      
      - name: "tenant2"
        domains: ["tenant2.example.com"]
        resources:
          max_connections: 500
          max_bandwidth: "50Mbps"
```

### 高可用性
```yaml
enterprise:
  high_availability:
    enabled: true
    
    # 负载均衡器配置
    load_balancer:
      algorithm: "least_connections"
      health_check:
        enabled: true
        interval: 30s
        timeout: 5s
        path: "/health"
    
    # 故障转移配置
    failover:
      enabled: true
      timeout: 10s
      retries: 3
      backup_servers:
        - "sslcat-backup1.example.com"
        - "sslcat-backup2.example.com"
```

## 环境变量

### 配置变量
```bash
# SSLcat 配置
SSLCAT_CONFIG=/app/sslcat.conf
SSLCAT_LOG_LEVEL=info
SSLCAT_DEBUG=false

# SSL/TLS 设置
SSLCAT_SSL_ENABLED=true
SSLCAT_SSL_CERT_PATH=/app/certs
SSLCAT_SSL_KEY_PATH=/app/keys

# 监控
SSLCAT_METRICS_ENABLED=true
SSLCAT_METRICS_PORT=8080
SSLCAT_TRACING_ENABLED=true
SSLCAT_TRACING_SAMPLE_RATE=0.1

# 缓存设置
SSLCAT_CACHE_ENABLED=true
SSLCAT_CACHE_TYPE=memory
SSLCAT_CACHE_SIZE=100MB
SSLCAT_CACHE_TTL=3600
```

## 配置验证

### 验证命令
```bash
# 验证配置文件
sslcat -config sslcat.conf -validate

# 测试配置
sslcat -config sslcat.conf -test

# 显示配置
sslcat -config sslcat.conf -show-config
```

### 配置检查
```bash
# 检查 YAML 语法
python -c "import yaml; yaml.safe_load(open('sslcat.conf'))"

# 检查配置完整性
sslcat -config sslcat.conf -check
```

## 相关文档

- [基础配置](../configuration/basic.md)
- [高级配置](../configuration/advanced.md)
- [安全配置](../configuration/security.md)
- [监控配置](../features/monitoring.md)

---

*这个配置参考提供了 SSLcat 所有可用配置选项的完整说明。*

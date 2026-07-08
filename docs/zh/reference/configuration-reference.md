# 配置参考

本指南提供 SSLcat 配置文件的完整参考，包括所有可用的配置选项和示例。

## 配置文件格式

SSLcat 使用 JSON 格式的配置文件，默认文件名为 `sslcat.conf`。

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
  },
  "ssl": {
    "email": "admin@example.com",
    "staging": false,
    "auto_renew": true
  }
}
```

## 服务器配置

### 基本设置
```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 80,
    "ssl_port": 443,
    "debug": false,
    "workers": 4,
    "max_connections": 1000
  }
}
```

### 高级设置
```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 80,
    "ssl_port": 443,
    "debug": false
  
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
```json
{
  "server": {
    "admin": {
      "enabled": true,
      "host": "0.0.0.0",
      "port": 18080,
      "path": "/admin",
      "auth": {
        "username": "admin",
        "password": "admin123"
      }
    }
  }
}
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

### 访问日志配置

SSLcat 支持灵活的访问日志配置，包括日期占位符、多种日志格式和自动轮转。

#### 基本访问日志配置

```json
{
  "server": {
    "access_log_enabled": true,
    "access_log_format": "nginx",
    "access_log_path": "./data/access.log",
    "access_log_max_size": 104857600,
    "access_log_max_files": 10
  }
}
```

#### 日志路径日期占位符

访问日志路径支持日期占位符，实现按日期自动轮转日志文件。

**Go 风格占位符（推荐）**：

| 占位符 | 说明 | 示例 |
|--------|------|------|
| `{yyyy}` | 4位年份 | `2025` |
| `{yy}` | 2位年份 | `25` |
| `{mm}` | 2位月份（带前导零） | `02` |
| `{m}` | 月份（无前导零） | `2` |
| `{dd}` | 2位日期（带前导零） | `28` |
| `{d}` | 日期（无前导零） | `8` |
| `{HH}` | 2位小时（24小时制） | `15` |
| `{H}` | 小时（无前导零） | `5` |
| `{MM}` | 2位分钟 | `04` |
| `{M}` | 分钟（无前导零） | `4` |
| `{SS}` | 2位秒数 | `05` |
| `{S}` | 秒数（无前导零） | `5` |
| `{date}` | 完整日期（YYYY-MM-DD） | `2025-02-28` |
| `{time}` | 完整时间（HH:MM:SS） | `15:04:05` |
| `{datetime}` | 日期时间（YYYY-MM-DD_HH-MM-SS） | `2025-02-28_15-04-05` |

**strftime 风格占位符（Nginx 兼容）**：

| 占位符 | 说明 | 示例 |
|--------|------|------|
| `%Y` | 4位年份 | `2025` |
| `%m` | 2位月份 | `02` |
| `%d` | 2位日期 | `28` |
| `%H` | 2位小时 | `15` |
| `%M` | 2位分钟 | `04` |
| `%S` | 2位秒数 | `05` |
| `%s` | Unix时间戳 | `1740739445` |

#### 日期占位符示例

**按日轮转日志**：
```json
{
  "server": {
    "access_log_path": "./data/access-{yyyy}-{mm}-{dd}.log"
  }
}
```
生成文件：`access-2025-02-28.log`

**按月轮转日志**：
```json
{
  "server": {
    "access_log_path": "./logs/access-{yyyy}-{mm}.log"
  }
}
```
生成文件：`access-2025-02.log`

**按小时轮转日志**：
```json
{
  "server": {
    "access_log_path": "./data/access-{yyyy}-{mm}-{dd}_{HH}.log"
  }
}
```
生成文件：`access-2025-02-28_15.log`

**Nginx 风格日期路径**：
```json
{
  "server": {
    "access_log_path": "/var/log/nginx/access-%Y%m%d.log"
  }
}
```
生成文件：`access-20250228.log`

**按日期目录组织日志**：
```json
{
  "server": {
    "access_log_path": "./logs/{yyyy}/{mm}/{dd}/access.log"
  }
}
```
生成目录：`./logs/2025/02/28/access.log`

#### 日志格式

支持三种日志格式：

**Nginx 格式（默认）**：
```
192.168.1.100 - - [28/Feb/2025:15:04:05 +0800] "GET /api/users HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0" 0.123 "backend:8080"
```

**Apache 格式**：
```
192.168.1.100 - - [28/Feb/2025:15:04:05 +0800] "GET /api/users HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0"
```

**JSON 格式**：
```json
{"timestamp":"2025-02-28T15:04:05+08:00","client_ip":"192.168.1.100","method":"GET","url":"/api/users","protocol":"HTTP/1.1","status_code":200,"bytes_sent":1234,"referer":"https://example.com","user_agent":"Mozilla/5.0","request_time":0.123,"upstream_addr":"backend:8080","host":"example.com","request_id":"abc123"}
```

#### 日志轮转

**按大小轮转（无日期占位符时）**：
当日志文件超过 `access_log_max_size` 时自动轮转，保留最多 `access_log_max_files` 个旧文件。

```json
{
  "server": {
    "access_log_path": "./data/access.log",
    "access_log_max_size": 104857600,
    "access_log_max_files": 10
  }
}
```

轮转后的文件名：`access.log.20250228-150405`

**按日期轮转（使用日期占位符）**：
使用日期占位符时，系统会在日期变化时自动创建新的日志文件。此时 `access_log_max_size` 配置会被忽略。

```json
{
  "server": {
    "access_log_path": "./data/access-{yyyy}-{mm}-{dd}.log"
  }
}
```

每个日期会自动创建新文件：
- `access-2025-02-27.log`
- `access-2025-02-28.log`
- `access-2025-03-01.log`

#### 站点级别访问日志配置

每个站点可以单独配置访问日志路径：

```json
{
  "proxy": {
    "rules": [
      {
        "domain": "api.example.com",
        "target": "http://localhost:8080",
        "access_log_enabled": true,
        "access_log_path": "./logs/api-{yyyy}-{mm}-{dd}.log"
      },
      {
        "domain": "web.example.com",
        "target": "http://localhost:8081",
        "access_log_enabled": true,
        "access_log_path": "./logs/web-{yyyy}-{mm}-{dd}.log"
      }
    ]
  }
}
```

### 错误日志配置

SSLcat 支持灵活的错误日志配置，同样支持日期占位符和按站点独立配置。

#### 基本错误日志配置

```json
{
  "server": {
    "error_log_enabled": true,
    "error_log_path": "./data/error.log",
    "error_log_max_size": 104857600,
    "error_log_max_files": 10
  }
}
```

#### 错误日志日期占位符

错误日志路径支持与访问日志相同的日期占位符：

**按日轮转错误日志**：
```json
{
  "server": {
    "error_log_path": "./data/error-{yyyy}-{mm}-{dd}.log"
  }
}
```
生成文件：`error-2025-02-28.log`

**按月轮转错误日志**：
```json
{
  "server": {
    "error_log_path": "./logs/error-{yyyy}-{mm}.log"
  }
}
```
生成文件：`error-2025-02.log`

**按日期目录组织错误日志**：
```json
{
  "server": {
    "error_log_path": "./logs/{yyyy}/{mm}/{dd}/error.log"
  }
}
```
生成目录：`./logs/2025/02/28/error.log`

#### 站点级别错误日志配置

每个站点可以单独配置错误日志路径：

```json
{
  "proxy": {
    "rules": [
      {
        "domain": "api.example.com",
        "target": "http://localhost:8080",
        "error_log_enabled": true,
        "error_log_path": "./logs/api-error-{yyyy}-{mm}-{dd}.log"
      },
      {
        "domain": "web.example.com",
        "target": "http://localhost:8081",
        "error_log_enabled": true,
        "error_log_path": "./logs/web-error-{yyyy}-{mm}-{dd}.log"
      }
    ]
  }
}
```

#### 错误日志内容

错误日志记录以下类型错误：
- 应用程序运行时错误
- PHP 执行错误（针对 PHP 站点）
- 代理连接错误
- SSL 证书错误
- 其他系统级错误

错误日志格式示例：
```
[2025-02-28 15:04:05] [ERROR] Connection refused domain=api.example.com type=proxy_error backend=192.168.1.100:8080
[2025-02-28 15:05:10] [ERROR] PHP Fatal error domain=php.example.com type=php_error file=/var/www/index.php line=42
```

#### 关闭站点错误日志

如果不需要为特定站点记录错误日志，可以单独关闭：

```json
{
  "proxy": {
    "rules": [
      {
        "domain": "internal.example.com",
        "target": "http://localhost:8080",
        "error_log_enabled": false
      }
    ]
  }
}
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

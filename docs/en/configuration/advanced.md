# Advanced Configuration

This guide covers advanced configuration options for SSLcat, including performance tuning, security settings, and enterprise features.

## Server Configuration

### Basic Server Settings
```yaml
# sslcat.conf
server:
  host: "0.0.0.0"
  port: 80
  ssl_port: 443
  debug: false
  workers: 4  # Number of worker processes
  max_connections: 1000
  keep_alive_timeout: 30s
  read_timeout: 30s
  write_timeout: 30s
```

### Performance Tuning
```yaml
server:
  # Connection settings
  max_connections: 2000
  max_connections_per_ip: 100
  
  # Timeout settings
  keep_alive_timeout: 60s
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 120s
  
  # Buffer settings
  read_buffer_size: 4096
  write_buffer_size: 4096
  
  # Worker settings
  workers: 8  # Adjust based on CPU cores
  worker_connections: 1000
```

### Security Settings
```yaml
server:
  security:
    # Rate limiting
    rate_limit:
      enabled: true
      requests_per_second: 100
      burst_size: 200
    
    # IP filtering
    ip_filtering:
      enabled: true
      whitelist: ["192.168.1.0/24", "10.0.0.0/8"]
      blacklist: ["192.168.1.100"]
    
    # Request size limits
    max_request_size: "10MB"
    max_header_size: "8KB"
    
    # Security headers
    security_headers:
      enabled: true
      hsts: true
      xss_protection: true
      content_type_options: true
      frame_options: "DENY"
```

## Proxy Configuration

### Advanced Proxy Rules
```yaml
proxy:
  rules:
    - domain: "api.example.com"
      target: "http://localhost:8080"
      ssl: true
      
      # Path-based routing
      path: "/api/v1"
      path_rewrite: "/v1"
      
      # Header manipulation
      headers:
        pass_through: true
        add:
          X-Forwarded-Proto: "https"
          X-Real-IP: "$remote_addr"
        remove: ["X-Forwarded-For"]
      
      # Request/Response modification
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

### Load Balancing Configuration
```yaml
proxy:
  rules:
    - domain: "api.example.com"
      target: "http://localhost:8080"
      ssl: true
      load_balancing:
        enabled: true
        algorithm: "least_connections"  # round_robin, least_connections, ip_hash, weighted
        backends:
          - url: "http://backend1:8080"
            weight: 3
            max_connections: 100
          - url: "http://backend2:8080"
            weight: 2
            max_connections: 50
          - url: "http://backend3:8080"
            weight: 1
            max_connections: 25
        
        # Health checking
        health_check:
          enabled: true
          path: "/health"
          interval: 30s
          timeout: 5s
          retries: 3
          success_threshold: 2
          failure_threshold: 3
        
        # Circuit breaker
        circuit_breaker:
          enabled: true
          failure_threshold: 5
          recovery_timeout: 30s
          half_open_max_calls: 3
```

### Caching Configuration
```yaml
proxy:
  rules:
    - domain: "api.example.com"
      target: "http://localhost:8080"
      ssl: true
      caching:
        enabled: true
        ttl: 3600  # 1 hour
        max_size: "100MB"
        max_entries: 10000
        
        # Cache policies
        policies:
          - path: "/static/*"
            ttl: 86400  # 24 hours
          - path: "/api/cacheable/*"
            ttl: 300   # 5 minutes
          - path: "/api/dynamic/*"
            ttl: 0     # No caching
        
        # Cache invalidation
        invalidation:
          enabled: true
          patterns: ["/api/users/*"]
          webhook_url: "http://backend:8080/cache/invalidate"
        
        # Cache storage
        storage:
          type: "memory"  # memory, redis, file
          redis:
            host: "localhost"
            port: 6379
            password: "redis_password"
            db: 0
```

## SSL/TLS Configuration

### Advanced SSL Settings
```yaml
ssl:
  # Certificate management
  certificates:
    - domain: "example.com"
      provider: "letsencrypt"
      email: "admin@example.com"
      auto_renew: true
      renew_before_expiry: "30d"
      
      # Custom certificate settings
      key_size: 2048
      key_type: "RSA"  # RSA, ECDSA
      curve: "P-256"   # For ECDSA
      
      # Certificate validation
      validation:
        method: "http-01"  # http-01, dns-01
        timeout: 30s
        retries: 3
  
  # TLS configuration
  tls:
    min_version: "1.2"
    max_version: "1.3"
    cipher_suites:
      - "TLS_AES_256_GCM_SHA384"
      - "TLS_CHACHA20_POLY1305_SHA256"
      - "TLS_AES_128_GCM_SHA256"
    
    # HSTS settings
    hsts:
      enabled: true
      max_age: 31536000  # 1 year
      include_subdomains: true
      preload: true
    
    # OCSP stapling
    ocsp_stapling:
      enabled: true
      cache_timeout: 3600s
```

### Custom SSL Certificates
```yaml
ssl:
  certificates:
    - domain: "example.com"
      cert_file: "/path/to/cert.pem"
      key_file: "/path/to/key.pem"
      chain_file: "/path/to/chain.pem"
      
      # Certificate validation
      validation:
        enabled: true
        check_expiry: true
        check_revocation: true
        ocsp_check: true
```

## Monitoring and Observability

### Metrics Configuration
```yaml
monitoring:
  metrics:
    enabled: true
    endpoint: "/metrics"
    port: 8080
    
    # Prometheus metrics
    prometheus:
      enabled: true
      path: "/metrics"
      format: "prometheus"
    
    # Custom metrics
    custom_metrics:
      enabled: true
      request_duration: true
      request_size: true
      response_size: true
      connection_count: true
      ssl_handshake_time: true
```

### Distributed Tracing
```yaml
monitoring:
  tracing:
    enabled: true
    service_name: "sslcat-proxy"
    sample_rate: 0.1  # 10% sampling for production
    
    # Trace exporters
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
    
    # Trace attributes
    attributes:
      enabled: true
      request_headers: ["User-Agent", "X-Forwarded-For"]
      response_headers: ["Content-Type", "Content-Length"]
      custom_attributes:
        environment: "production"
        version: "1.3.16-rc18"
```

### Logging Configuration
```yaml
monitoring:
  logging:
    enabled: true
    level: "info"  # debug, info, warn, error
    format: "json"  # json, text
    
    # Log outputs
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
    
    # Structured logging
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

## Security Configuration

### DDoS Protection
```yaml
security:
  ddos_protection:
    enabled: true
    
    # Rate limiting
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
    
    # Connection limiting
    connection_limiting:
      max_connections_per_ip: 50
      max_connections_per_domain: 500
      connection_timeout: 30s
    
    # Attack detection
    attack_detection:
      enabled: true
      suspicious_patterns:
        - ".*\\.\\./.*"  # Path traversal
        - ".*<script.*"  # XSS attempts
        - ".*union.*select.*"  # SQL injection
      
      response:
        block_duration: 300s  # 5 minutes
        return_status: 429
        return_message: "Too Many Requests"
```

### Access Control
```yaml
security:
  access_control:
    enabled: true
    
    # IP-based access control
    ip_filtering:
      whitelist: ["192.168.1.0/24", "10.0.0.0/8"]
      blacklist: ["192.168.1.100", "10.0.0.100"]
      default_policy: "deny"  # allow, deny
    
    # Geographic filtering
    geo_filtering:
      enabled: true
      allowed_countries: ["US", "CA", "GB"]
      blocked_countries: ["CN", "RU"]
    
    # Time-based access
    time_based_access:
      enabled: true
      allowed_hours: "09:00-17:00"
      allowed_days: ["monday", "tuesday", "wednesday", "thursday", "friday"]
      timezone: "UTC"
```

### Authentication and Authorization
```yaml
security:
  authentication:
    enabled: true
    
    # Basic authentication
    basic_auth:
      enabled: true
      users:
        - username: "admin"
          password: "$2a$10$..."  # bcrypt hash
          roles: ["admin"]
        - username: "user"
          password: "$2a$10$..."
          roles: ["user"]
    
    # JWT authentication
    jwt:
      enabled: true
      secret: "your-jwt-secret"
      issuer: "sslcat"
      audience: "sslcat-users"
      expiration: 3600s
    
    # OAuth2 integration
    oauth2:
      enabled: true
      provider: "google"  # google, github, microsoft
      client_id: "your-client-id"
      client_secret: "your-client-secret"
      redirect_url: "https://sslcat.example.com/auth/callback"
```

## Performance Optimization

### Caching Optimization
```yaml
performance:
  caching:
    # Multi-level caching
    levels:
      - type: "memory"
        size: "100MB"
        ttl: 300s
      
      - type: "redis"
        host: "localhost"
        port: 6379
        size: "1GB"
        ttl: 3600s
    
    # Cache warming
    warming:
      enabled: true
      urls: ["/api/popular", "/api/trending"]
      interval: 300s
    
    # Cache compression
    compression:
      enabled: true
      algorithm: "gzip"
      min_size: 1024
      max_size: 10485760  # 10MB
```

### Connection Optimization
```yaml
performance:
  connections:
    # Connection pooling
    pooling:
      enabled: true
      max_idle: 100
      max_active: 200
      max_wait: 30s
      idle_timeout: 60s
    
    # HTTP/2 optimization
    http2:
      enabled: true
      max_concurrent_streams: 100
      initial_window_size: 65535
      max_frame_size: 16384
    
    # Keep-alive optimization
    keep_alive:
      enabled: true
      timeout: 30s
      max_requests: 100
```

## Enterprise Features

### Multi-tenant Configuration
```yaml
enterprise:
  multi_tenant:
    enabled: true
    
    # Tenant isolation
    isolation:
      level: "domain"  # domain, subdomain, path
      default_tenant: "default"
    
    # Tenant-specific configuration
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

### High Availability
```yaml
enterprise:
  high_availability:
    enabled: true
    
    # Load balancer configuration
    load_balancer:
      algorithm: "least_connections"
      health_check:
        enabled: true
        interval: 30s
        timeout: 5s
        path: "/health"
    
    # Failover configuration
    failover:
      enabled: true
      timeout: 10s
      retries: 3
      backup_servers:
        - "sslcat-backup1.example.com"
        - "sslcat-backup2.example.com"
```

## Configuration Validation

```bash
# Validate configuration
sslcat -config sslcat.conf -validate

# Test configuration
sslcat -config sslcat.conf -test

# Dry run
sslcat -config sslcat.conf -dry-run
```

## Best Practices

### Security
1. **Use Strong SSL/TLS Configuration**: Enable modern cipher suites
2. **Implement Rate Limiting**: Prevent abuse and DDoS attacks
3. **Enable Access Controls**: Restrict access by IP and time
4. **Regular Security Updates**: Keep SSLcat updated
5. **Monitor Security Events**: Set up alerting for suspicious activity

### Performance
1. **Optimize Caching**: Configure appropriate cache policies
2. **Tune Connection Settings**: Adjust based on your traffic patterns
3. **Monitor Resource Usage**: Track CPU, memory, and network usage
4. **Load Test**: Regularly test your configuration under load
5. **Profile Performance**: Use monitoring tools to identify bottlenecks

### Reliability
1. **Health Checks**: Implement comprehensive health monitoring
2. **Circuit Breakers**: Prevent cascade failures
3. **Graceful Degradation**: Handle backend failures gracefully
4. **Backup Configuration**: Regular configuration backups
5. **Disaster Recovery**: Plan for service recovery

## Related Documentation

- [Basic Configuration](basic.md)
- [SSL Certificates](ssl-certificates.md)
- [Load Balancing](load-balancing.md)
- [Security](security.md)
- [Monitoring](../features/monitoring.md)

---

*Advanced configuration allows you to optimize SSLcat for enterprise use cases with high performance, security, and reliability requirements.*

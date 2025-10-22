# 基础代理设置

本示例展示如何设置基础反向代理，包括 SSL 终端、负载均衡和监控。

## 场景

你有一个运行在 `localhost:3000` 的 Web 应用程序，想要：
- 通过 HTTPS 在 `example.com` 上暴露
- 添加 SSL 证书管理
- 启用基础监控
- 为多个实例设置负载均衡

## 步骤 1：基础配置

创建基础 SSLcat 配置：

```yaml
# sslcat.conf
server:
  host: "0.0.0.0"
  port: 80
  ssl_port: 443
  debug: true

proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:3000"
      ssl: true

ssl:
  certificates:
    - domain: "example.com"
      provider: "letsencrypt"
      email: "admin@example.com"
      auto_renew: true
```

## 步骤 2：启动 SSLcat

```bash
# 使用配置文件启动 SSLcat
sslcat -config sslcat.conf

# 或使用 Docker 启动
docker run -d --name sslcat \
  -p 80:80 -p 443:443 \
  -v $(pwd)/sslcat.conf:/app/sslcat.conf \
  xurenlu/sslcat:latest
```

## 步骤 3：测试基础代理

```bash
# 测试 HTTP（重定向到 HTTPS）
curl -I http://example.com

# 测试 HTTPS
curl -I https://example.com

# 使用自定义头部测试
curl -H "X-Custom-Header: test" https://example.com
```

## 步骤 4：添加负载均衡

配置多个后端实例：

```yaml
# sslcat.conf
server:
  host: "0.0.0.0"
  port: 80
  ssl_port: 443

proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:3000"
      ssl: true
      load_balancing:
        enabled: true
        algorithm: "round_robin"
        backends:
          - "http://localhost:3000"
          - "http://localhost:3001"
          - "http://localhost:3002"
        health_check:
          enabled: true
          path: "/health"
          interval: 30s
          timeout: 5s

ssl:
  certificates:
    - domain: "example.com"
      provider: "letsencrypt"
      email: "admin@example.com"
      auto_renew: true
```

## 步骤 5：添加监控

启用监控和指标：

```yaml
# sslcat.conf
server:
  host: "0.0.0.0"
  port: 80
  ssl_port: 443

proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:3000"
      ssl: true
      load_balancing:
        enabled: true
        algorithm: "round_robin"
        backends:
          - "http://localhost:3000"
          - "http://localhost:3001"
          - "http://localhost:3002"
        health_check:
          enabled: true
          path: "/health"
          interval: 30s
          timeout: 5s

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
    sample_rate: 1.0
```

## 步骤 6：测试负载均衡

```bash
# 测试负载均衡
for i in {1..10}; do
  curl -s https://example.com/api/health | jq '.instance'
done

# 检查后端健康状态
curl https://example.com/health
```

## 步骤 7：添加缓存

启用缓存以提高性能：

```yaml
# sslcat.conf
server:
  host: "0.0.0.0"
  port: 80
  ssl_port: 443

proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:3000"
      ssl: true
      load_balancing:
        enabled: true
        algorithm: "round_robin"
        backends:
          - "http://localhost:3000"
          - "http://localhost:3001"
          - "http://localhost:3002"
        health_check:
          enabled: true
          path: "/health"
          interval: 30s
          timeout: 5s
      caching:
        enabled: true
        ttl: 3600  # 1小时
        max_size: "100MB"

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
    sample_rate: 1.0
```

## 步骤 8：生产环境配置

为生产使用优化：

```yaml
# sslcat.conf
server:
  host: "0.0.0.0"
  port: 80
  ssl_port: 443
  debug: false
  workers: 4

proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:3000"
      ssl: true
      load_balancing:
        enabled: true
        algorithm: "least_connections"
        backends:
          - "http://localhost:3000"
          - "http://localhost:3001"
          - "http://localhost:3002"
        health_check:
          enabled: true
          path: "/health"
          interval: 30s
          timeout: 5s
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
    sample_rate: 0.1  # 生产环境10%采样

security:
  ddos_protection:
    enabled: true
    rate_limit: 100  # 每秒请求数
  access_control:
    enabled: true
    whitelist: ["192.168.1.0/24"]
```

## Docker Compose 示例

使用 Docker Compose 的完整设置：

```yaml
# docker-compose.yml
version: '3.8'

services:
  sslcat:
    image: sslcat:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./sslcat.conf:/app/sslcat.conf
      - ./data:/app/data
    depends_on:
      - app1
      - app2
      - app3
    networks:
      - app-network

  app1:
    image: your-app:latest
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
    networks:
      - app-network

  app2:
    image: your-app:latest
    ports:
      - "3001:3000"
    environment:
      - NODE_ENV=production
    networks:
      - app-network

  app3:
    image: your-app:latest
    ports:
      - "3002:3000"
    environment:
      - NODE_ENV=production
    networks:
      - app-network

networks:
  app-network:
    driver: bridge
```

## 测试设置

### 1. 基础功能
```bash
# 测试 HTTP 到 HTTPS 重定向
curl -I http://example.com

# 测试 HTTPS
curl -I https://example.com

# 使用自定义头部测试
curl -H "X-Forwarded-For: 192.168.1.1" https://example.com
```

### 2. 负载均衡
```bash
# 测试负载均衡
for i in {1..20}; do
  echo "请求 $i:"
  curl -s https://example.com/api/instance
  echo
done
```

### 3. 健康检查
```bash
# 检查后端健康状态
curl https://example.com/health

# 检查 SSLcat 指标
curl http://localhost:8080/metrics
```

### 4. 缓存
```bash
# 测试缓存
curl -I https://example.com/static/style.css

# 检查缓存头部
curl -I https://example.com/static/style.css | grep -i cache
```

## 监控

### 1. 指标端点
```bash
# 获取 Prometheus 指标
curl http://localhost:8080/metrics

# 获取特定指标
curl http://localhost:8080/metrics | grep sslcat_requests_total
```

### 2. 健康仪表板
```bash
# 检查 SSLcat 健康状态
curl http://localhost:8080/health

# 检查后端健康状态
curl https://example.com/health
```

### 3. 日志
```bash
# 查看 SSLcat 日志
docker logs sslcat

# 实时跟踪日志
docker logs -f sslcat
```

## 故障排除

### 常见问题

1. **SSL 证书问题**
   ```bash
   # 检查证书状态
   curl -I https://example.com
   
   # 检查证书详情
   openssl s_client -connect example.com:443 -servername example.com
   ```

2. **负载均衡不工作**
   ```bash
   # 检查后端健康状态
   curl http://localhost:3000/health
   curl http://localhost:3001/health
   curl http://localhost:3002/health
   ```

3. **缓存问题**
   ```bash
   # 检查缓存头部
   curl -I https://example.com/static/style.css
   
   # 清除缓存（如果支持）
   curl -X POST https://example.com/admin/cache/clear
   ```

### 调试模式
启用调试模式进行详细日志记录：

```yaml
# sslcat.conf
server:
  debug: true
  log_level: "DEBUG"
```

## 最佳实践

1. **安全**
   - 使用强 SSL/TLS 配置
   - 启用 DDoS 防护
   - 实施访问控制
   - 定期安全更新

2. **性能**
   - 启用压缩
   - 配置适当的缓存
   - 监控资源使用
   - 优化负载均衡

3. **监控**
   - 设置健康检查
   - 监控指标和日志
   - 配置告警
   - 定期性能审查

## 相关文档

- [配置指南](../configuration/basic.md)
- [SSL 证书](../configuration/ssl-certificates.md)
- [负载均衡](../features/load-balancing.md)
- [缓存](../features/caching.md)
- [监控](../features/monitoring.md)

---

*这个基础代理设置为更高级的 SSLcat 配置提供了坚实的基础。*

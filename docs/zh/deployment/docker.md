# Docker 部署

本指南介绍使用 Docker 和 Docker Compose 部署 SSLcat，适用于开发、测试和生产环境。

## 快速开始

### 基本 Docker 运行
```bash
# 拉取最新镜像
docker pull xurenlu/sslcat:latest

# 运行 SSLcat 基本配置
docker run -d --name sslcat \
  -p 80:80 -p 443:443 \
  -v $(pwd)/sslcat.conf:/app/sslcat.conf \
  xurenlu/sslcat:latest
```

### Docker Compose
```yaml
# docker-compose.yml
version: '3.8'

services:
  sslcat:
    image: xurenlu/sslcat:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./sslcat.conf:/app/sslcat.conf
      - ./data:/app/data
    environment:
      - SSLCAT_LOG_LEVEL=info
    restart: unless-stopped
```

## 生产环境部署

### 多服务设置
```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  sslcat:
    image: xurenlu/sslcat:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./sslcat.conf:/app/sslcat.conf
      - ./data:/app/data
      - ./logs:/app/logs
    environment:
      - SSLCAT_LOG_LEVEL=info
      - SSLCAT_DEBUG=false
    restart: unless-stopped
    networks:
      - sslcat-network
    depends_on:
      - redis
      - prometheus

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data
    networks:
      - sslcat-network
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    networks:
      - sslcat-network
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
    networks:
      - sslcat-network
    restart: unless-stopped

volumes:
  redis-data:
  grafana-data:

networks:
  sslcat-network:
    driver: bridge
```

### SSLcat 配置
```yaml
# sslcat.conf
server:
  host: "0.0.0.0"
  port: 80
  ssl_port: 443
  debug: false

proxy:
  rules:
    - domain: "api.example.com"
      target: "http://backend:8080"
      ssl: true
      load_balancing:
        enabled: true
        algorithm: "round_robin"
        backends:
          - "http://backend-1:8080"
          - "http://backend-2:8080"
          - "http://backend-3:8080"

ssl:
  certificates:
    - domain: "api.example.com"
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
```

## 开发环境

### 开发设置
```yaml
# docker-compose.dev.yml
version: '3.8'

services:
  sslcat:
    image: xurenlu/sslcat:latest
    ports:
      - "80:80"
      - "443:443"
      - "18080:18080"  # 管理界面
    volumes:
      - ./sslcat.conf:/app/sslcat.conf
      - ./data:/app/data
      - ./logs:/app/logs
    environment:
      - SSLCAT_LOG_LEVEL=debug
      - SSLCAT_DEBUG=true
    restart: unless-stopped
    networks:
      - dev-network

  backend:
    image: node:18-alpine
    working_dir: /app
    volumes:
      - ./backend:/app
    ports:
      - "3000:3000"
    command: npm start
    networks:
      - dev-network

  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"
    environment:
      - COLLECTOR_OTLP_ENABLED=true
    networks:
      - dev-network

networks:
  dev-network:
    driver: bridge
```

### 开发配置
```yaml
# sslcat.conf (开发环境)
server:
  host: "0.0.0.0"
  port: 80
  ssl_port: 443
  debug: true

proxy:
  rules:
    - domain: "localhost"
      target: "http://backend:3000"
      ssl: false  # 开发环境禁用 SSL

monitoring:
  metrics:
    enabled: true
    endpoint: "/metrics"
  tracing:
    enabled: true
    sample_rate: 1.0  # 开发环境100%采样
    exporters:
      jaeger:
        endpoint: "http://jaeger:14268/api/traces"
```

## Kubernetes 部署

### SSLcat 部署
```yaml
# sslcat-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sslcat
  labels:
    app: sslcat
spec:
  replicas: 3
  selector:
    matchLabels:
      app: sslcat
  template:
    metadata:
      labels:
        app: sslcat
    spec:
      containers:
      - name: sslcat
        image: xurenlu/sslcat:latest
        ports:
        - containerPort: 80
        - containerPort: 443
        - containerPort: 8080
        env:
        - name: SSLCAT_LOG_LEVEL
          value: "info"
        volumeMounts:
        - name: config
          mountPath: /app/sslcat.conf
          subPath: sslcat.conf
        - name: data
          mountPath: /app/data
        - name: logs
          mountPath: /app/logs
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: sslcat-config
      - name: data
        persistentVolumeClaim:
          claimName: sslcat-data
      - name: logs
        emptyDir: {}
```

### SSLcat 服务
```yaml
# sslcat-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: sslcat
  labels:
    app: sslcat
spec:
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 80
    protocol: TCP
    name: http
  - port: 443
    targetPort: 443
    protocol: TCP
    name: https
  - port: 8080
    targetPort: 8080
    protocol: TCP
    name: admin
  selector:
    app: sslcat
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

### Docker 环境文件
```bash
# .env
SSLCAT_LOG_LEVEL=info
SSLCAT_DEBUG=false
SSLCAT_METRICS_ENABLED=true
SSLCAT_TRACING_ENABLED=true
REDIS_URL=redis://redis:6379
PROMETHEUS_URL=http://prometheus:9090
```

## 卷管理

### 数据持久化
```yaml
# docker-compose.yml
services:
  sslcat:
    image: xurenlu/sslcat:latest
    volumes:
      # 配置
      - ./sslcat.conf:/app/sslcat.conf:ro
      
      # 数据持久化
      - sslcat-data:/app/data
      - sslcat-logs:/app/logs
      - sslcat-certs:/app/certs
      - sslcat-keys:/app/keys
      
      # 缓存数据
      - sslcat-cache:/app/cache

volumes:
  sslcat-data:
    driver: local
  sslcat-logs:
    driver: local
  sslcat-certs:
    driver: local
  sslcat-keys:
    driver: local
  sslcat-cache:
    driver: local
```

### 外部卷挂载
```bash
# 创建命名卷
docker volume create sslcat-data
docker volume create sslcat-logs
docker volume create sslcat-certs

# 使用外部卷运行
docker run -d --name sslcat \
  -p 80:80 -p 443:443 \
  -v sslcat-data:/app/data \
  -v sslcat-logs:/app/logs \
  -v sslcat-certs:/app/certs \
  xurenlu/sslcat:latest
```

## 网络配置

### 自定义网络
```yaml
# docker-compose.yml
version: '3.8'

services:
  sslcat:
    image: xurenlu/sslcat:latest
    networks:
      - frontend
      - backend
    ports:
      - "80:80"
      - "443:443"

  backend:
    image: nginx:alpine
    networks:
      - backend
    ports:
      - "8080:80"

  redis:
    image: redis:7-alpine
    networks:
      - backend

networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
```

### 网络安全
```yaml
# docker-compose.yml
services:
  sslcat:
    image: xurenlu/sslcat:latest
    networks:
      - sslcat-network
    ports:
      - "80:80"
      - "443:443"
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
      - /var/run

networks:
  sslcat-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

## 健康检查

### 容器健康检查
```yaml
# docker-compose.yml
services:
  sslcat:
    image: xurenlu/sslcat:latest
    healthcheck:
      test: ["CMD", "sslcat", "health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

### 应用健康检查
```bash
# 检查 SSLcat 健康状态
docker exec sslcat sslcat health

# 检查特定组件
docker exec sslcat sslcat health -component proxy
docker exec sslcat sslcat health -component ssl

# 获取指标
docker exec sslcat sslcat metrics
```

## 监控和日志

### 日志管理
```yaml
# docker-compose.yml
services:
  sslcat:
    image: xurenlu/sslcat:latest
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    volumes:
      - ./logs:/app/logs
```

### Prometheus 集成
```yaml
# docker-compose.yml
services:
  sslcat:
    image: xurenlu/sslcat:latest
    environment:
      - SSLCAT_METRICS_ENABLED=true
      - SSLCAT_METRICS_PORT=8080

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--web.enable-lifecycle'
```

## 安全最佳实践

### 容器安全
```yaml
# docker-compose.yml
services:
  sslcat:
    image: xurenlu/sslcat:latest
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
      - /var/run
    user: "1000:1000"
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
```

### 网络安全
```yaml
# docker-compose.yml
services:
  sslcat:
    image: xurenlu/sslcat:latest
    networks:
      - sslcat-network
    ports:
      - "80:80"
      - "443:443"

networks:
  sslcat-network:
    driver: bridge
    internal: true
```

## 故障排除

### 常见问题
```bash
# 检查容器日志
docker logs sslcat

# 实时跟踪日志
docker logs -f sslcat

# 检查容器状态
docker ps -a

# 检查容器资源
docker stats sslcat

# 在容器中执行命令
docker exec -it sslcat /bin/sh
```

### 调试模式
```bash
# 调试模式运行
docker run -d --name sslcat-debug \
  -p 80:80 -p 443:443 \
  -e SSLCAT_DEBUG=true \
  -e SSLCAT_LOG_LEVEL=debug \
  xurenlu/sslcat:latest
```

## 相关文档

- [Kubernetes 部署](kubernetes.md)
- [生产环境部署](production.md)
- [配置指南](../configuration/basic.md)
- [监控指南](../features/monitoring.md)

---

*Docker 部署为在任何环境中运行 SSLcat 提供了灵活且可扩展的方式。*

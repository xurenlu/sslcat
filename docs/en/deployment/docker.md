# Docker Deployment

This guide covers deploying SSLcat using Docker and Docker Compose for development, testing, and production environments.

## Quick Start

### Basic Docker Run
```bash
# Pull the latest image
docker pull xurenlu/sslcat:latest

# Run SSLcat with basic configuration
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

## Production Deployment

### Multi-Service Setup
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

### SSLcat Configuration
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

## Development Environment

### Development Setup
```yaml
# docker-compose.dev.yml
version: '3.8'

services:
  sslcat:
    image: xurenlu/sslcat:latest
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"  # Admin interface
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

### Development Configuration
```yaml
# sslcat.conf (development)
server:
  host: "0.0.0.0"
  port: 80
  ssl_port: 443
  debug: true

proxy:
  rules:
    - domain: "localhost"
      target: "http://backend:3000"
      ssl: false  # Disable SSL for development

monitoring:
  metrics:
    enabled: true
    endpoint: "/metrics"
  tracing:
    enabled: true
    sample_rate: 1.0  # 100% sampling for development
    exporters:
      jaeger:
        endpoint: "http://jaeger:14268/api/traces"
```

## Kubernetes Deployment

### SSLcat Deployment
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

### SSLcat Service
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

### SSLcat ConfigMap
```yaml
# sslcat-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sslcat-config
data:
  sslcat.conf: |
    server:
      host: "0.0.0.0"
      port: 80
      ssl_port: 443
      debug: false

    proxy:
      rules:
        - domain: "api.example.com"
          target: "http://backend-service:8080"
          ssl: true

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

## Environment Variables

### Configuration Variables
```bash
# SSLcat configuration
SSLCAT_CONFIG=/app/sslcat.conf
SSLCAT_LOG_LEVEL=info
SSLCAT_DEBUG=false

# SSL/TLS settings
SSLCAT_SSL_ENABLED=true
SSLCAT_SSL_CERT_PATH=/app/certs
SSLCAT_SSL_KEY_PATH=/app/keys

# Monitoring
SSLCAT_METRICS_ENABLED=true
SSLCAT_METRICS_PORT=8080
SSLCAT_TRACING_ENABLED=true
SSLCAT_TRACING_SAMPLE_RATE=0.1

# Cache settings
SSLCAT_CACHE_ENABLED=true
SSLCAT_CACHE_TYPE=memory
SSLCAT_CACHE_SIZE=100MB
SSLCAT_CACHE_TTL=3600
```

### Docker Environment File
```bash
# .env
SSLCAT_LOG_LEVEL=info
SSLCAT_DEBUG=false
SSLCAT_METRICS_ENABLED=true
SSLCAT_TRACING_ENABLED=true
REDIS_URL=redis://redis:6379
PROMETHEUS_URL=http://prometheus:9090
```

## Volume Management

### Data Persistence
```yaml
# docker-compose.yml
services:
  sslcat:
    image: xurenlu/sslcat:latest
    volumes:
      # Configuration
      - ./sslcat.conf:/app/sslcat.conf:ro
      
      # Data persistence
      - sslcat-data:/app/data
      - sslcat-logs:/app/logs
      - sslcat-certs:/app/certs
      - sslcat-keys:/app/keys
      
      # Cache data
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

### External Volume Mounts
```bash
# Create named volumes
docker volume create sslcat-data
docker volume create sslcat-logs
docker volume create sslcat-certs

# Run with external volumes
docker run -d --name sslcat \
  -p 80:80 -p 443:443 \
  -v sslcat-data:/app/data \
  -v sslcat-logs:/app/logs \
  -v sslcat-certs:/app/certs \
  xurenlu/sslcat:latest
```

## Networking

### Custom Networks
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

### Network Security
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

## Health Checks

### Container Health Checks
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

### Application Health Checks
```bash
# Check SSLcat health
docker exec sslcat sslcat health

# Check specific components
docker exec sslcat sslcat health -component proxy
docker exec sslcat sslcat health -component ssl

# Get metrics
docker exec sslcat sslcat metrics
```

## Monitoring and Logging

### Log Management
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

### Prometheus Integration
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

## Security Best Practices

### Container Security
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

### Network Security
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

## Troubleshooting

### Common Issues
```bash
# Check container logs
docker logs sslcat

# Follow logs in real-time
docker logs -f sslcat

# Check container status
docker ps -a

# Check container resources
docker stats sslcat

# Execute commands in container
docker exec -it sslcat /bin/sh
```

### Debug Mode
```bash
# Run in debug mode
docker run -d --name sslcat-debug \
  -p 80:80 -p 443:443 \
  -e SSLCAT_DEBUG=true \
  -e SSLCAT_LOG_LEVEL=debug \
  xurenlu/sslcat:latest
```

## Related Documentation

- [Kubernetes Deployment](kubernetes.md)
- [Production Deployment](production.md)
- [Configuration Guide](../configuration/basic.md)
- [Monitoring](../features/monitoring.md)

---

*Docker deployment provides a flexible and scalable way to run SSLcat in any environment.*
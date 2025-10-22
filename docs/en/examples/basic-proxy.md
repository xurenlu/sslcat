# Basic Proxy Setup

This example shows how to set up a basic reverse proxy with SSLcat, including SSL termination, load balancing, and monitoring.

## Scenario

You have a web application running on `localhost:3000` and want to:
- Expose it via HTTPS on `example.com`
- Add SSL certificate management
- Enable basic monitoring
- Set up load balancing for multiple instances

## Step 1: Basic Configuration

Create a basic SSLcat configuration:

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

## Step 2: Start SSLcat

```bash
# Start SSLcat with configuration
sslcat -config sslcat.conf

# Or start with Docker
docker run -d --name sslcat \
  -p 80:80 -p 443:443 \
  -v $(pwd)/sslcat.conf:/app/sslcat.conf \
  xurenlu/sslcat:latest
```

## Step 3: Test Basic Proxy

```bash
# Test HTTP (redirects to HTTPS)
curl -I http://example.com

# Test HTTPS
curl -I https://example.com

# Test with specific headers
curl -H "X-Custom-Header: test" https://example.com
```

## Step 4: Add Load Balancing

Configure multiple backend instances:

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

## Step 5: Add Monitoring

Enable monitoring and metrics:

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

## Step 6: Test Load Balancing

```bash
# Test load balancing
for i in {1..10}; do
  curl -s https://example.com/api/health | jq '.instance'
done

# Check backend health
curl https://example.com/health
```

## Step 7: Add Caching

Enable caching for better performance:

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
        ttl: 300  # 5 minutes
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

## Step 8: Production Configuration

Optimize for production use:

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
        ttl: 300
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
    sample_rate: 0.1  # 10% sampling for production

security:
  ddos_protection:
    enabled: true
    rate_limit: 100  # requests per second
  access_control:
    enabled: true
    whitelist: ["192.168.1.0/24"]
```

## Docker Compose Example

Complete setup with Docker Compose:

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

## Testing the Setup

### 1. Basic Functionality
```bash
# Test HTTP to HTTPS redirect
curl -I http://example.com

# Test HTTPS
curl -I https://example.com

# Test with custom headers
curl -H "X-Forwarded-For: 192.168.1.1" https://example.com
```

### 2. Load Balancing
```bash
# Test load balancing
for i in {1..20}; do
  echo "Request $i:"
  curl -s https://example.com/api/instance
  echo
done
```

### 3. Health Checks
```bash
# Check backend health
curl https://example.com/health

# Check SSLcat metrics
curl http://localhost:8080/metrics
```

### 4. Caching
```bash
# Test caching
curl -I https://example.com/static/style.css

# Check cache headers
curl -I https://example.com/static/style.css | grep -i cache
```

## Monitoring

### 1. Metrics Endpoint
```bash
# Get Prometheus metrics
curl http://localhost:8080/metrics

# Get specific metrics
curl http://localhost:8080/metrics | grep sslcat_requests_total
```

### 2. Health Dashboard
```bash
# Check SSLcat health
curl http://localhost:8080/health

# Check backend health
curl https://example.com/health
```

### 3. Logs
```bash
# View SSLcat logs
docker logs sslcat

# Follow logs in real-time
docker logs -f sslcat
```

## Troubleshooting

### Common Issues

1. **SSL Certificate Issues**
   ```bash
   # Check certificate status
   curl -I https://example.com
   
   # Check certificate details
   openssl s_client -connect example.com:443 -servername example.com
   ```

2. **Load Balancing Not Working**
   ```bash
   # Check backend health
   curl http://localhost:3000/health
   curl http://localhost:3001/health
   curl http://localhost:3002/health
   ```

3. **Caching Issues**
   ```bash
   # Check cache headers
   curl -I https://example.com/static/style.css
   
   # Clear cache (if supported)
   curl -X POST https://example.com/admin/cache/clear
   ```

### Debug Mode
Enable debug mode for detailed logging:

```yaml
# sslcat.conf
server:
  debug: true
  log_level: "DEBUG"
```

## Best Practices

1. **Security**
   - Use strong SSL/TLS configuration
   - Enable DDoS protection
   - Implement access controls
   - Regular security updates

2. **Performance**
   - Enable compression
   - Configure appropriate caching
   - Monitor resource usage
   - Optimize load balancing

3. **Monitoring**
   - Set up health checks
   - Monitor metrics and logs
   - Configure alerting
   - Regular performance reviews

## Related Documentation

- [Configuration Guide](../configuration/basic.md)
- [SSL Certificates](../configuration/ssl-certificates.md)
- [Load Balancing](../features/load-balancing.md)
- [Caching](../features/caching.md)
- [Monitoring](../features/monitoring.md)

---

*This basic proxy setup provides a solid foundation for more advanced SSLcat configurations.*

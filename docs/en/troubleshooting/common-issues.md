# Common Issues and Solutions

This guide covers the most common issues you might encounter when using SSLcat and their solutions.

## SSL Certificate Issues

### Issue: Certificate Not Generated
**Symptoms**: HTTPS requests fail, certificate errors in browser

**Possible Causes**:
- Domain not pointing to SSLcat server
- Let's Encrypt rate limits exceeded
- DNS propagation not complete
- Firewall blocking port 80/443

**Solutions**:
```bash
# Check domain resolution
nslookup example.com

# Check if ports are accessible
telnet example.com 80
telnet example.com 443

# Check SSLcat logs
docker logs sslcat

# Verify Let's Encrypt status
curl -I http://example.com/.well-known/acme-challenge/test
```

### Issue: Certificate Expired
**Symptoms**: Browser shows "Certificate Expired" error

**Solutions**:
```yaml
# sslcat.conf - Enable auto-renewal
ssl:
  certificates:
    - domain: "example.com"
      provider: "letsencrypt"
      auto_renew: true
      renew_before_expiry: "30d"  # Renew 30 days before expiry
```

```bash
# Manual certificate renewal
sslcat -config sslcat.conf -renew-certificates

# Check certificate expiration
openssl x509 -in /path/to/cert.pem -text -noout | grep "Not After"
```

### Issue: Certificate Chain Issues
**Symptoms**: "Certificate Chain Incomplete" errors

**Solutions**:
```bash
# Check certificate chain
openssl s_client -connect example.com:443 -servername example.com

# Verify intermediate certificates
curl -I https://example.com
```

## Proxy Configuration Issues

### Issue: 502 Bad Gateway
**Symptoms**: All requests return 502 Bad Gateway

**Possible Causes**:
- Backend service not running
- Incorrect target URL
- Network connectivity issues
- Backend service not responding

**Solutions**:
```bash
# Check backend service status
curl http://localhost:8080/health

# Check SSLcat configuration
sslcat -config sslcat.conf -validate

# Check network connectivity
telnet backend-host 8080

# Check SSLcat logs
docker logs sslcat
```

### Issue: Requests Not Routed Correctly
**Symptoms**: Requests going to wrong backend or not being processed

**Solutions**:
```yaml
# sslcat.conf - Check proxy rules
proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:8080"  # Verify this is correct
      ssl: true
      path: "/api"  # Add path if needed
```

```bash
# Test proxy rules
curl -H "Host: example.com" http://localhost/api/test

# Check SSLcat configuration
sslcat -config sslcat.conf -test
```

### Issue: Headers Not Passed
**Symptoms**: Backend not receiving expected headers

**Solutions**:
```yaml
# sslcat.conf - Configure header passing
proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:8080"
      headers:
        pass_through: true  # Pass all headers
        custom:
          X-Forwarded-Proto: "https"
          X-Real-IP: "$remote_addr"
```

## Load Balancing Issues

### Issue: Load Balancing Not Working
**Symptoms**: All requests going to one backend

**Possible Causes**:
- Health checks failing
- Backend services not responding
- Incorrect load balancing configuration

**Solutions**:
```yaml
# sslcat.conf - Check load balancing config
proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:8080"
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
          timeout: 5s
```

```bash
# Check backend health
curl http://localhost:8080/health
curl http://localhost:8081/health
curl http://localhost:8082/health

# Test load balancing
for i in {1..10}; do
  curl -s https://example.com/api/instance
done
```

### Issue: Backend Health Check Failures
**Symptoms**: Backends marked as unhealthy

**Solutions**:
```bash
# Check health check endpoint
curl http://localhost:8080/health

# Check health check configuration
curl -I http://localhost:8080/health

# Verify backend service is running
ps aux | grep your-backend-service
```

## Performance Issues

### Issue: High CPU Usage
**Symptoms**: SSLcat using high CPU resources

**Solutions**:
```yaml
# sslcat.conf - Optimize configuration
server:
  workers: 4  # Adjust based on CPU cores
  max_connections: 1000

proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:8080"
      caching:
        enabled: true
        ttl: 300
      compression:
        enabled: true
```

```bash
# Monitor CPU usage
top -p $(pgrep sslcat)

# Check SSLcat metrics
curl http://localhost:8080/metrics | grep cpu
```

### Issue: Memory Usage High
**Symptoms**: SSLcat using excessive memory

**Solutions**:
```yaml
# sslcat.conf - Optimize memory usage
server:
  max_connections: 500
  cache_size: "50MB"

proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:8080"
      caching:
        enabled: true
        max_size: "50MB"
```

```bash
# Monitor memory usage
ps aux | grep sslcat

# Check memory metrics
curl http://localhost:8080/metrics | grep memory
```

### Issue: Slow Response Times
**Symptoms**: High response times, slow page loads

**Solutions**:
```yaml
# sslcat.conf - Enable caching and compression
proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:8080"
      caching:
        enabled: true
        ttl: 3600  # 1 hour
      compression:
        enabled: true
        types: ["text/html", "text/css", "application/javascript"]
```

```bash
# Test response times
curl -w "@curl-format.txt" -o /dev/null -s https://example.com

# Check backend response times
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8080
```

## Network Issues

### Issue: Connection Refused
**Symptoms**: "Connection Refused" errors

**Solutions**:
```bash
# Check if SSLcat is running
ps aux | grep sslcat

# Check port binding
netstat -tlnp | grep :80
netstat -tlnp | grep :443

# Check firewall rules
iptables -L
ufw status
```

### Issue: DNS Resolution Issues
**Symptoms**: Domain not resolving to SSLcat server

**Solutions**:
```bash
# Check DNS resolution
nslookup example.com
dig example.com

# Check DNS propagation
dig @8.8.8.8 example.com
dig @1.1.1.1 example.com

# Test with different DNS servers
curl -H "Host: example.com" http://your-server-ip/
```

## Configuration Issues

### Issue: Configuration Syntax Errors
**Symptoms**: SSLcat fails to start, configuration errors

**Solutions**:
```bash
# Validate configuration
sslcat -config sslcat.conf -validate

# Check JSON syntax
python -c "import json; json.load(open('sslcat.conf'))"

# Test configuration
sslcat -config sslcat.conf -test
```

### Issue: Missing Configuration Files
**Symptoms**: SSLcat cannot find configuration file

**Solutions**:
```bash
# Check file permissions
ls -la sslcat.conf

# Check file path
pwd
ls -la sslcat.conf

# Use absolute path
sslcat -config /full/path/to/sslcat.conf
```

## Monitoring Issues

### Issue: Metrics Not Available
**Symptoms**: Metrics endpoint not responding

**Solutions**:
```yaml
# sslcat.conf - Enable metrics
monitoring:
  metrics:
    enabled: true
    endpoint: "/metrics"
    port: 8080
```

```bash
# Check metrics endpoint
curl http://localhost:8080/metrics

# Check if monitoring is enabled
curl http://localhost:8080/health
```

### Issue: Tracing Not Working
**Symptoms**: No trace data in monitoring systems

**Solutions**:
```yaml
# sslcat.conf - Enable tracing
monitoring:
  tracing:
    enabled: true
    sample_rate: 1.0
    exporters:
      jaeger:
        endpoint: "http://jaeger:14268/api/traces"
```

```bash
# Check tracing configuration
curl -H "traceparent: 00-test-trace-id-test-span-id-01" https://example.com

# Check trace headers
curl -I https://example.com | grep -i trace
```

## Docker Issues

### Issue: Container Not Starting
**Symptoms**: Docker container exits immediately

**Solutions**:
```bash
# Check container logs
docker logs sslcat

# Check container status
docker ps -a

# Check configuration file
docker run --rm -v $(pwd)/sslcat.conf:/app/sslcat.conf sslcat:latest -validate
```

### Issue: Volume Mount Issues
**Symptoms**: Configuration not loading, data not persisting

**Solutions**:
```bash
# Check volume mounts
docker inspect sslcat

# Check file permissions
ls -la sslcat.conf

# Test volume mount
docker run --rm -v $(pwd)/sslcat.conf:/app/sslcat.conf sslcat:latest -test
```

## Debugging Tools

### SSLcat Debug Mode
```yaml
# sslcat.conf
server:
  debug: true
  log_level: "DEBUG"
```

### Log Analysis
```bash
# View SSLcat logs
docker logs sslcat

# Follow logs in real-time
docker logs -f sslcat

# Filter specific log levels
docker logs sslcat 2>&1 | grep ERROR
```

### Network Debugging
```bash
# Test connectivity
telnet example.com 80
telnet example.com 443

# Check SSL/TLS
openssl s_client -connect example.com:443 -servername example.com

# Test with curl
curl -v https://example.com
```

### Performance Debugging
```bash
# Monitor system resources
top -p $(pgrep sslcat)
htop

# Check network connections
netstat -tlnp | grep sslcat
ss -tlnp | grep sslcat

# Monitor disk I/O
iostat -x 1
```

## Getting Help

### Log Collection
When reporting issues, collect the following information:

```bash
# SSLcat version
sslcat --version

# Configuration file
cat sslcat.conf

# System information
uname -a
cat /etc/os-release

# SSLcat logs
docker logs sslcat > sslcat.log

# System logs
journalctl -u sslcat > system.log
```

### Community Support
- **GitHub Issues**: [Report bugs](https://github.com/xurenlu/sslcat/issues)
- **Discussions**: [Community discussions](https://github.com/xurenlu/sslcat/discussions)
- **Documentation**: This comprehensive guide

---

*This troubleshooting guide covers the most common issues. For specific problems not covered here, please check the other troubleshooting guides or reach out to the community.*

# 常见问题和解决方案

本指南涵盖了使用 SSLcat 时可能遇到的最常见问题及其解决方案。

## SSL 证书问题

### 问题：证书未生成
**症状**: HTTPS 请求失败，浏览器显示证书错误

**可能原因**:
- 域名未指向 SSLcat 服务器
- Let's Encrypt 速率限制
- DNS 传播未完成
- 防火墙阻止端口 80/443

**解决方案**:
```bash
# 检查域名解析
nslookup example.com

# 检查端口是否可访问
telnet example.com 80
telnet example.com 443

# 检查 SSLcat 日志
docker logs sslcat

# 验证 Let's Encrypt 状态
curl -I http://example.com/.well-known/acme-challenge/test
```

### 问题：证书过期
**症状**: 浏览器显示"证书过期"错误

**解决方案**:
```yaml
# sslcat.conf - 启用自动续期
ssl:
  certificates:
    - domain: "example.com"
      provider: "letsencrypt"
      auto_renew: true
      renew_before_expiry: "30d"  # 过期前30天续期
```

```bash
# 手动证书续期
sslcat -config sslcat.conf -renew-certificates

# 检查证书过期时间
openssl x509 -in /path/to/cert.pem -text -noout | grep "Not After"
```

### 问题：证书链问题
**症状**: "证书链不完整"错误

**解决方案**:
```bash
# 检查证书链
openssl s_client -connect example.com:443 -servername example.com

# 验证中间证书
curl -I https://example.com
```

## 代理配置问题

### 问题：502 Bad Gateway
**症状**: 所有请求返回 502 Bad Gateway

**可能原因**:
- 后端服务未运行
- 目标 URL 错误
- 网络连接问题
- 后端服务无响应

**解决方案**:
```bash
# 检查后端服务状态
curl http://localhost:8080/health

# 检查 SSLcat 配置
sslcat -config sslcat.conf -validate

# 检查网络连接
telnet backend-host 8080

# 检查 SSLcat 日志
docker logs sslcat
```

### 问题：请求路由不正确
**症状**: 请求发送到错误的后端或未被处理

**解决方案**:
```yaml
# sslcat.conf - 检查代理规则
proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:8080"  # 验证这是正确的
      ssl: true
      path: "/api"  # 如果需要，添加路径
```

```bash
# 测试代理规则
curl -H "Host: example.com" http://localhost/api/test

# 检查 SSLcat 配置
sslcat -config sslcat.conf -test
```

### 问题：头部未传递
**症状**: 后端未收到预期的头部

**解决方案**:
```yaml
# sslcat.conf - 配置头部传递
proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:8080"
      headers:
        pass_through: true  # 传递所有头部
        custom:
          X-Forwarded-Proto: "https"
          X-Real-IP: "$remote_addr"
```

## 负载均衡问题

### 问题：负载均衡不工作
**症状**: 所有请求都发送到一个后端

**可能原因**:
- 健康检查失败
- 后端服务无响应
- 负载均衡配置错误

**解决方案**:
```yaml
# sslcat.conf - 检查负载均衡配置
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
# 检查后端健康状态
curl http://localhost:8080/health
curl http://localhost:8081/health
curl http://localhost:8082/health

# 测试负载均衡
for i in {1..10}; do
  curl -s https://example.com/api/instance
done
```

### 问题：后端健康检查失败
**症状**: 后端被标记为不健康

**解决方案**:
```bash
# 检查健康检查端点
curl http://localhost:8080/health

# 检查健康检查配置
curl -I http://localhost:8080/health

# 验证后端服务正在运行
ps aux | grep your-backend-service
```

## 性能问题

### 问题：CPU 使用率高
**症状**: SSLcat 使用高 CPU 资源

**解决方案**:
```yaml
# sslcat.conf - 优化配置
server:
  workers: 4  # 根据 CPU 核心数调整
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
# 监控 CPU 使用率
top -p $(pgrep sslcat)

# 检查 SSLcat 指标
curl http://localhost:8080/metrics | grep cpu
```

### 问题：内存使用率高
**症状**: SSLcat 使用过多内存

**解决方案**:
```yaml
# sslcat.conf - 优化内存使用
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
# 监控内存使用率
ps aux | grep sslcat

# 检查内存指标
curl http://localhost:8080/metrics | grep memory
```

### 问题：响应时间慢
**症状**: 高响应时间，页面加载慢

**解决方案**:
```yaml
# sslcat.conf - 启用缓存和压缩
proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:8080"
      caching:
        enabled: true
        ttl: 3600  # 1小时
      compression:
        enabled: true
        types: ["text/html", "text/css", "application/javascript"]
```

```bash
# 测试响应时间
curl -w "@curl-format.txt" -o /dev/null -s https://example.com

# 检查后端响应时间
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8080
```

## 网络问题

### 问题：连接被拒绝
**症状**: "连接被拒绝"错误

**解决方案**:
```bash
# 检查 SSLcat 是否运行
ps aux | grep sslcat

# 检查端口绑定
netstat -tlnp | grep :80
netstat -tlnp | grep :443

# 检查防火墙规则
iptables -L
ufw status
```

### 问题：DNS 解析问题
**症状**: 域名未解析到 SSLcat 服务器

**解决方案**:
```bash
# 检查 DNS 解析
nslookup example.com
dig example.com

# 检查 DNS 传播
dig @8.8.8.8 example.com
dig @1.1.1.1 example.com

# 使用不同 DNS 服务器测试
curl -H "Host: example.com" http://your-server-ip/
```

## 配置问题

### 问题：配置语法错误
**症状**: SSLcat 启动失败，配置错误

**解决方案**:
```bash
# 验证配置
sslcat -config sslcat.conf -validate

# 检查 YAML 语法
python -c "import yaml; yaml.safe_load(open('sslcat.conf'))"

# 测试配置
sslcat -config sslcat.conf -test
```

### 问题：配置文件缺失
**症状**: SSLcat 找不到配置文件

**解决方案**:
```bash
# 检查文件权限
ls -la sslcat.conf

# 检查文件路径
pwd
ls -la sslcat.conf

# 使用绝对路径
sslcat -config /full/path/to/sslcat.conf
```

## 监控问题

### 问题：指标不可用
**症状**: 指标端点无响应

**解决方案**:
```yaml
# sslcat.conf - 启用指标
monitoring:
  metrics:
    enabled: true
    endpoint: "/metrics"
    port: 8080
```

```bash
# 检查指标端点
curl http://localhost:8080/metrics

# 检查是否启用了监控
curl http://localhost:8080/health
```

### 问题：追踪不工作
**症状**: 监控系统中没有追踪数据

**解决方案**:
```yaml
# sslcat.conf - 启用追踪
monitoring:
  tracing:
    enabled: true
    sample_rate: 1.0
    exporters:
      jaeger:
        endpoint: "http://jaeger:14268/api/traces"
```

```bash
# 检查追踪配置
curl -H "traceparent: 00-test-trace-id-test-span-id-01" https://example.com

# 检查追踪头部
curl -I https://example.com | grep -i trace
```

## Docker 问题

### 问题：容器未启动
**症状**: Docker 容器立即退出

**解决方案**:
```bash
# 检查容器日志
docker logs sslcat

# 检查容器状态
docker ps -a

# 检查配置文件
docker run --rm -v $(pwd)/sslcat.conf:/app/sslcat.conf sslcat:latest -validate
```

### 问题：卷挂载问题
**症状**: 配置未加载，数据未持久化

**解决方案**:
```bash
# 检查卷挂载
docker inspect sslcat

# 检查文件权限
ls -la sslcat.conf

# 测试卷挂载
docker run --rm -v $(pwd)/sslcat.conf:/app/sslcat.conf sslcat:latest -test
```

## 调试工具

### SSLcat 调试模式
```yaml
# sslcat.conf
server:
  debug: true
  log_level: "DEBUG"
```

### 日志分析
```bash
# 查看 SSLcat 日志
docker logs sslcat

# 实时跟踪日志
docker logs -f sslcat

# 过滤特定日志级别
docker logs sslcat 2>&1 | grep ERROR
```

### 网络调试
```bash
# 测试连接
telnet example.com 80
telnet example.com 443

# 检查 SSL/TLS
openssl s_client -connect example.com:443 -servername example.com

# 使用 curl 测试
curl -v https://example.com
```

### 性能调试
```bash
# 监控系统资源
top -p $(pgrep sslcat)
htop

# 检查网络连接
netstat -tlnp | grep sslcat
ss -tlnp | grep sslcat

# 监控磁盘 I/O
iostat -x 1
```

## 获取帮助

### 日志收集
报告问题时，收集以下信息：

```bash
# SSLcat 版本
sslcat --version

# 配置文件
cat sslcat.conf

# 系统信息
uname -a
cat /etc/os-release

# SSLcat 日志
docker logs sslcat > sslcat.log

# 系统日志
journalctl -u sslcat > system.log
```

### 社区支持
- **GitHub Issues**: [报告错误](https://github.com/xurenlu/sslcat/issues)
- **讨论**: [社区讨论](https://github.com/xurenlu/sslcat/discussions)
- **文档**: 这份综合指南

## 相关文档

- [性能故障排除](performance.md)
- [SSL 错误](ssl-errors.md)
- [配置指南](../configuration/basic.md)
- [监控指南](../features/monitoring.md)

---

*本故障排除指南涵盖了最常见的问题。如果遇到此处未涵盖的特定问题，请查看其他故障排除指南或联系社区。*

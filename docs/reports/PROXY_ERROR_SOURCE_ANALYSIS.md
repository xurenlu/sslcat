# 代理错误请求来源分析

## 📊 当前情况

**问题统计**:
- **5分钟内**: 34,404 条代理错误日志（约 115 条/秒）
- **主要错误域名**: 
  - `gg.some.im` -> `http://127.0.0.1:80` (context canceled)
  - `api.myownx.com` -> `http://127.0.0.1:8812` (connection refused)

**问题**: 现有的错误日志**不包含**客户端IP、User-Agent等请求特征信息

## 🔍 为什么现有日志没有这些信息？

查看当前的错误日志格式：
```
time="2025-12-27 04:10:44" level=error msg="Proxy error gg.some.im -> http://127.0.0.1:80: context canceled" component=proxy_manager
```

原因：之前的错误日志记录代码只记录了基本的错误信息（域名、目标、错误类型），没有包含请求对象 `*http.Request` 中的客户端信息。

## ✅ 已实施的修复

我已经修改了代码，现在错误日志会包含以下信息：

### 1. 增强的错误日志格式

**修改文件**: `internal/proxy/manager.go`

**新增字段**:
- `client_ip`: 客户端真实IP地址
- `user_agent`: User-Agent 字符串
- `method`: HTTP 方法（GET/POST等）
- `path`: 请求路径
- `referer`: Referer 头部（如果存在）

**日志格式示例**:
```json
{
  "level": "error",
  "msg": "Proxy error gg.some.im -> http://127.0.0.1:80: context canceled",
  "component": "proxy_manager",
  "client_ip": "123.45.67.89",
  "user_agent": "Mozilla/5.0...",
  "method": "GET",
  "path": "/api/endpoint",
  "referer": "https://example.com"
}
```

### 2. 错误日志限流

- 相同错误每分钟最多记录一次（包含客户端信息）
- 跳过的错误每100次记录一次统计信息

## 🔧 如何查看请求来源（部署新版本后）

### 方法1: 实时监控错误日志

部署新版本后，查看新的错误日志：

```bash
# 实时查看包含客户端信息的错误日志
sudo journalctl -u sslcat -f | grep "Proxy error"

# 查看最近的错误，提取客户端IP
sudo journalctl -u sslcat --since '5 minutes ago' | \
  grep "Proxy error" | \
  grep -oP '"client_ip":"[^"]+"' | \
  sort | uniq -c | sort -rn
```

### 方法2: 分析 User-Agent 分布

```bash
# 提取 User-Agent 统计
sudo journalctl -u sslcat --since '5 minutes ago' | \
  grep "Proxy error" | \
  grep -oP '"user_agent":"[^"]+"' | \
  sort | uniq -c | sort -rn | head -20
```

### 方法3: 通过 pprof 分析（临时方案）

如果新版本还未部署，可以通过 pprof 查看当前的 goroutine 堆栈：

```bash
# 查看活跃的连接
ssh rocky@shifen.de "curl -s http://127.0.0.1/debug/pprof/goroutine?debug=2" | \
  grep -E 'gg.some.im|api.myownx.com' | \
  head -20
```

## 📝 临时诊断脚本

在部署新版本之前，可以使用以下脚本分析网络连接：

```bash
#!/bin/bash
# analyze_proxy_errors.sh

echo "=== 分析 gg.some.im 和 api.myownx.com 的错误请求 ==="

# 1. 检查活跃连接
echo -e "\n1. 当前到 127.0.0.1:80 和 127.0.0.1:8812 的连接:"
sudo ss -tnp | grep -E ':80 |:8812 ' | grep ESTAB | \
  awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn

# 2. 检查错误日志频率
echo -e "\n2. 错误日志频率（每分钟）:"
sudo journalctl -u sslcat --since '5 minutes ago' | \
  grep -E '(gg.some.im|api.myownx.com)' | \
  wc -l | awk '{print "总错误数:", $1, "(" $1/5, "条/分钟)"}'

# 3. 检查是否有外部连接
echo -e "\n3. 外部连接到 SSLcat (80/443端口):"
sudo ss -tnp | grep -E ':80 |:443 ' | grep ESTAB | \
  awk '{print $5}' | cut -d: -f1 | grep -v '127.0.0.1' | \
  sort | uniq -c | sort -rn | head -20

# 4. 检查时间分布
echo -e "\n4. 错误时间分布:"
sudo journalctl -u sslcat --since '1 hour ago' | \
  grep -E '(gg.some.im|api.myownx.com)' | \
  awk '{print $3}' | cut -d: -f1-2 | sort | uniq -c
```

## 🎯 可能的情况分析

基于错误类型 `context canceled`，可能的原因：

### 1. 客户端主动取消请求
- **特征**: 大量 `context canceled` 错误
- **可能原因**:
  - 客户端超时设置过短
  - 客户端在等待响应时关闭连接
  - 爬虫或自动化工具请求

### 2. 后端服务不可用
- **特征**: `connection refused` 错误
- **可能原因**:
  - 后端服务未启动或崩溃
  - 端口被防火墙阻止
  - 服务负载过高拒绝连接

### 3. 内部请求循环
- **特征**: 目标地址是 `127.0.0.1:80`
- **可能原因**:
  - SSLcat 代理到自己
  - 配置错误导致循环代理

## 🚀 建议的下一步行动

1. **立即部署新版本**
   - 新版本会记录客户端IP和User-Agent
   - 可以立即看到请求来源

2. **检查代理配置**
   ```bash
   ssh rocky@shifen.de "sudo cat /etc/sslcat/sslcat.conf | jq '.proxy.rules[] | select(.domain == \"gg.some.im\" or .domain == \"api.myownx.com\")'"
   ```

3. **检查后端服务状态**
   ```bash
   ssh rocky@shifen.de "sudo netstat -tlnp | grep -E ':80 |:8812 '"
   ```

4. **启用访问日志（临时）**
   如果需要更详细的分析，可以临时启用访问日志：
   ```json
   {
     "server": {
       "access_log_enabled": true,
       "access_log_path": "/var/log/sslcat/access.log"
     }
   }
   ```

## 📋 部署新版本后的检查清单

部署新版本后，立即检查：

- [ ] 错误日志是否包含 `client_ip` 字段
- [ ] 错误日志是否包含 `user_agent` 字段
- [ ] 统计主要来源IP地址
- [ ] 分析 User-Agent 分布
- [ ] 检查是否有异常请求模式

## 📞 快速命令参考

```bash
# 查看最近的错误（包含客户端信息）
ssh rocky@shifen.de "sudo journalctl -u sslcat -n 50 --no-pager | grep 'Proxy error'"

# 统计来源IP
ssh rocky@shifen.de "sudo journalctl -u sslcat --since '10 minutes ago' --no-pager | grep 'Proxy error' | grep -oP '\"client_ip\":\"[^\"]+\"' | sort | uniq -c | sort -rn | head -10"

# 统计 User-Agent
ssh rocky@shifen.de "sudo journalctl -u sslcat --since '10 minutes ago' --no-pager | grep 'Proxy error' | grep -oP '\"user_agent\":\"[^\"]+\"' | sort | uniq -c | sort -rn | head -10"
```


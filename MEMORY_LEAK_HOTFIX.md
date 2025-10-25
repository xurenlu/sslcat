# 🚨 SSLcat 内存泄漏紧急修复补丁

## 问题诊断

生产环境 sslcat 占满内存的可能原因：

1. **日志流客户端泄漏** - LogStream 客户端连接没有正确清理
2. **健康检查 goroutine 泄漏** - 负载均衡健康检查创建过多 goroutine
3. **日志监听器泄漏** - LogWatcher 没有正确关闭
4. **缓存无限增长** - 内存缓存没有正确的清理机制

## 🔧 紧急修复方案

### 1. 立即重启服务（临时解决）

```bash
# 停止服务
sudo systemctl stop sslcat

# 等待进程完全退出
sleep 10

# 检查进程是否完全退出
ps aux | grep sslcat | grep -v grep

# 启动服务
sudo systemctl start sslcat

# 监控内存使用
watch -n 1 'ps aux | grep sslcat | grep -v grep'
```

### 2. 检查内存使用情况

```bash
# 查看 sslcat 进程内存使用
ps aux | grep sslcat | grep -v grep

# 查看系统内存使用
free -h

# 查看 goroutine 数量（如果启用了 pprof）
curl -s "http://localhost:8080/debug/pprof/goroutine?debug=1" | grep -c "goroutine"
```

### 3. 配置优化（减少内存占用）

编辑配置文件 `/etc/sslcat/sslcat.conf`：

```json
{
  "server": {
    "log_level": "warn",
    "debug": false,
    "access_log_enabled": false,
    "detailed_logging": false
  },
  "load_balancer": {
    "health_check_interval": 120,
    "max_concurrent_checks": 10
  },
  "cache": {
    "max_size": "100MB",
    "cleanup_interval": "5m"
  }
}
```

### 4. 监控脚本

创建监控脚本 `monitor_memory.sh`：

```bash
#!/bin/bash

while true; do
    # 获取 sslcat 进程信息
    SSL_PID=$(pgrep sslcat)
    if [ -n "$SSL_PID" ]; then
        MEMORY=$(ps -p $SSL_PID -o rss --no-headers)
        CPU=$(ps -p $SSL_PID -o %cpu --no-headers)
        echo "$(date): SSLcat PID: $SSL_PID, Memory: ${MEMORY}KB, CPU: ${CPU}%"
        
        # 如果内存使用超过 1GB，重启服务
        if [ "$MEMORY" -gt 1048576 ]; then
            echo "$(date): Memory usage too high (${MEMORY}KB), restarting sslcat..."
            sudo systemctl restart sslcat
            sleep 30
        fi
    else
        echo "$(date): SSLcat process not found"
    fi
    
    sleep 60
done
```

### 5. 长期解决方案

#### 5.1 修复日志流客户端泄漏

在 `internal/runner/realtime_logs.go` 中添加客户端清理机制：

```go
// 添加定期清理机制
func (ls *LogStream) cleanupStaleClients() {
    ls.clientMutex.Lock()
    defer ls.clientMutex.Unlock()
    
    for clientID, ch := range ls.clients {
        select {
        case <-ch:
            // 客户端还在活跃
        default:
            // 客户端可能已断开，清理
            close(ch)
            delete(ls.clients, clientID)
            ls.log.Debugf("Cleaned up stale client: %s", clientID)
        }
    }
}
```

#### 5.2 修复健康检查 goroutine 泄漏

在 `internal/loadbalancer/healthcheck.go` 中限制并发：

```go
// 限制最大并发健康检查数量
maxConcurrent := 10
if len(backends) > maxConcurrent {
    // 分批检查，避免一次性创建过多 goroutine
    for i := 0; i < len(backends); i += maxConcurrent {
        end := i + maxConcurrent
        if end > len(backends) {
            end = len(backends)
        }
        
        batch := backends[i:end]
        // 处理这一批后端
        for _, backend := range batch {
            go hc.checkBackendHealth(backend)
        }
        
        // 等待这一批完成
        time.Sleep(1 * time.Second)
    }
}
```

#### 5.3 添加内存监控和自动重启

```bash
# 创建 systemd 服务监控
sudo tee /etc/systemd/system/sslcat-monitor.service > /dev/null << 'EOF'
[Unit]
Description=SSLcat Memory Monitor
After=sslcat.service

[Service]
Type=simple
ExecStart=/usr/local/bin/sslcat-monitor.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable sslcat-monitor
sudo systemctl start sslcat-monitor
```

## 🚨 紧急处理步骤

1. **立即重启服务**（临时解决内存问题）
2. **应用配置优化**（减少内存占用）
3. **部署监控脚本**（防止再次发生）
4. **升级到最新版本**（包含内存泄漏修复）

## 📊 预期效果

- **内存使用**：从占满内存降低到正常水平（< 500MB）
- **稳定性**：避免内存泄漏导致的崩溃
- **监控**：实时监控内存使用情况
- **自动恢复**：内存过高时自动重启

## 🔍 后续监控

```bash
# 持续监控内存使用
watch -n 5 'ps aux | grep sslcat | grep -v grep && free -h'

# 检查日志
journalctl -u sslcat -f

# 检查系统资源
htop
```

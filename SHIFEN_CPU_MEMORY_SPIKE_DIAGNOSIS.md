# shifen.de 服务器 sslcat CPU 和内存飙升诊断报告

**诊断时间**: 2025-12-30 10:38 UTC  
**服务器**: shifen.de (rocky@shifen.de)  
**进程**: sslcat (PID: 1214804)  
**运行时长**: 46 分钟

## 🔴 严重问题摘要

### 1. **Goroutine 泄漏严重**
- **当前 Goroutine 数量**: 23,000 - 26,000+
- **基线 Goroutine 数量**: 31
- **泄漏增长**: 超过 **26,000 个 goroutine**
- **严重程度**: 🔴 极其严重

### 2. **内存泄漏严重**
- **当前内存使用**: 2,891 - 4,081 MB
- **基线内存**: 100 MB
- **内存增长**: 超过 **3,900 MB**
- **系统内存占用**: 6,626 MB (Sys)
- **严重程度**: 🔴 极其严重

### 3. **CPU 使用率异常高**
- **当前 CPU 使用率**: **41-43%**
- **运行 46 分钟消耗**: 20 分钟 CPU 时间
- **平均 CPU 使用率**: 约 43%
- **严重程度**: 🔴 严重

## 📊 详细数据分析

### 资源使用情况

```
进程信息:
PID:      1214804
用户:     root
CPU:      41.3%
内存:     115 MB (RSS) / 8.6 GB (VIRT)
运行时间: 46 分钟
CPU 时间: 20 分钟 8 秒
```

### 内存统计 (最新)

```
Alloc        = 2891.60 MB  (当前堆内存分配)
TotalAlloc   = 126121.89 MB (累计堆内存分配)
Sys          = 6626.70 MB  (从系统获取的内存)
NumGC        = 1837        (GC 次数)
HeapAlloc    = 2891.60 MB  (堆内存分配)
HeapSys      = 6422.84 MB  (堆系统内存)
HeapIdle     = 3525.23 MB  (堆空闲内存)
HeapInuse    = 2897.61 MB  (堆使用中内存)
HeapReleased = 3525.11 MB  (堆已释放内存)
StackInuse   = 155.34 MB   (栈使用中内存)
StackSys     = 155.34 MB   (栈系统内存)
```

### Goroutine 泄漏时间线

| 时间 | Goroutine 数量 | 增长量 |
|------|---------------|--------|
| 10:30:06 | 25,059 | +25,028 |
| 10:31:07 | 26,370 | +26,339 |
| 10:32:08 | 24,456 | +24,425 |
| 10:33:09 | 23,669 | +23,638 |

**观察**: Goroutine 数量在 23,000-26,000 之间波动，但始终保持在极高水平。

## 🎯 根本原因分析

### 主要触发源: **恶意扫描攻击**

**攻击者 IP**: `34.74.55.33`  
**攻击目标**: `gg.some.im` (代理到 `http://127.0.0.1:80`)  
**攻击特征**: WordPress 漏洞扫描

#### 攻击模式

1. **高频请求**:
   - 每秒发送大量请求
   - 请求路径: `/`, `/wp-includes/wlwmanifest.xml`, `/website/wp-includes/wlwmanifest.xml`, 等

2. **后端服务不可用**:
   - `gg.some.im` 配置的后端 `http://127.0.0.1:80` **没有运行**
   - 导致所有请求超时或被取消

3. **错误日志示例**:
```
Proxy error gg.some.im -> http://127.0.0.1:80: net/http: timeout awaiting response headers
Proxy error gg.some.im -> http://127.0.0.1:80: context canceled
```

### 问题链条

```
攻击者发起大量请求
    ↓
后端服务 127.0.0.1:80 不可用
    ↓
sslcat 创建大量 goroutine 尝试连接
    ↓
连接超时 / context canceled
    ↓
goroutine 未正确清理
    ↓
goroutine 泄漏累积
    ↓
内存持续增长
    ↓
CPU 忙于 GC 和 goroutine 调度
    ↓
系统性能严重下降
```

## 🔍 Goroutine 堆栈分析

### 泄漏的 Goroutine 类型

从堆栈信息可以看到大量的:

1. **HTTP 连接读取 goroutine**:
```go
goroutine 448777 [IO wait]:
net/http.(*connReader).backgroundRead
```

2. **HTTP 持久连接 goroutine**:
```go
goroutine 598239 [select]:
net/http.(*persistConn).writeLoop
```

3. **HTTP Transport 相关 goroutine**:
```go
goroutine 303945 [IO wait]:
net/http.(*persistConn).readLoop
```

**结论**: 这些都是 HTTP 客户端尝试连接后端时创建的 goroutine，由于后端不可用，这些 goroutine 卡在等待状态，未能正确清理。

## 🛠️ 解决方案

### 立即措施 (紧急)

#### 1. **封禁攻击 IP**

```bash
# 在服务器上执行
ssh rocky@shifen.de "sudo iptables -A INPUT -s 34.74.55.33 -j DROP"
ssh rocky@shifen.de "sudo iptables-save > /etc/iptables/rules.v4"
```

#### 2. **修复后端配置**

检查 `gg.some.im` 的配置:

```bash
ssh rocky@shifen.de "cat /etc/sslcat/sslcat.conf | grep -A 10 'gg.some.im'"
```

**选项 A**: 如果后端服务应该运行但没有运行，启动它:
```bash
# 检查后端服务状态
ssh rocky@shifen.de "sudo systemctl status <backend-service>"
# 启动后端服务
ssh rocky@shifen.de "sudo systemctl start <backend-service>"
```

**选项 B**: 如果后端服务已废弃，删除该域名配置:
```bash
# 编辑配置文件，删除 gg.some.im 相关配置
ssh rocky@shifen.de "sudo vi /etc/sslcat/sslcat.conf"
# 重启 sslcat
ssh rocky@shifen.de "sudo systemctl restart sslcat"
```

#### 3. **重启 sslcat 服务** (清理泄漏的 goroutine)

```bash
ssh rocky@shifen.de "sudo systemctl restart sslcat"
```

### 中期措施 (24小时内)

#### 1. **启用 WAF 规则防止扫描**

在 sslcat 配置中添加 WAF 规则:

```json
{
  "waf": {
    "enabled": true,
    "rules": [
      {
        "name": "Block WordPress Scan",
        "pattern": ".*wp-includes.*|.*wp-content.*|.*xmlrpc\\.php.*",
        "action": "block",
        "rate_limit": {
          "requests": 10,
          "window": "1m"
        }
      }
    ]
  }
}
```

#### 2. **配置速率限制**

针对 `gg.some.im` 添加严格的速率限制:

```json
{
  "domains": {
    "gg.some.im": {
      "rate_limit": {
        "requests_per_second": 5,
        "burst": 10
      }
    }
  }
}
```

### 长期措施 (代码修复)

#### 1. **修复 HTTP Client Goroutine 泄漏**

**问题代码位置**: `internal/proxy/manager.go`

需要确保:
- 所有 HTTP 请求都有合理的超时设置
- Context 被正确传递和取消
- HTTP Client 使用连接池且有最大连接数限制

**建议修复**:

```go
// 在创建 HTTP Client 时设置合理的超时和连接池限制
client := &http.Client{
    Timeout: 30 * time.Second,
    Transport: &http.Transport{
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 10,
        MaxConnsPerHost:     20,
        IdleConnTimeout:     90 * time.Second,
        DisableKeepAlives:   false,
        // 重要: 设置响应头超时
        ResponseHeaderTimeout: 10 * time.Second,
        // 重要: 设置拨号超时
        DialContext: (&net.Dialer{
            Timeout:   5 * time.Second,
            KeepAlive: 30 * time.Second,
        }).DialContext,
    },
}
```

#### 2. **添加 Goroutine 泄漏自动恢复**

在 `internal/monitor/goroutine_monitor.go` 中添加:

```go
// 当 goroutine 数量超过阈值时，自动触发紧急措施
if count > criticalThreshold {
    log.Error("Goroutine count exceeds critical threshold, triggering emergency recovery")
    
    // 1. 记录详细堆栈到文件
    dumpGoroutineStackToFile()
    
    // 2. 触发告警
    sendCriticalAlert()
    
    // 3. 可选: 自动重启 (需要配置)
    if cfg.AutoRestart {
        triggerGracefulRestart()
    }
}
```

#### 3. **改进后端健康检查**

添加后端健康检查，当后端不可用时快速失败:

```go
// 定期检查后端健康状态
func (m *ProxyManager) healthCheck(backend string) {
    client := &http.Client{Timeout: 2 * time.Second}
    resp, err := client.Get(backend)
    if err != nil || resp.StatusCode >= 500 {
        m.markBackendUnhealthy(backend)
        // 快速失败，不创建新的连接尝试
    }
}
```

## 📈 监控建议

### 1. **设置告警阈值**

```yaml
alerts:
  - name: goroutine_leak
    condition: goroutine_count > 1000
    action: notify
    
  - name: goroutine_critical
    condition: goroutine_count > 5000
    action: restart
    
  - name: memory_leak
    condition: memory_mb > 1024
    action: notify
    
  - name: memory_critical
    condition: memory_mb > 2048
    action: restart
```

### 2. **启用 pprof 持续监控**

确保 pprof 端口可访问 (当前配置已启用):

```bash
# 定期收集 goroutine profile
ssh rocky@shifen.de "curl -s http://localhost:6060/debug/pprof/goroutine?debug=2 > /tmp/goroutine-$(date +%s).txt"

# 定期收集 heap profile
ssh rocky@shifen.de "curl -s http://localhost:6060/debug/pprof/heap > /tmp/heap-$(date +%s).pprof"
```

### 3. **日志分析**

设置日志分析规则，自动检测异常模式:

```bash
# 检测高频错误
journalctl -u sslcat -f | grep -E "timeout|context canceled" | awk '{print $NF}' | sort | uniq -c | sort -rn
```

## 🎯 预期效果

执行上述措施后，预期:

1. **立即**: 
   - 攻击流量被阻断
   - CPU 使用率降至 < 5%
   - 内存使用降至 < 200 MB
   - Goroutine 数量降至 < 100

2. **24小时内**:
   - 系统稳定运行
   - 无新的 goroutine 泄漏
   - 内存使用稳定

3. **长期**:
   - 自动防御类似攻击
   - 系统自愈能力增强
   - 监控告警完善

## 📝 总结

**根本原因**: 恶意扫描攻击 + 后端服务不可用 + HTTP Client Goroutine 泄漏

**影响范围**: 
- CPU 使用率 41%
- 内存泄漏 3.9 GB
- Goroutine 泄漏 26,000+

**紧急程度**: 🔴 极高 - 需要立即处理

**建议操作顺序**:
1. 封禁攻击 IP (立即)
2. 修复或删除 gg.some.im 配置 (立即)
3. 重启 sslcat 服务 (立即)
4. 添加 WAF 规则 (24小时内)
5. 修复代码中的 goroutine 泄漏 (1周内)
6. 完善监控告警 (1周内)

---

**诊断工具使用记录**:
- `ps aux` - 进程资源使用
- `systemctl status` - 服务状态
- `journalctl` - 系统日志分析
- sslcat 内置监控 - Goroutine 和内存监控
- pprof (配置已启用但端口未响应)

**下一步行动**: 请确认是否执行上述紧急措施。


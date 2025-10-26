# SSLcat 每天早上 4:18 内存暴涨问题分析

## 问题描述

每天早上 4:18 sslcat 进程会突然占用内存很高，导致机器崩溃。

## 原因分析

经过代码搜索，没有找到在 4:18 执行的特定定时器。问题可能源于以下几个方面：

### 1. Go 垃圾回收（GC）行为

Go 的 GC 在没有明确限制的情况下会占用大量内存。当内存使用达到一定阈值时，GC 会触发长时间的 STW（Stop The World）阶段，导致：
- 内存突然增长
- CPU 占用率飙升
- 服务短暂无响应

### 2. 定时任务叠加

代码中有 41 个 `time.NewTicker` 实例，包括：
- 缓存清理任务（5分钟间隔）
- 监控检查任务（每分钟）
- 健康检查任务（60秒）
- 统计收集清理（每小时）
- AI 安全分析器（可配置间隔）
- SSL 证书检查（12小时）
- Docker 镜像清理（可配置小时）

虽然这些任务都有各自的间隔，但某些任务可能会在相近的时间点叠加执行。

### 3. 没有内存上限限制

代码中没有设置 Go 的内存限制（GOMEMLIMIT），导致 Go 运行时无限制增长内存。

## 解决方案

### 1. 添加 Go 运行时内存管理（已实施）

在 `deploy/sslcat.service` 中添加了以下环境变量：

```ini
# Go 运行时内存管理优化
Environment="GOMEMLIMIT=1536MiB"  # 限制最大内存为 1.5GB
Environment="GOGC=100"             # GC 目标百分比
Environment="GODEBUG=madvdontneed=1"  # 优化内存释放
```

**说明：**
- `GOMEMLIMIT`: 设置 Go 运行时可以使用的最大内存，超过这个限制会强制触发 GC
- `GOGC`: 控制 GC 频率，100 表示每增长 100% 内存触发一次 GC
- `madvdontneed=1`: 使用 Linux madvise(MADV_DONTNEED) 更快释放内存给操作系统

### 2. 内存监控脚本（已存在）

`sslcat-memory-monitor.sh` 脚本会每 30 秒检查一次内存使用，如果超过 1GB 会自动重启服务。

### 3. 配置优化建议

编辑 `/etc/sslcat/sslcat.conf`，减少内存占用：

```json
{
  "server": {
    "log_level": "warn",
    "debug": false,
    "access_log_enabled": false
  },
  "monitoring": {
    "enabled": true  // 启用监控器以检测内存泄漏
  },
  "cache": {
    "max_size": "100MB",
    "cleanup_interval": "5m"
  },
  "statistics": {
    "enabled": true,
    "max_data_age": "24h"
  },
  "ai_security": {
    "enabled": false  // 如果不需要可以禁用 AI 安全分析
  }
}
```

### 4. 部署步骤

```bash
# 1. 更新 systemd 服务文件
sudo cp deploy/sslcat.service /etc/systemd/system/sslcat.service

# 2. 重新加载 systemd
sudo systemctl daemon-reload

# 3. 重启服务应用新配置
sudo systemctl restart sslcat

# 4. 检查日志
sudo journalctl -u sslcat -f
```

### 5. 监控内存使用

```bash
# 实时监控内存
watch -n 1 'ps aux | grep sslcat | grep -v grep'

# 查看 Go 运行时的内存统计
curl -s http://localhost:8080/debug/pprof/heap?debug=1

# 查看 Goroutine 数量
curl -s http://localhost:8080/debug/pprof/goroutine?debug=1 | grep "goroutine"
```

## 进一步优化

### 如果问题仍然存在，可以考虑：

1. **降低 GOMEMLIMIT**（如果机器内存有限）：
   ```ini
   Environment="GOMEMLIMIT=1024MiB"  # 降低到 1GB
   ```

2. **调整 GC 频率**（更频繁的 GC，但会影响性能）：
   ```ini
   Environment="GOGC=50"  # 每增长 50% 触发一次 GC
   ```

3. **启用内存监控器**：
   配置文件中启用 `monitoring.enabled: true`，让内存监控器自动检测泄漏。

4. **检查是否有定时任务可以禁用**：
   - 如果不需要 AI 安全分析，禁用 `ai_security.enabled`
   - 如果不需要统计，禁用 `statistics.enabled`

## 预期效果

实施这些优化后：
- 内存使用上限被限制在 1.5GB
- GC 会提前触发，避免内存突然增长
- 内存监控脚本会自动检测并重启异常进程
- 系统会更加稳定，避免凌晨内存暴涨导致崩溃

## 监控建议

建议每天检查日志，确认内存使用情况：

```bash
# 查看前一天的内存峰值
grep "Memory:" /var/log/sslcat-monitor.log | sort -k 3 -n -r | head -10
```

如果仍然出现 4:18 内存暴涨的问题，请查看具体日志以确定是哪个任务触发的。


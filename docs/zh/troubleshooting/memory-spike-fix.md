# SSLcat 内存暴涨问题修复指南

## 问题现象

每天早上 4:18 左右，sslcat 进程会突然占用大量内存，导致服务器崩溃。

## 问题原因

经过详细排查，代码中**没有在 4:18 执行的特定定时器**。问题的根本原因是：

1. **Go 运行时没有内存上限限制**，导致 GC 可能触发长时间的 STW（Stop The World）阶段
2. **多个定时任务可能叠加执行**，短时间内消耗大量内存
3. **缺少内存管理环境变量**，Go 运行时会无限制增长内存

## 解决方案

### 已实施的修复

已在 `deploy/sslcat.service` 中添加 Go 运行时内存管理优化：

```ini
# Go 运行时内存管理优化
Environment="GOMEMLIMIT=1536MiB"     # 限制最大内存为 1.5GB
Environment="GOGC=100"               # GC 目标百分比
Environment="GODEBUG=madvdontneed=1" # 优化内存释放
```

### 部署步骤

```bash
# 1. 复制更新后的服务文件
sudo cp deploy/sslcat.service /etc/systemd/system/sslcat.service

# 2. 重新加载 systemd
sudo systemctl daemon-reload

# 3. 重启服务
sudo systemctl restart sslcat

# 4. 检查服务状态
sudo systemctl status sslcat
```

### 监控内存使用

```bash
# 查看实时内存使用
watch -n 1 'ps aux | grep sslcat | grep -v grep'

# 查看系统日志
sudo journalctl -u sslcat -f

# 查看内存监控日志
tail -f /var/log/sslcat-monitor.log
```

## 环境变量说明

### GOMEMLIMIT

设置 Go 运行时可以使用的最大内存。当达到这个限制时，会强制触发 GC。

- **默认值**: 无限制
- **推荐值**: `1536MiB`（1.5GB）
- **调整建议**: 根据服务器内存情况调整

### GOGC

控制 GC 频率的目标百分比。

- **默认值**: 100
- **含义**: 每次增长 100% 内存时触发 GC
- **调整建议**: 
  - 降低到 50：更频繁的 GC，减少内存峰值，但可能影响性能
  - 提高到 200：更少的 GC，更好的性能，但内存峰值更高

### GODEBUG=madvdontneed=1

使用 Linux madvise(MADV_DONTNEED) 更快地将内存释放给操作系统。

- **效果**: 优化内存释放速度
- **适用**: Linux 系统

## 进一步优化

如果内存问题仍然存在，可以尝试：

### 1. 降低内存限制

```ini
Environment="GOMEMLIMIT=1024MiB"  # 降低到 1GB
```

### 2. 更频繁的 GC

```ini
Environment="GOGC=50"  # 每增长 50% 触发一次 GC
```

### 3. 禁用不必要的功能

编辑 `/etc/sslcat/sslcat.conf`：

```json
{
  "ai_security": {
    "enabled": false  // 如果不需要可以禁用
  },
  "statistics": {
    "enabled": false  // 如果不需要可以禁用
  }
}
```

## 定时任务列表

代码中的主要定时任务：

| 任务 | 间隔 | 功能 |
|------|------|------|
| 缓存清理 | 5分钟 | 清理过期缓存 |
| 内存监控 | 1分钟 | 监控内存使用 |
| Goroutine 监控 | 1分钟 | 监控协程数量 |
| 健康检查 | 60秒 | 检查后端健康状态 |
| SSL 证书检查 | 12小时 | 检查证书到期 |
| SSL 证书续期 | 24小时 | 自动续期证书 |
| 统计清理 | 1小时 | 清理统计数据 |
| AI 安全分析 | 可配置 | AI 安全分析 |
| Docker 清理 | 可配置小时 | 清理 Docker 镜像 |

## 监控和诊断

### 检查内存泄漏

```bash
# 查看 pprof 内存信息
curl -s http://localhost:18080/debug/pprof/heap?debug=1

# 查看 Goroutine 信息
curl -s http://localhost:18080/debug/pprof/goroutine?debug=1
```

### 查看内存历史

```bash
# 查看内存监控日志
grep "Memory:" /var/log/sslcat-monitor.log | sort -k 3 -n -r | head -20
```

## 预防措施

1. **启用内存监控脚本**：`sslcat-memory-monitor.sh` 会自动检测并重启异常进程
2. **定期检查日志**：每天检查日志确认内存使用正常
3. **设置告警**：为内存使用设置告警阈值
4. **定期重启**：可以设置 cron 任务在凌晨低峰期重启服务

## 相关文档

- [MEMORY_SPIKE_4AM_ANALYSIS.md](../../MEMORY_SPIKE_4AM_ANALYSIS.md) - 详细问题分析
- [MEMORY_LEAK_HOTFIX.md](../../MEMORY_LEAK_HOTFIX.md) - 内存泄漏修复补丁
- [sslcat-memory-monitor.sh](../../sslcat-memory-monitor.sh) - 内存监控脚本


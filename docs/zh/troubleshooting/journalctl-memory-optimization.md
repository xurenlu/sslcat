# journalctl 内存优化说明

## 问题分析

### 为什么 journalctl 会占用内存？

**原因：**
1. **日志收集机制**：systemd 会将所有服务的 stdout/stderr 收集到 journald
2. **索引和存储**：每条日志都会建立索引，并在内存中缓存
3. **快速增长**：当服务产生大量日志时，journald 内存会快速增长

### SSLcat 的实际情况

```bash
# 当前 journalctl 占用
journalctl --disk-usage
# Archived and active journals take up 3.9G in the file system.

# SSLcat 每小时产生的日志
journalctl -u sslcat --since "1 hour ago" | wc -l
# 5197 条
```

**问题：**
- journalctl 已占用 3.9GB 磁盘空间
- 每小时产生约 5000 条日志
- 高频日志会快速填充 journald 的内存缓冲区

## 解决方案

### 方案 1：完全禁用 journald 收集（推荐）

修改 `/etc/systemd/system/sslcat.service`：

```ini
[Service]
StandardOutput=null
StandardError=null
```

**优点：**
- ✅ 完全不占用 journald 内存
- ✅ 不影响应用日志输出（应用内已使用 logrus 记录到文件）
- ✅ 最省资源

**缺点：**
- ❌ 无法通过 `journalctl -u sslcat` 查看日志
- ✅ 但可以通过应用日志文件查看：`tail -f /var/lib/sslcat/data/access.log`

### 方案 2：限制 journald 大小

修改 `/etc/systemd/journald.conf`：

```ini
[Journal]
SystemMaxUse=500M
SystemKeepFree=100M
MaxRetentionSec=7day
```

**缺点：**
- ⚠️ 影响整个系统的所有服务
- ⚠️ 可能导致其他重要日志被截断

### 方案 3：使用文件输出

```ini
[Service]
StandardOutput=file:/var/log/sslcat/output.log
StandardError=file:/var/log/sslcat/error.log
```

**优点：**
- ✅ 可以将日志写入文件
- ✅ 可控的日志轮转

**缺点：**
- ⚠️ 仍需要通过日志轮转控制大小

## 为什么推荐方案 1？

### SSLcat 的日志架构

SSLcat 使用 logrus 进行日志管理：

```go
// SSLcat 内建日志系统
logrus.SetOutput(os.Stdout)  // 输出到 stdout
logrus.SetLevel(logrus.WarnLevel)  // 只记录警告和错误
```

**实际情况：**
1. **应用日志** → stdout → journald → 占用内存
2. **访问日志** → 文件（`./data/access.log`）→ 不经过 journald
3. **错误日志** → stdout → journald → 占用内存

### 优化后的效果

**之前：**
```
应用日志 → stdout → journald → 3.9GB 占用
访问日志 → 文件
```

**优化后：**
```
应用日志 → null（丢弃）→ 节省内存
访问日志 → 文件（保留重要信息）
错误日志 → 应用内文件记录（如果需要）
```

## 如何查看日志？

### 方法 1：访问日志（最重要）

```bash
# 实时查看访问日志
tail -f /var/lib/sslcat/data/access.log

# 查看错误（nginx 格式）
tail -f /var/lib/sslcat/data/access.log | grep ERROR
```

### 方法 2：应用错误日志

如果开启了错误日志文件（可通过配置启用）：

```bash
tail -f /var/lib/sslcat/data/error.log
```

### 方法 3：系统监控

```bash
# 查看进程状态
systemctl status sslcat

# 查看最近启动信息
systemctl status sslcat -l --no-pager
```

## 部署修改

### 1. 更新 systemd 服务文件

```bash
sudo cp deploy/sslcat.service /etc/systemd/system/sslcat.service
sudo systemctl daemon-reload
sudo systemctl restart sslcat
```

### 2. 验证配置

```bash
# 检查服务状态
sudo systemctl status sslcat

# 验证不再写入 journald
sudo journalctl -u sslcat --since "1 minute ago" | wc -l
# 应该返回 0 或很少的条目

# 检查应用日志文件
tail -f /var/lib/sslcat/data/access.log
```

### 3. 清理旧的 journald 数据（可选）

```bash
# 清理旧日志
sudo journalctl --vacuum-time=7d
# 或
sudo journalctl --vacuum-size=500M

# 重启 journald
sudo systemctl restart systemd-journald
```

## 内存优化效果

### 预期效果

**之前：**
- journalctl: 3.9GB+
- 持续增长：每小时 +5000 条

**优化后：**
- journalctl: 大幅减少（减少约 1-2GB）
- 不再持续增长
- SSLcat 内存使用更加稳定

### 监控建议

```bash
# 定期检查 journalctl 大小
journalctl --disk-usage

# 检查磁盘空间
df -h

# 检查 SSLcat 内存
ps aux | grep sslcat
```

## 注意事项

⚠️ **重要**：
- 确保 SSLcat 的访问日志文件配置正确
- 定期检查日志文件大小，必要时启用日志轮转
- 重要错误应通过应用内的通知系统（如邮件/钉钉）发送

✅ **好处**：
- 减少 systemd-journald 的内存占用
- 降低 journald 的 CPU 使用
- 提高系统整体性能
- 更快的日志查询速度

## 总结

将 `StandardOutput` 和 `StandardError` 设置为 `null` 可以：

1. ✅ **节省内存**：journald 不再缓存大量日志
2. ✅ **提高性能**：减少 journald 的索引和存储开销
3. ✅ **保留重要信息**：访问日志和错误日志仍在文件中
4. ✅ **便于监控**：配合应用内置的监控和告警系统

这是一个生产环境的最佳实践！


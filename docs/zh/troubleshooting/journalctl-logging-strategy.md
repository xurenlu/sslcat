# journalctl 日志记录策略

## 配置方案

```ini
[Service]
StandardOutput=null     # 丢弃标准输出（减少内存占用）
StandardError=journal   # 保留错误日志（便于排查问题）
```

## 设计思路

### StandardOutput=null
**目的：** 减少内存占用

**为什么：**
- Info 级别的日志量大（每小时 5000+ 条）
- 正常运行时不太需要查看
- 日志级别设置为 `warn` 后，stdout 输出较少

**影响：**
- ✅ 节省大量 journald 内存
- ✅ 不影响访问日志（文件形式）
- ❌ 无法通过 `journalctl` 查看正常日志

### StandardError=journal
**目的：** 保留错误信息

**为什么：**
- ✅ 错误日志量小，不会大量占用内存
- ✅ 便于通过 `journalctl -u sslcat` 快速排查问题
- ✅ 系统级错误（如崩溃）会被记录

**如何查看：**
```bash
# 查看最近的错误
sudo journalctl -u sslcat -p err --since "1 hour ago"

# 查看所有错误和警告
sudo journalctl -u sslcat -p warning --since "1 hour ago"

# 实时监控错误
sudo journalctl -u sslcat -f -p warning
```

## 日志查看方式

### 1. 错误日志（推荐）
```bash
# 查看所有错误
sudo journalctl -u sslcat -p err

# 查看警告和错误
sudo journalctl -u sslcat -p warning
```

### 2. 访问日志
```bash
# 实时查看访问日志
tail -f /var/lib/sslcat/data/access.log

# 查看今天的访问日志
grep "$(date +%Y-%m-%d)" /var/lib/sslcat/data/access.log
```

### 3. 应用监控日志
```bash
# 内存监控警告
sudo journalctl -u sslcat | grep "内存"

# Goroutine 监控
sudo journalctl -u sslcat | grep "goroutine"

# 性能监控
sudo journalctl -u sslcat | grep "性能"
```

## 内存占用对比

### 之前（全部记录）
```
journalctl: 3.9GB+
每小时: +5000 条日志
持续增长
```

### 优化后（只记录错误）
```
journalctl: 预计 500MB-1GB
每小时: +50-100 条错误日志（if any）
稳定
```

**节省：** 约 2-3GB 内存

## 完整日志架构

```
SSLcat 应用
    ├── Stdout (Info日志) → null (丢弃) ✅ 节省内存
    ├── Stderr (Error日志) → journalctl ✅ 保留错误
    ├── 访问日志 → 文件 (/var/lib/sslcat/data/access.log) ✅ 完整记录
    └── 监控日志 → journalctl (错误级别) ✅ 重要告警
```

## 故障排查流程

### 场景 1：应用崩溃
```bash
# 查看崩溃信息
sudo journalctl -u sslcat -p err --since "10 minutes ago"

# 检查服务状态
sudo systemctl status sslcat
```

### 场景 2：性能问题
```bash
# 查看性能告警
sudo journalctl -u sslcat | grep "性能"
sudo journalctl -u sslcat | grep "响应时间"
```

### 场景 3：内存泄漏
```bash
# 查看内存告警
sudo journalctl -u sslcat | grep "内存"
sudo journalctl -u sslcat | grep "泄漏"
```

### 场景 4：访问问题
```bash
# 查看访问日志
tail -f /var/lib/sslcat/data/access.log

# 过滤错误
tail -f /var/lib/sslcat/data/access.log | grep ERROR
```

## 监控建议

### 定期检查 journalctl 大小
```bash
# 检查占用
journalctl --disk-usage

# 如果超过 1GB，清理旧日志
sudo journalctl --vacuum-time=7d
```

### 设置告警
```bash
# 检查是否有异常错误
sudo journalctl -u sslcat -p err --since "1 hour ago" | wc -l

# 如果超过阈值，发送告警
```

## 最佳实践

1. ✅ **定期清理**：每周检查 journalctl 大小
2. ✅ **监控错误**：设置错误日志告警
3. ✅ **查看访问日志**：主要通过文件日志排查问题
4. ✅ **使用 pprof**：通过 `/debug/pprof/` 进行性能分析
5. ✅ **保留重要信息**：访问日志和错误日志都有记录

## 总结

这是一个平衡的配置：
- 🎯 **节省内存**：丢弃大量 Info 日志
- 🔍 **保留错误**：错误日志仍可查看
- 📊 **完整记录**：访问日志完整保留
- ✅ **便于排查**：关键信息不丢失


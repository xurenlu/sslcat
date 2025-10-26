# 内存问题修复总结

## 问题分析

### 发现的问题

1. **频繁的 Info 日志输出**：`internal/proxy/manager.go:990` 行每小时产生约 3877 条 "最终发送的Host信息" 的 Info 日志
   - 即使配置了 `log_level: "warn"`，这些日志仍然在输出
   - 大量日志会占用内存和 CPU 资源

2. **内存监控基线设置过低**：`internal/monitor/memory_monitor.go` 中基线设置为 2.38 MB
   - 导致系统正常运行（1.5GB）也触发内存泄漏警告
   - 产生了大量的误报警告

## 修复方案

### 1. 修复日志级别配置（main.go）

在系统启动时优先使用配置文件中的 `log_level` 设置：

```go
// 日志级别 - 优先使用配置文件中的 log_level
if cfg.Server.LogLevel != "" {
    logger.Init(cfg.Server.LogLevel)
    log.Infof("日志级别已设置为: %s", cfg.Server.LogLevel)
} else if cfg.Server.Debug {
    logrus.SetLevel(logrus.DebugLevel)
} else {
    logrus.SetLevel(logrus.InfoLevel)
}
```

### 2. 将频繁日志改为 Debug 级别（internal/proxy/manager.go）

将高频的 Info 日志改为 Debug 级别：

```go
// 记录Host字段的最终状态 (Debug级别，避免频繁日志)
m.log.Debugf("最终发送的Host信息 - req.Host: %s, Header['Host']: %s", req.Host, req.Header.Get("Host"))
```

### 3. 修复内存监控基线设置（internal/monitor/memory_monitor.go）

设置合理的基线内存（至少 100MB）：

```go
// 设置合理的基线内存（至少 100MB，避免启动时内存过低导致的误报）
baselineAlloc := m.Alloc
if baselineAlloc < 100*1024*1024 {
    baselineAlloc = 100 * 1024 * 1024 // 100MB 作为最小基线
}
```

## 预期效果

1. **减少日志输出**：当 `log_level` 设置为 `warn` 时，高频的 Host 信息日志不再输出
2. **减少内存占用**：减少日志相关的内存分配
3. **减少误报**：内存监控基线设置为合理值，避免误报

## 部署状态

- ✅ 代码已提交：commit b564f2c
- ✅ 已打标签：v1.0.22
- ❌ 部署到线上：由于本地编译 webp 依赖问题，尚未部署
- ⚠️ 当前线上版本：已恢复并正常运行

## 后续步骤

1. 解决本地编译问题（webp 依赖）
2. 重新构建 Linux 版本
3. 部署到线上服务器
4. 监控内存使用情况，确认修复效果

## 新增功能：pprof 性能分析

已添加 Go 内置的 pprof 性能分析工具支持，可以通过以下方式访问：

```bash
# 查看内存情况
http://localhost:8080/debug/pprof/heap

# 分析 CPU
go tool pprof http://localhost:8080/debug/pprof/profile?seconds=30

# 查看 Goroutine
go tool pprof http://localhost:8080/debug/pprof/goroutine
```

详细使用说明请参考：`docs/zh/troubleshooting/pprof-usage.md`

## 注意事项

由于 macOS ARM64 环境下交叉编译到 Linux AMD64 的问题，建议：
- 使用 Docker 进行构建
- 或在 Linux 服务器上直接编译


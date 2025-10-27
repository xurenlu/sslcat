# 日志性能热修复 (Log Performance Hotfix)

## 🐛 问题描述

通过 pprof 性能分析发现，sslcat 在生产环境（非 Debug 模式）下存在严重的性能问题：

- **CPU 占用**: 40%
- **GC 时间占比**: 70% CPU 时间
- **内存分配**: 日志相关分配占总分配的 88.9% (约 124 GB/运行周期)

## 🔍 根本原因

三个高频日志函数存在严重的性能 bug：

### 1. `logResponseDetails` (每个响应都调用)
```go
// ❌ 问题代码
func (m *Manager) logResponseDetails(...) {
    if m.config.Server.Debug {
        // 第一个 WithFields 有保护
    }
    
    // ❌ 这部分代码没有保护，总是执行！
    headers := make(map[string]string)  // 分配内存
    for _, header := range importantHeaders {
        // 遍历 11 个 header
    }
    m.log.WithFields(...).Debug(...)  // 即使不输出，也会创建 map
}
```

**问题**: 即使在非 Debug 模式下（不输出日志），仍然会：
- 创建 headers map
- 遍历 11 个 header  
- 调用 `WithFields` 创建新的 logrus Fields map
- 这些对象立即被丢弃，触发频繁 GC

**数据**: 此函数导致 **50.46 GB** 内存分配（36.15%）

### 2. `logRequestDetails` (每个请求都调用)
**问题**: 同上，创建 headers map 和遍历在 Debug 检查外部

### 3. `loggingTransport.RoundTrip` (每个上游请求都调用)  
**问题**: 
- 构建 curl 命令字符串（即使不输出）
- 创建 headers map 和遍历 22 个 header

## ✅ 修复方案

在三个函数开头增加 early return，确保非 Debug 模式下立即返回：

```go
// ✅ 修复后
func (m *Manager) logResponseDetails(...) {
    // 立即返回，避免任何内存分配
    if !m.config.Server.Debug {
        return
    }
    
    // 以下代码只在 Debug 模式下执行
    targetInfo := m.buildTargetInfo(rule)
    m.log.WithFields(...).Debug(...)
    
    headers := make(map[string]string)
    // ...
}
```

## 📊 性能改善预期

| 指标 | 修复前 | 修复后 | 改善 |
|------|--------|--------|------|
| CPU 占用 | 40% | 5-10% | **↓ 60-80%** |
| GC CPU 占比 | 70% | 10-15% | **↓ 55%** |
| 日志相关内存分配 | 124 GB (88.9%) | ~0 GB | **↓ 99%** |
| 总内存分配 | 139.6 GB | ~15 GB | **↓ 89%** |

## 🔬 性能分析数据

### CPU Profile (30秒采样)
```
Duration: 30.14s
Total samples: 23.13s (76.75% CPU 利用率)

Top CPU 消耗:
- runtime.gcBgMarkWorker: 15.96s (69.00%) - GC 标记
- runtime.scanobject: 4.61s (19.93%) - GC 扫描对象
- proxy.logResponseDetails: 5.37s (23.22%) - ❌ 问题函数
- logrus.WithFields: 67.26 GB 分配 (48.19%) - ❌ 日志分配
```

### Heap Profile (内存分配)
```
总分配空间: 139.57 GB

Top 分配:
1. logrus.WithFields: 67.26 GB (48.19%) ❌
2. proxy.logResponseDetails: 50.46 GB (36.15%) ❌  
3. proxy.ProxyRequest.func1: 3.60 GB (2.58%)
4. proxy.buildTargetInfo: 3.58 GB (2.56%)

当前内存使用: 1.39 GB (其中 1.37 GB 是 bigcache - 正常)
```

## 📝 修改文件

- `internal/proxy/manager.go`
  - `logResponseDetails()` - 行 1791-1850
  - `logRequestDetails()` - 行 1708-1774
  - `loggingTransport.RoundTrip()` - 行 1945-2015

## ✅ 测试验证

修复后应该观察到：
1. CPU 占用从 40% 降至 5-10%
2. 内存使用稳定在 1.5 GB 左右（缓存占用）
3. GC 暂停时间显著减少
4. 响应延迟降低

## 🚀 部署建议

此修复为热修复，建议立即部署到生产环境：

```bash
# 1. 编译新版本
make build-linux

# 2. 备份现有二进制
sudo cp /opt/sslcat/sslcat /opt/sslcat/sslcat.backup.$(date +%Y%m%d_%H%M%S)

# 3. 部署新版本
sudo systemctl stop sslcat
sudo cp build/sslcat-linux-amd64 /opt/sslcat/sslcat
sudo systemctl start sslcat

# 4. 验证性能
ps aux | grep sslcat  # 观察 CPU 占用
curl http://localhost/debug/pprof/profile?seconds=30 -o profile.pprof
```

## 📌 版本信息

- 修复版本: v1.0.22-rc1  
- 修复日期: 2025-10-28
- 修复类型: 性能热修复 (Performance Hotfix)
- 优先级: 🔴 高 (High Priority)


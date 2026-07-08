# 使用 pprof 排查内存泄漏实战指南

## 前置条件

已集成 pprof，SSLcat 运行后可通过以下端点访问：
- `http://shifen.de:8080/debug/pprof/` (需要确保 8080 端口可访问)

## 排查内存泄漏的完整流程

### 步骤 1：实时查看内存使用情况

```bash
# 方式 1：浏览器访问（最简单）
http://shifen.de:8080/debug/pprof/heap

# 方式 2：使用 go tool pprof（更详细）
go tool pprof http://shifen.de:8080/debug/pprof/heap
```

进入交互式界面后，使用以下命令：

```bash
(pprof) top20          # 查看占用内存最多的前20个对象
(pprof) list <func>   # 查看具体函数的代码和内存分配
(pprof) png           # 生成调用图（可选）
```

### 步骤 2：追踪内存增长趋势

```bash
# 1. 第一次获取 heap profile
curl http://shifen.de:8080/debug/pprof/heap > heap_before.pprof

# 2. 等待一段时间（例如 10 分钟）
sleep 600

# 3. 第二次获取 heap profile
curl http://shifen.de:8080/debug/pprof/heap > heap_after.pprof

# 4. 比较差异
go tool pprof -base heap_before.pprof heap_after.pprof
```

### 步骤 3：分析内存泄漏原因

在交互式界面中：

```bash
(pprof) top10 -cum      # 按累计分配查看（最容易发现泄漏）
(pprof) alloc_space     # 查看分配空间而非使用空间
(pprof) list func_name  # 查看具体函数的内存分配
```

**关键指标：**
- `flat` - 当前函数直接分配的内存
- `cum` - 累计分配的内存（包括调用的函数）
- 如果某个函数 `cum` 值持续增长，很可能是泄漏点

### 步骤 4：查看 Goroutine 泄漏

```bash
go tool pprof http://shifen.de:8080/debug/pprof/goroutine

# 查看 goroutine 数量是否异常增长
(pprof) top20
```

**注意事项：**
- 正常情况：goroutine 数量应该相对稳定
- 泄漏迹象：数量持续增长，或者某些 goroutine 一直存在

### 步骤 5：分析内存分配模式

```bash
go tool pprof http://shifen.de:8080/debug/pprof/allocs

# 查看总分配量（比 heap 更能反映泄漏）
(pprof) top20
```

## 实际案例：排查 sslcat 内存泄漏

假设你发现 sslcat 内存从 100MB 增长到 1.5GB，可以这样排查：

### 1. 获取当前状态

```bash
ssh rocky@shifen.de
curl http://localhost:18080/debug/pprof/heap > /tmp/heap_v1.pprof
```

### 2. 监控一段时间

```bash
# 查看进程信息
watch -n 5 'ps aux | grep sslcat'

# 同时监控 pprof
go tool pprof http://localhost:18080/debug/pprof/heap
```

### 3. 对比分析

```bash
# 等待 10 分钟后再次获取
curl http://localhost:18080/debug/pprof/heap > /tmp/heap_v2.pprof

# 对比差异
go tool pprof -base /tmp/heap_v1.pprof /tmp/heap_v2.pprof
```

### 4. 解读结果

pprof 输出示例：

```
    234.56MB  15.04%  15.04%   456.78MB  29.30%  github.com/xurenlu/sslcat/internal/cache.(*CDNCache).Get
```

**解读：**
- `234.56MB` - 这个函数直接占用了 234MB
- `456.78MB` - 累计占用了 456MB（包括调用的其他函数）
- 如果这个值持续增长，说明 `CDNCache.Get` 可能有问题

### 5. 深入分析

```bash
(pprof) list CDNCache.Get
```

这会显示函数的代码以及每行分配了多少内存，方便定位具体的泄漏点。

## 常见内存泄漏模式识别

### 模式 1：缓存未清理

**症状：** `heap` 中看到大量缓存对象
**排查：** 
```bash
(pprof) top20 | grep cache
```
检查缓存是否有 TTL 和清理机制

### 模式 2：Goroutine 泄漏

**症状：** Goroutine 数量持续增长
**排查：**
```bash
go tool pprof http://localhost:18080/debug/pprof/goroutine
(pprof) top20
```
查看哪些 goroutine 数量最多

### 模式 3：请求响应未释放

**症状：** `heap` 中看到大量 HTTP 响应对象
**排查：**
```bash
(pprof) top20 | grep http
```
检查是否有响应体未关闭

### 模式 4：定时器泄漏

**症状：** 定期内存增长
**排查：**
```bash
go tool pprof http://localhost:18080/debug/pprof/heap
(pprof) top20 | grep ticker
```
检查定时器是否正确清理

## 结合现有监控使用

SSLcat 已经内置了内存监控器，可以这样配合使用：

### 1. 监控器发现异常

```
🔴 内存严重泄漏警告: 当前=1172.24 MB, 基线=2.38 MB, 增长=1169.87 MB
```

### 2. 立即使用 pprof 深入分析

```bash
# 获取详细的 heap profile
go tool pprof http://localhost:18080/debug/pprof/heap
(pprof) top20
```

### 3. 定位问题并修复

根据 pprof 的输出找出占用内存最多的代码

### 4. 验证修复效果

```bash
# 修复后再次采集
curl http://localhost:18080/debug/pprof/heap > heap_fixed.pprof

# 对比
go tool pprof -base heap_before.pprof heap_fixed.pprof
```

## 高级技巧

### 技巧 1：定期采集快照

创建一个脚本定期采集 heap profile：

```bash
#!/bin/bash
# collect_heaps.sh
DATE=$(date +%Y%m%d_%H%M%S)
curl http://localhost:18080/debug/pprof/heap > /tmp/heap_${DATE}.pprof
echo "采集完成: heap_${DATE}.pprof"
```

### 技巧 2：实时监控关键指标

```bash
# 查看实时的 goroutine 数量
watch -n 1 'curl -s http://localhost:18080/debug/pprof/goroutine?debug=1 | grep -c "goroutine"'
```

### 技巧 3：生成报告

```bash
# 生成可视化的调用图
go tool pprof -png http://localhost:18080/debug/pprof/heap > heap_graph.png
```

## 总结

使用 pprof 排查内存泄漏的核心步骤：

1. ✅ **发现** - 通过监控器或系统监控发现内存增长
2. 🔍 **采集** - 使用 pprof 获取 heap profile
3. 📊 **分析** - 使用 `top` 和 `list` 找出热点
4. 🎯 **定位** - 结合代码分析找到泄漏点
5. 🔧 **修复** - 修改代码解决问题
6. ✅ **验证** - 重新部署后持续监控

## 注意事项

⚠️ **安全**：pprof 端点应该添加认证保护
⚠️ **性能**：频繁采集 heap profile 会影响性能
⚠️ **存储**：heap profile 文件可能很大，注意清理


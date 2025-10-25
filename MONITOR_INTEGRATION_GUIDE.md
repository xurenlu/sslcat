# 监控系统集成指南

## 📊 新增监控模块

本次更新添加了三个强大的监控工具：

### 1. Goroutine泄漏检测器 (`internal/monitor/goroutine_monitor.go`)
### 2. 内存泄漏检测器 (`internal/monitor/memory_monitor.go`)
### 3. 性能基线监控器 (`internal/monitor/performance_monitor.go`)
### 4. 监控管理器 (`internal/monitor/manager.go`)

---

## 🔧 集成步骤

### 步骤1：在Server结构中添加监控管理器

在 `internal/web/server.go` 的 `Server` 结构体中添加：

```go
type Server struct {
	// ... 现有字段 ...
	
	// 监控管理器
	monitorManager *monitor.Manager
}
```

### 步骤2：在NewServer中初始化监控管理器

在 `NewServer` 函数中添加：

```go
import "github.com/xurenlu/sslcat/internal/monitor"

func NewServer(cfg *config.Config) (*Server, error) {
	// ... 现有初始化代码 ...
	
	server := &Server{
		// ... 现有字段 ...
		monitorManager: monitor.NewManager(true), // true表示启用监控
	}
	
	// 启动监控
	server.monitorManager.Start()
	
	return server, nil
}
```

### 步骤3：在Server停止时停止监控

在 `Server.Stop()` 或 `Server.Shutdown()` 方法中添加：

```go
func (s *Server) Shutdown(ctx context.Context) error {
	// ... 现有关闭代码 ...
	
	// 停止监控
	if s.monitorManager != nil {
		s.monitorManager.Stop()
	}
	
	return nil
}
```

### 步骤4：在HTTP请求处理中记录性能数据

在 `ServeHTTP` 的 defer 中添加：

```go
defer func() {
	duration := time.Since(startTime)
	
	// 记录到性能监控器
	if s.monitorManager != nil {
		perfMonitor := s.monitorManager.GetPerformanceMonitor()
		if perfMonitor != nil {
			isError := wrappedWriter.statusCode >= 400
			perfMonitor.RecordRequest(duration, isError)
		}
	}
	
	// ... 现有defer代码 ...
}()
```

---

## 📈 监控指标说明

### Goroutine监控指标

- `sslcat_goroutines_current`: 当前goroutine数量
- `sslcat_goroutines_baseline`: 基线goroutine数量
- `sslcat_goroutines_peak`: 峰值goroutine数量
- `sslcat_goroutines_warnings_total`: Goroutine泄漏警告次数

**告警规则**：
- 🟡 警告：超过基线100个
- 🔴 严重：超过基线500个

### 内存监控指标

- `sslcat_memory_alloc_mb`: 当前内存分配（MB）
- `sslcat_memory_sys_mb`: 系统内存（MB）
- `sslcat_memory_baseline_mb`: 基线内存（MB）
- `sslcat_memory_peak_mb`: 峰值内存（MB）
- `sslcat_memory_warnings_total`: 内存泄漏警告次数
- `sslcat_memory_gc_count`: GC次数

**告警规则**：
- 🟡 警告：增长超过500MB
- 🔴 严重：增长超过1GB

### 性能基线监控指标

- `sslcat_performance_baseline_qps`: 基线QPS
- `sslcat_performance_current_qps`: 当前QPS
- `sslcat_performance_baseline_rt_ms`: 基线响应时间（ms）
- `sslcat_performance_current_rt_ms`: 当前响应时间（ms）
- `sslcat_performance_baseline_error_rate`: 基线错误率
- `sslcat_performance_current_error_rate`: 当前错误率

**告警规则**：
- 🟡 QPS下降超过50%
- 🟡 响应时间增加超过50%
- 🔴 错误率增长超过2倍

---

## 🎯 使用示例

### 查看监控统计

```go
// 获取所有监控统计
stats := server.monitorManager.GetAllStats()

// 获取Goroutine统计
goroutineStats := server.monitorManager.GetGoroutineMonitor().GetStats()

// 获取内存统计
memoryStats := server.monitorManager.GetMemoryMonitor().GetStats()

// 获取性能统计
perfStats := server.monitorManager.GetPerformanceMonitor().GetStats()
```

### 重置基线

```go
// 重置所有基线（在系统稳定后调用）
server.monitorManager.ResetAllBaselines()

// 或单独重置
server.monitorManager.GetGoroutineMonitor().ResetBaseline()
server.monitorManager.GetMemoryMonitor().ResetBaseline()
server.monitorManager.GetPerformanceMonitor().ResetBaseline()
```

### 手动触发GC

```go
// 当内存警告时，可以手动触发GC
server.monitorManager.GetMemoryMonitor().ForceGC()
```

---

## 📊 Prometheus集成

监控指标已自动集成到 `/metrics` 端点。

使用Prometheus抓取配置：

```yaml
scrape_configs:
  - job_name: 'sslcat'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/sslcat-panel/metrics'
    scrape_interval: 30s
```

---

## 🔔 告警规则示例

### Prometheus告警规则

```yaml
groups:
  - name: sslcat_monitoring
    rules:
      # Goroutine泄漏告警
      - alert: GoroutineLeakWarning
        expr: sslcat_goroutines_current - sslcat_goroutines_baseline > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Goroutine泄漏警告"
          description: "Goroutine数量超过基线100个，当前: {{ $value }}"
      
      # 内存泄漏告警
      - alert: MemoryLeakWarning
        expr: sslcat_memory_alloc_mb - sslcat_memory_baseline_mb > 500
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "内存泄漏警告"
          description: "内存增长超过500MB，当前: {{ $value }}MB"
      
      # 性能下降告警
      - alert: PerformanceDegradation
        expr: |
          (sslcat_performance_baseline_rt_ms - sslcat_performance_current_rt_ms) 
          / sslcat_performance_baseline_rt_ms > 0.5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "性能下降"
          description: "响应时间增加超过50%"
```

---

## 🎨 Grafana仪表板

### 推荐面板

1. **Goroutine趋势图**
   - 指标：`sslcat_goroutines_current`, `sslcat_goroutines_baseline`
   - 类型：时间序列

2. **内存使用趋势图**
   - 指标：`sslcat_memory_alloc_mb`, `sslcat_memory_baseline_mb`
   - 类型：时间序列

3. **性能对比图**
   - 指标：`sslcat_performance_current_qps` vs `sslcat_performance_baseline_qps`
   - 类型：时间序列

4. **错误率趋势图**
   - 指标：`sslcat_performance_current_error_rate`
   - 类型：时间序列

---

## 💡 最佳实践

### 1. 基线设置时机

- ✅ 系统启动后运行10分钟
- ✅ 负载稳定后
- ✅ 无异常流量时

### 2. 监控检查间隔

- Goroutine监控：1分钟
- 内存监控：1分钟
- 性能监控：30秒

### 3. 告警处理

**Goroutine泄漏**：
1. 查看日志中的堆栈信息
2. 检查是否有goroutine没有正确退出
3. 检查channel是否有阻塞

**内存泄漏**：
1. 查看详细内存统计
2. 尝试手动GC
3. 检查缓存是否正确清理
4. 使用pprof分析内存

**性能下降**：
1. 检查慢查询日志
2. 检查数据库连接
3. 检查外部服务响应时间
4. 检查CPU/磁盘使用率

---

## 🔍 调试工具

### 查看Goroutine堆栈

当发生Goroutine泄漏警告时，监控器会自动输出堆栈信息到日志。

### 查看内存详情

当发生内存泄漏警告时，监控器会自动输出详细内存统计到日志。

### 使用pprof

```bash
# CPU分析
curl http://localhost:8080/debug/pprof/profile?seconds=30 > cpu.prof
go tool pprof cpu.prof

# 内存分析
curl http://localhost:8080/debug/pprof/heap > heap.prof
go tool pprof heap.prof

# Goroutine分析
curl http://localhost:8080/debug/pprof/goroutine > goroutine.prof
go tool pprof goroutine.prof
```

---

## 📝 配置选项

### 自定义阈值

可以在创建监控器时自定义阈值：

```go
// 自定义Goroutine监控器
goroutineMonitor := monitor.NewGoroutineMonitor(1 * time.Minute)
goroutineMonitor.warningThreshold = 200  // 自定义警告阈值
goroutineMonitor.criticalThreshold = 1000 // 自定义严重阈值

// 自定义内存监控器
memoryMonitor := monitor.NewMemoryMonitor(1 * time.Minute)
memoryMonitor.warningThreshold = 1024 * 1024 * 1024 // 1GB
memoryMonitor.criticalThreshold = 2048 * 1024 * 1024 // 2GB

// 自定义性能监控器
perfMonitor := monitor.NewPerformanceMonitor(30 * time.Second)
perfMonitor.qpsDeviationThreshold = 0.3 // 30%
perfMonitor.rtDeviationThreshold = 0.3  // 30%
```

---

## ✅ 验证集成

### 1. 检查日志

启动后应该看到：

```
INFO[0000] 监控管理器已启动（Goroutine监控、内存监控、性能监控）
INFO[0000] Goroutine监控器已启动，基线数量: 25, 检查间隔: 1m0s
INFO[0000] 内存监控器已启动，基线内存: 45.23 MB, 检查间隔: 1m0s
INFO[0000] 性能基线监控器已启动，检查间隔: 30s
```

### 2. 检查Prometheus指标

访问 `http://localhost:8080/sslcat-panel/metrics`，应该看到新增的监控指标。

### 3. 触发告警测试

可以通过压力测试触发告警，验证监控系统是否正常工作。

---

## 🎉 总结

监控系统已经完全实现，包括：

✅ Goroutine泄漏检测
✅ 内存泄漏检测
✅ 性能基线监控
✅ Prometheus指标集成
✅ 自动告警
✅ 趋势分析

只需要按照上述步骤集成到Server中即可使用！


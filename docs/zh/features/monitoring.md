# 监控系统

## 概述

SSLcat 内置了完整的监控系统，可以自动检测 Goroutine 泄漏、内存泄漏和性能问题。

## 功能特性

### Goroutine 监控
- 自动检测 Goroutine 泄漏
- 建立基线并检测异常增长
- 记录峰值和警告次数

### 内存监控
- 自动检测内存泄漏
- 监控内存分配和系统内存
- 跟踪 GC 次数

### 性能监控
- 自动建立性能基线
- 监控 QPS、响应时间、错误率
- 检测性能回归

## 配置

在 `sslcat.conf` 中启用监控：

```json
{
  "monitoring": {
    "enabled": true
  }
}
```

## Prometheus 指标

监控系统提供了 16 个 Prometheus 指标：

### Goroutine 监控指标
- `sslcat_goroutines_current` - 当前 Goroutine 数量
- `sslcat_goroutines_baseline` - 基线 Goroutine 数量
- `sslcat_goroutines_peak` - 峰值 Goroutine 数量
- `sslcat_goroutines_warnings_total` - 泄漏警告总数

### 内存监控指标
- `sslcat_memory_alloc_mb` - 当前内存分配（MB）
- `sslcat_memory_sys_mb` - 系统内存（MB）
- `sslcat_memory_baseline_mb` - 基线内存（MB）
- `sslcat_memory_peak_mb` - 峰值内存（MB）
- `sslcat_memory_warnings_total` - 内存泄漏警告总数
- `sslcat_memory_gc_count` - GC 次数

### 性能监控指标
- `sslcat_performance_baseline_qps` - 基线 QPS
- `sslcat_performance_current_qps` - 当前 QPS
- `sslcat_performance_baseline_avg_rt_ms` - 基线平均响应时间（ms）
- `sslcat_performance_current_avg_rt_ms` - 当前平均响应时间（ms）
- `sslcat_performance_baseline_error_rate` - 基线错误率
- `sslcat_performance_current_error_rate` - 当前错误率

## 使用示例

### 查看监控指标

```bash
curl http://localhost/sslcat-panel/metrics
```

### 配置 Prometheus

```yaml
scrape_configs:
  - job_name: 'sslcat'
    static_configs:
      - targets: ['localhost:443']
    metrics_path: '/sslcat-panel/metrics'
    scheme: https
```

## 监控间隔

- Goroutine 监控：每 1 分钟检查一次
- 内存监控：每 1 分钟检查一次
- 性能监控：每 30 秒检查一次

## 基线建立

- Goroutine 基线：启动后 5 分钟
- 内存基线：启动后 5 分钟
- 性能基线：启动后 10 分钟

## 告警规则

监控系统会在以下情况自动告警：

- Goroutine 数量超过基线 50%
- 内存使用超过基线 50%
- QPS 下降超过 20%
- 响应时间增加超过 50%

## 相关文档

- [Grafana 集成指南](../guides/grafana-integration.md)
- [性能调优指南](../guides/performance-tuning.md)


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

- Goroutine 基线：启动后 5 分钟（预热期）
- 内存基线：启动后 5 分钟
- 性能基线：启动后 10 分钟

Goroutine 监控器在启动时并不立即确定基线。监控器早于流量到达就已启动，此刻的
Goroutine 数只反映空载状态，直接作为基线会让正常业务水位被长期误判为泄漏增长。
因此预热期内只采样、不告警，预热结束时取样本的**中位数**作为基线——用中位数而非
均值，是为了避免预热期内的偶发流量尖峰把基线抬高。

业务水位长期变化后（例如接入大量新站点、上游数量翻倍），可通过接口手动校准基线：

```bash
curl -X POST -H "Authorization: Bearer $SSLCAT_WRITE_TOKEN" \
  https://your-domain/sslcat-panel/api/monitoring/baselines/reset
```

该接口会同时重置 Goroutine、内存、性能三项基线，并在响应中回传重置后的统计数据。

## 告警规则

Goroutine 泄漏判定同时考虑水位和趋势，避免把稳态波动误报为泄漏：

- **警告**：超出基线 100 个，**且**连续 3 个检查周期呈上升趋势
- **严重**：超出基线 500 个（绝对增量到此量级即告警，不要求趋势条件），并输出堆栈快照

趋势由最近 10 次采样与前 10 次采样的均值差判定，差值超过 ±10 才算上升/下降，
样本不足 20 次时不参与判定。两次告警之间有 10 分钟冷却，冷却窗口内重复命中阈值
只累加计数、不重复输出日志。

其余监控项的告警条件：

- 内存使用超过基线 50%
- QPS 下降超过 20%
- 响应时间增加超过 50%

## 相关文档

- [Grafana 集成指南](../guides/grafana-integration.md)
- [性能调优指南](../guides/performance-tuning.md)


# Monitoring System

## Overview

SSLcat has a built-in comprehensive monitoring system that automatically detects Goroutine leaks, memory leaks, and performance issues.

## Features

### Goroutine Monitoring
- Automatic Goroutine leak detection
- Establish baseline and detect abnormal growth
- Record peak and warning counts

### Memory Monitoring
- Automatic memory leak detection
- Monitor memory allocation and system memory
- Track GC counts

### Performance Monitoring
- Automatic performance baseline establishment
- Monitor QPS, response time, error rate
- Detect performance regression

## Configuration

Enable monitoring in `sslcat.conf`:

```json
{
  "monitoring": {
    "enabled": true
  }
}
```

## Prometheus Metrics

The monitoring system provides 16 Prometheus metrics:

### Goroutine Monitoring Metrics
- `sslcat_goroutines_current` - Current Goroutine count
- `sslcat_goroutines_baseline` - Baseline Goroutine count
- `sslcat_goroutines_peak` - Peak Goroutine count
- `sslcat_goroutines_warnings_total` - Total leak warnings

### Memory Monitoring Metrics
- `sslcat_memory_alloc_mb` - Current memory allocation (MB)
- `sslcat_memory_sys_mb` - System memory (MB)
- `sslcat_memory_baseline_mb` - Baseline memory (MB)
- `sslcat_memory_peak_mb` - Peak memory (MB)
- `sslcat_memory_warnings_total` - Total memory leak warnings
- `sslcat_memory_gc_count` - GC count

### Performance Monitoring Metrics
- `sslcat_performance_baseline_qps` - Baseline QPS
- `sslcat_performance_current_qps` - Current QPS
- `sslcat_performance_baseline_avg_rt_ms` - Baseline average response time (ms)
- `sslcat_performance_current_avg_rt_ms` - Current average response time (ms)
- `sslcat_performance_baseline_error_rate` - Baseline error rate
- `sslcat_performance_current_error_rate` - Current error rate

## Usage Examples

### View Monitoring Metrics

```bash
curl http://localhost/sslcat-panel/metrics
```

### Configure Prometheus

```yaml
scrape_configs:
  - job_name: 'sslcat'
    static_configs:
      - targets: ['localhost:443']
    metrics_path: '/sslcat-panel/metrics'
    scheme: https
```

## Monitoring Intervals

- Goroutine monitoring: Check every 1 minute
- Memory monitoring: Check every 1 minute
- Performance monitoring: Check every 30 seconds

## Baseline Establishment

- Goroutine baseline: 5 minutes after startup
- Memory baseline: 5 minutes after startup
- Performance baseline: 10 minutes after startup

## Alert Rules

The monitoring system will automatically alert in the following cases:

- Goroutine count exceeds baseline by 50%
- Memory usage exceeds baseline by 50%
- QPS drops by more than 20%
- Response time increases by more than 50%

## Related Documentation

- [Grafana Integration Guide](../guides/grafana-integration.md)
- [Performance Tuning Guide](../guides/performance-tuning.md)


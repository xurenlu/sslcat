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

- Goroutine baseline: 5 minutes after startup (warm-up period)
- Memory baseline: 5 minutes after startup
- Performance baseline: 10 minutes after startup

The goroutine monitor does not capture its baseline at startup. It starts before any
traffic arrives, so the goroutine count at that moment only reflects an idle process;
using it as the baseline makes normal steady-state traffic look like leak growth.
During the warm-up period the monitor only samples without alerting, and when the
period ends it takes the **median** of those samples as the baseline — the median
rather than the mean, so an occasional traffic spike during warm-up cannot skew it.

After a lasting shift in traffic levels (many new sites onboarded, upstream count
doubled), the baselines can be recalibrated manually:

```bash
curl -X POST -H "Authorization: Bearer $SSLCAT_WRITE_TOKEN" \
  https://your-domain/sslcat-panel/api/monitoring/baselines/reset
```

This resets the goroutine, memory, and performance baselines together, and returns
the post-reset statistics in the response.

## Alert Rules

Goroutine leak detection considers both level and trend, so steady-state fluctuation
is not reported as a leak:

- **Warning**: 100 above baseline **and** rising for 3 consecutive check intervals
- **Critical**: 500 above baseline (an absolute increase of this size alerts on its
  own, no trend condition), together with a stack dump

The trend compares the mean of the last 10 samples against the previous 10; the
difference must exceed ±10 to count as rising or falling, and fewer than 20 samples
yields no trend verdict. Alerts have a 10-minute cooldown — repeated threshold hits
within the window only increment counters instead of repeating the log line.

Alert conditions for the other monitors:

- Memory usage exceeds baseline by 50%
- QPS drops by more than 20%
- Response time increases by more than 50%

## Related Documentation

- [Grafana Integration Guide](../guides/grafana-integration.md)
- [Performance Tuning Guide](../guides/performance-tuning.md)


# SSLcat CPU Usage Troubleshooting Guide

## 📋 Problem Overview

SSLcat frequently consumes 90% CPU in production, requiring systematic investigation and resolution.

## 🚀 Quick Diagnosis (5 minutes)

### 1. Use Automated Diagnostic Tool

We provide an automated diagnostic tool that collects all necessary information with one command:

```bash
# Run on the server
cd /path/to/sslcat
./tools/cpu-profiler.sh
```

This tool automatically collects:
- Process CPU usage
- Goroutine count and stack traces
- CPU profile data
- Memory usage
- Configuration file information
- Known issue checks

After running, it generates a directory containing all diagnostic data and analysis reports.

### 2. Quick Check - View Goroutine Count

```bash
# Method 1: Use API (requires admin privileges)
curl -u admin:password "http://localhost/sslcat-panel/api/debug/pprof/goroutine?debug=1" | head -1

# Method 2: Check process thread count
ps -p $(pgrep sslcat) -o pid,nlwp

# Method 3: Use system commands
ps -eLf | grep sslcat | wc -l
```

**Normal Conditions**:
- Goroutine count: < 100
- Thread count: < 50

**Abnormal Conditions**:
- Goroutine count: > 500 (possible leak)
- Goroutine count: > 1000 (severe problem)

---

## 🔍 Detailed Investigation

### 1. CPU Profile Analysis

```bash
# Generate CPU profile
curl -o cpu.prof "http://localhost/sslcat-panel/api/debug/pprof/profile?seconds=30"

# Analyze with go tool
go tool pprof cpu.prof

# In pprof interactive mode:
(pprof) top10
(pprof) list function_name
(pprof) web
```

### 2. Goroutine Analysis

```bash
# Get goroutine stack trace
curl -o goroutine.txt "http://localhost/sslcat-panel/api/debug/pprof/goroutine?debug=1"

# Analyze goroutine distribution
grep -c "goroutine" goroutine.txt
grep -c "runtime.gopark" goroutine.txt
```

### 3. Memory Analysis

```bash
# Get memory profile
curl -o mem.prof "http://localhost/sslcat-panel/api/debug/pprof/heap"

# Analyze memory usage
go tool pprof mem.prof
```

## 🛠️ Common Issues and Solutions

### Issue 1: Goroutine Leak

**Symptoms**:
- Goroutine count continuously increasing
- Memory usage growing
- CPU usage high

**Diagnosis**:
```bash
# Check goroutine count over time
watch -n 1 'curl -s "http://localhost/sslcat-panel/api/debug/pprof/goroutine?debug=1" | head -1'
```

**Solution**:
1. Check for blocked goroutines
2. Review channel operations
3. Fix resource leaks

### Issue 2: Infinite Loop

**Symptoms**:
- Single goroutine consuming 100% CPU
- High CPU usage on one core

**Diagnosis**:
```bash
# Check CPU profile
go tool pprof cpu.prof
(pprof) top
```

**Solution**:
1. Identify the problematic function
2. Add proper exit conditions
3. Implement timeouts

### Issue 3: Excessive Logging

**Symptoms**:
- High I/O wait
- Disk usage high
- Log files growing rapidly

**Diagnosis**:
```bash
# Check log file size
ls -lh /var/log/sslcat/
du -sh /var/log/sslcat/

# Check log level
grep "log_level" /etc/sslcat/sslcat.conf
```

**Solution**:
```json
{
  "server": {
    "log_level": "warn",
    "debug": false
  }
}
```

### Issue 4: SSL Certificate Processing

**Symptoms**:
- High CPU during SSL handshake
- Certificate validation overhead

**Diagnosis**:
```bash
# Check SSL metrics
curl "http://localhost/sslcat-panel/api/ssl/stats"
```

**Solution**:
1. Optimize certificate chain
2. Use efficient cipher suites
3. Enable session resumption

## 🔧 Configuration Optimization

### 1. Reduce Logging

```json
{
  "server": {
    "log_level": "error",
    "debug": false,
    "access_log": false
  }
}
```

### 2. Optimize Goroutine Pool

```json
{
  "server": {
    "max_workers": 4,
    "worker_timeout": "30s"
  }
}
```

### 3. SSL Configuration

```json
{
  "ssl": {
    "min_version": "TLS12",
    "cipher_suites": [
      "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384"
    ]
  }
}
```

## 📊 Monitoring and Alerting

### 1. CPU Monitoring

```bash
# Create monitoring script
cat > monitor_cpu.sh << 'EOF'
#!/bin/bash
while true; do
    CPU_USAGE=$(ps -p $(pgrep sslcat) -o %cpu --no-headers)
    if (( $(echo "$CPU_USAGE > 80" | bc -l) )); then
        echo "High CPU usage: $CPU_USAGE%"
        # Send alert
    fi
    sleep 60
done
EOF

chmod +x monitor_cpu.sh
```

### 2. Goroutine Monitoring

```bash
# Monitor goroutine count
cat > monitor_goroutines.sh << 'EOF'
#!/bin/bash
while true; do
    GOROUTINES=$(curl -s "http://localhost/sslcat-panel/api/debug/pprof/goroutine?debug=1" | head -1 | grep -o '[0-9]*' | head -1)
    if [ "$GOROUTINES" -gt 500 ]; then
        echo "High goroutine count: $GOROUTINES"
        # Send alert
    fi
    sleep 60
done
EOF
```

## 🚀 Performance Tuning

### 1. System-Level Optimization

```bash
# Increase file descriptor limits
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Optimize kernel parameters
echo "net.core.somaxconn = 65536" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" >> /etc/sysctl.conf
sysctl -p
```

### 2. SSLcat Configuration

```json
{
  "server": {
    "max_connections": 1000,
    "read_timeout": "30s",
    "write_timeout": "30s",
    "idle_timeout": "120s"
  },
  "compression": {
    "enabled": true,
    "cache_size": "100MB"
  }
}
```

## 🔍 Advanced Debugging

### 1. Trace Analysis

```bash
# Enable tracing
curl -X POST "http://localhost/sslcat-panel/api/debug/trace/start"

# Stop tracing and get results
curl -X POST "http://localhost/sslcat-panel/api/debug/trace/stop" -o trace.out

# Analyze trace
go tool trace trace.out
```

### 2. Memory Profiling

```bash
# Get memory profile
curl -o mem.prof "http://localhost/sslcat-panel/api/debug/pprof/heap"

# Analyze memory
go tool pprof -http=:8080 mem.prof
```

### 3. Blocking Profile

```bash
# Get blocking profile
curl -o block.prof "http://localhost/sslcat-panel/api/debug/pprof/block"

# Analyze blocking
go tool pprof block.prof
```

## 📚 Related Documentation

- [Image Optimization CPU Fix](IMAGE_OPTIMIZATION_CPU_FIX.md)
- [Logging and Performance Optimization](LOGGING_AND_PERFORMANCE_OPTIMIZATION.md)
- [Logging CPU Fix Summary](LOGGING_CPU_FIX_SUMMARY.md)
- [Performance Optimization](performance.md)

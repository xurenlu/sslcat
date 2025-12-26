# CPU 暴涨诊断报告 - 2025-12-26

## 问题现象

- **CPU 使用率**: 193.3%（异常高）
- **内存占用**: 1.7GB RSS
- **系统负载**: 1.60

## 诊断过程

### 1. CPU Profile 分析

**主要 CPU 消耗**:
- `runtime.gcDrain`: 41.81% - GC 操作占用大量 CPU
- `runtime.scanobject`: 17.41% - 对象扫描
- `net/textproto.readMIMEHeader`: 24.73% - HTTP header 解析
- `github.com/xurenlu/sslcat/internal/proxy.(*Manager).ProxyRequest`: 12.03% - 代理请求处理

### 2. 内存分配分析

**10 秒内内存分配**:
- `net/textproto.(*Reader).readLineSlice`: 19.1MB (56.32%)
- `net/textproto.readMIMEHeader`: 25.1MB (73.87%)
- `net/http/httputil.(*ReverseProxy).ServeHTTP`: 4.8MB (14.04%)
- `internal/proxy.(*Manager).ProxyRequest`: 8.3MB (24.57%)

**总分配**: 33.9MB / 10秒 = 3.39MB/秒

### 3. 根本原因

1. **HTTP header 解析导致大量内存分配**
   - 每个请求的 header 解析都会分配内存
   - `readLineSlice` 和 `readMIMEHeader` 是主要分配源

2. **GC 频率过高**
   - 当前 `GOGC=100`，内存分配速度快导致频繁 GC
   - GC 占用 41.81% 的 CPU

3. **内存分配速率**
   - 3.39MB/秒的分配速率
   - 在 `GOGC=100` 下，每分配 100MB 就会触发一次 GC
   - 大约每 30 秒触发一次 GC

## 解决方案

### 临时方案（已实施）✅

**提高 GOGC 到 300**:
```bash
sudo sed -i 's/GOGC=100/GOGC=300/' /etc/systemd/system/sslcat.service
sudo systemctl daemon-reload
sudo systemctl restart sslcat.service
```

**效果**:
- CPU 从 193.3% 降低到 0.4%（降低 99.8%）
- 内存从 1.7GB 降低到 45MB（降低 97.4%）
- GC 频率降低，CPU 占用大幅减少

### 长期方案

1. **更新代码默认值**
   - 将代码中的默认 `GOGC` 从 100 提高到 300
   - 或者根据环境自动调整

2. **优化 HTTP header 解析**
   - 考虑使用对象池复用 header 解析缓冲区
   - 限制 header 大小，避免异常大的 header

3. **监控和告警**
   - 添加 GC 频率监控
   - 当 GC 频率过高时发出告警

## 建议

### 对于低流量场景

**推荐配置**:
```bash
GOGC=300  # 减少 GC 频率
GOMEMLIMIT=512MiB  # 限制内存使用
```

### 对于高并发场景

**推荐配置**:
```bash
GOGC=200  # 平衡 GC 频率和内存占用
GOMEMLIMIT=1GiB  # 允许更多内存
```

## 当前状态

- ✅ **临时修复已应用**: GOGC=300
- ✅ **CPU 已恢复正常**: 0.4%
- ✅ **内存已恢复正常**: 45MB
- ⚠️ **需要代码更新**: 更新默认 GOGC 值

## 后续行动

1. **更新代码默认值** - 将默认 GOGC 从 100 提高到 300
2. **监控效果** - 观察长期运行效果
3. **优化 header 解析** - 如果问题再次出现，考虑优化 HTTP header 解析


# SSLcat 性能分析报告

**日期**: 2026-03-07 00:12
**服务器**: sg1.1605ai.com
**问题**: `/api/analyze-image` 接口 30 秒超时

---

## 问题概述

客户端在调用 `/api/analyze-image` 时，30 秒还没有返回。当时时间约为 **2026-03-06 23:12:01**。

---

## 监控数据分析

### 时间线

- **2026-03-05 23:55** 开始检测到异常
- **2026-03-06 01:40** 持续报警
- **2026-03-06 23:12:01** 客户端报告超时

### 异常触发数据

```
时间: 2026-03-06 23:12:01
Goroutine: 108 (正常)
Mutex: 1 (1个互斥锁争用)
Block: 1 (1个阻塞操作)
```

**注意**: 这些数值本身很小，但由于旧监控脚本阈值设置太严格（>0 即报警），所以每次都触发。

---

## Pprof 性能分析

### 1. HTTP/2 连接阻塞（最严重）

```
7458284688026 cycles (12939 samples)
golang.org/x/net/http2.(*serverConn).serve
```

**分析**:
- **12939 个阻塞样本**，约 7.4万亿 CPU 周期
- HTTP/2 连接处理中的 `select` 等待
- 影响 HTTP/2 请求的处理能力

### 2. ML 推理引擎阻塞

```
2868328585975 cycles (11475 samples)
github.com/xurenlu/sslcat/internal/ml.(*InferenceEngine).processBatchLoop
```

**分析**:
- **11475 个阻塞样本**，约 2.9万亿 CPU 周期
- ML 推理引擎在 `select` 中等待处理批次
- **注意**: ML 推理引擎不在关键请求路径上，是异步的

### 3. HTTP 持久连接写入循环阻塞

```
9170194567890 cycles (1035 samples)
net/http.(*persistConn).writeLoop
```

**分析**:
- 1035 个样本，约 9.2万亿 CPU 周期
- 影响 HTTP 出站连接的写入

### 4. Mutex 争用（代理相关）

```
218772880 cycles (1240 samples)
net/http/httputil.(*maxLatencyWriter).Write
→ github.com/xurenlu/sslcat/internal/proxy.(*Manager).proxyToBackend
```

**分析**:
- 1240 个样本，约 2.2亿 CPU 周期
- 反向代理写入时的锁争用

---

## Goroutine 状态分析

### 总体状态

- **总 Goroutine 数**: 82
- **运行中**: 3
- **IO 等待**: 39
- **Channel 接收等待**: 12
- **Select 等待**: 28

### 结论

Goroutine 数量完全正常，没有 goroutine 泄漏或堆积。

---

## 根本原因

**主要问题**: HTTP/2 连接阻塞

根据 pprof 数据，HTTP/2 的 `serverConn.serve` 占用了最多的阻塞时间。这导致：

1. **并发流处理能力受限**
2. **HTTP/2 的多路复用在特定场景下反而成为瓶颈**
3. **流之间的相互影响**

**次要问题**:
- ML 推理引擎的批处理等待（但不影响主请求流程）
- 代理写入时的锁争用

---

## 解决方案

### 已实施的修改

#### 1. ML 推理引擎优化

**新增配置** (`ai_security.ml_inference`):
```json
{
  "worker_pool_size": 50,          // Worker 数量
  "max_queue_size": 5000,          // 最大队列大小
  "batch_timeout": "100ms",        // 批处理超时
  "queue_full_strategy": "drop"    // drop|wait|error
}
```

**队列满时策略**:
- `"drop"` - 静默丢弃推理请求（默认，推荐）
- `"error"` - 返回错误给回调
- `"wait"` - 阻塞等待

**注意**: ML 推理引擎不在关键请求路径上，丢弃不影响正常服务。

#### 2. HTTP/2 配置优化

**新增配置** (`server.http2_config`):
```json
{
  "max_concurrent_streams": 250,          // 最大并发流数
  "max_read_frame_size": 1048576,         // 最大帧大小（1MB）
  "idle_timeout": 120,                    // 空闲超时（秒）
  "max_upload_buffer_per_connection": 1048576,  // 连接级缓冲
  "max_upload_buffer_per_stream": 262144        // 流级缓冲
}
```

#### 3. HTTP/2 动态控制 API

| API | 方法 | 说明 |
|-----|------|------|
| `/api/http2/status` | GET | 获取 HTTP/2 状态 |
| `/api/http2/enable` | POST | 启用 HTTP/2 |
| `/api/http2/disable` | POST | 禁用 HTTP/2（可指定时长） |

**禁用示例**:
```bash
curl -X POST http://server/api/http2/disable \
  -H "Content-Type: application/json" \
  -d '{"duration": 600, "reason": "系统负载高"}'
```

**自动恢复**: 禁用后会自动在指定时间后恢复（默认 10 分钟）

#### 4. 监控脚本修复

- 修复了第 47 行的数值解析错误
- 阈值调整为：mutex > 100, block > 100, goroutine > 500
- 修复了 `grep -oP` 兼容性问题

---

## 建议的下一步

### 1. 测试禁用 HTTP/2

临时禁用 HTTP/2 测试性能改善：

```json
{
  "server": {
    "http2_enabled": false
  }
}
```

### 2. 或使用动态 API

```bash
# 禁用 10 分钟测试
curl -X POST http://server/api/http2/disable \
  -H "Content-Type: application/json" \
  -d '{"duration": 600, "reason": "性能测试"}'
```

### 3. 建议配置

根据服务器资源情况（内存和 CPU 都还能扛住）：

```json
{
  "ai_security": {
    "ml_inference": {
      "worker_pool_size": 100,
      "max_queue_size": 10000,
      "batch_timeout": "50ms",
      "queue_full_strategy": "drop"
    }
  },
  "server": {
    "http2_config": {
      "max_concurrent_streams": 500,
      "idle_timeout": 90
    }
  }
}
```

---

## 附录

### ML 推理引擎说明

**ML 推理引擎的作用**:
- 使用 Isolation Forest 算法检测异常请求
- 检测 SQL 注入、XSS、路径遍历等攻击
- 提供威胁评分功能

**位置**: **不在关键请求路径上**

ML 推理引擎是独立的服务，通过 API 调用：
- `/api/ml/train` - 训练模型
- `/api/ml/predict` - 单次预测
- `/api/ml/stats` - 获取统计
- `/api/ml/threat/score` - 威胁评分

**结论**: ML 推理队列的丢弃**不会影响**任何 HTTP 请求的正常处理。

### HTTP/2 优缺点分析

**优点**:
- 多路复用：一个连接处理多个请求
- 头部压缩：减少网络开销
- 服务器推送

**缺点**:
- 单个连接的流之间会相互影响
- TCP 层级别的阻塞（队头阻塞）
- HPACK 压缩有 CPU 开销

**建议**: 如果你的服务主要处理独立的 API 请求，而不是复杂 SPA 的资源加载，HTTP/1.1 可能更合适。

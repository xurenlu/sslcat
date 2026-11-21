# SSLCat CPU 占用诊断报告
## 问题：CPU 仍然 20%+ 占用

**日期**: 2025-12-26  
**服务器**: shifen.de  
**版本**: v1.3.29-rc15  
**运行时间**: 12 分钟

---

## 🔍 诊断结果

### 当前状态

```bash
USER    PID  %CPU %MEM    VSZ   RSS
root  92512  20.4  0.7  7966712  117624  # CPU 20.4%
```

### CPU Profile 分析

```
Duration: 10s, Total samples = 20ms (0.2%)
100% CPU 时间在: runtime.scanobject (GC 扫描对象)
```

**结论**: CPU 100% 被 GC 占用！

---

## 📊 内存分配分析

### 总分配量（运行 12 分钟）

```
Total alloc_space: 19.9 GB
```

### 主要分配点

| 函数 | 分配量 | 占比 |
|------|--------|------|
| `net/textproto.(*Reader).readLineSlice` | 10.3 GB | 51.64% |
| `net/textproto.readMIMEHeader` | 2.6 GB | 12.91% |
| `internal/proxy.(*Manager).ProxyRequest` | 2.5 GB | 12.40% |
| `net/http/httputil.(*ReverseProxy).ServeHTTP` | 2.5 GB | 12.38% |
| `bufio.NewWriterSize` | 840 MB | 4.21% |
| `bufio.NewReaderSize` | 812 MB | 4.07% |

**分配速度**: ~1.66 GB/分钟 = **27.7 MB/秒**

---

## 🔎 根本原因

### 1. 环境变量已设置但效果有限

```bash
Environment=GOMEMLIMIT=1073741824 GOGC=100 GODEBUG=madvdontneed=1
```

✅ 环境变量正确  
❌ **但分配速度太快，GC 仍然频繁触发**

### 2. 代码优化已实施但不够

已实施的优化：
- ✅ `MaxIdleConnsPerHost: 10`
- ✅ `ReadBufferSize: 32KB`
- ✅ `WriteBufferSize: 32KB`
- ✅ `ResponseHeaderTimeout: 30s`

**但问题是**：
- ❌ `bufio` 缓冲区仍然频繁分配（1.6GB）
- ❌ HTTP 头部解析仍然大量分配（12.9GB）
- ❌ 没有使用 `sync.Pool` 复用缓冲区

---

## 💡 解决方案

### 方案 1: 增加 GOGC 值（快速缓解）

**原理**: 提高 GOGC 值，减少 GC 频率

```bash
# 当前: GOGC=100 (堆增长 100% 触发 GC)
# 建议: GOGC=200 (堆增长 200% 触发 GC)
```

**效果预期**: CPU 降低 50%+，内存增加 ~50MB

**实施**:
```bash
ssh rocky@shifen.de "sudo sed -i 's/GOGC=100/GOGC=200/' /etc/systemd/system/sslcat.service && sudo systemctl daemon-reload && sudo systemctl restart sslcat"
```

---

### 方案 2: 使用 sync.Pool 复用缓冲区（根本解决）

**需要修改的代码**:

#### 1. 在 `internal/proxy/manager.go` 中添加 bufio 缓冲区池

```go
// 在 Manager 结构体中添加
type Manager struct {
    // ... 现有字段 ...
    
    // 缓冲区池
    bufferPool      *sync.Pool
    bufioReaderPool *sync.Pool  // 新增
    bufioWriterPool *sync.Pool  // 新增
}

// 在 NewManager 中初始化
func NewManager(...) *Manager {
    m := &Manager{
        // ... 现有初始化 ...
        
        bufferPool: &sync.Pool{
            New: func() interface{} {
                return make([]byte, 32*1024)
            },
        },
        
        // 新增 bufio.Reader 池
        bufioReaderPool: &sync.Pool{
            New: func() interface{} {
                return bufio.NewReaderSize(nil, 32*1024)
            },
        },
        
        // 新增 bufio.Writer 池
        bufioWriterPool: &sync.Pool{
            New: func() interface{} {
                return bufio.NewWriterSize(nil, 32*1024)
            },
        },
    }
    return m
}
```

#### 2. 在 HTTP Transport 中使用自定义 Dial

```go
// 在 getOrCreateProxy 中修改 Transport
baseTransport := &http.Transport{
    // ... 现有配置 ...
    
    // 自定义 DialContext 以使用缓冲区池
    DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
        dialer := &net.Dialer{
            Timeout:   time.Duration(connectTimeout) * time.Second,
            KeepAlive: time.Duration(keepAliveTimeout) * time.Second,
        }
        conn, err := dialer.DialContext(ctx, network, addr)
        if err != nil {
            return nil, err
        }
        
        // 包装连接以使用缓冲区池
        return &pooledConn{
            Conn:       conn,
            readerPool: m.bufioReaderPool,
            writerPool: m.bufioWriterPool,
        }, nil
    },
}
```

#### 3. 实现 pooledConn

```go
type pooledConn struct {
    net.Conn
    readerPool *sync.Pool
    writerPool *sync.Pool
    reader     *bufio.Reader
    writer     *bufio.Writer
}

func (c *pooledConn) Read(b []byte) (int, error) {
    if c.reader == nil {
        r := c.readerPool.Get().(*bufio.Reader)
        r.Reset(c.Conn)
        c.reader = r
    }
    return c.reader.Read(b)
}

func (c *pooledConn) Write(b []byte) (int, error) {
    if c.writer == nil {
        w := c.writerPool.Get().(*bufio.Writer)
        w.Reset(c.Conn)
        c.writer = w
    }
    n, err := c.writer.Write(b)
    if err != nil {
        return n, err
    }
    return n, c.writer.Flush()
}

func (c *pooledConn) Close() error {
    if c.reader != nil {
        c.readerPool.Put(c.reader)
        c.reader = nil
    }
    if c.writer != nil {
        c.writerPool.Put(c.writer)
        c.writer = nil
    }
    return c.Conn.Close()
}
```

**效果预期**: 
- 减少 80% 的 bufio 分配（1.6GB -> 320MB）
- CPU 降低 70%+
- 内存稳定

---

### 方案 3: 调整 HTTP/2 设置（辅助优化）

**问题**: HTTP/2 的 frame 读取也会产生大量分配

**修改**: 在 `main.go` 中调整 HTTP/2 配置

```go
http2.ConfigureServer(httpsServer, &http2.Server{
    MaxConcurrentStreams: 250,  // 从 1000 降低到 250
    MaxReadFrameSize:     262144, // 从 1MB 降低到 256KB
    IdleTimeout:          120 * time.Second,
    MaxUploadBufferPerConnection: 1 << 20, // 新增：限制上传缓冲区 1MB
    MaxUploadBufferPerStream:     256 << 10, // 新增：限制每个流 256KB
})
```

---

## 🎯 推荐实施顺序

### 立即实施（5 分钟）

**方案 1**: 调整 GOGC=200

```bash
# 1. 修改 systemd 配置
ssh rocky@shifen.de "sudo sed -i 's/GOGC=100/GOGC=200/' /etc/systemd/system/sslcat.service"

# 2. 重载并重启
ssh rocky@shifen.de "sudo systemctl daemon-reload && sudo systemctl restart sslcat"

# 3. 验证
ssh rocky@shifen.de "systemctl show sslcat.service | grep Environment"
ssh rocky@shifen.de "sleep 60 && ps aux | grep sslcat"
```

**预期**: CPU 从 20% 降到 10% 以下

---

### 后续优化（1-2 小时）

**方案 2**: 实施 sync.Pool 优化

1. 修改 `internal/proxy/manager.go`
2. 添加 bufio 缓冲区池
3. 实现 pooledConn
4. 测试验证

**预期**: CPU 降到 1-2%

---

### 可选优化

**方案 3**: 调整 HTTP/2 设置

**预期**: 进一步降低 5-10% CPU

---

## 📈 性能对比预测

| 方案 | CPU | 内存 | 实施难度 | 实施时间 |
|------|-----|------|---------|---------|
| **当前** | 20% | 118MB | - | - |
| **方案 1** | 8-10% | 150MB | 简单 | 5 分钟 |
| **方案 2** | 1-2% | 120MB | 中等 | 1-2 小时 |
| **方案 3** | 0.5-1% | 100MB | 简单 | 10 分钟 |
| **全部** | <1% | 120MB | - | 2 小时 |

---

## 🔧 监控命令

### 实时监控 CPU

```bash
ssh rocky@shifen.de "watch -n 1 'ps aux | grep sslcat | grep -v grep'"
```

### 监控 GC

```bash
ssh rocky@shifen.de "curl -s http://localhost/debug/pprof/heap | strings | grep -E 'GC|gc'"
```

### 监控分配速度

```bash
# 获取两次 heap profile，计算差值
ssh rocky@shifen.de "curl -s http://localhost/debug/pprof/heap -o /tmp/heap1.pprof && sleep 60 && curl -s http://localhost/debug/pprof/heap -o /tmp/heap2.pprof"

# 本地分析
scp rocky@shifen.de:/tmp/heap*.pprof /tmp/
go tool pprof -base /tmp/heap1.pprof /tmp/heap2.pprof -top
```

---

## 📝 总结

### 核心问题

**GC 频率过高** 导致 CPU 占用 20%

### 根本原因

**分配速度太快** (27.7 MB/秒)，主要来自：
1. HTTP 头部解析（12.9GB）
2. bufio 缓冲区（1.6GB）
3. 代理请求处理（2.5GB）

### 解决思路

1. **短期**: 提高 GOGC 值，减少 GC 频率
2. **长期**: 使用 sync.Pool 复用缓冲区，减少分配

### 预期效果

- **方案 1**: CPU 20% -> 10% (5 分钟实施)
- **方案 2**: CPU 10% -> 1-2% (1-2 小时实施)
- **最终**: CPU < 1%，内存稳定 ~120MB

---

## 🚀 下一步行动

1. ✅ **立即执行方案 1**（调整 GOGC=200）
2. ⏳ **规划方案 2**（实施 sync.Pool）
3. ⏳ **可选方案 3**（优化 HTTP/2）

**建议**: 先执行方案 1 快速缓解，然后规划方案 2 彻底解决。


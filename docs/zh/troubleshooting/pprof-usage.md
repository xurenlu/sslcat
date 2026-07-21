# 使用 pprof 进行性能分析

## 简介

pprof 是 Go 内置的性能分析工具，通过 HTTP 端点提供实时性能数据。我们已经在 SSLcat 中集成了 pprof，方便在线调试性能问题。

## 访问 pprof

pprof 使用独立监听器，默认只绑定 loopback，不会出现在 80/443 或自定义业务端口：

```
http://127.0.0.1:6060/debug/pprof/
```

配置示例：

```json
{
  "server": {
    "enable_pprof": true,
    "pprof_addr": "127.0.0.1:6060"
  }
}
```

`pprof_addr` 只接受 `127.0.0.0/8`、`::1` 或 `localhost`；通配地址、私网地址和公网地址都会使服务拒绝启动。

### 主要端点

- `/debug/pprof/` - 概览页面，列出所有可用的 profile
- `/debug/pprof/heap` - 堆内存分析
- `/debug/pprof/profile?seconds=30` - CPU profile（30秒）
- `/debug/pprof/goroutine` - Goroutine 分析
- `/debug/pprof/allocs` - 内存分配追踪
- `/debug/pprof/block` - 阻塞分析
- `/debug/pprof/mutex` - 互斥锁分析

## 使用方法

### 1. 查看内存使用情况

```bash
# 在服务器本机或 SSH 隧道另一端打开
http://127.0.0.1:6060/debug/pprof/heap

# 或使用 go tool pprof
go tool pprof http://127.0.0.1:6060/debug/pprof/heap
```

### 2. 分析 CPU 性能

```bash
# 采集 30 秒的 CPU profile
go tool pprof 'http://127.0.0.1:6060/debug/pprof/profile?seconds=30'

# 在交互式界面中可以使用以下命令：
# top - 查看占用资源最多的函数
# list <function_name> - 查看函数详细代码
# web - 生成调用图（需要安装 graphviz）
```

### 3. 分析 Goroutine

```bash
# 查看 goroutine 堆栈
go tool pprof http://127.0.0.1:6060/debug/pprof/goroutine

# 交互式命令：
# top - 查看 goroutine 数量最多的函数
# list <function_name> - 查看函数详情
```

### 4. 实时分析内存增长

```bash
# 下载 2 个不同时间点的 heap profile
curl http://127.0.0.1:6060/debug/pprof/heap > heap1.pprof
sleep 60
curl http://127.0.0.1:6060/debug/pprof/heap > heap2.pprof

# 比较差异
go tool pprof -base heap1.pprof heap2.pprof
```

## 生产环境使用注意事项

### 1. 不要通过反向代理暴露 pprof

不要在 nginx、sing-box、SSLcat 代理规则或容器端口映射中把 6060 暴露到公网/内网。heap、goroutine 等 profile 可能包含内部路径和内存数据。

### 2. 使用 SSH 隧道

如果服务器是远程的，可以使用 SSH 隧道：

```bash
# 在本地建立隧道
ssh -L 6060:127.0.0.1:6060 user@your-server

# 然后在本地访问
http://127.0.0.1:6060/debug/pprof/
```

## 实际应用场景

### 场景 1：内存缓慢增长

```bash
# 1. 先获取当前 heap
go tool pprof http://127.0.0.1:6060/debug/pprof/heap

# 2. 等待一段时间后再次获取
go tool pprof http://127.0.0.1:6060/debug/pprof/heap

# 3. 使用 top 命令查看占用内存最多的对象
(pprof) top20
```

### 场景 2：CPU 使用率高

```bash
# 采集 30 秒的 CPU profile
go tool pprof 'http://127.0.0.1:6060/debug/pprof/profile?seconds=30'

# 查看占用 CPU 最多的函数
(pprof) top10
```

### 场景 3：Goroutine 泄漏

```bash
# 获取 goroutine 信息
go tool pprof http://127.0.0.1:6060/debug/pprof/goroutine

# 查看 goroutine 数量最多的函数
(pprof) top20
```

## pprof 输出示例

### Heap Profile 示例

```
Type: inuse_space
Time: Oct 26, 2025 at 2:17pm (UTC)
Entering interactive mode (type "help" for commands, "o" for options)
(pprof) top10
Showing nodes accounting for 1234.56MB, 79.23% of 1558.72MB total
Showing top 10 nodes out of 234
      flat  flat%   sum%        cum   cum%
  456.78MB 29.30% 29.30%   456.78MB 29.30%  github.com/xurenlu/sslcat/internal/cache.(*CDNCache).Get
  234.56MB 15.04% 44.34%   234.56MB 15.04%  net/http.(*response).write
  123.45MB  7.92% 52.26%   123.45MB  7.92%  runtime.mallocgc
...
```

### CPU Profile 示例

```
Type: cpu
Time: Oct 26, 2025 at 2:17pm (UTC)
Duration: 30s, Total samples = 15.23s (50.77%)
Entering interactive mode (type "help" for commands, "o" for options)
(pprof) top10
Showing nodes accounting for 10.5s, 68.95% of 15.23s total
Showing top 10 nodes out of 156
      flat  flat%   sum%        cum   cum%
      2.1s 13.78% 13.78%      2.5s 16.42%  runtime.cgocall
      1.8s 11.81% 25.59%      2.3s 15.10%  compress/gzip.(*Writer).Write
      1.5s  9.84% 35.43%      1.5s  9.84%  runtime.madvise
...
```

## 配合内存监控使用

pprof 可以配合我们已有的内存监控器使用：

1. **内存监控器**发现内存增长问题 → 触发警告
2. **使用 pprof** 进行详细分析 → 找出具体原因
3. **修复问题** → 重新部署
4. **继续监控** → 确认问题已解决

## 故障排查流程

```
内存缓慢增长
    ↓
1. 检查内存监控日志
    ↓
2. 使用 pprof 获取 heap profile
    ↓
3. 分析 top10 占用内存的对象
    ↓
4. 使用 list 命令查看具体代码
    ↓
5. 找出问题根源
    ↓
6. 修复并重新部署
    ↓
7. 继续监控确认修复效果
```

## 常见问题

### Q: pprof 会影响性能吗？

A: pprof 的端点访问一般不会显著影响性能，但在高负载情况下建议限制访问频率。

### Q: 如何在容器中使用？

A: 不要发布 6060 端口；在容器内执行 pprof 命令，或通过仅绑定宿主机 loopback 的方式建立 SSH 隧道。

### Q: 看不到 pprof 数据？

A: 检查 `server.enable_pprof`、`server.pprof_addr` 和启动日志；远程机器必须先建立 SSH 隧道。

## 更多资源

- [Go pprof 官方文档](https://pkg.go.dev/net/http/pprof)
- [Profiling Go Programs](https://go.dev/blog/pprof)
- [Dave Cheney 的 pprof 教程](https://dave.cheney.net/2013/06/30/how-to-write-benchmarks-in-go)

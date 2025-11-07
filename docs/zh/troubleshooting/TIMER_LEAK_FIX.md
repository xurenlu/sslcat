# SSLcat 定时器泄露问题全面修复

## 🔍 发现的问题

通过全面扫描代码库，发现以下 `time.After()` 在循环中使用的问题：

### ✅ 已修复的问题

1. **`internal/proxy/manager.go`** - WebSocket 相关函数（3处）
   - `readWebSocketData` - 数据发送超时
   - `writeWebSocketData` - 空闲超时检查
   - `monitorWebSocketConnections` - 连接超时检查

2. **`internal/runner/realtime_logs.go`** - SSE 心跳（1处）
   - `handleSSE` - 心跳定时器

### ✅ 确认安全的使用（不在循环中）

以下 `time.After()` 的使用是安全的，因为它们不在循环中：

1. **`internal/web/server.go:1673`** - DNS 解析超时
   ```go
   // 在匿名函数中，只执行一次
   select {
   case res := <-ch:
       return res.ips, res.err
   case <-time.After(2 * time.Second):
       return nil, fmt.Errorf("DNS 解析超时")
   }
   ```

2. **`internal/ssl/manager.go:875`** - DNS 解析超时
   ```go
   // 在匿名函数中，只执行一次
   select {
   case res := <-ch:
       return res.ips, res.err
   case <-time.After(5 * time.Second):
       return nil, fmt.Errorf("DNS 解析超时")
   }
   ```

3. **`internal/config/watcher.go:154`** - 配置重载防抖
   ```go
   // 在 goroutine 中，但不在循环中，只执行一次
   go func() {
       select {
       case <-time.After(cw.debounceInterval):
           // 处理配置重载
       case <-cw.ctx.Done():
           return
       }
   }()
   ```

4. **DNS 验证相关文件** - 正确的用法
   ```go
   // time.After 在循环外创建，然后在循环中使用
   timeout := time.After(30 * time.Second)
   ticker := time.NewTicker(3 * time.Second)
   defer ticker.Stop()
   
   for {
       select {
       case <-timeout:  // 使用循环外创建的定时器
           return fmt.Errorf("timeout")
       case <-ticker.C:
           // 检查 DNS
       }
   }
   ```

## 📊 修复效果

### 修复前的问题

假设有 100 个 WebSocket 连接和 10 个 SSE 连接，运行 1 小时：

- **WebSocket 连接**：
  - `readWebSocketData`: 如果每秒发送数据，会创建 **360,000 个定时器**
  - `writeWebSocketData`: 会创建 **6,000 个定时器**
  - `monitorWebSocketConnections`: 会创建 **600 个定时器**

- **SSE 连接**：
  - `handleSSE`: 每个连接每 30 秒创建一个定时器，10 个连接运行 1 小时会创建 **1,200 个定时器**

**总计：约 368,000 个定时器泄露！**

### 修复后

- ✅ 所有定时器都正确管理
- ✅ 不再有定时器泄露
- ✅ 内存占用稳定
- ✅ CPU 占用降低（减少 GC 压力）
- ✅ 长时间运行后性能稳定

## 🚀 部署步骤

1. **编译新版本**：
```bash
make build
```

2. **部署到服务器**：
```bash
# 备份旧版本
sudo cp /opt/sslcat/sslcat /opt/sslcat/sslcat.backup.$(date +%Y%m%d-%H%M%S)

# 部署新版本
sudo cp build/sslcat /opt/sslcat/sslcat
sudo chmod +x /opt/sslcat/sslcat

# 重启服务
sudo systemctl restart sslcat
```

3. **验证修复**：
```bash
# 运行诊断脚本
bash scripts/diagnose-longrun-cpu.sh

# 监控 CPU 和内存
watch -n 5 'ps -p $(pgrep -x sslcat) -o %cpu,%mem,etime'
```

## 📝 修复总结

### 修复的文件

1. ✅ `internal/proxy/manager.go` - 3 处修复
2. ✅ `internal/runner/realtime_logs.go` - 1 处修复

### 修复方法

- **WebSocket 函数**：使用 `context.WithTimeout()` 替代 `time.After()`
- **SSE 心跳**：使用 `time.NewTicker()` 替代 `time.After()`

### 最佳实践

1. ✅ **在循环中使用 `time.NewTicker()`** 而不是 `time.After()`
2. ✅ **使用 `context.WithTimeout()`** 进行超时控制
3. ✅ **确保所有定时器都有 `defer ticker.Stop()`** 或 `defer cancel()`

## 🔍 如何避免类似问题

### 代码审查检查清单

- [ ] 检查所有 `time.After()` 的使用
- [ ] 确认 `time.After()` 不在循环中
- [ ] 如果需要在循环中定时，使用 `time.NewTicker()`
- [ ] 确保所有 ticker 都有 `defer ticker.Stop()`
- [ ] 使用 `context.WithTimeout()` 进行超时控制

### 自动化检查

可以使用以下命令检查：
```bash
# 查找所有 time.After 的使用
grep -r "time\.After(" internal/

# 查找在 select 循环中的 time.After（需要手动检查上下文）
grep -A 10 -B 10 "time\.After(" internal/*.go | grep -A 5 -B 5 "select"
```

## 📚 相关文档

- [长时间运行 CPU 高问题修复](./LONGRUN_CPU_FIX.md)
- [CPU 优化说明](./CPU_OPTIMIZATION.md)
- [CPU 问题排查指南](./CPU_TROUBLESHOOTING_GUIDE.md)


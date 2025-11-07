# SSLcat 长时间运行 CPU 高问题修复

## 🔍 问题根源

运行久了之后 CPU 占用高的主要原因是：**定时器泄露（Timer Leak）**

### 问题代码

在 `internal/proxy/manager.go` 中，WebSocket 相关的函数使用了 `time.After()` 在 `select` 循环中：

```go
// ❌ 错误示例
for {
    select {
    case data := <-dataChan:
        // 处理数据
    case <-time.After(5 * time.Second):  // 每次循环都创建新定时器！
        // 超时处理
    }
}
```

### 为什么会导致 CPU 高？

1. **定时器累积**：`time.After()` 在 `select` 循环中每次都会创建新的定时器
2. **内存泄露**：如果这个 case 没有被选中，定时器会一直存在直到触发（即使已经不需要了）
3. **CPU 占用**：大量未使用的定时器会导致：
   - 内存占用增加
   - GC 压力增大
   - 定时器管理开销增加

### 影响范围

如果有多个 WebSocket 连接长时间运行，每个连接都会：
- `readWebSocketData`: 每次发送数据时创建 5 秒定时器
- `writeWebSocketData`: 每 60 秒创建一个定时器
- `monitorWebSocketConnections`: 每 10 分钟创建一个定时器

**假设有 100 个 WebSocket 连接，运行 1 小时：**
- `readWebSocketData`: 如果每秒发送数据，会创建 360,000 个定时器！
- `writeWebSocketData`: 会创建 6,000 个定时器
- `monitorWebSocketConnections`: 会创建 600 个定时器

## ✅ 修复方案

使用 `context.WithTimeout()` 替代 `time.After()`：

```go
// ✅ 正确示例
timeoutCtx, timeoutCancel := context.WithTimeout(ctx, 5*time.Second)
defer timeoutCancel()

for {
    select {
    case data := <-dataChan:
        timeoutCancel() // 成功处理，取消超时
        // 处理数据
    case <-timeoutCtx.Done():
        // 超时处理
        return
    }
}
```

### 修复的函数

1. ✅ `readWebSocketData` - 修复数据发送超时
2. ✅ `writeWebSocketData` - 修复空闲超时检查
3. ✅ `monitorWebSocketConnections` - 修复连接超时检查

## 📊 预期效果

修复后：
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

# 监控 CPU 使用率
watch -n 5 'ps -p $(pgrep -x sslcat) -o %cpu,%mem,etime'
```

## 🔍 其他可能的问题

如果修复后 CPU 仍然高，检查：

1. **Goroutine 泄露**：
```bash
curl -s "http://localhost/debug/pprof/goroutine?debug=1" | grep -c "^goroutine "
```

2. **文件描述符泄露**：
```bash
ls /proc/$(pgrep -x sslcat)/fd | wc -l
```

3. **内存泄露**：
```bash
# 监控内存增长
watch -n 10 'ps -p $(pgrep -x sslcat) -o rss --no-headers'
```

4. **连接泄露**：
```bash
netstat -an | grep ESTABLISHED | wc -l
```

## 📝 相关文档

- [CPU 优化说明](./CPU_OPTIMIZATION.md)
- [CPU 问题排查指南](./CPU_TROUBLESHOOTING_GUIDE.md)


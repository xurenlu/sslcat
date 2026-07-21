# SSLcat CPU 优化说明

## 优化内容

### 1. 实时日志检查优化 (`internal/runner/realtime_logs.go`)

**问题**：
- 每个 Runner 应用都有一个 1 秒的日志检查 ticker
- 如果有多个应用，会导致大量频繁的文件检查操作
- 即使没有客户端查看日志，也会持续检查

**优化**：
- ✅ 将日志检查间隔从 **1 秒增加到 2 秒**（减少 50% 的检查频率）
- ✅ **无客户端连接时跳过日志读取**，避免浪费 CPU
- ✅ 优化文件状态检查逻辑，减少不必要的系统调用

**预期效果**：
- 如果有 10 个 Runner 应用，CPU 占用可降低约 **50%**
- 没有用户查看日志时，CPU 占用几乎为 0

### 2. 配置文件监听优化 (`internal/web/server.go`)

**问题**：
- 配置文件监听每 5 秒执行一次
- 非集群模式下也会执行不必要的检查

**优化**：
- ✅ 非集群模式下，将检查间隔从 5 秒增加到 **30 秒**
- ✅ 集群模式下保持 5 秒间隔（确保及时同步）

**预期效果**：
- 非集群模式下，配置文件检查的 CPU 占用降低 **83%**

## 部署步骤

1. **编译新版本**：
```bash
make build
# 或
go build -o sslcat
```

2. **在服务器上测试**：
```bash
# 先运行诊断脚本查看当前状态
bash scripts/debug-cpu-issue.sh

# 备份当前版本
sudo cp /usr/local/bin/sslcat /usr/local/bin/sslcat.backup

# 部署新版本
sudo cp build/sslcat /usr/local/bin/sslcat

# 重启服务
sudo systemctl restart sslcat

# 观察 CPU 使用率
watch -n 1 'ps aux | grep sslcat | grep -v grep'
```

3. **验证优化效果**：
```bash
# 运行诊断脚本对比优化前后
bash scripts/debug-cpu-issue.sh

# 查看 Goroutine 数量（应该没有明显变化）
curl -s "http://127.0.0.1:6060/debug/pprof/goroutine?debug=1" | grep -c "^goroutine "
```

## 预期效果

### 优化前（假设有 10 个 Runner 应用）：
- 日志检查：10 个应用 × 1 秒间隔 = 每秒 10 次检查
- 配置文件检查：每 5 秒 1 次
- **预计 CPU 占用：5-10%**

### 优化后：
- 日志检查：10 个应用 × 2 秒间隔 = 每秒 5 次检查（减少 50%）
- 无客户端时：几乎不检查（减少 100%）
- 配置文件检查：每 30 秒 1 次（非集群模式）
- **预计 CPU 占用：2-5%**

## 注意事项

1. **日志实时性**：日志检查间隔从 1 秒增加到 2 秒，日志显示会有最多 2 秒的延迟（通常用户感知不到）

2. **无客户端时的行为**：当没有用户查看日志时，日志检查会被跳过。当有用户连接时，会立即恢复正常的 2 秒间隔检查

3. **集群模式**：配置文件监听在集群模式下仍然保持 5 秒间隔，确保配置同步的及时性

4. **回滚**：如果出现问题，可以使用备份版本回滚：
```bash
sudo cp /usr/local/bin/sslcat.backup /usr/local/bin/sslcat
sudo systemctl restart sslcat
```

## 进一步优化建议

如果 CPU 占用仍然较高，可以考虑：

1. **增加健康检查间隔**：在配置文件中设置 `health_check_interval` ≥ 60 秒
2. **减少 Runner 应用数量**：如果可能，合并或减少应用数量
3. **使用 CPU Profile 分析**：运行 `tools/cpu-profiler.sh` 找出其他热点函数

## 监控

部署后建议监控以下指标：
- CPU 使用率（应该降低 30-50%）
- Goroutine 数量（应该没有明显变化）
- 日志实时性（用户反馈）
- 配置文件同步延迟（集群模式）

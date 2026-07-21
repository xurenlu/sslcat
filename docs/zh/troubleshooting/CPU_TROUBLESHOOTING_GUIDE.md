# SSLcat CPU 占用排查指南

## 📋 问题概述

线上 sslcat 经常占用 90% CPU，需要系统性排查和解决。

## 🚀 快速排查（5 分钟）

### 1. 使用自动诊断工具

我们提供了一个自动化诊断工具，可以一键收集所有必要的信息：

```bash
# 在服务器上运行
cd /path/to/sslcat
./tools/cpu-profiler.sh
```

该工具会自动收集：
- 进程 CPU 使用率
- Goroutine 数量和堆栈
- CPU Profile 数据
- 内存使用情况
- 配置文件信息
- 已知问题检查

运行后会生成一个目录，包含所有诊断数据和分析报告。

### 2. 快速检查 - 查看 Goroutine 数量

```bash
# 方式 1: 使用 API（需要管理员权限）
curl "http://127.0.0.1:6060/debug/pprof/goroutine?debug=1" | head -1

# 方式 2: 查看进程线程数
ps -p $(pgrep sslcat) -o pid,nlwp

# 方式 3: 使用系统命令
ps -eLf | grep sslcat | wc -l
```

**正常情况**：
- Goroutine 数量：< 100
- 线程数：< 50

**异常情况**：
- Goroutine 数量：> 500（可能存在泄露）
- Goroutine 数量：> 1000（严重问题）

---

## 🔍 详细排查步骤

### 步骤 1: 确认 CPU 占用情况

```bash
# 实时监控 CPU
top -p $(pgrep sslcat)

# 或使用 htop（更友好）
htop -p $(pgrep sslcat)

# 获取平均 CPU（10 秒采样）
for i in {1..10}; do 
    ps -p $(pgrep sslcat) -o %cpu | tail -1
    sleep 1
done | awk '{sum+=$1} END {print "Average CPU:", sum/NR "%"}'
```

### 步骤 2: 收集 CPU Profile

```bash
# 收集 30 秒的 CPU profile
curl "http://127.0.0.1:6060/debug/pprof/profile?seconds=30" > cpu.prof

# 如果没有管理员密码，可以从日志中查找
# 或者设置环境变量 SSLCAT_ADMIN_PASS

# 分析 CPU profile
go tool pprof -top cpu.prof
go tool pprof -text cpu.prof | head -20
```

### 步骤 3: 检查 Goroutine 堆栈

```bash
# 获取所有 goroutine 的堆栈
curl "http://127.0.0.1:6060/debug/pprof/goroutine?debug=2" > goroutines.txt

# 统计 goroutine 数量
grep -c "^goroutine " goroutines.txt

# 查找可疑的 goroutine（重点关注这些）
grep -E "watchLogs|WatchDeployTriggers|checkBackendHealth" goroutines.txt

# 按函数统计 goroutine
grep "^goroutine " goroutines.txt | sed 's/^goroutine [0-9]* \[//' | sed 's/\]:.*//' | sort | uniq -c | sort -rn
```

### 步骤 4: 检查配置

```bash
# 查看当前配置
cat /etc/sslcat/sslcat.conf  # 或你的配置文件路径

# 统计关键配置
echo "Runner 应用数量:"
grep -c '"type": "runner"' sslcat.conf

echo "代理规则数量:"
grep -c '"proxy_rules"' sslcat.conf

echo "负载均衡规则数量:"
grep -c '"load_balancer"' sslcat.conf

echo "健康检查间隔:"
grep -A 1 '"health_check_interval"' sslcat.conf
```

### 步骤 5: 检查系统日志

```bash
# 查看 sslcat 日志
journalctl -u sslcat --since "1 hour ago" | tail -100

# 查找错误和警告
journalctl -u sslcat --since "1 hour ago" | grep -iE "error|warn|panic"

# 查找性能相关日志
journalctl -u sslcat --since "1 hour ago" | grep -iE "cpu|memory|goroutine|slow"
```

---

## 🎯 常见问题和解决方案

### 问题 1: Goroutine 泄露（数量 > 500）

**症状**：
- Goroutine 数量持续增长
- CPU 占用逐渐升高
- 内存也在增长

**可能原因**：
1. 日志监听 goroutine 没有正确关闭（watchLogs）
2. HTTP 请求处理 goroutine 挂起
3. 健康检查 goroutine 堆积

**解决方案**：

```bash
# 1. 检查是否是日志监听问题
grep -c "watchLogs" goroutines.txt

# 如果数量异常多（> Runner 应用数），说明存在泄露
# 解决方法：升级到最新版本或应用补丁

# 2. 重启服务（临时方案）
systemctl restart sslcat

# 3. 减少 Runner 应用数量
# 编辑配置文件，禁用不必要的 Runner 应用
```

### 问题 2: 忙等待循环（watchLogs 或 WatchDeployTriggers CPU 占用高）

**症状**：
- CPU profile 显示 `watchLogs` 或 `WatchDeployTriggers` 占用高
- 即使没有请求，CPU 也很高（50-400%）
- 每个 Runner 应用贡献 ~50% CPU

**可能原因**：
- 使用了 `select` 的 `default` 分支导致忙等待
- 这是已知问题，已在新版本中修复

**解决方案**：

```bash
# 1. 检查版本
./sslcat --version

# 2. 升级到最新版本（推荐）
# 从 GitHub 下载最新 release
wget https://github.com/xurenlu/sslcat/releases/latest/download/sslcat_linux_amd64.tar.gz
tar xzf sslcat_linux_amd64.tar.gz

# 备份和替换
systemctl stop sslcat
cp /usr/local/bin/sslcat /usr/local/bin/sslcat.backup
cp sslcat /usr/local/bin/sslcat
systemctl start sslcat

# 3. 或者从源码编译最新版本
git pull origin main
make build
systemctl stop sslcat
cp build/sslcat /usr/local/bin/sslcat
systemctl start sslcat

# 4. 验证修复
# 等待 1 分钟后检查 CPU
top -p $(pgrep sslcat)
# 应该降低到 < 10%
```

### 问题 3: 健康检查过于频繁

**症状**：
- CPU profile 显示 `checkBackendHealth` 占用高
- Goroutine 中有大量健康检查相关的
- 配置了很多负载均衡规则

**可能原因**：
- 健康检查间隔太短（< 30 秒）
- 负载均衡规则过多
- 后端服务器数量过多
- 并发控制失效

**解决方案**：

```bash
# 1. 增加健康检查间隔
# 编辑配置文件，找到 health_check_interval
# 建议设置为 60 秒或更长

{
  "load_balancer": {
    "health_check_interval": "60s",  // 改为 60 秒
    "health_check_timeout": "10s"
  }
}

# 2. 重新加载配置
systemctl reload sslcat
# 或
kill -HUP $(pgrep sslcat)

# 3. 验证
curl "http://127.0.0.1:6060/debug/pprof/goroutine?debug=2" | grep -c "checkBackendHealth"
# 应该减少
```

### 问题 4: Runner 应用过多

**症状**：
- 配置了大量 Runner 应用（> 10 个）
- CPU 占用随 Runner 数量线性增长
- 每个 Runner 贡献约 5-10% CPU

**解决方案**：

```bash
# 1. 列出所有 Runner 应用
jq '.runners[] | select(.enabled==true) | .name' sslcat.conf

# 2. 禁用不必要的 Runner 应用
# 编辑配置文件，将不常用的 Runner 的 enabled 设置为 false

# 3. 合并 Runner 应用
# 如果可能，将多个小应用合并到一个 monorepo 中

# 4. 重新加载配置
systemctl reload sslcat
```

### 问题 5: 真实业务负载高

**症状**：
- CPU profile 显示 `ServeHTTP`、`ReadRequest`、`WriteResponse` 占用高
- 请求量很大（> 1000 req/s）
- CPU 占用与请求量成正比

**这是正常现象！** 说明服务器在处理真实的业务流量。

**解决方案**：

```bash
# 1. 查看请求量
tail -f /var/log/sslcat/access.log | pv -l -i 1 > /dev/null
# 或
journalctl -u sslcat -f | grep "HTTP" | pv -l -i 1 > /dev/null

# 2. 优化策略
# a) 增加服务器资源（CPU/内存）
# b) 使用负载均衡分散到多台服务器
# c) 启用缓存
# d) 优化后端应用性能
# e) 使用 CDN 分流静态资源

# 3. 启用缓存（如果适用）
# 在配置文件中启用上游缓存
{
  "upstream_cache": {
    "enabled": true,
    "max_size": "1GB",
    "ttl": "5m"
  }
}
```

---

## ❓ 为什么 sslcat 是系统中 CPU 占用最高的进程？

### 📊 这是正常现象

如果你发现 sslcat 是系统中 CPU 占用最高的进程（例如：3-5% CPU），这**通常是正常的**，原因如下：

#### 1. sslcat 有 30+ 个后台定时器在运行

sslcat 需要持续执行各种后台任务，包括：

- **1秒间隔**: 实时日志检查（`internal/runner/realtime_logs.go`）
- **5秒间隔**: 配置文件监听（`internal/web/server.go`）
- **30秒间隔**: 性能监控、WebSocket 监控、实时日志心跳
- **60秒间隔**: 内存监控、Goroutine 监控、健康检查、CDN 缓存清理
- **5分钟间隔**: 多个清理任务（缓存、会话、限流器等）
- **更长间隔**: 证书检查、威胁情报更新等

这些定时器虽然单个消耗很小，但累积起来会导致基础 CPU 占用。

#### 2. CPU 占用率通常很低

- **3% CPU = 每核约 0.75%**（在 4 核机器上）
- 这属于**低占用范围**，不是异常高
- 即使在定时器叠加时（如整点），通常也不会超过 10-15%

#### 3. 其他进程通常更轻量

- **puma**: 只是 Web 服务器，后台任务少
- **redis**: 主要是内存操作，CPU 占用低
- **其他服务**: 通常只有少量定时任务

### 💡 判断是否正常

**正常情况**（无需担心）：
- ✅ CPU 占用 < 10%（空闲或轻负载）
- ✅ CPU 占用随请求量成正比增长
- ✅ 没有持续的 CPU 占用异常（如空闲时仍 > 50%）

**异常情况**（需要排查）：
- ⚠️ 空闲时 CPU > 50%
- ⚠️ 单个 goroutine 占用 100% CPU
- ⚠️ Goroutine 数量持续增长
- ⚠️ CPU 占用与请求量不成比例

### 🔍 如何验证

```bash
# 1. 查看进程 CPU 占用（10 秒采样）
for i in {1..10}; do 
    ps -p $(pgrep sslcat) -o %cpu | tail -1
    sleep 1
done | awk '{sum+=$1} END {print "Average CPU:", sum/NR "%"}'

# 2. 检查是否与请求量相关
# 如果 CPU 随请求量变化，说明是正常业务负载

# 3. 检查定时器活动
# 查看日志，确认定时器正常执行
journalctl -u sslcat --since '1 hour ago' | grep -i "timer\|ticker\|cleanup\|monitor"
```

### ✅ 结论

**sslcat 成为 CPU 占用最高的进程是正常的**，因为：
- ✅ 它是功能最复杂的服务，需要持续监控、清理、检查
- ✅ 这些定时器是**必要的功能**，不是 bug
- ✅ 3-5% 的 CPU 占用率表明系统运行良好

**只有在以下情况才需要担心**：
- ❌ 空闲时 CPU > 50%
- ❌ CPU 占用持续增长且与请求量无关
- ❌ 发现 goroutine 泄漏或其他问题

---

## 📊 性能基准

### 正常情况下的 CPU 占用

| 场景 | 预期 CPU | 备注 |
|------|---------|------|
| 空闲（无请求） | < 1% | 如果 > 5%，可能有问题 |
| 轻负载（< 10 req/s） | 5-10% | |
| 中负载（100 req/s） | 15-30% | |
| 高负载（1000 req/s） | 40-70% | 取决于后端响应时间 |
| 极高负载（> 5000 req/s） | 80-100% | 正常，建议扩容 |

### Goroutine 数量基准

| 组件 | 正常数量 | 警告阈值 | 严重阈值 |
|------|---------|---------|---------|
| 基础 goroutine | ~15 | - | - |
| 每个 Runner 应用 | 2-3 | - | - |
| 每个负载均衡规则 | 1 | - | - |
| 活跃 HTTP 连接 | 变化 | > 500 | > 1000 |
| **总计** | < 100 | > 500 | > 1000 |

---

## 🛠️ 性能优化建议

### 1. 代码层面

✅ **已优化**（在最新版本中）：
- [x] 修复 realtime_logs.go 的忙等待问题
- [x] 将文件系统轮询改为事件驱动（fsnotify）
- [x] 添加健康检查并发控制
- [x] 强制健康检查最小间隔（30 秒）

🔄 **可以进一步优化**：
- [ ] 使用连接池复用 HTTP 连接
- [ ] 实现请求限流和熔断
- [ ] 优化日志写入（异步批量写入）
- [ ] 使用更高效的 JSON 库（如 sonic）

### 2. 配置层面

```json
{
  // 1. 优化健康检查
  "load_balancer": {
    "health_check_interval": "60s",  // 增加间隔
    "health_check_timeout": "5s"     // 减少超时
  },
  
  // 2. 限制并发连接
  "max_connections": 10000,  // 根据服务器资源设置
  
  // 3. 启用上游缓存
  "upstream_cache": {
    "enabled": true,
    "max_size": "1GB",
    "ttl": "5m"
  },
  
  // 4. 优化 Runner 配置
  "runners": [
    {
      "name": "app1",
      "enabled": true,
      "log_level": "warn",  // 减少日志输出
      "realtime_log": false // 如果不需要实时日志，可以禁用
    }
  ]
}
```

### 3. 系统层面

```bash
# 1. 调整文件描述符限制
ulimit -n 65535

# 在 /etc/security/limits.conf 中永久设置
* soft nofile 65535
* hard nofile 65535

# 2. 优化内核参数
# /etc/sysctl.conf
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30

# 应用设置
sysctl -p

# 3. 使用 cgroup 限制资源
# 创建 cgroup
cgcreate -g cpu,memory:/sslcat
# 限制 CPU 为 8 核
cgset -r cpu.cfs_quota_us=800000 sslcat
# 限制内存为 4GB
cgset -r memory.limit_in_bytes=4G sslcat

# 在 cgroup 中运行
cgexec -g cpu,memory:sslcat /usr/local/bin/sslcat
```

### 4. 架构层面

**水平扩展**：
```
             ┌─────────────┐
             │   Nginx     │
             │  (Layer 7)  │
             └──────┬──────┘
                    │
        ┌───────────┴───────────┐
        │                       │
   ┌────▼────┐            ┌────▼────┐
   │ SSLcat1 │            │ SSLcat2 │
   │ 50% CPU │            │ 50% CPU │
   └─────────┘            └─────────┘
```

**服务隔离**：
- 将 Runner 部署到单独的服务器
- 将静态文件服务分离到专门的文件服务器
- 使用 CDN 处理静态资源

---

## 📈 持续监控

### 1. 设置 Prometheus 监控

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'sslcat'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/sslcat-panel/api/metrics'
```

### 2. 设置告警规则

```yaml
# alerts.yml
groups:
  - name: sslcat
    rules:
      - alert: HighCPU
        expr: rate(process_cpu_seconds_total[5m]) > 0.8
        for: 5m
        annotations:
          summary: "SSLcat CPU 使用率过高"
          
      - alert: TooManyGoroutines
        expr: go_goroutines > 500
        for: 5m
        annotations:
          summary: "Goroutine 数量异常"
```

### 3. 定期健康检查脚本

```bash
#!/bin/bash
# /usr/local/bin/check-sslcat-health.sh

CPU=$(ps -p $(pgrep sslcat) -o %cpu | tail -1 | tr -d ' ')
GOROUTINES=$(curl -s "http://127.0.0.1:6060/debug/pprof/goroutine?debug=1" | head -1 | grep -oE '[0-9]+' | head -1)

echo "[$(date)] CPU: $CPU%, Goroutines: $GOROUTINES"

# 告警阈值
if (( $(echo "$CPU > 80" | bc -l) )); then
    echo "WARNING: CPU usage is too high!"
    # 发送告警邮件或通知
fi

if (( GOROUTINES > 500 )); then
    echo "WARNING: Too many goroutines!"
fi
```

添加到 crontab：
```bash
# 每 5 分钟检查一次
*/5 * * * * /usr/local/bin/check-sslcat-health.sh >> /var/log/sslcat-health.log 2>&1
```

---

## 📞 获取帮助

### 1. 自助诊断

运行诊断工具：
```bash
./tools/cpu-profiler.sh
```

然后查看生成的报告：
```bash
cat ./cpu-profile-*/README.md
```

### 2. 社区支持

- **GitHub Issues**: https://github.com/xurenlu/sslcat/issues
- **邮件**: m@some.im
- **提供信息**：
  - 运行 `./tools/cpu-profiler.sh` 生成的完整报告
  - SSLcat 版本: `./sslcat --version`
  - 系统信息: `uname -a`
  - 配置文件（去除敏感信息）

### 3. 紧急处理

如果 CPU 占用导致服务器无法响应：

```bash
# 1. 临时降低优先级
renice +10 $(pgrep sslcat)

# 2. 限制 CPU 使用
cpulimit -p $(pgrep sslcat) -l 200  # 限制为 2 个核心

# 3. 如果以上都无效，重启服务
systemctl restart sslcat
```

---

## ✅ 检查清单

在排查 CPU 问题时，请按以下清单逐项检查：

- [ ] 确认 CPU 占用确实很高（> 80%）
- [ ] 运行自动诊断工具 `./tools/cpu-profiler.sh`
- [ ] 检查 Goroutine 数量是否正常（< 500）
- [ ] 收集并分析 CPU Profile
- [ ] 检查是否有已知问题（watchLogs、WatchDeployTriggers）
- [ ] 检查配置是否合理（健康检查间隔、Runner 数量）
- [ ] 检查是否是真实业务负载
- [ ] 如果是已知问题，应用修复或升级版本
- [ ] 如果是配置问题，优化配置
- [ ] 如果是负载问题，考虑扩容
- [ ] 设置监控和告警
- [ ] 记录问题和解决方案，避免重复

---

## 📚 相关文档

- **CPU_ANALYSIS.md** - 详细的 CPU 问题分析
- **CPU_ISSUE_SUMMARY.md** - 问题总结
- **CPU_FIX_PATCH.md** - 修复补丁说明
- **CPU_OPTIMIZATION_COMPLETE.md** - 完整优化报告
- **tools/cpu-profiler.sh** - 自动诊断工具

---

**更新时间**: 2025-10-22  
**适用版本**: SSLcat v1.3.x 及以上

# 代理循环检测功能

## 概述

从此版本开始，sslcat 在启动和配置重载时会自动检测代理循环配置，防止将流量代理到自己导致的无限循环和资源耗尽问题。

## 问题背景

在 shifen.de 服务器上发现的真实案例：

```json
{
  "domain": "gg.some.im",
  "target": "127.0.0.1",
  "port": 80
}
```

**问题**：
- sslcat 监听在 80 和 443 端口
- `gg.some.im` 被配置为代理到 `127.0.0.1:80`
- 这导致请求被代理到 sslcat 自己，形成无限循环

**后果**：
- Goroutine 泄漏：26,000+ goroutines (正常 31 个)
- 内存泄漏：3.9 GB (正常 100 MB)
- CPU 飙升：41-43% (正常 < 5%)
- 系统几乎不可用

## 解决方案

### 1. 启动时检测

sslcat 在启动时会验证所有代理配置，检测以下情况：

#### 单后端模式
```go
// ❌ 错误配置 - 会被拒绝
{
  "domain": "example.com",
  "target": "127.0.0.1",  // 或 localhost, 0.0.0.0, ::1, 127.x.x.x
  "port": 80              // sslcat 监听的端口
}

// ✅ 正确配置 - 允许
{
  "domain": "example.com",
  "target": "127.0.0.1",
  "port": 3000            // 不是 sslcat 监听的端口
}

// ✅ 正确配置 - 允许
{
  "domain": "example.com",
  "target": "192.168.1.100",  // 外部 IP
  "port": 8080
}
```

#### 负载均衡模式
```go
// ❌ 错误配置 - 会被拒绝
{
  "domain": "lb.example.com",
  "load_balancer_enabled": true,
  "load_balancer_backends": [
    {
      "host": "localhost",  // 指向自己
      "port": 80
    }
  ]
}

// ✅ 正确配置 - 允许
{
  "domain": "lb.example.com",
  "load_balancer_enabled": true,
  "load_balancer_backends": [
    {
      "host": "192.168.1.100",  // 外部服务器
      "port": 8080
    },
    {
      "host": "192.168.1.101",
      "port": 8080
    }
  ]
}
```

### 2. 错误提示

当检测到循环配置时，sslcat 会拒绝启动并显示清晰的错误信息：

```
FATAL: failed to load config: proxy rule 0 (gg.some.im): proxy loop detected: 
gg.some.im proxies to itself (127.0.0.1:80), this will cause infinite loop 
and resource exhaustion
```

### 3. 配置重载时检测

当通过热重载更新配置时，也会进行相同的检测：

```bash
# 修改配置文件后
sudo systemctl reload sslcat

# 如果有循环配置，会看到错误日志
journalctl -u sslcat -f
# ERROR: Configuration validation failed: proxy loop detected...
# INFO: Keeping previous configuration
```

## 检测规则

### 本地地址识别

以下地址被视为本地地址：
- `localhost` (不区分大小写)
- `127.0.0.1`
- `127.x.x.x` (整个 127 网段)
- `::1` (IPv6 loopback)
- `0.0.0.0`
- `::`

### 监听端口识别

根据 sslcat 的运行模式，会检测以下端口：

#### 标准模式 (PortMode: "standard")
- 主端口 (通常是 443)
- HTTP 端口 (80)
- HTTPS 端口 (443)

#### 自定义模式 (PortMode: "custom")
- 主端口
- 自定义端口

### 检测逻辑

```
IF (后端地址是本地地址) AND (后端端口是 sslcat 监听端口)
THEN 拒绝配置
```

## 测试覆盖

已添加完整的单元测试：

```bash
# 运行循环检测测试
go test -v ./internal/config -run TestDetectProxyLoop

# 测试覆盖：
# ✅ 检测代理到 127.0.0.1:80
# ✅ 检测代理到 localhost:443
# ✅ 检测代理到 0.0.0.0:8080
# ✅ 检测代理到 127.x.x.x 网段
# ✅ 允许代理到外部 IP
# ✅ 允许代理到本地不同端口
# ✅ 检测负载均衡后端循环
# ✅ 允许正常的负载均衡配置
```

## 如何修复现有的循环配置

### 步骤 1: 识别问题

检查配置文件中是否有类似的配置：

```bash
cat /etc/sslcat/sslcat.conf | grep -A 5 '"target": "127.0.0.1"'
```

### 步骤 2: 确定正确的后端

确定该域名应该代理到哪里：

1. **如果后端服务应该运行但没有运行**：
   ```bash
   # 启动后端服务
   sudo systemctl start <backend-service>
   ```

2. **如果后端服务在不同端口**：
   ```json
   {
     "domain": "example.com",
     "target": "127.0.0.1",
     "port": 3000  // 修改为正确的端口
   }
   ```

3. **如果该域名不再使用**：
   ```bash
   # 从配置中删除该规则
   sudo vi /etc/sslcat/sslcat.conf
   # 删除相关的 proxy rule
   ```

### 步骤 3: 验证配置

```bash
# 测试配置是否有效
sudo sslcat --config /etc/sslcat/sslcat.conf --test

# 或者尝试重启服务
sudo systemctl restart sslcat

# 检查是否有错误
sudo journalctl -u sslcat -n 50
```

## 性能影响

循环检测在启动时执行，对运行时性能**没有影响**：

- ✅ 仅在启动和配置重载时执行
- ✅ 时间复杂度：O(n) where n = 代理规则数量
- ✅ 内存开销：可忽略不计
- ✅ 不影响请求处理性能

## 最佳实践

### 1. 本地开发环境

```json
{
  "proxy": {
    "rules": [
      {
        "domain": "app.local",
        "target": "127.0.0.1",
        "port": 3000,  // 确保是应用实际监听的端口
        "enabled": true
      }
    ]
  }
}
```

### 2. 生产环境

```json
{
  "proxy": {
    "rules": [
      {
        "domain": "api.example.com",
        "target": "10.0.1.100",  // 使用内网 IP
        "port": 8080,
        "enabled": true
      }
    ]
  }
}
```

### 3. 负载均衡

```json
{
  "proxy": {
    "rules": [
      {
        "domain": "app.example.com",
        "load_balancer_enabled": true,
        "load_balancer_algorithm": "round_robin",
        "load_balancer_backends": [
          {
            "host": "10.0.1.100",  // 后端服务器 1
            "port": 8080,
            "weight": 1,
            "enabled": true
          },
          {
            "host": "10.0.1.101",  // 后端服务器 2
            "port": 8080,
            "weight": 1,
            "enabled": true
          }
        ]
      }
    ]
  }
}
```

## 相关问题排查

### Q: 为什么我的配置被拒绝了？

**A**: 检查以下几点：
1. 后端地址是否是本地地址（127.0.0.1, localhost 等）
2. 后端端口是否是 sslcat 监听的端口
3. 是否真的需要代理到本地？通常应该代理到实际的后端服务

### Q: 我确实需要代理到本地怎么办？

**A**: 确保代理到的端口不是 sslcat 监听的端口：
- sslcat 通常监听 80 和 443
- 你的后端应用应该监听其他端口（如 3000, 8080 等）

### Q: 如何查看 sslcat 监听的端口？

**A**: 
```bash
# 方法 1: 查看配置
cat /etc/sslcat/sslcat.conf | grep -E '"port"|"port_mode"'

# 方法 2: 查看进程
sudo netstat -tlnp | grep sslcat

# 方法 3: 查看日志
sudo journalctl -u sslcat | grep "Listening on"
```

## 更新日志

- **v1.3.17** (2025-12-30)
  - ✨ 新增启动时代理循环检测
  - ✨ 新增配置重载时循环检测
  - ✨ 支持单后端和负载均衡模式
  - ✨ 详细的错误提示信息
  - ✅ 完整的单元测试覆盖

## 参考

- 诊断报告: `SHIFEN_CPU_MEMORY_SPIKE_DIAGNOSIS.md`
- 配置文档: `docs/zh/configuration.md`
- 测试代码: `internal/config/watcher_loop_test.go`


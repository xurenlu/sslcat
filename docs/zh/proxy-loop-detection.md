# 代理循环检测功能

## 概述

sslcat 实现了完整的代理循环检测机制，防止用户将代理后端配置为 sslcat 自己的监听端口，避免无限循环导致的系统资源耗尽。

## 问题背景

### 什么是代理循环？

当代理服务器的后端地址指向自己时，会形成无限循环：

```
客户端请求 → sslcat (80端口) → 代理到 127.0.0.1:80 → sslcat (80端口) → ...
```

### 会导致什么问题？

- **无限循环**：请求永远无法完成
- **资源耗尽**：大量 goroutine 泄漏
- **内存溢出**：内存持续增长
- **CPU 飙升**：GC 频繁触发
- **系统崩溃**：最终导致服务不可用

### 真实案例

在 shifen.de 服务器上，曾经发生过这样的问题：

```
配置：
  domain: gg.some.im
  backend: 127.0.0.1:80

结果：
  - CPU 使用率：400%+
  - 内存使用：持续增长
  - Goroutines：数万个
  - 系统状态：接近崩溃
```

## 解决方案

### 双重保护机制

sslcat 实现了前端 + 后端的双重保护：

```
┌─────────────┐
│   前端验证   │ ← 第一道防线：即时反馈
└─────────────┘
       ↓
┌─────────────┐
│   后端验证   │ ← 第二道防线：最终保障
└─────────────┘
```

### 1. 前端验证（用户体验）

**功能：**
- 输入时实时检测
- 显示清晰的警告
- 提供修复建议
- 阻止无效提交

**示例：**

当用户输入 `127.0.0.1:80` 时，立即显示：

```
⚠️ 检测到代理循环：后端地址 127.0.0.1:80 指向 sslcat 自己！
这会导致无限循环和资源耗尽。
💡 建议：如果需要代理到本地服务，请使用其他端口（如 3000、8080 等）
```

### 2. 后端验证（安全保障）

**功能：**
- 启动时验证配置
- 热重载时验证配置
- API 请求时验证配置
- 拒绝无效配置

**示例：**

当配置有循环时，拒绝启动：

```
FATAL: configuration validation failed: 
proxy rule 0 (gg.some.im): proxy loop detected: 
gg.some.im proxies to itself (127.0.0.1:80), 
this will cause infinite loop and resource exhaustion
```

## 检测规则

### 本地地址识别

系统能识别以下本地地址：

- `localhost`
- `127.0.0.1`
- `127.x.x.x`（整个 127 网段）
- `::1`（IPv6 loopback）
- `0.0.0.0`
- `::`（IPv6 any）

### 端口检测

检查后端端口是否是 sslcat 监听的端口：

- **标准模式**：80, 443
- **自定义模式**：用户配置的端口

### 检测逻辑

```
如果 (后端地址是本地地址) AND (后端端口是 sslcat 监听端口):
    返回错误：检测到代理循环
否则:
    配置有效
```

## 配置示例

### ❌ 错误配置

```yaml
proxy:
  rules:
    - domain: example.com
      target: 127.0.0.1
      port: 80
```

**问题**：代理到 sslcat 自己的 80 端口。

### ❌ 错误配置（负载均衡）

```yaml
proxy:
  rules:
    - domain: example.com
      load_balancer_enabled: true
      load_balancer_backends:
        - host: localhost
          port: 443
        - host: backend.example.com
          port: 80
```

**问题**：第一个后端指向 sslcat 自己。

### ✅ 正确配置（本地服务）

```yaml
proxy:
  rules:
    - domain: example.com
      target: 127.0.0.1
      port: 3000
```

**说明**：代理到本地的 3000 端口，这是一个独立的服务。

### ✅ 正确配置（外部服务）

```yaml
proxy:
  rules:
    - domain: example.com
      target: backend.example.com
      port: 80
```

**说明**：代理到外部服务器。

## 使用指南

### 前端操作

1. **添加代理规则**
   - 访问管理面板
   - 点击"添加代理"
   - 输入后端配置

2. **实时验证**
   - 输入后端地址和端口
   - 系统自动检测循环
   - 如果有问题，显示红色警告

3. **修复配置**
   - 根据提示修改端口
   - 警告消失后即可保存

### 命令行操作

1. **检查配置文件**

```bash
# 启动 sslcat，会自动验证配置
sudo ./sslcat

# 如果有循环配置，会拒绝启动并显示错误
```

2. **修复配置**

```bash
# 编辑配置文件
sudo nano /etc/sslcat/sslcat.conf

# 修改后端配置，避免循环
# 保存后重启服务
sudo systemctl restart sslcat
```

## 常见问题

### Q1: 我想代理到本地服务，怎么办？

**A**: 使用不同的端口。

```yaml
# ❌ 错误
proxy:
  rules:
    - domain: example.com
      target: 127.0.0.1
      port: 80

# ✅ 正确
proxy:
  rules:
    - domain: example.com
      target: 127.0.0.1
      port: 3000  # 使用其他端口
```

### Q2: 为什么 localhost:3000 可以，localhost:80 不行？

**A**: 因为 sslcat 监听 80 端口，代理到 80 端口会形成循环。3000 端口是其他服务，不会循环。

### Q3: 我禁用了后端，为什么还是显示警告？

**A**: 前端会跳过禁用的后端，不会显示警告。如果看到警告，请检查后端是否真的被禁用。

### Q4: 我可以绕过前端验证吗？

**A**: 可以，但不推荐。即使绕过前端验证，后端验证也会拒绝无效配置。

### Q5: 如何查看 sslcat 监听的端口？

**A**: 查看配置文件或使用命令：

```bash
# 查看监听端口
sudo netstat -tlnp | grep sslcat

# 或
sudo ss -tlnp | grep sslcat
```

## 技术细节

### 前端实现

- **文件**：`frontend/src/utils/proxyLoopDetection.ts`
- **核心函数**：`detectProxyLoop()`, `detectProxyLoopInBackends()`
- **集成位置**：`BackendConfig.tsx`, `ProxyAdd.tsx`, `ProxyEdit.tsx`

### 后端实现

- **文件**：`internal/config/config.go`, `internal/config/watcher.go`
- **核心函数**：`ValidateConfigAndDetectLoop()`, `isLoopbackTarget()`
- **调用时机**：启动时、热重载时、API 请求时

### 性能影响

- **前端验证**：< 10ms，用户无感知
- **后端验证**：< 100ms，对启动和重载影响极小

## 相关文档

- [前端循环检测详细文档](../../FRONTEND_LOOP_DETECTION.md)
- [前端循环检测实现总结](../../FRONTEND_LOOP_DETECTION_SUMMARY.md)
- [后端循环检测实现](../../PROXY_LOOP_DETECTION.md)
- [循环检测架构设计](../../LOOP_DETECTION_ARCHITECTURE.md)
- [与 Nginx/Caddy 的对比](../../PROXY_LOOP_DETECTION_COMPARISON.md)

## 总结

✅ **双重保护**：前端 + 后端
✅ **即时反馈**：输入时立即检测
✅ **清晰提示**：明确说明问题和解决方案
✅ **安全可靠**：无法绕过后端验证
✅ **用户友好**：不影响正常配置流程

这个功能有效防止了因配置错误导致的系统资源耗尽问题，保障了 sslcat 的稳定运行。


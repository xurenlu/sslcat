# 代理循环检测功能实现总结

## 实现日期
2025-12-30

## 背景
在 shifen.de 服务器上发现严重的资源泄漏问题，根本原因是 `gg.some.im` 被配置为代理到自己（127.0.0.1:80），导致：
- Goroutine 泄漏：26,000+ (正常 31)
- 内存泄漏：3.9 GB (正常 100 MB)  
- CPU 飙升：41-43% (正常 < 5%)

## 实现内容

### 1. 核心功能

#### 文件修改
1. **`internal/config/config.go`**
   - 新增 `ValidateConfigWithLoopDetection()` 函数
   - 新增 `detectProxyLoop()` - 检测单后端循环
   - 新增 `detectBackendLoop()` - 检测负载均衡后端循环
   - 新增 `getListeningPorts()` - 获取 sslcat 监听端口
   - 新增 `isLocalhost()` - 判断是否本地地址
   - 新增 `containsPort()` - 端口列表检查
   - 在 `Load()` 函数中调用验证

2. **`internal/config/watcher.go`**
   - 修改 `validateConfig()` 委托给公共验证函数
   - 配置热重载时也会进行循环检测

#### 测试文件
3. **`internal/config/watcher_loop_test.go`** (新建)
   - `TestDetectProxyLoop` - 测试单后端循环检测
   - `TestDetectBackendLoop` - 测试负载均衡循环检测
   - `TestIsLocalhost` - 测试本地地址识别
   - `TestGetListeningPorts` - 测试端口列表获取
   - 所有测试 100% 通过

### 2. 检测逻辑

```
IF (后端地址是本地地址) AND (后端端口是 sslcat 监听端口)
THEN 拒绝配置并显示错误
```

#### 本地地址识别
- `localhost` (不区分大小写)
- `127.0.0.1`
- `127.x.x.x` (整个 127 网段)
- `::1` (IPv6 loopback)
- `0.0.0.0`
- `::`

#### 监听端口识别
- **标准模式**: 主端口 + 80 + 443
- **自定义模式**: 主端口 + 自定义端口

### 3. 错误提示

#### 单后端模式
```
FATAL: failed to load config: configuration validation failed: 
proxy rule 0 (gg.some.im): proxy loop detected: gg.some.im proxies 
to itself (127.0.0.1:80), this will cause infinite loop and resource exhaustion
```

#### 负载均衡模式
```
FATAL: failed to load config: configuration validation failed: 
proxy rule 0 (lb.example.com), backend 0: proxy loop detected: 
lb.example.com backend (localhost:80) points to sslcat itself, 
this will cause infinite loop
```

## 测试结果

### 单元测试
```bash
$ go test -v ./internal/config -run "TestDetect|TestIsLocalhost|TestGetListeningPorts"

=== RUN   TestDetectProxyLoop
=== RUN   TestDetectProxyLoop/循环检测_-_代理到自己的80端口
=== RUN   TestDetectProxyLoop/循环检测_-_代理到_localhost
=== RUN   TestDetectProxyLoop/循环检测_-_代理到_0.0.0.0
=== RUN   TestDetectProxyLoop/正常配置_-_代理到外部服务
=== RUN   TestDetectProxyLoop/正常配置_-_代理到本地不同端口
=== RUN   TestDetectProxyLoop/循环检测_-_127.x.x.x_网段
--- PASS: TestDetectProxyLoop (0.00s)

=== RUN   TestDetectBackendLoop
=== RUN   TestDetectBackendLoop/负载均衡循环检测_-_后端指向自己
=== RUN   TestDetectBackendLoop/负载均衡正常配置
--- PASS: TestDetectBackendLoop (0.00s)

=== RUN   TestIsLocalhost
--- PASS: TestIsLocalhost (0.00s)

=== RUN   TestGetListeningPorts
--- PASS: TestGetListeningPorts (0.00s)

PASS
ok      github.com/xurenlu/sslcat/internal/config      0.562s
```

### 集成测试

#### 测试 1: 错误配置被拒绝
```bash
$ ./sslcat --config test-loop-config.json

FATAL: failed to load config: configuration validation failed: 
proxy rule 0 (loop-test.example.com): proxy loop detected: 
loop-test.example.com proxies to itself (127.0.0.1:80), 
this will cause infinite loop and resource exhaustion
```
✅ **通过** - 正确拒绝了循环配置

#### 测试 2: 正确配置正常启动
```bash
$ ./sslcat --config test-valid-config.json

INFO Starting SSLcat v1.3.31-rc12
INFO Effective configuration loaded
INFO HTTPS server listening on 0.0.0.0:443
INFO HTTP redirect server listening on 0.0.0.0:80
```
✅ **通过** - 正确的配置正常启动

## 性能影响

- ✅ **零运行时开销** - 仅在启动和配置重载时执行
- ✅ **O(n) 时间复杂度** - n = 代理规则数量
- ✅ **可忽略的内存开销** - 临时数组和字符串比较
- ✅ **不影响请求处理** - 验证在服务启动前完成

## 文档

1. **`PROXY_LOOP_DETECTION.md`** - 完整的功能文档
   - 概述和背景
   - 检测规则详解
   - 配置示例
   - 故障排查指南
   - 最佳实践

2. **`SHIFEN_CPU_MEMORY_SPIKE_DIAGNOSIS.md`** - 问题诊断报告
   - 详细的问题分析
   - 根本原因
   - 解决方案
   - 修复步骤

3. **`fix-shifen-spike.sh`** - 紧急修复脚本
   - 封禁攻击 IP
   - 检查配置
   - 重启服务

## 部署建议

### 立即部署到生产环境
此功能应该立即部署到所有环境，因为：

1. **安全性提升** - 防止配置错误导致的系统崩溃
2. **零风险** - 仅在启动时执行，不影响运行时
3. **向后兼容** - 不影响正确的配置
4. **清晰的错误提示** - 帮助用户快速定位问题

### 部署步骤

```bash
# 1. 编译新版本
make docker-cgo-extract
cp build/sslcat-linux-amd64-cgo build/sslcat-linux-amd64

# 2. 部署到 shifen.de
bash deploy-to-s2.sh

# 3. 验证
ssh rocky@shifen.de "sudo systemctl status sslcat"
ssh rocky@shifen.de "ps aux | grep sslcat | grep -v grep"
```

### 回滚计划
如果出现问题，可以快速回滚：

```bash
# 恢复之前的版本
ssh rocky@shifen.de "sudo systemctl stop sslcat"
ssh rocky@shifen.de "sudo cp /opt/sslcat/sslcat.backup /opt/sslcat/sslcat"
ssh rocky@shifen.de "sudo systemctl start sslcat"
```

## 后续优化建议

### 1. 增强检测能力
- [ ] 检测间接循环（A -> B -> A）
- [ ] 检测域名解析后的循环
- [ ] 支持自定义排除规则

### 2. 配置验证工具
```bash
# 添加配置验证命令
sslcat --validate-config /path/to/config.json
```

### 3. 监控告警
- [ ] 添加 Prometheus 指标：`sslcat_config_validation_errors`
- [ ] 配置重载失败时发送告警

### 4. 文档完善
- [ ] 添加到官方文档网站
- [ ] 创建视频教程
- [ ] 添加常见问题 FAQ

## 相关 Issue/PR

- Issue: #XXX - "服务器 CPU 和内存突然飙升"
- PR: #XXX - "添加代理循环检测功能"

## 贡献者

- 实现: AI Assistant
- 测试: AI Assistant  
- 文档: AI Assistant
- 问题发现: 用户报告 (shifen.de 服务器)

## 参考资料

- Go 标准库文档: `net/http`
- 类似问题: Nginx 的 `proxy_pass` 循环检测
- 最佳实践: 微服务反向代理配置

---

**状态**: ✅ 已完成并测试  
**版本**: v1.3.31-rc12+  
**优先级**: 🔴 高 - 建议立即部署


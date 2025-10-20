# 配置热重载通知功能更新说明

## 更新日期
2024-01-15

## 功能概述

为 SSLcat 配置热重载功能添加了自动通知支持，当配置文件发生变更并成功/失败重载时，系统会自动通过配置的通知渠道（邮件、Webhook、Syslog、控制台）发送通知给管理员。

## 代码变更

### 1. 新增通知类型 (`internal/notification/notification.go`)

```go
// 新增两种通知类型
TypeConfigReloaded   NotificationType = "config_reloaded"    // 配置重载成功
TypeConfigReloadFail NotificationType = "config_reload_fail" // 配置重载失败
```

### 2. 新增通知方法 (`internal/notification/notification.go`)

#### SendConfigReloaded - 发送配置重载成功通知
```go
func (nm *NotificationManager) SendConfigReloaded(configFile string, duration time.Duration, changes []string) error
```

**参数**:
- `configFile`: 配置文件路径
- `duration`: 重载耗时
- `changes`: 变更内容列表

**通知内容**:
- **级别**: Info
- **标题**: "配置文件热重载成功"
- **详情**: 包含配置文件路径、耗时、变更内容、时间戳

#### SendConfigReloadFailed - 发送配置重载失败通知
```go
func (nm *NotificationManager) SendConfigReloadFailed(configFile string, reason string, errorDetails string) error
```

**参数**:
- `configFile`: 配置文件路径
- `reason`: 失败原因
- `errorDetails`: 错误详情

**通知内容**:
- **级别**: Error
- **标题**: "配置文件热重载失败"
- **详情**: 包含配置文件路径、失败原因、错误详情、处理建议、时间戳

### 3. 集成通知功能 (`internal/notification/integration.go`)

为 `NotificationIntegrator` 添加两个新方法：

```go
// SendConfigReloaded 发送配置重载成功通知
func (ni *NotificationIntegrator) SendConfigReloaded(configFile string, duration time.Duration, changes []string) error

// SendConfigReloadFailed 发送配置重载失败通知  
func (ni *NotificationIntegrator) SendConfigReloadFailed(configFile, reason, errorDetails string) error
```

### 4. 主程序集成 (`main.go`)

在配置热重载回调函数中集成通知功能：

```go
// 用于记录配置重载开始时间
var reloadStartTime time.Time

configWatcher.OnReloadStart(func() {
    log.Info("Configuration reload started")
    reloadStartTime = time.Now()
})

configWatcher.OnReloadSuccess(func(newConfig *config.Config) {
    duration := time.Since(reloadStartTime)
    log.Infof("Configuration reload completed successfully in %v", duration)
    
    // 更新配置
    cfg = newConfig
    webServer.UpdateConfig(newConfig)

    // 发送成功通知
    changes := []string{"配置文件已更新"}
    if err := notificationIntegrator.SendConfigReloaded(cfg.ConfigFile, duration, changes); err != nil {
        log.Warnf("Failed to send config reload notification: %v", err)
    }
})

configWatcher.OnReloadError(func(err error) {
    log.Errorf("Configuration reload failed: %v", err)
    
    // 发送失败通知
    if err := notificationIntegrator.SendConfigReloadFailed(
        cfg.ConfigFile,
        "配置验证或应用失败",
        err.Error(),
    ); err != nil {
        log.Warnf("Failed to send config reload failure notification: %v", err)
    }
})
```

## 使用场景

### 场景 1: 正常配置更新

1. **操作**: 管理员编辑 `sslcat.conf` 并保存
2. **系统行为**:
   - 自动检测文件变更（1秒防抖）
   - 验证并重载新配置
   - 记录重载耗时
   - 发送成功通知到所有启用的渠道
3. **通知内容**:
   ```
   标题: 配置文件热重载成功
   消息: 配置文件 /etc/sslcat/sslcat.conf 已成功热重载
   耗时: 15.2ms
   时间: 2024-01-15 14:30:25
   ```

### 场景 2: 配置错误

1. **操作**: 管理员编辑配置文件时引入 JSON 语法错误
2. **系统行为**:
   - 检测到文件变更
   - 尝试解析配置文件失败
   - 保持旧配置继续运行
   - 发送错误通知
3. **通知内容**:
   ```
   标题: 配置文件热重载失败
   消息: 配置文件 /etc/sslcat/sslcat.conf 重载失败: 配置验证或应用失败
   错误: invalid character '}' after object key
   建议: 请检查配置文件语法或查看日志获取更多信息
   时间: 2024-01-15 14:35:10
   ```

## 配置示例

要启用配置重载通知，需要在 `sslcat.conf` 中配置通知系统：

```json
{
  "notification": {
    "enabled": true,
    "channels": {
      "email": {
        "enabled": true,
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "username": "notifications@example.com",
        "password": "your_password",
        "from": "notifications@example.com",
        "to": ["admin@example.com"],
        "use_tls": true
      },
      "webhook": {
        "enabled": true,
        "url": "https://your-webhook-url.com/notifications",
        "headers": {
          "Authorization": "Bearer your_token"
        },
        "timeout": 30
      },
      "console": {
        "enabled": true
      }
    }
  }
}
```

## 测试方法

### 1. 测试成功通知

```bash
# 1. 启动服务
./sslcat --config sslcat.conf

# 2. 修改配置文件（添加或修改一个代理规则）
nano sslcat.conf

# 3. 保存后等待 1-2 秒

# 4. 查看日志
tail -f /var/log/sslcat.log | grep -E "(reload|notification)"

# 5. 检查邮箱或 Webhook 是否收到通知
```

### 2. 测试失败通知

```bash
# 1. 修改配置文件引入语法错误
nano sslcat.conf
# 故意删除一个逗号或引号

# 2. 保存后等待 1-2 秒

# 3. 查看日志（应该看到错误但服务继续运行）
tail -f /var/log/sslcat.log | grep -E "(reload|error|notification)"

# 4. 检查是否收到错误通知

# 5. 修复配置文件恢复正常
```

## 日志示例

### 成功重载日志
```
INFO Configuration changed, starting hot reload...
INFO Configuration reload started
INFO Configuration reload completed successfully in 15.2ms
INFO 通知已发送: config_reloaded - 配置文件热重载成功
```

### 失败重载日志
```
INFO Configuration changed, starting hot reload...
INFO Configuration reload started
ERROR Failed to load new config: invalid character '}' after object key
ERROR Configuration reload failed: failed to load new config
INFO 通知已发送: config_reload_fail - 配置文件热重载失败
```

## 注意事项

### 1. 通知频率限制
- 通知系统内置速率限制，防止过于频繁的通知
- 如果短时间内多次修改配置，可能只发送部分通知

### 2. 配置防抖
- 文件变更后会等待 1 秒（防抖间隔）再触发重载
- 避免文件保存时的多次写入操作触发多次重载

### 3. 错误容忍
- 配置重载失败时，系统保持旧配置继续运行
- 不会因为配置错误导致服务中断

### 4. 需要重启的配置项
- 以下配置变更仍然需要重启服务：
  - 服务器端口
  - SSL证书目录
  - 管理面板前缀
  - 日志级别

## 技术细节

### 通知发送流程

```
配置文件变更
    ↓
fsnotify 检测到 Write/Create 事件
    ↓
防抖处理（等待 1 秒）
    ↓
记录开始时间
    ↓
计算配置文件哈希
    ↓
加载新配置文件
    ↓
验证配置格式和逻辑
    ↓
┌─────────────────┐
│  验证是否通过？  │
└─────────────────┘
   ↓ Yes        ↓ No
应用新配置    保持旧配置
   ↓              ↓
计算耗时      记录错误
   ↓              ↓
发送成功通知  发送失败通知
   ↓              ↓
记录INFO日志  记录ERROR日志
```

### 性能影响

- **通知发送**: 异步执行，不阻塞配置重载流程
- **额外开销**: < 1ms（通知发送在单独的 goroutine 中）
- **内存占用**: 忽略不计（只增加了通知对象）
- **网络开销**: 取决于启用的通知渠道

## 后续优化建议

### 1. 变更差异检测
当前实现中，`changes` 字段只包含简单的"配置文件已更新"信息。可以增强为：
- 检测具体变更的配置项
- 对比新旧配置的差异
- 在通知中展示具体变更内容

### 2. 通知模板定制
允许用户自定义通知内容模板：
- 邮件模板
- Webhook 数据格式
- 通知标题和内容格式

### 3. 通知筛选
允许用户配置哪些类型的配置变更需要通知：
- 只通知重要配置变更
- 过滤特定配置项的变更
- 基于变更影响范围决定是否通知

### 4. 集成更多通知渠道
- 企业微信
- 钉钉
- Telegram
- Slack
- Discord

## 相关文件

- `internal/notification/notification.go` - 通知类型和方法定义
- `internal/notification/integration.go` - 通知集成器
- `main.go` - 主程序配置重载回调
- `internal/config/watcher.go` - 配置文件监听器
- `CONFIG_RELOAD_NOTIFICATION.md` - 完整使用文档

## 版本信息

- **功能版本**: v1.3.12
- **更新日期**: 2024-01-15
- **兼容性**: 向后兼容，现有配置无需修改
- **依赖**: 需要通知系统配置（可选）

## 总结

此次更新为 SSLcat 的配置热重载功能添加了完整的通知支持，使管理员能够实时掌握配置变更情况，及时发现和处理配置问题。通知功能与现有的通知系统完全集成，支持多种通知渠道，提升了系统的可观测性和运维效率。


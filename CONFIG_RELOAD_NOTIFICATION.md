# 配置热重载通知功能

## 概述

SSLcat 配置热重载功能现已支持自动通知，当配置文件发生变更并成功/失败重载时，系统会通过配置的通知渠道发送通知给管理员。

## 功能特性

### ✅ **自动通知触发**
- 配置文件内容变更时自动检测
- 重载成功时发送成功通知
- 重载失败时发送错误通知
- 包含详细的重载信息和耗时

### 📊 **通知内容**

#### 重载成功通知
- **通知类型**: `config_reloaded`
- **通知级别**: Info
- **标题**: "配置文件热重载成功"
- **详细信息**:
  - 配置文件路径
  - 重载耗时
  - 变更内容列表
  - 时间戳

#### 重载失败通知
- **通知类型**: `config_reload_fail`
- **通知级别**: Error
- **标题**: "配置文件热重载失败"
- **详细信息**:
  - 配置文件路径
  - 失败原因
  - 错误详情
  - 时间戳
  - 处理建议

### 📨 **通知渠道**

配置重载通知会通过以下已启用的渠道发送：

1. **邮件通知**
   - 发送到配置的管理员邮箱
   - 包含详细的重载信息

2. **Webhook**
   - 发送 JSON 格式的通知数据
   - 可集成到第三方监控系统

3. **系统日志 (Syslog)**
   - 记录到系统日志服务
   - 便于集中日志管理

4. **控制台输出**
   - 实时输出到服务器控制台
   - 便于调试和监控

## 配置示例

在 `sslcat.conf` 中配置通知系统：

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
      },
      "syslog": {
        "enabled": false,
        "address": "localhost:514",
        "network": "udp"
      }
    }
  }
}
```

## 使用示例

### 场景 1: 正常配置更新

1. 编辑配置文件：
```bash
nano /etc/sslcat/sslcat.conf
```

2. 保存后，系统自动检测并重载

3. 管理员收到邮件通知：
```
标题：配置文件热重载成功
内容：配置文件 /etc/sslcat/sslcat.conf 已成功热重载
耗时：15.2ms
变更：配置文件已更新
时间：2024-01-15 14:30:25
```

### 场景 2: 配置错误

1. 编辑配置文件时引入 JSON 语法错误

2. 系统检测到错误，保持旧配置继续运行

3. 管理员立即收到错误通知：
```
标题：配置文件热重载失败
内容：配置文件 /etc/sslcat/sslcat.conf 重载失败: 配置验证或应用失败
错误详情：invalid character '}' after object key
建议：请检查配置文件语法或查看日志获取更多信息
时间：2024-01-15 14:35:10
```

## Webhook 通知格式

### 成功通知 JSON 格式

```json
{
  "id": "notif_1234567890",
  "type": "config_reloaded",
  "level": "info",
  "title": "配置文件热重载成功",
  "message": "配置文件 /etc/sslcat/sslcat.conf 已成功热重载",
  "details": {
    "config_file": "/etc/sslcat/sslcat.conf",
    "duration": "15.2ms",
    "changes": ["配置文件已更新"],
    "timestamp": "2024-01-15 14:30:25"
  },
  "timestamp": "2024-01-15T14:30:25Z",
  "source": "sslcat"
}
```

### 失败通知 JSON 格式

```json
{
  "id": "notif_1234567891",
  "type": "config_reload_fail",
  "level": "error",
  "title": "配置文件热重载失败",
  "message": "配置文件 /etc/sslcat/sslcat.conf 重载失败: 配置验证或应用失败",
  "details": {
    "config_file": "/etc/sslcat/sslcat.conf",
    "reason": "配置验证或应用失败",
    "error_details": "invalid character '}' after object key",
    "timestamp": "2024-01-15 14:35:10",
    "suggestion": "请检查配置文件语法或查看日志获取更多信息"
  },
  "timestamp": "2024-01-15T14:35:10Z",
  "source": "sslcat"
}
```

## 日志输出

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

## 最佳实践

### 1. 配置备份
```bash
# 修改配置前先备份
cp /etc/sslcat/sslcat.conf /etc/sslcat/sslcat.conf.backup.$(date +%Y%m%d_%H%M%S)
```

### 2. 语法验证
```bash
# 修改后先验证 JSON 语法
python -m json.tool /etc/sslcat/sslcat.conf
```

### 3. 监控邮箱
- 确保配置的通知邮箱能正常接收
- 设置邮件过滤规则，重要通知不被误判为垃圾邮件

### 4. Webhook 集成
- 将通知集成到团队协作工具（如钉钉、企业微信、Slack）
- 设置告警规则，重载失败时触发紧急通知

### 5. 配置测试环境
- 在测试环境先验证配置变更
- 确认无误后再应用到生产环境

## 故障排除

### 通知未发送

1. **检查通知系统是否启用**
```bash
# 查看配置文件中 notification.enabled 是否为 true
grep -A 2 '"notification"' sslcat.conf
```

2. **检查通知渠道配置**
```bash
# 验证邮件/Webhook配置是否正确
# 查看日志确认是否有发送失败的错误
tail -f /var/log/sslcat.log | grep -i notification
```

3. **测试通知渠道**
```bash
# 通过管理面板测试通知渠道
curl -X POST \
  -H "Cookie: session=xxx" \
  http://localhost/sslcat-panel/api/notification/test
```

### 重复通知

如果收到重复的配置重载通知：

1. 检查是否有程序在频繁修改配置文件
2. 查看配置文件防抖间隔设置（默认 1 秒）
3. 通知系统已内置速率限制，防止过于频繁的通知

### 邮件发送失败

1. 检查 SMTP 服务器配置
2. 验证邮箱用户名和密码
3. 确认 SMTP 端口和 TLS 设置
4. 检查网络连接和防火墙规则

## 相关文档

- [配置热重载指南](CONFIG_HOT_RELOAD_GUIDE.md)
- [通知系统配置](NOTIFICATION_SYSTEM.md)
- [API 文档](API.md)

## 技术实现

### 代码结构

1. **通知类型定义** (`internal/notification/notification.go`)
   - `TypeConfigReloaded`: 配置重载成功
   - `TypeConfigReloadFail`: 配置重载失败

2. **通知方法** (`internal/notification/notification.go`)
   - `SendConfigReloaded()`: 发送成功通知
   - `SendConfigReloadFailed()`: 发送失败通知

3. **集成点** (`main.go`)
   - `OnReloadSuccess` 回调：重载成功时触发
   - `OnReloadError` 回调：重载失败时触发

### 工作流程

```
配置文件变更
    ↓
文件系统监听器检测到变更
    ↓
防抖处理（等待 1 秒）
    ↓
计算配置文件哈希
    ↓
加载和验证新配置
    ↓
┌─────────────────────┐
│  配置重载成功？      │
└─────────────────────┘
   ↓ Yes          ↓ No
应用新配置    保持旧配置
   ↓               ↓
发送成功通知  发送失败通知
   ↓               ↓
更新系统状态   记录错误日志
```

## 更新日志

- **v1.3.12** (2024-01-15)
  - ✨ 新增配置热重载通知功能
  - 📧 支持邮件、Webhook、Syslog、控制台通知
  - 📊 包含详细的重载信息和耗时统计
  - ⚡ 自动速率限制，防止通知泛滥

---

通过配置热重载通知功能，管理员可以实时掌握系统配置变更情况，及时发现和处理配置问题，提升运维效率和系统可靠性。


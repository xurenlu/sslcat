# Git Deploy 部署通知集成功能

## 功能概述

SSLcat 现在完全集成了部署通知系统，在部署出现问题时自动通过邮件、Webhook、Syslog 等渠道发送通知。

##  支持的通知类型

### 1. 部署卡住 (Deploy Stuck)
- **触发条件**: 连续 30 秒没有新日志输出
- **通知级别**: Warning ⚠️
- **通知内容**:
  - 应用名称
  - Commit SHA
  - 空闲持续时间
  - 最后的日志内容
  - 建议操作

### 2. 部署超时 (Deploy Timeout)
- **触发条件**: 总部署时间超过 10 分钟
- **通知级别**: Warning ⚠️
- **通知内容**:
  - 应用名称
  - Commit SHA
  - 已用时间
  - 提示仍在后台运行

### 3. 部署失败 (Deploy Failed)
- **触发条件**: 构建或部署过程中出错
- **通知级别**: Error ❌
- **通知内容**:
  - 应用名称
  - Commit SHA 和消息
  - 失败原因
  - 详细错误信息

### 4. 部署成功 (Deploy Success)
- **触发条件**: 部署正常完成
- **通知级别**: Info ℹ️
- **通知内容**:
  - 应用名称
  - Commit SHA 和消息
  - 部署域名
  - 部署耗时

## 工作流程

```
Git Push
    ↓
post-receive hook 执行
    ↓
监控部署日志
    ↓
检测到异常? → 是 → 调用内部通知 API
    |                      ↓
    |             NotificationManager
    |                      ↓
    |             发送到配置的渠道
    ↓                      ↓
继续监控    → 邮件/Webhook/Syslog
```

## 配置通知渠道

### ⭐ 推荐方式：通过 Web 界面配置

1. 登录 SSLcat 管理面板
2. 进入 **设置** → **通知**
3. 在界面上配置各个渠道：
   - 📧 **邮件通知**: SMTP 服务器、端口、认证信息
   - 🔗 **Webhook**: Slack/企业微信/钉钉等 URL
   - 📝 **Syslog**: 服务器地址和端口
   - 💻 **控制台**: 开关按钮

配置会自动保存到 `sslcat.conf`，无需手动编辑文件。

### 方式二：直接编辑配置文件

在 `sslcat.conf` 中添加或修改 `notification` 部分：

```json
{
  "notification": {
    "enabled": true,
    "channels": {
      "email": {
        "enabled": true,
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "username": "your-email@gmail.com",
        "password": "your-app-password",
        "from": "sslcat@yourdomain.com",
        "to": ["admin@yourdomain.com", "dev@yourdomain.com"],
        "use_tls": true
      },
      "webhook": {
        "enabled": true,
        "url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
        "timeout": 10
      },
      "syslog": {
        "enabled": true,
        "address": "localhost:514"
      },
      "console": {
        "enabled": true
      }
    }
  }
}
```

重启 SSLcat 后配置生效。

### 方式三：环境变量（向后兼容）

⚠️ 仅在配置文件中未启用通知时使用（不推荐）：

```bash
export NOTIFICATION_SMTP_HOST="smtp.gmail.com"
export NOTIFICATION_SMTP_PORT="587"
export NOTIFICATION_SMTP_USERNAME="your-email@gmail.com"
export NOTIFICATION_SMTP_PASSWORD="your-app-password"
export NOTIFICATION_SMTP_FROM="sslcat@yourdomain.com"
export NOTIFICATION_SMTP_TO="admin@yourdomain.com,dev@yourdomain.com"
export NOTIFICATION_SMTP_TLS="true"
export WITHSSL_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
export WITHSSL_SYSLOG_ADDR="localhost:514"
```

## 通知消息格式

### 邮件通知示例

**主题**: `[SSLcat] 应用 myapp 部署可能卡住`

**正文**:
```
应用: myapp
类型: 部署卡住
级别: Warning

应用 myapp 部署 30s 内没有新日志输出，可能已卡住

详细信息:
- Commit: a3f2c1b
- 空闲时间: 30s
- 建议: 请检查构建进程是否卡住，可能需要手动介入

时间: 2024-10-04 16:30:45
```

### Webhook (Slack) 通知示例

```json
{
  "text": "⚠️ 部署告警",
  "attachments": [
    {
      "color": "warning",
      "title": "应用 myapp 部署可能卡住",
      "fields": [
        {
          "title": "应用",
          "value": "myapp",
          "short": true
        },
        {
          "title": "Commit",
          "value": "a3f2c1b",
          "short": true
        },
        {
          "title": "空闲时间",
          "value": "30s",
          "short": true
        },
        {
          "title": "建议",
          "value": "请检查构建进程是否卡住，可能需要手动介入",
          "short": false
        }
      ],
      "footer": "SSLcat Deploy Monitor",
      "ts": 1728052245
    }
  ]
}
```

## 实现细节

### 1. 内部 API 端点

```
POST /sslcat-panel2/api/internal/deploy-notification
```

**请求体**:
```json
{
  "type": "stuck|timeout|failed|success",
  "app_name": "myapp",
  "commit_sha": "a3f2c1b",
  "commit_msg": "Add new feature",
  "idle_duration": "30s",    // for stuck
  "duration": "600s",         // for timeout
  "reason": "Build failed",   // for failed
  "error_details": "...",     // for failed
  "domain": "myapp.com"       // for success
}
```

### 2. Hook 集成

Post-receive hook 在检测到异常时会自动调用此 API：

```bash
# 部署卡住时
curl -s -X POST "http://localhost:9942/sslcat-panel2/api/internal/deploy-notification" \
  -H "Content-Type: application/json" \
  -d '{"type":"stuck","app_name":"myapp","commit_sha":"a3f2c1b","idle_duration":"30s"}'

# 部署超时时
curl -s -X POST "http://localhost:9942/sslcat-panel2/api/internal/deploy-notification" \
  -H "Content-Type: application/json" \
  -d '{"type":"timeout","app_name":"myapp","commit_sha":"a3f2c1b","duration":"600s"}'
```

### 3. 通知管理器方法

在 `internal/notification/notification.go` 中新增：

- `SendDeploySuccess()`
- `SendDeployFailed()`
- `SendDeployTimeout()`
- `SendDeployStuck()`

### 4. GitServer 集成

在 `internal/runner/git_server.go` 中：

- 添加了 `notificationManager` 字段
- 实现了 `SendDeployNotification()` 方法
- 在 `NewGitServer()` 中初始化通知管理器

## 通知速率限制

为避免通知轰炸，系统内置了速率限制：

- 相同类型的通知在短时间内只发送一次
- 可通过配置调整限制策略

## 测试通知

### 通过 Web 界面测试

访问管理面板 → 设置 → 通知 → 测试通知

### 通过 API 测试

```bash
curl -X POST http://localhost:9942/sslcat-panel2/api/notifications/test \
  -u admin:password \
  -H "Content-Type: application/json"
```

### 手动触发测试通知

```bash
curl -X POST http://localhost:9942/sslcat-panel2/api/internal/deploy-notification \
  -H "Content-Type: application/json" \
  -d '{
    "type": "stuck",
    "app_name": "test-app",
    "commit_sha": "test123",
    "idle_duration": "30s"
  }'
```

## 常见平台集成

### Slack

1. 创建 Incoming Webhook: https://api.slack.com/messaging/webhooks
2. 配置 Webhook URL

```bash
export WITHSSL_WEBHOOK_URL="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX"
```

### 企业微信

配置企业微信 Webhook:

```bash
export WITHSSL_WEBHOOK_URL="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=YOUR-KEY"
```

### 钉钉

配置钉钉机器人 Webhook:

```bash
export WITHSSL_WEBHOOK_URL="https://oapi.dingtalk.com/robot/send?access_token=YOUR-TOKEN"
```

### Telegram

可通过 Bot API 实现（需自定义适配器）

### Discord

配置 Discord Webhook:

```bash
export WITHSSL_WEBHOOK_URL="https://discord.com/api/webhooks/YOUR/WEBHOOK/URL"
```

## 通知历史

所有发送的通知都会保存在历史记录中：

```bash
# 查看通知历史
curl http://localhost:9942/sslcat-panel2/api/notifications/history \
  -u admin:password
```

## 故障排查

### 1. 没有收到通知

**检查列表**:
- [ ] 确认通知渠道已启用
- [ ] 检查配置是否正确（邮箱、Webhook URL 等）
- [ ] 查看 sslcat 日志：`journalctl -u sslcat -f | grep notification`
- [ ] 测试通知功能是否正常
- [ ] 检查网络连接（如邮件服务器、Webhook 端点）

### 2. 邮件发送失败

常见原因：
- SMTP 密码错误（Gmail 需使用应用专用密码）
- 端口被防火墙拦截
- TLS/SSL 配置不正确

### 3. Webhook 调用失败

检查：
- URL 是否正确
- 超时设置是否合理
- 目标服务是否可达

### 4. 通知太多

调整速率限制或只启用特定级别的通知（Error, Critical）

## 最佳实践

### 1. 分级通知

根据严重程度配置不同的接收人：

```json
{
  "notification": {
    "routes": [
      {
        "level": "critical",
        "channels": ["email", "webhook"],
        "recipients": ["oncall@company.com"]
      },
      {
        "level": "error",
        "channels": ["email"],
        "recipients": ["dev-team@company.com"]
      },
      {
        "level": "warning",
        "channels": ["webhook"],
        "recipients": []
      }
    ]
  }
}
```

### 2. 通知内容自定义

可以通过模板自定义通知格式。

### 3. 集成监控系统

将通知发送到 Prometheus Alertmanager、Grafana 等监控系统。

### 4. 静默时段

配置工作时间外的静默策略，避免夜间打扰。

## 性能影响

- 通知发送是异步的，不影响部署流程
- 失败的通知不会中断部署
- 每次部署最多触发 2-3 个通知（开始、完成/失败、异常）

## 安全考虑

- 内部 API endpoint 只监听 localhost
- Webhook URL 中的 token 应妥善保管
- 邮件密码建议使用应用专用密码，而非主密码
- 可以配置 IP 白名单限制 API 访问

## 未来增强

- [ ] 支持通知模板自定义
- [ ] 添加通知聚合功能
- [ ] 支持更多通知渠道（PagerDuty、Opsgenie 等）
- [ ] 添加通知统计和分析
- [ ] 支持基于标签的通知路由
- [ ] 添加通知重试机制
- [ ] 支持通知确认和响应

## 相关文档

- [Git Push 实时部署日志](GIT_PUSH_REALTIME_DEPLOY.md)
- [通知系统 API 文档](API.md#notifications)
- [配置文件说明](CONFIG_FILES.md)

## 贡献

欢迎为通知系统贡献新的渠道适配器或功能改进！


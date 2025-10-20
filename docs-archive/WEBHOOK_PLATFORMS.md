# Webhook 平台支持

SSLcat 的 Webhook 通知系统现在支持自动识别和适配多种主流平台的消息格式。

## 支持的平台

### 1. 企业微信 (WeChat Work)
- **检测URL**: `qyapi.weixin.qq.com` 或 `weixin.qq.com`
- **格式**: Markdown 格式消息
- **示例URL**: `https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx`

### 2. 飞书 (Feishu/Lark)
- **检测URL**: `open.feishu.cn` 或 `feishu.cn`
- **格式**: 文本消息格式
- **示例URL**: `https://open.feishu.cn/open-apis/bot/v2/hook/xxx`

### 3. 钉钉 (DingTalk)
- **检测URL**: `oapi.dingtalk.com` 或 `dingtalk.com`
- **格式**: Markdown 格式消息
- **示例URL**: `https://oapi.dingtalk.com/robot/send?access_token=xxx`

### 4. Slack
- **检测URL**: `hooks.slack.com` 或 `slack.com`
- **格式**: 富文本附件格式
- **示例URL**: `https://hooks.slack.com/services/xxx`

### 5. Discord
- **检测URL**: `discord.com` 或 `discordapp.com`
- **格式**: Embed 格式消息
- **示例URL**: `https://discord.com/api/webhooks/xxx`

### 6. Telegram
- **检测URL**: `api.telegram.org` 或 `telegram.org`
- **格式**: Markdown 格式消息
- **示例URL**: `https://api.telegram.org/bot<token>/sendMessage`

### 7. 通用格式 (Generic)
- **检测**: 其他所有URL
- **格式**: 标准JSON格式
- **示例URL**: `https://your-custom-webhook.com/notify`

## 自动格式转换

系统会根据Webhook URL自动检测目标平台，并转换消息格式：

### 企业微信格式示例
```json
{
  "msgtype": "markdown",
  "markdown": {
    "content": "**SSL证书即将过期**\n\n域名 example.com 的SSL证书将在7天后过期\n\n**级别**: warning\n**时间**: 2024-01-15 10:30:00\n**来源**: sslcat"
  }
}
```

### 飞书格式示例
```json
{
  "msg_type": "text",
  "content": {
    "text": "**SSL证书即将过期**\n\n域名 example.com 的SSL证书将在7天后过期\n\n**级别**: warning\n**时间**: 2024-01-15 10:30:00\n**来源**: sslcat"
  }
}
```

### Slack格式示例
```json
{
  "attachments": [
    {
      "color": "warning",
      "title": "SSL证书即将过期",
      "text": "域名 example.com 的SSL证书将在7天后过期",
      "fields": [
        {
          "title": "级别",
          "value": "warning",
          "short": true
        },
        {
          "title": "时间",
          "value": "2024-01-15 10:30:00",
          "short": true
        }
      ],
      "timestamp": 1705294200,
      "footer": "SSLcat 通知系统"
    }
  ]
}
```

## 配置方法

### 1. 通过配置文件
```json
{
  "notifications": {
    "enabled": true,
    "channels": {
      "webhook": {
        "enabled": true,
        "url": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=your-key",
        "headers": {
          "Authorization": "Bearer your-token"
        },
        "timeout": 10
      }
    }
  }
}
```

### 2. 通过环境变量
```bash
export NOTIFICATION_WEBHOOK_URL="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=your-key"
export NOTIFICATION_WEBHOOK_HEADERS="Authorization:Bearer your-token"
```

### 3. 通过管理界面
在SSLcat管理面板的"通知设置"中配置Webhook URL，系统会自动检测平台类型。

## 自定义头部支持

所有平台都支持自定义HTTP头部，可以用于：
- 身份验证 (Authorization, X-API-Key等)
- 自定义标识 (X-Source, X-Environment等)
- 平台特定头部

## 平台检测逻辑

系统通过URL域名自动检测平台：
1. 企业微信: `qyapi.weixin.qq.com`, `weixin.qq.com`
2. 飞书: `open.feishu.cn`, `feishu.cn`
3. 钉钉: `oapi.dingtalk.com`, `dingtalk.com`
4. Slack: `hooks.slack.com`, `slack.com`
5. Discord: `discord.com`, `discordapp.com`
6. Telegram: `api.telegram.org`, `telegram.org`
7. 其他: 通用JSON格式

## 消息格式特性

### 企业微信/钉钉
- 支持Markdown格式
- 自动换行和格式化
- 支持粗体、斜体等样式

### 飞书
- 支持文本格式
- 自动换行
- 简洁的消息结构

### Slack
- 富文本附件格式
- 颜色编码 (绿色=正常, 橙色=警告, 红色=错误)
- 字段化信息展示

### Discord
- Embed格式消息
- 颜色编码
- 时间戳支持

### Telegram
- Markdown格式
- 支持粗体、斜体
- 简洁的消息结构

## 故障排除

### 1. 平台检测失败
如果URL不在支持的域名列表中，系统会使用通用JSON格式。

### 2. 消息格式错误
检查目标平台的API文档，确保URL和认证信息正确。

### 3. 自定义头部
某些平台可能需要特定的认证头部，在配置中添加相应的头部信息。

## 扩展支持

如需支持新的平台，可以：
1. 在 `platform_adapters.go` 中添加新的适配器
2. 在 `DetectPlatform` 函数中添加URL检测逻辑
3. 实现 `PlatformAdapter` 接口

## 测试方法

可以使用以下命令测试Webhook通知：
```bash
# 发送测试通知
curl -X POST "http://localhost:80/api/notifications/test" \
  -H "Content-Type: application/json" \
  -d '{"webhook_url": "https://your-webhook-url"}'
```

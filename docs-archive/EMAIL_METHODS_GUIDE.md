# SSLcat 多邮件发送方式指南

## 概述

SSLcat 现在支持多种邮件发送方式，用户可以根据自己的需求和环境选择最适合的邮件发送方法。

## 支持的邮件发送方式

### 1. SMTP 服务器 (默认)
传统的 SMTP 服务器发送方式，适用于大多数邮件服务商。

**配置示例：**
```toml
[notification.email]
method = "smtp"
smtp_host = "smtp.gmail.com"
smtp_port = 587
username = "your-email@gmail.com"
password = "your-app-password"
from = "noreply@example.com"
to = ["admin@example.com", "support@example.com"]
use_tls = true
```

**适用场景：**
- Gmail、Outlook、企业邮箱等传统邮件服务
- 需要自定义 SMTP 服务器的情况

### 2. 系统 Sendmail
使用系统自带的 sendmail 命令发送邮件。

**配置示例：**
```toml
[notification.email]
method = "sendmail"
sendmail_command = "/usr/sbin/sendmail"
sendmail_args = "-t"
from = "noreply@example.com"
to = ["admin@example.com", "support@example.com"]
```

**适用场景：**
- 服务器已配置邮件系统
- 需要通过系统邮件服务发送
- 企业内部邮件系统

### 3. Resend 服务
现代化的邮件发送服务，提供简洁的 API。

**配置示例：**
```toml
[notification.email]
method = "resend"
resend_api_key = "re_xxxxxxxxxx"
resend_from = "noreply@example.com"
resend_to = "admin@example.com,support@example.com"
```

**适用场景：**
- 需要高送达率的应用
- 现代化的邮件发送需求
- 开发者友好的邮件服务

### 4. Mailgun 服务
专业的邮件发送服务，提供强大的分析功能。

**配置示例：**
```toml
[notification.email]
method = "mailgun"
mailgun_api_key = "key-xxxxxxxxxx"
mailgun_domain = "mg.example.com"
mailgun_from = "noreply@example.com"
mailgun_to = "admin@example.com,support@example.com"
```

**适用场景：**
- 需要邮件分析和统计
- 大量邮件发送需求
- 企业级邮件服务

### 5. SendGrid 服务
Twilio 旗下的邮件发送服务，提供全球化的邮件投递。

**配置示例：**
```toml
[notification.email]
method = "sendgrid"
sendgrid_api_key = "SG.xxxxxxxxxx"
sendgrid_from = "noreply@example.com"
sendgrid_to = "admin@example.com,support@example.com"
```

**适用场景：**
- 国际化应用
- 需要全球邮件投递
- 高可靠性要求

## 前端配置界面

在 SSLcat 管理面板的系统设置页面中，现在提供了邮件发送方式选择器：

1. **邮件发送方式选择**：下拉菜单选择发送方式
2. **动态配置表单**：根据选择的发送方式显示相应的配置字段
3. **实时验证**：配置字段会根据选择的方式动态显示/隐藏

## 配置步骤

### 1. 选择邮件发送方式
在系统设置页面的"邮件通知"部分，选择适合的邮件发送方式。

### 2. 填写配置信息
根据选择的发送方式，填写相应的配置信息：

- **SMTP**：服务器地址、端口、用户名、密码等
- **Sendmail**：命令路径、参数等
- **Resend**：API Key、发件人、收件人等
- **Mailgun**：API Key、域名、发件人、收件人等
- **SendGrid**：API Key、发件人、收件人等

### 3. 测试配置
保存配置后，系统会自动验证配置的完整性，并在日志中显示验证结果。

## 最佳实践

### 1. 选择建议
- **开发环境**：使用 SMTP 或 Sendmail
- **生产环境**：推荐使用 Resend、Mailgun 或 SendGrid
- **企业环境**：根据现有邮件基础设施选择

### 2. 安全考虑
- API Key 和密码等敏感信息会加密存储
- 建议使用专用的邮件发送账户
- 定期轮换 API Key 和密码

### 3. 监控和日志
- 所有邮件发送都会记录在系统日志中
- 支持邮件发送状态监控
- 失败重试机制

## 故障排除

### 常见问题

1. **SMTP 连接失败**
   - 检查服务器地址和端口
   - 验证用户名和密码
   - 确认 TLS 设置

2. **API 服务错误**
   - 验证 API Key 是否正确
   - 检查域名配置
   - 确认账户状态

3. **Sendmail 执行失败**
   - 确认 sendmail 命令路径
   - 检查系统权限
   - 验证参数设置

### 日志查看
```bash
# 查看邮件发送日志
tail -f /var/log/sslcat/notification.log

# 查看系统日志
journalctl -u sslcat -f
```

## 更新日志

### v1.3.15-rc1
- ✅ 新增多种邮件发送方式支持
- ✅ 前端设置页面优化
- ✅ 后端邮件发送逻辑重构
- ✅ 国际化支持完善
- ✅ 配置验证和错误处理

## 技术支持

如有问题，请查看：
- 系统日志文件
- 配置验证结果
- 邮件服务商文档

或联系技术支持团队。

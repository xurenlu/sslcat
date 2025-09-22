#!/bin/bash

# 通知系统测试脚本
# 此脚本展示了如何配置SSLcat的通知系统

echo "=== SSLcat 通知系统配置指南 ==="

echo "通知配置已集成到主配置文件 sslcat.conf 中。"
echo ""
echo "配置方法1: 修改 sslcat.conf 文件（推荐）"
echo "在您的 sslcat.conf 文件中添加以下通知配置部分："
echo ""
cat << 'EOF'
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
        "from": "your-email@gmail.com",
        "to": ["admin@example.com"],
        "use_tls": true
      },
      "webhook": {
        "enabled": false,
        "url": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
        "headers": {
          "Authorization": "Bearer your-token"
        },
        "timeout": 10
      },
      "syslog": {
        "enabled": false,
        "address": "localhost:514",
        "network": "udp"
      },
      "console": {
        "enabled": true
      }
    }
  }
}
EOF

echo ""
echo "配置方法2: 使用环境变量（后备方案）"
echo "如果配置文件中没有通知配置，系统会尝试从环境变量读取："

# 邮件通知配置（请修改为您的实际邮件设置）
export NOTIFICATION_SMTP_HOST="smtp.gmail.com"
export NOTIFICATION_SMTP_PORT="587"
export NOTIFICATION_SMTP_USERNAME="your-email@gmail.com"
export NOTIFICATION_SMTP_PASSWORD="your-app-password"
export NOTIFICATION_SMTP_FROM="your-email@gmail.com"
export NOTIFICATION_SMTP_TO="admin@example.com,support@example.com"
export NOTIFICATION_SMTP_TLS="true"

# Webhook通知配置（可选）
# export NOTIFICATION_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
# export NOTIFICATION_WEBHOOK_HEADERS="Content-Type:application/json,Authorization:Bearer your-token"

# 系统日志通知配置（可选）
# export NOTIFICATION_SYSLOG_ENABLED="true"
# export NOTIFICATION_SYSLOG_ADDR="localhost:514"

echo "环境变量已设置为示例值。"
echo ""
echo "支持的通知类型："
echo "- DDoS攻击检测"
echo "- SSL证书即将过期 (15天、7天、3天前通知)"
echo "- SSL证书申请失败"
echo "- 系统启动/关闭"
echo "- 安全警报"
echo "- 用户操作"
echo ""
echo "通知渠道："
echo "- 📧 邮件通知 (配置SMTP)"
echo "- 🔗 Webhook通知 (Slack, Discord等)"
echo "- 📝 系统日志通知"
echo "- 🖥️ 控制台输出 (默认启用)"
echo ""
echo "访问管理面板的通知页面查看通知历史和发送测试通知："
echo "https://your-domain.com/sslcat-panel/notifications"

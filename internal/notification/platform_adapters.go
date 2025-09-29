package notification

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// PlatformType 平台类型
type PlatformType string

const (
	PlatformGeneric  PlatformType = "generic"  // 通用格式
	PlatformWeChat   PlatformType = "wechat"   // 企业微信
	PlatformFeishu   PlatformType = "feishu"   // 飞书
	PlatformDingTalk PlatformType = "dingtalk" // 钉钉
	PlatformSlack    PlatformType = "slack"    // Slack
	PlatformDiscord  PlatformType = "discord"  // Discord
	PlatformTelegram PlatformType = "telegram" // Telegram
)

// PlatformAdapter 平台适配器接口
type PlatformAdapter interface {
	Adapt(notification *Notification) ([]byte, error)
	GetContentType() string
	GetHeaders() map[string]string
}

// GenericAdapter 通用适配器
type GenericAdapter struct{}

func (g *GenericAdapter) Adapt(notification *Notification) ([]byte, error) {
	payload := map[string]any{
		"id":        notification.ID,
		"type":      notification.Type,
		"level":     notification.Level.String(),
		"title":     notification.Title,
		"message":   notification.Message,
		"details":   notification.Details,
		"timestamp": notification.Timestamp.Format(time.RFC3339),
		"source":    notification.Source,
		"resolved":  notification.Resolved,
	}
	return json.Marshal(payload)
}

func (g *GenericAdapter) GetContentType() string {
	return "application/json"
}

func (g *GenericAdapter) GetHeaders() map[string]string {
	return map[string]string{
		"User-Agent": "SSLcat-Notification/1.0",
	}
}

// WeChatAdapter 企业微信适配器
type WeChatAdapter struct{}

func (w *WeChatAdapter) Adapt(notification *Notification) ([]byte, error) {
	// 企业微信机器人消息格式
	content := fmt.Sprintf("**%s**\n\n%s\n\n**级别**: %s\n**时间**: %s\n**来源**: %s",
		notification.Title,
		notification.Message,
		notification.Level.String(),
		notification.Timestamp.Format("2006-01-02 15:04:05"),
		notification.Source,
	)

	// 添加详细信息
	if len(notification.Details) > 0 {
		content += "\n\n**详细信息**:\n"
		for key, value := range notification.Details {
			content += fmt.Sprintf("- %s: %v\n", key, value)
		}
	}

	payload := map[string]any{
		"msgtype": "markdown",
		"markdown": map[string]any{
			"content": content,
		},
	}

	return json.Marshal(payload)
}

func (w *WeChatAdapter) GetContentType() string {
	return "application/json"
}

func (w *WeChatAdapter) GetHeaders() map[string]string {
	return map[string]string{
		"User-Agent": "SSLcat-Notification/1.0",
	}
}

// FeishuAdapter 飞书适配器
type FeishuAdapter struct{}

func (f *FeishuAdapter) Adapt(notification *Notification) ([]byte, error) {
	// 飞书机器人消息格式
	content := fmt.Sprintf("**%s**\n\n%s\n\n**级别**: %s\n**时间**: %s\n**来源**: %s",
		notification.Title,
		notification.Message,
		notification.Level.String(),
		notification.Timestamp.Format("2006-01-02 15:04:05"),
		notification.Source,
	)

	// 添加详细信息
	if len(notification.Details) > 0 {
		content += "\n\n**详细信息**:\n"
		for key, value := range notification.Details {
			content += fmt.Sprintf("- %s: %v\n", key, value)
		}
	}

	payload := map[string]any{
		"msg_type": "text",
		"content": map[string]any{
			"text": content,
		},
	}

	return json.Marshal(payload)
}

func (f *FeishuAdapter) GetContentType() string {
	return "application/json"
}

func (f *FeishuAdapter) GetHeaders() map[string]string {
	return map[string]string{
		"User-Agent": "SSLcat-Notification/1.0",
	}
}

// DingTalkAdapter 钉钉适配器
type DingTalkAdapter struct{}

func (d *DingTalkAdapter) Adapt(notification *Notification) ([]byte, error) {
	// 钉钉机器人消息格式
	content := fmt.Sprintf("## %s\n\n%s\n\n**级别**: %s\n**时间**: %s\n**来源**: %s",
		notification.Title,
		notification.Message,
		notification.Level.String(),
		notification.Timestamp.Format("2006-01-02 15:04:05"),
		notification.Source,
	)

	// 添加详细信息
	if len(notification.Details) > 0 {
		content += "\n\n**详细信息**:\n"
		for key, value := range notification.Details {
			content += fmt.Sprintf("- %s: %v\n", key, value)
		}
	}

	payload := map[string]any{
		"msgtype": "markdown",
		"markdown": map[string]any{
			"title": notification.Title,
			"text":  content,
		},
	}

	return json.Marshal(payload)
}

func (d *DingTalkAdapter) GetContentType() string {
	return "application/json"
}

func (d *DingTalkAdapter) GetHeaders() map[string]string {
	return map[string]string{
		"User-Agent": "SSLcat-Notification/1.0",
	}
}

// SlackAdapter Slack适配器
type SlackAdapter struct{}

func (s *SlackAdapter) Adapt(notification *Notification) ([]byte, error) {
	// Slack消息格式
	color := "good"
	switch notification.Level {
	case LevelWarning:
		color = "warning"
	case LevelError, LevelCritical:
		color = "danger"
	}

	fields := []map[string]any{
		{
			"title": "级别",
			"value": notification.Level.String(),
			"short": true,
		},
		{
			"title": "时间",
			"value": notification.Timestamp.Format("2006-01-02 15:04:05"),
			"short": true,
		},
		{
			"title": "来源",
			"value": notification.Source,
			"short": true,
		},
	}

	// 添加详细信息
	if len(notification.Details) > 0 {
		for key, value := range notification.Details {
			fields = append(fields, map[string]any{
				"title": key,
				"value": fmt.Sprintf("%v", value),
				"short": true,
			})
		}
	}

	payload := map[string]any{
		"attachments": []map[string]any{
			{
				"color":       color,
				"title":       notification.Title,
				"text":        notification.Message,
				"fields":      fields,
				"timestamp":   notification.Timestamp.Unix(),
				"footer":      "SSLcat 通知系统",
				"footer_icon": "https://sslcat.com/favicon.ico",
			},
		},
	}

	return json.Marshal(payload)
}

func (s *SlackAdapter) GetContentType() string {
	return "application/json"
}

func (s *SlackAdapter) GetHeaders() map[string]string {
	return map[string]string{
		"User-Agent": "SSLcat-Notification/1.0",
	}
}

// DiscordAdapter Discord适配器
type DiscordAdapter struct{}

func (d *DiscordAdapter) Adapt(notification *Notification) ([]byte, error) {
	// Discord Webhook格式
	color := 0x00ff00 // 绿色
	switch notification.Level {
	case LevelWarning:
		color = 0xffaa00 // 橙色
	case LevelError:
		color = 0xff0000 // 红色
	case LevelCritical:
		color = 0x8b0000 // 深红色
	}

	fields := []map[string]any{
		{
			"name":   "级别",
			"value":  notification.Level.String(),
			"inline": true,
		},
		{
			"name":   "时间",
			"value":  notification.Timestamp.Format("2006-01-02 15:04:05"),
			"inline": true,
		},
		{
			"name":   "来源",
			"value":  notification.Source,
			"inline": true,
		},
	}

	// 添加详细信息
	if len(notification.Details) > 0 {
		for key, value := range notification.Details {
			fields = append(fields, map[string]any{
				"name":   key,
				"value":  fmt.Sprintf("%v", value),
				"inline": true,
			})
		}
	}

	payload := map[string]any{
		"embeds": []map[string]any{
			{
				"title":       notification.Title,
				"description": notification.Message,
				"color":       color,
				"fields":      fields,
				"timestamp":   notification.Timestamp.Format(time.RFC3339),
				"footer": map[string]any{
					"text": "SSLcat 通知系统",
				},
			},
		},
	}

	return json.Marshal(payload)
}

func (d *DiscordAdapter) GetContentType() string {
	return "application/json"
}

func (d *DiscordAdapter) GetHeaders() map[string]string {
	return map[string]string{
		"User-Agent": "SSLcat-Notification/1.0",
	}
}

// TelegramAdapter Telegram适配器
type TelegramAdapter struct{}

func (t *TelegramAdapter) Adapt(notification *Notification) ([]byte, error) {
	// Telegram Bot API格式
	text := fmt.Sprintf("*%s*\n\n%s\n\n*级别*: %s\n*时间*: %s\n*来源*: %s",
		notification.Title,
		notification.Message,
		notification.Level.String(),
		notification.Timestamp.Format("2006-01-02 15:04:05"),
		notification.Source,
	)

	// 添加详细信息
	if len(notification.Details) > 0 {
		text += "\n\n*详细信息*:\n"
		for key, value := range notification.Details {
			text += fmt.Sprintf("• %s: %v\n", key, value)
		}
	}

	payload := map[string]any{
		"text":       text,
		"parse_mode": "Markdown",
	}

	return json.Marshal(payload)
}

func (t *TelegramAdapter) GetContentType() string {
	return "application/json"
}

func (t *TelegramAdapter) GetHeaders() map[string]string {
	return map[string]string{
		"User-Agent": "SSLcat-Notification/1.0",
	}
}

// GetPlatformAdapter 根据URL获取平台适配器
func GetPlatformAdapter(url string) PlatformAdapter {
	url = strings.ToLower(url)

	// 企业微信
	if strings.Contains(url, "qyapi.weixin.qq.com") || strings.Contains(url, "weixin.qq.com") {
		return &WeChatAdapter{}
	}

	// 飞书
	if strings.Contains(url, "open.feishu.cn") || strings.Contains(url, "feishu.cn") {
		return &FeishuAdapter{}
	}

	// 钉钉
	if strings.Contains(url, "oapi.dingtalk.com") || strings.Contains(url, "dingtalk.com") {
		return &DingTalkAdapter{}
	}

	// Slack
	if strings.Contains(url, "hooks.slack.com") || strings.Contains(url, "slack.com") {
		return &SlackAdapter{}
	}

	// Discord
	if strings.Contains(url, "discord.com") || strings.Contains(url, "discordapp.com") {
		return &DiscordAdapter{}
	}

	// Telegram
	if strings.Contains(url, "api.telegram.org") || strings.Contains(url, "telegram.org") {
		return &TelegramAdapter{}
	}

	// 默认使用通用适配器
	return &GenericAdapter{}
}

// DetectPlatform 检测平台类型
func DetectPlatform(url string) PlatformType {
	url = strings.ToLower(url)

	if strings.Contains(url, "qyapi.weixin.qq.com") || strings.Contains(url, "weixin.qq.com") {
		return PlatformWeChat
	}

	if strings.Contains(url, "open.feishu.cn") || strings.Contains(url, "feishu.cn") {
		return PlatformFeishu
	}

	if strings.Contains(url, "oapi.dingtalk.com") || strings.Contains(url, "dingtalk.com") {
		return PlatformDingTalk
	}

	if strings.Contains(url, "hooks.slack.com") || strings.Contains(url, "slack.com") {
		return PlatformSlack
	}

	if strings.Contains(url, "discord.com") || strings.Contains(url, "discordapp.com") {
		return PlatformDiscord
	}

	if strings.Contains(url, "api.telegram.org") || strings.Contains(url, "telegram.org") {
		return PlatformTelegram
	}

	return PlatformGeneric
}

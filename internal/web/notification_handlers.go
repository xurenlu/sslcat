package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/xurenlu/sslcat/internal/notification"
)

// handleNotifications 通知管理页面
func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 检查权限
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || (currentUser.Role != RoleSuperAdmin && currentUser.Role != RoleAdmin) {
		http.Error(w, "权限不足", http.StatusForbidden)
		return
	}

	// 获取通知历史
	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 200 {
			limit = l
		}
	}

	history := s.notificationIntegrator.GetNotificationHistory(limit)
	stats := s.notificationIntegrator.GetNotificationStats()

	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"History":     history,
		"Stats":       stats,
		"CurrentUser": currentUser,
		"Limit":       limit,
		"Levels": map[string]string{
			"info":     "信息",
			"warning":  "警告",
			"error":    "错误",
			"critical": "严重",
		},
		"Types": map[string]string{
			"ddos_attack":     "DDoS攻击",
			"cert_expiring":   "证书过期",
			"cert_failed":     "证书失败",
			"system_error":    "系统错误",
			"security_alert":  "安全警报",
			"user_login":      "用户登录",
			"user_action":     "用户操作",
			"system_startup":  "系统启动",
			"system_shutdown": "系统关闭",
		},
	}

	// 检查模板是否存在，如果不存在则回退到前端 SPA
	if !s.templateRenderer.TemplateExists("notifications.html") {
		s.handleSPA(w, r)
		return
	}

	s.templateRenderer.DetectLanguageAndRender(w, r, "notifications.html", data)
}

// handleNotificationTest 测试通知
func (s *Server) handleNotificationTest(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 检查权限
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || currentUser.Role != RoleSuperAdmin {
		http.Error(w, "权限不足", http.StatusForbidden)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 支持两种格式：JSON 和 FormData
	var notificationType, level, title, message string

	// 尝试解析JSON
	contentType := r.Header.Get("Content-Type")
	if contentType == "application/json" {
		var testData struct {
			Type    string `json:"type"`
			Level   string `json:"level"`
			Title   string `json:"title"`
			Message string `json:"message"`
		}

		if err := json.NewDecoder(r.Body).Decode(&testData); err != nil {
			http.Error(w, "无效的JSON数据", http.StatusBadRequest)
			return
		}

		notificationType = testData.Type
		level = testData.Level
		title = testData.Title
		message = testData.Message
	} else {
		// 兼容表单数据
		notificationType = r.FormValue("type")
		level = r.FormValue("level")
		title = r.FormValue("title")
		message = r.FormValue("message")
	}

	if notificationType == "" || level == "" || title == "" || message == "" {
		http.Error(w, "参数不完整", http.StatusBadRequest)
		return
	}

	// 创建测试通知
	notification := &notification.Notification{
		Type:    notification.NotificationType(notificationType),
		Level:   notification.NotificationLevel(parseLevel(level)),
		Title:   title,
		Message: message,
		Details: map[string]any{
			"test":      true,
			"tested_by": currentUser.Username,
			"tested_at": time.Now().Format(time.RFC3339),
		},
	}

	err := s.notificationIntegrator.GetManager().Send(notification)
	if err != nil {
		http.Error(w, fmt.Sprintf("发送测试通知失败: %v", err), http.StatusInternalServerError)
		return
	}

	// 返回成功响应
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "测试通知已发送",
	})
}

// handleNotificationStats 获取通知统计API
func (s *Server) handleNotificationStats(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	stats := s.notificationIntegrator.GetNotificationStats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleNotificationHistory 获取通知历史API
func (s *Server) handleNotificationHistory(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 200 {
			limit = l
		}
	}

	history := s.notificationIntegrator.GetNotificationHistory(limit)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}

// handleNotificationTestChannels 测试通知渠道
func (s *Server) handleNotificationTestChannels(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 检查权限
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || currentUser.Role != RoleSuperAdmin {
		http.Error(w, "权限不足", http.StatusForbidden)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 测试所有通知渠道
	results := s.notificationIntegrator.GetManager().TestNotificationChannels()

	// 返回测试结果
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"results": results,
	})
}

// handleNotificationConfig 获取通知配置
func (s *Server) handleNotificationConfig(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method == "GET" {
		// 返回当前通知配置
		config := s.config.Notification

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"config":  config,
		})
	} else if r.Method == "POST" {
		// 更新通知配置
		var updateConfig struct {
			MinNotificationLevel string                            `json:"min_notification_level"`
			Channels             map[string]map[string]interface{} `json:"channels"`
		}

		if err := json.NewDecoder(r.Body).Decode(&updateConfig); err != nil {
			http.Error(w, "无效的JSON数据", http.StatusBadRequest)
			return
		}

		// 更新最小通知级别
		if updateConfig.MinNotificationLevel != "" {
			s.config.Notification.MinNotificationLevel = updateConfig.MinNotificationLevel
		}

		// 更新邮件配置
		if emailConfig, exists := updateConfig.Channels["email"]; exists {
			if enabled, ok := emailConfig["enabled"].(bool); ok {
				s.config.Notification.Channels.Email.Enabled = enabled
			}
			// 邮件发送方式
			if method, ok := emailConfig["method"].(string); ok {
				s.config.Notification.Channels.Email.Method = method
			}
			// SMTP 配置
			if host, ok := emailConfig["smtp_host"].(string); ok {
				s.config.Notification.Channels.Email.SMTPHost = host
			}
			if port, ok := emailConfig["smtp_port"].(float64); ok {
				s.config.Notification.Channels.Email.SMTPPort = int(port)
			}
			if username, ok := emailConfig["username"].(string); ok {
				s.config.Notification.Channels.Email.Username = username
			}
			if password, ok := emailConfig["password"].(string); ok {
				s.config.Notification.Channels.Email.Password = password
			}
			if from, ok := emailConfig["from"].(string); ok {
				s.config.Notification.Channels.Email.From = from
			}
			if to, ok := emailConfig["to"].([]interface{}); ok {
				var toList []string
				for _, t := range to {
					if str, ok := t.(string); ok {
						toList = append(toList, str)
					}
				}
				s.config.Notification.Channels.Email.To = toList
			}
			if useTLS, ok := emailConfig["use_tls"].(bool); ok {
				s.config.Notification.Channels.Email.UseTLS = useTLS
			}
			// Sendmail 配置
			if sendmailCommand, ok := emailConfig["sendmail_command"].(string); ok {
				s.config.Notification.Channels.Email.SendmailCommand = sendmailCommand
			}
			if sendmailArgs, ok := emailConfig["sendmail_args"].(string); ok {
				s.config.Notification.Channels.Email.SendmailArgs = sendmailArgs
			}
			// Resend 配置
			if resendAPIKey, ok := emailConfig["resend_api_key"].(string); ok {
				s.config.Notification.Channels.Email.ResendAPIKey = resendAPIKey
			}
			if resendFrom, ok := emailConfig["resend_from"].(string); ok {
				s.config.Notification.Channels.Email.ResendFrom = resendFrom
			}
			if resendTo, ok := emailConfig["resend_to"].(string); ok {
				s.config.Notification.Channels.Email.ResendTo = resendTo
			}
			// Mailgun 配置
			if mailgunAPIKey, ok := emailConfig["mailgun_api_key"].(string); ok {
				s.config.Notification.Channels.Email.MailgunAPIKey = mailgunAPIKey
			}
			if mailgunDomain, ok := emailConfig["mailgun_domain"].(string); ok {
				s.config.Notification.Channels.Email.MailgunDomain = mailgunDomain
			}
			if mailgunFrom, ok := emailConfig["mailgun_from"].(string); ok {
				s.config.Notification.Channels.Email.MailgunFrom = mailgunFrom
			}
			if mailgunTo, ok := emailConfig["mailgun_to"].(string); ok {
				s.config.Notification.Channels.Email.MailgunTo = mailgunTo
			}
			// SendGrid 配置
			if sendgridAPIKey, ok := emailConfig["sendgrid_api_key"].(string); ok {
				s.config.Notification.Channels.Email.SendGridAPIKey = sendgridAPIKey
			}
			if sendgridFrom, ok := emailConfig["sendgrid_from"].(string); ok {
				s.config.Notification.Channels.Email.SendGridFrom = sendgridFrom
			}
			if sendgridTo, ok := emailConfig["sendgrid_to"].(string); ok {
				s.config.Notification.Channels.Email.SendGridTo = sendgridTo
			}
		}

		// 更新Webhook配置（包括Slack、企业微信、飞书等）
		if webhookConfig, exists := updateConfig.Channels["webhook"]; exists {
			if enabled, ok := webhookConfig["enabled"].(bool); ok {
				s.config.Notification.Channels.Webhook.Enabled = enabled
			}
			// 支持多个URL
			if urls, ok := webhookConfig["urls"].([]interface{}); ok {
				var urlList []string
				for _, u := range urls {
					if str, ok := u.(string); ok && str != "" {
						urlList = append(urlList, str)
					}
				}
				s.config.Notification.Channels.Webhook.URLs = urlList
				// 为了向后兼容，也设置单个URL（使用第一个）
				if len(urlList) > 0 {
					s.config.Notification.Channels.Webhook.URL = urlList[0]
				}
			}
			// 向后兼容单个URL
			if url, ok := webhookConfig["url"].(string); ok && url != "" {
				s.config.Notification.Channels.Webhook.URL = url
				// 如果没有URLs数组，则创建一个
				if len(s.config.Notification.Channels.Webhook.URLs) == 0 {
					s.config.Notification.Channels.Webhook.URLs = []string{url}
				}
			}
			if headers, ok := webhookConfig["headers"].(map[string]interface{}); ok {
				headerMap := make(map[string]string)
				for k, v := range headers {
					if str, ok := v.(string); ok {
						headerMap[k] = str
					}
				}
				s.config.Notification.Channels.Webhook.Headers = headerMap
			}
			if timeout, ok := webhookConfig["timeout"].(float64); ok {
				s.config.Notification.Channels.Webhook.Timeout = int(timeout)
			}
		}

		// 保存配置到文件
		if err := s.config.Save(s.config.ConfigFile); err != nil {
			http.Error(w, fmt.Sprintf("保存配置失败: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "通知配置已更新",
		})
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// parseLevel 解析通知级别
func parseLevel(level string) int {
	switch level {
	case "info":
		return 0
	case "warning":
		return 1
	case "error":
		return 2
	case "critical":
		return 3
	default:
		return 0
	}
}

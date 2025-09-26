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

	notificationType := r.FormValue("type")
	level := r.FormValue("level")
	title := r.FormValue("title")
	message := r.FormValue("message")

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
			Enabled  bool                              `json:"enabled"`
			Channels map[string]map[string]interface{} `json:"channels"`
		}

		if err := json.NewDecoder(r.Body).Decode(&updateConfig); err != nil {
			http.Error(w, "无效的JSON数据", http.StatusBadRequest)
			return
		}

		// 更新配置
		s.config.Notification.Enabled = updateConfig.Enabled

		// 更新邮件配置
		if emailConfig, exists := updateConfig.Channels["email"]; exists {
			if enabled, ok := emailConfig["enabled"].(bool); ok {
				s.config.Notification.Channels.Email.Enabled = enabled
			}
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
		}

		// 更新Webhook配置
		if webhookConfig, exists := updateConfig.Channels["webhook"]; exists {
			if enabled, ok := webhookConfig["enabled"].(bool); ok {
				s.config.Notification.Channels.Webhook.Enabled = enabled
			}
			if url, ok := webhookConfig["url"].(string); ok {
				s.config.Notification.Channels.Webhook.URL = url
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

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

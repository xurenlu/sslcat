package notification

import (
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

// NotificationLevel 通知级别
type NotificationLevel int

const (
	LevelInfo NotificationLevel = iota
	LevelWarning
	LevelError
	LevelCritical
)

func (l NotificationLevel) String() string {
	switch l {
	case LevelInfo:
		return "info"
	case LevelWarning:
		return "warning"
	case LevelError:
		return "error"
	case LevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// NotificationType 通知类型
type NotificationType string

const (
	TypeDDoSAttack     NotificationType = "ddos_attack"
	TypeCertExpiring   NotificationType = "cert_expiring"
	TypeCertFailed     NotificationType = "cert_failed"
	TypeSystemError    NotificationType = "system_error"
	TypeSecurityAlert  NotificationType = "security_alert"
	TypeUserLogin      NotificationType = "user_login"
	TypeUserAction     NotificationType = "user_action"
	TypeSystemStartup  NotificationType = "system_startup"
	TypeSystemShutdown NotificationType = "system_shutdown"
)

// Notification 通知结构
type Notification struct {
	ID         string            `json:"id"`
	Type       NotificationType  `json:"type"`
	Level      NotificationLevel `json:"level"`
	Title      string            `json:"title"`
	Message    string            `json:"message"`
	Details    map[string]any    `json:"details"`
	Timestamp  time.Time         `json:"timestamp"`
	Source     string            `json:"source"`
	Recipients []string          `json:"recipients"`
	Channels   []string          `json:"channels"`
	Resolved   bool              `json:"resolved"`
	ResolvedAt *time.Time        `json:"resolved_at,omitempty"`
}

// NotificationChannel 通知渠道接口
type NotificationChannel interface {
	Send(notification *Notification) error
	IsEnabled() bool
	GetName() string
}

// NotificationManager 通知管理器
type NotificationManager struct {
	channels    map[string]NotificationChannel
	log         *logrus.Entry
	rateLimiter *RateLimiter
	history     []Notification
	maxHistory  int
}

// NewNotificationManager 创建通知管理器
func NewNotificationManager() *NotificationManager {
	nm := &NotificationManager{
		channels:    make(map[string]NotificationChannel),
		log:         logrus.WithFields(logrus.Fields{"component": "notification"}),
		rateLimiter: NewRateLimiter(),
		history:     make([]Notification, 0),
		maxHistory:  1000,
	}

	// 初始化默认渠道
	nm.initDefaultChannels()

	return nm
}

// NewNotificationManagerFromConfig 从配置创建通知管理器
func NewNotificationManagerFromConfig(configData interface{}) *NotificationManager {
	nm := &NotificationManager{
		channels:    make(map[string]NotificationChannel),
		log:         logrus.WithFields(logrus.Fields{"component": "notification"}),
		rateLimiter: NewRateLimiter(),
		history:     make([]Notification, 0),
		maxHistory:  1000,
	}

	// 尝试从interface{}中提取配置
	// 由于interface{}类型，我们使用类型断言或反射
	// 这里先创建一个基础的控制台输出作为后备
	nm.channels["console"] = NewConsoleChannelFromConfig(config.ConsoleChannelConfig{Enabled: true})

	// 从环境变量作为后备配置
	nm.initDefaultChannels()

	nm.log.Info("通知管理器已初始化（使用默认配置）")
	return nm
}

// ValidateNotificationConfig 验证通知配置
func ValidateNotificationConfig(config interface{}) []string {
	var errors []string
	
	// 这里可以添加具体的配置验证逻辑
	// 例如：验证SMTP配置、Webhook URL格式等
	
	return errors
}

// TestNotificationChannels 测试通知渠道
func (nm *NotificationManager) TestNotificationChannels() map[string]string {
	results := make(map[string]string)
	
	for name, channel := range nm.channels {
		if !channel.IsEnabled() {
			results[name] = "未启用"
			continue
		}
		
		// 创建测试通知
		testNotification := &Notification{
			Type:    TypeSystemStartup,
			Level:   LevelInfo,
			Title:   "通知渠道测试",
			Message: "这是一条测试通知，用于验证通知渠道是否正常工作",
			Details: map[string]any{
				"test":      true,
				"timestamp": time.Now().Format(time.RFC3339),
			},
		}
		
		// 尝试发送测试通知
		if err := channel.Send(testNotification); err != nil {
			results[name] = fmt.Sprintf("测试失败: %v", err)
		} else {
			results[name] = "测试成功"
		}
	}
	
	return results
}

// initDefaultChannels 初始化默认通知渠道
func (nm *NotificationManager) initDefaultChannels() {
	// 邮件通知
	if email := NewEmailChannel(); email != nil {
		nm.channels["email"] = email
	}

	// Webhook通知
	if webhook := NewWebhookChannel(); webhook != nil {
		nm.channels["webhook"] = webhook
	}

	// 系统日志
	nm.channels["syslog"] = NewSyslogChannel()

	// 控制台输出
	nm.channels["console"] = NewConsoleChannel()
}

// Send 发送通知
func (nm *NotificationManager) Send(notification *Notification) error {
	// 设置默认值
	if notification.ID == "" {
		notification.ID = nm.generateID()
	}
	if notification.Timestamp.IsZero() {
		notification.Timestamp = time.Now()
	}
	if notification.Source == "" {
		notification.Source = "sslcat"
	}

	// 速率限制检查
	if nm.rateLimiter.IsRateLimited(notification.Type, notification.Level) {
		nm.log.Debugf("通知被速率限制: %s", notification.Type)
		return nil
	}

	// 记录到历史
	nm.addToHistory(notification)

	// 发送到各个渠道
	var errors []string
	for name, channel := range nm.channels {
		if !channel.IsEnabled() {
			continue
		}

		if err := channel.Send(notification); err != nil {
			nm.log.Errorf("发送通知到 %s 失败: %v", name, err)
			errors = append(errors, fmt.Sprintf("%s: %v", name, err))
		} else {
			nm.log.Debugf("通知已发送到 %s", name)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("部分通知发送失败: %s", strings.Join(errors, "; "))
	}

	nm.log.Infof("通知已发送: %s - %s", notification.Type, notification.Title)
	return nil
}

// SendDDoSAttack 发送DDoS攻击通知
func (nm *NotificationManager) SendDDoSAttack(ip, userAgent, url, reason string, severity string) error {
	level := LevelWarning
	if severity == "high" || severity == "critical" {
		level = LevelCritical
	}

	notification := &Notification{
		Type:    TypeDDoSAttack,
		Level:   level,
		Title:   "DDoS攻击检测",
		Message: fmt.Sprintf("检测到来自 %s 的DDoS攻击", ip),
		Details: map[string]any{
			"ip":         ip,
			"user_agent": userAgent,
			"url":        url,
			"reason":     reason,
			"severity":   severity,
		},
	}

	return nm.Send(notification)
}

// SendCertExpiring 发送证书即将过期通知
func (nm *NotificationManager) SendCertExpiring(domain string, daysLeft int) error {
	level := LevelWarning
	if daysLeft <= 3 {
		level = LevelCritical
	}

	notification := &Notification{
		Type:    TypeCertExpiring,
		Level:   level,
		Title:   "SSL证书即将过期",
		Message: fmt.Sprintf("域名 %s 的SSL证书将在 %d 天后过期", domain, daysLeft),
		Details: map[string]any{
			"domain":    domain,
			"days_left": daysLeft,
		},
	}

	return nm.Send(notification)
}

// SendCertFailed 发送证书申请失败通知
func (nm *NotificationManager) SendCertFailed(domain string, reason string) error {
	notification := &Notification{
		Type:    TypeCertFailed,
		Level:   LevelError,
		Title:   "SSL证书申请失败",
		Message: fmt.Sprintf("域名 %s 的SSL证书申请失败", domain),
		Details: map[string]any{
			"domain": domain,
			"reason": reason,
		},
	}

	return nm.Send(notification)
}

// SendSecurityAlert 发送安全警报
func (nm *NotificationManager) SendSecurityAlert(alertType, description string, details map[string]any) error {
	notification := &Notification{
		Type:    TypeSecurityAlert,
		Level:   LevelWarning,
		Title:   "安全警报",
		Message: description,
		Details: map[string]any{
			"alert_type":  alertType,
			"description": description,
		},
	}

	// 合并详细信息
	for k, v := range details {
		notification.Details[k] = v
	}

	return nm.Send(notification)
}

// SendUserAction 发送用户操作通知
func (nm *NotificationManager) SendUserAction(username, action, resource string, details map[string]any) error {
	notification := &Notification{
		Type:    TypeUserAction,
		Level:   LevelInfo,
		Title:   "用户操作",
		Message: fmt.Sprintf("用户 %s 执行了 %s 操作", username, action),
		Details: map[string]any{
			"username": username,
			"action":   action,
			"resource": resource,
		},
	}

	// 合并详细信息
	for k, v := range details {
		notification.Details[k] = v
	}

	return nm.Send(notification)
}

// addToHistory 添加到历史记录
func (nm *NotificationManager) addToHistory(notification *Notification) {
	nm.history = append(nm.history, *notification)
	if len(nm.history) > nm.maxHistory {
		nm.history = nm.history[1:]
	}
}

// generateID 生成通知ID
func (nm *NotificationManager) generateID() string {
	return fmt.Sprintf("notif_%d", time.Now().UnixNano())
}

// GetHistory 获取通知历史
func (nm *NotificationManager) GetHistory(limit int) []Notification {
	if limit <= 0 || limit > len(nm.history) {
		limit = len(nm.history)
	}
	start := len(nm.history) - limit
	if start < 0 {
		start = 0
	}
	return nm.history[start:]
}

// GetStats 获取通知统计
func (nm *NotificationManager) GetStats() map[string]any {
	stats := map[string]any{
		"total_notifications": len(nm.history),
		"channels_enabled":    len(nm.getEnabledChannels()),
		"channels_total":      len(nm.channels),
	}

	// 按类型统计
	typeCount := make(map[NotificationType]int)
	levelCount := make(map[NotificationLevel]int)

	for _, notification := range nm.history {
		typeCount[notification.Type]++
		levelCount[notification.Level]++
	}

	stats["by_type"] = typeCount
	stats["by_level"] = levelCount

	return stats
}

// getEnabledChannels 获取启用的渠道
func (nm *NotificationManager) getEnabledChannels() []string {
	var enabled []string
	for name, channel := range nm.channels {
		if channel.IsEnabled() {
			enabled = append(enabled, name)
		}
	}
	return enabled
}

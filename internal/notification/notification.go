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

// parseNotificationLevel 解析通知级别字符串
func parseNotificationLevel(level string) NotificationLevel {
	switch strings.ToLower(level) {
	case "info":
		return LevelInfo
	case "warning", "warn":
		return LevelWarning
	case "error":
		return LevelError
	case "critical":
		return LevelCritical
	default:
		return LevelInfo // 默认级别
	}
}

// NotificationType 通知类型
type NotificationType string

const (
	TypeDDoSAttack       NotificationType = "ddos_attack"
	TypeCertExpiring     NotificationType = "cert_expiring"
	TypeCertSuccess      NotificationType = "cert_success"
	TypeCertFailed       NotificationType = "cert_failed"
	TypeSystemError      NotificationType = "system_error"
	TypeSecurityAlert    NotificationType = "security_alert"
	TypeUserLogin        NotificationType = "user_login"
	TypeUserAction       NotificationType = "user_action"
	TypeSystemStartup    NotificationType = "system_startup"
	TypeSystemShutdown   NotificationType = "system_shutdown"
	TypeDeploySuccess    NotificationType = "deploy_success"
	TypeDeployFailed     NotificationType = "deploy_failed"
	TypeDeployTimeout    NotificationType = "deploy_timeout"
	TypeDeployStuck      NotificationType = "deploy_stuck"
	TypeConfigReloaded   NotificationType = "config_reloaded"
	TypeConfigReloadFail NotificationType = "config_reload_fail"
)

// String 返回通知类型的字符串表示
func (t NotificationType) String() string {
	return string(t)
}

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
	channels           map[string]NotificationChannel
	log                *logrus.Entry
	rateLimiter        *RateLimiter
	history            []Notification
	maxHistory         int
	minLevel           NotificationLevel // 最小通知级别
	sendSemaphore      chan struct{}     // 并发控制
	maxConcurrentSends int               // 最大并发发送数
}

// NewNotificationManager 创建通知管理器
func NewNotificationManager() *NotificationManager {
	maxConcurrentSends := 10 // 最多10个并发发送

	nm := &NotificationManager{
		channels:           make(map[string]NotificationChannel),
		log:                logrus.WithFields(logrus.Fields{"component": "notification"}),
		rateLimiter:        NewRateLimiter(),
		history:            make([]Notification, 0),
		maxHistory:         1000,
		minLevel:           LevelInfo, // 默认最小级别为info
		sendSemaphore:      make(chan struct{}, maxConcurrentSends),
		maxConcurrentSends: maxConcurrentSends,
	}

	// 初始化默认渠道
	nm.initDefaultChannels()

	return nm
}

// NewNotificationManagerFromConfig 从配置创建通知管理器
func NewNotificationManagerFromConfig(cfg config.NotificationConfig) *NotificationManager {
	maxConcurrentSends := 10 // 最多10个并发发送

	nm := &NotificationManager{
		channels:           make(map[string]NotificationChannel),
		log:                logrus.WithFields(logrus.Fields{"component": "notification"}),
		rateLimiter:        NewRateLimiter(),
		history:            make([]Notification, 0),
		maxHistory:         1000,
		minLevel:           parseNotificationLevel(cfg.MinNotificationLevel),
		sendSemaphore:      make(chan struct{}, maxConcurrentSends),
		maxConcurrentSends: maxConcurrentSends,
	}

	// 从配置文件初始化各个渠道
	// 邮件通知
	if cfg.Channels.Email.Enabled {
		emailChannel := NewEmailChannelFromConfig(cfg.Channels.Email)
		if emailChannel != nil {
			nm.channels["email"] = emailChannel
			nm.log.Info("邮件通知渠道已从配置启用")
		}
	}

	// Webhook通知（包括Slack、企业微信、飞书等）
	if cfg.Channels.Webhook.Enabled {
		webhookChannel := NewWebhookChannelFromConfig(cfg.Channels.Webhook)
		if webhookChannel != nil {
			nm.channels["webhook"] = webhookChannel
			nm.log.Info("Webhook通知渠道已从配置启用")
		}
	}

	// Syslog通知
	if cfg.Channels.Syslog.Enabled {
		syslogChannel := NewSyslogChannelFromConfig(cfg.Channels.Syslog)
		if syslogChannel != nil {
			nm.channels["syslog"] = syslogChannel
			nm.log.Info("Syslog通知渠道已从配置启用")
		}
	}

	// 控制台通知
	if cfg.Channels.Console.Enabled {
		consoleChannel := NewConsoleChannelFromConfig(cfg.Channels.Console)
		if consoleChannel != nil {
			nm.channels["console"] = consoleChannel
			nm.log.Info("控制台通知渠道已从配置启用")
		}
	}

	nm.log.Infof("通知管理器已从配置初始化，启用 %d 个渠道", len(nm.channels))
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

// Send 发送通知（异步）
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

	// 级别过滤检查
	if notification.Level < nm.minLevel {
		nm.log.Debugf("通知级别 %s 低于最小级别 %s，跳过发送: %s",
			notification.Level.String(), nm.minLevel.String(), notification.Type)
		return nil
	}

	// 速率限制检查
	if nm.rateLimiter.IsRateLimited(notification.Type, notification.Level) {
		nm.log.Debugf("通知被速率限制: %s", notification.Type)
		return nil
	}

	// 记录到历史
	nm.addToHistory(notification)

	// 异步发送到各个渠道（避免阻塞）
	go nm.sendAsync(notification)

	return nil
}

// sendAsync 异步发送通知到各个渠道
func (nm *NotificationManager) sendAsync(notification *Notification) {
	// 并发控制
	select {
	case nm.sendSemaphore <- struct{}{}:
		// 添加panic恢复，确保信号量不泄漏
		defer func() {
			<-nm.sendSemaphore
			if r := recover(); r != nil {
				nm.log.Errorf("Notification send panic recovered for %s: %v", notification.Type, r)
			}
		}()
	default:
		// 发送队列已满，记录警告
		nm.log.Warnf("通知发送队列已满（最多%d个并发），跳过: %s", nm.maxConcurrentSends, notification.Type)
		return
	}

	// 发送到各个渠道（每个渠道单独捕获panic）
	var errors []string
	for name, channel := range nm.channels {
		if !channel.IsEnabled() {
			continue
		}

		// 为每个渠道添加panic保护
		func() {
			defer func() {
				if r := recover(); r != nil {
					errMsg := fmt.Sprintf("panic: %v", r)
					nm.log.Errorf("发送通知到 %s 时panic: %v", name, r)
					errors = append(errors, fmt.Sprintf("%s: %s", name, errMsg))
				}
			}()

			if err := channel.Send(notification); err != nil {
				nm.log.Errorf("发送通知到 %s 失败: %v", name, err)
				errors = append(errors, fmt.Sprintf("%s: %v", name, err))
			} else {
				nm.log.Debugf("通知已发送到 %s", name)
			}
		}()
	}

	if len(errors) > 0 {
		nm.log.Errorf("部分通知发送失败: %s", strings.Join(errors, "; "))
	} else {
		nm.log.Infof("通知已发送: %s - %s", notification.Type, notification.Title)
	}
}

// SendDDoSAttack 发送DDoS攻击通知
func (nm *NotificationManager) SendDDoSAttack(ip, userAgent, url, reason string, severity string, blocked bool) error {
	level := LevelWarning
	title := "检测到可疑请求行为"
	message := fmt.Sprintf("检测到来自 %s 的可疑请求行为", ip)

	// 根据是否真正拦截来设置级别和标题
	if blocked {
		title = "DDoS攻击检测并拦截"
		message = fmt.Sprintf("检测到来自 %s 的DDoS攻击并已拦截", ip)
		if severity == "high" || severity == "critical" {
			level = LevelCritical
		} else {
			level = LevelError
		}
	} else {
		// 仅检测到可疑行为但未拦截
		if severity == "high" || severity == "critical" {
			level = LevelWarning
		} else {
			level = LevelInfo
		}
	}

	notification := &Notification{
		Type:    TypeDDoSAttack,
		Level:   level,
		Title:   title,
		Message: message,
		Details: map[string]any{
			"ip":         ip,
			"user_agent": userAgent,
			"url":        url,
			"reason":     reason,
			"severity":   severity,
			"blocked":    blocked,
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

// SendCertSuccess 发送证书申请成功通知
func (nm *NotificationManager) SendCertSuccess(domain string, attempts int, duration time.Duration) error {
	notification := &Notification{
		Type:    TypeCertSuccess,
		Level:   LevelInfo,
		Title:   "SSL证书申请成功",
		Message: fmt.Sprintf("域名 %s 的SSL证书申请成功", domain),
		Details: map[string]any{
			"domain":   domain,
			"attempts": attempts,
			"duration": duration.String(),
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

// SendDeploySuccess 发送部署成功通知
func (nm *NotificationManager) SendDeploySuccess(appName, commitSHA, commitMsg, domain string, duration time.Duration) error {
	notification := &Notification{
		Type:    TypeDeploySuccess,
		Level:   LevelInfo,
		Title:   fmt.Sprintf("应用 %s 部署成功", appName),
		Message: fmt.Sprintf("应用 %s 已成功部署到 %s", appName, domain),
		Details: map[string]any{
			"app_name":   appName,
			"commit_sha": commitSHA,
			"commit_msg": commitMsg,
			"domain":     domain,
			"duration":   duration.String(),
		},
	}

	return nm.Send(notification)
}

// SendDeployFailed 发送部署失败通知
func (nm *NotificationManager) SendDeployFailed(appName, commitSHA, commitMsg, reason string, errorDetails string) error {
	notification := &Notification{
		Type:    TypeDeployFailed,
		Level:   LevelError,
		Title:   fmt.Sprintf("应用 %s 部署失败", appName),
		Message: fmt.Sprintf("应用 %s 部署失败: %s", appName, reason),
		Details: map[string]any{
			"app_name":      appName,
			"commit_sha":    commitSHA,
			"commit_msg":    commitMsg,
			"reason":        reason,
			"error_details": errorDetails,
		},
	}

	return nm.Send(notification)
}

// SendDeployTimeout 发送部署超时通知
func (nm *NotificationManager) SendDeployTimeout(appName, commitSHA, duration string) error {
	notification := &Notification{
		Type:    TypeDeployTimeout,
		Level:   LevelWarning,
		Title:   fmt.Sprintf("应用 %s 部署超时", appName),
		Message: fmt.Sprintf("应用 %s 部署超过 %s 仍未完成，可能仍在后台运行", appName, duration),
		Details: map[string]any{
			"app_name":   appName,
			"commit_sha": commitSHA,
			"duration":   duration,
			"suggestion": "请检查管理面板或日志文件确认部署状态",
		},
	}

	return nm.Send(notification)
}

// SendDeployStuck 发送部署卡住通知
func (nm *NotificationManager) SendDeployStuck(appName, commitSHA, lastLog string, idleDuration string) error {
	notification := &Notification{
		Type:    TypeDeployStuck,
		Level:   LevelWarning,
		Title:   fmt.Sprintf("应用 %s 部署可能卡住", appName),
		Message: fmt.Sprintf("应用 %s 部署 %s 内没有新日志输出，可能已卡住", appName, idleDuration),
		Details: map[string]any{
			"app_name":      appName,
			"commit_sha":    commitSHA,
			"idle_duration": idleDuration,
			"last_log":      lastLog,
			"suggestion":    "请检查构建进程是否卡住，可能需要手动介入",
		},
	}

	return nm.Send(notification)
}

// SendConfigReloaded 发送配置重载成功通知
func (nm *NotificationManager) SendConfigReloaded(configFile string, duration time.Duration, changes []string) error {
	notification := &Notification{
		Type:    TypeConfigReloaded,
		Level:   LevelInfo,
		Title:   "配置文件热重载成功",
		Message: fmt.Sprintf("配置文件 %s 已成功热重载", configFile),
		Details: map[string]any{
			"config_file": configFile,
			"duration":    duration.String(),
			"changes":     changes,
			"timestamp":   time.Now().Format("2006-01-02 15:04:05"),
		},
	}

	return nm.Send(notification)
}

// SendConfigReloadFailed 发送配置重载失败通知
func (nm *NotificationManager) SendConfigReloadFailed(configFile string, reason string, errorDetails string) error {
	notification := &Notification{
		Type:    TypeConfigReloadFail,
		Level:   LevelError,
		Title:   "配置文件热重载失败",
		Message: fmt.Sprintf("配置文件 %s 重载失败: %s", configFile, reason),
		Details: map[string]any{
			"config_file":   configFile,
			"reason":        reason,
			"error_details": errorDetails,
			"timestamp":     time.Now().Format("2006-01-02 15:04:05"),
			"suggestion":    "请检查配置文件语法或查看日志获取更多信息",
		},
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
	// 统计真实的总通知数（从日志文件）
	totalNotificationsAll := nm.getTotalNotificationsFromFile()

	stats := map[string]any{
		"recent_notifications": len(nm.history),       // 内存中最近的通知
		"total_notifications":  totalNotificationsAll, // 真实的总通知数
		"channels_enabled":     len(nm.getEnabledChannels()),
		"channels_total":       len(nm.channels),
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

// getTotalNotificationsFromFile 从日志文件统计真实的总通知数
func (nm *NotificationManager) getTotalNotificationsFromFile() int {
	// 通知系统可能没有持久化日志文件
	// 如果未来添加了持久化，可以在这里实现
	// 目前返回内存中的数量
	return len(nm.history)
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

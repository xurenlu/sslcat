package notification

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

// NotificationIntegrator 通知集成器
type NotificationIntegrator struct {
	manager *NotificationManager
	log     *logrus.Entry
}

// NewNotificationIntegrator 创建通知集成器
func NewNotificationIntegrator() *NotificationIntegrator {
	return &NotificationIntegrator{
		manager: NewNotificationManager(),
		log:     logrus.WithFields(logrus.Fields{"component": "notification_integrator"}),
	}
}

// NewNotificationIntegratorFromConfig 从配置创建通知集成器
func NewNotificationIntegratorFromConfig(notificationConfig config.NotificationConfig) *NotificationIntegrator {
	manager := NewNotificationManagerFromConfig(notificationConfig)
	return &NotificationIntegrator{
		manager: manager,
		log:     logrus.WithFields(logrus.Fields{"component": "notification_integrator"}),
	}
}

// GetManager 获取通知管理器
func (ni *NotificationIntegrator) GetManager() *NotificationManager {
	return ni.manager
}

// AttackInfo 攻击信息（避免直接依赖ddos包）
type AttackInfo struct {
	ClientIP  string
	UserAgent string
	URL       string
	Reason    string
	Severity  string
	Blocked   bool // 是否真正拦截了请求
}

// SendDDoSAttackNotification 发送DDoS攻击通知
func (ni *NotificationIntegrator) SendDDoSAttackNotification(attack *AttackInfo) {
	severity := "medium"
	if attack.Severity == "high" || attack.Severity == "critical" {
		severity = attack.Severity
	}

	err := ni.manager.SendDDoSAttack(
		attack.ClientIP,
		attack.UserAgent,
		attack.URL,
		attack.Reason,
		severity,
		attack.Blocked,
	)

	if err != nil {
		ni.log.Errorf("发送DDoS攻击通知失败: %v", err)
	}
}

// SendCertExpiringNotification 发送证书即将过期通知
func (ni *NotificationIntegrator) SendCertExpiringNotification(domain string, daysLeft int) {
	err := ni.manager.SendCertExpiring(domain, daysLeft)
	if err != nil {
		ni.log.Errorf("发送证书过期通知失败: %v", err)
	}
}

// SendCertSuccessNotification 发送证书申请成功通知
func (ni *NotificationIntegrator) SendCertSuccessNotification(domain string, attempts int, duration time.Duration) {
	err := ni.manager.SendCertSuccess(domain, attempts, duration)
	if err != nil {
		ni.log.Errorf("发送证书申请成功通知失败: %v", err)
	}
}

// SendCertFailedNotification 发送证书申请失败通知
func (ni *NotificationIntegrator) SendCertFailedNotification(domain, reason string) {
	err := ni.manager.SendCertFailed(domain, reason)
	if err != nil {
		ni.log.Errorf("发送证书申请失败通知失败: %v", err)
	}
}

// SendSecurityAlertNotification 发送安全警报通知
func (ni *NotificationIntegrator) SendSecurityAlertNotification(alertType, description string, details map[string]any) {
	err := ni.manager.SendSecurityAlert(alertType, description, details)
	if err != nil {
		ni.log.Errorf("发送安全警报通知失败: %v", err)
	}
}

// SendUserActionNotification 发送用户操作通知
func (ni *NotificationIntegrator) SendUserActionNotification(username, action, resource string, details map[string]any) {
	err := ni.manager.SendUserAction(username, action, resource, details)
	if err != nil {
		ni.log.Errorf("发送用户操作通知失败: %v", err)
	}
}

// SendSystemStartupNotification 发送系统启动通知
func (ni *NotificationIntegrator) SendSystemStartupNotification() {
	notification := &Notification{
		Type:    TypeSystemStartup,
		Level:   LevelInfo,
		Title:   "系统启动",
		Message: "SSLcat系统已启动",
		Details: map[string]any{
			"startup_time": time.Now().Format(time.RFC3339),
			"version":      "1.2.2", // 可以从配置中获取
		},
	}

	err := ni.manager.Send(notification)
	if err != nil {
		ni.log.Errorf("发送系统启动通知失败: %v", err)
	}
}

// SendSystemShutdownNotification 发送系统关闭通知
func (ni *NotificationIntegrator) SendSystemShutdownNotification() {
	notification := &Notification{
		Type:    TypeSystemShutdown,
		Level:   LevelInfo,
		Title:   "系统关闭",
		Message: "SSLcat系统正在关闭",
		Details: map[string]any{
			"shutdown_time": time.Now().Format(time.RFC3339),
		},
	}

	err := ni.manager.Send(notification)
	if err != nil {
		ni.log.Errorf("发送系统关闭通知失败: %v", err)
	}
}

// SendSystemErrorNotification 发送系统错误通知
func (ni *NotificationIntegrator) SendSystemErrorNotification(err error, context string) {
	level := LevelError
	if err != nil {
		// 根据错误类型判断级别
		level = LevelError
	}

	notification := &Notification{
		Type:    TypeSystemError,
		Level:   level,
		Title:   "系统错误",
		Message: fmt.Sprintf("系统发生错误: %v", err),
		Details: map[string]any{
			"error":   err.Error(),
			"context": context,
		},
	}

	sendErr := ni.manager.Send(notification)
	if sendErr != nil {
		ni.log.Errorf("发送系统错误通知失败: %v", sendErr)
	}
}

// GetNotificationStats 获取通知统计
func (ni *NotificationIntegrator) GetNotificationStats() map[string]any {
	return ni.manager.GetStats()
}

// GetNotificationHistory 获取通知历史
func (ni *NotificationIntegrator) GetNotificationHistory(limit int) []Notification {
	return ni.manager.GetHistory(limit)
}

package notification

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

// EmailChannel 邮件通知渠道
type EmailChannel struct {
	enabled  bool
	smtpHost string
	smtpPort string
	username string
	password string
	from     string
	to       []string
	useTLS   bool
	client   *smtp.Client
	log      *logrus.Entry
}

// NewEmailChannel 创建邮件通知渠道
func NewEmailChannel() *EmailChannel {
	ec := &EmailChannel{
		enabled:  false,
		smtpHost: os.Getenv("NOTIFICATION_SMTP_HOST"),
		smtpPort: os.Getenv("NOTIFICATION_SMTP_PORT"),
		username: os.Getenv("NOTIFICATION_SMTP_USERNAME"),
		password: os.Getenv("NOTIFICATION_SMTP_PASSWORD"),
		from:     os.Getenv("NOTIFICATION_SMTP_FROM"),
		to:       strings.Split(os.Getenv("NOTIFICATION_SMTP_TO"), ","),
		useTLS:   os.Getenv("NOTIFICATION_SMTP_TLS") == "true",
		log:      logrus.WithFields(logrus.Fields{"component": "email_channel"}),
	}

	// 检查是否配置完整
	if ec.smtpHost != "" && ec.smtpPort != "" && ec.username != "" &&
		ec.password != "" && ec.from != "" && len(ec.to) > 0 && ec.to[0] != "" {
		ec.enabled = true
		ec.log.Info("邮件通知渠道已启用")
	} else {
		ec.log.Debug("邮件通知渠道未配置或配置不完整")
	}

	return ec
}

// NewEmailChannelFromConfig 从配置创建邮件通知渠道
func NewEmailChannelFromConfig(cfg config.EmailChannelConfig) *EmailChannel {
	ec := &EmailChannel{
		enabled:  cfg.Enabled,
		smtpHost: cfg.SMTPHost,
		smtpPort: fmt.Sprintf("%d", cfg.SMTPPort),
		username: cfg.Username,
		password: cfg.Password,
		from:     cfg.From,
		to:       cfg.To,
		useTLS:   cfg.UseTLS,
		log:      logrus.WithFields(logrus.Fields{"component": "email_channel"}),
	}

	// 验证配置完整性
	if ec.enabled {
		if ec.smtpHost == "" || ec.smtpPort == "" || ec.username == "" ||
			ec.password == "" || ec.from == "" || len(ec.to) == 0 {
			ec.enabled = false
			ec.log.Warn("邮件通知配置不完整，已禁用")
		} else {
			ec.log.Info("邮件通知渠道已从配置启用")
		}
	}

	return ec
}

// Send 发送邮件通知
func (ec *EmailChannel) Send(notification *Notification) error {
	if !ec.enabled {
		return nil
	}

	// 构建邮件内容
	subject := fmt.Sprintf("[%s] %s", strings.ToUpper(notification.Level.String()), notification.Title)
	body := ec.buildEmailBody(notification)

	// 发送邮件
	return ec.sendEmail(ec.to, subject, body)
}

// buildEmailBody 构建邮件正文
func (ec *EmailChannel) buildEmailBody(notification *Notification) string {
	var buffer bytes.Buffer

	buffer.WriteString(fmt.Sprintf("通知类型: %s\n", notification.Type))
	buffer.WriteString(fmt.Sprintf("级别: %s\n", notification.Level.String()))
	buffer.WriteString(fmt.Sprintf("时间: %s\n", notification.Timestamp.Format("2006-01-02 15:04:05")))
	buffer.WriteString(fmt.Sprintf("来源: %s\n", notification.Source))
	buffer.WriteString(fmt.Sprintf("\n标题: %s\n", notification.Title))
	buffer.WriteString(fmt.Sprintf("内容: %s\n", notification.Message))

	if len(notification.Details) > 0 {
		buffer.WriteString("\n详细信息:\n")
		for key, value := range notification.Details {
			buffer.WriteString(fmt.Sprintf("  %s: %v\n", key, value))
		}
	}

	buffer.WriteString(fmt.Sprintf("\n---\nSSLcat 通知系统\n时间: %s", time.Now().Format("2006-01-02 15:04:05")))

	return buffer.String()
}

// sendEmail 发送邮件
func (ec *EmailChannel) sendEmail(to []string, subject, body string) error {
	addr := ec.smtpHost + ":" + ec.smtpPort

	// 创建SMTP客户端
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("连接SMTP服务器失败: %v", err)
	}
	defer client.Quit()

	// 启用TLS
	if ec.useTLS {
		tlsConfig := &tls.Config{
			ServerName: ec.smtpHost,
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("启用TLS失败: %v", err)
		}
	}

	// 认证
	auth := smtp.PlainAuth("", ec.username, ec.password, ec.smtpHost)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("SMTP认证失败: %v", err)
	}

	// 设置发件人
	if err := client.Mail(ec.from); err != nil {
		return fmt.Errorf("设置发件人失败: %v", err)
	}

	// 设置收件人
	for _, recipient := range to {
		if recipient != "" {
			if err := client.Rcpt(recipient); err != nil {
				return fmt.Errorf("设置收件人失败 %s: %v", recipient, err)
			}
		}
	}

	// 发送邮件内容
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("获取数据写入器失败: %v", err)
	}

	// 构建完整邮件
	message := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		ec.from, strings.Join(to, ","), subject, body)

	_, err = writer.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("写入邮件内容失败: %v", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("关闭数据写入器失败: %v", err)
	}

	ec.log.Infof("邮件已发送到: %s", strings.Join(to, ","))
	return nil
}

// IsEnabled 检查是否启用
func (ec *EmailChannel) IsEnabled() bool {
	return ec.enabled
}

// GetName 获取渠道名称
func (ec *EmailChannel) GetName() string {
	return "email"
}

// WebhookChannel Webhook通知渠道
type WebhookChannel struct {
	enabled bool
	url     string
	headers map[string]string
	client  *http.Client
	log     *logrus.Entry
}

// NewWebhookChannel 创建Webhook通知渠道
func NewWebhookChannel() *WebhookChannel {
	whc := &WebhookChannel{
		enabled: false,
		url:     os.Getenv("NOTIFICATION_WEBHOOK_URL"),
		headers: make(map[string]string),
		client:  &http.Client{Timeout: 10 * time.Second},
		log:     logrus.WithFields(logrus.Fields{"component": "webhook_channel"}),
	}

	// 解析自定义头部
	if headers := os.Getenv("NOTIFICATION_WEBHOOK_HEADERS"); headers != "" {
		for _, header := range strings.Split(headers, ",") {
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				whc.headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	if whc.url != "" {
		whc.enabled = true
		whc.log.Info("Webhook通知渠道已启用")
	} else {
		whc.log.Debug("Webhook通知渠道未配置")
	}

	return whc
}

// NewWebhookChannelFromConfig 从配置创建Webhook通知渠道
func NewWebhookChannelFromConfig(cfg config.WebhookChannelConfig) *WebhookChannel {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10
	}

	whc := &WebhookChannel{
		enabled: cfg.Enabled && cfg.URL != "",
		url:     cfg.URL,
		headers: cfg.Headers,
		client:  &http.Client{Timeout: time.Duration(timeout) * time.Second},
		log:     logrus.WithFields(logrus.Fields{"component": "webhook_channel"}),
	}

	if whc.headers == nil {
		whc.headers = make(map[string]string)
	}

	if whc.enabled {
		whc.log.Info("Webhook通知渠道已从配置启用")
	}

	return whc
}

// Send 发送Webhook通知
func (whc *WebhookChannel) Send(notification *Notification) error {
	if !whc.enabled {
		return nil
	}

	// 构建请求体
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

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("序列化通知数据失败: %v", err)
	}

	// 创建HTTP请求
	req, err := http.NewRequest("POST", whc.url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("创建HTTP请求失败: %v", err)
	}

	// 设置默认头部
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SSLcat-Notification/1.0")

	// 设置自定义头部
	for key, value := range whc.headers {
		req.Header.Set(key, value)
	}

	// 发送请求
	resp, err := whc.client.Do(req)
	if err != nil {
		return fmt.Errorf("发送Webhook请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Webhook返回错误状态码: %d", resp.StatusCode)
	}

	whc.log.Infof("Webhook通知已发送到: %s", whc.url)
	return nil
}

// IsEnabled 检查是否启用
func (whc *WebhookChannel) IsEnabled() bool {
	return whc.enabled
}

// GetName 获取渠道名称
func (whc *WebhookChannel) GetName() string {
	return "webhook"
}

// SyslogChannel 系统日志通知渠道
type SyslogChannel struct {
	enabled bool
	addr    string
	log     *logrus.Entry
}

// NewSyslogChannel 创建系统日志通知渠道
func NewSyslogChannel() *SyslogChannel {
	sc := &SyslogChannel{
		enabled: os.Getenv("NOTIFICATION_SYSLOG_ENABLED") == "true",
		addr:    os.Getenv("NOTIFICATION_SYSLOG_ADDR"),
		log:     logrus.WithFields(logrus.Fields{"component": "syslog_channel"}),
	}

	if sc.enabled && sc.addr != "" {
		sc.log.Info("系统日志通知渠道已启用")
	}

	return sc
}

// NewSyslogChannelFromConfig 从配置创建系统日志通知渠道
func NewSyslogChannelFromConfig(cfg config.SyslogChannelConfig) *SyslogChannel {
	sc := &SyslogChannel{
		enabled: cfg.Enabled && cfg.Address != "",
		addr:    cfg.Address,
		log:     logrus.WithFields(logrus.Fields{"component": "syslog_channel"}),
	}

	if sc.enabled {
		sc.log.Info("系统日志通知渠道已从配置启用")
	}

	return sc
}

// Send 发送系统日志通知
func (sc *SyslogChannel) Send(notification *Notification) error {
	if !sc.enabled {
		return nil
	}

	// 构建syslog消息
	priority := sc.getPriority(notification.Level)
	message := fmt.Sprintf("<%d>%s sslcat-notification: %s - %s",
		priority,
		notification.Timestamp.Format("Jan 02 15:04:05"),
		notification.Title,
		notification.Message,
	)

	// 发送UDP消息
	return sc.sendUDP(message)
}

// getPriority 获取syslog优先级
func (sc *SyslogChannel) getPriority(level NotificationLevel) int {
	// 使用local0 facility (16) + severity level
	facility := 16 << 3
	severity := int(level)
	return facility + severity
}

// sendUDP 发送UDP消息
func (sc *SyslogChannel) sendUDP(message string) error {
	addr, err := net.ResolveUDPAddr("udp", sc.addr)
	if err != nil {
		return fmt.Errorf("解析UDP地址失败: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("连接UDP服务器失败: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("发送UDP消息失败: %v", err)
	}

	sc.log.Debugf("系统日志已发送: %s", message)
	return nil
}

// IsEnabled 检查是否启用
func (sc *SyslogChannel) IsEnabled() bool {
	return sc.enabled
}

// GetName 获取渠道名称
func (sc *SyslogChannel) GetName() string {
	return "syslog"
}

// ConsoleChannel 控制台通知渠道
type ConsoleChannel struct {
	enabled bool
	log     *logrus.Entry
}

// NewConsoleChannel 创建控制台通知渠道
func NewConsoleChannel() *ConsoleChannel {
	cc := &ConsoleChannel{
		enabled: true, // 默认启用
		log:     logrus.WithFields(logrus.Fields{"component": "console_channel"}),
	}
	return cc
}

// NewConsoleChannelFromConfig 从配置创建控制台通知渠道
func NewConsoleChannelFromConfig(cfg config.ConsoleChannelConfig) *ConsoleChannel {
	cc := &ConsoleChannel{
		enabled: cfg.Enabled,
		log:     logrus.WithFields(logrus.Fields{"component": "console_channel"}),
	}
	return cc
}

// Send 发送控制台通知
func (cc *ConsoleChannel) Send(notification *Notification) error {
	if !cc.enabled {
		return nil
	}

	// 根据级别选择日志级别
	switch notification.Level {
	case LevelCritical:
		cc.log.Error(cc.formatMessage(notification))
	case LevelError:
		cc.log.Error(cc.formatMessage(notification))
	case LevelWarning:
		cc.log.Warn(cc.formatMessage(notification))
	default:
		cc.log.Info(cc.formatMessage(notification))
	}

	return nil
}

// formatMessage 格式化消息
func (cc *ConsoleChannel) formatMessage(notification *Notification) string {
	return fmt.Sprintf("[%s] %s: %s - %s",
		strings.ToUpper(notification.Level.String()),
		notification.Type,
		notification.Title,
		notification.Message,
	)
}

// IsEnabled 检查是否启用
func (cc *ConsoleChannel) IsEnabled() bool {
	return cc.enabled
}

// GetName 获取渠道名称
func (cc *ConsoleChannel) GetName() string {
	return "console"
}

package notification

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

// EmailChannel 邮件通知渠道
type EmailChannel struct {
	enabled  bool
	method   string // smtp, sendmail, resend, mailgun, sendgrid
	
	// SMTP 配置
	smtpHost string
	smtpPort string
	username string
	password string
	from     string
	to       []string
	useTLS   bool
	client   *smtp.Client
	
	// Sendmail 配置
	sendmailCommand string
	sendmailArgs    string
	
	// Resend 配置
	resendAPIKey string
	resendFrom   string
	resendTo     string
	
	// Mailgun 配置
	mailgunAPIKey string
	mailgunDomain string
	mailgunFrom   string
	mailgunTo     string
	
	// SendGrid 配置
	sendgridAPIKey string
	sendgridFrom   string
	sendgridTo     string
	
	log *logrus.Entry
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
		enabled: cfg.Enabled,
		method:  cfg.Method,
		
		// SMTP 配置（优先使用环境变量）
		smtpHost: getEnvOrDefault("NOTIFICATION_SMTP_HOST", cfg.SMTPHost),
		smtpPort: getEnvOrDefault("NOTIFICATION_SMTP_PORT", fmt.Sprintf("%d", cfg.SMTPPort)),
		username: getEnvOrDefault("NOTIFICATION_SMTP_USERNAME", cfg.Username),
		password: getEnvOrDefault("NOTIFICATION_SMTP_PASSWORD", cfg.Password),
		from:     getEnvOrDefault("NOTIFICATION_SMTP_FROM", cfg.From),
		to:       cfg.To,
		useTLS:   cfg.UseTLS,
		
		// Sendmail 配置
		sendmailCommand: getEnvOrDefault("NOTIFICATION_SENDMAIL_COMMAND", cfg.SendmailCommand),
		sendmailArgs:    getEnvOrDefault("NOTIFICATION_SENDMAIL_ARGS", cfg.SendmailArgs),
		
		// Resend 配置（优先使用环境变量）
		resendAPIKey: getEnvOrDefault("RESEND_API_KEY", cfg.ResendAPIKey),
		resendFrom:   getEnvOrDefault("RESEND_FROM", cfg.ResendFrom),
		resendTo:     getEnvOrDefault("RESEND_TO", cfg.ResendTo),
		
		// Mailgun 配置（优先使用环境变量）
		mailgunAPIKey: getEnvOrDefault("MAILGUN_API_KEY", cfg.MailgunAPIKey),
		mailgunDomain: getEnvOrDefault("MAILGUN_DOMAIN", cfg.MailgunDomain),
		mailgunFrom:   getEnvOrDefault("MAILGUN_FROM", cfg.MailgunFrom),
		mailgunTo:     getEnvOrDefault("MAILGUN_TO", cfg.MailgunTo),
		
		// SendGrid 配置（优先使用环境变量）
		sendgridAPIKey: getEnvOrDefault("SENDGRID_API_KEY", cfg.SendGridAPIKey),
		sendgridFrom:   getEnvOrDefault("SENDGRID_FROM", cfg.SendGridFrom),
		sendgridTo:     getEnvOrDefault("SENDGRID_TO", cfg.SendGridTo),
		
		log: logrus.WithFields(logrus.Fields{"component": "email_channel"}),
	}

	// 验证配置完整性
	if ec.enabled {
		switch ec.method {
		case "smtp":
			if ec.smtpHost == "" || ec.smtpPort == "" || ec.username == "" ||
				ec.password == "" || ec.from == "" || len(ec.to) == 0 {
				ec.enabled = false
				ec.log.Warn("SMTP邮件通知配置不完整，已禁用")
			} else {
				ec.log.Info("SMTP邮件通知渠道已从配置启用")
			}
		case "sendmail":
			if ec.sendmailCommand == "" || ec.from == "" || len(ec.to) == 0 {
				ec.enabled = false
				ec.log.Warn("Sendmail邮件通知配置不完整，已禁用")
			} else {
				ec.log.Info("Sendmail邮件通知渠道已从配置启用")
			}
		case "resend":
			if ec.resendAPIKey == "" || ec.resendFrom == "" || ec.resendTo == "" {
				ec.enabled = false
				ec.log.Warn("Resend邮件通知配置不完整，已禁用")
			} else {
				ec.log.Info("Resend邮件通知渠道已从配置启用")
			}
		case "mailgun":
			if ec.mailgunAPIKey == "" || ec.mailgunDomain == "" || ec.mailgunFrom == "" || ec.mailgunTo == "" {
				ec.enabled = false
				ec.log.Warn("Mailgun邮件通知配置不完整，已禁用")
			} else {
				ec.log.Info("Mailgun邮件通知渠道已从配置启用")
			}
		case "sendgrid":
			if ec.sendgridAPIKey == "" || ec.sendgridFrom == "" || ec.sendgridTo == "" {
				ec.enabled = false
				ec.log.Warn("SendGrid邮件通知配置不完整，已禁用")
			} else {
				ec.log.Info("SendGrid邮件通知渠道已从配置启用")
			}
		default:
			ec.enabled = false
			ec.log.Warnf("不支持的邮件发送方式: %s", ec.method)
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

	// 根据配置的发送方式发送邮件
	switch ec.method {
	case "smtp":
		return ec.sendEmailSMTP(ec.to, subject, body)
	case "sendmail":
		return ec.sendEmailSendmail(ec.to, subject, body)
	case "resend":
		return ec.sendEmailResend(ec.resendTo, subject, body)
	case "mailgun":
		return ec.sendEmailMailgun(ec.mailgunTo, subject, body)
	case "sendgrid":
		return ec.sendEmailSendGrid(ec.sendgridTo, subject, body)
	default:
		return fmt.Errorf("不支持的邮件发送方式: %s", ec.method)
	}
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

// sendEmailSMTP 通过SMTP发送邮件
func (ec *EmailChannel) sendEmailSMTP(to []string, subject, body string) error {
	addr := ec.smtpHost + ":" + ec.smtpPort

	// 创建带超时的连接
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("连接SMTP服务器失败: %v", err)
	}
	defer conn.Close()

	// 设置总超时（30秒）
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// 创建SMTP客户端
	client, err := smtp.NewClient(conn, ec.smtpHost)
	if err != nil {
		return fmt.Errorf("创建SMTP客户端失败: %v", err)
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

// sendEmailSendmail 通过系统sendmail发送邮件
func (ec *EmailChannel) sendEmailSendmail(to []string, subject, body string) error {
	// 构建邮件内容
	message := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		ec.from, strings.Join(to, ","), subject, body)

	// 执行sendmail命令
	cmd := exec.Command(ec.sendmailCommand, strings.Fields(ec.sendmailArgs)...)
	cmd.Stdin = strings.NewReader(message)
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sendmail执行失败: %v, 输出: %s", err, string(output))
	}

	ec.log.Infof("邮件已通过sendmail发送到: %s", strings.Join(to, ","))
	return nil
}

// sendEmailResend 通过Resend API发送邮件
func (ec *EmailChannel) sendEmailResend(to, subject, body string) error {
	// 构建请求数据
	data := map[string]interface{}{
		"from":    ec.resendFrom,
		"to":      []string{to},
		"subject": subject,
		"text":    body,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("JSON序列化失败: %v", err)
	}

	// 发送HTTP请求
	req, err := http.NewRequest("POST", "https://api.resend.com/emails", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("创建请求失败: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+ec.resendAPIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Resend API错误: %d, %s", resp.StatusCode, string(body))
	}

	ec.log.Infof("邮件已通过Resend发送到: %s", to)
	return nil
}

// sendEmailMailgun 通过Mailgun API发送邮件
func (ec *EmailChannel) sendEmailMailgun(to, subject, body string) error {
	// 构建表单数据
	data := url.Values{}
	data.Set("from", ec.mailgunFrom)
	data.Set("to", to)
	data.Set("subject", subject)
	data.Set("text", body)

	// 发送HTTP请求
	req, err := http.NewRequest("POST", fmt.Sprintf("https://api.mailgun.net/v3/%s/messages", ec.mailgunDomain), strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("创建请求失败: %v", err)
	}

	req.SetBasicAuth("api", ec.mailgunAPIKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Mailgun API错误: %d, %s", resp.StatusCode, string(body))
	}

	ec.log.Infof("邮件已通过Mailgun发送到: %s", to)
	return nil
}

// sendEmailSendGrid 通过SendGrid API发送邮件
func (ec *EmailChannel) sendEmailSendGrid(to, subject, body string) error {
	// 构建请求数据
	data := map[string]interface{}{
		"personalizations": []map[string]interface{}{
			{
				"to": []map[string]string{
					{"email": to},
				},
			},
		},
		"from": map[string]string{
			"email": ec.sendgridFrom,
		},
		"subject": subject,
		"content": []map[string]string{
			{
				"type":  "text/plain",
				"value": body,
			},
		},
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("JSON序列化失败: %v", err)
	}

	// 发送HTTP请求
	req, err := http.NewRequest("POST", "https://api.sendgrid.com/v3/mail/send", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("创建请求失败: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+ec.sendgridAPIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("SendGrid API错误: %d, %s", resp.StatusCode, string(body))
	}

	ec.log.Infof("邮件已通过SendGrid发送到: %s", to)
	return nil
}

// WebhookChannel Webhook通知渠道
type WebhookChannel struct {
	enabled bool
	urls    []string
	url     string // 向后兼容
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

	// 处理URLs数组和单个URL的兼容性
	urls := cfg.URLs
	if len(urls) == 0 && cfg.URL != "" {
		urls = []string{cfg.URL}
	}

	whc := &WebhookChannel{
		enabled: cfg.Enabled && len(urls) > 0,
		urls:    urls,
		url:     cfg.URL, // 向后兼容
		headers: cfg.Headers,
		client:  &http.Client{Timeout: time.Duration(timeout) * time.Second},
		log:     logrus.WithFields(logrus.Fields{"component": "webhook_channel"}),
	}

	if whc.headers == nil {
		whc.headers = make(map[string]string)
	}

	if whc.enabled {
		whc.log.Infof("Webhook通知渠道已从配置启用，共 %d 个URL", len(urls))
	}

	return whc
}

// Send 发送Webhook通知
func (whc *WebhookChannel) Send(notification *Notification) error {
	if !whc.enabled {
		return nil
	}

	// 确定要发送的URL列表
	urls := whc.urls
	if len(urls) == 0 && whc.url != "" {
		urls = []string{whc.url}
	}

	var errors []string
	successCount := 0

	// 向所有URL发送通知
	for _, url := range urls {
		if url == "" {
			continue
		}

		err := whc.sendToURL(url, notification)
		if err != nil {
			errors = append(errors, fmt.Sprintf("URL %s: %v", url, err))
		} else {
			successCount++
		}
	}

	// 记录发送结果
	if len(errors) > 0 {
		whc.log.Warnf("Webhook通知发送部分失败: %d/%d 成功, 错误: %v",
			successCount, len(urls), errors)
		if successCount == 0 {
			return fmt.Errorf("所有Webhook发送失败: %v", errors)
		}
	} else {
		whc.log.Infof("Webhook通知已发送到 %d 个URL", successCount)
	}

	return nil
}

// sendToURL 向指定URL发送通知
func (whc *WebhookChannel) sendToURL(url string, notification *Notification) error {
	// 获取平台适配器
	adapter := GetPlatformAdapter(url)

	// 使用适配器转换消息格式
	jsonData, err := adapter.Adapt(notification)
	if err != nil {
		return fmt.Errorf("适配通知格式失败: %v", err)
	}

	// 创建HTTP请求
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("创建HTTP请求失败: %v", err)
	}

	// 设置适配器指定的Content-Type
	req.Header.Set("Content-Type", adapter.GetContentType())

	// 设置适配器的默认头部
	for key, value := range adapter.GetHeaders() {
		req.Header.Set(key, value)
	}

	// 设置自定义头部（覆盖默认头部）
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

	// 检测平台类型用于日志
	platform := DetectPlatform(url)
	whc.log.Debugf("Webhook通知已发送到 %s 平台: %s", platform, url)
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

// getEnvOrDefault 获取环境变量，如果不存在则返回默认值
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

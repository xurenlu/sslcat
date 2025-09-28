package waf

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// BlockActionHandler 阻止动作处理器
type BlockActionHandler struct{}

func (h *BlockActionHandler) Handle(action RuleAction, event *AttackEvent, w http.ResponseWriter, r *http.Request) error {
	if w == nil {
		return nil // 如果没有ResponseWriter，只记录事件
	}

	statusCode := http.StatusForbidden
	if code, exists := action.Parameters["status_code"]; exists {
		if parsed, err := strconv.Atoi(code); err == nil {
			statusCode = parsed
		}
	}

	message := "Request blocked by WAF"
	if action.Message != "" {
		message = action.Message
	}

	w.WriteHeader(statusCode)
	w.Write([]byte(message))

	logrus.WithFields(logrus.Fields{
		"rule_id":   event.RuleID,
		"client_ip": event.ClientIP,
		"url":       event.URL,
	}).Warn("WAF blocked request")

	return nil
}

func (h *BlockActionHandler) GetName() string {
	return "block"
}

// AllowActionHandler 允许动作处理器
type AllowActionHandler struct{}

func (h *AllowActionHandler) Handle(action RuleAction, event *AttackEvent, w http.ResponseWriter, r *http.Request) error {
	// 允许动作通常只是记录日志，不做其他操作
	logrus.WithFields(logrus.Fields{
		"rule_id":   event.RuleID,
		"client_ip": event.ClientIP,
		"url":       event.URL,
	}).Info("WAF explicitly allowed request")

	return nil
}

func (h *AllowActionHandler) GetName() string {
	return "allow"
}

// LogActionHandler 日志动作处理器
type LogActionHandler struct{}

func (h *LogActionHandler) Handle(action RuleAction, event *AttackEvent, w http.ResponseWriter, r *http.Request) error {
	level := "info"
	if l, exists := action.Parameters["level"]; exists {
		level = l
	}

	fields := logrus.Fields{
		"rule_id":    event.RuleID,
		"rule_name":  event.RuleName,
		"rule_type":  event.RuleType,
		"client_ip":  event.ClientIP,
		"user_agent": event.UserAgent,
		"url":        event.URL,
		"method":     event.Method,
		"payload":    event.Payload,
	}

	message := "WAF rule triggered"
	if action.Message != "" {
		message = action.Message
	}

	switch level {
	case "debug":
		logrus.WithFields(fields).Debug(message)
	case "info":
		logrus.WithFields(fields).Info(message)
	case "warn":
		logrus.WithFields(fields).Warn(message)
	case "error":
		logrus.WithFields(fields).Error(message)
	case "high", "critical":
		logrus.WithFields(fields).Error(message)
	default:
		logrus.WithFields(fields).Info(message)
	}

	return nil
}

func (h *LogActionHandler) GetName() string {
	return "log"
}

// RedirectActionHandler 重定向动作处理器
type RedirectActionHandler struct{}

func (h *RedirectActionHandler) Handle(action RuleAction, event *AttackEvent, w http.ResponseWriter, r *http.Request) error {
	if w == nil {
		return nil
	}

	url := action.Parameters["url"]
	if url == "" {
		url = "/blocked"
	}

	statusCode := http.StatusFound
	if code, exists := action.Parameters["status_code"]; exists {
		if parsed, err := strconv.Atoi(code); err == nil {
			statusCode = parsed
		}
	}

	http.Redirect(w, r, url, statusCode)

	logrus.WithFields(logrus.Fields{
		"rule_id":     event.RuleID,
		"client_ip":   event.ClientIP,
		"redirect_to": url,
	}).Info("WAF redirected request")

	return nil
}

func (h *RedirectActionHandler) GetName() string {
	return "redirect"
}

// RateLimitActionHandler 限流动作处理器
type RateLimitActionHandler struct {
	limiters map[string]*TokenBucket
	mutex    sync.RWMutex
}

func (h *RateLimitActionHandler) Handle(action RuleAction, event *AttackEvent, w http.ResponseWriter, r *http.Request) error {
	if h.limiters == nil {
		h.limiters = make(map[string]*TokenBucket)
	}

	// 解析限流参数
	rateStr := action.Parameters["rate"]
	if rateStr == "" {
		rateStr = "10" // 默认每秒10个请求
	}

	rate, err := strconv.Atoi(rateStr)
	if err != nil {
		rate = 10
	}

	burstStr := action.Parameters["burst"]
	if burstStr == "" {
		burstStr = "20" // 默认突发20个
	}

	burst, err := strconv.Atoi(burstStr)
	if err != nil {
		burst = 20
	}

	// 获取限流器
	key := fmt.Sprintf("%s:%s", event.ClientIP, event.RuleID)

	h.mutex.Lock()
	limiter, exists := h.limiters[key]
	if !exists {
		limiter = NewTokenBucket(rate, burst)
		h.limiters[key] = limiter
	}
	h.mutex.Unlock()

	// 检查是否允许请求
	if !limiter.Allow() {
		if w != nil {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		}

		logrus.WithFields(logrus.Fields{
			"rule_id":   event.RuleID,
			"client_ip": event.ClientIP,
			"rate":      rate,
			"burst":     burst,
		}).Warn("WAF rate limit exceeded")

		return fmt.Errorf("rate limit exceeded")
	}

	return nil
}

func (h *RateLimitActionHandler) GetName() string {
	return "rate_limit"
}

// CaptchaActionHandler 验证码动作处理器
type CaptchaActionHandler struct{}

func (h *CaptchaActionHandler) Handle(action RuleAction, event *AttackEvent, w http.ResponseWriter, r *http.Request) error {
	if w == nil {
		return nil
	}

	// 检查是否已经通过验证码验证
	if r.Header.Get("X-Captcha-Verified") == "true" {
		return nil
	}

	// 生成验证码页面
	captchaPage := h.generateCaptchaPage(action, event)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(captchaPage))

	logrus.WithFields(logrus.Fields{
		"rule_id":   event.RuleID,
		"client_ip": event.ClientIP,
	}).Info("WAF presented captcha challenge")

	return nil
}

func (h *CaptchaActionHandler) generateCaptchaPage(action RuleAction, event *AttackEvent) string {
	title := "安全验证"
	if t, exists := action.Parameters["title"]; exists {
		title = t
	}

	message := "请完成安全验证以继续访问"
	if action.Message != "" {
		message = action.Message
	}

	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>%s</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin-top: 100px; }
        .container { max-width: 400px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
        .message { margin-bottom: 20px; color: #666; }
        .captcha { margin: 20px 0; }
        button { padding: 10px 20px; background: #007cba; color: white; border: none; border-radius: 3px; cursor: pointer; }
        button:hover { background: #005a87; }
    </style>
</head>
<body>
    <div class="container">
        <h2>%s</h2>
        <p class="message">%s</p>
        <div class="captcha">
            <p>请点击下方按钮完成验证：</p>
            <button onclick="verifyCaptcha()">我不是机器人</button>
        </div>
    </div>
    
    <script>
        function verifyCaptcha() {
            // 简单的验证逻辑，实际应该更复杂
            document.cookie = "captcha_verified=true; path=/";
            location.reload();
        }
    </script>
</body>
</html>
`, title, title, message)
}

func (h *CaptchaActionHandler) GetName() string {
	return "captcha"
}

// TokenBucket 令牌桶限流器
type TokenBucket struct {
	rate     int       // 每秒令牌数
	burst    int       // 桶容量
	tokens   int       // 当前令牌数
	lastTime time.Time // 上次更新时间
	mutex    sync.Mutex
}

// NewTokenBucket 创建令牌桶
func NewTokenBucket(rate, burst int) *TokenBucket {
	return &TokenBucket{
		rate:     rate,
		burst:    burst,
		tokens:   burst,
		lastTime: time.Now(),
	}
}

// Allow 检查是否允许请求
func (tb *TokenBucket) Allow() bool {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastTime)

	// 添加令牌
	tokensToAdd := int(elapsed.Seconds()) * tb.rate
	tb.tokens += tokensToAdd
	if tb.tokens > tb.burst {
		tb.tokens = tb.burst
	}

	tb.lastTime = now

	// 消费令牌
	if tb.tokens > 0 {
		tb.tokens--
		return true
	}

	return false
}

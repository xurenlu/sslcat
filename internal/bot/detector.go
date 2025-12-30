package bot

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Detector 机器人检测器
type Detector struct {
	analyzer   *BehaviorAnalyzer
	whitelist  *WhitelistManager
	challenge  *ChallengeManager
	logger     *logrus.Entry
	mutex      sync.RWMutex
	enabled    bool
}

// DetectionResult 检测结果
type DetectionResult struct {
	IsBot         bool
	RiskScore     int
	NeedsChallenge bool
	Challenge     *Challenge
	Reason        string
	Action        string // "allow", "challenge", "block"
}

// BotDetectionConfig 机器人检测配置
type BotDetectionConfig struct {
	// 检测模式: "monitor"(仅记录) | "challenge"(验证)
	Mode string `json:"mode"`

	// 风险阈值
	LowRiskThreshold    int `json:"low_risk_threshold"`
	MediumRiskThreshold int `json:"medium_risk_threshold"`
	HighRiskThreshold   int `json:"high_risk_threshold"`

	// 频率限制
	MaxRequestsPerMinute int `json:"max_requests_per_minute"`
	MaxRequestsPerHour   int `json:"max_requests_per_hour"`

	// 白名单有效期(小时)
	WhitelistDuration int `json:"whitelist_duration"`

	// Token 有效期(小时)
	TokenDuration int `json:"token_duration"`

	// 跳过验证的路径
	SkipPaths []string `json:"skip_paths"`
}

// NewDetector 创建机器人检测器
func NewDetector(logger *logrus.Logger, whitelist *WhitelistManager, challenge *ChallengeManager) *Detector {
	return &Detector{
		analyzer:  NewBehaviorAnalyzer(logger),
		whitelist: whitelist,
		challenge: challenge,
		logger:    logger.WithField("component", "bot_detector"),
		enabled:   true,
	}
}

// CheckRequest 检查请求是否为机器人
func (d *Detector) CheckRequest(r *http.Request, config *BotDetectionConfig) (*DetectionResult, bool) {
	if !d.enabled || config == nil {
		return nil, false
	}

	// 获取客户端信息
	clientIP := d.getClientIP(r)
	userAgent := r.Header.Get("User-Agent")
	domain := r.Host

	// 检查是否在跳过路径列表中
	if d.shouldSkipPath(r.URL.Path, config.SkipPaths) {
		return &DetectionResult{
			IsBot:          false,
			RiskScore:      0,
			NeedsChallenge: false,
			Action:         "allow",
			Reason:         "skipped path",
		}, false
	}

	// 检查白名单
	if d.whitelist != nil && d.whitelist.IsWhitelisted(clientIP, domain) {
		d.logger.Debugf("IP %s is whitelisted for domain %s", clientIP, domain)
		return &DetectionResult{
			IsBot:          false,
			RiskScore:      0,
			NeedsChallenge: false,
			Action:         "allow",
			Reason:         "whitelisted",
		}, false
	}

	// 检查验证 Token
	if token := d.getVerificationToken(r); token != "" {
		if d.challenge != nil && d.challenge.VerifyToken(token, clientIP, userAgent) {
			d.logger.Debugf("Valid verification token for IP %s", clientIP)
			// Token 有效，添加到白名单
			if d.whitelist != nil {
				d.whitelist.Add(clientIP, domain, token, time.Duration(config.WhitelistDuration)*time.Hour)
			}
			return &DetectionResult{
				IsBot:          false,
				RiskScore:      0,
				NeedsChallenge: false,
				Action:         "allow",
				Reason:         "valid token",
			}, false
		}
	}

	// 行为分析
	riskScore := d.analyzer.AnalyzeRequest(r, config)

	result := &DetectionResult{
		RiskScore: riskScore,
		IsBot:     riskScore >= config.MediumRiskThreshold,
	}

	// 根据风险评分决定动作
	if riskScore < config.LowRiskThreshold {
		// 低风险，直接放行
		result.NeedsChallenge = false
		result.Action = "allow"
		result.Reason = "low risk"
	} else if riskScore < config.MediumRiskThreshold {
		// 中风险，检查是否有有效 Token
		result.NeedsChallenge = false
		result.Action = "allow"
		result.Reason = "medium risk but no challenge"
	} else if riskScore < config.HighRiskThreshold {
		// 中高风险，需要验证
		if config.Mode == "challenge" {
			result.NeedsChallenge = true
			result.Action = "challenge"
			result.Reason = fmt.Sprintf("risk score %d requires verification", riskScore)
			// 生成挑战
			if d.challenge != nil {
				challenge := d.challenge.GenerateChallenge(clientIP, domain)
				result.Challenge = challenge
			}
		} else {
			// 监控模式，仅记录
			result.NeedsChallenge = false
			result.Action = "monitor"
			result.Reason = fmt.Sprintf("risk score %d (monitor mode)", riskScore)
		}
	} else {
		// 高风险，强制验证或阻止
		if config.Mode == "challenge" {
			result.NeedsChallenge = true
			result.Action = "challenge"
			result.Reason = fmt.Sprintf("high risk score %d", riskScore)
			// 生成挑战
			if d.challenge != nil {
				challenge := d.challenge.GenerateChallenge(clientIP, domain)
				result.Challenge = challenge
			}
		} else {
			result.NeedsChallenge = false
			result.Action = "monitor"
			result.Reason = fmt.Sprintf("high risk score %d (monitor mode)", riskScore)
		}
	}

	d.logger.WithFields(logrus.Fields{
		"client_ip":  clientIP,
		"domain":     domain,
		"risk_score": riskScore,
		"action":     result.Action,
		"reason":     result.Reason,
	}).Info("Bot detection result")

	return result, result.NeedsChallenge
}

// getClientIP 获取客户端真实IP
func (d *Detector) getClientIP(r *http.Request) string {
	// 1. 检查 CF-Connecting-IP (Cloudflare)
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		return strings.TrimSpace(cfIP)
	}

	// 2. 检查 X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// 3. 检查 X-Forwarded-For (取第一个IP)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// 4. 使用 RemoteAddr
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}

	return r.RemoteAddr
}

// getVerificationToken 从请求中获取验证 Token
func (d *Detector) getVerificationToken(r *http.Request) string {
	// 优先从 Cookie 获取
	if cookie, err := r.Cookie("bot_verification"); err == nil {
		return cookie.Value
	}

	// 其次从 Header 获取
	return r.Header.Get("X-Bot-Verification")
}

// shouldSkipPath 检查路径是否应该跳过验证
func (d *Detector) shouldSkipPath(path string, skipPaths []string) bool {
	for _, skipPath := range skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// Enable 启用检测器
func (d *Detector) Enable() {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.enabled = true
}

// Disable 禁用检测器
func (d *Detector) Disable() {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.enabled = false
}

// IsEnabled 检查是否启用
func (d *Detector) IsEnabled() bool {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	return d.enabled
}

// GetStats 获取统计信息
func (d *Detector) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})

	if d.analyzer != nil {
		stats["analyzer"] = d.analyzer.GetStats()
	}

	if d.whitelist != nil {
		stats["whitelist_count"] = d.whitelist.Count()
	}

	if d.challenge != nil {
		stats["active_challenges"] = d.challenge.ActiveCount()
	}

	return stats
}

// hashString 计算字符串的 SHA256 哈希
func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

// DefaultConfig 返回默认配置
func DefaultConfig() *BotDetectionConfig {
	return &BotDetectionConfig{
		Mode:                 "monitor",
		LowRiskThreshold:     30,
		MediumRiskThreshold:  50,
		HighRiskThreshold:    70,
		MaxRequestsPerMinute: 60,
		MaxRequestsPerHour:   1000,
		WhitelistDuration:    168, // 7 天
		TokenDuration:        24,  // 24 小时
		SkipPaths:            []string{},
	}
}

// Common bot User-Agent patterns
var botUserAgentPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)bot`),
	regexp.MustCompile(`(?i)crawler`),
	regexp.MustCompile(`(?i)spider`),
	regexp.MustCompile(`(?i)scraper`),
	regexp.MustCompile(`(?i)curl`),
	regexp.MustCompile(`(?i)wget`),
	regexp.MustCompile(`(?i)python-requests`),
	regexp.MustCompile(`(?i)scrapy`),
	regexp.MustCompile(`(?i)selenium`),
	regexp.MustCompile(`(?i)phantomjs`),
	regexp.MustCompile(`(?i)headless`),
	regexp.MustCompile(`(?i)puppeteer`),
	regexp.MustCompile(`(?i)playwright`),
}

// IsKnownBot 检查 User-Agent 是否为已知机器人
func IsKnownBot(userAgent string) bool {
	if userAgent == "" {
		return true
	}

	for _, pattern := range botUserAgentPatterns {
		if pattern.MatchString(userAgent) {
			return true
		}
	}

	return false
}


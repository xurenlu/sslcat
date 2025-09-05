package ddos

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ProtectionLevel 防护级别
type ProtectionLevel int

const (
	LevelOff ProtectionLevel = iota
	LevelLow
	LevelMedium
	LevelHigh
	LevelExtreme
)

func (l ProtectionLevel) String() string {
	switch l {
	case LevelOff:
		return "off"
	case LevelLow:
		return "low"
	case LevelMedium:
		return "medium"
	case LevelHigh:
		return "high"
	case LevelExtreme:
		return "extreme"
	default:
		return "unknown"
	}
}

// ClientInfo 客户端信息
type ClientInfo struct {
	IP           string    `json:"ip"`
	RequestCount int       `json:"request_count"`
	LastRequest  time.Time `json:"last_request"`
	FirstRequest time.Time `json:"first_request"`
	BlockedUntil time.Time `json:"blocked_until"`
	UserAgent    string    `json:"user_agent"`
	RequestRate  float64   `json:"request_rate"`
	Suspicious   bool      `json:"suspicious"`
	BlockCount   int       `json:"block_count"`
}

// Attack 攻击信息
type Attack struct {
	ID         string    `json:"id"`
	ClientIP   string    `json:"client_ip"`
	UserAgent  string    `json:"user_agent"`
	URL        string    `json:"url"`
	Method     string    `json:"method"`
	AttackType string    `json:"attack_type"`
	Severity   string    `json:"severity"`
	Timestamp  time.Time `json:"timestamp"`
	Blocked    bool      `json:"blocked"`
	Reason     string    `json:"reason"`
}

// Protector DDoS防护器
type Protector struct {
	enabled         bool
	level           ProtectionLevel
	clients         map[string]*ClientInfo
	attacks         []Attack
	mutex           sync.RWMutex
	cleanupInterval time.Duration
	stopChan        chan struct{}

	// 配置参数
	maxRequestsPerMinute int
	maxRequestsPerHour   int
	blockDuration        time.Duration
	maxClients           int
	maxAttacks           int

	// 防护阈值
	thresholds map[ProtectionLevel]ThresholdConfig

	log *logrus.Entry
}

// ThresholdConfig 阈值配置
type ThresholdConfig struct {
	RequestsPerMinute int           `json:"requests_per_minute"`
	RequestsPerHour   int           `json:"requests_per_hour"`
	BlockDuration     time.Duration `json:"block_duration"`
	SuspiciousUA      bool          `json:"suspicious_ua"`
	GeoBlocking       bool          `json:"geo_blocking"`
	ChallengeMode     bool          `json:"challenge_mode"`
}

// NewProtector 创建DDoS防护器
func NewProtector() *Protector {
	p := &Protector{
		enabled:         true,
		level:           LevelMedium,
		clients:         make(map[string]*ClientInfo),
		attacks:         make([]Attack, 0),
		cleanupInterval: 5 * time.Minute,
		stopChan:        make(chan struct{}),
		blockDuration:   1 * time.Hour,
		maxClients:      10000,
		maxAttacks:      1000,
		log: logrus.WithFields(logrus.Fields{
			"component": "ddos_protector",
		}),
	}

	// 初始化阈值配置
	p.initThresholds()

	// 启动清理协程
	go p.cleanupRoutine()

	return p
}

// initThresholds 初始化阈值配置
func (p *Protector) initThresholds() {
	p.thresholds = map[ProtectionLevel]ThresholdConfig{
		LevelOff: {
			RequestsPerMinute: 0,
			RequestsPerHour:   0,
			BlockDuration:     0,
			SuspiciousUA:      false,
			GeoBlocking:       false,
			ChallengeMode:     false,
		},
		LevelLow: {
			RequestsPerMinute: 120,
			RequestsPerHour:   7200,
			BlockDuration:     10 * time.Minute,
			SuspiciousUA:      false,
			GeoBlocking:       false,
			ChallengeMode:     false,
		},
		LevelMedium: {
			RequestsPerMinute: 60,
			RequestsPerHour:   3600,
			BlockDuration:     30 * time.Minute,
			SuspiciousUA:      true,
			GeoBlocking:       false,
			ChallengeMode:     false,
		},
		LevelHigh: {
			RequestsPerMinute: 30,
			RequestsPerHour:   1800,
			BlockDuration:     1 * time.Hour,
			SuspiciousUA:      true,
			GeoBlocking:       true,
			ChallengeMode:     true,
		},
		LevelExtreme: {
			RequestsPerMinute: 10,
			RequestsPerHour:   600,
			BlockDuration:     4 * time.Hour,
			SuspiciousUA:      true,
			GeoBlocking:       true,
			ChallengeMode:     true,
		},
	}
}

// CheckRequest 检查请求
func (p *Protector) CheckRequest(r *http.Request) (bool, string) {
	if !p.enabled || p.level == LevelOff {
		return false, ""
	}

	clientIP := p.getClientIP(r)
	userAgent := r.Header.Get("User-Agent")
	now := time.Now()

	p.mutex.Lock()
	defer p.mutex.Unlock()

	// 获取或创建客户端信息
	client, exists := p.clients[clientIP]
	if !exists {
		client = &ClientInfo{
			IP:           clientIP,
			RequestCount: 0,
			FirstRequest: now,
			UserAgent:    userAgent,
		}
		p.clients[clientIP] = client
	}

	// 检查是否已被封禁
	if now.Before(client.BlockedUntil) {
		p.recordAttack(clientIP, userAgent, r.URL.String(), r.Method,
			"rate_limit", "high", "IP仍在封禁期内", true)
		return true, "IP已被封禁"
	}

	// 更新客户端信息
	client.RequestCount++
	client.LastRequest = now

	// 计算请求速率
	duration := now.Sub(client.FirstRequest)
	if duration > 0 {
		client.RequestRate = float64(client.RequestCount) / duration.Minutes()
	}

	// 获取当前阈值配置
	threshold := p.thresholds[p.level]

	// 检查请求频率
	if blocked, reason := p.checkRateLimit(client, threshold, now); blocked {
		p.blockClient(client, threshold.BlockDuration, now)
		p.recordAttack(clientIP, userAgent, r.URL.String(), r.Method,
			"rate_limit", "high", reason, true)
		return true, reason
	}

	// 检查可疑User-Agent
	if threshold.SuspiciousUA && p.isSuspiciousUserAgent(userAgent) {
		p.recordAttack(clientIP, userAgent, r.URL.String(), r.Method,
			"suspicious_ua", "medium", "可疑的User-Agent", false)
		client.Suspicious = true
	}

	// 检查请求模式
	if p.isSuspiciousPattern(r, client) {
		p.recordAttack(clientIP, userAgent, r.URL.String(), r.Method,
			"suspicious_pattern", "medium", "可疑的请求模式", false)
		client.Suspicious = true
	}

	return false, ""
}

// checkRateLimit 检查请求频率限制
func (p *Protector) checkRateLimit(client *ClientInfo, threshold ThresholdConfig, now time.Time) (bool, string) {
	// 检查每分钟请求数
	if threshold.RequestsPerMinute > 0 {
		minuteAgo := now.Add(-time.Minute)
		if client.LastRequest.After(minuteAgo) && client.RequestRate > float64(threshold.RequestsPerMinute) {
			return true, "每分钟请求数超限"
		}
	}

	// 检查每小时请求数
	if threshold.RequestsPerHour > 0 {
		hourAgo := now.Add(-time.Hour)
		if client.FirstRequest.After(hourAgo) && client.RequestCount > threshold.RequestsPerHour {
			return true, "每小时请求数超限"
		}
	}

	return false, ""
}

// blockClient 封禁客户端
func (p *Protector) blockClient(client *ClientInfo, duration time.Duration, now time.Time) {
	client.BlockedUntil = now.Add(duration)
	client.BlockCount++

	p.log.Warnf("封禁客户端 %s，持续时间: %v，封禁次数: %d",
		client.IP, duration, client.BlockCount)
}

// isSuspiciousUserAgent 检查是否为可疑User-Agent
func (p *Protector) isSuspiciousUserAgent(userAgent string) bool {
	if userAgent == "" {
		return true
	}

	// 检查常见的恶意User-Agent
	suspicious := []string{
		"bot", "crawler", "spider", "scraper", "scan", "hack", "attack",
		"sql", "injection", "exploit", "payload", "shell",
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, keyword := range suspicious {
		if strings.Contains(userAgentLower, keyword) {
			return true
		}
	}

	// 检查是否为正常浏览器User-Agent
	browsers := []string{
		"mozilla", "chrome", "safari", "firefox", "edge", "opera",
	}

	for _, browser := range browsers {
		if strings.Contains(userAgentLower, browser) {
			return false
		}
	}

	// 如果不包含常见浏览器标识，可能是可疑的
	return len(userAgent) < 20 || len(userAgent) > 500
}

// isSuspiciousPattern 检查是否为可疑请求模式
func (p *Protector) isSuspiciousPattern(r *http.Request, client *ClientInfo) bool {
	url := r.URL.String()

	// 检查路径遍历攻击
	if strings.Contains(url, "../") || strings.Contains(url, "..\\") {
		return true
	}

	// 检查SQL注入尝试
	sqlKeywords := []string{
		"union", "select", "insert", "delete", "drop", "update",
		"or 1=1", "and 1=1", "' or '", "\" or \"",
	}

	urlLower := strings.ToLower(url)
	for _, keyword := range sqlKeywords {
		if strings.Contains(urlLower, keyword) {
			return true
		}
	}

	// 检查异常请求频率
	if client.RequestRate > 10 { // 每分钟超过10个请求
		return true
	}

	return false
}

// recordAttack 记录攻击
func (p *Protector) recordAttack(clientIP, userAgent, url, method, attackType, severity, reason string, blocked bool) {
	attack := Attack{
		ID:         p.generateAttackID(),
		ClientIP:   clientIP,
		UserAgent:  userAgent,
		URL:        url,
		Method:     method,
		AttackType: attackType,
		Severity:   severity,
		Timestamp:  time.Now(),
		Blocked:    blocked,
		Reason:     reason,
	}

	p.attacks = append(p.attacks, attack)

	// 保持攻击记录数量限制
	if len(p.attacks) > p.maxAttacks {
		p.attacks = p.attacks[1:]
	}

	if blocked {
		p.log.Warnf("DDoS攻击已阻止: %s from %s, 原因: %s", attackType, clientIP, reason)
	} else {
		p.log.Infof("检测到可疑活动: %s from %s, 原因: %s", attackType, clientIP, reason)
	}
}

// generateAttackID 生成攻击ID
func (p *Protector) generateAttackID() string {
	return fmt.Sprintf("ddos_%d", time.Now().UnixNano())
}

// getClientIP 获取客户端IP
func (p *Protector) getClientIP(r *http.Request) string {
	// 检查X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// 检查X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// 使用RemoteAddr
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}

	return r.RemoteAddr
}

// cleanupRoutine 清理协程
func (p *Protector) cleanupRoutine() {
	ticker := time.NewTicker(p.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanup()
		case <-p.stopChan:
			return
		}
	}
}

// cleanup 清理过期数据
func (p *Protector) cleanup() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	now := time.Now()

	// 清理过期的客户端记录
	for ip, client := range p.clients {
		// 如果客户端1小时内没有请求，且没有被封禁，则删除记录
		if now.Sub(client.LastRequest) > time.Hour && now.After(client.BlockedUntil) {
			delete(p.clients, ip)
		}
	}

	// 清理旧的攻击记录（保留24小时）
	cutoff := now.Add(-24 * time.Hour)
	newAttacks := make([]Attack, 0)
	for _, attack := range p.attacks {
		if attack.Timestamp.After(cutoff) {
			newAttacks = append(newAttacks, attack)
		}
	}
	p.attacks = newAttacks

	p.log.Debugf("清理完成，当前客户端数: %d，攻击记录数: %d",
		len(p.clients), len(p.attacks))
}

// SetEnabled 设置启用状态
func (p *Protector) SetEnabled(enabled bool) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.enabled = enabled
	p.log.Infof("DDoS防护已%s", map[bool]string{true: "启用", false: "禁用"}[enabled])
}

// SetLevel 设置防护级别
func (p *Protector) SetLevel(level ProtectionLevel) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.level = level
	p.log.Infof("DDoS防护级别已设置为: %s", level.String())
}

// GetStats 获取统计信息
func (p *Protector) GetStats() map[string]interface{} {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	blockedClients := 0
	suspiciousClients := 0
	now := time.Now()

	for _, client := range p.clients {
		if now.Before(client.BlockedUntil) {
			blockedClients++
		}
		if client.Suspicious {
			suspiciousClients++
		}
	}

	attacksByType := make(map[string]int)
	blockedAttacks := 0

	for _, attack := range p.attacks {
		attacksByType[attack.AttackType]++
		if attack.Blocked {
			blockedAttacks++
		}
	}

	return map[string]interface{}{
		"enabled":            p.enabled,
		"level":              p.level.String(),
		"total_clients":      len(p.clients),
		"blocked_clients":    blockedClients,
		"suspicious_clients": suspiciousClients,
		"total_attacks":      len(p.attacks),
		"blocked_attacks":    blockedAttacks,
		"attacks_by_type":    attacksByType,
		"thresholds":         p.thresholds[p.level],
	}
}

// GetClients 获取客户端信息
func (p *Protector) GetClients(limit int) map[string]*ClientInfo {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	result := make(map[string]*ClientInfo)
	count := 0

	for ip, client := range p.clients {
		if count >= limit {
			break
		}

		result[ip] = &ClientInfo{
			IP:           client.IP,
			RequestCount: client.RequestCount,
			LastRequest:  client.LastRequest,
			FirstRequest: client.FirstRequest,
			BlockedUntil: client.BlockedUntil,
			UserAgent:    client.UserAgent,
			RequestRate:  client.RequestRate,
			Suspicious:   client.Suspicious,
			BlockCount:   client.BlockCount,
		}
		count++
	}

	return result
}

// GetAttacks 获取攻击记录
func (p *Protector) GetAttacks(limit int) []Attack {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	if limit <= 0 || limit > len(p.attacks) {
		limit = len(p.attacks)
	}

	// 返回最新的攻击记录
	start := len(p.attacks) - limit
	return p.attacks[start:]
}

// UnblockIP 解除IP封禁
func (p *Protector) UnblockIP(ip string) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if client, exists := p.clients[ip]; exists {
		client.BlockedUntil = time.Time{}
		p.log.Infof("手动解除IP封禁: %s", ip)
		return true
	}

	return false
}

// BlockIP 手动封禁IP
func (p *Protector) BlockIP(ip string, duration time.Duration, reason string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	now := time.Now()
	client, exists := p.clients[ip]
	if !exists {
		client = &ClientInfo{
			IP:           ip,
			FirstRequest: now,
		}
		p.clients[ip] = client
	}

	client.BlockedUntil = now.Add(duration)
	client.BlockCount++

	p.recordAttack(ip, "", "", "", "manual", "high", reason, true)
	p.log.Warnf("手动封禁IP: %s，持续时间: %v，原因: %s", ip, duration, reason)
}

// Stop 停止防护器
func (p *Protector) Stop() {
	p.log.Info("停止DDoS防护器")
	close(p.stopChan)
}

package ddos

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/logger"
	"github.com/xurenlu/sslcat/internal/notification"
	"github.com/xurenlu/sslcat/internal/security"
	"github.com/xurenlu/sslcat/internal/threatintel"
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
	// 滑动窗口：记录每个请求的时间戳
	RequestTimestamps []time.Time `json:"-"`
}

// Attack 攻击信息
type Attack struct {
	ID          string    `json:"id"`
	ClientIP    string    `json:"client_ip"`
	UserAgent   string    `json:"user_agent"`
	URL         string    `json:"url"`
	Method      string    `json:"method"`
	AttackType  string    `json:"attack_type"`
	Severity    string    `json:"severity"`
	Timestamp   time.Time `json:"timestamp"`
	Blocked     bool      `json:"blocked"`
	Reason      string    `json:"reason"`
	Country     string    `json:"country,omitempty"`      // 国家
	CountryCode string    `json:"country_code,omitempty"` // 国家代码
	ISP         string    `json:"isp,omitempty"`          // ISP/组织
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
	// 持久化轮转
	rotator *logger.Rotator
	// 通知集成器
	notificationIntegrator *notification.NotificationIntegrator
	// 威胁情报检测器
	threatDetector *threatintel.ThreatDetector
	// GeoIP 服务
	geoIPService *security.GeoIPService
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
func NewProtector(notificationIntegrator *notification.NotificationIntegrator) *Protector {
	return NewProtectorWithThreatIntel(notificationIntegrator, nil)
}

// NewProtectorWithThreatIntel 创建带威胁情报的 DDoS防护器
func NewProtectorWithThreatIntel(notificationIntegrator *notification.NotificationIntegrator, threatDetector *threatintel.ThreatDetector) *Protector {
	p := &Protector{
		enabled:                true,
		level:                  LevelMedium,
		clients:                make(map[string]*ClientInfo),
		attacks:                make([]Attack, 0),
		cleanupInterval:        5 * time.Minute,
		stopChan:               make(chan struct{}),
		blockDuration:          1 * time.Hour,
		maxClients:             10000,
		maxAttacks:             1000,
		notificationIntegrator: notificationIntegrator,
		log: logrus.WithFields(logrus.Fields{
			"component": "ddos_protector",
		}),
	}

	// 初始化阈值配置
	p.initThresholds()

	// 启动清理协程
	go p.cleanupRoutine()

	// 初始化轮转器（10MB*10）
	if rot, err := logger.NewRotator("./data/ddos_attacks.log", 10*1024*1024, 10); err == nil {
		p.rotator = rot
	}

	// 设置威胁检测器（如果有）
	if threatDetector != nil {
		p.threatDetector = threatDetector
	}

	return p
}

// SetGeoIPService 设置 GeoIP 服务
func (p *Protector) SetGeoIPService(geoIPService *security.GeoIPService) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.geoIPService = geoIPService
	p.log.Info("已设置 GeoIP 服务到 DDoS 防护器")
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
			RequestsPerMinute: 1200,
			RequestsPerHour:   72000,
			BlockDuration:     10 * time.Minute,
			SuspiciousUA:      false,
			GeoBlocking:       false,
			ChallengeMode:     false,
		},
		LevelMedium: {
			RequestsPerMinute: 3000,            // 提高到每分钟3000次（50次/秒）
			RequestsPerHour:   180000,          // 提高到每小时18万次
			BlockDuration:     5 * time.Minute, // 缩短封禁时间
			SuspiciousUA:      false,           // 关闭可疑UA检测，避免误判
			GeoBlocking:       false,
			ChallengeMode:     false,
		},
		LevelHigh: {
			RequestsPerMinute: 300,
			RequestsPerHour:   18000,
			BlockDuration:     1 * time.Hour,
			SuspiciousUA:      true,
			GeoBlocking:       true,
			ChallengeMode:     true,
		},
		LevelExtreme: {
			RequestsPerMinute: 100,
			RequestsPerHour:   6000,
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
			IP:                clientIP,
			RequestCount:      0,
			FirstRequest:      now,
			UserAgent:         userAgent,
			RequestTimestamps: make([]time.Time, 0),
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

	// 添加当前请求时间戳到滑动窗口
	client.RequestTimestamps = append(client.RequestTimestamps, now)

	// 清理滑动窗口：移除1小时前的请求记录（保留足够长的历史用于每小时限制检查）
	cutoffTime := now.Add(-time.Hour)
	validTimestamps := make([]time.Time, 0, len(client.RequestTimestamps))
	for _, ts := range client.RequestTimestamps {
		if ts.After(cutoffTime) {
			validTimestamps = append(validTimestamps, ts)
		}
	}
	client.RequestTimestamps = validTimestamps

	// 计算请求速率（使用滑动窗口）
	duration := now.Sub(client.FirstRequest)
	if duration > 0 {
		client.RequestRate = float64(client.RequestCount) / duration.Minutes()
	}

	// 获取当前阈值配置
	threshold := p.thresholds[p.level]

	// 对静态资源路径放宽限制（提高阈值）
	isStaticResource := p.isStaticResourcePath(r.URL.Path)
	if isStaticResource {
		// 对于静态资源，阈值提高5倍
		threshold.RequestsPerMinute *= 5
		threshold.RequestsPerHour *= 5
	}

	// 使用威胁情报检测（如果可用）
	if p.threatDetector != nil {
		threatResult := p.threatDetector.CheckRequest(r)
		if threatResult.IsThreat {
			// 根据威胁等级决定是否封禁
			shouldBlock := threatResult.ThreatLevel >= threatintel.ThreatLevelHigh
			severity := threatResult.ThreatLevel.String()

			if shouldBlock {
				p.blockClient(client, threshold.BlockDuration, now)
			}

			p.recordAttack(clientIP, userAgent, r.URL.String(), r.Method,
				"threat_intel", severity, fmt.Sprintf("威胁情报检测: %s (置信度: %.2f)", threatResult.Description, threatResult.Confidence), shouldBlock)
			client.Suspicious = true

			if shouldBlock {
				return true, fmt.Sprintf("威胁情报检测: %s", threatResult.Description)
			}
		}
	}

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

// isStaticResourcePath 判断是否为静态资源路径，应该放宽限制
func (p *Protector) isStaticResourcePath(urlPath string) bool {
	staticPrefixes := []string{
		"/_next/",        // Next.js 静态资源
		"/static/",       // 通用静态资源
		"/assets/",       // 资产文件
		"/public/",       // 公开资源
		"/.well-known/",  // 验证文件
		"/favicon.ico",   // 网站图标
		"/robots.txt",    // 爬虫文件
		"/sitemap.xml",   // 站点地图
		"/sw.js",         // Service Worker
		"/manifest.json", // PWA Manifest
	}

	// 检查常见静态资源扩展名
	staticExtensions := []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
		".woff", ".woff2", ".ttf", ".eot", ".webp", ".avif",
		".map", // source maps
	}

	urlLower := strings.ToLower(urlPath)

	// 检查路径前缀
	for _, prefix := range staticPrefixes {
		if strings.HasPrefix(urlLower, prefix) {
			return true
		}
	}

	// 检查文件扩展名
	for _, ext := range staticExtensions {
		if strings.HasSuffix(urlLower, ext) {
			return true
		}
	}

	return false
}

// checkRateLimit 检查请求频率限制
func (p *Protector) checkRateLimit(client *ClientInfo, threshold ThresholdConfig, now time.Time) (bool, string) {
	// 检查每分钟请求数 - 使用真正的滑动窗口统计
	if threshold.RequestsPerMinute > 0 {
		minuteAgo := now.Add(-time.Minute)

		// 统计最近1分钟内的实际请求数
		requestsInLastMinute := 0
		for _, ts := range client.RequestTimestamps {
			if ts.After(minuteAgo) {
				requestsInLastMinute++
			}
		}

		// 只有当最近1分钟的请求数超过阈值时才拦截
		if requestsInLastMinute > threshold.RequestsPerMinute {
			return true, fmt.Sprintf("每分钟请求数超限: %d > %d", requestsInLastMinute, threshold.RequestsPerMinute)
		}
	}

	// 检查每小时请求数 - 也使用滑动窗口统计
	if threshold.RequestsPerHour > 0 {
		hourAgo := now.Add(-time.Hour)

		// 统计最近1小时内的实际请求数
		requestsInLastHour := 0
		for _, ts := range client.RequestTimestamps {
			if ts.After(hourAgo) {
				requestsInLastHour++
			}
		}

		if requestsInLastHour > threshold.RequestsPerHour {
			return true, fmt.Sprintf("每小时请求数超限: %d > %d", requestsInLastHour, threshold.RequestsPerHour)
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

	// 检查异常请求频率 - 放宽阈值
	if client.RequestRate > 120 { // 每分钟超过120个请求（2次/秒）
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

	// 查询 GeoIP 信息
	if p.geoIPService != nil {
		if geoLoc, err := p.geoIPService.GetLocation(clientIP); err == nil && geoLoc != nil {
			attack.Country = geoLoc.Country
			attack.CountryCode = geoLoc.CountryCode
			attack.ISP = geoLoc.ISP
		}
	}

	p.attacks = append(p.attacks, attack)

	// JSON Lines 持久化（优先轮转器）
	rec := map[string]any{
		"time":     attack.Timestamp.Format(time.RFC3339),
		"id":       attack.ID,
		"ip":       attack.ClientIP,
		"ua":       attack.UserAgent,
		"url":      attack.URL,
		"method":   attack.Method,
		"type":     attack.AttackType,
		"severity": attack.Severity,
		"blocked":  attack.Blocked,
		"reason":   attack.Reason,
	}

	// 添加 GeoIP 信息到日志
	if attack.Country != "" {
		rec["country"] = attack.Country
	}
	if attack.CountryCode != "" {
		rec["country_code"] = attack.CountryCode
	}
	if attack.ISP != "" {
		rec["isp"] = attack.ISP
	}
	if b, err := json.Marshal(rec); err == nil {
		if p.rotator != nil {
			_, _ = p.rotator.Write(append(b, '\n'))
		} else {
			_ = os.MkdirAll("./data", 0755)
			if f, err := os.OpenFile("./data/ddos_attacks.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
				_, _ = f.Write(append(b, '\n'))
				_ = f.Close()
			}
		}
	}

	// 保持攻击记录数量限制
	if len(p.attacks) > p.maxAttacks {
		p.attacks = p.attacks[1:]
	}

	// 发送攻击通知
	if p.notificationIntegrator != nil {
		attackInfo := &notification.AttackInfo{
			ClientIP:  clientIP,
			UserAgent: userAgent,
			URL:       url,
			Reason:    reason,
			Severity:  severity,
			Blocked:   blocked,
		}
		p.notificationIntegrator.SendDDoSAttackNotification(attackInfo)
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

	// 统计真实的总攻击数（从日志文件）
	totalAttacksAll := p.getTotalAttacksFromFile()

	return map[string]interface{}{
		"enabled":            p.enabled,
		"level":              p.level.String(),
		"total_clients":      len(p.clients),
		"blocked_clients":    blockedClients,
		"suspicious_clients": suspiciousClients,
		"recent_attacks":     len(p.attacks),  // 内存中最近的攻击
		"total_attacks":      totalAttacksAll, // 真实的总攻击数
		"blocked_attacks":    blockedAttacks,
		"attacks_by_type":    attacksByType,
		"thresholds":         p.thresholds[p.level],
	}
}

// getTotalAttacksFromFile 从日志文件统计真实的总攻击数
func (p *Protector) getTotalAttacksFromFile() int {
	path := "./data/ddos_attacks.log"

	// 尝试打开文件
	f, err := os.Open(path)
	if err != nil {
		// 文件不存在或无法打开，返回内存中的数量
		return len(p.attacks)
	}
	defer f.Close()

	// 统计非空行数
	count := 0
	data, err := os.ReadFile(path)
	if err != nil {
		return len(p.attacks)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}

	return count
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

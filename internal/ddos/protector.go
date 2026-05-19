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

// max 返回两个整数中的最大值
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

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
	stopOnce        sync.Once
	attackQueue     chan attackRecord

	// 配置参数
	maxRequestsPerMinute int
	maxRequestsPerHour   int
	blockDuration        time.Duration
	maxClients           int
	maxAttacks           int

	// 防护阈值
	thresholds map[ProtectionLevel]ThresholdConfig
	// 自定义5分钟阈值（如果设置，会覆盖当前级别的阈值）
	customRequestsPer5Minutes int
	// 过老浏览器 UA 检测开关（由配置注入）
	outdatedBrowserEnabled bool

	log *logrus.Entry
	// 持久化轮转
	rotator *logger.Rotator
	// 通知集成器
	notificationIntegrator *notification.NotificationIntegrator
	// 威胁情报检测器
	threatDetector *threatintel.ThreatDetector
	// GeoIP 服务
	geoIPService *security.GeoIPService

	// 全局攻击感知
	lastAttackCheckTime  time.Time
	attackCheckInterval  time.Duration
	lastNotificationTime time.Time
	notificationCooldown time.Duration
	// 自动应对措施
	autoEscalateEnabled bool
	autoBlockEnabled    bool
	// Security Manager 引用（用于统一封禁管理）
	securityManager *security.Manager
}

// ThresholdConfig 阈值配置
type ThresholdConfig struct {
	RequestsPerMinute   int           `json:"requests_per_minute"`
	RequestsPer5Minutes int           `json:"requests_per_5minutes"` // 5分钟窗口阈值（优先使用）
	RequestsPerHour     int           `json:"requests_per_hour"`
	BlockDuration       time.Duration `json:"block_duration"`
	SuspiciousUA        bool          `json:"suspicious_ua"`
	GeoBlocking         bool          `json:"geo_blocking"`
	ChallengeMode       bool          `json:"challenge_mode"`
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
		attackQueue:            make(chan attackRecord, 4096),
		blockDuration:          1 * time.Hour,
		maxClients:             10000,
		maxAttacks:             1000,
		notificationIntegrator: notificationIntegrator,
		attackCheckInterval:    1 * time.Minute, // 每分钟检查一次全局攻击
		notificationCooldown:   5 * time.Minute, // 通知冷却时间5分钟
		autoEscalateEnabled:    true,            // 默认启用自动升级
		autoBlockEnabled:       true,            // 默认启用自动封禁
		log: logrus.WithFields(logrus.Fields{
			"component": "ddos_protector",
		}),
	}

	// 初始化阈值配置
	p.initThresholds()

	// 启动清理协程
	go p.cleanupRoutine()

	// 启动全局攻击检测协程
	go p.globalAttackDetectionRoutine()
	go p.attackRecorderRoutine()

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

// SetSecurityManager 设置 Security Manager（用于统一封禁管理）
func (p *Protector) SetSecurityManager(manager *security.Manager) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.securityManager = manager
	p.log.Info("已设置 Security Manager 到 DDoS 防护器")
}

// SetOutdatedBrowserEnabled 设置过老浏览器 UA 检测开关
func (p *Protector) SetOutdatedBrowserEnabled(enabled bool) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.outdatedBrowserEnabled = enabled
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

// attackRecord 用于异步记录攻击
type attackRecord struct {
	clientIP   string
	userAgent  string
	url        string
	method     string
	attackType string
	severity   string
	reason     string
	blocked    bool
	timestamp  time.Time
}

// CheckRequest 检查请求
func (p *Protector) CheckRequest(r *http.Request) (bool, string) {
	p.mutex.RLock()
	enabled := p.enabled
	level := p.level
	threshold := p.thresholds[level]
	customRequestsPer5Minutes := p.customRequestsPer5Minutes
	outdatedBrowserEnabled := p.outdatedBrowserEnabled
	threatDetector := p.threatDetector
	p.mutex.RUnlock()

	if !enabled || level == LevelOff {
		return false, ""
	}

	clientIP := p.getClientIP(r)

	// 排除内网IP，不对内网请求进行DDoS检测
	if p.isPrivateIP(clientIP) {
		return false, ""
	}

	userAgent := r.Header.Get("User-Agent")
	now := time.Now()

	// 如果设置了自定义5分钟阈值，使用自定义值
	if customRequestsPer5Minutes > 0 {
		threshold.RequestsPer5Minutes = customRequestsPer5Minutes
	}

	// 对静态资源路径放宽限制（提高阈值）
	isStaticResource := p.isStaticResourcePath(r.URL.Path)
	if isStaticResource {
		// 对于静态资源，阈值提高5倍
		threshold.RequestsPerMinute *= 5
		if threshold.RequestsPer5Minutes > 0 {
			threshold.RequestsPer5Minutes *= 5
		}
		threshold.RequestsPerHour *= 5
	}

	// 修复：预先检查不需要锁的条件
	// 极老浏览器 UA：直接拦截（多为爬虫）
	if outdatedBrowserEnabled && userAgent != "" && security.IsVeryOutdatedBrowser(userAgent) {
		// 需要锁来更新客户端状态
		p.blockClientAndUpdate(clientIP, userAgent, r.URL.String(), r.Method,
			"outdated_browser", "high", "极老浏览器 UA", true, threshold.BlockDuration, now)
		return true, "极老浏览器 UA"
	}

	// 修复：使用读锁获取客户端信息
	p.mutex.RLock()
	client, exists := p.clients[clientIP]
	var blockedUntil time.Time
	if exists {
		blockedUntil = client.BlockedUntil
	}
	p.mutex.RUnlock()

	// 检查是否已被封禁（不需要锁）
	if now.Before(blockedUntil) {
		p.enqueueAttackRecord(clientIP, userAgent, r.URL.String(), r.Method,
			"rate_limit", "high", "IP仍在封禁期内", true)
		return true, "IP已被封禁"
	}

	// 修复：只在需要更新时获取写锁，并且缩小临界区
	p.mutex.Lock()

	// 获取或创建客户端信息
	client, exists = p.clients[clientIP]
	if !exists {
		client = &ClientInfo{
			IP:                clientIP,
			RequestCount:      0,
			FirstRequest:      now,
			UserAgent:         userAgent,
			RequestTimestamps: make([]time.Time, 0, 100), // 预分配容量
		}
		p.clients[clientIP] = client
	}

	// 更新客户端信息（快速操作）
	client.RequestCount++
	client.LastRequest = now
	client.RequestTimestamps = append(client.RequestTimestamps, now)

	// 清理滑动窗口：移除1小时前的请求记录
	cutoffTime := now.Add(-time.Hour)
	validTimestamps := client.RequestTimestamps[:0] // 重用切片
	for _, ts := range client.RequestTimestamps {
		if ts.After(cutoffTime) {
			validTimestamps = append(validTimestamps, ts)
		}
	}
	client.RequestTimestamps = validTimestamps

	// 计算请求速率
	duration := now.Sub(client.FirstRequest)
	if duration > 0 {
		client.RequestRate = float64(client.RequestCount) / duration.Minutes()
	}

	// 复制需要的数据用于后续检查
	clientCopy := *client
	clientCopy.RequestTimestamps = append([]time.Time(nil), client.RequestTimestamps...)

	p.mutex.Unlock()

	// 修复：所有耗时操作和 I/O 操作都在锁外执行

	// 使用威胁情报检测（如果可用）
	if threatDetector != nil {
		threatResult := threatDetector.CheckRequest(r)
		if threatResult.IsThreat {
			shouldBlock := threatResult.ThreatLevel >= threatintel.ThreatLevelHigh
			severity := threatResult.ThreatLevel.String()

			if shouldBlock {
				p.blockClientAndUpdate(clientIP, userAgent, r.URL.String(), r.Method,
					"threat_intel", severity,
					fmt.Sprintf("威胁情报检测: %s (置信度: %.2f)", threatResult.Description, threatResult.Confidence),
					shouldBlock, threshold.BlockDuration, now)
			} else {
				p.enqueueAttackRecord(clientIP, userAgent, r.URL.String(), r.Method,
					"threat_intel", severity,
					fmt.Sprintf("威胁情报检测: %s (置信度: %.2f)", threatResult.Description, threatResult.Confidence),
					false)
			}

			if shouldBlock {
				return true, fmt.Sprintf("威胁情报检测: %s", threatResult.Description)
			}
		}
	}

	// 较老浏览器 UA：标记 + 使用更严格的速率限制
	rateLimitThreshold := threshold
	if outdatedBrowserEnabled && userAgent != "" && security.IsOutdatedBrowser(userAgent) {
		p.enqueueAttackRecord(clientIP, userAgent, r.URL.String(), r.Method,
			"outdated_browser", "medium", "较老浏览器 UA", false)

		// 更新客户端可疑状态（需要锁）
		p.mutex.Lock()
		if c, ok := p.clients[clientIP]; ok {
			c.Suspicious = true
		}
		p.mutex.Unlock()

		rateLimitThreshold.RequestsPerMinute = max(1, threshold.RequestsPerMinute/2)
		rateLimitThreshold.RequestsPer5Minutes = max(1, threshold.RequestsPer5Minutes/2)
		rateLimitThreshold.RequestsPerHour = max(1, threshold.RequestsPerHour/2)
	}

	// 检查请求频率（使用客户端副本）
	if blocked, reason := p.checkRateLimit(&clientCopy, rateLimitThreshold, now); blocked {
		p.blockClientAndUpdate(clientIP, userAgent, r.URL.String(), r.Method,
			"rate_limit", "high", reason, true, threshold.BlockDuration, now)
		return true, reason
	}

	// 检查可疑User-Agent（非过老浏览器的其他可疑 UA）
	if threshold.SuspiciousUA && p.isSuspiciousUserAgent(userAgent) {
		p.enqueueAttackRecord(clientIP, userAgent, r.URL.String(), r.Method,
			"suspicious_ua", "medium", "可疑的User-Agent", false)

		// 更新状态（快速加锁）
		p.mutex.Lock()
		if c, ok := p.clients[clientIP]; ok {
			c.Suspicious = true
		}
		p.mutex.Unlock()
	}

	// 检查请求模式
	if p.isSuspiciousPattern(r, &clientCopy) {
		p.enqueueAttackRecord(clientIP, userAgent, r.URL.String(), r.Method,
			"suspicious_pattern", "medium", "可疑的请求模式", false)

		// 更新状态（快速加锁）
		p.mutex.Lock()
		if c, ok := p.clients[clientIP]; ok {
			c.Suspicious = true
		}
		p.mutex.Unlock()
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
		"/api/chrome/",   // Chrome 开发工具相关
		"/devtools/",     // 开发工具
		"/bootstrap/",    // Bootstrap CSS 库
		"/jquery/",       // jQuery 库
		"/fontawesome/",  // Font Awesome 图标库
		"/cdn/",          // CDN 资源
		"/lib/",          // 库文件
		"/vendor/",       // 第三方库
	}

	// 检查常见静态资源扩展名
	staticExtensions := []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
		".woff", ".woff2", ".ttf", ".eot", ".webp", ".avif",
		".map", // source maps
	}

	// 检查常见的静态资源文件名
	staticFiles := []string{
		"favicon.ico",
		"apple-touch-icon.png",
		"apple-touch-icon-57x57.png",
		"apple-touch-icon-72x72.png",
		"apple-touch-icon-76x76.png",
		"apple-touch-icon-114x114.png",
		"apple-touch-icon-120x120.png",
		"apple-touch-icon-144x144.png",
		"apple-touch-icon-152x152.png",
		"apple-touch-icon-180x180.png",
		"apple-touch-icon-precomposed.png",
		"browserconfig.xml",
		"crossdomain.xml",
		"humans.txt",
		"robots.txt",
		"sitemap.xml",
		"sw.js",
		"manifest.json",
		"service-worker.js",
		"offline.html",
		"404.html",
		"500.html",
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

	// 检查常见静态文件名
	for _, file := range staticFiles {
		if urlLower == "/"+file || strings.HasSuffix(urlLower, "/"+file) {
			return true
		}
	}

	// 检查 Chrome 开发工具相关的 JSON 文件
	if strings.Contains(urlLower, "chrome-devtools") ||
		strings.Contains(urlLower, "devtools") ||
		strings.Contains(urlLower, "source-map") ||
		strings.Contains(urlLower, "hot-update") {
		return true
	}

	// 检查常见的 CSS 库文件路径
	cssLibraryPaths := []string{
		"bootstrap.min.css",
		"bootstrap.css",
		"jquery-ui.css",
		"font-awesome.css",
		"fontawesome.css",
		"animate.css",
		"normalize.css",
		"reset.css",
	}

	for _, cssFile := range cssLibraryPaths {
		if strings.Contains(urlLower, cssFile) {
			return true
		}
	}

	return false
}

// checkRateLimit 检查请求频率限制
func (p *Protector) checkRateLimit(client *ClientInfo, threshold ThresholdConfig, now time.Time) (bool, string) {
	// 优先检查5分钟窗口（如果设置了）
	if threshold.RequestsPer5Minutes > 0 {
		fiveMinutesAgo := now.Add(-5 * time.Minute)

		// 统计最近5分钟内的实际请求数
		requestsInLast5Minutes := 0
		for _, ts := range client.RequestTimestamps {
			if ts.After(fiveMinutesAgo) {
				requestsInLast5Minutes++
			}
		}

		// 只有当最近5分钟的请求数超过阈值时才拦截
		if requestsInLast5Minutes > threshold.RequestsPer5Minutes {
			return true, fmt.Sprintf("5分钟内请求数超限: %d > %d", requestsInLast5Minutes, threshold.RequestsPer5Minutes)
		}
	}

	// 检查每分钟请求数 - 使用真正的滑动窗口统计（仅在未设置5分钟阈值时使用）
	if threshold.RequestsPerMinute > 0 && threshold.RequestsPer5Minutes == 0 {
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
	urlPath := r.URL.Path

	// 对于静态资源，不进行可疑模式检测
	if p.isStaticResourcePath(urlPath) {
		return false
	}

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

// blockClientAndUpdate 封禁客户端并更新状态（组合操作，减少锁持有时间）
func (p *Protector) blockClientAndUpdate(clientIP, userAgent, url, method, attackType, severity, reason string, blocked bool, blockDuration time.Duration, now time.Time) {
	// 快速获取锁并更新状态
	p.mutex.Lock()
	if client, exists := p.clients[clientIP]; exists {
		client.BlockedUntil = now.Add(blockDuration)
		client.BlockCount++
	}
	p.mutex.Unlock()

	p.enqueueAttackRecord(clientIP, userAgent, url, method, attackType, severity, reason, blocked)
}

func (p *Protector) enqueueAttackRecord(clientIP, userAgent, url, method, attackType, severity, reason string, blocked bool) {
	record := attackRecord{
		clientIP:   clientIP,
		userAgent:  userAgent,
		url:        url,
		method:     method,
		attackType: attackType,
		severity:   severity,
		reason:     reason,
		blocked:    blocked,
		timestamp:  time.Now(),
	}

	select {
	case p.attackQueue <- record:
	default:
		p.log.Warnf("DDoS攻击记录队列已满，跳过一条攻击日志: ip=%s type=%s", clientIP, attackType)
	}
}

func (p *Protector) attackRecorderRoutine() {
	for {
		select {
		case record := <-p.attackQueue:
			p.recordAttackAsync(record.clientIP, record.userAgent, record.url, record.method, record.attackType, record.severity, record.reason, record.blocked)
		case <-p.stopChan:
			p.drainAttackQueue()
			return
		}
	}
}

func (p *Protector) drainAttackQueue() {
	for {
		select {
		case record := <-p.attackQueue:
			p.recordAttackAsync(record.clientIP, record.userAgent, record.url, record.method, record.attackType, record.severity, record.reason, record.blocked)
		default:
			return
		}
	}
}

// recordAttackAsync 异步记录攻击（避免在持锁时调用）
func (p *Protector) recordAttackAsync(clientIP, userAgent, url, method, attackType, severity, reason string, blocked bool) {
	p.mutex.RLock()
	geoIPService := p.geoIPService
	securityManager := p.securityManager
	notificationIntegrator := p.notificationIntegrator
	threshold := p.thresholds[p.level]
	p.mutex.RUnlock()

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

	// 查询 GeoIP 信息（可能在锁外进行网络请求）
	if geoIPService != nil {
		if geoLoc, err := geoIPService.GetLocation(clientIP); err == nil && geoLoc != nil {
			attack.Country = geoLoc.Country
			attack.CountryCode = geoLoc.CountryCode
			attack.ISP = geoLoc.ISP
		}
	}

	// 更新攻击记录（需要锁，但操作快速）
	p.mutex.Lock()
	p.attacks = append(p.attacks, attack)
	// 保持攻击记录数量限制
	if len(p.attacks) > p.maxAttacks {
		p.attacks = p.attacks[1:]
	}
	p.mutex.Unlock()

	// JSON Lines 持久化（I/O 操作，在锁外执行）
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

	// 只对实际被阻止的攻击发送通知（可能在锁外进行网络请求）
	if notificationIntegrator != nil && blocked {
		attackInfo := &notification.AttackInfo{
			ClientIP:  clientIP,
			UserAgent: userAgent,
			URL:       url,
			Reason:    reason,
			Severity:  severity,
			Blocked:   blocked,
		}
		notificationIntegrator.SendDDoSAttackNotification(attackInfo)
	}

	// 如果被封禁，同时添加到统一封禁管理系统（可能涉及 I/O）
	if blocked && securityManager != nil {
		securityManager.BlockIP(clientIP, threshold.BlockDuration, fmt.Sprintf("DDoS攻击: %s", reason))
	}

	if blocked {
		p.log.Warnf("DDoS攻击已阻止: %s from %s, 原因: %s", attackType, clientIP, reason)
	} else {
		p.log.Infof("检测到可疑活动: %s from %s, 原因: %s", attackType, clientIP, reason)
	}
}

// recordAttack 记录攻击（保留用于向后兼容）
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

	// 只对实际被阻止的攻击发送通知，避免可疑请求的垃圾通知
	if p.notificationIntegrator != nil && blocked {
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

	// 如果被封禁，同时添加到统一封禁管理系统
	if blocked && p.securityManager != nil {
		// 获取封禁时长（使用当前防护级别的封禁时长）
		threshold := p.thresholds[p.level]
		p.securityManager.BlockIP(clientIP, threshold.BlockDuration, fmt.Sprintf("DDoS攻击: %s", reason))
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

// isPrivateIP 检查是否为内网IP
func (p *Protector) isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// 检查是否为内网IP段
	privateBlocks := []string{
		"10.0.0.0/8",     // A类私有地址
		"172.16.0.0/12",  // B类私有地址
		"192.168.0.0/16", // C类私有地址
		"127.0.0.0/8",    // 本地回环地址
		"169.254.0.0/16", // 链路本地地址
		"::1/128",        // IPv6 本地回环
		"fc00::/7",       // IPv6 私有地址
		"fe80::/10",      // IPv6 链路本地地址
	}

	for _, block := range privateBlocks {
		_, network, err := net.ParseCIDR(block)
		if err != nil {
			continue
		}
		if network.Contains(parsedIP) {
			return true
		}
	}

	return false
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
	initialClients := len(p.clients)
	initialAttacks := len(p.attacks)

	// 清理过期的客户端记录
	for ip, client := range p.clients {
		// 如果客户端1小时内没有请求，且没有被封禁，则删除记录
		if now.Sub(client.LastRequest) > time.Hour && now.After(client.BlockedUntil) {
			delete(p.clients, ip)
		}
	}

	// 如果客户端数量仍然超过限制，删除最旧的
	if len(p.clients) > p.maxClients {
		p.pruneOldestClients(p.maxClients)
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

	// 如果攻击记录仍然超过限制，只保留最新的
	if len(p.attacks) > p.maxAttacks {
		p.attacks = p.attacks[len(p.attacks)-p.maxAttacks:]
	}

	if initialClients > len(p.clients) || initialAttacks > len(p.attacks) {
		p.log.Infof("清理完成，客户端: %d→%d，攻击记录: %d→%d",
			initialClients, len(p.clients),
			initialAttacks, len(p.attacks))
	}
}

// pruneOldestClients 删除最旧的客户端记录
func (p *Protector) pruneOldestClients(maxCount int) {
	if len(p.clients) <= maxCount {
		return
	}

	// 收集所有客户端及其最后请求时间
	type clientWithTime struct {
		ip   string
		time time.Time
	}

	var items []clientWithTime
	for ip, client := range p.clients {
		items = append(items, clientWithTime{
			ip:   ip,
			time: client.LastRequest,
		})
	}

	// 按时间排序（最旧的在前）
	for i := 0; i < len(items)-1; i++ {
		for j := i + 1; j < len(items); j++ {
			if items[i].time.After(items[j].time) {
				items[i], items[j] = items[j], items[i]
			}
		}
	}

	// 删除最旧的
	deleteCount := len(p.clients) - maxCount
	for i := 0; i < deleteCount && i < len(items); i++ {
		delete(p.clients, items[i].ip)
	}

	p.log.Warnf("Pruned %d oldest client records (limit: %d)", deleteCount, maxCount)
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

// SetCustomRequestsPer5Minutes 设置自定义5分钟阈值（会覆盖当前级别的阈值）
func (p *Protector) SetCustomRequestsPer5Minutes(maxRequests int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.customRequestsPer5Minutes = maxRequests
	if maxRequests > 0 {
		p.log.Infof("DDoS防护自定义5分钟阈值已设置为: %d", maxRequests)
	} else {
		p.log.Infof("DDoS防护自定义5分钟阈值已清除，将使用级别默认值")
	}
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

// GetAttacksByTimeRange 按时间范围获取攻击记录
func (p *Protector) GetAttacksByTimeRange(startTime, endTime time.Time) []Attack {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	var result []Attack
	for _, attack := range p.attacks {
		if (attack.Timestamp.After(startTime) || attack.Timestamp.Equal(startTime)) &&
			(attack.Timestamp.Before(endTime) || attack.Timestamp.Equal(endTime)) {
			result = append(result, attack)
		}
	}

	return result
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
	p.mutex.Unlock()

	p.enqueueAttackRecord(ip, "", "", "", "manual", "high", reason, true)
	p.log.Warnf("手动封禁IP: %s，持续时间: %v，原因: %s", ip, duration, reason)
}

// Stop 停止防护器
func (p *Protector) Stop() {
	p.log.Info("停止DDoS防护器")
	p.stopOnce.Do(func() {
		close(p.stopChan)
	})
}

// globalAttackDetectionRoutine 全局攻击检测协程
func (p *Protector) globalAttackDetectionRoutine() {
	ticker := time.NewTicker(p.attackCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.detectGlobalAttack()
		case <-p.stopChan:
			return
		}
	}
}

// detectGlobalAttack 检测全局攻击（大规模DDoS攻击）
func (p *Protector) detectGlobalAttack() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	now := time.Now()

	// 检查最近1分钟内的攻击情况
	recentWindow := 1 * time.Minute
	cutoffTime := now.Add(-recentWindow)

	// 统计最近1分钟内的攻击
	recentAttacks := 0
	recentBlockedAttacks := 0
	recentBlockedIPs := make(map[string]bool)

	for _, attack := range p.attacks {
		if attack.Timestamp.After(cutoffTime) {
			recentAttacks++
			if attack.Blocked {
				recentBlockedAttacks++
				recentBlockedIPs[attack.ClientIP] = true
			}
		}
	}

	// 统计当前被封禁的客户端数量
	currentBlockedCount := 0
	for _, client := range p.clients {
		if now.Before(client.BlockedUntil) {
			currentBlockedCount++
		}
	}

	// 检测大规模攻击的指标
	// 主要关注被封禁的攻击，这才是真正的DDoS攻击
	// 1. 最近1分钟内超过500次被封禁的攻击（提高阈值，避免误报）
	// 2. 最近1分钟内超过20个不同IP被封禁
	// 3. 当前被封禁的IP超过100个
	isLargeScaleAttack := false
	attackSeverity := "medium"

	// 优先使用被封禁的攻击数和被封禁的IP数作为判断标准
	if recentBlockedAttacks >= 500 || len(recentBlockedIPs) >= 20 || currentBlockedCount >= 100 {
		isLargeScaleAttack = true
		if recentBlockedAttacks >= 2000 || len(recentBlockedIPs) >= 50 || currentBlockedCount >= 500 {
			attackSeverity = "critical"
		} else if recentBlockedAttacks >= 1000 || len(recentBlockedIPs) >= 30 || currentBlockedCount >= 200 {
			attackSeverity = "high"
		}
	}

	if isLargeScaleAttack {
		// 检查是否需要发送通知（避免频繁通知）
		shouldNotify := now.Sub(p.lastNotificationTime) >= p.notificationCooldown

		if shouldNotify {
			p.lastNotificationTime = now

			// 发送大规模攻击通知
			if p.notificationIntegrator != nil {
				attackInfo := &notification.AttackInfo{
					ClientIP:  "multiple",
					UserAgent: "DDoS Attack",
					URL:       "global",
					Reason: fmt.Sprintf("检测到大规模DDoS攻击: 最近1分钟%d次攻击被拦截, %d个IP被封禁, 当前%d个IP被封禁",
						recentBlockedAttacks, len(recentBlockedIPs), currentBlockedCount),
					Severity: attackSeverity,
					Blocked:  true,
				}
				p.notificationIntegrator.SendDDoSAttackNotification(attackInfo)
			}

			p.log.Warnf("🚨 检测到大规模DDoS攻击！最近1分钟: %d次攻击被拦截, %d个IP被封禁, 当前%d个IP被封禁, 严重程度: %s",
				recentBlockedAttacks, len(recentBlockedIPs), currentBlockedCount, attackSeverity)

			// 自动应对措施
			if p.autoEscalateEnabled {
				p.autoEscalateProtection(attackSeverity)
			}
		}
	}
}

// autoEscalateProtection 自动升级防护级别
func (p *Protector) autoEscalateProtection(severity string) {
	currentLevel := p.level

	switch severity {
	case "critical":
		// 严重攻击：升级到最高级别
		if currentLevel < LevelExtreme {
			p.level = LevelExtreme
			p.log.Warnf("⚠️ 自动升级防护级别: %s -> %s (检测到严重DDoS攻击)",
				currentLevel.String(), p.level.String())
		}
	case "high":
		// 高级攻击：升级到高级别
		if currentLevel < LevelHigh {
			p.level = LevelHigh
			p.log.Warnf("⚠️ 自动升级防护级别: %s -> %s (检测到高级DDoS攻击)",
				currentLevel.String(), p.level.String())
		}
	case "medium":
		// 中级攻击：升级到中高级别
		if currentLevel < LevelMedium {
			p.level = LevelMedium
			p.log.Warnf("⚠️ 自动升级防护级别: %s -> %s (检测到中级DDoS攻击)",
				currentLevel.String(), p.level.String())
		}
	}
}

// GetGlobalAttackStats 获取全局攻击统计
func (p *Protector) GetGlobalAttackStats() map[string]interface{} {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	now := time.Now()
	recentWindow := 1 * time.Minute
	cutoffTime := now.Add(-recentWindow)

	recentAttacks := 0
	recentBlockedAttacks := 0
	recentBlockedIPs := make(map[string]bool)
	currentBlockedCount := 0

	for _, attack := range p.attacks {
		if attack.Timestamp.After(cutoffTime) {
			recentAttacks++
			if attack.Blocked {
				recentBlockedAttacks++
				recentBlockedIPs[attack.ClientIP] = true
			}
		}
	}

	for _, client := range p.clients {
		if now.Before(client.BlockedUntil) {
			currentBlockedCount++
		}
	}

	return map[string]interface{}{
		"recent_attacks_1min":      recentAttacks,
		"recent_blocked_attacks":   recentBlockedAttacks,
		"recent_blocked_ips":       len(recentBlockedIPs),
		"current_blocked_ips":      currentBlockedCount,
		"is_large_scale_attack":    recentAttacks >= 50 || len(recentBlockedIPs) >= 20 || currentBlockedCount >= 100,
		"auto_escalate_enabled":    p.autoEscalateEnabled,
		"auto_block_enabled":       p.autoBlockEnabled,
		"current_protection_level": p.level.String(),
	}
}

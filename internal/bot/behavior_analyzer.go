package bot

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// BehaviorAnalyzer 行为分析器
type BehaviorAnalyzer struct {
	logger         *logrus.Entry
	requestTracker *RequestTracker
	pathTracker    *PathTracker
	mutex          sync.RWMutex
}

// RequestTracker 请求追踪器
type RequestTracker struct {
	requests map[string]*RequestStats // key: clientIP
	mutex    sync.RWMutex
}

// RequestStats 请求统计
type RequestStats struct {
	MinuteWindow []time.Time // 1分钟内的请求时间戳
	HourWindow   []time.Time // 1小时内的请求时间戳
	LastRequest  time.Time
	TotalCount   int64
}

// PathTracker 路径追踪器
type PathTracker struct {
	paths map[string]*PathStats // key: clientIP
	mutex sync.RWMutex
}

// PathStats 路径统计
type PathStats struct {
	UniquePaths  map[string]bool // 访问过的唯一路径
	PathSequence []string        // 路径访问序列
	LastUpdate   time.Time
}

// NewBehaviorAnalyzer 创建行为分析器
func NewBehaviorAnalyzer(logger *logrus.Logger) *BehaviorAnalyzer {
	analyzer := &BehaviorAnalyzer{
		logger: logger.WithField("component", "behavior_analyzer"),
		requestTracker: &RequestTracker{
			requests: make(map[string]*RequestStats),
		},
		pathTracker: &PathTracker{
			paths: make(map[string]*PathStats),
		},
	}

	// 启动清理协程
	go analyzer.cleanupRoutine()

	return analyzer
}

// AnalyzeRequest 分析请求并返回风险评分 (0-100)
func (ba *BehaviorAnalyzer) AnalyzeRequest(r *http.Request, config *BotDetectionConfig) int {
	clientIP := ba.getClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	score := 0

	// 1. User-Agent 分析 (0-30分)
	score += ba.analyzeUserAgent(userAgent)

	// 2. 请求频率分析 (0-30分)
	score += ba.analyzeRequestFrequency(clientIP, config)

	// 3. 路径模式分析 (0-25分)
	score += ba.analyzePathPattern(clientIP, r.URL.Path)

	// 4. JavaScript 能力检测 (0-15分)
	score += ba.analyzeJavaScriptCapability(r)

	return min(score, 100)
}

// analyzeUserAgent 分析 User-Agent
func (ba *BehaviorAnalyzer) analyzeUserAgent(userAgent string) int {
	score := 0

	// 空 User-Agent
	if userAgent == "" {
		return 30
	}

	// 检查是否为已知机器人
	if IsKnownBot(userAgent) {
		return 30
	}

	// User-Agent 过短
	if len(userAgent) < 20 {
		score += 15
	}

	// 缺少常见浏览器标识
	hasCommonBrowser := strings.Contains(userAgent, "Mozilla") ||
		strings.Contains(userAgent, "Chrome") ||
		strings.Contains(userAgent, "Safari") ||
		strings.Contains(userAgent, "Firefox") ||
		strings.Contains(userAgent, "Edge")

	if !hasCommonBrowser {
		score += 10
	}

	// 检查是否包含可疑关键词
	suspiciousKeywords := []string{
		"http", "HTTP", "lib", "python", "java", "ruby", "perl",
		"go-http", "okhttp", "axios", "fetch",
	}

	for _, keyword := range suspiciousKeywords {
		if strings.Contains(strings.ToLower(userAgent), strings.ToLower(keyword)) {
			score += 5
			break
		}
	}

	return min(score, 30)
}

// analyzeRequestFrequency 分析请求频率
func (ba *BehaviorAnalyzer) analyzeRequestFrequency(clientIP string, config *BotDetectionConfig) int {
	ba.requestTracker.mutex.Lock()
	defer ba.requestTracker.mutex.Unlock()

	now := time.Now()
	stats, exists := ba.requestTracker.requests[clientIP]

	if !exists {
		stats = &RequestStats{
			MinuteWindow: []time.Time{},
			HourWindow:   []time.Time{},
			LastRequest:  now,
			TotalCount:   0,
		}
		ba.requestTracker.requests[clientIP] = stats
	}

	// 清理过期的时间戳
	stats.MinuteWindow = ba.filterRecentRequests(stats.MinuteWindow, now, time.Minute)
	stats.HourWindow = ba.filterRecentRequests(stats.HourWindow, now, time.Hour)

	// 添加当前请求
	stats.MinuteWindow = append(stats.MinuteWindow, now)
	stats.HourWindow = append(stats.HourWindow, now)
	stats.TotalCount++
	stats.LastRequest = now

	score := 0

	// 检查每分钟请求数
	minuteCount := len(stats.MinuteWindow)
	if config.MaxRequestsPerMinute > 0 && minuteCount > config.MaxRequestsPerMinute {
		// 超过限制，评分增加
		excess := float64(minuteCount-config.MaxRequestsPerMinute) / float64(config.MaxRequestsPerMinute)
		score += int(excess * 20)
	}

	// 检查每小时请求数
	hourCount := len(stats.HourWindow)
	if config.MaxRequestsPerHour > 0 && hourCount > config.MaxRequestsPerHour {
		excess := float64(hourCount-config.MaxRequestsPerHour) / float64(config.MaxRequestsPerHour)
		score += int(excess * 10)
	}

	return min(score, 30)
}

// analyzePathPattern 分析路径访问模式
func (ba *BehaviorAnalyzer) analyzePathPattern(clientIP, path string) int {
	ba.pathTracker.mutex.Lock()
	defer ba.pathTracker.mutex.Unlock()

	now := time.Now()
	stats, exists := ba.pathTracker.paths[clientIP]

	if !exists {
		stats = &PathStats{
			UniquePaths:  make(map[string]bool),
			PathSequence: []string{},
			LastUpdate:   now,
		}
		ba.pathTracker.paths[clientIP] = stats
	}

	// 添加路径
	stats.UniquePaths[path] = true
	stats.PathSequence = append(stats.PathSequence, path)
	stats.LastUpdate = now

	// 限制序列长度
	if len(stats.PathSequence) > 100 {
		stats.PathSequence = stats.PathSequence[len(stats.PathSequence)-100:]
	}

	score := 0

	// 检查唯一路径数量（短时间内访问大量不同路径）
	uniquePathCount := len(stats.UniquePaths)
	if uniquePathCount > 50 {
		score += 15
	} else if uniquePathCount > 30 {
		score += 10
	} else if uniquePathCount > 20 {
		score += 5
	}

	// 检查路径遍历模式
	if ba.detectPathTraversal(stats.PathSequence) {
		score += 10
	}

	return min(score, 25)
}

// analyzeJavaScriptCapability 分析 JavaScript 能力
func (ba *BehaviorAnalyzer) analyzeJavaScriptCapability(r *http.Request) int {
	// 检查是否有 JavaScript 设置的 Cookie
	if cookie, err := r.Cookie("js_enabled"); err == nil && cookie.Value == "1" {
		return 0 // 有 JS 能力，风险低
	}

	// 检查是否是首次访问（没有任何 Cookie）
	cookies := r.Cookies()
	if len(cookies) == 0 {
		return 5 // 首次访问，轻微可疑
	}

	// 有 Cookie 但没有 JS 标记，可能是机器人
	return 15
}

// detectPathTraversal 检测路径遍历行为
func (ba *BehaviorAnalyzer) detectPathTraversal(sequence []string) bool {
	if len(sequence) < 10 {
		return false
	}

	// 检查最近的路径是否都不同（典型的遍历行为）
	recent := sequence
	if len(sequence) > 20 {
		recent = sequence[len(sequence)-20:]
	}

	uniqueCount := 0
	seen := make(map[string]bool)
	for _, path := range recent {
		if !seen[path] {
			uniqueCount++
			seen[path] = true
		}
	}

	// 如果最近的访问中，唯一路径占比超过 80%，可能是遍历
	ratio := float64(uniqueCount) / float64(len(recent))
	return ratio > 0.8
}

// filterRecentRequests 过滤最近的请求
func (ba *BehaviorAnalyzer) filterRecentRequests(timestamps []time.Time, now time.Time, duration time.Duration) []time.Time {
	cutoff := now.Add(-duration)
	result := []time.Time{}

	for _, ts := range timestamps {
		if ts.After(cutoff) {
			result = append(result, ts)
		}
	}

	return result
}

// cleanupRoutine 定期清理过期数据
func (ba *BehaviorAnalyzer) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ba.cleanup()
	}
}

// cleanup 清理过期数据
func (ba *BehaviorAnalyzer) cleanup() {
	now := time.Now()

	// 清理请求追踪器
	ba.requestTracker.mutex.Lock()
	for ip, stats := range ba.requestTracker.requests {
		// 如果超过 1 小时没有请求，删除记录
		if now.Sub(stats.LastRequest) > time.Hour {
			delete(ba.requestTracker.requests, ip)
		}
	}
	ba.requestTracker.mutex.Unlock()

	// 清理路径追踪器
	ba.pathTracker.mutex.Lock()
	for ip, stats := range ba.pathTracker.paths {
		// 如果超过 1 小时没有更新，删除记录
		if now.Sub(stats.LastUpdate) > time.Hour {
			delete(ba.pathTracker.paths, ip)
		}
	}
	ba.pathTracker.mutex.Unlock()

	ba.logger.Debug("Cleaned up expired behavior tracking data")
}

// GetStats 获取统计信息
func (ba *BehaviorAnalyzer) GetStats() map[string]interface{} {
	ba.requestTracker.mutex.RLock()
	requestCount := len(ba.requestTracker.requests)
	ba.requestTracker.mutex.RUnlock()

	ba.pathTracker.mutex.RLock()
	pathCount := len(ba.pathTracker.paths)
	ba.pathTracker.mutex.RUnlock()

	return map[string]interface{}{
		"tracked_ips":    requestCount,
		"tracked_paths":  pathCount,
	}
}

// getClientIP 获取客户端IP
func (ba *BehaviorAnalyzer) getClientIP(r *http.Request) string {
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		return strings.TrimSpace(cfIP)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}


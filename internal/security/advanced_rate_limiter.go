package security

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

// AdvancedRateLimiter 高级限流器
type AdvancedRateLimiter struct {
	config config.RateLimitConfig

	// 不同维度的限流器
	ipLimiters     map[string]*RateLimiter
	userLimiters   map[string]*RateLimiter
	pathLimiters   map[string]*RateLimiter
	methodLimiters map[string]*RateLimiter

	// 路径规则编译后的正则表达式
	pathRuleRegexes map[string]*regexp.Regexp

	mutex sync.RWMutex
	log   *logrus.Entry
}

// RateLimitConfig 限流配置
type RateLimitConfig struct {
	// IP限流
	IPRateLimit config.IPRateLimitConfig `json:"ip_rate_limit"`

	// 用户限流
	UserRateLimit config.UserRateLimitConfig `json:"user_rate_limit"`

	// 路径限流
	PathRateLimit []config.PathRateLimitRule `json:"path_rate_limit"`

	// 方法限流
	MethodRateLimit map[string]int `json:"method_rate_limit"`

	// 全局限流
	GlobalRateLimit config.GlobalRateLimitConfig `json:"global_rate_limit"`
}

// RateLimiter 单个限流器
type RateLimiter struct {
	// 不同时间窗口的限制
	perSecond *WindowLimiter
	perMinute *WindowLimiter
	perHour   *WindowLimiter

	// 突发限制
	burstLimiter *rateLimitTokenBucket

	// 统计信息
	totalRequests   int64
	blockedRequests int64
	lastRequest     time.Time

	mutex sync.RWMutex
}

// WindowLimiter 时间窗口限流器
type WindowLimiter struct {
	limit    int
	window   time.Duration
	requests []time.Time
	mutex    sync.RWMutex
}

// NewAdvancedRateLimiter 创建高级限流器
func NewAdvancedRateLimiter(config config.RateLimitConfig) *AdvancedRateLimiter {
	limiter := &AdvancedRateLimiter{
		config:          config,
		ipLimiters:      make(map[string]*RateLimiter),
		userLimiters:    make(map[string]*RateLimiter),
		pathLimiters:    make(map[string]*RateLimiter),
		methodLimiters:  make(map[string]*RateLimiter),
		pathRuleRegexes: make(map[string]*regexp.Regexp),
		log: logrus.WithFields(logrus.Fields{
			"component": "advanced_rate_limiter",
		}),
	}

	// 编译路径规则的正则表达式
	for _, rule := range config.PathRateLimit {
		if rule.Pattern != "" {
			if regex, err := regexp.Compile(rule.Pattern); err == nil {
				limiter.pathRuleRegexes[rule.Path] = regex
			} else {
				limiter.log.Errorf("Failed to compile path pattern %s: %v", rule.Pattern, err)
			}
		}
	}

	return limiter
}

// CheckRequest 检查请求是否被限流
func (arl *AdvancedRateLimiter) CheckRequest(r *http.Request) (bool, string) {
	clientIP := GetClientIP(r.RemoteAddr, map[string]string{
		"X-Forwarded-For": r.Header.Get("X-Forwarded-For"),
		"X-Real-IP":       r.Header.Get("X-Real-IP"),
	})

	// 1. 检查IP限流
	if blocked, reason := arl.checkIPRateLimit(clientIP); blocked {
		return true, reason
	}

	// 2. 检查用户限流（如果有用户信息）
	if user := arl.extractUser(r); user != "" {
		if blocked, reason := arl.checkUserRateLimit(user); blocked {
			return true, reason
		}
	}

	// 3. 检查路径限流
	if blocked, reason := arl.checkPathRateLimit(r.URL.Path); blocked {
		return true, reason
	}

	// 4. 检查方法限流
	if blocked, reason := arl.checkMethodRateLimit(r.Method); blocked {
		return true, reason
	}

	// 5. 检查全局限流
	if blocked, reason := arl.checkGlobalRateLimit(); blocked {
		return true, reason
	}

	return false, ""
}

// checkIPRateLimit 检查IP限流
func (arl *AdvancedRateLimiter) checkIPRateLimit(ip string) (bool, string) {
	if arl.config.IPRateLimit.RequestsPerSecond <= 0 {
		return false, ""
	}

	arl.mutex.Lock()
	limiter, exists := arl.ipLimiters[ip]
	if !exists {
		limiter = arl.createIPRateLimiter()
		arl.ipLimiters[ip] = limiter
	}
	arl.mutex.Unlock()

	return limiter.Allow(fmt.Sprintf("IP %s rate limit", ip))
}

// checkUserRateLimit 检查用户限流
func (arl *AdvancedRateLimiter) checkUserRateLimit(user string) (bool, string) {
	if arl.config.UserRateLimit.RequestsPerMinute <= 0 {
		return false, ""
	}

	arl.mutex.Lock()
	limiter, exists := arl.userLimiters[user]
	if !exists {
		limiter = arl.createUserRateLimiter()
		arl.userLimiters[user] = limiter
	}
	arl.mutex.Unlock()

	return limiter.Allow(fmt.Sprintf("User %s rate limit", user))
}

// checkPathRateLimit 检查路径限流
func (arl *AdvancedRateLimiter) checkPathRateLimit(path string) (bool, string) {
	for _, rule := range arl.config.PathRateLimit {
		if rule.RequestsPerMinute <= 0 {
			continue
		}

		matched := false

		// 精确匹配
		if rule.Path != "" && rule.Path == path {
			matched = true
		}

		// 正则匹配
		if !matched && rule.Pattern != "" {
			if regex, exists := arl.pathRuleRegexes[rule.Path]; exists {
				matched = regex.MatchString(path)
			}
		}

		if matched {
			arl.mutex.Lock()
			limiter, exists := arl.pathLimiters[rule.Path]
			if !exists {
				limiter = arl.createPathRateLimiter(rule)
				arl.pathLimiters[rule.Path] = limiter
			}
			arl.mutex.Unlock()

			if blocked, reason := limiter.Allow(fmt.Sprintf("Path %s rate limit", rule.Path)); blocked {
				return true, reason
			}
		}
	}

	return false, ""
}

// checkMethodRateLimit 检查方法限流
func (arl *AdvancedRateLimiter) checkMethodRateLimit(method string) (bool, string) {
	limit, exists := arl.config.MethodRateLimit[method]
	if !exists || limit <= 0 {
		return false, ""
	}

	arl.mutex.Lock()
	limiter, exists := arl.methodLimiters[method]
	if !exists {
		limiter = arl.createMethodRateLimiter(method, limit)
		arl.methodLimiters[method] = limiter
	}
	arl.mutex.Unlock()

	return limiter.Allow(fmt.Sprintf("Method %s rate limit", method))
}

// checkGlobalRateLimit 检查全局限流
func (arl *AdvancedRateLimiter) checkGlobalRateLimit() (bool, string) {
	if arl.config.GlobalRateLimit.RequestsPerSecond <= 0 {
		return false, ""
	}

	arl.mutex.Lock()
	limiter, exists := arl.methodLimiters["_global"]
	if !exists {
		limiter = arl.createGlobalRateLimiter()
		arl.methodLimiters["_global"] = limiter
	}
	arl.mutex.Unlock()

	return limiter.Allow("Global rate limit")
}

// createIPRateLimiter 创建IP限流器
func (arl *AdvancedRateLimiter) createIPRateLimiter() *RateLimiter {
	config := arl.config.IPRateLimit

	limiter := &RateLimiter{
		lastRequest: time.Now(),
	}

	if config.RequestsPerSecond > 0 {
		limiter.perSecond = &WindowLimiter{
			limit:  config.RequestsPerSecond,
			window: time.Second,
		}
	}

	if config.RequestsPerMinute > 0 {
		limiter.perMinute = &WindowLimiter{
			limit:  config.RequestsPerMinute,
			window: time.Minute,
		}
	}

	if config.RequestsPerHour > 0 {
		limiter.perHour = &WindowLimiter{
			limit:  config.RequestsPerHour,
			window: time.Hour,
		}
	}

	if config.BurstSize > 0 {
		limiter.burstLimiter = newRateLimitTokenBucket(config.RequestsPerSecond, config.BurstSize)
	}

	return limiter
}

// createUserRateLimiter 创建用户限流器
func (arl *AdvancedRateLimiter) createUserRateLimiter() *RateLimiter {
	config := arl.config.UserRateLimit

	limiter := &RateLimiter{
		lastRequest: time.Now(),
	}

	if config.RequestsPerMinute > 0 {
		limiter.perMinute = &WindowLimiter{
			limit:  config.RequestsPerMinute,
			window: time.Minute,
		}
	}

	if config.RequestsPerHour > 0 {
		limiter.perHour = &WindowLimiter{
			limit:  config.RequestsPerHour,
			window: time.Hour,
		}
	}

	return limiter
}

// createPathRateLimiter 创建路径限流器
func (arl *AdvancedRateLimiter) createPathRateLimiter(rule config.PathRateLimitRule) *RateLimiter {
	limiter := &RateLimiter{
		lastRequest: time.Now(),
	}

	if rule.RequestsPerMinute > 0 {
		limiter.perMinute = &WindowLimiter{
			limit:  rule.RequestsPerMinute,
			window: time.Minute,
		}
	}

	if rule.BurstSize > 0 {
		limiter.burstLimiter = newRateLimitTokenBucket(rule.RequestsPerMinute/60, rule.BurstSize)
	}

	return limiter
}

// createMethodRateLimiter 创建方法限流器
func (arl *AdvancedRateLimiter) createMethodRateLimiter(method string, limit int) *RateLimiter {
	return &RateLimiter{
		perMinute: &WindowLimiter{
			limit:  limit,
			window: time.Minute,
		},
		lastRequest: time.Now(),
	}
}

// createGlobalRateLimiter 创建全局限流器
func (arl *AdvancedRateLimiter) createGlobalRateLimiter() *RateLimiter {
	config := arl.config.GlobalRateLimit

	limiter := &RateLimiter{
		lastRequest: time.Now(),
	}

	if config.RequestsPerSecond > 0 {
		limiter.perSecond = &WindowLimiter{
			limit:  config.RequestsPerSecond,
			window: time.Second,
		}
	}

	if config.RequestsPerMinute > 0 {
		limiter.perMinute = &WindowLimiter{
			limit:  config.RequestsPerMinute,
			window: time.Minute,
		}
	}

	return limiter
}

// Allow 检查是否允许请求
func (rl *RateLimiter) Allow(context string) (bool, string) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	rl.totalRequests++
	rl.lastRequest = now

	// 检查突发限制
	if rl.burstLimiter != nil {
		if !rl.burstLimiter.Allow() {
			rl.blockedRequests++
			return true, fmt.Sprintf("%s: burst limit exceeded", context)
		}
	}

	// 检查各时间窗口限制
	if rl.perSecond != nil {
		if !rl.perSecond.Allow() {
			rl.blockedRequests++
			return true, fmt.Sprintf("%s: per-second limit exceeded", context)
		}
	}

	if rl.perMinute != nil {
		if !rl.perMinute.Allow() {
			rl.blockedRequests++
			return true, fmt.Sprintf("%s: per-minute limit exceeded", context)
		}
	}

	if rl.perHour != nil {
		if !rl.perHour.Allow() {
			rl.blockedRequests++
			return true, fmt.Sprintf("%s: per-hour limit exceeded", context)
		}
	}

	return false, ""
}

// Allow 检查窗口限制
func (wl *WindowLimiter) Allow() bool {
	wl.mutex.Lock()
	defer wl.mutex.Unlock()

	now := time.Now()

	// 清理过期请求
	cutoff := now.Add(-wl.window)
	var validRequests []time.Time
	for _, req := range wl.requests {
		if req.After(cutoff) {
			validRequests = append(validRequests, req)
		}
	}
	wl.requests = validRequests

	// 检查是否超过限制
	if len(wl.requests) >= wl.limit {
		return false
	}

	// 添加当前请求
	wl.requests = append(wl.requests, now)
	return true
}

// extractUser 从请求中提取用户信息
func (arl *AdvancedRateLimiter) extractUser(r *http.Request) string {
	// 从Authorization头提取
	if auth := r.Header.Get("Authorization"); auth != "" {
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) == 2 && parts[0] == "Bearer" {
			return parts[1] // 简化处理，实际应该解析JWT等
		}
	}

	// 从Cookie提取
	if cookie, err := r.Cookie("user_id"); err == nil {
		return cookie.Value
	}

	// 从URL参数提取
	if userID := r.URL.Query().Get("user_id"); userID != "" {
		return userID
	}

	return ""
}

// GetStats 获取限流统计信息
func (arl *AdvancedRateLimiter) GetStats() map[string]interface{} {
	arl.mutex.RLock()
	defer arl.mutex.RUnlock()

	stats := map[string]interface{}{
		"ip_limiters":     len(arl.ipLimiters),
		"user_limiters":   len(arl.userLimiters),
		"path_limiters":   len(arl.pathLimiters),
		"method_limiters": len(arl.methodLimiters),
	}

	// 统计各限流器的使用情况
	ipStats := make(map[string]interface{})
	for ip, limiter := range arl.ipLimiters {
		limiter.mutex.RLock()
		ipStats[ip] = map[string]interface{}{
			"total_requests":   limiter.totalRequests,
			"blocked_requests": limiter.blockedRequests,
			"last_request":     limiter.lastRequest,
		}
		limiter.mutex.RUnlock()
	}
	stats["ip_stats"] = ipStats

	return stats
}

// Cleanup 清理过期的限流器
func (arl *AdvancedRateLimiter) Cleanup() {
	arl.mutex.Lock()
	defer arl.mutex.Unlock()

	now := time.Now()
	expireTime := 10 * time.Minute // 10分钟未使用则清理

	// 清理IP限流器
	for ip, limiter := range arl.ipLimiters {
		limiter.mutex.RLock()
		lastRequest := limiter.lastRequest
		limiter.mutex.RUnlock()

		if now.Sub(lastRequest) > expireTime {
			delete(arl.ipLimiters, ip)
		}
	}

	// 清理用户限流器
	for user, limiter := range arl.userLimiters {
		limiter.mutex.RLock()
		lastRequest := limiter.lastRequest
		limiter.mutex.RUnlock()

		if now.Sub(lastRequest) > expireTime {
			delete(arl.userLimiters, user)
		}
	}

	arl.log.Debugf("Cleaned up rate limiters: %d IP, %d user remaining",
		len(arl.ipLimiters), len(arl.userLimiters))
}

// rateLimitTokenBucket 令牌桶限流器 (内部实现)
type rateLimitTokenBucket struct {
	rate     int       // 每秒令牌数
	burst    int       // 桶容量
	tokens   int       // 当前令牌数
	lastTime time.Time // 上次更新时间
	mutex    sync.Mutex
}

// newRateLimitTokenBucket 创建令牌桶
func newRateLimitTokenBucket(rate, burst int) *rateLimitTokenBucket {
	return &rateLimitTokenBucket{
		rate:     rate,
		burst:    burst,
		tokens:   burst,
		lastTime: time.Now(),
	}
}

// Allow 检查是否允许请求
func (tb *rateLimitTokenBucket) Allow() bool {
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

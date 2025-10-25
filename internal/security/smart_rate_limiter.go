package security

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// RateLimitAlgorithm 限流算法类型
type RateLimitAlgorithm string

const (
	AlgorithmFixedWindow    RateLimitAlgorithm = "fixed_window"    // 固定窗口
	AlgorithmSlidingWindow  RateLimitAlgorithm = "sliding_window"  // 滑动窗口
	AlgorithmTokenBucket    RateLimitAlgorithm = "token_bucket"    // 令牌桶
	AlgorithmLeakyBucket    RateLimitAlgorithm = "leaky_bucket"    // 漏桶
	AlgorithmAdaptive       RateLimitAlgorithm = "adaptive"        // 自适应
)

// SmartRateLimiter 智能限流器（支持多种算法）
type SmartRateLimiter struct {
	algorithm  RateLimitAlgorithm
	maxRate    int           // 最大速率（请求/秒）
	capacity   int           // 容量
	windowSize time.Duration // 窗口大小

	// 滑动窗口
	slidingWindow *SlidingWindowLimiter

	// 令牌桶
	tokenBucket *TokenBucketLimiter

	// 漏桶
	leakyBucket *LeakyBucketLimiter

	// 自适应限流
	adaptiveLimiter *AdaptiveLimiter

	mutex sync.RWMutex
	log   *logrus.Entry
}

// NewSmartRateLimiter 创建智能限流器
func NewSmartRateLimiter(algorithm RateLimitAlgorithm, maxRate, capacity int, windowSize time.Duration) *SmartRateLimiter {
	limiter := &SmartRateLimiter{
		algorithm:  algorithm,
		maxRate:    maxRate,
		capacity:   capacity,
		windowSize: windowSize,
		log: logrus.WithFields(logrus.Fields{
			"component": "smart_rate_limiter",
			"algorithm": algorithm,
		}),
	}

	// 根据算法类型初始化对应的限流器
	switch algorithm {
	case AlgorithmSlidingWindow:
		limiter.slidingWindow = NewSlidingWindowLimiter(maxRate, windowSize)
	case AlgorithmTokenBucket:
		limiter.tokenBucket = NewTokenBucketLimiter(maxRate, capacity)
	case AlgorithmLeakyBucket:
		limiter.leakyBucket = NewLeakyBucketLimiter(maxRate, capacity)
	case AlgorithmAdaptive:
		limiter.adaptiveLimiter = NewAdaptiveLimiter(maxRate, capacity)
	default:
		// 默认使用滑动窗口
		limiter.slidingWindow = NewSlidingWindowLimiter(maxRate, windowSize)
	}

	return limiter
}

// Allow 检查是否允许请求
func (srl *SmartRateLimiter) Allow() bool {
	srl.mutex.RLock()
	defer srl.mutex.RUnlock()

	switch srl.algorithm {
	case AlgorithmSlidingWindow:
		return srl.slidingWindow.Allow()
	case AlgorithmTokenBucket:
		return srl.tokenBucket.Allow()
	case AlgorithmLeakyBucket:
		return srl.leakyBucket.Allow()
	case AlgorithmAdaptive:
		return srl.adaptiveLimiter.Allow()
	default:
		return srl.slidingWindow.Allow()
	}
}

// GetStats 获取统计信息
func (srl *SmartRateLimiter) GetStats() map[string]interface{} {
	srl.mutex.RLock()
	defer srl.mutex.RUnlock()

	switch srl.algorithm {
	case AlgorithmSlidingWindow:
		return srl.slidingWindow.GetStats()
	case AlgorithmTokenBucket:
		return srl.tokenBucket.GetStats()
	case AlgorithmLeakyBucket:
		return srl.leakyBucket.GetStats()
	case AlgorithmAdaptive:
		return srl.adaptiveLimiter.GetStats()
	default:
		return srl.slidingWindow.GetStats()
	}
}

// ============================================================================
// 滑动窗口限流器
// ============================================================================

// SlidingWindowLimiter 滑动窗口限流器
type SlidingWindowLimiter struct {
	maxRate    int
	windowSize time.Duration
	requests   []time.Time
	mutex      sync.RWMutex
}

// NewSlidingWindowLimiter 创建滑动窗口限流器
func NewSlidingWindowLimiter(maxRate int, windowSize time.Duration) *SlidingWindowLimiter {
	return &SlidingWindowLimiter{
		maxRate:    maxRate,
		windowSize: windowSize,
		requests:   make([]time.Time, 0),
	}
}

// Allow 检查是否允许请求
func (swl *SlidingWindowLimiter) Allow() bool {
	swl.mutex.Lock()
	defer swl.mutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-swl.windowSize)

	// 清理过期请求
	validRequests := make([]time.Time, 0)
	for _, reqTime := range swl.requests {
		if reqTime.After(cutoff) {
			validRequests = append(validRequests, reqTime)
		}
	}
	swl.requests = validRequests

	// 检查是否超过限制
	if len(swl.requests) >= swl.maxRate {
		return false
	}

	// 添加当前请求
	swl.requests = append(swl.requests, now)
	return true
}

// GetStats 获取统计信息
func (swl *SlidingWindowLimiter) GetStats() map[string]interface{} {
	swl.mutex.RLock()
	defer swl.mutex.RUnlock()

	return map[string]interface{}{
		"algorithm":         "sliding_window",
		"current_requests":  len(swl.requests),
		"max_rate":          swl.maxRate,
		"window_size_sec":   swl.windowSize.Seconds(),
	}
}

// ============================================================================
// 令牌桶限流器
// ============================================================================

// TokenBucketLimiter 令牌桶限流器
type TokenBucketLimiter struct {
	maxRate    int           // 每秒生成令牌数
	capacity   int           // 桶容量
	tokens     int           // 当前令牌数
	lastUpdate time.Time     // 上次更新时间
	mutex      sync.RWMutex
}

// NewTokenBucketLimiter 创建令牌桶限流器
func NewTokenBucketLimiter(maxRate, capacity int) *TokenBucketLimiter {
	return &TokenBucketLimiter{
		maxRate:    maxRate,
		capacity:   capacity,
		tokens:     capacity, // 初始满桶
		lastUpdate: time.Now(),
	}
}

// Allow 检查是否允许请求
func (tbl *TokenBucketLimiter) Allow() bool {
	tbl.mutex.Lock()
	defer tbl.mutex.Unlock()

	now := time.Now()
	elapsed := now.Sub(tbl.lastUpdate)

	// 计算新增令牌数
	tokensToAdd := int(elapsed.Seconds() * float64(tbl.maxRate))
	if tokensToAdd > 0 {
		tbl.tokens = min(tbl.tokens+tokensToAdd, tbl.capacity)
		tbl.lastUpdate = now
	}

	// 检查是否有令牌
	if tbl.tokens <= 0 {
		return false
	}

	// 消耗一个令牌
	tbl.tokens--
	return true
}

// GetStats 获取统计信息
func (tbl *TokenBucketLimiter) GetStats() map[string]interface{} {
	tbl.mutex.RLock()
	defer tbl.mutex.RUnlock()

	return map[string]interface{}{
		"algorithm":      "token_bucket",
		"current_tokens": tbl.tokens,
		"capacity":       tbl.capacity,
		"max_rate":       tbl.maxRate,
	}
}

// ============================================================================
// 漏桶限流器
// ============================================================================

// LeakyBucketLimiter 漏桶限流器
type LeakyBucketLimiter struct {
	maxRate    int           // 每秒漏出速率
	capacity   int           // 桶容量
	queue      int           // 当前队列长度
	lastLeak   time.Time     // 上次漏水时间
	mutex      sync.RWMutex
}

// NewLeakyBucketLimiter 创建漏桶限流器
func NewLeakyBucketLimiter(maxRate, capacity int) *LeakyBucketLimiter {
	return &LeakyBucketLimiter{
		maxRate:  maxRate,
		capacity: capacity,
		queue:    0,
		lastLeak: time.Now(),
	}
}

// Allow 检查是否允许请求
func (lbl *LeakyBucketLimiter) Allow() bool {
	lbl.mutex.Lock()
	defer lbl.mutex.Unlock()

	now := time.Now()
	elapsed := now.Sub(lbl.lastLeak)

	// 漏水（处理队列中的请求）
	if elapsed > 0 {
		tokensToLeak := int(elapsed.Seconds() * float64(lbl.maxRate))
		lbl.queue = max(0, lbl.queue-tokensToLeak)
		lbl.lastLeak = now
	}

	// 检查是否溢出
	if lbl.queue >= lbl.capacity {
		return false
	}

	// 入队
	lbl.queue++
	return true
}

// GetStats 获取统计信息
func (lbl *LeakyBucketLimiter) GetStats() map[string]interface{} {
	lbl.mutex.RLock()
	defer lbl.mutex.RUnlock()

	return map[string]interface{}{
		"algorithm":      "leaky_bucket",
		"current_queue":  lbl.queue,
		"capacity":       lbl.capacity,
		"max_rate":       lbl.maxRate,
	}
}

// ============================================================================
// 自适应限流器
// ============================================================================

// AdaptiveLimiter 自适应限流器
type AdaptiveLimiter struct {
	maxRate    int
	capacity   int
	tokens     int
	lastUpdate time.Time
	// 自适应参数
	targetLatency time.Duration // 目标延迟
	currentRate   float64       // 当前速率
	mutex         sync.RWMutex
}

// NewAdaptiveLimiter 创建自适应限流器
func NewAdaptiveLimiter(maxRate, capacity int) *AdaptiveLimiter {
	return &AdaptiveLimiter{
		maxRate:       maxRate,
		capacity:      capacity,
		tokens:        capacity,
		lastUpdate:    time.Now(),
		targetLatency: 100 * time.Millisecond,
		currentRate:   float64(maxRate),
	}
}

// Allow 检查是否允许请求
func (al *AdaptiveLimiter) Allow() bool {
	al.mutex.Lock()
	defer al.mutex.Unlock()

	now := time.Now()
	elapsed := now.Sub(al.lastUpdate)

	// 根据当前速率生成令牌
	tokensToAdd := int(elapsed.Seconds() * al.currentRate)
	if tokensToAdd > 0 {
		al.tokens = min(al.tokens+tokensToAdd, al.capacity)
		al.lastUpdate = now
	}

	// 检查是否有令牌
	if al.tokens <= 0 {
		return false
	}

	// 消耗一个令牌
	al.tokens--
	return true
}

// UpdateLatency 更新延迟信息（用于自适应调整）
func (al *AdaptiveLimiter) UpdateLatency(latency time.Duration) {
	al.mutex.Lock()
	defer al.mutex.Unlock()

	// 如果延迟超过目标，降低速率
	if latency > al.targetLatency {
		al.currentRate = al.currentRate * 0.9
	} else {
		// 否则逐渐增加速率
		if al.currentRate*1.1 < float64(al.maxRate) {
			al.currentRate = al.currentRate * 1.1
		} else {
			al.currentRate = float64(al.maxRate)
		}
	}
}

// GetStats 获取统计信息
func (al *AdaptiveLimiter) GetStats() map[string]interface{} {
	al.mutex.RLock()
	defer al.mutex.RUnlock()

	return map[string]interface{}{
		"algorithm":       "adaptive",
		"current_tokens":  al.tokens,
		"capacity":        al.capacity,
		"current_rate":    al.currentRate,
		"target_latency":  al.targetLatency.Milliseconds(),
	}
}

// ============================================================================
// 辅助函数
// ============================================================================

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}


package monitor

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// RequestStats 请求统计
type RequestStats struct {
	TotalRequests    int64   `json:"total_requests"`
	SuccessRequests  int64   `json:"success_requests"`
	ErrorRequests    int64   `json:"error_requests"`
	ErrorRate        float64 `json:"error_rate"`
	AvgResponseTime  float64 `json:"avg_response_time_ms"`
	MaxResponseTime  int64   `json:"max_response_time_ms"`
	MinResponseTime  int64   `json:"min_response_time_ms"`
	BytesTransferred int64   `json:"bytes_transferred"`
	RequestsPerSec   float64 `json:"requests_per_sec"`
}

// DomainStats 域名统计
type DomainStats struct {
	Domain         string        `json:"domain"`
	RequestStats   *RequestStats `json:"request_stats"`
	LastAccessTime time.Time     `json:"last_access_time"`
	StatusCodes    map[int]int64 `json:"status_codes"`
}

// Monitor 监控器
type Monitor struct {
	globalStats    *RequestStats
	domainStats    map[string]*DomainStats
	mutex          sync.RWMutex
	startTime      time.Time
	requestTimes   []time.Time
	responseTimes  []int64
	maxHistorySize int
	log            *logrus.Entry
}

// NewMonitor 创建监控器
func NewMonitor() *Monitor {
	return &Monitor{
		globalStats: &RequestStats{
			MinResponseTime: 999999999, // 初始化为一个很大的值
		},
		domainStats:    make(map[string]*DomainStats),
		startTime:      time.Now(),
		requestTimes:   make([]time.Time, 0),
		responseTimes:  make([]int64, 0),
		maxHistorySize: 10000, // 最多保存10000个请求的历史数据
		log: logrus.WithFields(logrus.Fields{
			"component": "monitor",
		}),
	}
}

// RecordRequest 记录请求
func (m *Monitor) RecordRequest(domain string, statusCode int, responseTime time.Duration, bytesSent int64) {
	now := time.Now()
	responseTimeMs := responseTime.Milliseconds()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 更新全局统计
	m.updateGlobalStats(statusCode, responseTimeMs, bytesSent, now)

	// 更新域名统计
	m.updateDomainStats(domain, statusCode, responseTimeMs, bytesSent, now)

	// 记录请求时间（用于计算QPS）
	m.requestTimes = append(m.requestTimes, now)
	if len(m.requestTimes) > m.maxHistorySize {
		m.requestTimes = m.requestTimes[1:]
	}

	// 记录响应时间
	m.responseTimes = append(m.responseTimes, responseTimeMs)
	if len(m.responseTimes) > m.maxHistorySize {
		m.responseTimes = m.responseTimes[1:]
	}
}

// updateGlobalStats 更新全局统计
func (m *Monitor) updateGlobalStats(statusCode int, responseTimeMs int64, bytesSent int64, now time.Time) {
	atomic.AddInt64(&m.globalStats.TotalRequests, 1)
	atomic.AddInt64(&m.globalStats.BytesTransferred, bytesSent)

	if statusCode >= 200 && statusCode < 400 {
		atomic.AddInt64(&m.globalStats.SuccessRequests, 1)
	} else {
		atomic.AddInt64(&m.globalStats.ErrorRequests, 1)
	}

	// 更新响应时间统计
	if responseTimeMs > m.globalStats.MaxResponseTime {
		m.globalStats.MaxResponseTime = responseTimeMs
	}

	if responseTimeMs < m.globalStats.MinResponseTime {
		m.globalStats.MinResponseTime = responseTimeMs
	}

	// 计算平均响应时间
	if len(m.responseTimes) > 0 {
		var total int64
		for _, rt := range m.responseTimes {
			total += rt
		}
		m.globalStats.AvgResponseTime = float64(total) / float64(len(m.responseTimes))
	}

	// 计算错误率
	if m.globalStats.TotalRequests > 0 {
		m.globalStats.ErrorRate = float64(m.globalStats.ErrorRequests) / float64(m.globalStats.TotalRequests) * 100
	}

	// 计算QPS
	m.globalStats.RequestsPerSec = m.calculateQPS()
}

// updateDomainStats 更新域名统计
func (m *Monitor) updateDomainStats(domain string, statusCode int, responseTimeMs int64, bytesSent int64, now time.Time) {
	stats, exists := m.domainStats[domain]
	if !exists {
		stats = &DomainStats{
			Domain: domain,
			RequestStats: &RequestStats{
				MinResponseTime: 999999999,
			},
			StatusCodes: make(map[int]int64),
		}
		m.domainStats[domain] = stats
	}

	stats.LastAccessTime = now
	stats.StatusCodes[statusCode]++

	// 更新请求统计
	atomic.AddInt64(&stats.RequestStats.TotalRequests, 1)
	atomic.AddInt64(&stats.RequestStats.BytesTransferred, bytesSent)

	if statusCode >= 200 && statusCode < 400 {
		atomic.AddInt64(&stats.RequestStats.SuccessRequests, 1)
	} else {
		atomic.AddInt64(&stats.RequestStats.ErrorRequests, 1)
	}

	// 更新响应时间统计
	if responseTimeMs > stats.RequestStats.MaxResponseTime {
		stats.RequestStats.MaxResponseTime = responseTimeMs
	}

	if responseTimeMs < stats.RequestStats.MinResponseTime {
		stats.RequestStats.MinResponseTime = responseTimeMs
	}

	// 计算错误率
	if stats.RequestStats.TotalRequests > 0 {
		stats.RequestStats.ErrorRate = float64(stats.RequestStats.ErrorRequests) / float64(stats.RequestStats.TotalRequests) * 100
	}
}

// calculateQPS 计算每秒请求数
func (m *Monitor) calculateQPS() float64 {
	if len(m.requestTimes) < 2 {
		return 0
	}

	// 计算最近1分钟的QPS
	now := time.Now()
	oneMinuteAgo := now.Add(-time.Minute)

	var recentRequests int
	for i := len(m.requestTimes) - 1; i >= 0; i-- {
		if m.requestTimes[i].After(oneMinuteAgo) {
			recentRequests++
		} else {
			break
		}
	}

	return float64(recentRequests) / 60.0
}

// GetGlobalStats 获取全局统计
func (m *Monitor) GetGlobalStats() *RequestStats {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// 返回副本以避免并发问题
	return &RequestStats{
		TotalRequests:    atomic.LoadInt64(&m.globalStats.TotalRequests),
		SuccessRequests:  atomic.LoadInt64(&m.globalStats.SuccessRequests),
		ErrorRequests:    atomic.LoadInt64(&m.globalStats.ErrorRequests),
		ErrorRate:        m.globalStats.ErrorRate,
		AvgResponseTime:  m.globalStats.AvgResponseTime,
		MaxResponseTime:  m.globalStats.MaxResponseTime,
		MinResponseTime:  m.globalStats.MinResponseTime,
		BytesTransferred: atomic.LoadInt64(&m.globalStats.BytesTransferred),
		RequestsPerSec:   m.globalStats.RequestsPerSec,
	}
}

// GetDomainStats 获取域名统计
func (m *Monitor) GetDomainStats(domain string) *DomainStats {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if stats, exists := m.domainStats[domain]; exists {
		// 返回副本
		return &DomainStats{
			Domain:         stats.Domain,
			RequestStats:   m.copyRequestStats(stats.RequestStats),
			LastAccessTime: stats.LastAccessTime,
			StatusCodes:    m.copyStatusCodes(stats.StatusCodes),
		}
	}

	return nil
}

// GetAllDomainStats 获取所有域名统计
func (m *Monitor) GetAllDomainStats() map[string]*DomainStats {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	result := make(map[string]*DomainStats)
	for domain, stats := range m.domainStats {
		result[domain] = &DomainStats{
			Domain:         stats.Domain,
			RequestStats:   m.copyRequestStats(stats.RequestStats),
			LastAccessTime: stats.LastAccessTime,
			StatusCodes:    m.copyStatusCodes(stats.StatusCodes),
		}
	}

	return result
}

// copyRequestStats 复制请求统计
func (m *Monitor) copyRequestStats(stats *RequestStats) *RequestStats {
	return &RequestStats{
		TotalRequests:    atomic.LoadInt64(&stats.TotalRequests),
		SuccessRequests:  atomic.LoadInt64(&stats.SuccessRequests),
		ErrorRequests:    atomic.LoadInt64(&stats.ErrorRequests),
		ErrorRate:        stats.ErrorRate,
		AvgResponseTime:  stats.AvgResponseTime,
		MaxResponseTime:  stats.MaxResponseTime,
		MinResponseTime:  stats.MinResponseTime,
		BytesTransferred: atomic.LoadInt64(&stats.BytesTransferred),
		RequestsPerSec:   stats.RequestsPerSec,
	}
}

// copyStatusCodes 复制状态码统计
func (m *Monitor) copyStatusCodes(codes map[int]int64) map[int]int64 {
	result := make(map[int]int64)
	for code, count := range codes {
		result[code] = count
	}
	return result
}

// GetTimeSeriesData 获取时间序列数据
func (m *Monitor) GetTimeSeriesData(minutes int) map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	now := time.Now()
	startTime := now.Add(-time.Duration(minutes) * time.Minute)

	// 按分钟分组统计
	buckets := make(map[string]int)
	errors := make(map[string]int)

	for _, reqTime := range m.requestTimes {
		if reqTime.After(startTime) {
			bucket := reqTime.Format("15:04")
			buckets[bucket]++
		}
	}

	// 生成时间标签
	labels := make([]string, 0, minutes)
	requests := make([]int, 0, minutes)
	errorCounts := make([]int, 0, minutes)

	for i := minutes - 1; i >= 0; i-- {
		t := now.Add(-time.Duration(i) * time.Minute)
		label := t.Format("15:04")
		labels = append(labels, label)
		requests = append(requests, buckets[label])
		errorCounts = append(errorCounts, errors[label])
	}

	return map[string]interface{}{
		"labels":     labels,
		"requests":   requests,
		"errors":     errorCounts,
		"start_time": startTime,
		"end_time":   now,
		"interval":   "1m",
	}
}

// GetTopDomains 获取访问量最高的域名
func (m *Monitor) GetTopDomains(limit int) []*DomainStats {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	domains := make([]*DomainStats, 0, len(m.domainStats))
	for _, stats := range m.domainStats {
		domains = append(domains, &DomainStats{
			Domain:         stats.Domain,
			RequestStats:   m.copyRequestStats(stats.RequestStats),
			LastAccessTime: stats.LastAccessTime,
			StatusCodes:    m.copyStatusCodes(stats.StatusCodes),
		})
	}

	// 按总请求数排序
	for i := 0; i < len(domains)-1; i++ {
		for j := i + 1; j < len(domains); j++ {
			if domains[i].RequestStats.TotalRequests < domains[j].RequestStats.TotalRequests {
				domains[i], domains[j] = domains[j], domains[i]
			}
		}
	}

	if len(domains) > limit {
		domains = domains[:limit]
	}

	return domains
}

// GetUptimeStats 获取运行时间统计
func (m *Monitor) GetUptimeStats() map[string]interface{} {
	uptime := time.Since(m.startTime)

	return map[string]interface{}{
		"start_time":     m.startTime,
		"uptime_seconds": uptime.Seconds(),
		"uptime_string":  uptime.String(),
		"current_time":   time.Now(),
	}
}

// Reset 重置统计数据
func (m *Monitor) Reset() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.globalStats = &RequestStats{
		MinResponseTime: 999999999,
	}
	m.domainStats = make(map[string]*DomainStats)
	m.requestTimes = make([]time.Time, 0)
	m.responseTimes = make([]int64, 0)
	m.startTime = time.Now()

	m.log.Info("监控统计数据已重置")
}

// IsHealthy 检查系统是否健康
func (m *Monitor) IsHealthy() bool {
	stats := m.GetGlobalStats()

	// 简单的健康检查规则
	if stats.ErrorRate > 50 { // 错误率超过50%
		return false
	}

	if stats.AvgResponseTime > 10000 { // 平均响应时间超过10秒
		return false
	}

	return true
}

// GetHealthStatus 获取健康状态
func (m *Monitor) GetHealthStatus() map[string]interface{} {
	stats := m.GetGlobalStats()
	healthy := m.IsHealthy()

	status := "healthy"
	if !healthy {
		status = "unhealthy"
	}

	return map[string]interface{}{
		"status":            status,
		"healthy":           healthy,
		"error_rate":        stats.ErrorRate,
		"avg_response_time": stats.AvgResponseTime,
		"total_requests":    stats.TotalRequests,
		"check_time":        time.Now(),
	}
}

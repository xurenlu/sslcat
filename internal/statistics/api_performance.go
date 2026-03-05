package statistics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// APIPerformanceStats API 性能统计
type APIPerformanceStats struct {
	Path             string        `json:"path"`              // API 路径（可能含 domain:pathPattern）
	Domain           string        `json:"domain,omitempty"`  // 域名，从 Path 解析，便于筛选
	Method           string        `json:"method"`            // HTTP 方法
	TotalRequests    int64         `json:"total_requests"`    // 总请求数
	SuccessRequests  int64         `json:"success_requests"`  // 成功请求数 (2xx, 3xx)
	ErrorRequests    int64         `json:"error_requests"`    // 错误请求数 (4xx, 5xx)

	// 业务状态码统计
	BusinessSuccessRequests int64            `json:"business_success_requests"` // 业务成功请求数
	BusinessErrorRequests   int64            `json:"business_error_requests"`   // 业务失败请求数
	BusinessStatusCodes     map[string]int64 `json:"business_status_codes"`     // 业务状态码分布 (code -> count)
	BusinessStatusSource    string           `json:"business_status_source"`    // 业务状态字段来源 (如 "status", "code")

	// 响应时间统计 (毫秒)
	AvgResponseTime float64 `json:"avg_response_time"` // 平均响应时间
	MinResponseTime float64 `json:"min_response_time"` // 最小响应时间
	MaxResponseTime float64 `json:"max_response_time"` // 最大响应时间
	P50ResponseTime float64 `json:"p50_response_time"` // P50 (中位数)
	P95ResponseTime float64 `json:"p95_response_time"` // P95
	P99ResponseTime float64 `json:"p99_response_time"` // P99

	// 时间桶
	ResponseTimeBuckets map[string]int64 `json:"response_time_buckets"` // 响应时间分布

	// 状态码分布
	StatusCodes map[int]int64 `json:"status_codes"` // 状态码分布

	// 时间戳
	FirstSeen time.Time `json:"first_seen"` // 首次记录时间
	LastSeen  time.Time `json:"last_seen"`  // 最后记录时间
}

// APIPerformanceEntry API 性能条目（用于记录单个请求）
type APIPerformanceEntry struct {
	Path         string        `json:"path"`
	Method       string        `json:"method"`
	Status       int           `json:"status"`
	ResponseTime time.Duration `json:"response_time"` // 响应时间
	Timestamp    time.Time     `json:"timestamp"`

	// 业务状态（可选）
	BusinessStatus       *BusinessStatus `json:"business_status,omitempty"` // 业务状态
	IsProxiedAPI         bool            `json:"is_proxied_api"`          // 是否是代理的API
	BackendAddress       string          `json:"backend_address,omitempty"` // 后端地址
}

// BusinessStatus 业务状态
type BusinessStatus struct {
	IsSuccess bool   `json:"is_success"` // 是否成功
	Code      int    `json:"code"`       // 业务状态码
	Message   string `json:"message"`    // 状态消息
	Source    string `json:"source"`     // 来源字段（如 "status", "code" 等）
}

// APIPerformanceCollector API 性能收集器
type APIPerformanceCollector struct {
	mu      sync.RWMutex
	enabled bool
	log     *logrus.Entry

	// 按路径+方法索引的性能统计
	// key: "METHOD:PATH" 例如: "GET:example.com:/api/users/*"
	performanceStats map[string]*APIPerformanceStats

	// 响应时间样本存储（用于计算百分位数）
	// key: "METHOD:PATH"
	responseTimeSamples map[string][]time.Duration

	// 配置
	maxSamplesPerPath int           // 每个路径保留的最大样本数（用于百分位数计算）
	sampleWindow      time.Duration // 样本时间窗口
	cleanupInterval   time.Duration
	maxDataAge        time.Duration

	// 时间桶定义
	timeBuckets []TimeBucket

	// 停止信号
	stopChan chan struct{}
}

// TimeBucket 响应时间桶
type TimeBucket struct {
	Name  string  `json:"name"`
	MinMs float64 `json:"min_ms"`
	MaxMs float64 `json:"max_ms"`
}

// 默认时间桶定义
var defaultTimeBuckets = []TimeBucket{
	{Name: "<10ms", MinMs: 0, MaxMs: 10},
	{Name: "10-50ms", MinMs: 10, MaxMs: 50},
	{Name: "50-100ms", MinMs: 50, MaxMs: 100},
	{Name: "100-200ms", MinMs: 100, MaxMs: 200},
	{Name: "200-500ms", MinMs: 200, MaxMs: 500},
	{Name: "500ms-1s", MinMs: 500, MaxMs: 1000},
	{Name: "1s-2s", MinMs: 1000, MaxMs: 2000},
	{Name: ">2s", MinMs: 2000, MaxMs: 999999},
}

// NewAPIPerformanceCollector 创建 API 性能收集器
func NewAPIPerformanceCollector() *APIPerformanceCollector {
	apc := &APIPerformanceCollector{
		enabled:              true,
		log:                  logrus.WithFields(logrus.Fields{"component": "api_performance_collector"}),
		performanceStats:     make(map[string]*APIPerformanceStats),
		responseTimeSamples:  make(map[string][]time.Duration),
		maxSamplesPerPath:    1000,                    // 保留最近1000个样本
		sampleWindow:         5 * time.Minute,         // 5分钟窗口
		cleanupInterval:      10 * time.Minute,        // 每10分钟清理一次
		maxDataAge:           24 * time.Hour,          // 数据保留24小时
		timeBuckets:          defaultTimeBuckets,
		stopChan:             make(chan struct{}),
	}

	// 启动清理协程
	go apc.cleanupLoop()

	return apc
}

// Record 记录 API 请求性能
func (apc *APIPerformanceCollector) Record(entry APIPerformanceEntry) {
	if !apc.enabled {
		return
	}

	// 构建键
	key := buildAPIKey(entry.Method, entry.Path)

	apc.mu.Lock()
	defer apc.mu.Unlock()

	// 获取或创建统计对象
	stats, exists := apc.performanceStats[key]
	if !exists {
		domain, _ := parseDomainFromPath(entry.Path)
		stats = &APIPerformanceStats{
			Path:                 entry.Path,
			Domain:               domain,
			Method:               entry.Method,
			StatusCodes:          make(map[int]int64),
			ResponseTimeBuckets:   make(map[string]int64),
			BusinessStatusCodes:  make(map[string]int64),
			FirstSeen:            entry.Timestamp,
			LastSeen:             entry.Timestamp,
		}
		apc.performanceStats[key] = stats
	} else if stats.Domain == "" {
		// 兼容旧数据：按需解析 Domain
		stats.Domain, _ = parseDomainFromPath(entry.Path)
	}

	// 更新统计
	stats.TotalRequests++
	stats.LastSeen = entry.Timestamp

	// 更新状态码
	stats.StatusCodes[entry.Status]++

	// 判断是否成功
	if entry.Status >= 200 && entry.Status < 400 {
		stats.SuccessRequests++
	} else {
		stats.ErrorRequests++
	}

	// 更新业务状态码统计
	if entry.BusinessStatus != nil {
		// 更新业务状态来源
		if stats.BusinessStatusSource == "" {
			stats.BusinessStatusSource = entry.BusinessStatus.Source
		}

		// 更新业务状态码分布
		statusKey := fmt.Sprintf("%d", entry.BusinessStatus.Code)
		stats.BusinessStatusCodes[statusKey]++

		// 更新业务成功/失败统计
		if entry.BusinessStatus.IsSuccess {
			stats.BusinessSuccessRequests++
		} else {
			stats.BusinessErrorRequests++
		}
	}

	// 转换响应时间为毫秒
	responseTimeMs := float64(entry.ResponseTime.Milliseconds())

	// 更新响应时间统计
	if stats.TotalRequests == 1 {
		stats.AvgResponseTime = responseTimeMs
		stats.MinResponseTime = responseTimeMs
		stats.MaxResponseTime = responseTimeMs
	} else {
		// 增量更新平均值
		stats.AvgResponseTime = stats.AvgResponseTime +
			(responseTimeMs-stats.AvgResponseTime)/float64(stats.TotalRequests)

		// 更新最小/最大值
		if responseTimeMs < stats.MinResponseTime {
			stats.MinResponseTime = responseTimeMs
		}
		if responseTimeMs > stats.MaxResponseTime {
			stats.MaxResponseTime = responseTimeMs
		}
	}

	// 更新时间桶
	for _, bucket := range apc.timeBuckets {
		if responseTimeMs >= bucket.MinMs && responseTimeMs < bucket.MaxMs {
			stats.ResponseTimeBuckets[bucket.Name]++
			break
		}
	}

	// 保存样本用于百分位数计算
	apc.responseTimeSamples[key] = append(apc.responseTimeSamples[key], entry.ResponseTime)

	// 限制样本数量
	if len(apc.responseTimeSamples[key]) > apc.maxSamplesPerPath {
		// 移除最旧的样本（FIFO）
		apc.responseTimeSamples[key] = apc.responseTimeSamples[key][1:]
	}

	// 修复：不在持锁时更新百分位数（排序操作很慢）
	// 百分位数将在下次读取时异步计算
}

// updatePercentiles 更新百分位数
func (apc *APIPerformanceCollector) updatePercentiles(key string, stats *APIPerformanceStats) {
	samples := apc.responseTimeSamples[key]
	if len(samples) == 0 {
		return
	}

	// 排序样本
	sort.Slice(samples, func(i, j int) bool {
		return samples[i] < samples[j]
	})

	// 计算百分位数
	stats.P50ResponseTime = float64(samples[percentileIndex(samples, 50)])
	stats.P95ResponseTime = float64(samples[percentileIndex(samples, 95)])
	stats.P99ResponseTime = float64(samples[percentileIndex(samples, 99)])
}

// percentileIndex 计算百分位数索引
func percentileIndex(samples []time.Duration, p int) int {
	if len(samples) == 0 {
		return 0
	}
	index := (float64(p) / 100.0) * float64(len(samples))
	if int(index) >= len(samples) {
		return len(samples) - 1
	}
	return int(index)
}

// GetStats 获取所有性能统计，domainFilter 为空时不过滤
func (apc *APIPerformanceCollector) GetStats(domainFilter string) []*APIPerformanceStats {
	apc.mu.Lock()
	defer apc.mu.Unlock()

	stats := make([]*APIPerformanceStats, 0, len(apc.performanceStats))
	for _, s := range apc.performanceStats {
		if domainFilter != "" && s.Domain != domainFilter {
			continue
		}
		// 深拷贝避免数据竞争
		statsCopy := *s
		statsCopy.ResponseTimeBuckets = make(map[string]int64)
		for k, v := range s.ResponseTimeBuckets {
			statsCopy.ResponseTimeBuckets[k] = v
		}
		statsCopy.StatusCodes = make(map[int]int64)
		for k, v := range s.StatusCodes {
			statsCopy.StatusCodes[k] = v
		}
		statsCopy.BusinessStatusCodes = make(map[string]int64)
		for k, v := range s.BusinessStatusCodes {
			statsCopy.BusinessStatusCodes[k] = v
		}

		// 修复：在获取统计时计算百分位数（避免在 Record 时持锁排序）
		key := buildAPIKey(s.Method, s.Path)
		samples := apc.responseTimeSamples[key]
		if len(samples) > 0 {
			// 创建样本副本并排序
			samplesCopy := make([]time.Duration, len(samples))
			copy(samplesCopy, samples)
			sort.Slice(samplesCopy, func(i, j int) bool {
				return samplesCopy[i] < samplesCopy[j]
			})

			// 计算百分位数
			statsCopy.P50ResponseTime = float64(samplesCopy[percentileIndex(samplesCopy, 50)])
			statsCopy.P95ResponseTime = float64(samplesCopy[percentileIndex(samplesCopy, 95)])
			statsCopy.P99ResponseTime = float64(samplesCopy[percentileIndex(samplesCopy, 99)])
		}

		stats = append(stats, &statsCopy)
	}

	// 按平均响应时间排序（降序）
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].AvgResponseTime > stats[j].AvgResponseTime
	})

	return stats
}

// GetDomains 获取所有出现过的域名列表，按字典序排序。省内存：遍历时去重，不额外存储
func (apc *APIPerformanceCollector) GetDomains() []string {
	apc.mu.RLock()
	defer apc.mu.RUnlock()

	seen := make(map[string]struct{})
	for _, s := range apc.performanceStats {
		if s.Domain != "" {
			seen[s.Domain] = struct{}{}
		}
	}
	domains := make([]string, 0, len(seen))
	for d := range seen {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	return domains
}

// GetStatsByPath 获取特定路径的统计
func (apc *APIPerformanceCollector) GetStatsByPath(method, path string) *APIPerformanceStats {
	apc.mu.RLock()
	defer apc.mu.RUnlock()

	key := buildAPIKey(method, path)
	stats, exists := apc.performanceStats[key]
	if !exists {
		return nil
	}

	// 深拷贝
	statsCopy := *stats
	statsCopy.ResponseTimeBuckets = make(map[string]int64)
	for k, v := range stats.ResponseTimeBuckets {
		statsCopy.ResponseTimeBuckets[k] = v
	}
	statsCopy.StatusCodes = make(map[int]int64)
	for k, v := range stats.StatusCodes {
		statsCopy.StatusCodes[k] = v
	}
	statsCopy.BusinessStatusCodes = make(map[string]int64)
	for k, v := range stats.BusinessStatusCodes {
		statsCopy.BusinessStatusCodes[k] = v
	}

	return &statsCopy
}

// GetTopSlowAPIs 获取最慢的 API 列表，domainFilter 为空时不过滤
func (apc *APIPerformanceCollector) GetTopSlowAPIs(n int, domainFilter string) []*APIPerformanceStats {
	stats := apc.GetStats(domainFilter)
	if n > 0 && len(stats) > n {
		stats = stats[:n]
	}
	return stats
}

// GetTopErrorAPIs 获取错误率最高的 API 列表，domainFilter 为空时不过滤
func (apc *APIPerformanceCollector) GetTopErrorAPIs(n int, domainFilter string) []*APIPerformanceStats {
	apc.mu.RLock()
	defer apc.mu.RUnlock()

	type errorRate struct {
		stats     *APIPerformanceStats
		errorRate float64
	}

	rates := make([]errorRate, 0, len(apc.performanceStats))
	for _, s := range apc.performanceStats {
		if domainFilter != "" && s.Domain != domainFilter {
			continue
		}
		if s.TotalRequests == 0 {
			continue
		}
		rate := float64(s.ErrorRequests) / float64(s.TotalRequests)
		rates = append(rates, errorRate{
			stats:     s,
			errorRate: rate,
		})
	}

	sort.Slice(rates, func(i, j int) bool {
		return rates[i].errorRate > rates[j].errorRate
	})

	result := make([]*APIPerformanceStats, 0, n)
	for i := 0; i < len(rates) && (n <= 0 || i < n); i++ {
		result = append(result, rates[i].stats)
	}

	return result
}

// GetTopBusinessErrorAPIs 获取业务失败率最高的 API 列表（JSON 内 code/status 判定），domainFilter 为空时不过滤
func (apc *APIPerformanceCollector) GetTopBusinessErrorAPIs(n int, domainFilter string) []*APIPerformanceStats {
	apc.mu.RLock()
	defer apc.mu.RUnlock()

	type bizRate struct {
		stats   *APIPerformanceStats
		errRate float64
	}
	rates := make([]bizRate, 0, len(apc.performanceStats))
	for _, s := range apc.performanceStats {
		if domainFilter != "" && s.Domain != domainFilter {
			continue
		}
		total := s.BusinessSuccessRequests + s.BusinessErrorRequests
		if total == 0 {
			continue
		}
		rates = append(rates, bizRate{
			stats:   s,
			errRate: float64(s.BusinessErrorRequests) / float64(total),
		})
	}
	sort.Slice(rates, func(i, j int) bool { return rates[i].errRate > rates[j].errRate })
	result := make([]*APIPerformanceStats, 0, n)
	for i := 0; i < len(rates) && (n <= 0 || i < n); i++ {
		result = append(result, rates[i].stats)
	}
	return result
}

// GetMostActiveAPIs 获取请求量最多的 API 列表，domainFilter 为空时不过滤
func (apc *APIPerformanceCollector) GetMostActiveAPIs(n int, domainFilter string) []*APIPerformanceStats {
	apc.mu.RLock()
	defer apc.mu.RUnlock()

	stats := make([]*APIPerformanceStats, 0, len(apc.performanceStats))
	for _, s := range apc.performanceStats {
		if domainFilter != "" && s.Domain != domainFilter {
			continue
		}
		stats = append(stats, s)
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].TotalRequests > stats[j].TotalRequests
	})

	if n > 0 && len(stats) > n {
		stats = stats[:n]
	}

	return stats
}

// Clear 清空统计数据
func (apc *APIPerformanceCollector) Clear() {
	apc.mu.Lock()
	defer apc.mu.Unlock()

	apc.performanceStats = make(map[string]*APIPerformanceStats)
	apc.responseTimeSamples = make(map[string][]time.Duration)
}

// SetEnabled 启用/禁用收集器
func (apc *APIPerformanceCollector) SetEnabled(enabled bool) {
	apc.mu.Lock()
	defer apc.mu.Unlock()
	apc.enabled = enabled
}

// IsEnabled 检查收集器是否启用
func (apc *APIPerformanceCollector) IsEnabled() bool {
	apc.mu.RLock()
	defer apc.mu.RUnlock()
	return apc.enabled
}

// cleanupLoop 定期清理过期数据
func (apc *APIPerformanceCollector) cleanupLoop() {
	ticker := time.NewTicker(apc.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			apc.cleanup()
		case <-apc.stopChan:
			return
		}
	}
}

// cleanup 清理过期数据
func (apc *APIPerformanceCollector) cleanup() {
	apc.mu.Lock()
	defer apc.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-apc.maxDataAge)

	for key, stats := range apc.performanceStats {
		// 删除长时间无数据的路径
		if stats.LastSeen.Before(cutoff) {
			delete(apc.performanceStats, key)
			delete(apc.responseTimeSamples, key)
			apc.log.Debugf("Cleaned up stale data for API: %s", key)
		}
	}
}

// Stop 停止收集器
func (apc *APIPerformanceCollector) Stop() {
	close(apc.stopChan)
}

// buildAPIKey 构建统计键
func buildAPIKey(method, path string) string {
	return method + ":" + path
}

// parseDomainFromPath 从 Path 解析域名。Path 格式: "domain:pathPattern" 或 "pathPattern"
// 返回 (domain, pathPart)，无域名时 domain 为空
func parseDomainFromPath(path string) (domain, pathPart string) {
	if path == "" {
		return "", ""
	}
	idx := strings.Index(path, ":")
	if idx <= 0 {
		return "", path
	}
	// 避免把 /api/v1:xxx 这种误判为域名（域名不含 /）
	candidate := path[:idx]
	if strings.Contains(candidate, "/") {
		return "", path
	}
	return candidate, path[idx+1:]
}

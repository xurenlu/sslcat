package statistics

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// TimeDimension 时间维度
type TimeDimension string

const (
	DimensionHour  TimeDimension = "hour"
	DimensionDay   TimeDimension = "day"
	DimensionMonth TimeDimension = "month"
)

// RequestStats 请求统计数据
type RequestStats struct {
	TotalRequests    int64 `json:"total_requests"`
	NonSuccessCount  int64 `json:"non_success_count"` // 非20x状态码请求数
	UniqueIPs        int64 `json:"unique_ips"`
	UniqueUserAgents int64 `json:"unique_user_agents"`
}

// StatisticsEntry 统计条目
type StatisticsEntry struct {
	Domain    string        `json:"domain"`
	Timestamp time.Time     `json:"timestamp"`
	Dimension TimeDimension `json:"dimension"`
	Stats     RequestStats  `json:"stats"`
}

// AccessRecord 访问记录
type AccessRecord struct {
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Domain    string    `json:"domain"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	Status    int       `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	City      string    `json:"city,omitempty"`
	Country   string    `json:"country,omitempty"`
}

// TopEntry 排行榜条目
type TopEntry struct {
	Key   string  `json:"key"`
	Count int     `json:"count"`
	Score float64 `json:"score,omitempty"`
}

// StatisticsData 统计数据
type StatisticsData struct {
	Dimension   TimeDimension           `json:"dimension"`
	TimeKey     string                  `json:"time_key"`
	DomainStats map[string]RequestStats `json:"domain_stats"`
	TopIPs      []TopEntry              `json:"top_ips"`
	TopUAs      []TopEntry              `json:"top_user_agents"`
	TopCities   []TopEntry              `json:"top_cities"`
	Generated   time.Time               `json:"generated"`
}

// Collector 统计数据收集器
type Collector struct {
	mu      sync.RWMutex
	enabled bool
	dataDir string
	log     *logrus.Entry

	// 漏斗模型
	ipFunnel   *FunnelModel
	uaFunnel   *FunnelModel
	cityFunnel *FunnelModel

	// 实时数据缓存
	ipEntries   map[string]*FunnelEntry
	uaEntries   map[string]*FunnelEntry
	cityEntries map[string]*FunnelEntry

	// 域名统计缓存
	domainStats map[string]map[TimeDimension]map[string]*RequestStats

	// 配置参数
	topN            int
	cleanupInterval time.Duration
	maxDataAge      time.Duration
	geoIPEnabled    bool

	// 内存泄漏防护
	stopChan       chan struct{}
	maxIPEntries   int
	maxUAEntries   int
	maxCityEntries int
	maxDomainStats int
}

// NewCollector 创建统计收集器
func NewCollector(dataDir string, enabled bool) *Collector {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		logrus.WithError(err).Error("创建统计数据目录失败")
	}

	collector := &Collector{
		enabled: enabled,
		dataDir: dataDir,
		log: logrus.WithFields(logrus.Fields{
			"component": "statistics_collector",
		}),

		// 创建漏斗模型
		ipFunnel:   NewFunnelModel(5, 10*time.Minute, 100), // IP: 至少5次访问，10分钟时间跨度，最多100条
		uaFunnel:   NewFunnelModel(3, 5*time.Minute, 50),   // UA: 至少3次访问，5分钟时间跨度，最多50条
		cityFunnel: NewFunnelModel(10, 30*time.Minute, 20), // 城市: 至少10次访问，30分钟时间跨度，最多20条

		// 初始化数据存储
		ipEntries:   make(map[string]*FunnelEntry),
		uaEntries:   make(map[string]*FunnelEntry),
		cityEntries: make(map[string]*FunnelEntry),
		domainStats: make(map[string]map[TimeDimension]map[string]*RequestStats),

		// 默认配置
		topN:            20,
		cleanupInterval: 1 * time.Hour,
		maxDataAge:      30 * 24 * time.Hour, // 30天
		geoIPEnabled:    false,

		// 内存泄漏防护配置
		stopChan:       make(chan struct{}),
		maxIPEntries:   1000, // 最多1000个IP条目
		maxUAEntries:   500,  // 最多500个UA条目
		maxCityEntries: 200,  // 最多200个城市条目
		maxDomainStats: 100,  // 最多100个域名统计
	}

	if enabled {
		// 启动清理任务
		go collector.startCleanupTask()
		collector.log.Info("统计收集器已启动")
	}

	return collector
}

// RecordAccess 记录访问数据
func (c *Collector) RecordAccess(record *AccessRecord) {
	if !c.enabled {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := record.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	// 更新漏斗条目
	c.ipFunnel.UpdateEntry(c.ipEntries, record.IP, now)
	c.uaFunnel.UpdateEntry(c.uaEntries, record.UserAgent, now)

	// 如果启用了地理位置且有城市信息
	if c.geoIPEnabled && record.City != "" {
		c.cityFunnel.UpdateEntry(c.cityEntries, record.City, now)
	}

	// 更新域名统计
	c.updateDomainStats(record, now)
}

// updateDomainStats 更新域名统计数据
func (c *Collector) updateDomainStats(record *AccessRecord, timestamp time.Time) {
	domain := record.Domain
	if domain == "" {
		domain = "default"
	}

	// 确保域名统计结构存在
	if c.domainStats[domain] == nil {
		c.domainStats[domain] = make(map[TimeDimension]map[string]*RequestStats)
	}

	dimensions := []TimeDimension{DimensionHour, DimensionDay, DimensionMonth}

	for _, dim := range dimensions {
		timeKey := c.getTimeKey(timestamp, dim)

		if c.domainStats[domain][dim] == nil {
			c.domainStats[domain][dim] = make(map[string]*RequestStats)
		}

		stats := c.domainStats[domain][dim][timeKey]
		if stats == nil {
			stats = &RequestStats{}
			c.domainStats[domain][dim][timeKey] = stats
		}

		// 更新统计
		stats.TotalRequests++
		if record.Status < 200 || record.Status >= 300 {
			stats.NonSuccessCount++
		}

		// 这里简化处理，实际应该基于时间窗口计算unique值
		// 在真实实现中需要维护独立的集合来跟踪唯一值
	}
}

// getTimeKey 获取时间键
func (c *Collector) getTimeKey(t time.Time, dimension TimeDimension) string {
	switch dimension {
	case DimensionHour:
		return t.Format("2006-01-02-15")
	case DimensionDay:
		return t.Format("2006-01-02")
	case DimensionMonth:
		return t.Format("2006-01")
	default:
		return t.Format("2006-01-02-15")
	}
}

// GetStatistics 获取统计数据
func (c *Collector) GetStatistics(dimension TimeDimension, timeKey string, domain string) (*StatisticsData, error) {
	if !c.enabled {
		return nil, fmt.Errorf("统计收集器未启用")
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()

	// 如果timeKey为空，使用当前时间
	if timeKey == "" {
		timeKey = c.getTimeKey(now, dimension)
	}

	// 获取过滤后的Top条目
	topIPs := c.getTopEntries(c.ipFunnel.Filter(c.ipEntries, now))
	topUAs := c.getTopEntries(c.uaFunnel.Filter(c.uaEntries, now))
	topCities := c.getTopEntries(c.cityFunnel.Filter(c.cityEntries, now))

	// 获取域名统计
	domainStats := make(map[string]RequestStats)
	if domain == "" || domain == "all" {
		// 获取所有域名统计
		for d, dimStats := range c.domainStats {
			if dimStats[dimension] != nil && dimStats[dimension][timeKey] != nil {
				domainStats[d] = *dimStats[dimension][timeKey]
			}
		}
	} else {
		// 获取特定域名统计
		if c.domainStats[domain] != nil &&
			c.domainStats[domain][dimension] != nil &&
			c.domainStats[domain][dimension][timeKey] != nil {
			domainStats[domain] = *c.domainStats[domain][dimension][timeKey]
		}
	}

	return &StatisticsData{
		Dimension:   dimension,
		TimeKey:     timeKey,
		DomainStats: domainStats,
		TopIPs:      topIPs,
		TopUAs:      topUAs,
		TopCities:   topCities,
		Generated:   now,
	}, nil
}

// getTopEntries 获取Top条目
func (c *Collector) getTopEntries(entries []*FunnelEntry) []TopEntry {
	var result []TopEntry
	limit := c.topN
	if len(entries) < limit {
		limit = len(entries)
	}

	for i := 0; i < limit; i++ {
		result = append(result, TopEntry{
			Key:   entries[i].Key,
			Count: entries[i].Count,
			Score: entries[i].WeightedScore,
		})
	}

	return result
}

// startCleanupTask 启动清理任务
func (c *Collector) startCleanupTask() {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !c.enabled {
				return
			}
			c.cleanup()
		case <-c.stopChan:
			c.log.Info("统计收集器清理任务已停止")
			return
		}
	}
}

// cleanup 清理过期数据
func (c *Collector) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// 清理漏斗条目
	c.ipFunnel.CleanupOldEntries(c.ipEntries, c.maxDataAge, now)
	c.uaFunnel.CleanupOldEntries(c.uaEntries, c.maxDataAge, now)
	c.cityFunnel.CleanupOldEntries(c.cityEntries, c.maxDataAge, now)

	// 清理域名统计数据
	c.cleanupDomainStats(now)

	// 限制数据增长（防止内存泄漏）
	c.limitDataGrowth()

	c.log.Debug("完成数据清理")
}

// cleanupDomainStats 清理域名统计数据
func (c *Collector) cleanupDomainStats(now time.Time) {
	for domain, dimStats := range c.domainStats {
		for dim, timeStats := range dimStats {
			for timeKey := range timeStats {
				// 解析时间键判断是否过期
				if c.isTimeKeyExpired(timeKey, dim, now) {
					delete(timeStats, timeKey)
				}
			}
			// 如果维度统计为空，删除它
			if len(timeStats) == 0 {
				delete(dimStats, dim)
			}
		}
		// 如果域名统计为空，删除它
		if len(dimStats) == 0 {
			delete(c.domainStats, domain)
		}
	}
}

// isTimeKeyExpired 检查时间键是否过期
func (c *Collector) isTimeKeyExpired(timeKey string, dimension TimeDimension, now time.Time) bool {
	var format string
	var maxAge time.Duration

	switch dimension {
	case DimensionHour:
		format = "2006-01-02-15"
		maxAge = 7 * 24 * time.Hour // 保留7天的小时数据
	case DimensionDay:
		format = "2006-01-02"
		maxAge = 30 * 24 * time.Hour // 保留30天的日数据
	case DimensionMonth:
		format = "2006-01"
		maxAge = 365 * 24 * time.Hour // 保留1年的月数据
	default:
		return false
	}

	t, err := time.Parse(format, timeKey)
	if err != nil {
		return true // 解析失败，认为过期
	}

	return now.Sub(t) > maxAge
}

// limitDataGrowth 限制数据增长（防止内存泄漏）
func (c *Collector) limitDataGrowth() {
	// 限制 IP 条目数量
	if len(c.ipEntries) > c.maxIPEntries {
		c.cleanupOldEntries(c.ipEntries, c.maxIPEntries/2)
		c.log.Warnf("IP条目数量超限，清理到 %d 条", len(c.ipEntries))
	}

	// 限制 UA 条目数量
	if len(c.uaEntries) > c.maxUAEntries {
		c.cleanupOldEntries(c.uaEntries, c.maxUAEntries/2)
		c.log.Warnf("UA条目数量超限，清理到 %d 条", len(c.uaEntries))
	}

	// 限制城市条目数量
	if len(c.cityEntries) > c.maxCityEntries {
		c.cleanupOldEntries(c.cityEntries, c.maxCityEntries/2)
		c.log.Warnf("城市条目数量超限，清理到 %d 条", len(c.cityEntries))
	}

	// 限制域名统计数量
	if len(c.domainStats) > c.maxDomainStats {
		c.cleanupOldDomainStats(c.maxDomainStats / 2)
		c.log.Warnf("域名统计数量超限，清理到 %d 个", len(c.domainStats))
	}
}

// cleanupOldEntries 清理最旧的条目
func (c *Collector) cleanupOldEntries(entries map[string]*FunnelEntry, targetCount int) {
	if len(entries) <= targetCount {
		return
	}

	// 按最后访问时间排序
	type entryWithTime struct {
		key  string
		time time.Time
	}

	var sortedEntries []entryWithTime
	for key, entry := range entries {
		sortedEntries = append(sortedEntries, entryWithTime{
			key:  key,
			time: entry.LastAccess,
		})
	}

	// 按时间排序（最旧的在前）
	for i := 0; i < len(sortedEntries)-1; i++ {
		for j := i + 1; j < len(sortedEntries); j++ {
			if sortedEntries[i].time.After(sortedEntries[j].time) {
				sortedEntries[i], sortedEntries[j] = sortedEntries[j], sortedEntries[i]
			}
		}
	}

	// 删除最旧的条目
	deleteCount := len(entries) - targetCount
	for i := 0; i < deleteCount && i < len(sortedEntries); i++ {
		delete(entries, sortedEntries[i].key)
	}
}

// cleanupOldDomainStats 清理最旧的域名统计
func (c *Collector) cleanupOldDomainStats(targetCount int) {
	if len(c.domainStats) <= targetCount {
		return
	}

	// 按域名统计条目数量排序，删除条目最少的
	type domainWithCount struct {
		domain string
		count  int
	}

	var sortedDomains []domainWithCount
	for domain, dimStats := range c.domainStats {
		totalCount := 0
		for _, timeStats := range dimStats {
			totalCount += len(timeStats)
		}
		sortedDomains = append(sortedDomains, domainWithCount{
			domain: domain,
			count:  totalCount,
		})
	}

	// 按统计条目数量排序（最少的在前）
	for i := 0; i < len(sortedDomains)-1; i++ {
		for j := i + 1; j < len(sortedDomains); j++ {
			if sortedDomains[i].count > sortedDomains[j].count {
				sortedDomains[i], sortedDomains[j] = sortedDomains[j], sortedDomains[i]
			}
		}
	}

	// 删除统计条目最少的域名
	deleteCount := len(c.domainStats) - targetCount
	for i := 0; i < deleteCount && i < len(sortedDomains); i++ {
		delete(c.domainStats, sortedDomains[i].domain)
	}
}

// Stop 停止统计收集器
func (c *Collector) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stopChan != nil {
		close(c.stopChan)
		c.stopChan = nil
	}

	c.enabled = false
	c.log.Info("统计收集器已停止")
}

// SaveToFile 保存统计数据到文件
func (c *Collector) SaveToFile(data *StatisticsData, filename string) error {
	if !c.enabled {
		return fmt.Errorf("统计收集器未启用")
	}

	filepath := filepath.Join(c.dataDir, filename)
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("创建文件失败: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// LoadFromFile 从文件加载统计数据
func (c *Collector) LoadFromFile(filename string) (*StatisticsData, error) {
	filepath := filepath.Join(c.dataDir, filename)
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	var data StatisticsData
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return nil, fmt.Errorf("解析文件失败: %w", err)
	}

	return &data, nil
}

// SetEnabled 设置是否启用
func (c *Collector) SetEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = enabled
	c.log.Infof("统计收集器已%s", map[bool]string{true: "启用", false: "禁用"}[enabled])
}

// SetTopN 设置Top N数量
func (c *Collector) SetTopN(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.topN = n
}

// SetGeoIPEnabled 设置是否启用地理位置功能
func (c *Collector) SetGeoIPEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.geoIPEnabled = enabled
}

// GetStats 获取收集器统计信息
func (c *Collector) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"enabled":          c.enabled,
		"top_n":            c.topN,
		"geoip_enabled":    c.geoIPEnabled,
		"cleanup_interval": c.cleanupInterval.String(),
		"max_data_age":     c.maxDataAge.String(),
		"ip_entries":       len(c.ipEntries),
		"ua_entries":       len(c.uaEntries),
		"city_entries":     len(c.cityEntries),
		"domain_count":     len(c.domainStats),
		"ip_funnel":        c.ipFunnel.GetStats(),
		"ua_funnel":        c.uaFunnel.GetStats(),
		"city_funnel":      c.cityFunnel.GetStats(),
	}
}

// ResolveIPToCity 解析IP到城市（示例实现，实际需要集成GeoIP库）
func (c *Collector) ResolveIPToCity(ip string) (city, country string) {
	// 这里应该集成真实的GeoIP解析库，如MaxMind GeoLite2
	// 现在返回示例数据
	if net.ParseIP(ip) == nil {
		return "Unknown", "Unknown"
	}

	// 简单的示例逻辑
	return "Unknown", "Unknown"
}

// RecordAccessFromHTTP 从HTTP请求记录访问数据
func (c *Collector) RecordAccessFromHTTP(r *http.Request, statusCode int) {
	if !c.enabled {
		return
	}

	clientIP := c.getClientIP(r)
	userAgent := r.Header.Get("User-Agent")
	city, country := c.ResolveIPToCity(clientIP)

	record := &AccessRecord{
		IP:        clientIP,
		UserAgent: userAgent,
		Domain:    r.Host,
		Method:    r.Method,
		URL:       r.RequestURI,
		Status:    statusCode,
		Timestamp: time.Now(),
		City:      city,
		Country:   country,
	}

	c.RecordAccess(record)
}

// getClientIP 获取客户端IP
func (c *Collector) getClientIP(r *http.Request) string {
	// 优先使用 X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}

	// 使用 X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// 使用 RemoteAddr
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}

	return r.RemoteAddr
}

package report

import (
	"fmt"
	"time"

	"github.com/xurenlu/sslcat/internal/ddos"
	"github.com/xurenlu/sslcat/internal/monitor"
	"github.com/xurenlu/sslcat/internal/ssl"
	"github.com/xurenlu/sslcat/internal/statistics"
	"github.com/xurenlu/sslcat/internal/waf"
)

// ReportData 报告数据
type ReportData struct {
	TimeRange      string                 `json:"time_range"`
	StartTime      time.Time              `json:"start_time"`
	EndTime        time.Time              `json:"end_time"`
	HighLoadEvents []HighLoadEvent        `json:"high_load_events"`
	AttackEvents   []AttackEventSummary   `json:"attack_events"`
	CertIssues     []CertIssue            `json:"cert_issues"`
	ErrorRequests  ErrorRequestStats      `json:"error_requests"`
	SystemStats    SystemStats            `json:"system_stats"`
}

// HighLoadEvent 高负载事件
type HighLoadEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	CPUPercent    float64   `json:"cpu_percent"`
	MemoryPercent float64   `json:"memory_percent"`
	MemoryMB      float64   `json:"memory_mb"`
}

// AttackEventSummary 攻击事件摘要
type AttackEventSummary struct {
	Type         string    `json:"type"`          // waf, ddos
	Count        int       `json:"count"`         // 总次数
	Blocked      int       `json:"blocked"`       // 被拦截次数
	Severity     string    `json:"severity"`      // low, medium, high, critical
	FirstSeen    time.Time `json:"first_seen"`    // 首次出现时间
	LastSeen     time.Time `json:"last_seen"`    // 最后出现时间
	TopIPs       []string  `json:"top_ips"`       // 主要攻击IP
	TopCountries []string  `json:"top_countries"` // 主要来源国家
	TopURLs      []string  `json:"top_urls"`       // 主要攻击目标URL
}

// CertIssue 证书问题
type CertIssue struct {
	Domain     string    `json:"domain"`
	Status     string    `json:"status"`     // expired, expiring_soon
	ExpiresAt  time.Time `json:"expires_at"`
	DaysLeft   int       `json:"days_left"`
	Issuer     string    `json:"issuer"`
	SelfSigned bool      `json:"self_signed"`
}

// ErrorRequestStats 错误请求统计
type ErrorRequestStats struct {
	TotalRequests    int64            `json:"total_requests"`
	NonSuccessCount  int64            `json:"non_success_count"`
	NonSuccessRate   float64          `json:"non_success_rate"`
	StatusCodes      map[int]int64    `json:"status_codes"`
	TopErrorURLs     []URLStat        `json:"top_error_urls"`
}

// URLStat URL统计
type URLStat struct {
	URL   string `json:"url"`
	Count int64  `json:"count"`
}

// SystemStats 系统统计
type SystemStats struct {
	AvgCPUPercent    float64 `json:"avg_cpu_percent"`
	MaxCPUPercent    float64 `json:"max_cpu_percent"`
	AvgMemoryPercent float64 `json:"avg_memory_percent"`
	MaxMemoryPercent float64 `json:"max_memory_percent"`
	AvgMemoryMB      float64 `json:"avg_memory_mb"`
	MaxMemoryMB      float64 `json:"max_memory_mb"`
}

// DataCollector 数据收集器
type DataCollector struct {
	metricsStorage *monitor.MetricsStorage
	wafEngine      interface{ GetEvents(int) []waf.AttackEvent } // 支持Engine和AdvancedEngine
	ddosProtector  *ddos.Protector
	sslManager     *ssl.Manager
	statsCollector *statistics.Collector
}

// NewDataCollector 创建数据收集器
func NewDataCollector(
	metricsStorage *monitor.MetricsStorage,
	wafEngine interface{ GetEvents(int) []waf.AttackEvent }, // 支持Engine和AdvancedEngine
	ddosProtector *ddos.Protector,
	sslManager *ssl.Manager,
	statsCollector *statistics.Collector,
) *DataCollector {
	return &DataCollector{
		metricsStorage: metricsStorage,
		wafEngine:      wafEngine,
		ddosProtector:  ddosProtector,
		sslManager:     sslManager,
		statsCollector: statsCollector,
	}
}

// CollectReportData 收集报告数据
func (dc *DataCollector) CollectReportData(startTime, endTime time.Time) (*ReportData, error) {
	data := &ReportData{
		StartTime:      startTime,
		EndTime:        endTime,
		TimeRange:      fmt.Sprintf("%s 至 %s", startTime.Format("2006-01-02 15:04:05"), endTime.Format("2006-01-02 15:04:05")),
		HighLoadEvents: []HighLoadEvent{},
		AttackEvents:   []AttackEventSummary{},
		CertIssues:     []CertIssue{},
		ErrorRequests:  ErrorRequestStats{StatusCodes: make(map[int]int64)},
	}

	// 收集高负载事件
	if err := dc.collectHighLoadEvents(data, startTime, endTime); err != nil {
		return nil, fmt.Errorf("收集高负载事件失败: %w", err)
	}

	// 收集攻击事件
	if err := dc.collectAttackEvents(data, startTime, endTime); err != nil {
		return nil, fmt.Errorf("收集攻击事件失败: %w", err)
	}

	// 收集证书问题
	if err := dc.collectCertIssues(data, startTime, endTime); err != nil {
		return nil, fmt.Errorf("收集证书问题失败: %w", err)
	}

	// 收集错误请求统计
	if err := dc.collectErrorRequests(data, startTime, endTime); err != nil {
		return nil, fmt.Errorf("收集错误请求统计失败: %w", err)
	}

	// 计算系统统计
	dc.calculateSystemStats(data)

	return data, nil
}

// collectHighLoadEvents 收集高负载事件
func (dc *DataCollector) collectHighLoadEvents(data *ReportData, startTime, endTime time.Time) error {
	if dc.metricsStorage == nil {
		return nil
	}

	// 定义高负载阈值
	const cpuThreshold = 80.0
	const memoryThreshold = 90.0

	// 使用GetMetrics方法查询指标数据
	result, err := dc.metricsStorage.GetMetrics(startTime, endTime, "1min")
	if err != nil {
		return err
	}

	// 遍历查询结果，检查高负载事件
	for _, metric := range result.Data {
		// 检查是否超过阈值
		if metric.CPUPercent >= cpuThreshold || metric.MemoryPercent >= memoryThreshold {
			data.HighLoadEvents = append(data.HighLoadEvents, HighLoadEvent{
				Timestamp:     metric.Timestamp,
				CPUPercent:    metric.CPUPercent,
				MemoryPercent: metric.MemoryPercent,
				MemoryMB:      metric.MemoryMB,
			})
		}
	}

	return nil
}

// collectAttackEvents 收集攻击事件
func (dc *DataCollector) collectAttackEvents(data *ReportData, startTime, endTime time.Time) error {
	// 收集WAF事件
	if dc.wafEngine != nil {
		wafEvents := dc.wafEngine.GetEvents(10000) // 获取足够多的事件以便过滤
		wafSummary := dc.summarizeWAFEvents(wafEvents, startTime, endTime)
		if wafSummary.Count > 0 {
			data.AttackEvents = append(data.AttackEvents, wafSummary)
		}
	}

	// 收集DDoS事件
	if dc.ddosProtector != nil {
		ddosAttacks := dc.ddosProtector.GetAttacksByTimeRange(startTime, endTime)
		ddosSummary := dc.summarizeDDoSEvents(ddosAttacks)
		if ddosSummary.Count > 0 {
			data.AttackEvents = append(data.AttackEvents, ddosSummary)
		}
	}

	return nil
}

// summarizeWAFEvents 汇总WAF事件
func (dc *DataCollector) summarizeWAFEvents(events []waf.AttackEvent, startTime, endTime time.Time) AttackEventSummary {
	summary := AttackEventSummary{
		Type:         "waf",
		Severity:     "medium",
		TopIPs:       make([]string, 0),
		TopURLs:      make([]string, 0),
		FirstSeen:    endTime,
		LastSeen:     startTime,
	}

	ipCount := make(map[string]int)
	urlCount := make(map[string]int)

	for _, event := range events {
		// 过滤时间范围
		if event.Timestamp.Before(startTime) || event.Timestamp.After(endTime) {
			continue
		}

		summary.Count++
		if event.Blocked {
			summary.Blocked++
		}

		// 更新首次和最后出现时间
		if event.Timestamp.Before(summary.FirstSeen) {
			summary.FirstSeen = event.Timestamp
		}
		if event.Timestamp.After(summary.LastSeen) {
			summary.LastSeen = event.Timestamp
		}

		// 统计IP
		ipCount[event.ClientIP]++
		// 统计URL
		urlCount[event.URL]++
	}

	// 获取Top IPs
	summary.TopIPs = getTopKeys(ipCount, 10)
	// 获取Top URLs
	summary.TopURLs = getTopKeys(urlCount, 10)

	// 根据攻击次数确定严重程度
	if summary.Count > 1000 {
		summary.Severity = "critical"
	} else if summary.Count > 500 {
		summary.Severity = "high"
	} else if summary.Count > 100 {
		summary.Severity = "medium"
	} else {
		summary.Severity = "low"
	}

	return summary
}

// summarizeDDoSEvents 汇总DDoS事件
func (dc *DataCollector) summarizeDDoSEvents(attacks []ddos.Attack) AttackEventSummary {
	summary := AttackEventSummary{
		Type:         "ddos",
		Severity:     "medium",
		TopIPs:       make([]string, 0),
		FirstSeen:    time.Now(),
		LastSeen:     time.Time{},
	}

	ipCount := make(map[string]int)
	countryCount := make(map[string]int)

	for _, attack := range attacks {
		summary.Count++
		if attack.Blocked {
			summary.Blocked++
		}

		// 更新首次和最后出现时间
		if attack.Timestamp.Before(summary.FirstSeen) {
			summary.FirstSeen = attack.Timestamp
		}
		if attack.Timestamp.After(summary.LastSeen) {
			summary.LastSeen = attack.Timestamp
		}

		// 统计IP
		ipCount[attack.ClientIP]++
		// 统计国家
		if attack.Country != "" {
			countryCount[attack.Country]++
		}
	}

	// 获取Top IPs
	summary.TopIPs = getTopKeys(ipCount, 10)
	// 获取Top Countries
	summary.TopCountries = getTopKeys(countryCount, 10)

	// 根据攻击次数确定严重程度
	if summary.Count > 1000 {
		summary.Severity = "critical"
	} else if summary.Count > 500 {
		summary.Severity = "high"
	} else if summary.Count > 100 {
		summary.Severity = "medium"
	} else {
		summary.Severity = "low"
	}

	return summary
}

// collectCertIssues 收集证书问题
func (dc *DataCollector) collectCertIssues(data *ReportData, startTime, endTime time.Time) error {
	if dc.sslManager == nil {
		return nil
	}

	certs := dc.sslManager.ListCertificatesFromDisk()
	now := time.Now()

	for _, cert := range certs {
		// 检查证书是否在报告期间过期或即将过期
		daysLeft := int(time.Until(cert.ExpiresAt).Hours() / 24)

		// 如果证书已过期
		if cert.ExpiresAt.Before(now) {
			// 检查是否在报告期间过期
			if cert.ExpiresAt.After(startTime) && cert.ExpiresAt.Before(endTime) {
				data.CertIssues = append(data.CertIssues, CertIssue{
					Domain:     cert.Domain,
					Status:     "expired",
					ExpiresAt:  cert.ExpiresAt,
					DaysLeft:   daysLeft,
					Issuer:     cert.Issuer,
					SelfSigned: cert.SelfSigned,
				})
			}
		} else if daysLeft <= 30 && daysLeft >= 0 {
			// 证书即将过期（30天内）
			data.CertIssues = append(data.CertIssues, CertIssue{
				Domain:     cert.Domain,
				Status:     "expiring_soon",
				ExpiresAt:  cert.ExpiresAt,
				DaysLeft:   daysLeft,
				Issuer:     cert.Issuer,
				SelfSigned: cert.SelfSigned,
			})
		}
	}

	return nil
}

// collectErrorRequests 收集错误请求统计
func (dc *DataCollector) collectErrorRequests(data *ReportData, startTime, endTime time.Time) error {
	if dc.statsCollector == nil {
		return nil
	}

	// 计算时间维度
	dimension := statistics.DimensionDay
	if endTime.Sub(startTime) > 7*24*time.Hour {
		dimension = statistics.DimensionMonth
	} else if endTime.Sub(startTime) > 24*time.Hour {
		dimension = statistics.DimensionDay
	} else {
		dimension = statistics.DimensionHour
	}

	// 获取统计数据
	statsData, err := dc.statsCollector.GetStatistics(dimension, "", "")
	if err != nil {
		return err
	}

	// 汇总所有域名的统计数据
	totalRequests := int64(0)
	nonSuccessCount := int64(0)
	statusCodes := make(map[int]int64)

	for _, domainStats := range statsData.DomainStats {
		totalRequests += domainStats.TotalRequests
		nonSuccessCount += domainStats.NonSuccessCount
		// 注意：statistics.RequestStats 没有 StatusCodes 字段，需要从其他地方获取
	}

	data.ErrorRequests.TotalRequests = totalRequests
	data.ErrorRequests.NonSuccessCount = nonSuccessCount
	if totalRequests > 0 {
		data.ErrorRequests.NonSuccessRate = float64(nonSuccessCount) / float64(totalRequests) * 100
	}
	data.ErrorRequests.StatusCodes = statusCodes

	return nil
}

// calculateSystemStats 计算系统统计
func (dc *DataCollector) calculateSystemStats(data *ReportData) {
	if len(data.HighLoadEvents) == 0 {
		return
	}

	var totalCPU, totalMemory, totalMemoryMB float64
	var maxCPU, maxMemory, maxMemoryMB float64

	for _, event := range data.HighLoadEvents {
		totalCPU += event.CPUPercent
		totalMemory += event.MemoryPercent
		totalMemoryMB += event.MemoryMB

		if event.CPUPercent > maxCPU {
			maxCPU = event.CPUPercent
		}
		if event.MemoryPercent > maxMemory {
			maxMemory = event.MemoryPercent
		}
		if event.MemoryMB > maxMemoryMB {
			maxMemoryMB = event.MemoryMB
		}
	}

	count := float64(len(data.HighLoadEvents))
	data.SystemStats = SystemStats{
		AvgCPUPercent:    totalCPU / count,
		MaxCPUPercent:    maxCPU,
		AvgMemoryPercent: totalMemory / count,
		MaxMemoryPercent: maxMemory,
		AvgMemoryMB:      totalMemoryMB / count,
		MaxMemoryMB:      maxMemoryMB,
	}
}

// getTopKeys 获取Top键
func getTopKeys(countMap map[string]int, limit int) []string {
	type kv struct {
		Key   string
		Value int
	}

	var kvs []kv
	for k, v := range countMap {
		kvs = append(kvs, kv{k, v})
	}

	// 排序
	for i := 0; i < len(kvs)-1; i++ {
		for j := i + 1; j < len(kvs); j++ {
			if kvs[i].Value < kvs[j].Value {
				kvs[i], kvs[j] = kvs[j], kvs[i]
			}
		}
	}

	// 取前N个
	result := make([]string, 0, limit)
	for i := 0; i < len(kvs) && i < limit; i++ {
		result = append(result, kvs[i].Key)
	}

	return result
}


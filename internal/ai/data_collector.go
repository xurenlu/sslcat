package ai

import (
	"fmt"
	"sort"
	"time"

	"github.com/xurenlu/sslcat/internal/ddos"
	"github.com/xurenlu/sslcat/internal/security"
)

// DataCollector 安全数据收集器
type DataCollector struct {
	ddosProtector   *ddos.Protector
	securityManager *security.Manager
	analysisWindow  time.Duration
}

// NewDataCollector 创建数据收集器
func NewDataCollector(
	ddosProtector *ddos.Protector,
	securityManager *security.Manager,
	analysisWindow time.Duration,
) *DataCollector {
	if analysisWindow == 0 {
		analysisWindow = 1 * time.Hour
	}

	return &DataCollector{
		ddosProtector:   ddosProtector,
		securityManager: securityManager,
		analysisWindow:  analysisWindow,
	}
}

// Collect 收集安全数据
func (dc *DataCollector) Collect() *SecurityData {
	now := time.Now()
	startTime := now.Add(-dc.analysisWindow)

	data := &SecurityData{
		TimeRange:       fmt.Sprintf("%s 至 %s", startTime.Format("15:04"), now.Format("15:04")),
		TrafficPatterns: make(map[string]interface{}),
	}

	// 从 DDoS 防护器收集数据
	if dc.ddosProtector != nil {
		dc.collectDDoSData(data, startTime, now)
	}

	// 从安全管理器收集数据
	if dc.securityManager != nil {
		dc.collectSecurityData(data, startTime, now)
	}

	return data
}

// collectDDoSData 从 DDoS 防护器收集数据
func (dc *DataCollector) collectDDoSData(data *SecurityData, startTime, endTime time.Time) {
	// 获取统计信息
	stats := dc.ddosProtector.GetStats()
	if stats != nil {
		if total, ok := stats["total_clients"].(int); ok {
			data.TotalRequests = int64(total)
		}
		if blocked, ok := stats["blocked_clients"].(int); ok {
			data.BlockedIPs = blocked
		}
		if suspicious, ok := stats["suspicious_clients"].(int); ok {
			data.SuspiciousIPs = suspicious
		}
	}

	// 获取攻击事件
	attacks := dc.ddosProtector.GetAttacks(1000) // 最近 1000 条攻击记录
	attackMap := make(map[string]*AttackSummary)
	ipAttackTypes := make(map[string]map[string]bool)
	countryDistrib := make(map[string]int)     // 全局国家分布
	urlAccessPattern := make(map[string]int)   // URL 访问统计
	ipURLs := make(map[string]map[string]bool) // IP -> URL 映射
	ipCountries := make(map[string]string)     // IP -> Country 映射

	for _, attack := range attacks {
		// 过滤时间范围
		if attack.Timestamp.Before(startTime) || attack.Timestamp.After(endTime) {
			continue
		}

		// 聚合攻击类型
		if _, exists := attackMap[attack.AttackType]; !exists {
			attackMap[attack.AttackType] = &AttackSummary{
				Type:         attack.AttackType,
				Severity:     attack.Severity,
				TopIPs:       make([]string, 0),
				TopCountries: make([]string, 0),
				TopURLs:      make([]string, 0),
				FirstSeen:    attack.Timestamp,
				LastSeen:     attack.Timestamp,
				GeoDistrib:   make(map[string]int),
			}
		}

		summary := attackMap[attack.AttackType]
		summary.Count++
		if attack.Blocked {
			summary.Blocked++
		}

		// 更新时间范围
		if attack.Timestamp.Before(summary.FirstSeen) {
			summary.FirstSeen = attack.Timestamp
		}
		if attack.Timestamp.After(summary.LastSeen) {
			summary.LastSeen = attack.Timestamp
		}

		// 统计国家分布
		if attack.Country != "" {
			summary.GeoDistrib[attack.Country]++
			countryDistrib[attack.Country]++
			ipCountries[attack.ClientIP] = attack.Country
		}

		// 统计 URL 访问
		if attack.URL != "" {
			urlAccessPattern[attack.URL]++
		}

		// 记录 IP 的攻击类型
		if _, exists := ipAttackTypes[attack.ClientIP]; !exists {
			ipAttackTypes[attack.ClientIP] = make(map[string]bool)
		}
		ipAttackTypes[attack.ClientIP][attack.AttackType] = true

		// 记录 IP 访问的 URL
		if _, exists := ipURLs[attack.ClientIP]; !exists {
			ipURLs[attack.ClientIP] = make(map[string]bool)
		}
		if attack.URL != "" {
			ipURLs[attack.ClientIP][attack.URL] = true
		}
	}

	// 保存全局统计
	data.CountryDistrib = countryDistrib
	data.URLAccessPattern = urlAccessPattern

	// 提取 Top 攻击 IP、国家、URL
	for attackType, summary := range attackMap {
		topIPs := make(map[string]int)
		topURLs := make(map[string]int)

		for _, attack := range attacks {
			if attack.AttackType == attackType &&
				!attack.Timestamp.Before(startTime) &&
				!attack.Timestamp.After(endTime) {
				topIPs[attack.ClientIP]++
				if attack.URL != "" {
					topURLs[attack.URL]++
				}
			}
		}

		// 排序并取 Top 5 IP
		type ipCount struct {
			ip    string
			count int
		}
		ipCounts := make([]ipCount, 0, len(topIPs))
		for ip, count := range topIPs {
			ipCounts = append(ipCounts, ipCount{ip, count})
		}
		sort.Slice(ipCounts, func(i, j int) bool {
			return ipCounts[i].count > ipCounts[j].count
		})

		for i := 0; i < len(ipCounts) && i < 5; i++ {
			summary.TopIPs = append(summary.TopIPs, ipCounts[i].ip)
		}

		// 提取 Top 国家（从 GeoDistrib 中排序）
		type countryCount struct {
			country string
			count   int
		}
		countryCounts := make([]countryCount, 0, len(summary.GeoDistrib))
		for country, count := range summary.GeoDistrib {
			countryCounts = append(countryCounts, countryCount{country, count})
		}
		sort.Slice(countryCounts, func(i, j int) bool {
			return countryCounts[i].count > countryCounts[j].count
		})
		for i := 0; i < len(countryCounts) && i < 5; i++ {
			summary.TopCountries = append(summary.TopCountries, countryCounts[i].country)
		}

		// 提取 Top URL
		type urlCount struct {
			url   string
			count int
		}
		urlCounts := make([]urlCount, 0, len(topURLs))
		for url, count := range topURLs {
			urlCounts = append(urlCounts, urlCount{url, count})
		}
		sort.Slice(urlCounts, func(i, j int) bool {
			return urlCounts[i].count > urlCounts[j].count
		})
		for i := 0; i < len(urlCounts) && i < 5; i++ {
			summary.TopURLs = append(summary.TopURLs, urlCounts[i].url)
		}

		data.AttackEvents = append(data.AttackEvents, *summary)
	}

	// 获取高频攻击者
	clients := dc.ddosProtector.GetClients(100) // Top 100 客户端
	topAttackers := make([]IPSummary, 0)

	for ip, client := range clients {
		// 只统计有攻击行为的客户端
		if client.BlockCount == 0 && !client.Suspicious {
			continue
		}

		// 提取该 IP 的攻击类型
		attackTypes := make([]string, 0)
		if types, exists := ipAttackTypes[ip]; exists {
			for attackType := range types {
				attackTypes = append(attackTypes, attackType)
			}
		}

		// 提取该 IP 访问的 URL（Top 5）
		targetURLs := make([]string, 0)
		if urls, exists := ipURLs[ip]; exists {
			for url := range urls {
				targetURLs = append(targetURLs, url)
				if len(targetURLs) >= 5 {
					break
				}
			}
		}

		// 获取国家信息
		country := ""
		countryCode := ""
		isp := ""
		if c, exists := ipCountries[ip]; exists {
			country = c
		}

		// 如果有 GeoIP 服务，获取完整信息
		if dc.securityManager != nil && dc.securityManager.GetGeoIPService() != nil {
			if geoLoc, err := dc.securityManager.GetGeoIPService().GetLocation(ip); err == nil && geoLoc != nil {
				country = geoLoc.Country
				countryCode = geoLoc.CountryCode
				isp = geoLoc.ISP
			}
		}

		summary := IPSummary{
			IP:           ip,
			RequestCount: client.RequestCount,
			BlockCount:   client.BlockCount,
			AttackTypes:  attackTypes,
			FirstSeen:    client.FirstRequest,
			LastSeen:     client.LastRequest,
			RequestRate:  client.RequestRate,
			Country:      country,
			CountryCode:  countryCode,
			ISP:          isp,
			TargetURLs:   targetURLs,
		}

		topAttackers = append(topAttackers, summary)
	}

	// 按请求速率排序
	sort.Slice(topAttackers, func(i, j int) bool {
		return topAttackers[i].RequestRate > topAttackers[j].RequestRate
	})

	// 只保留 Top 10
	if len(topAttackers) > 10 {
		topAttackers = topAttackers[:10]
	}

	data.TopAttackers = topAttackers

	// 生成 Top URL 访问统计
	topURLs := make([]URLSummary, 0)
	urlIPMap := make(map[string]map[string]bool)      // URL -> IPs 映射
	urlCountryMap := make(map[string]map[string]bool) // URL -> Countries 映射

	// 统计每个 URL 的访问 IP 和国家
	for _, attack := range attacks {
		if attack.URL == "" {
			continue
		}
		if attack.Timestamp.Before(startTime) || attack.Timestamp.After(endTime) {
			continue
		}

		if _, exists := urlIPMap[attack.URL]; !exists {
			urlIPMap[attack.URL] = make(map[string]bool)
			urlCountryMap[attack.URL] = make(map[string]bool)
		}
		urlIPMap[attack.URL][attack.ClientIP] = true
		if attack.Country != "" {
			urlCountryMap[attack.URL][attack.Country] = true
		}
	}

	// 构建 URLSummary 列表
	for url, count := range urlAccessPattern {
		uniqueIPs := len(urlIPMap[url])

		// 提取 Top IPs
		topIPList := make([]string, 0)
		ipCounts := make(map[string]int)
		for _, attack := range attacks {
			if attack.URL == url && !attack.Timestamp.Before(startTime) && !attack.Timestamp.After(endTime) {
				ipCounts[attack.ClientIP]++
			}
		}

		type ipCountPair struct {
			ip    string
			count int
		}
		ipCountList := make([]ipCountPair, 0, len(ipCounts))
		for ip, cnt := range ipCounts {
			ipCountList = append(ipCountList, ipCountPair{ip, cnt})
		}
		sort.Slice(ipCountList, func(i, j int) bool {
			return ipCountList[i].count > ipCountList[j].count
		})
		for i := 0; i < len(ipCountList) && i < 3; i++ {
			topIPList = append(topIPList, ipCountList[i].ip)
		}

		// 提取 Top Countries
		topCountryList := make([]string, 0)
		for country := range urlCountryMap[url] {
			topCountryList = append(topCountryList, country)
			if len(topCountryList) >= 3 {
				break
			}
		}

		// 判断是否为可疑路径
		suspicious := dc.isSuspiciousURL(url)

		topURLs = append(topURLs, URLSummary{
			URL:          url,
			RequestCount: count,
			UniqueIPs:    uniqueIPs,
			TopIPs:       topIPList,
			TopCountries: topCountryList,
			Suspicious:   suspicious,
		})
	}

	// 按请求数排序
	sort.Slice(topURLs, func(i, j int) bool {
		return topURLs[i].RequestCount > topURLs[j].RequestCount
	})

	// 只保留 Top 20
	if len(topURLs) > 20 {
		topURLs = topURLs[:20]
	}

	data.TopTargetURLs = topURLs

	// 计算错误率（简化实现）
	if data.TotalRequests > 0 {
		// 假设被拦截的请求都是错误请求
		data.ErrorRate = float64(data.BlockedIPs) / float64(data.TotalRequests)
	}
}

// collectSecurityData 从安全管理器收集数据
func (dc *DataCollector) collectSecurityData(data *SecurityData, startTime, endTime time.Time) {
	// 获取最近的访问日志（从所有 IP 的日志）
	logsMap := dc.securityManager.AccessLogsSnapshot()
	logs := make([]security.AccessLog, 0)

	// 展平日志映射
	for _, ipLogs := range logsMap {
		logs = append(logs, ipLogs...)
	}

	// 限制数量
	if len(logs) > 1000 {
		logs = logs[len(logs)-1000:]
	}

	// 统计异常 User-Agent
	uaMap := make(map[string]*UASummary)
	uaIPs := make(map[string]map[string]bool) // UA -> IP 集合

	for _, log := range logs {
		// 简单的异常 UA 检测逻辑
		isSuspicious := dc.isSuspiciousUA(log.UserAgent)

		if !isSuspicious && log.UserAgent != "" {
			continue // 跳过正常的 UA
		}

		if _, exists := uaMap[log.UserAgent]; !exists {
			uaMap[log.UserAgent] = &UASummary{
				UserAgent:  log.UserAgent,
				Suspicious: isSuspicious,
			}
			uaIPs[log.UserAgent] = make(map[string]bool)
		}

		summary := uaMap[log.UserAgent]
		summary.RequestCount++
		uaIPs[log.UserAgent][log.IP] = true
	}

	// 计算唯一 IP 数
	anomalousUA := make([]UASummary, 0)
	for ua, summary := range uaMap {
		summary.UniqueIPs = len(uaIPs[ua])

		// 添加可疑原因
		if summary.Suspicious {
			summary.Reason = dc.getSuspiciousReason(ua)
		}

		anomalousUA = append(anomalousUA, *summary)
	}

	// 按请求数排序
	sort.Slice(anomalousUA, func(i, j int) bool {
		return anomalousUA[i].RequestCount > anomalousUA[j].RequestCount
	})

	// 只保留 Top 10
	if len(anomalousUA) > 10 {
		anomalousUA = anomalousUA[:10]
	}

	data.AnomalousUA = anomalousUA
}

// isSuspiciousUA 判断 UA 是否可疑
func (dc *DataCollector) isSuspiciousUA(ua string) bool {
	if ua == "" {
		return true // 空 UA
	}

	// 检查常见的恶意 UA 特征
	suspiciousKeywords := []string{
		"bot", "crawler", "spider", "scraper", "scan",
		"hack", "attack", "exploit", "injection",
		"python", "curl", "wget", "masscan", "nmap",
		"sqlmap", "nikto", "dirbuster", "burp", "leakix",
	}

	uaLower := ua
	for _, keyword := range suspiciousKeywords {
		if contains(uaLower, keyword) {
			return true
		}
	}

	// 检查是否过短或过长
	if len(ua) < 10 || len(ua) > 500 {
		return true
	}

	return false
}

// getSuspiciousReason 获取可疑原因
func (dc *DataCollector) getSuspiciousReason(ua string) string {
	if ua == "" {
		return "空 User-Agent"
	}

	keywords := map[string]string{
		"bot":       "疑似爬虫",
		"crawler":   "疑似爬虫",
		"spider":    "疑似爬虫",
		"scraper":   "疑似抓取工具",
		"scan":      "疑似扫描工具",
		"hack":      "疑似攻击工具",
		"attack":    "疑似攻击工具",
		"exploit":   "疑似漏洞利用工具",
		"injection": "疑似注入工具",
		"python":    "疑似脚本请求",
		"curl":      "疑似命令行工具",
		"wget":      "疑似命令行工具",
		"sqlmap":    "SQL 注入工具",
		"nikto":     "Web 扫描工具",
	}

	uaLower := ua
	for keyword, reason := range keywords {
		if contains(uaLower, keyword) {
			return reason
		}
	}

	if len(ua) < 10 {
		return "User-Agent 过短"
	}
	if len(ua) > 500 {
		return "User-Agent 过长"
	}

	return "未知原因"
}

// contains 简单的字符串包含检查（不区分大小写）
func contains(s, substr string) bool {
	return len(s) >= len(substr) && indexIgnoreCase(s, substr) >= 0
}

// indexIgnoreCase 不区分大小写的字符串查找
func indexIgnoreCase(s, substr string) int {
	sLower := toLower(s)
	substrLower := toLower(substr)
	return indexString(sLower, substrLower)
}

// toLower 简单的转小写实现
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			result[i] = s[i] + 32
		} else {
			result[i] = s[i]
		}
	}
	return string(result)
}

// indexString 字符串查找
func indexString(s, substr string) int {
	if len(substr) == 0 {
		return 0
	}
	if len(s) < len(substr) {
		return -1
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// isSuspiciousURL 判断 URL 是否可疑
func (dc *DataCollector) isSuspiciousURL(url string) bool {
	suspiciousPaths := []string{
		"admin", "phpmyadmin", "wp-admin", "wp-login",
		".env", ".git", "config", "backup",
		"shell", "cmd", "exec", "eval",
		"../", "..\\", // 路径遍历
	}

	urlLower := toLower(url)
	for _, path := range suspiciousPaths {
		if contains(urlLower, path) {
			return true
		}
	}

	return false
}

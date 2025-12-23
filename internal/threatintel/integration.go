package threatintel

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ThreatIntelAPI 威胁情报API接口
type ThreatIntelAPI struct {
	manager *ThreatIntelManager
	client  *http.Client
	log     *logrus.Entry
}

// NewThreatIntelAPI 创建威胁情报API
func NewThreatIntelAPI(manager *ThreatIntelManager) *ThreatIntelAPI {
	return &ThreatIntelAPI{
		manager: manager,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		log: logrus.WithFields(logrus.Fields{
			"component": "threat_intel_api",
		}),
	}
}

// AbuseIPDBResponse AbuseIPDB API响应
type AbuseIPDBResponse struct {
	Data struct {
		IPAddress        string   `json:"ipAddress"`
		IsPublic         bool     `json:"isPublic"`
		IPVersion        int      `json:"ipVersion"`
		IsWhitelisted    bool     `json:"isWhitelisted"`
		AbuseConfidence  int      `json:"abuseConfidencePercentage"`
		CountryCode      string   `json:"countryCode"`
		UsageType        string   `json:"usageType"`
		ISP              string   `json:"isp"`
		Domain           string   `json:"domain"`
		Hostnames        []string `json:"hostnames"`
		TotalReports     int      `json:"totalReports"`
		NumDistinctUsers int      `json:"numDistinctUsers"`
		LastReportedAt   string   `json:"lastReportedAt"`
		Reports          []struct {
			ReportedAt string `json:"reportedAt"`
			Comment    string `json:"comment"`
			Categories []int  `json:"categories"`
		} `json:"reports"`
	} `json:"data"`
}

// VirusTotalResponse VirusTotal API响应
type VirusTotalResponse struct {
	ResponseCode int    `json:"response_code"`
	VerboseMsg   string `json:"verbose_msg"`
	Resource     string `json:"resource"`
	ScanID       string `json:"scan_id"`
	Permalink    string `json:"permalink"`
	ScanDate     string `json:"scan_date"`
	Positives    int    `json:"positives"`
	Total        int    `json:"total"`
	Scans        map[string]struct {
		Detected bool   `json:"detected"`
		Result   string `json:"result"`
		Version  string `json:"version"`
		Update   string `json:"update"`
	} `json:"scans"`
}

// CheckIPWithAbuseIPDB 使用AbuseIPDB检查IP
func (api *ThreatIntelAPI) CheckIPWithAbuseIPDB(ip string) (*IOC, error) {
	if !ValidateIP(ip) {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	// 构建请求
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90&verbose", ip)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// 添加API密钥（需要配置）
	req.Header.Set("Key", "your-api-key-here")
	req.Header.Set("Accept", "application/json")

	// 发送请求
	resp, err := api.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 解析响应
	var abuseResp AbuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&abuseResp); err != nil {
		return nil, err
	}

	// 转换为IOC
	threatLevel := ThreatLevelLow
	confidence := float64(abuseResp.Data.AbuseConfidence) / 100.0

	if abuseResp.Data.AbuseConfidence >= 75 {
		threatLevel = ThreatLevelCritical
	} else if abuseResp.Data.AbuseConfidence >= 50 {
		threatLevel = ThreatLevelHigh
	} else if abuseResp.Data.AbuseConfidence >= 25 {
		threatLevel = ThreatLevelMedium
	}

	ioc := &IOC{
		Value:       ip,
		Type:        IOCTypeIP,
		ThreatLevel: threatLevel,
		Source:      "AbuseIPDB",
		Description: fmt.Sprintf("Abuse confidence: %d%%, Reports: %d",
			abuseResp.Data.AbuseConfidence, abuseResp.Data.TotalReports),
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
		Confidence: confidence,
		Tags:       []string{"abuse", "reported"},
	}

	return ioc, nil
}

// CheckIPWithVirusTotal 使用VirusTotal检查IP
func (api *ThreatIntelAPI) CheckIPWithVirusTotal(ip string) (*IOC, error) {
	if !ValidateIP(ip) {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	// 构建请求
	url := fmt.Sprintf("https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=your-api-key&ip=%s", ip)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// 发送请求
	resp, err := api.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 解析响应
	var vtResp VirusTotalResponse
	if err := json.NewDecoder(resp.Body).Decode(&vtResp); err != nil {
		return nil, err
	}

	// 转换为IOC
	threatLevel := ThreatLevelLow
	confidence := float64(vtResp.Positives) / float64(vtResp.Total)

	if vtResp.Positives >= 5 {
		threatLevel = ThreatLevelCritical
	} else if vtResp.Positives >= 3 {
		threatLevel = ThreatLevelHigh
	} else if vtResp.Positives >= 1 {
		threatLevel = ThreatLevelMedium
	}

	ioc := &IOC{
		Value:       ip,
		Type:        IOCTypeIP,
		ThreatLevel: threatLevel,
		Source:      "VirusTotal",
		Description: fmt.Sprintf("Detected by %d/%d engines", vtResp.Positives, vtResp.Total),
		FirstSeen:   time.Now(),
		LastSeen:    time.Now(),
		Confidence:  confidence,
		Tags:        []string{"malware", "detected"},
	}

	return ioc, nil
}

// CheckDomainWithMalwareDomains 使用恶意域名列表检查域名
func (api *ThreatIntelAPI) CheckDomainWithMalwareDomains(domain string) (*IOC, error) {
	if !ValidateDomain(domain) {
		return nil, fmt.Errorf("invalid domain: %s", domain)
	}

	// 获取恶意域名列表
	url := "https://mirror1.malwaredomains.com/files/domains.txt"
	resp, err := api.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 检查域名是否在列表中
	domainLower := strings.ToLower(domain)
	lines := strings.Split(string(body), "\n")

	for _, line := range lines {
		if strings.Contains(line, domainLower) {
			// 解析行内容获取更多信息
			parts := strings.Split(line, "\t")
			if len(parts) >= 2 {
				malwareType := parts[1]

				ioc := &IOC{
					Value:       domain,
					Type:        IOCTypeDomain,
					ThreatLevel: ThreatLevelHigh,
					Source:      "Malware Domains",
					Description: fmt.Sprintf("Malware domain: %s", malwareType),
					FirstSeen:   time.Now(),
					LastSeen:    time.Now(),
					Confidence:  0.9,
					Tags:        []string{"malware", "domain"},
				}

				return ioc, nil
			}
		}
	}

	return nil, nil // 未找到
}

// CheckIPWithEmergingThreats 使用Emerging Threats检查IP
func (api *ThreatIntelAPI) CheckIPWithEmergingThreats(ip string) (*IOC, error) {
	if !ValidateIP(ip) {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	// 获取威胁IP列表
	url := "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
	resp, err := api.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 检查IP是否在列表中
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == ip {
			ioc := &IOC{
				Value:       ip,
				Type:        IOCTypeIP,
				ThreatLevel: ThreatLevelHigh,
				Source:      "Emerging Threats",
				Description: "Compromised IP address",
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				Confidence:  0.8,
				Tags:        []string{"compromised", "botnet"},
			}

			return ioc, nil
		}
	}

	return nil, nil // 未找到
}

// BulkCheckIP 批量检查IP地址
// 修复：添加并发限制和同步机制，避免创建大量 goroutine 导致内存快速增长
func (api *ThreatIntelAPI) BulkCheckIP(ips []string) map[string]*IOC {
	results := make(map[string]*IOC)
	resultsMu := sync.Mutex{} // 保护 results map 的并发访问

	// 限制并发数量，避免一次性创建过多 goroutine 导致内存快速增长
	// 这符合"突然出问题时短时间内增长很多"的特征
	maxConcurrent := 50 // 最多同时检查50个IP
	if len(ips) < maxConcurrent {
		maxConcurrent = len(ips)
	}

	semaphore := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		semaphore <- struct{}{} // 获取信号量

		go func(ipAddr string) {
			defer wg.Done()
			defer func() { <-semaphore }() // 释放信号量

			// 检查AbuseIPDB
			if ioc, err := api.CheckIPWithAbuseIPDB(ipAddr); err == nil && ioc != nil {
				resultsMu.Lock()
				results[ipAddr] = ioc
				resultsMu.Unlock()
				api.manager.AddIOC(ioc)
			}

			// 检查VirusTotal
			if ioc, err := api.CheckIPWithVirusTotal(ipAddr); err == nil && ioc != nil {
				resultsMu.Lock()
				results[ipAddr] = ioc
				resultsMu.Unlock()
				api.manager.AddIOC(ioc)
			}

			// 检查Emerging Threats
			if ioc, err := api.CheckIPWithEmergingThreats(ipAddr); err == nil && ioc != nil {
				resultsMu.Lock()
				results[ipAddr] = ioc
				resultsMu.Unlock()
				api.manager.AddIOC(ioc)
			}
		}(ip)
	}

	// 等待所有检查完成
	wg.Wait()

	return results
}

// GetThreatIntelligenceReport 获取威胁情报报告
func (api *ThreatIntelAPI) GetThreatIntelligenceReport() map[string]interface{} {
	stats := api.manager.GetThreatStats()

	report := map[string]interface{}{
		"timestamp":      time.Now().Format(time.RFC3339),
		"threat_stats":   stats,
		"active_sources": len(api.manager.sources),
		"last_update":    time.Now(),
		"recommendations": []string{
			"定期更新威胁情报源",
			"监控高风险IOC",
			"实施自动化响应",
			"加强日志分析",
		},
	}

	return report
}

// UpdateThreatIntelligence 更新威胁情报
func (api *ThreatIntelAPI) UpdateThreatIntelligence() error {
	api.log.Info("Updating threat intelligence from external sources")

	// 这里可以添加更多的威胁情报源更新逻辑
	// 例如：更新本地威胁情报数据库、同步外部源等

	return nil
}

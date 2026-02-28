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

// 威胁情报源配置
const (
	// Abuse.ch
	AbuseCHBaseURL = "https://bazaar.abuse.ch/export"

	// AlienVault OTX
	AlienVaultOTXBaseURL = "https://otx.alienvault.com/api/v1"

	// VirusTotal
	VirusTotalBaseURL = "https://www.virustotal.com/vtapi/v2"

	// URLhaus
	URLHausBaseURL = "https://urlhaus.abuse.ch/api"

	// PhishTank
	PhishTankBaseURL = "https://checkphish.dotdefeated.com/api/v1"
)

// ThreatFeed 威胁情报源
type ThreatFeed struct {
	Name        string        `json:"name"`
	Type        string        `json:"type"`         // ip, domain, url, hash
	URL         string        `json:"url"`
	Enabled     bool          `json:"enabled"`
	UpdateFreq  time.Duration `json:"update_freq"`
	LastUpdate  time.Time     `json:"last_update"`
	APIKey      string        `json:"api_key"`
	RateLimit   int           `json:"rate_limit"`   // 每分钟请求数
}

// EnhancedThreatIntelAPI 增强的威胁情报API
type EnhancedThreatIntelAPI struct {
	manager    *ThreatIntelManager
	client     *http.Client
	feeds      map[string]*ThreatFeed
	log        *logrus.Entry
	rateLimiter map[string]*rateLimiter
}

// rateLimiter 速率限制器
type rateLimiter struct {
	tokens     chan struct{}
	lastRefill time.Time
}

// NewEnhancedThreatIntelAPI 创建增强的威胁情报API
func NewEnhancedThreatIntelAPI(manager *ThreatIntelManager) *EnhancedThreatIntelAPI {
	api := &EnhancedThreatIntelAPI{
		manager: manager,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  true,
				DisableKeepAlives:   false,
			},
		},
		feeds:       make(map[string]*ThreatFeed),
		log:         logrus.WithFields(logrus.Fields{
			"component": "enhanced_threat_intel",
		}),
		rateLimiter: make(map[string]*rateLimiter),
	}

	// 初始化威胁情报源
	api.initFeeds()

	return api
}

// initFeeds 初始化威胁情报源
func (api *EnhancedThreatIntelAPI) initFeeds() {
	// Abuse.ch - IP 情报
	api.feeds["abusech_ip"] = &ThreatFeed{
		Name:       "Abuse.ch IP",
		Type:       "ip",
		URL:        "https://bazaar.abuse.ch/export/txt/IPs_recent.txt",
		Enabled:    true,
		UpdateFreq: 1 * time.Hour,
	}

	// Abuse.ch - 域名情报
	api.feeds["abusech_domain"] = &ThreatFeed{
		Name:       "Abuse.ch Domain",
		Type:       "domain",
		URL:        "https://bazaar.abuse.ch/export/txt/DOMAINS_recent.txt",
		Enabled:    true,
		UpdateFreq: 1 * time.Hour,
	}

	// URLhaus - 恶意URL
	api.feeds["urlhaus"] = &ThreatFeed{
		Name:       "URLhaus",
		Type:       "url",
		URL:        "https://urlhaus.abuse.ch/api/urls/recent/",
		Enabled:    true,
		UpdateFreq: 30 * time.Minute,
	}

	// PhishTank - 钓鱼URL
	api.feeds["phishtank"] = &ThreatFeed{
		Name:       "PhishTank",
		Type:       "url",
		URL:        "https://checkphish.dotdefeated.com/api/v1/phish-feeds/",
		Enabled:    true,
		UpdateFreq: 1 * time.Hour,
	}

	// 初始化速率限制器
	for name, feed := range api.feeds {
		if feed.RateLimit > 0 {
			api.rateLimiter[name] = &rateLimiter{
				tokens:     make(chan struct{}, feed.RateLimit),
				lastRefill: time.Now(),
			}
			// 初始填充
			for i := 0; i < feed.RateLimit; i++ {
				api.rateLimiter[name].tokens <- struct{}{}
			}
		}
	}
}

// UpdateFromFeed 从指定数据源更新威胁情报
func (api *EnhancedThreatIntelAPI) UpdateFromFeed(feedName string) error {
	feed, exists := api.feeds[feedName]
	if !exists || !feed.Enabled {
		return fmt.Errorf("feed not found or disabled: %s", feedName)
	}

	// 速率限制检查
	if limiter, ok := api.rateLimiter[feedName]; ok {
		select {
		case <-limiter.tokens:
			// 获取到令牌，继续
		default:
			return fmt.Errorf("rate limit exceeded for feed: %s", feedName)
		}
	}

	api.log.Infof("Updating threat intel from feed: %s", feedName)

	start := time.Now()
	iocs, err := api.fetchFeedData(feed)
	if err != nil {
		api.log.Errorf("Failed to fetch from %s: %v", feedName, err)
		return err
	}

	// 添加到管理器
	count := 0
	for _, ioc := range iocs {
		api.manager.AddIOC(ioc)
		count++
	}

	api.log.Infof("Updated %d IOCs from %s in %v", count, feedName, time.Since(start))

	// 更新最后更新时间
	feed.LastUpdate = time.Now()

	return nil
}

// fetchFeedData 获取数据源数据
func (api *EnhancedThreatIntelAPI) fetchFeedData(feed *ThreatFeed) ([]*IOC, error) {
	req, err := http.NewRequest("GET", feed.URL, nil)
	if err != nil {
		return nil, err
	}

	// 添加必要的headers
	if feed.Name == "URLhaus" {
		req.Header.Set("User-Agent", "SSLcat-ThreatIntel/1.0")
	}

	resp, err := api.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 根据数据源类型解析
	switch feed.Name {
	case "URLhaus":
		return api.parseURLhausJSON(body)
	case "PhishTank":
		return api.parsePhishTankJSON(body)
	default:
		iocType := IOCType(feed.Type)
		return api.parseTextFeed(body, iocType)
	}
}

// parseTextFeed 解析文本格式数据源
func (api *EnhancedThreatIntelAPI) parseTextFeed(data []byte, iocType IOCType) ([]*IOC, error) {
	lines := strings.Split(string(data), "\n")
	iocs := make([]*IOC, 0, len(lines))

	now := time.Now()
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var ioc *IOC
		switch iocType {
		case "ip":
			if validateIP(line) {
				ioc = &IOC{
					Value:       line,
					Type:        IOCTypeIP,
					ThreatLevel: ThreatLevelHigh,
					Source:      "Threat Feed",
					Description: "Malicious IP from threat feed",
					FirstSeen:   now,
					LastSeen:    now,
					Confidence:  0.8,
					Tags:        []string{"feed", "malicious"},
				}
			}
		case "domain":
			if validateDomain(line) {
				ioc = &IOC{
					Value:       line,
					Type:        IOCTypeDomain,
					ThreatLevel: ThreatLevelHigh,
					Source:      "Threat Feed",
					Description: "Malicious domain from threat feed",
					FirstSeen:   now,
					LastSeen:    now,
					Confidence:  0.8,
					Tags:        []string{"feed", "malicious"},
				}
			}
		case "url":
			if validateURL(line) {
				ioc = &IOC{
					Value:       line,
					Type:        IOCTypeURL,
					ThreatLevel: ThreatLevelHigh,
					Source:      "Threat Feed",
					Description: "Malicious URL from threat feed",
					FirstSeen:   now,
					LastSeen:    now,
					Confidence:  0.8,
					Tags:        []string{"feed", "malicious"},
				}
			}
		}

		if ioc != nil {
			iocs = append(iocs, ioc)
		}
	}

	return iocs, nil
}

// parseURLhausJSON 解析URLhaus JSON数据
func (api *EnhancedThreatIntelAPI) parseURLhausJSON(data []byte) ([]*IOC, error) {
	var response struct {
		URLs []struct {
			URL          string    `json:"url"`
			ThreatType   string    `json:"threat_type"`
			DateAdded    string    `json:"date_added"`
			Tags         []string  `json:"tags"`
		} `json:"urls"`
	}

	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	iocs := make([]*IOC, 0, len(response.URLs))
	now := time.Now()

	for _, urlData := range response.URLs {
		dateAdded, _ := time.Parse("2006-01-02T15:04:05", urlData.DateAdded)

		ioc := &IOC{
			Value:       urlData.URL,
			Type:        IOCTypeURL,
			ThreatLevel: getThreatLevel(urlData.ThreatType),
			Source:      "URLhaus",
			Description: fmt.Sprintf("URLhaus: %s", urlData.ThreatType),
			FirstSeen:   dateAdded,
			LastSeen:    now,
			Confidence:  0.9,
			Tags:        append(urlData.Tags, "urlhaus"),
		}
		iocs = append(iocs, ioc)
	}

	return iocs, nil
}

// parsePhishTankJSON 解析PhishTank JSON数据
func (api *EnhancedThreatIntelAPI) parsePhishTankJSON(data []byte) ([]*IOC, error) {
	var response []struct {
		URL           string    `json:"url"`
		PhishDetailID string    `json:"phish_detail_url"`
		Submission   string    `json:"submission_time"`
	}

	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	iocs := make([]*IOC, 0, len(response))
	now := time.Now()

	for _, phish := range response {
		ioc := &IOC{
			Value:       phish.URL,
			Type:        IOCTypeURL,
			ThreatLevel: ThreatLevelCritical,
			Source:      "PhishTank",
			Description: "Verified phishing URL",
			FirstSeen:   now,
			LastSeen:    now,
			Confidence:  0.95,
			Tags:        []string{"phishing", "verified"},
		}
		iocs = append(iocs, ioc)
	}

	return iocs, nil
}

// getThreatLevel 根据威胁类型获取威胁级别
func getThreatLevel(threatType string) ThreatLevel {
	switch strings.ToLower(threatType) {
	case "malware_download", "exploit_kit", "payload_url":
		return ThreatLevelCritical
	case "phishing", "credential_harvester":
		return ThreatLevelHigh
	case "botnet_cc", "redirector":
		return ThreatLevelMedium
	default:
		return ThreatLevelMedium
	}
}

// CheckAllFeeds 检查所有数据源
func (api *EnhancedThreatIntelAPI) CheckAllFeeds() map[string]FeedStatus {
	status := make(map[string]FeedStatus)
	var mu sync.Mutex

	var wg sync.WaitGroup
	for name := range api.feeds {
		wg.Add(1)
		go func(feedName string) {
			defer wg.Done()

			start := time.Now()
			err := api.UpdateFromFeed(feedName)

			mu.Lock()
			stats := api.manager.GetThreatStats()
			iocsCount := 0
			if total, ok := stats["total_iocs"].(int); ok {
				iocsCount = total
			}
			status[feedName] = FeedStatus{
				Name:       feedName,
				Success:    err == nil,
				LastUpdate: time.Now(),
				Duration:   time.Since(start),
				Error:       getErrorString(err),
				IOCsCount:  iocsCount,
			}
			mu.Unlock()
		}(name)
	}
	wg.Wait()

	return status
}

// FeedStatus 数据源状态
type FeedStatus struct {
	Name       string    `json:"name"`
	Success    bool      `json:"success"`
	LastUpdate time.Time `json:"last_update"`
	Duration   time.Duration `json:"duration"`
	Error      string    `json:"error,omitempty"`
	IOCsCount  int       `json:"iocs_count"`
}

// CheckIPMultipleSources 使用多个数据源检查IP
func (api *EnhancedThreatIntelAPI) CheckIPMultipleSources(ip string) ([]*IOC, error) {
	if !validateIP(ip) {
		return nil, fmt.Errorf("invalid IP: %s", ip)
	}

	var results []*IOC
	var mu sync.Mutex

	// 并发检查多个数据源
	var wg sync.WaitGroup
	sources := []string{"abusech_ip", "emergingthreats"}

	for _, source := range sources {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()

			var ioc *IOC
			var err error

			switch src {
			case "abusech_ip":
				ioc, err = api.checkAbuseCHIP(ip)
			case "emergingthreats":
				// 使用现有的集成
				ioc, err = api.checkEmergingThreats(ip)
			}

			if err == nil && ioc != nil {
				mu.Lock()
				results = append(results, ioc)
				api.manager.AddIOC(ioc)
				mu.Unlock()
			}
		}(source)
	}
	wg.Wait()

	return results, nil
}

// checkAbuseCHIP 使用Abuse.ch检查IP
func (api *EnhancedThreatIntelAPI) checkAbuseCHIP(ip string) (*IOC, error) {
	// Abuse.ch 提供最近的恶意IP列表
	feed := api.feeds["abusech_ip"]
	if feed == nil || !feed.Enabled {
		return nil, fmt.Errorf("Abuse.ch IP feed not enabled")
	}

	req, err := http.NewRequest("GET", feed.URL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := api.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 检查IP是否在列表中
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == ip {
			return &IOC{
				Value:       ip,
				Type:        IOCTypeIP,
				ThreatLevel: ThreatLevelHigh,
				Source:      "Abuse.ch",
				Description: "Malicious IP from Abuse.ch",
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				Confidence:  0.9,
				Tags:        []string{"abusech", "malicious"},
			}, nil
		}
	}

	return nil, nil
}

// checkEmergingThreats 使用Emerging Threats检查IP
func (api *EnhancedThreatIntelAPI) checkEmergingThreats(ip string) (*IOC, error) {
	if !ValidateIP(ip) {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	url := "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
	resp, err := api.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == ip {
			return &IOC{
				Value:       ip,
				Type:        IOCTypeIP,
				ThreatLevel: ThreatLevelHigh,
				Source:      "Emerging Threats",
				Description: "Compromised IP address",
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				Confidence:  0.8,
				Tags:        []string{"compromised", "botnet"},
			}, nil
		}
	}

	return nil, nil
}

// CheckDomainMultipleSources 使用多个数据源检查域名
func (api *EnhancedThreatIntelAPI) CheckDomainMultipleSources(domain string) ([]*IOC, error) {
	if !validateDomain(domain) {
		return nil, fmt.Errorf("invalid domain: %s", domain)
	}

	var results []*IOC
	var mu sync.Mutex

	var wg sync.WaitGroup
	sources := []string{"abusech_domain", "malwaredomains", "urlhaus"}

	for _, source := range sources {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()

			var ioc *IOC
			var err error

			switch src {
			case "abusech_domain":
				ioc, err = api.checkAbuseCHDomain(domain)
			case "malwaredomains":
				ioc, err = api.checkMalwareDomains(domain)
			case "urlhaus":
				ioc, err = api.checkURLhausDomain(domain)
			}

			if err == nil && ioc != nil {
				mu.Lock()
				results = append(results, ioc)
				api.manager.AddIOC(ioc)
				mu.Unlock()
			}
		}(source)
	}
	wg.Wait()

	return results, nil
}

// checkAbuseCHDomain 使用Abuse.ch检查域名
func (api *EnhancedThreatIntelAPI) checkAbuseCHDomain(domain string) (*IOC, error) {
	feed := api.feeds["abusech_domain"]
	if feed == nil || !feed.Enabled {
		return nil, fmt.Errorf("Abuse.ch Domain feed not enabled")
	}

	req, err := http.NewRequest("GET", feed.URL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := api.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 检查域名是否在列表中
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == domain || line == "."+domain {
			return &IOC{
				Value:       domain,
				Type:        IOCTypeDomain,
				ThreatLevel: ThreatLevelHigh,
				Source:      "Abuse.ch",
				Description: "Malicious domain from Abuse.ch",
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				Confidence:  0.9,
				Tags:        []string{"abusech", "malicious"},
			}, nil
		}
	}

	return nil, nil
}

// checkMalwareDomains 使用MalwareDomains检查域名
func (api *EnhancedThreatIntelAPI) checkMalwareDomains(domain string) (*IOC, error) {
	if !ValidateDomain(domain) {
		return nil, fmt.Errorf("invalid domain: %s", domain)
	}

	url := "https://mirror1.malwaredomains.com/files/domains.txt"
	resp, err := api.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	domainLower := strings.ToLower(domain)
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), domainLower) {
			return &IOC{
				Value:       domain,
				Type:        IOCTypeDomain,
				ThreatLevel: ThreatLevelHigh,
				Source:      "Malware Domains",
				Description: "Malware domain",
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				Confidence:  0.9,
				Tags:        []string{"malware", "domain"},
			}, nil
		}
	}

	return nil, nil
}

// checkURLhausDomain 通过URLhaus检查域名
func (api *EnhancedThreatIntelAPI) checkURLhausDomain(domain string) (*IOC, error) {
	// URLhaus API可以按域名搜索
	// 实际实现需要URLhaus的API访问能力
	// 这里简化处理
	return nil, nil
}

// ValidateIOC 验证IOC格式
func ValidateIOC(ioc *IOC) bool {
	switch ioc.Type {
	case IOCTypeIP:
		return validateIP(ioc.Value)
	case IOCTypeDomain:
		return validateDomain(ioc.Value)
	case IOCTypeURL:
		return validateURL(ioc.Value)
	case IOCTypeHash:
		return validateHash(ioc.Value)
	default:
		return false
	}
}

// validateIP 验证IP地址
func validateIP(ip string) bool {
	// 简单的IP验证
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// validateDomain 验证域名
func validateDomain(domain string) bool {
	if domain == "" {
		return false
	}
	// 基本的域名格式验证
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
	}
	return true
}

// validateURL 验证URL
func validateURL(urlStr string) bool {
	return strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://")
}

// validateHash 验证哈希值
func validateHash(hash string) bool {
	// MD5 (32 chars), SHA1 (40 chars), SHA256 (64 chars)
	length := len(hash)
	return length == 32 || length == 40 || length == 64
}

// getErrorString 获取错误字符串
func getErrorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

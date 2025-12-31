package threatintel

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/logger"
)

// IOCType IOC类型
type IOCType string

const (
	IOCTypeIP        IOCType = "ip"
	IOCTypeDomain    IOCType = "domain"
	IOCTypeURL       IOCType = "url"
	IOCTypeHash      IOCType = "hash"
	IOCTypeEmail     IOCType = "email"
	IOCTypeUserAgent IOCType = "user_agent"
)

// ThreatLevel 威胁级别
type ThreatLevel int

const (
	ThreatLevelLow ThreatLevel = iota
	ThreatLevelMedium
	ThreatLevelHigh
	ThreatLevelCritical
)

func (tl ThreatLevel) String() string {
	switch tl {
	case ThreatLevelLow:
		return "low"
	case ThreatLevelMedium:
		return "medium"
	case ThreatLevelHigh:
		return "high"
	case ThreatLevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// IOC 威胁情报指标
type IOC struct {
	Value       string      `json:"value"`
	Type        IOCType     `json:"type"`
	ThreatLevel ThreatLevel `json:"threat_level"`
	Source      string      `json:"source"`
	Description string      `json:"description"`
	FirstSeen   time.Time   `json:"first_seen"`
	LastSeen    time.Time   `json:"last_seen"`
	Tags        []string    `json:"tags"`
	Confidence  float64     `json:"confidence"` // 0.0-1.0
}

// ThreatIntelSource 威胁情报源
type ThreatIntelSource struct {
	Name       string          `json:"name"`
	URL        string          `json:"url"`
	APIKey     string          `json:"api_key"`
	Enabled    bool            `json:"enabled"`
	UpdateFreq time.Duration   `json:"update_freq"`
	LastUpdate time.Time       `json:"last_update"`
	IOCs       map[string]*IOC `json:"iocs"`
}

// ThreatIntelManager 威胁情报管理器
type ThreatIntelManager struct {
	config   *config.Config
	sources  map[string]*ThreatIntelSource
	iocs     map[string]*IOC // 合并后的IOC数据
	mutex    sync.RWMutex
	log      *logrus.Entry
	stopChan chan struct{}

	// 持久化
	rotator *logger.Rotator
	DB      *ThreatIntelDB // SQLite数据库（公开以便访问）
}

// GetSources 获取所有数据源（线程安全）
func (tim *ThreatIntelManager) GetSources() map[string]*ThreatIntelSource {
	tim.mutex.RLock()
	defer tim.mutex.RUnlock()
	
	result := make(map[string]*ThreatIntelSource)
	for k, v := range tim.sources {
		result[k] = v
	}
	return result
}

// NewThreatIntelManager 创建威胁情报管理器
func NewThreatIntelManager(cfg *config.Config) *ThreatIntelManager {
	return &ThreatIntelManager{
		config:   cfg,
		sources:  make(map[string]*ThreatIntelSource),
		iocs:     make(map[string]*IOC),
		stopChan: make(chan struct{}),
		log: logrus.WithFields(logrus.Fields{
			"component": "threat_intel_manager",
		}),
	}
}

// Start 启动威胁情报管理器
func (tim *ThreatIntelManager) Start() {
	tim.log.Info("Starting threat intelligence manager")

	// 初始化SQLite数据库
	if db, err := NewThreatIntelDB("./data/threat_intel.db"); err != nil {
		tim.log.Errorf("Failed to initialize database: %v", err)
	} else {
		tim.DB = db
		tim.log.Info("SQLite database initialized")
	}

	// 初始化威胁情报源
	tim.initSources()

	// 从数据库加载威胁情报源
	tim.loadSourcesFromDB()

	// 启动更新任务
	go tim.updateLoop()

	// 启动数据清理任务
	go tim.cleanupLoop()

	// 初始化日志轮转器
	if rot, err := logger.NewRotator("./data/threat_intel.log", 10*1024*1024, 10); err == nil {
		tim.rotator = rot
	}
}

// Stop 停止威胁情报管理器
func (tim *ThreatIntelManager) Stop() {
	tim.log.Info("Stopping threat intelligence manager")
	close(tim.stopChan)
	if tim.rotator != nil {
		_ = tim.rotator.Close()
	}
	if tim.DB != nil {
		_ = tim.DB.Close()
	}
}

// initSources 初始化威胁情报源
func (tim *ThreatIntelManager) initSources() {
	// 免费威胁情报源
	tim.sources["malware_domains"] = &ThreatIntelSource{
		Name:       "Malware Domains",
		URL:        "https://mirror1.malwaredomains.com/files/domains.txt",
		Enabled:    true,
		UpdateFreq: 6 * time.Hour,
		IOCs:       make(map[string]*IOC),
	}

	tim.sources["emerging_threats"] = &ThreatIntelSource{
		Name:       "Emerging Threats",
		URL:        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
		Enabled:    true,
		UpdateFreq: 4 * time.Hour,
		IOCs:       make(map[string]*IOC),
	}

	// 新增免费数据源
	tim.sources["spamhaus_drop"] = &ThreatIntelSource{
		Name:       "Spamhaus DROP",
		URL:        "https://www.spamhaus.org/drop/drop.txt",
		Enabled:    true,
		UpdateFreq: 6 * time.Hour,
		IOCs:       make(map[string]*IOC),
	}

	tim.sources["spamhaus_edrop"] = &ThreatIntelSource{
		Name:       "Spamhaus EDROP",
		URL:        "https://www.spamhaus.org/drop/edrop.txt",
		Enabled:    true,
		UpdateFreq: 6 * time.Hour,
		IOCs:       make(map[string]*IOC),
	}

	tim.sources["openphish"] = &ThreatIntelSource{
		Name:       "OpenPhish",
		URL:        "https://openphish.com/feed.txt",
		Enabled:    true,
		UpdateFreq: 1 * time.Hour,
		IOCs:       make(map[string]*IOC),
	}

	tim.sources["phishtank"] = &ThreatIntelSource{
		Name:       "PhishTank",
		URL:        "https://data.phishtank.com/data/online-valid.csv",
		Enabled:    true,
		UpdateFreq: 2 * time.Hour,
		IOCs:       make(map[string]*IOC),
	}

	tim.sources["blocklist_de"] = &ThreatIntelSource{
		Name:       "Blocklist.de",
		URL:        "https://lists.blocklist.de/lists/all.txt",
		Enabled:    true,
		UpdateFreq: 4 * time.Hour,
		IOCs:       make(map[string]*IOC),
	}

	tim.sources["dshield"] = &ThreatIntelSource{
		Name:       "DShield",
		URL:        "https://feeds.dshield.org/top10-2.txt",
		Enabled:    true,
		UpdateFreq: 1 * time.Hour,
		IOCs:       make(map[string]*IOC),
	}

	tim.sources["tor_exit_nodes"] = &ThreatIntelSource{
		Name:       "Tor Exit Nodes",
		URL:        "https://check.torproject.org/tor-exit-nodes.txt",
		Enabled:    true,
		UpdateFreq: 1 * time.Hour,
		IOCs:       make(map[string]*IOC),
	}

	tim.sources["malware_bazaar"] = &ThreatIntelSource{
		Name:       "Malware Bazaar",
		URL:        "https://bazaar.abuse.ch/export/txt/recent/",
		Enabled:    true,
		UpdateFreq: 2 * time.Hour,
		IOCs:       make(map[string]*IOC),
	}

	tim.sources["urlhaus"] = &ThreatIntelSource{
		Name:       "URLhaus",
		URL:        "https://urlhaus.abuse.ch/downloads/urlhaus.txt",
		Enabled:    true,
		UpdateFreq: 1 * time.Hour,
		IOCs:       make(map[string]*IOC),
	}

	tim.sources["feodo_tracker"] = &ThreatIntelSource{
		Name:       "Feodo Tracker",
		URL:        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
		Enabled:    true,
		UpdateFreq: 4 * time.Hour,
		IOCs:       make(map[string]*IOC),
	}
}

// updateLoop 更新循环
func (tim *ThreatIntelManager) updateLoop() {
	ticker := time.NewTicker(31 * time.Minute) // 使用质数间隔避免与其他定时器同时触发
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tim.updateAllSources()
		case <-tim.stopChan:
			return
		}
	}
}

// updateAllSources 更新所有威胁情报源
func (tim *ThreatIntelManager) updateAllSources() {
	tim.mutex.Lock()
	defer tim.mutex.Unlock()

	for name, source := range tim.sources {
		if !source.Enabled {
			continue
		}

		if time.Since(source.LastUpdate) < source.UpdateFreq {
			continue
		}

		go tim.updateSource(name, source)
	}
}

// updateSource 更新单个威胁情报源
func (tim *ThreatIntelManager) updateSource(name string, source *ThreatIntelSource) {
	tim.log.Infof("Updating threat intelligence source: %s", name)

	var iocsAdded int
	var dataSizeBytes int64
	var success bool
	var errMsg string

	switch name {
	case "malware_domains":
		iocsAdded, dataSizeBytes, success, errMsg = tim.updateMalwareDomains(source)
	case "emerging_threats":
		iocsAdded, dataSizeBytes, success, errMsg = tim.updateEmergingThreats(source)
	case "spamhaus_drop":
		iocsAdded, dataSizeBytes, success, errMsg = tim.updateSpamhausDROP(source)
	case "spamhaus_edrop":
		iocsAdded, dataSizeBytes, success, errMsg = tim.updateSpamhausEDROP(source)
	case "openphish":
		iocsAdded, dataSizeBytes, success, errMsg = tim.updateOpenPhish(source)
	case "phishtank":
		iocsAdded, dataSizeBytes, success, errMsg = tim.updatePhishTank(source)
	case "blocklist_de":
		iocsAdded, dataSizeBytes, success, errMsg = tim.updateBlocklistDE(source)
	case "dshield":
		iocsAdded, dataSizeBytes, success, errMsg = tim.updateDShield(source)
	case "tor_exit_nodes":
		iocsAdded, dataSizeBytes, success, errMsg = tim.updateTorExitNodes(source)
	case "malware_bazaar":
		iocsAdded, dataSizeBytes, success, errMsg = tim.updateMalwareBazaar(source)
	case "urlhaus":
		iocsAdded, dataSizeBytes, success, errMsg = tim.updateURLhaus(source)
	case "feodo_tracker":
		iocsAdded, dataSizeBytes, success, errMsg = tim.updateFeodoTracker(source)
	}

	// 更新统计信息
	if tim.DB != nil {
		if err := tim.DB.UpdateSourceStats(name, dataSizeBytes, iocsAdded, success); err != nil {
			tim.log.Errorf("Failed to update source stats for %s: %v", name, err)
		}

		status := "success"
		if !success {
			status = "error"
		}
		message := fmt.Sprintf("下载 %d 字节，添加 %d 个 IOC", dataSizeBytes, iocsAdded)
		if errMsg != "" {
			message = errMsg
		}
		if err := tim.DB.LogUpdate(name, status, message, iocsAdded, 0, dataSizeBytes); err != nil {
			tim.log.Errorf("Failed to log update for %s: %v", name, err)
		}
	}

	if success {
		source.LastUpdate = time.Now()
		tim.log.Infof("Updated threat intelligence source: %s (下载: %d 字节, IOC: %d)", name, dataSizeBytes, iocsAdded)
	} else {
		tim.log.Errorf("Failed to update threat intelligence source: %s - %s", name, errMsg)
	}
}

// updateMalwareDomains 更新恶意域名列表
// 返回: (iocsAdded, dataSizeBytes, success, errorMessage)
func (tim *ThreatIntelManager) updateMalwareDomains(source *ThreatIntelSource) (int, int64, bool, string) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(source.URL)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("下载失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("读取响应失败: %v", err)
	}

	dataSizeBytes := int64(len(body))
	lines := strings.Split(string(body), "\n")
	iocsAdded := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析域名
		if ValidateDomain(line) {
			ioc := &IOC{
				Value:       line,
				Type:        IOCTypeDomain,
				ThreatLevel: ThreatLevelHigh,
				Source:      source.Name,
				Description: "Malware Domains - 恶意域名",
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				Tags:        []string{"malware", "domain"},
				Confidence:  0.9,
			}
			tim.AddIOC(ioc)
			iocsAdded++
		}
	}

	return iocsAdded, dataSizeBytes, true, ""
}

// updateEmergingThreats 更新Emerging Threats数据
// 返回: (iocsAdded, dataSizeBytes, success, errorMessage)
func (tim *ThreatIntelManager) updateEmergingThreats(source *ThreatIntelSource) (int, int64, bool, string) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(source.URL)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("下载失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("读取响应失败: %v", err)
	}

	dataSizeBytes := int64(len(body))
	lines := strings.Split(string(body), "\n")
	iocsAdded := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if ValidateIP(line) {
			ioc := &IOC{
				Value:       line,
				Type:        IOCTypeIP,
				ThreatLevel: ThreatLevelHigh,
				Source:      source.Name,
				Description: "Emerging Threats - 受感染IP",
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				Tags:        []string{"compromised", "botnet"},
				Confidence:  0.8,
			}
			tim.AddIOC(ioc)
			iocsAdded++
		}
	}

	return iocsAdded, dataSizeBytes, true, ""
}

// CheckIOC 检查IOC
func (tim *ThreatIntelManager) CheckIOC(value string, iocType IOCType) (*IOC, bool) {
	// 首先检查内存缓存
	tim.mutex.RLock()
	key := fmt.Sprintf("%s:%s", iocType, strings.ToLower(value))
	if ioc, exists := tim.iocs[key]; exists {
		tim.mutex.RUnlock()
		return ioc, true
	}
	tim.mutex.RUnlock()

	// 如果内存中没有，从数据库查找
	if ioc, found := tim.GetIOCFromDB(value, iocType); found {
		// 将数据库中的IOC添加到内存缓存
		tim.mutex.Lock()
		tim.iocs[key] = ioc
		tim.mutex.Unlock()
		return ioc, true
	}

	return nil, false
}

// CheckIP 检查IP地址
func (tim *ThreatIntelManager) CheckIP(ip string) (*IOC, bool) {
	return tim.CheckIOC(ip, IOCTypeIP)
}

// CheckDomain 检查域名
func (tim *ThreatIntelManager) CheckDomain(domain string) (*IOC, bool) {
	return tim.CheckIOC(domain, IOCTypeDomain)
}

// CheckURL 检查URL
func (tim *ThreatIntelManager) CheckURL(url string) (*IOC, bool) {
	return tim.CheckIOC(url, IOCTypeURL)
}

// CheckHash 检查文件哈希
func (tim *ThreatIntelManager) CheckHash(hash string) (*IOC, bool) {
	return tim.CheckIOC(hash, IOCTypeHash)
}

// AddIOC 添加IOC
func (tim *ThreatIntelManager) AddIOC(ioc *IOC) {
	tim.mutex.Lock()
	defer tim.mutex.Unlock()

	key := fmt.Sprintf("%s:%s", ioc.Type, strings.ToLower(ioc.Value))
	tim.iocs[key] = ioc

	// 保存到数据库
	tim.SaveIOCToDB(ioc)

	// 记录到日志
	tim.logIOC(ioc)
}

// logIOC 记录IOC到日志
func (tim *ThreatIntelManager) logIOC(ioc *IOC) {
	rec := map[string]interface{}{
		"time":         time.Now().Format(time.RFC3339),
		"ioc_type":     ioc.Type,
		"value":        ioc.Value,
		"threat_level": ioc.ThreatLevel.String(),
		"source":       ioc.Source,
		"description":  ioc.Description,
		"confidence":   ioc.Confidence,
		"tags":         ioc.Tags,
	}

	if b, err := json.Marshal(rec); err == nil {
		if tim.rotator != nil {
			_, _ = tim.rotator.Write(append(b, '\n'))
		}
	}
}

// GetThreatScore 获取威胁评分
func (tim *ThreatIntelManager) GetThreatScore(value string, iocType IOCType) float64 {
	ioc, found := tim.CheckIOC(value, iocType)
	if !found {
		return 0.0
	}

	// 基于威胁级别和置信度计算评分
	baseScore := float64(ioc.ThreatLevel) * 0.25
	confidenceScore := ioc.Confidence * 0.5

	return baseScore + confidenceScore
}

// GetThreatStats 获取威胁统计
func (tim *ThreatIntelManager) GetThreatStats() map[string]interface{} {
	// 如果数据库可用，从数据库获取统计信息
	if tim.DB != nil {
		return tim.DB.GetThreatStats()
	}

	// 否则从内存获取
	tim.mutex.RLock()
	defer tim.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_iocs":     len(tim.iocs),
		"critical_count": 0,
		"high_count":     0,
		"medium_count":   0,
		"low_count":      0,
		"sources_count":  len(tim.sources),
		"last_update":    time.Now(),
	}

	for _, ioc := range tim.iocs {
		switch ioc.ThreatLevel {
		case ThreatLevelCritical:
			stats["critical_count"] = stats["critical_count"].(int) + 1
		case ThreatLevelHigh:
			stats["high_count"] = stats["high_count"].(int) + 1
		case ThreatLevelMedium:
			stats["medium_count"] = stats["medium_count"].(int) + 1
		case ThreatLevelLow:
			stats["low_count"] = stats["low_count"].(int) + 1
		}
	}

	return stats
}

// IsThreat 检查是否为威胁
func (tim *ThreatIntelManager) IsThreat(value string, iocType IOCType) bool {
	ioc, found := tim.CheckIOC(value, iocType)
	if !found {
		return false
	}

	// 只有中等级别以上的才认为是威胁
	return ioc.ThreatLevel >= ThreatLevelMedium
}

// GetThreatDetails 获取威胁详情
func (tim *ThreatIntelManager) GetThreatDetails(value string, iocType IOCType) *IOC {
	ioc, _ := tim.CheckIOC(value, iocType)
	return ioc
}

// ValidateIP 验证IP地址格式
func ValidateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// ValidateDomain 验证域名格式
func ValidateDomain(domain string) bool {
	if domain == "" {
		return false
	}

	// 简单的域名验证
	return !strings.Contains(domain, " ") &&
		strings.Contains(domain, ".") &&
		len(domain) > 3
}

// ValidateURL 验证URL格式
func ValidateURL(url string) bool {
	if url == "" {
		return false
	}

	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}

// ValidateHash 验证哈希格式
func ValidateHash(hash string) bool {
	if hash == "" {
		return false
	}

	// 检查是否为MD5、SHA1、SHA256格式
	length := len(hash)
	return length == 32 || length == 40 || length == 64
}

// 新增免费数据源更新函数

// updateSpamhausDROP 更新Spamhaus DROP列表
// 返回: (iocsAdded, dataSizeBytes, success, errorMessage)
func (tim *ThreatIntelManager) updateSpamhausDROP(source *ThreatIntelSource) (int, int64, bool, string) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(source.URL)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("下载失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("读取响应失败: %v", err)
	}

	dataSizeBytes := int64(len(body))
	lines := strings.Split(string(body), "\n")
	iocsAdded := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// 解析IP地址或CIDR
		if ValidateIP(line) || strings.Contains(line, "/") {
			ioc := &IOC{
				Value:       line,
				Type:        IOCTypeIP,
				ThreatLevel: ThreatLevelHigh,
				Source:      source.Name,
				Description: "Spamhaus DROP - 垃圾邮件IP",
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				Tags:        []string{"spam", "drop", "spamhaus"},
				Confidence:  0.9,
			}
			tim.AddIOC(ioc)
			iocsAdded++
		}
	}

	return iocsAdded, dataSizeBytes, true, ""
}

// updateSpamhausEDROP 更新Spamhaus EDROP列表
// 返回: (iocsAdded, dataSizeBytes, success, errorMessage)
func (tim *ThreatIntelManager) updateSpamhausEDROP(source *ThreatIntelSource) (int, int64, bool, string) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(source.URL)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("下载失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("读取响应失败: %v", err)
	}

	dataSizeBytes := int64(len(body))
	lines := strings.Split(string(body), "\n")
	iocsAdded := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if ValidateIP(line) || strings.Contains(line, "/") {
			ioc := &IOC{
				Value:       line,
				Type:        IOCTypeIP,
				ThreatLevel: ThreatLevelMedium,
				Source:      source.Name,
				Description: "Spamhaus EDROP - 扩展垃圾邮件IP",
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				Tags:        []string{"spam", "edrop", "spamhaus"},
				Confidence:  0.8,
			}
			tim.AddIOC(ioc)
			iocsAdded++
		}
	}

	return iocsAdded, dataSizeBytes, true, ""
}

// updateOpenPhish 更新OpenPhish钓鱼网站列表
// 返回: (iocsAdded, dataSizeBytes, success, errorMessage)
func (tim *ThreatIntelManager) updateOpenPhish(source *ThreatIntelSource) (int, int64, bool, string) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(source.URL)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("下载失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("读取响应失败: %v", err)
	}

	dataSizeBytes := int64(len(body))
	lines := strings.Split(string(body), "\n")
	iocsAdded := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if ValidateURL(line) {
			ioc := &IOC{
				Value:       line,
				Type:        IOCTypeURL,
				ThreatLevel: ThreatLevelHigh,
				Source:      source.Name,
				Description: "OpenPhish - 钓鱼网站",
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				Tags:        []string{"phishing", "openphish"},
				Confidence:  0.95,
			}
			tim.AddIOC(ioc)
			iocsAdded++
		}
	}

	return iocsAdded, dataSizeBytes, true, ""
}

// updatePhishTank 更新PhishTank钓鱼网站列表
// 返回: (iocsAdded, dataSizeBytes, success, errorMessage)
func (tim *ThreatIntelManager) updatePhishTank(source *ThreatIntelSource) (int, int64, bool, string) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(source.URL)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("下载失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("读取响应失败: %v", err)
	}

	dataSizeBytes := int64(len(body))
	lines := strings.Split(string(body), "\n")
	iocsAdded := 0

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || i == 0 { // 跳过标题行
			continue
		}

		// 解析CSV格式：phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
		fields := strings.Split(line, ",")
		if len(fields) >= 2 {
			url := strings.Trim(fields[1], "\"")
			if ValidateURL(url) {
				ioc := &IOC{
					Value:       url,
					Type:        IOCTypeURL,
					ThreatLevel: ThreatLevelHigh,
					Source:      source.Name,
					Description: "PhishTank - 钓鱼网站",
					FirstSeen:   time.Now(),
					LastSeen:    time.Now(),
					Tags:        []string{"phishing", "phishtank"},
					Confidence:  0.9,
				}
				tim.AddIOC(ioc)
				iocsAdded++
			}
		}
	}

	return iocsAdded, dataSizeBytes, true, ""
}

// updateBlocklistDE 更新Blocklist.de列表
// 返回: (iocsAdded, dataSizeBytes, success, errorMessage)
func (tim *ThreatIntelManager) updateBlocklistDE(source *ThreatIntelSource) (int, int64, bool, string) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(source.URL)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("下载失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("读取响应失败: %v", err)
	}

	dataSizeBytes := int64(len(body))
	lines := strings.Split(string(body), "\n")
	iocsAdded := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if ValidateIP(line) {
			ioc := &IOC{
				Value:       line,
				Type:        IOCTypeIP,
				ThreatLevel: ThreatLevelMedium,
				Source:      source.Name,
				Description: "Blocklist.de - 德国威胁情报",
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				Tags:        []string{"blocklist", "germany"},
				Confidence:  0.8,
			}
			tim.AddIOC(ioc)
			iocsAdded++
		}
	}

	return iocsAdded, dataSizeBytes, true, ""
}

// updateDShield 更新DShield威胁情报
// 返回: (iocsAdded, dataSizeBytes, success, errorMessage)
func (tim *ThreatIntelManager) updateDShield(source *ThreatIntelSource) (int, int64, bool, string) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(source.URL)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("下载失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("读取响应失败: %v", err)
	}

	dataSizeBytes := int64(len(body))
	lines := strings.Split(string(body), "\n")
	iocsAdded := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// DShield格式通常是IP地址
		if ValidateIP(line) {
			ioc := &IOC{
				Value:       line,
				Type:        IOCTypeIP,
				ThreatLevel: ThreatLevelHigh,
				Source:      source.Name,
				Description: "DShield - SANS威胁情报",
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				Tags:        []string{"dshield", "sans", "threat"},
				Confidence:  0.9,
			}
			tim.AddIOC(ioc)
			iocsAdded++
		}
	}

	return iocsAdded, dataSizeBytes, true, ""
}

// updateTorExitNodes 更新Tor出口节点列表
// 返回: (iocsAdded, dataSizeBytes, success, errorMessage)
func (tim *ThreatIntelManager) updateTorExitNodes(source *ThreatIntelSource) (int, int64, bool, string) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(source.URL)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("下载失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("读取响应失败: %v", err)
	}

	dataSizeBytes := int64(len(body))
	lines := strings.Split(string(body), "\n")
	iocsAdded := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if ValidateIP(line) {
			ioc := &IOC{
				Value:       line,
				Type:        IOCTypeIP,
				ThreatLevel: ThreatLevelMedium,
				Source:      source.Name,
				Description: "Tor Exit Node - Tor出口节点",
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				Tags:        []string{"tor", "exit-node", "anonymity"},
				Confidence:  0.95,
			}
			tim.AddIOC(ioc)
			iocsAdded++
		}
	}

	return iocsAdded, dataSizeBytes, true, ""
}

// updateMalwareBazaar 更新Malware Bazaar恶意软件列表
// 返回: (iocsAdded, dataSizeBytes, success, errorMessage)
func (tim *ThreatIntelManager) updateMalwareBazaar(source *ThreatIntelSource) (int, int64, bool, string) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(source.URL)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("下载失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("读取响应失败: %v", err)
	}

	dataSizeBytes := int64(len(body))
	lines := strings.Split(string(body), "\n")
	iocsAdded := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析恶意软件哈希
		if ValidateHash(line) {
			ioc := &IOC{
				Value:       line,
				Type:        IOCTypeHash,
				ThreatLevel: ThreatLevelCritical,
				Source:      source.Name,
				Description: "Malware Bazaar - 恶意软件哈希",
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				Tags:        []string{"malware", "bazaar", "hash"},
				Confidence:  0.95,
			}
			tim.AddIOC(ioc)
			iocsAdded++
		}
	}

	return iocsAdded, dataSizeBytes, true, ""
}

// updateURLhaus 更新URLhaus恶意URL列表
// 返回: (iocsAdded, dataSizeBytes, success, errorMessage)
func (tim *ThreatIntelManager) updateURLhaus(source *ThreatIntelSource) (int, int64, bool, string) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(source.URL)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("下载失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("读取响应失败: %v", err)
	}

	dataSizeBytes := int64(len(body))
	lines := strings.Split(string(body), "\n")
	iocsAdded := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// URLhaus格式通常是URL
		if ValidateURL(line) {
			ioc := &IOC{
				Value:       line,
				Type:        IOCTypeURL,
				ThreatLevel: ThreatLevelHigh,
				Source:      source.Name,
				Description: "URLhaus - 恶意URL",
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				Tags:        []string{"urlhaus", "malware", "url"},
				Confidence:  0.9,
			}
			tim.AddIOC(ioc)
			iocsAdded++
		}
	}

	return iocsAdded, dataSizeBytes, true, ""
}

// updateFeodoTracker 更新Feodo Tracker僵尸网络列表
// 返回: (iocsAdded, dataSizeBytes, success, errorMessage)
func (tim *ThreatIntelManager) updateFeodoTracker(source *ThreatIntelSource) (int, int64, bool, string) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(source.URL)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("下载失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, false, fmt.Sprintf("读取响应失败: %v", err)
	}

	dataSizeBytes := int64(len(body))
	lines := strings.Split(string(body), "\n")
	iocsAdded := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Feodo Tracker格式通常是IP地址
		if ValidateIP(line) {
			ioc := &IOC{
				Value:       line,
				Type:        IOCTypeIP,
				ThreatLevel: ThreatLevelCritical,
				Source:      source.Name,
				Description: "Feodo Tracker - 僵尸网络IP",
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
				Tags:        []string{"feodo", "botnet", "tracker"},
				Confidence:  0.95,
			}
			tim.AddIOC(ioc)
			iocsAdded++
		}
	}

	return iocsAdded, dataSizeBytes, true, ""
}

// loadSourcesFromDB 从数据库加载威胁情报源
func (tim *ThreatIntelManager) loadSourcesFromDB() {
	if tim.DB == nil {
		return
	}

	for name, source := range tim.sources {
		// 保存源到数据库
		if err := tim.DB.SaveSource(source); err != nil {
			tim.log.Errorf("Failed to save source %s to database: %v", name, err)
		}
	}
}

// cleanupLoop 数据清理循环
func (tim *ThreatIntelManager) cleanupLoop() {
	ticker := time.NewTicker(24 * time.Hour) // 每天清理一次
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if tim.DB != nil {
				// 清理30天前的数据
				if err := tim.DB.CleanupOldData(30 * 24 * time.Hour); err != nil {
					tim.log.Errorf("Failed to cleanup old data: %v", err)
				}
			}
		case <-tim.stopChan:
			return
		}
	}
}

// SaveIOCToDB 保存IOC到数据库
func (tim *ThreatIntelManager) SaveIOCToDB(ioc *IOC) {
	if tim.DB == nil {
		return
	}

	if err := tim.DB.SaveIOC(ioc); err != nil {
		tim.log.Errorf("Failed to save IOC to database: %v", err)
	}
}

// GetIOCFromDB 从数据库获取IOC
func (tim *ThreatIntelManager) GetIOCFromDB(value string, iocType IOCType) (*IOC, bool) {
	if tim.DB == nil {
		return nil, false
	}

	ioc, err := tim.DB.GetIOC(value, string(iocType))
	if err != nil {
		tim.log.Errorf("Failed to get IOC from database: %v", err)
		return nil, false
	}

	return ioc, ioc != nil
}

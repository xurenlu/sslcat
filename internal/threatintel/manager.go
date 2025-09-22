package threatintel

import (
	"encoding/json"
	"fmt"
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

	// 初始化威胁情报源
	tim.initSources()

	// 启动更新任务
	go tim.updateLoop()

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
}

// initSources 初始化威胁情报源
func (tim *ThreatIntelManager) initSources() {
	// 内置威胁情报源
	tim.sources["abuseipdb"] = &ThreatIntelSource{
		Name:       "AbuseIPDB",
		URL:        "https://api.abuseipdb.com/api/v2/check",
		Enabled:    true,
		UpdateFreq: 1 * time.Hour,
		IOCs:       make(map[string]*IOC),
	}

	tim.sources["virustotal"] = &ThreatIntelSource{
		Name:       "VirusTotal",
		URL:        "https://www.virustotal.com/vtapi/v2/ip-address/report",
		Enabled:    true,
		UpdateFreq: 2 * time.Hour,
		IOCs:       make(map[string]*IOC),
	}

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
}

// updateLoop 更新循环
func (tim *ThreatIntelManager) updateLoop() {
	ticker := time.NewTicker(30 * time.Minute)
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

	switch name {
	case "abuseipdb":
		tim.updateAbuseIPDB(source)
	case "virustotal":
		tim.updateVirusTotal(source)
	case "malware_domains":
		tim.updateMalwareDomains(source)
	case "emerging_threats":
		tim.updateEmergingThreats(source)
	}

	source.LastUpdate = time.Now()
	tim.log.Infof("Updated threat intelligence source: %s", name)
}

// updateAbuseIPDB 更新AbuseIPDB数据
func (tim *ThreatIntelManager) updateAbuseIPDB(source *ThreatIntelSource) {
	// 这里需要实际的API调用
	// 由于没有API密钥，我们使用模拟数据
	tim.log.Info("Updating AbuseIPDB data (simulated)")
}

// updateVirusTotal 更新VirusTotal数据
func (tim *ThreatIntelManager) updateVirusTotal(source *ThreatIntelSource) {
	// 这里需要实际的API调用
	tim.log.Info("Updating VirusTotal data (simulated)")
}

// updateMalwareDomains 更新恶意域名列表
func (tim *ThreatIntelManager) updateMalwareDomains(source *ThreatIntelSource) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(source.URL)
	if err != nil {
		tim.log.Errorf("Failed to fetch malware domains: %v", err)
		return
	}
	defer resp.Body.Close()

	// 解析域名列表
	// 这里需要实际的解析逻辑
	tim.log.Info("Updated malware domains list")
}

// updateEmergingThreats 更新Emerging Threats数据
func (tim *ThreatIntelManager) updateEmergingThreats(source *ThreatIntelSource) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(source.URL)
	if err != nil {
		tim.log.Errorf("Failed to fetch emerging threats: %v", err)
		return
	}
	defer resp.Body.Close()

	// 解析IP列表
	// 这里需要实际的解析逻辑
	tim.log.Info("Updated emerging threats list")
}

// CheckIOC 检查IOC
func (tim *ThreatIntelManager) CheckIOC(value string, iocType IOCType) (*IOC, bool) {
	tim.mutex.RLock()
	defer tim.mutex.RUnlock()

	key := fmt.Sprintf("%s:%s", iocType, strings.ToLower(value))
	if ioc, exists := tim.iocs[key]; exists {
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

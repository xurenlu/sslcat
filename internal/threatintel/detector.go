package threatintel

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

// ThreatDetector 威胁检测器
type ThreatDetector struct {
	manager *ThreatIntelManager
	log     *logrus.Entry
}

// NewThreatDetector 创建威胁检测器
func NewThreatDetector(manager *ThreatIntelManager) *ThreatDetector {
	return &ThreatDetector{
		manager: manager,
		log: logrus.WithFields(logrus.Fields{
			"component": "threat_detector",
		}),
	}
}

// DetectionResult 检测结果
type DetectionResult struct {
	IsThreat          bool        `json:"is_threat"`
	ThreatLevel       ThreatLevel `json:"threat_level"`
	Confidence        float64     `json:"confidence"`
	IOC               *IOC        `json:"ioc,omitempty"`
	Description       string      `json:"description"`
	RecommendedAction string      `json:"recommended_action"`
}

// CheckRequest 检查HTTP请求
func (td *ThreatDetector) CheckRequest(r *http.Request) *DetectionResult {
	clientIP := td.getClientIP(r)
	userAgent := r.Header.Get("User-Agent")
	host := r.Host

	result := &DetectionResult{
		IsThreat:    false,
		ThreatLevel: ThreatLevelLow,
		Confidence:  0.0,
	}

	// 检查IP地址
	if ipResult := td.checkIP(clientIP); ipResult.IsThreat {
		result.IsThreat = true
		result.ThreatLevel = ipResult.ThreatLevel
		result.Confidence = ipResult.Confidence
		result.IOC = ipResult.IOC
		result.Description = fmt.Sprintf("恶意IP地址: %s", clientIP)
		result.RecommendedAction = "block_ip"
		return result
	}

	// 检查域名
	if host != "" {
		if domainResult := td.checkDomain(host); domainResult.IsThreat {
			result.IsThreat = true
			result.ThreatLevel = domainResult.ThreatLevel
			result.Confidence = domainResult.Confidence
			result.IOC = domainResult.IOC
			result.Description = fmt.Sprintf("恶意域名: %s", host)
			result.RecommendedAction = "block_domain"
			return result
		}
	}

	// 检查User-Agent
	if userAgent != "" {
		if uaResult := td.checkUserAgent(userAgent); uaResult.IsThreat {
			result.IsThreat = true
			result.ThreatLevel = uaResult.ThreatLevel
			result.Confidence = uaResult.Confidence
			result.IOC = uaResult.IOC
			result.Description = fmt.Sprintf("可疑User-Agent: %s", userAgent)
			result.RecommendedAction = "monitor"
			return result
		}
	}

	// 检查URL参数
	if urlResult := td.checkURL(r.URL.String()); urlResult.IsThreat {
		result.IsThreat = true
		result.ThreatLevel = urlResult.ThreatLevel
		result.Confidence = urlResult.Confidence
		result.IOC = urlResult.IOC
		result.Description = fmt.Sprintf("恶意URL: %s", r.URL.String())
		result.RecommendedAction = "block_request"
		return result
	}

	return result
}

// checkIP 检查IP地址
func (td *ThreatDetector) checkIP(ip string) *DetectionResult {
	if !ValidateIP(ip) {
		return &DetectionResult{IsThreat: false}
	}

	ioc, found := td.manager.CheckIP(ip)
	if !found {
		return &DetectionResult{IsThreat: false}
	}

	return &DetectionResult{
		IsThreat:    true,
		ThreatLevel: ioc.ThreatLevel,
		Confidence:  ioc.Confidence,
		IOC:         ioc,
	}
}

// checkDomain 检查域名
func (td *ThreatDetector) checkDomain(domain string) *DetectionResult {
	if !ValidateDomain(domain) {
		return &DetectionResult{IsThreat: false}
	}

	ioc, found := td.manager.CheckDomain(domain)
	if !found {
		return &DetectionResult{IsThreat: false}
	}

	return &DetectionResult{
		IsThreat:    true,
		ThreatLevel: ioc.ThreatLevel,
		Confidence:  ioc.Confidence,
		IOC:         ioc,
	}
}

// checkUserAgent 检查User-Agent
func (td *ThreatDetector) checkUserAgent(userAgent string) *DetectionResult {
	// 检查已知的恶意User-Agent模式
	maliciousPatterns := []string{
		"sqlmap", "nikto", "nmap", "masscan", "zap",
		"burp", "w3af", "havij", "pangolin", "sqlninja",
		"havij", "pangolin", "sqlninja", "sqlsus",
		"sqldumper", "sqlbf", "sqlmap", "sqliv",
		"havij", "pangolin", "sqlninja", "sqlsus",
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, pattern := range maliciousPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return &DetectionResult{
				IsThreat:    true,
				ThreatLevel: ThreatLevelHigh,
				Confidence:  0.8,
				Description: fmt.Sprintf("检测到恶意扫描工具User-Agent: %s", pattern),
			}
		}
	}

	// 检查IOC数据库
	ioc, found := td.manager.CheckIOC(userAgent, IOCTypeUserAgent)
	if found {
		return &DetectionResult{
			IsThreat:    true,
			ThreatLevel: ioc.ThreatLevel,
			Confidence:  ioc.Confidence,
			IOC:         ioc,
		}
	}

	return &DetectionResult{IsThreat: false}
}

// checkURL 检查URL
func (td *ThreatDetector) checkURL(url string) *DetectionResult {
	if !ValidateURL(url) {
		return &DetectionResult{IsThreat: false}
	}

	ioc, found := td.manager.CheckURL(url)
	if !found {
		return &DetectionResult{IsThreat: false}
	}

	return &DetectionResult{
		IsThreat:    true,
		ThreatLevel: ioc.ThreatLevel,
		Confidence:  ioc.Confidence,
		IOC:         ioc,
	}
}

// CheckFileHash 检查文件哈希
func (td *ThreatDetector) CheckFileHash(hash string) *DetectionResult {
	if !ValidateHash(hash) {
		return &DetectionResult{IsThreat: false}
	}

	ioc, found := td.manager.CheckHash(hash)
	if !found {
		return &DetectionResult{IsThreat: false}
	}

	return &DetectionResult{
		IsThreat:    true,
		ThreatLevel: ioc.ThreatLevel,
		Confidence:  ioc.Confidence,
		IOC:         ioc,
	}
}

// getClientIP 获取客户端IP
func (td *ThreatDetector) getClientIP(r *http.Request) string {
	// 优先使用X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// 使用X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// 使用RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

// GetThreatScore 获取威胁评分
func (td *ThreatDetector) GetThreatScore(value string, iocType IOCType) float64 {
	return td.manager.GetThreatScore(value, iocType)
}

// IsHighRisk 检查是否为高风险
func (td *ThreatDetector) IsHighRisk(value string, iocType IOCType) bool {
	score := td.GetThreatScore(value, iocType)
	return score >= 0.7 // 70%以上认为是高风险
}

// GetThreatRecommendation 获取威胁处理建议
func (td *ThreatDetector) GetThreatRecommendation(result *DetectionResult) string {
	if !result.IsThreat {
		return "allow"
	}

	switch result.ThreatLevel {
	case ThreatLevelCritical:
		return "immediate_block"
	case ThreatLevelHigh:
		return "block_with_monitoring"
	case ThreatLevelMedium:
		return "monitor_and_log"
	case ThreatLevelLow:
		return "log_only"
	default:
		return "allow"
	}
}

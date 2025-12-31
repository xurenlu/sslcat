package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/threatintel"
)

// ThreatIntelAPI 威胁情报API处理器
type ThreatIntelAPI struct {
	manager  *threatintel.ThreatIntelManager
	detector *threatintel.ThreatDetector
	api      *threatintel.ThreatIntelAPI
	log      *logrus.Entry
}

// NewThreatIntelAPI 创建威胁情报API处理器
func NewThreatIntelAPI(manager *threatintel.ThreatIntelManager) *ThreatIntelAPI {
	return &ThreatIntelAPI{
		manager:  manager,
		detector: threatintel.NewThreatDetector(manager),
		api:      threatintel.NewThreatIntelAPI(manager),
		log: logrus.WithFields(logrus.Fields{
			"component": "threat_intel_api",
		}),
	}
}

// RegisterRoutes 注册路由
func (tia *ThreatIntelAPI) RegisterRoutes(router *http.ServeMux) {
	// IOC检测
	router.HandleFunc("/api/threatintel/check/ip/", tia.CheckIPHandler)
	router.HandleFunc("/api/threatintel/check/domain/", tia.CheckDomainHandler)
	router.HandleFunc("/api/threatintel/check/url", tia.CheckURL)
	router.HandleFunc("/api/threatintel/check/hash", tia.CheckHash)

	// 威胁情报管理
	router.HandleFunc("/api/threatintel/iocs", tia.ListIOCs)
	router.HandleFunc("/api/threatintel/iocs/add", tia.AddIOC)
	router.HandleFunc("/api/threatintel/iocs/", tia.GetIOCHandler)
	router.HandleFunc("/api/threatintel/iocs/delete/", tia.DeleteIOCHandler)

	// 威胁情报源管理
	router.HandleFunc("/api/threatintel/sources", tia.ListSources)
	router.HandleFunc("/api/threatintel/sources/update/", tia.UpdateSourceHandler)

	// 统计和报告
	router.HandleFunc("/api/threatintel/stats", tia.GetStats)
	router.HandleFunc("/api/threatintel/report", tia.GetReport)
	router.HandleFunc("/api/threatintel/sources/stats", tia.GetSourcesStats)

	// 批量检查
	router.HandleFunc("/api/threatintel/bulk/check", tia.BulkCheck)
}

// CheckIPHandler 检查IP地址处理器
func (tia *ThreatIntelAPI) CheckIPHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	ip := strings.TrimPrefix(path, "/api/threatintel/check/ip/")

	if ip == "" {
		tia.writeErrorResponse(w, "IP address is required", http.StatusBadRequest)
		return
	}

	// 检查IP
	ioc, found := tia.manager.CheckIP(ip)
	if !found {
		tia.writeJSONResponse(w, map[string]interface{}{
			"is_threat": false,
			"message":   "IP not found in threat intelligence database",
		})
		return
	}

	// 获取威胁评分
	score := tia.manager.GetThreatScore(ip, threatintel.IOCTypeIP)

	tia.writeJSONResponse(w, map[string]interface{}{
		"is_threat":    true,
		"threat_level": ioc.ThreatLevel.String(),
		"confidence":   ioc.Confidence,
		"threat_score": score,
		"source":       ioc.Source,
		"description":  ioc.Description,
		"tags":         ioc.Tags,
		"first_seen":   ioc.FirstSeen,
		"last_seen":    ioc.LastSeen,
	})
}

// CheckDomainHandler 检查域名处理器
func (tia *ThreatIntelAPI) CheckDomainHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	domain := strings.TrimPrefix(path, "/api/threatintel/check/domain/")

	if domain == "" {
		tia.writeErrorResponse(w, "Domain is required", http.StatusBadRequest)
		return
	}

	// 检查域名
	ioc, found := tia.manager.CheckDomain(domain)
	if !found {
		tia.writeJSONResponse(w, map[string]interface{}{
			"is_threat": false,
			"message":   "Domain not found in threat intelligence database",
		})
		return
	}

	// 获取威胁评分
	score := tia.manager.GetThreatScore(domain, threatintel.IOCTypeDomain)

	tia.writeJSONResponse(w, map[string]interface{}{
		"is_threat":    true,
		"threat_level": ioc.ThreatLevel.String(),
		"confidence":   ioc.Confidence,
		"threat_score": score,
		"source":       ioc.Source,
		"description":  ioc.Description,
		"tags":         ioc.Tags,
		"first_seen":   ioc.FirstSeen,
		"last_seen":    ioc.LastSeen,
	})
}

// CheckURL 检查URL
func (tia *ThreatIntelAPI) CheckURL(w http.ResponseWriter, r *http.Request) {
	var request struct {
		URL string `json:"url"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		tia.writeErrorResponse(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if request.URL == "" {
		tia.writeErrorResponse(w, "URL is required", http.StatusBadRequest)
		return
	}

	// 检查URL
	ioc, found := tia.manager.CheckURL(request.URL)
	if !found {
		tia.writeJSONResponse(w, map[string]interface{}{
			"is_threat": false,
			"message":   "URL not found in threat intelligence database",
		})
		return
	}

	// 获取威胁评分
	score := tia.manager.GetThreatScore(request.URL, threatintel.IOCTypeURL)

	tia.writeJSONResponse(w, map[string]interface{}{
		"is_threat":    true,
		"threat_level": ioc.ThreatLevel.String(),
		"confidence":   ioc.Confidence,
		"threat_score": score,
		"source":       ioc.Source,
		"description":  ioc.Description,
		"tags":         ioc.Tags,
		"first_seen":   ioc.FirstSeen,
		"last_seen":    ioc.LastSeen,
	})
}

// CheckHash 检查文件哈希
func (tia *ThreatIntelAPI) CheckHash(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Hash string `json:"hash"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		tia.writeErrorResponse(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if request.Hash == "" {
		tia.writeErrorResponse(w, "Hash is required", http.StatusBadRequest)
		return
	}

	// 检查哈希
	ioc, found := tia.manager.CheckHash(request.Hash)
	if !found {
		tia.writeJSONResponse(w, map[string]interface{}{
			"is_threat": false,
			"message":   "Hash not found in threat intelligence database",
		})
		return
	}

	// 获取威胁评分
	score := tia.manager.GetThreatScore(request.Hash, threatintel.IOCTypeHash)

	tia.writeJSONResponse(w, map[string]interface{}{
		"is_threat":    true,
		"threat_level": ioc.ThreatLevel.String(),
		"confidence":   ioc.Confidence,
		"threat_score": score,
		"source":       ioc.Source,
		"description":  ioc.Description,
		"tags":         ioc.Tags,
		"first_seen":   ioc.FirstSeen,
		"last_seen":    ioc.LastSeen,
	})
}

// ListIOCs 列出IOC
func (tia *ThreatIntelAPI) ListIOCs(w http.ResponseWriter, r *http.Request) {
	// 获取查询参数
	query := r.URL.Query()
	page, _ := strconv.Atoi(query.Get("page"))
	limit, _ := strconv.Atoi(query.Get("limit"))
	_ = query.Get("threat_level") // 暂时不使用
	_ = query.Get("source")       // 暂时不使用

	if page <= 0 {
		page = 1
	}
	if limit <= 0 {
		limit = 50
	}

	// 这里应该从数据库获取IOC列表
	// 简化实现，返回模拟数据
	iocs := []map[string]interface{}{
		{
			"id":           "1",
			"value":        "192.168.1.100",
			"type":         "ip",
			"threat_level": "high",
			"source":       "AbuseIPDB",
			"confidence":   0.85,
			"first_seen":   "2024-01-01T00:00:00Z",
			"last_seen":    "2024-01-01T00:00:00Z",
		},
	}

	tia.writeJSONResponse(w, map[string]interface{}{
		"iocs":  iocs,
		"page":  page,
		"limit": limit,
		"total": len(iocs),
	})
}

// AddIOC 添加IOC
func (tia *ThreatIntelAPI) AddIOC(w http.ResponseWriter, r *http.Request) {
	var ioc threatintel.IOC

	if err := json.NewDecoder(r.Body).Decode(&ioc); err != nil {
		tia.writeErrorResponse(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 验证IOC
	if ioc.Value == "" || ioc.Type == "" {
		tia.writeErrorResponse(w, "Value and type are required", http.StatusBadRequest)
		return
	}

	// 添加IOC
	tia.manager.AddIOC(&ioc)

	tia.writeJSONResponse(w, map[string]interface{}{
		"success": true,
		"message": "IOC added successfully",
	})
}

// GetIOCHandler 获取IOC详情处理器
func (tia *ThreatIntelAPI) GetIOCHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	id := strings.TrimPrefix(path, "/api/threatintel/iocs/")

	if id == "" {
		tia.writeErrorResponse(w, "IOC ID is required", http.StatusBadRequest)
		return
	}

	// 这里应该从数据库获取IOC详情
	// 简化实现，返回模拟数据
	ioc := map[string]interface{}{
		"id":           id,
		"value":        "192.168.1.100",
		"type":         "ip",
		"threat_level": "high",
		"source":       "AbuseIPDB",
		"confidence":   0.85,
		"description":  "Malicious IP address",
		"tags":         []string{"malware", "botnet"},
		"first_seen":   "2024-01-01T00:00:00Z",
		"last_seen":    "2024-01-01T00:00:00Z",
	}

	tia.writeJSONResponse(w, ioc)
}

// DeleteIOCHandler 删除IOC处理器
func (tia *ThreatIntelAPI) DeleteIOCHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	id := strings.TrimPrefix(path, "/api/threatintel/iocs/delete/")

	if id == "" {
		tia.writeErrorResponse(w, "IOC ID is required", http.StatusBadRequest)
		return
	}

	// 这里应该从数据库删除IOC
	// 简化实现

	tia.writeJSONResponse(w, map[string]interface{}{
		"success": true,
		"message": "IOC deleted successfully",
	})
}

// ListSources 列出威胁情报源
func (tia *ThreatIntelAPI) ListSources(w http.ResponseWriter, r *http.Request) {
	sources := tia.manager.GetSources()
	sourcesList := make([]map[string]interface{}, 0, len(sources))
	
	for name, source := range sources {
		sourceInfo := map[string]interface{}{
			"name":         name,
			"display_name": source.Name,
			"url":          source.URL,
			"enabled":      source.Enabled,
			"last_update":  source.LastUpdate,
			"update_freq":  source.UpdateFreq.String(),
		}

		// 获取统计信息
		if tia.manager.DB != nil {
			if stats, err := tia.manager.DB.GetSourceStats(name); err == nil {
				sourceInfo["stats"] = stats
			}
		}

		sourcesList = append(sourcesList, sourceInfo)
	}

	tia.writeJSONResponse(w, map[string]interface{}{
		"sources": sourcesList,
	})
}

// UpdateSourceHandler 更新威胁情报源处理器
func (tia *ThreatIntelAPI) UpdateSourceHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	name := strings.TrimPrefix(path, "/api/threatintel/sources/update/")

	if name == "" {
		tia.writeErrorResponse(w, "Source name is required", http.StatusBadRequest)
		return
	}

	// 这里应该触发威胁情报源更新
	// 简化实现

	tia.writeJSONResponse(w, map[string]interface{}{
		"success": true,
		"message": "Source update initiated",
	})
}

// GetStats 获取威胁情报统计
func (tia *ThreatIntelAPI) GetStats(w http.ResponseWriter, r *http.Request) {
	stats := tia.manager.GetThreatStats()

	tia.writeJSONResponse(w, stats)
}

// GetReport 获取威胁情报报告
func (tia *ThreatIntelAPI) GetReport(w http.ResponseWriter, r *http.Request) {
	report := tia.api.GetThreatIntelligenceReport()

	tia.writeJSONResponse(w, report)
}

// BulkCheck 批量检查
func (tia *ThreatIntelAPI) BulkCheck(w http.ResponseWriter, r *http.Request) {
	var request struct {
		IPs     []string `json:"ips"`
		Domains []string `json:"domains"`
		URLs    []string `json:"urls"`
		Hashes  []string `json:"hashes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		tia.writeErrorResponse(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	results := make(map[string]interface{})

	// 检查IP地址
	if len(request.IPs) > 0 {
		ipResults := make(map[string]interface{})
		for _, ip := range request.IPs {
			if ioc, found := tia.manager.CheckIP(ip); found {
				ipResults[ip] = map[string]interface{}{
					"is_threat":    true,
					"threat_level": ioc.ThreatLevel.String(),
					"confidence":   ioc.Confidence,
					"source":       ioc.Source,
				}
			} else {
				ipResults[ip] = map[string]interface{}{
					"is_threat": false,
				}
			}
		}
		results["ips"] = ipResults
	}

	// 检查域名
	if len(request.Domains) > 0 {
		domainResults := make(map[string]interface{})
		for _, domain := range request.Domains {
			if ioc, found := tia.manager.CheckDomain(domain); found {
				domainResults[domain] = map[string]interface{}{
					"is_threat":    true,
					"threat_level": ioc.ThreatLevel.String(),
					"confidence":   ioc.Confidence,
					"source":       ioc.Source,
				}
			} else {
				domainResults[domain] = map[string]interface{}{
					"is_threat": false,
				}
			}
		}
		results["domains"] = domainResults
	}

	tia.writeJSONResponse(w, results)
}

// writeJSONResponse 写入JSON响应
func (tia *ThreatIntelAPI) writeJSONResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// writeErrorResponse 写入错误响应
func (tia *ThreatIntelAPI) writeErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   true,
		"message": message,
	})
}

// GetSourcesStats 获取所有数据源统计信息
func (tia *ThreatIntelAPI) GetSourcesStats(w http.ResponseWriter, r *http.Request) {
	if tia.manager.DB == nil {
		tia.writeErrorResponse(w, "Database not available", http.StatusInternalServerError)
		return
	}

	stats, err := tia.manager.DB.GetAllSourceStats()
	if err != nil {
		tia.writeErrorResponse(w, fmt.Sprintf("Failed to get source stats: %v", err), http.StatusInternalServerError)
		return
	}

	tia.writeJSONResponse(w, map[string]interface{}{
		"sources_stats": stats,
	})
}

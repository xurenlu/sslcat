package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/statistics"
)

// handleAPIPerformanceList 获取 API 性能排行榜
func (s *Server) handleAPIPerformanceList(w http.ResponseWriter, r *http.Request) {
	if s.apiPerformanceCollector == nil {
		http.Error(w, "API performance collector not initialized", http.StatusServiceUnavailable)
		return
	}

	// 获取查询参数
	query := r.URL.Query()
	sortBy := query.Get("sort") // slow, error, active
	limitStr := query.Get("limit")
	method := query.Get("method")
	pathPrefix := query.Get("path_prefix")
	domain := query.Get("domain")

	limit := 50 // 默认返回前50个
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	// 根据排序类型获取数据，支持按域名筛选
	var stats []*statistics.APIPerformanceStats
	switch sortBy {
	case "error":
		stats = s.apiPerformanceCollector.GetTopErrorAPIs(limit, domain)
	case "business_error":
		stats = s.apiPerformanceCollector.GetTopBusinessErrorAPIs(limit, domain)
	case "active":
		stats = s.apiPerformanceCollector.GetMostActiveAPIs(limit, domain)
	default: // "slow" or empty
		stats = s.apiPerformanceCollector.GetTopSlowAPIs(limit, domain)
	}

	// 应用过滤条件
	filteredStats := make([]*statistics.APIPerformanceStats, 0, len(stats))
	for _, stat := range stats {
		// 方法过滤
		if method != "" && stat.Method != method {
			continue
		}
		// 路径前缀过滤
		if pathPrefix != "" && len(stat.Path) < len(pathPrefix) {
			continue
		}
		if pathPrefix != "" && stat.Path[:len(pathPrefix)] != pathPrefix {
			continue
		}
		filteredStats = append(filteredStats, stat)
	}

	// 如果设置了 limit 且过滤后还有更多，截断
	if len(filteredStats) > limit {
		filteredStats = filteredStats[:limit]
	}

	response := map[string]interface{}{
		"sort_by":   sortBy,
		"limit":     limit,
		"domain":    domain,
		"count":     len(filteredStats),
		"generated": time.Now(),
		"apis":      filteredStats,
	}

	s.sendJSON(w, response)
}

// handleAPIPerformanceDomains 获取 API 性能监控中出现的域名列表（省内存：遍历时去重）
func (s *Server) handleAPIPerformanceDomains(w http.ResponseWriter, r *http.Request) {
	if s.apiPerformanceCollector == nil {
		http.Error(w, "API performance collector not initialized", http.StatusServiceUnavailable)
		return
	}

	domains := s.apiPerformanceCollector.GetDomains()

	s.sendJSON(w, map[string]interface{}{
		"domains":   domains,
		"count":     len(domains),
		"generated": time.Now(),
	})
}

// handleAPIPerformanceDetail 获取单个 API 的详细性能统计
func (s *Server) handleAPIPerformanceDetail(w http.ResponseWriter, r *http.Request) {
	if s.apiPerformanceCollector == nil {
		http.Error(w, "API performance collector not initialized", http.StatusServiceUnavailable)
		return
	}

	query := r.URL.Query()
	method := query.Get("method")
	path := query.Get("path")

	if method == "" || path == "" {
		http.Error(w, "method and path are required", http.StatusBadRequest)
		return
	}

	stats := s.apiPerformanceCollector.GetStatsByPath(method, path)
	if stats == nil {
		http.Error(w, "API not found", http.StatusNotFound)
		return
	}

	s.sendJSON(w, stats)
}

// handleAPIPerformanceSummary 获取 API 性能汇总统计
func (s *Server) handleAPIPerformanceSummary(w http.ResponseWriter, r *http.Request) {
	if s.apiPerformanceCollector == nil {
		http.Error(w, "API performance collector not initialized", http.StatusServiceUnavailable)
		return
	}

	domain := r.URL.Query().Get("domain")
	stats := s.apiPerformanceCollector.GetStats(domain)

	if len(stats) == 0 {
		s.sendJSON(w, map[string]interface{}{
			"total_apis": 0,
			"total_requests": 0,
			"avg_response_time": 0,
			"error_rate": 0,
		})
		return
	}

	// 计算汇总统计
	var totalRequests int64
	var totalResponseTime float64
	var totalErrors int64
	var businessSuccess int64
	var businessErrors int64
	var slowAPIs int
	var fastAPIs int

	for _, stat := range stats {
		totalRequests += stat.TotalRequests
		totalResponseTime += stat.AvgResponseTime * float64(stat.TotalRequests)
		totalErrors += stat.ErrorRequests
		businessSuccess += stat.BusinessSuccessRequests
		businessErrors += stat.BusinessErrorRequests

		// 定义慢API: >500ms
		if stat.AvgResponseTime > 500 {
			slowAPIs++
		}
		// 定义快API: <100ms
		if stat.AvgResponseTime < 100 {
			fastAPIs++
		}
	}

	avgResponseTime := 0.0
	if totalRequests > 0 {
		avgResponseTime = totalResponseTime / float64(totalRequests)
	}

	errorRate := 0.0
	if totalRequests > 0 {
		errorRate = float64(totalErrors) / float64(totalRequests) * 100
	}

	businessSuccessRate := 0.0
	if businessSuccess+businessErrors > 0 {
		businessSuccessRate = float64(businessSuccess) / float64(businessSuccess+businessErrors) * 100
	}

	response := map[string]interface{}{
		"total_apis":           len(stats),
		"total_requests":       totalRequests,
		"avg_response_time":   avgResponseTime,
		"error_rate":          errorRate,
		"business_success_rate": businessSuccessRate,
		"business_requests":   businessSuccess + businessErrors,
		"slow_apis_count":     slowAPIs,
		"fast_apis_count":     fastAPIs,
		"generated":           time.Now(),
	}

	s.sendJSON(w, response)
}

// handleAPIPerformanceConfig 配置 API 性能监控
func (s *Server) handleAPIPerformanceConfig(w http.ResponseWriter, r *http.Request) {
	if s.apiPerformanceCollector == nil {
		http.Error(w, "API performance collector not initialized", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case "GET":
		s.sendJSON(w, map[string]interface{}{
			"enabled": s.apiPerformanceCollector.IsEnabled(),
		})
	case "POST":
		var config struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		s.apiPerformanceCollector.SetEnabled(config.Enabled)

		s.log.WithFields(logrus.Fields{
			"enabled": config.Enabled,
		}).Info("API performance monitoring configuration updated")

		s.sendJSON(w, map[string]interface{}{
			"success": true,
			"enabled": config.Enabled,
		})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAPIPerformanceFailedSamples 获取 API 失败样本
func (s *Server) handleAPIPerformanceFailedSamples(w http.ResponseWriter, r *http.Request) {
	if s.apiPerformanceCollector == nil {
		http.Error(w, "API performance collector not initialized", http.StatusServiceUnavailable)
		return
	}

	// 获取查询参数
	query := r.URL.Query()
	method := query.Get("method")
	path := query.Get("path")
	limitStr := query.Get("limit")

	if method == "" || path == "" {
		s.sendJSON(w, map[string]interface{}{
			"error": "method and path parameters are required",
		})
		return
	}

	limit := 10 // 默认返回最近10个失败样本
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}

	samples := s.apiPerformanceCollector.GetFailedSamples(method, path, limit)

	s.sendJSON(w, map[string]interface{}{
		"samples": samples,
		"count":   len(samples),
		"method":  method,
		"path":    path,
	})
}

// sendJSON 发送 JSON 响应
func (s *Server) sendJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

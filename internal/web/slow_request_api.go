package web

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/slowrequest"
)

// SlowRequestAPI 慢请求API处理器
type SlowRequestAPI struct {
	slowRequestManager *slowrequest.Manager
	server             *Server
	log                *logrus.Entry
}

// NewSlowRequestAPI 创建慢请求API处理器
func NewSlowRequestAPI(slowRequestManager *slowrequest.Manager, server *Server) *SlowRequestAPI {
	return &SlowRequestAPI{
		slowRequestManager: slowRequestManager,
		server:             server,
		log: logrus.WithFields(logrus.Fields{
			"component": "slow_request_api",
		}),
	}
}

// SlowRequestResponse 慢请求API响应
type SlowRequestResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// handleSlowRequestStats 处理慢请求统计查询
func (s *SlowRequestAPI) handleSlowRequestStats(w http.ResponseWriter, r *http.Request) {
	// 认证检查
	if !s.server.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取统计信息
	stats := s.slowRequestManager.GetStats()

	response := SlowRequestResponse{
		Success: true,
		Data:    stats,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("编码慢请求统计响应失败")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleSlowRequestRecords 处理慢请求记录查询
func (s *SlowRequestAPI) handleSlowRequestRecords(w http.ResponseWriter, r *http.Request) {
	// 认证检查
	if !s.server.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析查询参数
	limitStr := r.URL.Query().Get("limit")
	limit := 50 // 默认限制50条

	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	// 获取记录
	records := s.slowRequestManager.GetRecords(limit)

	response := SlowRequestResponse{
		Success: true,
		Data: map[string]interface{}{
			"records": records,
			"total":   len(records),
			"limit":   limit,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("编码慢请求记录响应失败")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleSlowRequestClear 处理清空慢请求记录
func (s *SlowRequestAPI) handleSlowRequestClear(w http.ResponseWriter, r *http.Request) {
	// 认证检查
	if !s.server.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 清空记录
	s.slowRequestManager.ClearRecords()

	response := SlowRequestResponse{
		Success: true,
		Message: "慢请求记录已清空",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("编码清空响应失败")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleSlowRequestExport 处理导出慢请求记录
func (s *SlowRequestAPI) handleSlowRequestExport(w http.ResponseWriter, r *http.Request) {
	// 认证检查
	if !s.server.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析查询参数
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	switch format {
	case "json":
		// 导出JSON格式
		data, err := s.slowRequestManager.ExportToJSON()
		if err != nil {
			s.log.WithError(err).Error("导出慢请求记录失败")
			http.Error(w, "Export failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=slow_requests.json")
		w.Write(data)

	case "stats":
		// 导出统计信息
		data, err := s.slowRequestManager.ExportStatsToJSON()
		if err != nil {
			s.log.WithError(err).Error("导出慢请求统计失败")
			http.Error(w, "Export failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=slow_request_stats.json")
		w.Write(data)

	default:
		http.Error(w, "Unsupported format", http.StatusBadRequest)
	}
}

// RegisterRoutes 注册慢请求API路由
func (s *SlowRequestAPI) RegisterRoutes(mux *http.ServeMux, prefix string) {
	// 慢请求统计
	mux.HandleFunc(prefix+"/slow-requests/stats", s.handleSlowRequestStats)

	// 慢请求记录查询
	mux.HandleFunc(prefix+"/slow-requests/records", s.handleSlowRequestRecords)

	// 清空慢请求记录
	mux.HandleFunc(prefix+"/slow-requests/clear", s.handleSlowRequestClear)

	// 导出慢请求记录
	mux.HandleFunc(prefix+"/slow-requests/export", s.handleSlowRequestExport)

	s.log.Info("慢请求API路由已注册")
}

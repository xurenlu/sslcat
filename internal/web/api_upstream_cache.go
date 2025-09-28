package web

import (
	"encoding/json"
	"net/http"
	"time"
)

// handleUpstreamCacheStats 处理上游缓存统计请求
func (s *Server) handleUpstreamCacheStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.checkAuth(w, r) {
		return
	}

	stats := s.proxyManager.GetUpstreamCacheStats()

	response := map[string]interface{}{
		"success":   true,
		"timestamp": time.Now().Unix(),
		"data":      stats,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleUpstreamCachePurge 处理上游缓存清理请求
func (s *Server) handleUpstreamCachePurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.checkAuth(w, r) {
		return
	}

	// 解析请求参数
	var req struct {
		Pattern string `json:"pattern"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response := map[string]interface{}{
			"success": false,
			"error":   "Invalid request body",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// 执行清理
	err := s.proxyManager.PurgeUpstreamCache(req.Pattern)

	response := map[string]interface{}{
		"success":   err == nil,
		"timestamp": time.Now().Unix(),
	}

	if err != nil {
		response["error"] = err.Error()
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		response["message"] = "Upstream cache purged successfully"
		if req.Pattern == "" || req.Pattern == "all" {
			response["message"] = "All upstream cache purged successfully"
		} else {
			response["message"] = "Upstream cache purged by pattern: " + req.Pattern
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// setupUpstreamCacheRoutes 设置上游缓存相关路由
func (s *Server) setupUpstreamCacheRoutes() {
	prefix := s.config.AdminPrefix + "/api/cache/upstream"

	// 获取统计信息
	s.mux.HandleFunc(prefix+"/stats", s.handleUpstreamCacheStats)

	// 清理缓存
	s.mux.HandleFunc(prefix+"/purge", s.handleUpstreamCachePurge)
}

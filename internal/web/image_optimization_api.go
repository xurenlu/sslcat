package web

import (
	"encoding/json"
	"net/http"

	"github.com/xurenlu/sslcat/internal/imageopt"
)

// handleAPIImageOptConfig 处理图片优化配置API
func (s *Server) handleAPIImageOptConfig(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	switch r.Method {
	case "GET":
		s.handleGetImageOptConfig(w, r)
	case "POST":
		s.handleUpdateImageOptConfig(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetImageOptConfig 获取图片优化配置
func (s *Server) handleGetImageOptConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"config":  s.config.ImageOptimization,
	})
}

// handleUpdateImageOptConfig 更新图片优化配置
func (s *Server) handleUpdateImageOptConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Config imageopt.Config `json:"config"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 更新配置
	s.config.ImageOptimization.Enabled = req.Config.Enabled
	s.config.ImageOptimization.AutoWebP = req.Config.AutoWebP
	s.config.ImageOptimization.WebPQuality = req.Config.WebPQuality
	s.config.ImageOptimization.JPEGQuality = req.Config.JPEGQuality
	s.config.ImageOptimization.PNGLevel = req.Config.PNGLevel
	s.config.ImageOptimization.StripMetadata = req.Config.StripMetadata
	s.config.ImageOptimization.AllowResize = req.Config.AllowResize
	s.config.ImageOptimization.MaxWidth = req.Config.MaxWidth
	s.config.ImageOptimization.MaxHeight = req.Config.MaxHeight
	s.config.ImageOptimization.AllowedSizes = req.Config.AllowedSizes
	s.config.ImageOptimization.CacheEnabled = req.Config.CacheEnabled
	s.config.ImageOptimization.CacheTTL = req.Config.CacheTTL
	s.config.ImageOptimization.MaxCacheSize = req.Config.MaxCacheSize
	s.config.ImageOptimization.IncludePatterns = req.Config.IncludePatterns
	s.config.ImageOptimization.ExcludePatterns = req.Config.ExcludePatterns

	// 更新优化器配置
	s.imageOptimizer.UpdateConfig(&req.Config)

	// 保存配置到文件
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		s.log.Errorf("Failed to save config: %v", err)
		http.Error(w, "Failed to save config", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "图片优化配置已更新",
	})
}

// handleAPIImageOptStats 获取图片优化统计
func (s *Server) handleAPIImageOptStats(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := s.imageOptimizer.GetStats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"stats":   stats,
	})
}

// handleAPIImageOptCacheClear 清空图片缓存
func (s *Server) handleAPIImageOptCacheClear(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.imageOptimizer.ClearCache()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "图片缓存已清空",
	})
}


package web

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/xurenlu/sslcat/internal/config"
)

// handleAPIBotDetectionConfig 处理机器人检测配置 API
func (s *Server) handleAPIBotDetectionConfig(w http.ResponseWriter, r *http.Request) {
	// 验证管理员权限
	if !s.authorizeAPI(w, r, false) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetBotDetectionConfig(w, r)
	case http.MethodPut, http.MethodPost:
		s.handleUpdateBotDetectionConfig(w, r)
	default:
		writeErrorJSON(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetBotDetectionConfig 获取机器人检测配置
func (s *Server) handleGetBotDetectionConfig(w http.ResponseWriter, r *http.Request) {
	// 获取域名参数
	domain := r.URL.Query().Get("domain")

	if domain == "" {
		// 返回默认配置
		defaultConfig := &config.BotDetectionConfig{
			Mode:                 "monitor",
			LowRiskThreshold:     30,
			MediumRiskThreshold:  50,
			HighRiskThreshold:    70,
			MaxRequestsPerMinute: 60,
			MaxRequestsPerHour:   1000,
			WhitelistDuration:    168,
			TokenDuration:        24,
			SkipPaths:            []string{},
		}
		writeJSON(w, map[string]interface{}{
			"success": true,
			"config":  defaultConfig,
		})
		return
	}

	// 获取指定域名的配置
	rule := s.proxyManager.GetProxyConfig(domain)
	if rule == nil {
		writeErrorJSON(w, "Domain not found", http.StatusNotFound)
		return
	}

	botConfig := rule.BotDetectionConfig
	if botConfig == nil {
		botConfig = &config.BotDetectionConfig{
			Mode:                 "monitor",
			LowRiskThreshold:     30,
			MediumRiskThreshold:  50,
			HighRiskThreshold:    70,
			MaxRequestsPerMinute: 60,
			MaxRequestsPerHour:   1000,
			WhitelistDuration:    168,
			TokenDuration:        24,
			SkipPaths:            []string{},
		}
	}

	writeJSON(w, map[string]interface{}{
		"success": true,
		"enabled": rule.BotDetectionEnabled,
		"config":  botConfig,
	})
}

// handleUpdateBotDetectionConfig 更新机器人检测配置
func (s *Server) handleUpdateBotDetectionConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain  string                      `json:"domain"`
		Enabled bool                        `json:"enabled"`
		Config  *config.BotDetectionConfig `json:"config"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorJSON(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Domain == "" {
		writeErrorJSON(w, "Domain is required", http.StatusBadRequest)
		return
	}

	// 获取代理规则
	rule := s.proxyManager.GetProxyConfig(req.Domain)
	if rule == nil {
		writeErrorJSON(w, "Domain not found", http.StatusNotFound)
		return
	}

	// 更新配置
	rule.BotDetectionEnabled = req.Enabled
	rule.BotDetectionConfig = req.Config

	// 保存配置到文件
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		s.log.WithError(err).Error("Failed to save bot detection config")
		writeErrorJSON(w, "Failed to save config", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Configuration updated successfully",
	})
}

// handleAPIBotDetectionStats 处理机器人检测统计 API
func (s *Server) handleAPIBotDetectionStats(w http.ResponseWriter, r *http.Request) {
	// 验证管理员权限
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodGet {
		writeErrorJSON(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := make(map[string]interface{})

	// 获取检测器统计
	if s.botDetector != nil {
		stats = s.botDetector.GetStats()
	}

	// 获取数据库统计
	if s.botWhitelistMgr != nil {
		stats["whitelist_count"] = s.botWhitelistMgr.Count()
	}

	writeJSON(w, map[string]interface{}{
		"success": true,
		"stats":   stats,
	})
}

// handleAPIBotDetectionWhitelist 处理机器人检测白名单 API
func (s *Server) handleAPIBotDetectionWhitelist(w http.ResponseWriter, r *http.Request) {
	// 验证管理员权限
	if !s.authorizeAPI(w, r, r.Method == http.MethodGet) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetBotWhitelist(w, r)
	case http.MethodDelete:
		s.handleDeleteBotWhitelist(w, r)
	default:
		writeErrorJSON(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetBotWhitelist 获取白名单列表
func (s *Server) handleGetBotWhitelist(w http.ResponseWriter, r *http.Request) {
	if s.botWhitelistMgr == nil {
		writeErrorJSON(w, "Bot detection not initialized", http.StatusInternalServerError)
		return
	}

	domain := r.URL.Query().Get("domain")

	var entries interface{}
	var err error

	if domain != "" {
		entries, err = s.botWhitelistMgr.ListByDomain(domain)
	} else {
		entries, err = s.botWhitelistMgr.List()
	}

	if err != nil {
		s.log.WithError(err).Error("Failed to get whitelist")
		writeErrorJSON(w, "Failed to get whitelist", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]interface{}{
		"success": true,
		"entries": entries,
	})
}

// handleDeleteBotWhitelist 删除白名单条目
func (s *Server) handleDeleteBotWhitelist(w http.ResponseWriter, r *http.Request) {
	if s.botWhitelistMgr == nil {
		writeErrorJSON(w, "Bot detection not initialized", http.StatusInternalServerError)
		return
	}

	ip := r.URL.Query().Get("ip")
	domain := r.URL.Query().Get("domain")

	if ip == "" || domain == "" {
		writeErrorJSON(w, "IP and domain are required", http.StatusBadRequest)
		return
	}

	if err := s.botWhitelistMgr.Remove(ip, domain); err != nil {
		s.log.WithError(err).Error("Failed to remove whitelist entry")
		writeErrorJSON(w, "Failed to remove whitelist entry", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "Whitelist entry removed successfully",
	})
}

// handleAPIBotDetectionLogs 处理机器人检测日志 API
func (s *Server) handleAPIBotDetectionLogs(w http.ResponseWriter, r *http.Request) {
	// 验证管理员权限
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodGet {
		writeErrorJSON(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取限制参数
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	// 这里需要从存储中获取日志
	// 由于 WhitelistManager 没有直接暴露 storage，我们需要修改架构
	// 暂时返回空列表
	logs := []map[string]interface{}{}

	writeJSON(w, map[string]interface{}{
		"success": true,
		"logs":    logs,
		"limit":   limit,
	})
}


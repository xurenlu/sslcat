package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

// CDNStatsResponse CDN统计响应
type CDNStatsResponse struct {
	Enabled          bool        `json:"enabled"`
	CacheDir         string      `json:"cache_dir"`
	MaxSizeBytes     int64       `json:"max_size_bytes"`
	CurrentSizeBytes int64       `json:"current_size_bytes"`
	TotalObjects     int         `json:"total_objects"`
	HitRate          float64     `json:"hit_rate"`
	CacheRules       []CacheRule `json:"cache_rules"`
}

// CacheRule 缓存规则
type CacheRule struct {
	ID         string   `json:"id"`
	MatchType  string   `json:"match_type"`
	Pattern    string   `json:"pattern"`
	MediaTypes []string `json:"media_types"`
	TTLSeconds int      `json:"ttl_seconds"`
}

// CacheObjectsResponse 缓存对象响应
type CacheObjectsResponse struct {
	Objects []CacheObject `json:"objects"`
}

// CacheObject 缓存对象
type CacheObject struct {
	Key         string    `json:"key"`
	Path        string    `json:"path"`
	Host        string    `json:"host"`
	ContentType string    `json:"content_type"`
	SizeBytes   int64     `json:"size_bytes"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	LastAccess  time.Time `json:"last_access"`
	HitCount    int       `json:"hit_count"`
}

// handleAPICDNStats 处理CDN统计API
func (s *Server) handleAPICDNStats(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取代理管理器的CDN缓存实例
	var cache interface{}
	if s.proxyManager != nil {
		cache = s.proxyManager.GetCDNCache()
	}

	response := CDNStatsResponse{
		Enabled:          s.config.CDNCache.Enabled,
		CacheDir:         s.config.CDNCache.CacheDir,
		MaxSizeBytes:     s.config.CDNCache.MaxSizeBytes,
		CurrentSizeBytes: 0,
		TotalObjects:     0,
		HitRate:          0,
		CacheRules:       []CacheRule{},
	}

	// 如果有缓存实例，获取统计信息
	if cache != nil {
		if statsProvider, ok := cache.(interface{ Stats() map[string]interface{} }); ok {
			stats := statsProvider.Stats()
			if hits, ok := stats["hits"].(int64); ok {
				if misses, ok := stats["misses"].(int64); ok {
					total := hits + misses
					if total > 0 {
						response.HitRate = float64(hits) / float64(total) * 100
					}
				}
			}
			if size, ok := stats["size"].(int64); ok {
				response.CurrentSizeBytes = size
			}
			if objects, ok := stats["objects"].(int); ok {
				response.TotalObjects = objects
			}
		}
	}

	// 从配置中获取缓存规则
	for i, rule := range s.config.CDNCache.Rules {
		response.CacheRules = append(response.CacheRules, CacheRule{
			ID:         fmt.Sprintf("rule_%d", i),
			MatchType:  rule.MatchType,
			Pattern:    rule.Pattern,
			MediaTypes: rule.MediaTypes,
			TTLSeconds: rule.TTLSeconds,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleAPICDNObjects 处理CDN对象列表API
func (s *Server) handleAPICDNObjects(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := CacheObjectsResponse{
		Objects: []CacheObject{},
	}

	// TODO: 实现缓存对象列表获取
	// 这需要从CDNCache实例中获取缓存对象信息

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleAPICDNPurge 处理CDN缓存清理API
func (s *Server) handleAPICDNPurge(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 检查权限
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || (currentUser.Role != RoleSuperAdmin && currentUser.Role != RoleAdmin) {
		http.Error(w, "权限不足", http.StatusForbidden)
		return
	}

	pattern := r.URL.Query().Get("pattern")

	// 获取CDN缓存实例并清理
	var cache interface{}
	if s.proxyManager != nil {
		cache = s.proxyManager.GetCDNCache()
	}

	if cache != nil {
		if pattern == "" {
			// 清理全部缓存
			if purgeAll, ok := cache.(interface{ PurgeAll() error }); ok {
				if err := purgeAll.PurgeAll(); err != nil {
					s.log.Errorf("清理全部缓存失败: %v", err)
					http.Error(w, fmt.Sprintf("清理缓存失败: %v", err), http.StatusInternalServerError)
					return
				}
			}
		} else {
			// 按模式清理缓存
			if purgeByPattern, ok := cache.(interface {
				PurgeByCondition(string, string, string) error
			}); ok {
				if err := purgeByPattern.PurgeByCondition("prefix", pattern, ""); err != nil {
					s.log.Errorf("清理模式缓存失败: %v", err)
					http.Error(w, fmt.Sprintf("清理缓存失败: %v", err), http.StatusInternalServerError)
					return
				}
			}
		}
	}

	// 记录操作日志
	s.userManager.LogUserAction(
		currentUser.Username,
		"cdn_purge",
		"cache",
		fmt.Sprintf("清理CDN缓存: %s", pattern),
		s.getClientIP(r),
		r.Header.Get("User-Agent"),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "缓存清理成功"})
}

// handleAPICDNRules 处理CDN规则API
func (s *Server) handleAPICDNRules(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 检查权限
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || (currentUser.Role != RoleSuperAdmin && currentUser.Role != RoleAdmin) {
		http.Error(w, "权限不足", http.StatusForbidden)
		return
	}

	switch r.Method {
	case "POST":
		s.handleAPICDNRulesCreate(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAPICDNRulesCreate 创建CDN规则
func (s *Server) handleAPICDNRulesCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MatchType  string   `json:"match_type"`
		Pattern    string   `json:"pattern"`
		MediaTypes []string `json:"media_types"`
		TTLSeconds int      `json:"ttl_seconds"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 验证输入
	if req.TTLSeconds <= 0 {
		req.TTLSeconds = 3600 // 默认1小时
	}
	if req.MatchType == "" {
		req.MatchType = "prefix" // 默认前缀匹配
	}

	// 添加新规则到配置
	newRule := config.CDNCacheRule{
		MatchType:  req.MatchType,
		Pattern:    req.Pattern,
		MediaTypes: req.MediaTypes,
		TTLSeconds: req.TTLSeconds,
	}

	s.config.CDNCache.Rules = append(s.config.CDNCache.Rules, newRule)

	// 保存配置
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		s.log.Errorf("保存配置失败: %v", err)
		http.Error(w, "保存配置失败", http.StatusInternalServerError)
		return
	}
	s.syncProxyManagerConfig()

	// 记录操作日志
	currentUser := s.getCurrentUser(r)
	s.userManager.LogUserAction(
		currentUser.Username,
		"cdn_rule_create",
		"config",
		fmt.Sprintf("添加CDN规则: %s %s", req.MatchType, req.Pattern),
		s.getClientIP(r),
		r.Header.Get("User-Agent"),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "规则添加成功"})
}

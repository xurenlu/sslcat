package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/xurenlu/sslcat/internal/notification"
)

// 通用响应结构
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// 通用错误响应
func (s *Server) writeErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(APIResponse{
		Success: false,
		Error:   message,
	})
}

// 通用成功响应
func (s *Server) writeSuccessResponse(w http.ResponseWriter, data interface{}, message string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Message: message,
		Data:    data,
	})
}

// sendAdminPrefixChangeNotification 发送管理前缀变更通知
func (s *Server) sendAdminPrefixChangeNotification(oldPrefix, newPrefix string) {
	if s.notificationIntegrator == nil {
		return
	}

	notification := &notification.Notification{
		Type:    "admin_prefix_changed",
		Level:   notification.LevelInfo,
		Title:   "管理前缀已更改",
		Message: fmt.Sprintf("管理面板前缀已从 %s 更改为 %s。请使用新的URL访问管理面板。", oldPrefix, newPrefix),
		Details: map[string]any{
			"old_prefix": oldPrefix,
			"new_prefix": newPrefix,
		},
	}

	if err := s.notificationIntegrator.GetManager().Send(notification); err != nil {
		s.log.Errorf("发送前缀变更通知失败: %v", err)
	}
}

// handleAPISettings 获取系统设置
func (s *Server) handleAPISettings(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != "GET" {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// 返回非敏感的配置信息
	settings := map[string]interface{}{
		"admin_prefix":                 s.config.AdminPrefix,
		"admin_username":               s.config.Admin.Username,
		"ssl_email":                    s.config.SSL.Email,
		"ssl_disable_self_signed":      s.config.SSL.DisableSelfSigned,
		"proxy_unmatched_behavior":     s.config.Proxy.UnmatchedBehavior,
		"proxy_unmatched_redirect_url": s.config.Proxy.UnmatchedRedirectURL,
		"security": map[string]interface{}{
			"enable_captcha":    s.config.Security.EnableCaptcha,
			"enable_ddos":       s.config.Security.EnableDDOS,
			"enable_waf":        s.config.Security.EnableWAF,
			"enable_ua_filter":  s.config.Security.EnableUAFilter,
			"min_form_ms":       s.config.Security.MinFormMs,
			"max_attempts_5min": s.config.Security.MaxAttempts5Min,
			"max_attempts":      s.config.Security.MaxAttempts,
			"block_duration":    s.config.Security.BlockDurationStr,
		},
		"server": map[string]interface{}{
			"port":                     s.config.Server.Port,
			"access_log_enabled":       s.config.Server.AccessLogEnabled,
			"debug":                    s.config.Server.Debug,
			"log_level":                s.config.Server.LogLevel,
			"shared_cache_max_size_mb": s.config.Server.SharedCacheMaxSizeMB,
		},
		"ssl": map[string]interface{}{
			"email":               s.config.SSL.Email,
			"disable_self_signed": s.config.SSL.DisableSelfSigned,
			"auto_renew":          s.config.SSL.AutoRenew,
		},
		"monitoring": map[string]interface{}{
			"enabled":                     s.config.Monitoring.Enabled,
			"memory_max_usage_percent":    s.config.Monitoring.MemoryMaxUsagePercent,
			"memory_release_cooldown_sec": s.config.Monitoring.MemoryReleaseCooldownSec,
		},
		"totp_enabled": s.config.Admin.EnableTOTP,
		"webauthn_enabled": s.webauthnManager != nil, // WebAuthn 是否可用
		"server_info": map[string]interface{}{
			"version":    s.version,
			"build_time": time.Now().Format("2006-01-02 15:04:05"),
		},
	}

	s.writeSuccessResponse(w, settings, "Settings retrieved successfully")
}

// handleAPISettingsUpdate 更新系统设置
func (s *Server) handleAPISettingsUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != "PUT" && r.Method != "POST" {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		AdminPrefix               string `json:"admin_prefix,omitempty"`
		AdminUsername             string `json:"admin_username,omitempty"`
		SSLEmail                  string `json:"ssl_email,omitempty"`
		SSLDisableSelfSigned      *bool  `json:"ssl_disable_self_signed,omitempty"`
		ProxyUnmatchedBehavior    string `json:"proxy_unmatched_behavior,omitempty"`
		ProxyUnmatchedRedirectURL string `json:"proxy_unmatched_redirect_url,omitempty"`
		Security                  struct {
			EnableCaptcha  *bool `json:"enable_captcha,omitempty"`
			EnableDDOS     *bool `json:"enable_ddos,omitempty"`
			EnableWAF      *bool `json:"enable_waf,omitempty"`
			EnableUAFilter *bool `json:"enable_ua_filter,omitempty"`
			MinFormMs      *int  `json:"min_form_ms,omitempty"`
		} `json:"security,omitempty"`
		Server struct {
			SharedCacheMaxSizeMB *int `json:"shared_cache_max_size_mb,omitempty"`
		} `json:"server,omitempty"`
		Monitoring struct {
			MemoryMaxUsagePercent    *float64 `json:"memory_max_usage_percent,omitempty"`
			MemoryReleaseCooldownSec *int     `json:"memory_release_cooldown_sec,omitempty"`
		} `json:"monitoring,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON format")
		return
	}

	// 记录旧前缀用于路由重建
	oldPrefix := s.config.AdminPrefix
	sharedCacheChanged := false
	memoryOptionsChanged := false

	// 更新配置（只更新提供的字段）
	if req.AdminPrefix != "" {
		s.config.AdminPrefix = req.AdminPrefix
	}
	if req.AdminUsername != "" {
		s.config.Admin.Username = req.AdminUsername
	}
	if req.SSLEmail != "" {
		s.config.SSL.Email = req.SSLEmail
	}
	if req.SSLDisableSelfSigned != nil {
		s.config.SSL.DisableSelfSigned = *req.SSLDisableSelfSigned
	}
	if req.ProxyUnmatchedBehavior != "" {
		s.config.Proxy.UnmatchedBehavior = req.ProxyUnmatchedBehavior
	}
	if req.ProxyUnmatchedRedirectURL != "" {
		s.config.Proxy.UnmatchedRedirectURL = req.ProxyUnmatchedRedirectURL
	}

	// 安全设置
	if req.Security.EnableCaptcha != nil {
		s.config.Security.EnableCaptcha = *req.Security.EnableCaptcha
	}
	if req.Security.EnableDDOS != nil {
		s.config.Security.EnableDDOS = *req.Security.EnableDDOS
	}
	if req.Security.EnableWAF != nil {
		s.config.Security.EnableWAF = *req.Security.EnableWAF
	}
	if req.Security.EnableUAFilter != nil {
		s.config.Security.EnableUAFilter = *req.Security.EnableUAFilter
	}
	if req.Security.MinFormMs != nil && *req.Security.MinFormMs >= 0 && *req.Security.MinFormMs <= 10000 {
		s.config.Security.MinFormMs = *req.Security.MinFormMs
	}

	if req.Server.SharedCacheMaxSizeMB != nil {
		sizeMB := *req.Server.SharedCacheMaxSizeMB
		if sizeMB < 8 {
			sizeMB = 8
		}
		if sizeMB > 4096 {
			sizeMB = 4096
		}
		s.config.Server.SharedCacheMaxSizeMB = sizeMB
		sharedCacheChanged = true
	}

	if req.Monitoring.MemoryMaxUsagePercent != nil {
		value := *req.Monitoring.MemoryMaxUsagePercent
		if value < 5 {
			value = 5
		}
		if value > 90 {
			value = 90
		}
		s.config.Monitoring.MemoryMaxUsagePercent = value
		memoryOptionsChanged = true
	}

	if req.Monitoring.MemoryReleaseCooldownSec != nil {
		cooldown := *req.Monitoring.MemoryReleaseCooldownSec
		if cooldown < 60 {
			cooldown = 60
		}
		s.config.Monitoring.MemoryReleaseCooldownSec = cooldown
		memoryOptionsChanged = true
	}

	// 保存配置
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to save configuration")
		return
	}

	if sharedCacheChanged {
		s.updateSharedCache(s.config.Server.SharedCacheMaxSizeMB)
	}
	if memoryOptionsChanged {
		s.updateMemoryMonitor(s.config.Monitoring.MemoryMaxUsagePercent, s.config.Monitoring.MemoryReleaseCooldownSec)
	}

	// 如果管理前缀变化，重建路由并发送通知
	if oldPrefix != s.config.AdminPrefix {
		s.mux = http.NewServeMux()
		s.setupRoutes()

		// 发送前缀变更通知
		s.sendAdminPrefixChangeNotification(oldPrefix, s.config.AdminPrefix)
	}

	s.writeSuccessResponse(w, map[string]interface{}{
		"admin_prefix": s.config.AdminPrefix,
		"updated_at":   time.Now().Format("2006-01-02 15:04:05"),
	}, "Settings updated successfully")
}

// handleAPISettingsBasic 处理前端基础设置保存
func (s *Server) handleAPISettingsBasic(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != "POST" {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		AdminPrefix              string   `json:"adminPrefix,omitempty"`
		HTTPPort                 string   `json:"httpPort,omitempty"`
		HTTPSPort                string   `json:"httpsPort,omitempty"`
		AutoSSL                  *bool    `json:"autoSSL,omitempty"`
		LetsEncryptEmail         string   `json:"letsEncryptEmail,omitempty"`
		SSLProvider              string   `json:"sslProvider,omitempty"`
		SSLStaging               *bool    `json:"sslStaging,omitempty"`
		EnableDDoSProtection     *bool    `json:"enableDDoSProtection,omitempty"`
		MaxRequestsPerMinute     string   `json:"maxRequestsPerMinute,omitempty"`
		EnableRateLimit          *bool    `json:"enableRateLimit,omitempty"`
		EnableAccessLog          *bool    `json:"enableAccessLog,omitempty"`
		EnableErrorLog           *bool    `json:"enableErrorLog,omitempty"`
		LogLevel                 string   `json:"logLevel,omitempty"`
		SharedCacheMaxSizeMB     *int     `json:"sharedCacheMaxSizeMB,omitempty"`
		MemoryMaxUsagePercent    *float64 `json:"memoryMaxUsagePercent,omitempty"`
		MemoryReleaseCooldownSec *int     `json:"memoryReleaseCooldownSec,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON format: %s", err.Error()))
		return
	}

	// 记录旧前缀用于路由重建
	oldPrefix := s.config.AdminPrefix
	sharedCacheChanged := false
	memoryOptionsChanged := false

	// 更新配置（只更新提供的字段）
	if req.AdminPrefix != "" && req.AdminPrefix != oldPrefix {
		s.config.AdminPrefix = req.AdminPrefix
	}

	if req.HTTPSPort != "" {
		if port, err := strconv.Atoi(req.HTTPSPort); err == nil && port > 0 && port <= 65535 {
			s.config.Server.Port = port
		}
	}

	if req.LetsEncryptEmail != "" {
		s.config.SSL.Email = req.LetsEncryptEmail
	}

	if req.SSLStaging != nil {
		s.config.SSL.Staging = *req.SSLStaging
	}

	if req.EnableDDoSProtection != nil {
		s.config.Security.EnableDDOS = *req.EnableDDoSProtection
	}

	if req.MaxRequestsPerMinute != "" {
		if maxReq, err := strconv.Atoi(req.MaxRequestsPerMinute); err == nil && maxReq > 0 {
			s.config.Security.MaxAttempts5Min = maxReq
		}
	}

	if req.EnableRateLimit != nil {
		s.config.Security.EnableUAFilter = *req.EnableRateLimit
	}

	if req.EnableAccessLog != nil {
		s.config.Server.AccessLogEnabled = *req.EnableAccessLog
	}

	if req.LogLevel != "" {
		s.config.Server.LogLevel = req.LogLevel
	}

	if req.SharedCacheMaxSizeMB != nil {
		sizeMB := *req.SharedCacheMaxSizeMB
		if sizeMB < 8 {
			sizeMB = 8
		}
		if sizeMB > 4096 {
			sizeMB = 4096
		}
		s.config.Server.SharedCacheMaxSizeMB = sizeMB
		sharedCacheChanged = true
	}

	if req.MemoryMaxUsagePercent != nil {
		value := *req.MemoryMaxUsagePercent
		if value < 5 {
			value = 5
		}
		if value > 90 {
			value = 90
		}
		s.config.Monitoring.MemoryMaxUsagePercent = value
		memoryOptionsChanged = true
	}

	if req.MemoryReleaseCooldownSec != nil {
		cooldown := *req.MemoryReleaseCooldownSec
		if cooldown < 60 {
			cooldown = 60
		}
		s.config.Monitoring.MemoryReleaseCooldownSec = cooldown
		memoryOptionsChanged = true
	}

	if memoryOptionsChanged {
		s.updateMemoryMonitor(s.config.Monitoring.MemoryMaxUsagePercent, s.config.Monitoring.MemoryReleaseCooldownSec)
	}

	// 保存配置
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		s.log.Errorf("保存配置失败: %v", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to save configuration: %s", err.Error()))
		return
	}

	if sharedCacheChanged {
		s.updateSharedCache(s.config.Server.SharedCacheMaxSizeMB)
	}
	if memoryOptionsChanged {
		s.updateMemoryMonitor(s.config.Monitoring.MemoryMaxUsagePercent, s.config.Monitoring.MemoryReleaseCooldownSec)
	}

	// 如果管理前缀变化，重建路由并发送通知
	if oldPrefix != s.config.AdminPrefix {
		s.mux = http.NewServeMux()
		s.setupRoutes()
		s.log.Infof("管理前缀已从 %s 更改为 %s，路由已重建", oldPrefix, s.config.AdminPrefix)

		// 发送前缀变更通知
		s.sendAdminPrefixChangeNotification(oldPrefix, s.config.AdminPrefix)
	}

	s.writeSuccessResponse(w, map[string]interface{}{
		"adminPrefix": s.config.AdminPrefix,
		"httpsPort":   s.config.Server.Port,
		"updated_at":  time.Now().Format("2006-01-02 15:04:05"),
	}, "基础设置保存成功")
}

// handleAPISecurityUnblock 解除IP封禁
func (s *Server) handleAPISecurityUnblock(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != "POST" {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		IP string `json:"ip"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON format")
		return
	}

	if req.IP == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "IP address is required")
		return
	}

	// 解除封禁
	s.securityManager.UnblockIP(req.IP)

	s.writeSuccessResponse(w, map[string]interface{}{
		"ip":           req.IP,
		"unblocked_at": time.Now().Format("2006-01-02 15:04:05"),
	}, "IP address unblocked successfully")
}

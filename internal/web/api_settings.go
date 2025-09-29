package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/xurenlu/sslcat/internal/notification"
)

// handleAPISettings 获取系统设置
func (s *Server) handleAPISettings(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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
			"enable_captcha":   s.config.Security.EnableCaptcha,
			"enable_ddos":      s.config.Security.EnableDDOS,
			"enable_waf":       s.config.Security.EnableWAF,
			"enable_ua_filter": s.config.Security.EnableUAFilter,
			"min_form_ms":      s.config.Security.MinFormMs,
		},
		"totp_enabled": s.config.Admin.EnableTOTP,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

// handleAPISettingsUpdate 更新系统设置
func (s *Server) handleAPISettingsUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != "PUT" && r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	// 记录旧前缀用于路由重建
	oldPrefix := s.config.AdminPrefix

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

	// 保存配置
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to save config"})
		return
	}

	// 如果管理前缀变化，重建路由并发送通知
	if oldPrefix != s.config.AdminPrefix {
		s.mux = http.NewServeMux()
		s.setupRoutes()
		s.templateRenderer.ClearCache()
		
		// 发送前缀变更通知
		if s.notificationIntegrator != nil {
			notification := &notification.Notification{
				Type:    "admin_prefix_changed",
				Level:   notification.LevelInfo,
				Title:   "管理前缀已更改",
				Message: fmt.Sprintf("管理面板前缀已从 %s 更改为 %s。请使用新的URL访问管理面板。", oldPrefix, s.config.AdminPrefix),
				Details: map[string]any{
					"old_prefix": oldPrefix,
					"new_prefix": s.config.AdminPrefix,
				},
			}
			s.notificationIntegrator.GetManager().Send(notification)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "settings updated",
	})
}

// handleAPISettingsBasic 处理前端基础设置保存
func (s *Server) handleAPISettingsBasic(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AdminPrefix           string `json:"adminPrefix,omitempty"`
		HTTPPort              string `json:"httpPort,omitempty"`
		HTTPSPort             string `json:"httpsPort,omitempty"`
		AutoSSL               *bool  `json:"autoSSL,omitempty"`
		LetsEncryptEmail      string `json:"letsEncryptEmail,omitempty"`
		SSLProvider           string `json:"sslProvider,omitempty"`
		EnableDDoSProtection  *bool  `json:"enableDDoSProtection,omitempty"`
		MaxRequestsPerMinute  string `json:"maxRequestsPerMinute,omitempty"`
		EnableRateLimit       *bool  `json:"enableRateLimit,omitempty"`
		EnableAccessLog       *bool  `json:"enableAccessLog,omitempty"`
		EnableErrorLog        *bool  `json:"enableErrorLog,omitempty"`
		LogLevel              string `json:"logLevel,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON", "message": err.Error()})
		return
	}

	// 记录旧前缀用于路由重建
	oldPrefix := s.config.AdminPrefix

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

	// 保存配置
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		s.log.Errorf("保存配置失败: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to save config", "message": err.Error()})
		return
	}

	// 如果管理前缀变化，重建路由并发送通知
	if oldPrefix != s.config.AdminPrefix {
		s.mux = http.NewServeMux()
		s.setupRoutes()
		s.templateRenderer.ClearCache()
		s.log.Infof("管理前缀已从 %s 更改为 %s，路由已重建", oldPrefix, s.config.AdminPrefix)
		
		// 发送前缀变更通知
		if s.notificationIntegrator != nil {
			notification := &notification.Notification{
				Type:    "admin_prefix_changed",
				Level:   notification.LevelInfo,
				Title:   "管理前缀已更改",
				Message: fmt.Sprintf("管理面板前缀已从 %s 更改为 %s。请使用新的URL访问管理面板。", oldPrefix, s.config.AdminPrefix),
				Details: map[string]any{
					"old_prefix": oldPrefix,
					"new_prefix": s.config.AdminPrefix,
				},
			}
			s.notificationIntegrator.GetManager().Send(notification)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "基础设置保存成功",
		"data": map[string]interface{}{
			"adminPrefix": s.config.AdminPrefix,
			"httpsPort":   s.config.Server.Port,
		},
	})
}

// handleAPISecurityUnblock 解除IP封禁
func (s *Server) handleAPISecurityUnblock(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	if req.IP == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "ip is required"})
		return
	}

	// 解除封禁
	s.securityManager.UnblockIP(req.IP)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "IP unblocked",
		"ip":      req.IP,
	})
}

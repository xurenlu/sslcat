package web

import (
	"encoding/json"
	"net/http"
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
		"admin_prefix":    s.config.AdminPrefix,
		"admin_username":  s.config.Admin.Username,
		"ssl_email":       s.config.SSL.Email,
		"ssl_disable_self_signed": s.config.SSL.DisableSelfSigned,
		"proxy_unmatched_behavior": s.config.Proxy.UnmatchedBehavior,
		"proxy_unmatched_redirect_url": s.config.Proxy.UnmatchedRedirectURL,
		"security": map[string]interface{}{
			"enable_captcha":   s.config.Security.EnableCaptcha,
			"enable_pow":       s.config.Security.EnablePoW,
			"enable_ddos":      s.config.Security.EnableDDOS,
			"enable_waf":       s.config.Security.EnableWAF,
			"enable_ua_filter": s.config.Security.EnableUAFilter,
			"pow_bits":         s.config.Security.PoWBits,
			"min_form_ms":      s.config.Security.MinFormMs,
		},
		"cdn_cache": s.config.CDNCache,
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
		AdminPrefix    string `json:"admin_prefix,omitempty"`
		AdminUsername  string `json:"admin_username,omitempty"`
		SSLEmail       string `json:"ssl_email,omitempty"`
		SSLDisableSelfSigned *bool `json:"ssl_disable_self_signed,omitempty"`
		ProxyUnmatchedBehavior string `json:"proxy_unmatched_behavior,omitempty"`
		ProxyUnmatchedRedirectURL string `json:"proxy_unmatched_redirect_url,omitempty"`
		Security struct {
			EnableCaptcha   *bool `json:"enable_captcha,omitempty"`
			EnablePoW       *bool `json:"enable_pow,omitempty"`
			EnableDDOS      *bool `json:"enable_ddos,omitempty"`
			EnableWAF       *bool `json:"enable_waf,omitempty"`
			EnableUAFilter  *bool `json:"enable_ua_filter,omitempty"`
			PoWBits         *int  `json:"pow_bits,omitempty"`
			MinFormMs       *int  `json:"min_form_ms,omitempty"`
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
	if req.Security.EnablePoW != nil {
		s.config.Security.EnablePoW = *req.Security.EnablePoW
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
	if req.Security.PoWBits != nil && *req.Security.PoWBits >= 10 && *req.Security.PoWBits <= 30 {
		s.config.Security.PoWBits = *req.Security.PoWBits
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

	// 如果管理前缀变化，重建路由
	if oldPrefix != s.config.AdminPrefix {
		s.mux = http.NewServeMux()
		s.setupRoutes()
		s.templateRenderer.ClearCache()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "settings updated",
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

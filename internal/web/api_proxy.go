package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/xurenlu/sslcat/internal/config"
)

// parsePortFromTarget 从目标地址中解析端口号
func parsePortFromTarget(target string) int {
	// 解析URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		// 如果解析失败，返回0
		return 0
	}

	// 如果URL中有端口号，使用它
	if parsedURL.Port() != "" {
		if port, err := strconv.Atoi(parsedURL.Port()); err == nil {
			return port
		}
	}

	// 根据协议设置默认端口
	switch parsedURL.Scheme {
	case "http":
		return 80
	case "https":
		return 443
	default:
		return 0
	}
}

// handleAPIProxyRulesPost 添加或更新代理规则
func (s *Server) handleAPIProxyRulesPost(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain  string `json:"domain"`
		Target  string `json:"target"`
		Port    int    `json:"port"`
		Enabled bool   `json:"enabled"`
		SSLOnly bool   `json:"ssl_only"`
		// 类CDN设置
		CDNModeEnabled       bool   `json:"cdn_mode_enabled"`
		CDNEnabled           bool   `json:"cdn_enabled"`
		CDNPreset            string `json:"cdn_preset"`
		CDNDefaultTTLSeconds int    `json:"cdn_ttl_seconds"`
		// HTTP Host头部优化
		OptimizeHostHeader bool `json:"optimize_host_header"`

		// 访问控制字段
		AuthEnabled        bool                   `json:"auth_enabled"`
		AuthUsers          []config.ProxyAuthUser `json:"auth_users"`
		AuthSessionTimeout int                    `json:"auth_session_timeout"`
		AuthCookieDomain   string                 `json:"auth_cookie_domain"`

		// 代理超时配置
		ConnectTimeoutSec        int `json:"connect_timeout_sec"`
		KeepAliveTimeoutSec      int `json:"keep_alive_timeout_sec"`
		IdleTimeoutSec           int `json:"idle_timeout_sec"`
		TLSHandshakeTimeoutSec   int `json:"tls_handshake_timeout_sec"`
		ExpectContinueTimeoutSec int `json:"expect_continue_timeout_sec"`
		HealthCheckTimeoutSec    int `json:"health_check_timeout_sec"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Domain == "" || req.Target == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "domain and target are required"})
		return
	}

	// 验证访问控制配置
	if req.AuthEnabled {
		if len(req.AuthUsers) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "auth_users are required when auth is enabled"})
			return
		}

		// 验证用户名和密码不为空
		for i, user := range req.AuthUsers {
			if strings.TrimSpace(user.Username) == "" || strings.TrimSpace(user.Password) == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("username and password are required for user %d", i+1)})
				return
			}
		}

		// 设置默认会话超时时间
		if req.AuthSessionTimeout <= 0 {
			req.AuthSessionTimeout = 3600 // 默认1小时
		}

		// 设置默认cookie域名
		if req.AuthCookieDomain == "" {
			req.AuthCookieDomain = req.Domain
		}
	} else {
		// 未开启认证时，清空相关字段
		req.AuthUsers = nil
		req.AuthSessionTimeout = 0
		req.AuthCookieDomain = ""
	}

	// 检查是否已存在该域名
	existingIndex := -1
	for i, rule := range s.config.Proxy.Rules {
		if rule.Domain == req.Domain {
			existingIndex = i
			break
		}
	}

	// 自动解析端口号
	port := req.Port
	if port == 0 {
		port = parsePortFromTarget(req.Target)
	}

	newRule := config.ProxyRule{
		Domain:               req.Domain,
		Target:               req.Target,
		Port:                 port,
		Enabled:              req.Enabled,
		SSLOnly:              req.SSLOnly,
		CDNEnabled:           req.CDNEnabled,
		CDNPreset:            req.CDNPreset,
		CDNDefaultTTLSeconds: req.CDNDefaultTTLSeconds,
		// HTTP Host头部优化
		OptimizeHostHeader: req.OptimizeHostHeader,

		// 访问控制字段
		AuthEnabled:        req.AuthEnabled,
		AuthUsers:          req.AuthUsers,
		AuthSessionTimeout: req.AuthSessionTimeout,
		AuthCookieDomain:   req.AuthCookieDomain,

		// 代理超时配置
		ConnectTimeoutSec:        req.ConnectTimeoutSec,
		KeepAliveTimeoutSec:      req.KeepAliveTimeoutSec,
		IdleTimeoutSec:           req.IdleTimeoutSec,
		TLSHandshakeTimeoutSec:   req.TLSHandshakeTimeoutSec,
		ExpectContinueTimeoutSec: req.ExpectContinueTimeoutSec,
		HealthCheckTimeoutSec:    req.HealthCheckTimeoutSec,
	}

	if existingIndex >= 0 {
		// 更新现有规则
		s.config.Proxy.Rules[existingIndex] = newRule
	} else {
		// 添加新规则
		s.config.Proxy.Rules = append(s.config.Proxy.Rules, newRule)
	}

	// 保存配置
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		s.log.Errorf("Failed to save config: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to save config: " + err.Error()})
		return
	}

	// 记录配置保存成功
	s.log.Infof("Proxy rule saved successfully: %s -> %s:%d", req.Domain, req.Target, req.Port)

	// 尝试预取证书
	if s.sslManager != nil {
		if err := s.sslManager.EnsureDomainCert(req.Domain); err != nil {
			s.log.Warnf("Failed to prefetch certificate %s: %v", req.Domain, err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"rule":    newRule,
		"action":  map[bool]string{true: "updated", false: "created"}[existingIndex >= 0],
	})
}

// handleAPIProxyRulesDelete 删除代理规则
func (s *Server) handleAPIProxyRulesDelete(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	indexStr := strings.TrimSpace(r.URL.Query().Get("index"))

	var targetIndex = -1

	// 支持按域名或索引删除
	if domain != "" {
		for i, rule := range s.config.Proxy.Rules {
			if rule.Domain == domain {
				targetIndex = i
				break
			}
		}
	} else if indexStr != "" {
		if index, err := strconv.Atoi(indexStr); err == nil && index >= 0 && index < len(s.config.Proxy.Rules) {
			targetIndex = index
		}
	}

	if targetIndex < 0 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "rule not found"})
		return
	}

	// 删除规则
	deletedRule := s.config.Proxy.Rules[targetIndex]
	s.config.Proxy.Rules = append(s.config.Proxy.Rules[:targetIndex], s.config.Proxy.Rules[targetIndex+1:]...)

	// 保存配置
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		s.log.Errorf("Failed to save config after deletion: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to save config: " + err.Error()})
		return
	}

	// 记录配置删除成功
	s.log.Infof("Proxy rule deleted successfully: %s -> %s:%d", deletedRule.Domain, deletedRule.Target, deletedRule.Port)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"deleted_rule": deletedRule,
	})
}

// handleAPIProxyRule 单个代理规则的CRUD操作
func (s *Server) handleAPIProxyRule(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	domain := strings.TrimSpace(r.URL.Query().Get("domain"))

	switch r.Method {
	case "GET":
		// 获取单个代理规则
		if domain == "" {
			http.Error(w, "domain parameter is required", http.StatusBadRequest)
			return
		}

		for _, rule := range s.config.Proxy.Rules {
			if rule.Domain == domain {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": true,
					"data":    rule,
				})
				return
			}
		}

		http.Error(w, "rule not found", http.StatusNotFound)
		return

	case "POST":
		// 创建新的代理规则
		var req struct {
			Domain  string `json:"domain"`
			Target  string `json:"target"`
			Port    int    `json:"port"`
			Enabled bool   `json:"enabled"`
			SSLOnly bool   `json:"ssl_only"`
			// 类CDN设置
			CDNModeEnabled       bool   `json:"cdn_mode_enabled"`
			CDNEnabled           bool   `json:"cdn_enabled"`
			CDNPreset            string `json:"cdn_preset"`
			CDNDefaultTTLSeconds int    `json:"cdn_ttl_seconds"`
			// HTTP Host头部优化
			OptimizeHostHeader bool `json:"optimize_host_header"`
			// 代理超时配置
			ConnectTimeoutSec        int `json:"connect_timeout_sec"`
			KeepAliveTimeoutSec      int `json:"keep_alive_timeout_sec"`
			IdleTimeoutSec           int `json:"idle_timeout_sec"`
			TLSHandshakeTimeoutSec   int `json:"tls_handshake_timeout_sec"`
			ExpectContinueTimeoutSec int `json:"expect_continue_timeout_sec"`
			HealthCheckTimeoutSec    int `json:"health_check_timeout_sec"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		if req.Domain == "" || req.Target == "" {
			http.Error(w, "domain and target are required", http.StatusBadRequest)
			return
		}

		// 检查是否已存在
		for _, rule := range s.config.Proxy.Rules {
			if rule.Domain == req.Domain {
				http.Error(w, "rule already exists", http.StatusConflict)
				return
			}
		}

		// 自动解析端口号
		port := req.Port
		if port == 0 {
			port = parsePortFromTarget(req.Target)
		}

		newRule := config.ProxyRule{
			Domain:               req.Domain,
			Target:               req.Target,
			Port:                 port,
			Enabled:              req.Enabled,
			SSLOnly:              req.SSLOnly,
			CDNEnabled:           req.CDNEnabled,
			CDNPreset:            req.CDNPreset,
			CDNDefaultTTLSeconds: req.CDNDefaultTTLSeconds,
			// HTTP Host头部优化
			OptimizeHostHeader: req.OptimizeHostHeader,
			// 代理超时配置
			ConnectTimeoutSec:        req.ConnectTimeoutSec,
			KeepAliveTimeoutSec:      req.KeepAliveTimeoutSec,
			IdleTimeoutSec:           req.IdleTimeoutSec,
			TLSHandshakeTimeoutSec:   req.TLSHandshakeTimeoutSec,
			ExpectContinueTimeoutSec: req.ExpectContinueTimeoutSec,
			HealthCheckTimeoutSec:    req.HealthCheckTimeoutSec,
		}

		s.config.Proxy.Rules = append(s.config.Proxy.Rules, newRule)

		// 保存配置
		if err := s.config.Save(s.config.ConfigFile); err != nil {
			s.log.Errorf("Failed to save config: %v", err)
			http.Error(w, "failed to save config", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"rule":    newRule,
		})

	case "PUT":
		// 更新代理规则
		var req struct {
			Domain  string `json:"domain"`
			Target  string `json:"target"`
			Port    int    `json:"port"`
			Enabled bool   `json:"enabled"`
			SSLOnly bool   `json:"ssl_only"`
			// 类CDN设置
			CDNModeEnabled       bool   `json:"cdn_mode_enabled"`
			CDNEnabled           bool   `json:"cdn_enabled"`
			CDNPreset            string `json:"cdn_preset"`
			CDNDefaultTTLSeconds int    `json:"cdn_ttl_seconds"`
			// HTTP Host头部优化
			OptimizeHostHeader bool `json:"optimize_host_header"`

			// 访问控制字段
			AuthEnabled        bool                   `json:"auth_enabled"`
			AuthUsers          []config.ProxyAuthUser `json:"auth_users"`
			AuthSessionTimeout int                    `json:"auth_session_timeout"`
			AuthCookieDomain   string                 `json:"auth_cookie_domain"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		if req.Domain == "" || req.Target == "" {
			http.Error(w, "domain and target are required", http.StatusBadRequest)
			return
		}

		// 查找并更新规则
		for i, rule := range s.config.Proxy.Rules {
			if rule.Domain == domain {
				// 自动解析端口号
				port := req.Port
				if port == 0 {
					port = parsePortFromTarget(req.Target)
				}

				s.config.Proxy.Rules[i].Target = req.Target
				s.config.Proxy.Rules[i].Port = port
				s.config.Proxy.Rules[i].Enabled = req.Enabled
				s.config.Proxy.Rules[i].SSLOnly = req.SSLOnly
				s.config.Proxy.Rules[i].CDNEnabled = req.CDNEnabled
				s.config.Proxy.Rules[i].CDNPreset = req.CDNPreset
				s.config.Proxy.Rules[i].CDNDefaultTTLSeconds = req.CDNDefaultTTLSeconds
				// HTTP Host头部优化
				s.config.Proxy.Rules[i].OptimizeHostHeader = req.OptimizeHostHeader

				// 访问控制字段
				s.config.Proxy.Rules[i].AuthEnabled = req.AuthEnabled
				s.config.Proxy.Rules[i].AuthUsers = req.AuthUsers
				s.config.Proxy.Rules[i].AuthSessionTimeout = req.AuthSessionTimeout
				s.config.Proxy.Rules[i].AuthCookieDomain = req.AuthCookieDomain

				// 保存配置
				if err := s.config.Save(s.config.ConfigFile); err != nil {
					s.log.Errorf("Failed to save config: %v", err)
					http.Error(w, "failed to save config", http.StatusInternalServerError)
					return
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": true,
					"rule":    s.config.Proxy.Rules[i],
				})
				return
			}
		}

		http.Error(w, "rule not found", http.StatusNotFound)

	case "DELETE":
		// 删除代理规则
		if domain == "" {
			http.Error(w, "domain parameter is required", http.StatusBadRequest)
			return
		}

		for i, rule := range s.config.Proxy.Rules {
			if rule.Domain == domain {
				deletedRule := s.config.Proxy.Rules[i]
				s.config.Proxy.Rules = append(s.config.Proxy.Rules[:i], s.config.Proxy.Rules[i+1:]...)

				// 保存配置
				if err := s.config.Save(s.config.ConfigFile); err != nil {
					s.log.Errorf("Failed to save config: %v", err)
					http.Error(w, "failed to save config", http.StatusInternalServerError)
					return
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success":      true,
					"deleted_rule": deletedRule,
				})
				return
			}
		}

		http.Error(w, "rule not found", http.StatusNotFound)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

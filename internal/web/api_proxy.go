package web

import (
	"encoding/json"
	"fmt"
	"net"
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

// isHTTPSURL 检查后端主机是否为HTTPS URL（非IP地址）
func isHTTPSURL(host string) bool {
	// 检查是否以 https:// 开头
	if !strings.HasPrefix(strings.ToLower(host), "https://") {
		return false
	}

	// 解析URL
	parsedURL, err := url.Parse(host)
	if err != nil {
		return false
	}

	// 提取主机名（去除端口）
	hostname := parsedURL.Hostname()
	if hostname == "" {
		return false
	}

	// 检查主机名是否为IP地址
	return net.ParseIP(hostname) == nil
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
		ConnectTimeoutSec        int               `json:"connect_timeout_sec"`
		KeepAliveTimeoutSec      int               `json:"keep_alive_timeout_sec"`
		IdleTimeoutSec           int               `json:"idle_timeout_sec"`
		TLSHandshakeTimeoutSec   int               `json:"tls_handshake_timeout_sec"`
		ExpectContinueTimeoutSec int               `json:"expect_continue_timeout_sec"`
		HealthCheckTimeoutSec    int               `json:"health_check_timeout_sec"`
		UpstreamRequestHeaders   map[string]string `json:"upstream_request_headers"`
		ResponseHeaders          map[string]string `json:"response_headers"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	req.UpstreamRequestHeaders = sanitizeHeaderMap(req.UpstreamRequestHeaders)
	req.ResponseHeaders = sanitizeHeaderMap(req.ResponseHeaders)

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
	// 如果target是完整URL，从URL中提取端口，忽略req.Port字段
	port := req.Port
	if strings.HasPrefix(strings.ToLower(req.Target), "http://") || strings.HasPrefix(strings.ToLower(req.Target), "https://") {
		// 完整URL，从URL中提取端口
		port = parsePortFromTarget(req.Target)
	} else if port == 0 {
		// 非完整URL且端口为0，尝试从target解析
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
		UpstreamRequestHeaders:   sanitizeHeaderMap(req.UpstreamRequestHeaders),
		ResponseHeaders:          sanitizeHeaderMap(req.ResponseHeaders),
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

	// 异步尝试预取证书，避免阻塞 API 响应
	if s.sslManager != nil {
		go func(domain string) {
			if err := s.sslManager.EnsureDomainCert(domain); err != nil {
				s.log.Warnf("Failed to prefetch certificate %s: %v", domain, err)
			}
		}(req.Domain)
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
		// 获取单个代理规则；detail=1 时同时返回负载均衡与健康检查统计（多上游场景）
		if domain == "" {
			http.Error(w, "domain parameter is required", http.StatusBadRequest)
			return
		}

		withDetail := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("detail"))) == "1" ||
			strings.TrimSpace(strings.ToLower(r.URL.Query().Get("detail"))) == "true"

		for _, rule := range s.config.Proxy.Rules {
			if rule.Domain == domain {
				resp := map[string]interface{}{
					"success": true,
					"data":    rule,
				}
				if withDetail && s.proxyManager != nil {
					if lbStats := s.proxyManager.GetLoadBalancerStats(domain); lbStats != nil {
						resp["load_balancer_stats"] = lbStats
					}
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(resp)
				return
			}
		}

		http.Error(w, "rule not found", http.StatusNotFound)
		return

	case "POST":
		// 创建新的代理规则
		var req struct {
			Domain  string `json:"domain"`
			Target  string `json:"target"` // 兼容旧字段
			Port    int    `json:"port"`   // 兼容旧字段
			Enabled bool   `json:"enabled"`
			SSLOnly bool   `json:"ssl_only"`

			// 统一后端配置
			Backends []config.ProxyBackend `json:"backends"`

			// 类CDN设置
			CDNModeEnabled       bool   `json:"cdn_mode_enabled"`
			CDNEnabled           bool   `json:"cdn_enabled"`
			CDNPreset            string `json:"cdn_preset"`
			CDNDefaultTTLSeconds int    `json:"cdn_ttl_seconds"`
			// HTTP Host头部优化
			OptimizeHostHeader bool `json:"optimize_host_header"`
			// 代理超时配置 / 自定义头
			ConnectTimeoutSec        int               `json:"connect_timeout_sec"`
			KeepAliveTimeoutSec      int               `json:"keep_alive_timeout_sec"`
			IdleTimeoutSec           int               `json:"idle_timeout_sec"`
			TLSHandshakeTimeoutSec   int               `json:"tls_handshake_timeout_sec"`
			ExpectContinueTimeoutSec int               `json:"expect_continue_timeout_sec"`
			HealthCheckTimeoutSec    int               `json:"health_check_timeout_sec"`
			UpstreamRequestHeaders   map[string]string `json:"upstream_request_headers"`
			ResponseHeaders          map[string]string `json:"response_headers"`

			// 访问日志覆盖
			AccessLogEnabled *bool  `json:"access_log_enabled,omitempty"`
			AccessLogPath    string `json:"access_log_path,omitempty"`

			// HTTP/2 覆盖
			HTTP2Enabled *bool `json:"http2_enabled,omitempty"`
			// HTTP/3 覆盖
			HTTP3Enabled *bool `json:"http3_enabled,omitempty"`
			// 上游调试 header（多后端时）
			UpstreamDebugHeaders bool `json:"upstream_debug_headers"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		if req.Domain == "" {
			http.Error(w, "domain is required", http.StatusBadRequest)
			return
		}

		// 验证后端配置
		if len(req.Backends) == 0 {
			http.Error(w, "at least one backend is required", http.StatusBadRequest)
			return
		}

		// 验证后端配置的有效性
		hasHTTPSURLBackend := false
		for i, backend := range req.Backends {
			if backend.Host == "" {
				http.Error(w, fmt.Sprintf("backend %d: host is required", i), http.StatusBadRequest)
				return
			}
			// 检查是否为HTTPS URL后端（非IP地址）
			if isHTTPSURL(backend.Host) {
				hasHTTPSURLBackend = true
			}
			// 对于HTTPS URL后端，端口验证可以放宽（因为端口在URL中）
			if !isHTTPSURL(backend.Host) {
				if backend.Port <= 0 || backend.Port > 65535 {
					http.Error(w, fmt.Sprintf("backend %d: invalid port: %d", i, backend.Port), http.StatusBadRequest)
					return
				}
			}
		}

		// 如果存在HTTPS URL后端，限制只能配置一个后端
		if hasHTTPSURLBackend && len(req.Backends) > 1 {
			http.Error(w, "HTTPS URL后端仅支持单后端配置，不支持负载均衡", http.StatusBadRequest)
			return
		}

		// 检查是否已存在
		for _, rule := range s.config.Proxy.Rules {
			if rule.Domain == req.Domain {
				http.Error(w, "rule already exists", http.StatusConflict)
				return
			}
		}

		// 创建新规则
		newRule := config.ProxyRule{
			Domain:  req.Domain,
			Enabled: req.Enabled,
			SSLOnly: req.SSLOnly,

			// 统一后端配置
			Backends: req.Backends,

			// 为了向后兼容，同步到旧字段
			Target: req.Backends[0].Host,
			Port:   req.Backends[0].Port,

			// 类CDN设置
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
			UpstreamRequestHeaders:   req.UpstreamRequestHeaders,
			ResponseHeaders:          req.ResponseHeaders,

			AccessLogEnabled: req.AccessLogEnabled,
			AccessLogPath:    req.AccessLogPath,

			HTTP2Enabled: req.HTTP2Enabled,
			HTTP3Enabled: req.HTTP3Enabled,

			UpstreamDebugHeaders: req.UpstreamDebugHeaders,
		}

		s.config.Proxy.Rules = append(s.config.Proxy.Rules, newRule)

		// 保存配置
		if err := s.config.Save(s.config.ConfigFile); err != nil {
			s.log.Errorf("Failed to save config: %v", err)
			http.Error(w, "failed to save config", http.StatusInternalServerError)
			return
		}

		// 立即重载代理配置
		if err := s.proxyManager.Reload(s.config); err != nil {
			s.log.Warnf("Proxy reload after config save: %v", err)
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
			Target  string `json:"target"` // 兼容旧字段
			Port    int    `json:"port"`   // 兼容旧字段
			Enabled bool   `json:"enabled"`
			SSLOnly bool   `json:"ssl_only"`

			// 统一后端配置
			Backends []config.ProxyBackend `json:"backends"`

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
			ConnectTimeoutSec        int               `json:"connect_timeout_sec"`
			KeepAliveTimeoutSec      int               `json:"keep_alive_timeout_sec"`
			IdleTimeoutSec           int               `json:"idle_timeout_sec"`
			TLSHandshakeTimeoutSec   int               `json:"tls_handshake_timeout_sec"`
			ExpectContinueTimeoutSec int               `json:"expect_continue_timeout_sec"`
			HealthCheckTimeoutSec    int               `json:"health_check_timeout_sec"`
			UpstreamRequestHeaders   map[string]string `json:"upstream_request_headers"`
			ResponseHeaders          map[string]string `json:"response_headers"`

			// 访问日志覆盖
			AccessLogEnabled *bool  `json:"access_log_enabled,omitempty"`
			AccessLogPath    string `json:"access_log_path,omitempty"`

			// HTTP/2 覆盖
			HTTP2Enabled *bool `json:"http2_enabled,omitempty"`
			// HTTP/3 覆盖
			HTTP3Enabled *bool `json:"http3_enabled,omitempty"`
			// 上游调试 header（多后端时）
			UpstreamDebugHeaders bool `json:"upstream_debug_headers"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		req.UpstreamRequestHeaders = sanitizeHeaderMap(req.UpstreamRequestHeaders)
		req.ResponseHeaders = sanitizeHeaderMap(req.ResponseHeaders)

		if req.Domain == "" {
			http.Error(w, "domain is required", http.StatusBadRequest)
			return
		}

		// 验证后端配置（仅在提供后端配置时验证）
		if len(req.Backends) > 0 {
			// 验证后端配置的有效性
			for i, backend := range req.Backends {
				if backend.Host == "" {
					http.Error(w, fmt.Sprintf("backend %d: host is required", i), http.StatusBadRequest)
					return
				}
				if backend.Port <= 0 || backend.Port > 65535 {
					http.Error(w, fmt.Sprintf("backend %d: invalid port: %d", i, backend.Port), http.StatusBadRequest)
					return
				}
			}
		}

		// 查找并更新规则
		for i, rule := range s.config.Proxy.Rules {
			if rule.Domain == domain {
				// 更新基本字段（始终更新）
				s.config.Proxy.Rules[i].Enabled = req.Enabled
				s.config.Proxy.Rules[i].SSLOnly = req.SSLOnly

				// 更新统一后端配置（仅在提供时更新）
				if len(req.Backends) > 0 {
					s.config.Proxy.Rules[i].Backends = req.Backends
					// 为了向后兼容，同步到旧字段
					s.config.Proxy.Rules[i].Target = req.Backends[0].Host
					s.config.Proxy.Rules[i].Port = req.Backends[0].Port
				}

				// 类CDN设置（仅在提供时更新）
				if req.CDNEnabled || req.CDNPreset != "" || req.CDNDefaultTTLSeconds > 0 {
					s.config.Proxy.Rules[i].CDNEnabled = req.CDNEnabled
					s.config.Proxy.Rules[i].CDNPreset = req.CDNPreset
					s.config.Proxy.Rules[i].CDNDefaultTTLSeconds = req.CDNDefaultTTLSeconds
				}
				// HTTP Host头部优化
				s.config.Proxy.Rules[i].OptimizeHostHeader = req.OptimizeHostHeader

				// 访问控制字段（始终更新，包括禁用访问控制的情况）
				// 检查是否从启用变为禁用，需要清理 session
				wasAuthEnabled := s.config.Proxy.Rules[i].AuthEnabled
				s.config.Proxy.Rules[i].AuthEnabled = req.AuthEnabled

				if req.AuthEnabled {
					// 启用访问控制时保存用户配置
					s.config.Proxy.Rules[i].AuthUsers = req.AuthUsers
					s.config.Proxy.Rules[i].AuthSessionTimeout = req.AuthSessionTimeout
					if req.AuthCookieDomain != "" {
						s.config.Proxy.Rules[i].AuthCookieDomain = req.AuthCookieDomain
					} else {
						s.config.Proxy.Rules[i].AuthCookieDomain = domain
					}
				} else {
					// 禁用访问控制时清空相关字段
					s.config.Proxy.Rules[i].AuthUsers = nil
					s.config.Proxy.Rules[i].AuthSessionTimeout = 0
					s.config.Proxy.Rules[i].AuthCookieDomain = ""

					// 如果之前是启用状态，清除该域名的所有会话
					if wasAuthEnabled && s.proxyAuthManager != nil {
						s.proxyAuthManager.ClearDomainSessions(domain)
					}
				}

				// 代理超时配置
				s.config.Proxy.Rules[i].ConnectTimeoutSec = req.ConnectTimeoutSec
				s.config.Proxy.Rules[i].KeepAliveTimeoutSec = req.KeepAliveTimeoutSec
				s.config.Proxy.Rules[i].IdleTimeoutSec = req.IdleTimeoutSec
				s.config.Proxy.Rules[i].TLSHandshakeTimeoutSec = req.TLSHandshakeTimeoutSec
				s.config.Proxy.Rules[i].ExpectContinueTimeoutSec = req.ExpectContinueTimeoutSec
				s.config.Proxy.Rules[i].HealthCheckTimeoutSec = req.HealthCheckTimeoutSec
				s.config.Proxy.Rules[i].UpstreamRequestHeaders = req.UpstreamRequestHeaders
				s.config.Proxy.Rules[i].ResponseHeaders = req.ResponseHeaders

				// 访问日志覆盖
				if req.AccessLogEnabled != nil {
					s.config.Proxy.Rules[i].AccessLogEnabled = req.AccessLogEnabled
				}
				s.config.Proxy.Rules[i].AccessLogPath = req.AccessLogPath

				// HTTP/2 覆盖
				if req.HTTP2Enabled != nil {
					s.config.Proxy.Rules[i].HTTP2Enabled = req.HTTP2Enabled
				}
				// HTTP/3 覆盖
				if req.HTTP3Enabled != nil {
					s.config.Proxy.Rules[i].HTTP3Enabled = req.HTTP3Enabled
				}

				s.config.Proxy.Rules[i].UpstreamDebugHeaders = req.UpstreamDebugHeaders

				// 保存配置
				if err := s.config.Save(s.config.ConfigFile); err != nil {
					s.log.Errorf("Failed to save config: %v", err)
					http.Error(w, "failed to save config", http.StatusInternalServerError)
					return
				}

				// 立即重载代理配置，使负载均衡器等使用新端口/后端配置
				if err := s.proxyManager.Reload(s.config); err != nil {
					s.log.Warnf("Proxy reload after config save: %v", err)
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

				// 立即重载代理配置
				if err := s.proxyManager.Reload(s.config); err != nil {
					s.log.Warnf("Proxy reload after config save: %v", err)
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

// handleAPIProxyRulesRename 重命名代理规则域名
func (s *Server) handleAPIProxyRulesRename(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) {
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		OldDomain string `json:"old_domain"`
		NewDomain string `json:"new_domain"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	if req.OldDomain == "" || req.NewDomain == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "old_domain and new_domain are required"})
		return
	}

	if req.OldDomain == req.NewDomain {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "old_domain and new_domain cannot be the same"})
		return
	}

	// 检查新域名是否已存在
	for _, rule := range s.config.Proxy.Rules {
		if rule.Domain == req.NewDomain {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "new domain already exists"})
			return
		}
	}

	// 查找旧域名规则
	targetIndex := -1
	for i, rule := range s.config.Proxy.Rules {
		if rule.Domain == req.OldDomain {
			targetIndex = i
			break
		}
	}

	if targetIndex < 0 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "rule not found"})
		return
	}

	// 更新域名
	s.config.Proxy.Rules[targetIndex].Domain = req.NewDomain

	if err := s.config.Save(s.config.ConfigFile); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to save config"})
		return
	}

	s.log.Infof("Renamed proxy rule from %s to %s", req.OldDomain, req.NewDomain)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"rule":    s.config.Proxy.Rules[targetIndex],
	})
}

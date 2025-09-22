package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/xurenlu/sslcat/internal/config"
)

// 代理管理

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 获取所有代理规则
	rules := s.config.Proxy.Rules

	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"Rules":       rules,
	}

	// 这里需要创建代理管理模板
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateProxyManagementHTML(data)
	w.Write([]byte(html))
}

func (s *Server) handleProxyAdd(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method == "POST" {
		// 处理添加代理规则
		domain := r.FormValue("domain")
		target := r.FormValue("target")

		if domain != "" && target != "" {
			// 添加新规则到配置
			enabled := r.FormValue("enabled") == "on"
			sslOnly := r.FormValue("ssl_only") == "on"
			optimizeHostHeader := r.FormValue("optimize_host_header") == "on"
			cdnEnabled := r.FormValue("cdn_enabled") == "on"
			cdnPreset := r.FormValue("cdn_preset")
			cdnTTL := 0
			if v := strings.TrimSpace(r.FormValue("cdn_ttl_seconds")); v != "" {
				if n, err := strconv.Atoi(v); err == nil && n >= 0 {
					cdnTTL = n
				}
			}

			// 处理云存储配置字段
			cloudStorageType := r.FormValue("cloud_storage_type")
			cloudStorageRegion := r.FormValue("cloud_storage_region")
			cloudStorageBucket := r.FormValue("cloud_storage_bucket")
			cloudStorageEndpoint := r.FormValue("cloud_storage_endpoint")
			cloudStoragePath := r.FormValue("cloud_storage_path")
			cloudStorageAccessKey := r.FormValue("cloud_storage_access_key")
			cloudStorageSecretKey := r.FormValue("cloud_storage_secret_key")

			// 处理访问控制字段
			authEnabled := r.FormValue("auth_enabled") == "on"
			var authUsers []config.ProxyAuthUser
			var authSessionTimeout int = 3600
			var authCookieDomain string = domain

			if authEnabled {
				// 解析用户列表
				form := r.Form
				for key := range form {
					if strings.HasPrefix(key, "auth_users[") && strings.HasSuffix(key, "][username]") {
						// 提取索引
						indexStart := strings.Index(key, "[") + 1
						indexEnd := strings.Index(key, "]")
						if indexStart > 0 && indexEnd > indexStart {
							userIndex := key[indexStart:indexEnd]
							usernameKey := "auth_users[" + userIndex + "][username]"
							passwordKey := "auth_users[" + userIndex + "][password]"

							username := strings.TrimSpace(r.FormValue(usernameKey))
							password := strings.TrimSpace(r.FormValue(passwordKey))

							if username != "" && password != "" {
								authUsers = append(authUsers, config.ProxyAuthUser{
									Username: username,
									Password: password,
								})
							}
						}
					}
				}

				// 会话超时时间
				if v := strings.TrimSpace(r.FormValue("auth_session_timeout")); v != "" {
					if n, err := strconv.Atoi(v); err == nil && n >= 300 {
						authSessionTimeout = n
					}
				}

				// Cookie域名
				if v := strings.TrimSpace(r.FormValue("auth_cookie_domain")); v != "" {
					authCookieDomain = v
				}
			}

			newRule := config.ProxyRule{
				Domain:               domain,
				Target:               target,
				Enabled:              enabled,
				SSLOnly:              sslOnly,
				OptimizeHostHeader:   optimizeHostHeader,
				CDNEnabled:           cdnEnabled,
				CDNPreset:            cdnPreset,
				CDNDefaultTTLSeconds: cdnTTL,
				// 云存储配置字段
				CloudStorageType:      cloudStorageType,
				CloudStorageRegion:    cloudStorageRegion,
				CloudStorageBucket:    cloudStorageBucket,
				CloudStorageEndpoint:  cloudStorageEndpoint,
				CloudStoragePath:      cloudStoragePath,
				CloudStorageAccessKey: cloudStorageAccessKey,
				CloudStorageSecretKey: cloudStorageSecretKey,
				// 访问控制字段
				AuthEnabled:        authEnabled,
				AuthUsers:          authUsers,
				AuthSessionTimeout: authSessionTimeout,
				AuthCookieDomain:   authCookieDomain,
			}
			s.config.Proxy.Rules = append(s.config.Proxy.Rules, newRule)

			// 保存配置
			s.config.Save(s.config.ConfigFile)

			// 尝试为该域名预取/申请证书（若启用 ACME）
			if s.sslManager != nil {
				if err := s.sslManager.EnsureDomainCert(domain); err != nil {
					s.log.Warnf("Failed to prefetch certificate %s: %v", domain, err)
				}
			}

			// 重定向回代理管理页面
			http.Redirect(w, r, s.config.AdminPrefix+"/proxy", http.StatusFound)
			return
		}
	}

	// 显示添加表单
	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateProxyAddHTML(data)
	w.Write([]byte(html))
}

func (s *Server) handleProxyEdit(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	indexStr := r.URL.Query().Get("index")
	index, err := strconv.Atoi(indexStr)
	if err != nil || index < 0 || index >= len(s.config.Proxy.Rules) {
		http.Error(w, "invalid rule index", http.StatusBadRequest)
		return
	}

	if r.Method == "POST" {
		// 处理编辑代理规则
		domain := r.FormValue("domain")
		target := r.FormValue("target")
		enabled := r.FormValue("enabled") == "on"
		sslOnly := r.FormValue("ssl_only") == "on"
		optimizeHostHeader := r.FormValue("optimize_host_header") == "on"

		if domain != "" && target != "" {
			s.config.Proxy.Rules[index].Domain = domain
			s.config.Proxy.Rules[index].Target = target
			s.config.Proxy.Rules[index].Enabled = enabled
			s.config.Proxy.Rules[index].SSLOnly = sslOnly
			s.config.Proxy.Rules[index].OptimizeHostHeader = optimizeHostHeader
			s.config.Proxy.Rules[index].CDNEnabled = r.FormValue("cdn_enabled") == "on"
			s.config.Proxy.Rules[index].CDNPreset = r.FormValue("cdn_preset")
			if v := strings.TrimSpace(r.FormValue("cdn_ttl_seconds")); v != "" {
				if n, err := strconv.Atoi(v); err == nil && n >= 0 {
					s.config.Proxy.Rules[index].CDNDefaultTTLSeconds = n
				}
			} else {
				s.config.Proxy.Rules[index].CDNDefaultTTLSeconds = 0
			}

			// 更新云存储配置字段
			s.config.Proxy.Rules[index].CloudStorageType = r.FormValue("cloud_storage_type")
			s.config.Proxy.Rules[index].CloudStorageRegion = r.FormValue("cloud_storage_region")
			s.config.Proxy.Rules[index].CloudStorageBucket = r.FormValue("cloud_storage_bucket")
			s.config.Proxy.Rules[index].CloudStorageEndpoint = r.FormValue("cloud_storage_endpoint")
			s.config.Proxy.Rules[index].CloudStoragePath = r.FormValue("cloud_storage_path")
			s.config.Proxy.Rules[index].CloudStorageAccessKey = r.FormValue("cloud_storage_access_key")
			s.config.Proxy.Rules[index].CloudStorageSecretKey = r.FormValue("cloud_storage_secret_key")

			// 处理访问控制字段
			s.config.Proxy.Rules[index].AuthEnabled = r.FormValue("auth_enabled") == "on"

			if s.config.Proxy.Rules[index].AuthEnabled {
				// 解析用户列表
				var authUsers []config.ProxyAuthUser
				form := r.Form

				for key := range form {
					if strings.HasPrefix(key, "auth_users[") && strings.HasSuffix(key, "][username]") {
						// 提取索引
						indexStart := strings.Index(key, "[") + 1
						indexEnd := strings.Index(key, "]")
						if indexStart > 0 && indexEnd > indexStart {
							userIndex := key[indexStart:indexEnd]
							usernameKey := "auth_users[" + userIndex + "][username]"
							passwordKey := "auth_users[" + userIndex + "][password]"

							username := strings.TrimSpace(r.FormValue(usernameKey))
							password := strings.TrimSpace(r.FormValue(passwordKey))

							if username != "" && password != "" {
								authUsers = append(authUsers, config.ProxyAuthUser{
									Username: username,
									Password: password,
								})
							}
						}
					}
				}

				s.config.Proxy.Rules[index].AuthUsers = authUsers

				// 会话超时时间
				if v := strings.TrimSpace(r.FormValue("auth_session_timeout")); v != "" {
					if n, err := strconv.Atoi(v); err == nil && n >= 300 {
						s.config.Proxy.Rules[index].AuthSessionTimeout = n
					} else {
						s.config.Proxy.Rules[index].AuthSessionTimeout = 3600 // 默认1小时
					}
				} else {
					s.config.Proxy.Rules[index].AuthSessionTimeout = 3600
				}

				// Cookie域名
				s.config.Proxy.Rules[index].AuthCookieDomain = strings.TrimSpace(r.FormValue("auth_cookie_domain"))
				if s.config.Proxy.Rules[index].AuthCookieDomain == "" {
					s.config.Proxy.Rules[index].AuthCookieDomain = domain
				}
			} else {
				// 未开启认证时清空相关字段
				s.config.Proxy.Rules[index].AuthUsers = nil
				s.config.Proxy.Rules[index].AuthSessionTimeout = 0
				s.config.Proxy.Rules[index].AuthCookieDomain = ""
			}

			// 保存配置
			s.config.Save(s.config.ConfigFile)

			// 尝试为该域名预取/申请证书（若启用 ACME）
			if s.sslManager != nil {
				if err := s.sslManager.EnsureDomainCert(domain); err != nil {
					s.log.Warnf("Failed to prefetch certificate %s: %v", domain, err)
				}
			}

			// 重定向回代理管理页面
			http.Redirect(w, r, s.config.AdminPrefix+"/proxy", http.StatusFound)
			return
		}
	}

	// 显示编辑表单
	rule := s.config.Proxy.Rules[index]
	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"Rule":        rule,
		"Index":       index,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateProxyEditHTML(data)
	w.Write([]byte(html))
}

func (s *Server) handleProxyDelete(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	indexStr := r.URL.Query().Get("index")
	index, err := strconv.Atoi(indexStr)
	if err != nil || index < 0 || index >= len(s.config.Proxy.Rules) {
		http.Error(w, "invalid rule index", http.StatusBadRequest)
		return
	}

	// 删除规则
	s.config.Proxy.Rules = append(s.config.Proxy.Rules[:index], s.config.Proxy.Rules[index+1:]...)

	// 保存配置
	s.config.Save(s.config.ConfigFile)

	// 重定向回代理管理页面
	http.Redirect(w, r, s.config.AdminPrefix+"/proxy", http.StatusFound)
}

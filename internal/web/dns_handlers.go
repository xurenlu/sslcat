package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/xurenlu/sslcat/internal/config"
)

// handleDNS 显示DNS配置管理页面
func (s *Server) handleDNS(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"Providers":   s.config.SSL.DNSProviders,
		"DefaultProvider": s.config.SSL.DefaultDNSProvider,
		"ChallengeMethods": s.config.SSL.ChallengeMethods,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateDNSManagementHTML(data)
	w.Write([]byte(html))
}

// handleDNSAdd 显示添加DNS服务商页面
func (s *Server) handleDNSAdd(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method == "POST" {
		// 处理添加DNS服务商
		name := strings.TrimSpace(r.FormValue("name"))
		providerType := strings.TrimSpace(r.FormValue("type"))
		enabled := r.FormValue("enabled") == "on"
		apiKey := strings.TrimSpace(r.FormValue("api_key"))
		apiSecret := strings.TrimSpace(r.FormValue("api_secret"))
		zoneID := strings.TrimSpace(r.FormValue("zone_id"))
		endpoint := strings.TrimSpace(r.FormValue("endpoint"))
		priority := 0
		if v := strings.TrimSpace(r.FormValue("priority")); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				priority = n
			}
		}

		if name != "" && providerType != "" {
			newProvider := config.DNSProvider{
				Name:      name,
				Type:      providerType,
				Enabled:   enabled,
				APIKey:    apiKey,
				APISecret: apiSecret,
				ZoneID:    zoneID,
				Endpoint:  endpoint,
				Priority:  priority,
			}
			s.config.SSL.DNSProviders = append(s.config.SSL.DNSProviders, newProvider)

			// 保存配置
			s.config.Save(s.config.ConfigFile)

			// 重定向回DNS管理页面
			http.Redirect(w, r, s.config.AdminPrefix+"/dns", http.StatusFound)
			return
		}
	}

	// 显示添加表单
	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateDNSAddHTML(data)
	w.Write([]byte(html))
}

// handleDNSEdit 显示编辑DNS服务商页面
func (s *Server) handleDNSEdit(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	indexStr := r.URL.Query().Get("index")
	index, err := strconv.Atoi(indexStr)
	if err != nil || index < 0 || index >= len(s.config.SSL.DNSProviders) {
		http.Error(w, "invalid provider index", http.StatusBadRequest)
		return
	}

	if r.Method == "POST" {
		// 处理编辑DNS服务商
		name := strings.TrimSpace(r.FormValue("name"))
		providerType := strings.TrimSpace(r.FormValue("type"))
		enabled := r.FormValue("enabled") == "on"
		apiKey := strings.TrimSpace(r.FormValue("api_key"))
		apiSecret := strings.TrimSpace(r.FormValue("api_secret"))
		zoneID := strings.TrimSpace(r.FormValue("zone_id"))
		endpoint := strings.TrimSpace(r.FormValue("endpoint"))
		priority := 0
		if v := strings.TrimSpace(r.FormValue("priority")); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				priority = n
			}
		}

		if name != "" && providerType != "" {
			s.config.SSL.DNSProviders[index].Name = name
			s.config.SSL.DNSProviders[index].Type = providerType
			s.config.SSL.DNSProviders[index].Enabled = enabled
			s.config.SSL.DNSProviders[index].APIKey = apiKey
			s.config.SSL.DNSProviders[index].APISecret = apiSecret
			s.config.SSL.DNSProviders[index].ZoneID = zoneID
			s.config.SSL.DNSProviders[index].Endpoint = endpoint
			s.config.SSL.DNSProviders[index].Priority = priority

			// 保存配置
			s.config.Save(s.config.ConfigFile)

			// 重定向回DNS管理页面
			http.Redirect(w, r, s.config.AdminPrefix+"/dns", http.StatusFound)
			return
		}
	}

	// 显示编辑表单
	provider := s.config.SSL.DNSProviders[index]
	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"Provider":    provider,
		"Index":       index,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateDNSEditHTML(data)
	w.Write([]byte(html))
}

// handleDNSDelete 删除DNS服务商
func (s *Server) handleDNSDelete(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	indexStr := r.URL.Query().Get("index")
	index, err := strconv.Atoi(indexStr)
	if err != nil || index < 0 || index >= len(s.config.SSL.DNSProviders) {
		http.Error(w, "invalid provider index", http.StatusBadRequest)
		return
	}

	// 删除服务商
	deletedProvider := s.config.SSL.DNSProviders[index]
	s.config.SSL.DNSProviders = append(s.config.SSL.DNSProviders[:index], s.config.SSL.DNSProviders[index+1:]...)

	// 如果删除的是默认服务商，清空默认设置
	if s.config.SSL.DefaultDNSProvider == deletedProvider.Name {
		s.config.SSL.DefaultDNSProvider = ""
	}

	// 保存配置
	s.config.Save(s.config.ConfigFile)

	// 重定向回DNS管理页面
	http.Redirect(w, r, s.config.AdminPrefix+"/dns", http.StatusFound)
}

// handleDNSConfig 显示DNS全局配置页面
func (s *Server) handleDNSConfig(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method == "POST" {
		// 处理DNS全局配置
		defaultProvider := strings.TrimSpace(r.FormValue("default_provider"))
		challengeMethods := r.Form["challenge_methods"]

		// 验证挑战方法
		validMethods := []string{"http-01", "dns-01"}
		var validChallengeMethods []string
		for _, method := range challengeMethods {
			for _, validMethod := range validMethods {
				if method == validMethod {
					validChallengeMethods = append(validChallengeMethods, method)
					break
				}
			}
		}

		s.config.SSL.DefaultDNSProvider = defaultProvider
		s.config.SSL.ChallengeMethods = validChallengeMethods

		// 保存配置
		s.config.Save(s.config.ConfigFile)

		// 重定向回DNS管理页面
		http.Redirect(w, r, s.config.AdminPrefix+"/dns", http.StatusFound)
		return
	}

	// 显示配置表单
	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"DefaultProvider": s.config.SSL.DefaultDNSProvider,
		"ChallengeMethods": s.config.SSL.ChallengeMethods,
		"Providers": s.config.SSL.DNSProviders,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateDNSConfigHTML(data)
	w.Write([]byte(html))
}

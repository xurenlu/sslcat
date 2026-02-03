package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/xurenlu/sslcat/internal/config"
)

// handleAPIStaticSites 获取静态站点列表
func (s *Server) handleAPIStaticSites(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method == "GET" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"sites":   s.config.StaticSites,
		})
		return
	}

	if r.Method == "POST" {
		if !s.authorizeAPI(w, r, false) { // 需要写权限
			return
		}

		var req struct {
			Domain           string                  `json:"domain"`
			Root             string                  `json:"root"`
			Index            string                  `json:"index"`
			Enabled          bool                    `json:"enabled"`
			Headers          map[string]string       `json:"headers"`
			PathPrefixRules  []config.PathPrefixRule `json:"path_prefix_rules"`
			AccessLogEnabled *bool                   `json:"access_log_enabled,omitempty"`
			AccessLogPath    string                  `json:"access_log_path,omitempty"`
			HTTP2Enabled     *bool                   `json:"http2_enabled,omitempty"`
			HTTP3Enabled     *bool                   `json:"http3_enabled,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
			return
		}

		if req.Domain == "" || req.Root == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "domain and root are required"})
			return
		}

		if req.Index == "" {
			req.Index = "index.html"
		}

		// 检查是否已存在
		existingIndex := -1
		for i, site := range s.config.StaticSites {
			if site.Domain == req.Domain {
				existingIndex = i
				break
			}
		}

		newSite := config.StaticSite{
			Domain:           req.Domain,
			Root:             req.Root,
			Index:            req.Index,
			Enabled:          req.Enabled,
			ResponseHeaders:  sanitizeHeaderMap(req.Headers),
			PathPrefixRules:  req.PathPrefixRules,
			AccessLogEnabled: req.AccessLogEnabled,
			AccessLogPath:    req.AccessLogPath,
			HTTP2Enabled:     req.HTTP2Enabled,
			HTTP3Enabled:     req.HTTP3Enabled,
		}

		if existingIndex >= 0 {
			s.config.StaticSites[existingIndex] = newSite
		} else {
			s.config.StaticSites = append(s.config.StaticSites, newSite)
		}

		if err := s.config.Save(s.config.ConfigFile); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "failed to save config"})
			return
		}

		// 异步尝试为该域名预取/申请证书（若启用 ACME），避免阻塞 API 响应
		if s.sslManager != nil {
			go func(domain string) {
				if err := s.sslManager.EnsureDomainCert(domain); err != nil {
					s.log.Warnf("Failed to prefetch certificate for static site %s: %v", domain, err)
				}
			}(req.Domain)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"site":    newSite,
			"action":  map[bool]string{true: "updated", false: "created"}[existingIndex >= 0],
		})
		return
	}

	if r.Method == "PUT" {
		if !s.authorizeAPI(w, r, false) { // 需要写权限
			return
		}

		var req struct {
			Domain           string                  `json:"domain"`
			Root             string                  `json:"root"`
			Index            string                  `json:"index"`
			Enabled          bool                    `json:"enabled"`
			Headers          map[string]string       `json:"headers"`
			PathPrefixRules  []config.PathPrefixRule `json:"path_prefix_rules"`
			AccessLogEnabled *bool                   `json:"access_log_enabled,omitempty"`
			AccessLogPath    string                  `json:"access_log_path,omitempty"`
			HTTP2Enabled     *bool                   `json:"http2_enabled,omitempty"`
			HTTP3Enabled     *bool                   `json:"http3_enabled,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
			return
		}

		if req.Domain == "" || req.Root == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "domain and root are required"})
			return
		}

		if req.Index == "" {
			req.Index = "index.html"
		}

		// 查找现有站点
		existingIndex := -1
		for i, site := range s.config.StaticSites {
			if site.Domain == req.Domain {
				existingIndex = i
				break
			}
		}

		if existingIndex < 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "site not found"})
			return
		}

		// 更新站点
		s.config.StaticSites[existingIndex] = config.StaticSite{
			Domain:           req.Domain,
			Root:             req.Root,
			Index:            req.Index,
			Enabled:          req.Enabled,
			ResponseHeaders:  sanitizeHeaderMap(req.Headers),
			PathPrefixRules:  req.PathPrefixRules,
			AccessLogEnabled: req.AccessLogEnabled,
			AccessLogPath:    req.AccessLogPath,
			HTTP2Enabled:     req.HTTP2Enabled,
			HTTP3Enabled:     req.HTTP3Enabled,
		}

		if err := s.config.Save(s.config.ConfigFile); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "failed to save config"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"site":    s.config.StaticSites[existingIndex],
			"action":  "updated",
		})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// handleAPIPHPSites 获取PHP站点列表
func (s *Server) handleAPIPHPSites(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method == "GET" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"sites":   s.config.PHPSites,
		})
		return
	}

	if r.Method == "POST" {
		if !s.authorizeAPI(w, r, false) { // 需要写权限
			return
		}

		var req struct {
			Domain           string                  `json:"domain"`
			Root             string                  `json:"root"`
			Index            string                  `json:"index"`
			Enabled          bool                    `json:"enabled"`
			FCGIAddr         string                  `json:"fcgi_addr"`
			Vars             map[string]string       `json:"vars"`
			Headers          map[string]string       `json:"headers"`
			PathPrefixRules  []config.PathPrefixRule `json:"path_prefix_rules"`
			AccessLogEnabled *bool                   `json:"access_log_enabled,omitempty"`
			AccessLogPath    string                  `json:"access_log_path,omitempty"`
			HTTP2Enabled     *bool                   `json:"http2_enabled,omitempty"`
			HTTP3Enabled     *bool                   `json:"http3_enabled,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
			return
		}

		if req.Domain == "" || req.Root == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "domain and root are required"})
			return
		}

		if req.Index == "" {
			req.Index = "index.php"
		}
		if req.FCGIAddr == "" {
			req.FCGIAddr = "127.0.0.1:9000"
		}
		if req.Vars == nil {
			req.Vars = make(map[string]string)
		}

		// 检查是否已存在
		existingIndex := -1
		for i, site := range s.config.PHPSites {
			if site.Domain == req.Domain {
				existingIndex = i
				break
			}
		}

		newSite := config.PHPSite{
			Domain:           req.Domain,
			Root:             req.Root,
			Index:            req.Index,
			Enabled:          req.Enabled,
			FCGIAddr:         req.FCGIAddr,
			Vars:             req.Vars,
			ResponseHeaders:  sanitizeHeaderMap(req.Headers),
			PathPrefixRules:  req.PathPrefixRules,
			AccessLogEnabled: req.AccessLogEnabled,
			AccessLogPath:    req.AccessLogPath,
			HTTP2Enabled:     req.HTTP2Enabled,
			HTTP3Enabled:     req.HTTP3Enabled,
		}

		if existingIndex >= 0 {
			s.config.PHPSites[existingIndex] = newSite
		} else {
			s.config.PHPSites = append(s.config.PHPSites, newSite)
		}

		if err := s.config.Save(s.config.ConfigFile); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "failed to save config"})
			return
		}

		// 异步尝试为该域名预取/申请证书（若启用 ACME），避免阻塞 API 响应
		if s.sslManager != nil {
			go func(domain string) {
				if err := s.sslManager.EnsureDomainCert(domain); err != nil {
					s.log.Warnf("Failed to prefetch certificate for PHP site %s: %v", domain, err)
				}
			}(req.Domain)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"site":    newSite,
			"action":  map[bool]string{true: "updated", false: "created"}[existingIndex >= 0],
		})
		return
	}

	if r.Method == "PUT" {
		if !s.authorizeAPI(w, r, false) { // 需要写权限
			return
		}

		var req struct {
			Domain           string                  `json:"domain"`
			Root             string                  `json:"root"`
			Index            string                  `json:"index"`
			Enabled          bool                    `json:"enabled"`
			FCGIAddr         string                  `json:"fcgi_addr"`
			Vars             map[string]string       `json:"vars"`
			Headers          map[string]string       `json:"headers"`
			PathPrefixRules  []config.PathPrefixRule `json:"path_prefix_rules"`
			AccessLogEnabled *bool                   `json:"access_log_enabled,omitempty"`
			AccessLogPath    string                  `json:"access_log_path,omitempty"`
			HTTP2Enabled     *bool                   `json:"http2_enabled,omitempty"`
			HTTP3Enabled     *bool                   `json:"http3_enabled,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
			return
		}

		if req.Domain == "" || req.Root == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "domain and root are required"})
			return
		}

		if req.Index == "" {
			req.Index = "index.php"
		}
		if req.FCGIAddr == "" {
			req.FCGIAddr = "127.0.0.1:9000"
		}
		if req.Vars == nil {
			req.Vars = make(map[string]string)
		}

		// 查找现有站点
		existingIndex := -1
		for i, site := range s.config.PHPSites {
			if site.Domain == req.Domain {
				existingIndex = i
				break
			}
		}

		if existingIndex < 0 {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "site not found"})
			return
		}

		// 更新站点
		s.config.PHPSites[existingIndex] = config.PHPSite{
			Domain:           req.Domain,
			Root:             req.Root,
			Index:            req.Index,
			Enabled:          req.Enabled,
			FCGIAddr:         req.FCGIAddr,
			Vars:             req.Vars,
			ResponseHeaders:  sanitizeHeaderMap(req.Headers),
			PathPrefixRules:  req.PathPrefixRules,
			AccessLogEnabled: req.AccessLogEnabled,
			AccessLogPath:    req.AccessLogPath,
			HTTP2Enabled:     req.HTTP2Enabled,
			HTTP3Enabled:     req.HTTP3Enabled,
		}

		if err := s.config.Save(s.config.ConfigFile); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "failed to save config"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"site":    s.config.PHPSites[existingIndex],
			"action":  "updated",
		})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// handleAPIStaticSitesDelete 删除静态站点
func (s *Server) handleAPIStaticSitesDelete(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "domain parameter is required"})
		return
	}

	// 查找并删除
	targetIndex := -1
	for i, site := range s.config.StaticSites {
		if site.Domain == domain {
			targetIndex = i
			break
		}
	}

	if targetIndex < 0 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "site not found"})
		return
	}

	deletedSite := s.config.StaticSites[targetIndex]
	s.config.StaticSites = append(s.config.StaticSites[:targetIndex], s.config.StaticSites[targetIndex+1:]...)

	if err := s.config.Save(s.config.ConfigFile); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to save config"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"deleted_site": deletedSite,
	})
}

// handleAPIPHPSitesDelete 删除PHP站点
func (s *Server) handleAPIPHPSitesDelete(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "domain parameter is required"})
		return
	}

	// 查找并删除
	targetIndex := -1
	for i, site := range s.config.PHPSites {
		if site.Domain == domain {
			targetIndex = i
			break
		}
	}

	if targetIndex < 0 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "site not found"})
		return
	}

	deletedSite := s.config.PHPSites[targetIndex]
	s.config.PHPSites = append(s.config.PHPSites[:targetIndex], s.config.PHPSites[targetIndex+1:]...)

	if err := s.config.Save(s.config.ConfigFile); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to save config"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"deleted_site": deletedSite,
	})
}

// handleAPIStaticSitesRename 重命名静态站点域名
func (s *Server) handleAPIStaticSitesRename(w http.ResponseWriter, r *http.Request) {
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
	for _, site := range s.config.StaticSites {
		if site.Domain == req.NewDomain {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "new domain already exists"})
			return
		}
	}

	// 查找旧域名站点
	targetIndex := -1
	for i, site := range s.config.StaticSites {
		if site.Domain == req.OldDomain {
			targetIndex = i
			break
		}
	}

	if targetIndex < 0 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "site not found"})
		return
	}

	// 更新域名
	s.config.StaticSites[targetIndex].Domain = req.NewDomain

	if err := s.config.Save(s.config.ConfigFile); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to save config"})
		return
	}

	s.log.Infof("Renamed static site from %s to %s", req.OldDomain, req.NewDomain)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"site":    s.config.StaticSites[targetIndex],
	})
}

// handleAPIPHPSitesRename 重命名PHP站点域名
func (s *Server) handleAPIPHPSitesRename(w http.ResponseWriter, r *http.Request) {
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
	for _, site := range s.config.PHPSites {
		if site.Domain == req.NewDomain {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "new domain already exists"})
			return
		}
	}

	// 查找旧域名站点
	targetIndex := -1
	for i, site := range s.config.PHPSites {
		if site.Domain == req.OldDomain {
			targetIndex = i
			break
		}
	}

	if targetIndex < 0 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "site not found"})
		return
	}

	// 更新域名
	s.config.PHPSites[targetIndex].Domain = req.NewDomain

	if err := s.config.Save(s.config.ConfigFile); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to save config"})
		return
	}

	s.log.Infof("Renamed PHP site from %s to %s", req.OldDomain, req.NewDomain)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"site":    s.config.PHPSites[targetIndex],
	})
}

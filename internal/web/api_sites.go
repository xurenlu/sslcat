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
			Domain  string `json:"domain"`
			Root    string `json:"root"`
			Index   string `json:"index"`
			Enabled bool   `json:"enabled"`
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
			Domain:  req.Domain,
			Root:    req.Root,
			Index:   req.Index,
			Enabled: req.Enabled,
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

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"site":    newSite,
			"action":  map[bool]string{true: "updated", false: "created"}[existingIndex >= 0],
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
			Domain   string            `json:"domain"`
			Root     string            `json:"root"`
			Index    string            `json:"index"`
			Enabled  bool              `json:"enabled"`
			FCGIAddr string            `json:"fcgi_addr"`
			Vars     map[string]string `json:"vars"`
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
			Domain:   req.Domain,
			Root:     req.Root,
			Index:    req.Index,
			Enabled:  req.Enabled,
			FCGIAddr: req.FCGIAddr,
			Vars:     req.Vars,
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

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"site":    newSite,
			"action":  map[bool]string{true: "updated", false: "created"}[existingIndex >= 0],
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

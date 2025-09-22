package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/xurenlu/sslcat/internal/config"
)

// PHP 站点管理页面
func (s *Server) handlePHPSites(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 检测远程环境状态
	remoteDetector := NewPHPRemoteDetector(s.config)
	siteStatuses := make(map[string]interface{})

	for _, site := range s.config.PHPSites {
		status, err := remoteDetector.GetRemoteEnvironmentStatus(site.Domain)
		if err != nil {
			s.log.Errorf("检测远程环境状态失败 %s: %v", site.Domain, err)
			status = map[string]interface{}{
				"domain": site.Domain,
				"error":  err.Error(),
			}
		}
		siteStatuses[site.Domain] = status
	}

	data := map[string]interface{}{
		"AdminPrefix":  s.config.AdminPrefix,
		"Sites":        s.config.PHPSites,
		"SiteStatuses": siteStatuses,
	}
	s.templateRenderer.DetectLanguageAndRender(w, r, "php_sites.html", data)
}

func (s *Server) handlePHPSitesAdd(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	domain := strings.ToLower(strings.TrimSpace(r.FormValue("domain")))
	root := strings.TrimSpace(r.FormValue("root"))
	index := strings.TrimSpace(r.FormValue("index"))
	if index == "" {
		index = "index.php"
	}
	fcgi := strings.TrimSpace(r.FormValue("fcgi_addr"))
	if domain == "" || root == "" || fcgi == "" {
		http.Error(w, "domain/root/fcgi required", http.StatusBadRequest)
		return
	}
	if err := os.MkdirAll(root, 0755); err != nil {
		http.Error(w, fmt.Sprintf("failed to create root: %v", err), http.StatusBadRequest)
		return
	}

	updated := false
	for i := range s.config.PHPSites {
		if strings.EqualFold(s.config.PHPSites[i].Domain, domain) {
			s.config.PHPSites[i].Root = root
			s.config.PHPSites[i].Index = index
			s.config.PHPSites[i].FCGIAddr = fcgi
			s.config.PHPSites[i].Enabled = true
			updated = true
			break
		}
	}
	if !updated {
		s.config.PHPSites = append(s.config.PHPSites, config.PHPSite{Domain: domain, Root: root, Index: index, Enabled: true, FCGIAddr: fcgi})
	}

	if s.sslManager != nil {
		_ = s.sslManager.EnsureDomainCert(domain)
	}
	_ = s.config.Save(s.config.ConfigFile)
	http.Redirect(w, r, s.config.AdminPrefix+"/php-sites", http.StatusFound)
}

func (s *Server) handlePHPSitesDelete(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	domain := strings.ToLower(strings.TrimSpace(r.FormValue("domain")))
	var out []config.PHPSite
	for _, ss := range s.config.PHPSites {
		if !strings.EqualFold(ss.Domain, domain) {
			out = append(out, ss)
		}
	}
	s.config.PHPSites = out
	_ = s.config.Save(s.config.ConfigFile)
	http.Redirect(w, r, s.config.AdminPrefix+"/php-sites", http.StatusFound)
}

// 在代理前尝试处理 PHP
func (s *Server) tryServePHP(w http.ResponseWriter, r *http.Request) bool {
	// 先尝试 PHP；若未命中返回 false
	return s.servePHP(w, r)
}

// 获取 PHP 远程环境状态 API
func (s *Server) handlePHPRemoteStatus(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "domain parameter required", http.StatusBadRequest)
		return
	}

	remoteDetector := NewPHPRemoteDetector(s.config)
	status, err := remoteDetector.GetRemoteEnvironmentStatus(domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// 获取远程环境设置指南
func (s *Server) handlePHPRemoteGuide(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "domain parameter required", http.StatusBadRequest)
		return
	}

	remoteDetector := NewPHPRemoteDetector(s.config)
	guide, err := remoteDetector.GenerateRemoteSetupGuide(domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(guide))
}

// 检查远程环境能力
func (s *Server) handlePHPRemoteCapabilities(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "domain parameter required", http.StatusBadRequest)
		return
	}

	remoteDetector := NewPHPRemoteDetector(s.config)
	capabilities, err := remoteDetector.CheckRemoteCapabilities(domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(capabilities)
}

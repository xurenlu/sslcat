package web

import (
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
	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"Sites":       s.config.PHPSites,
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

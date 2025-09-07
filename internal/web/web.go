package web

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/xurenlu/sslcat/internal/config"
)

// handleStaticSites 静态站点管理页面
func (s *Server) handleStaticSites(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"Sites":       s.config.StaticSites,
	}

	s.templateRenderer.DetectLanguageAndRender(w, r, "static_sites.html", data)
}

// handleStaticSitesAdd 添加/保存静态站点
func (s *Server) handleStaticSitesAdd(w http.ResponseWriter, r *http.Request) {
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
		index = "index.html"
	}
	if domain == "" || root == "" {
		http.Error(w, "domain and root required", http.StatusBadRequest)
		return
	}

	// 确保目录存在
	if err := os.MkdirAll(root, 0755); err != nil {
		http.Error(w, fmt.Sprintf("failed to create root: %v", err), http.StatusBadRequest)
		return
	}

	// 写入/更新配置项
	updated := false
	for i := range s.config.StaticSites {
		if strings.EqualFold(s.config.StaticSites[i].Domain, domain) {
			s.config.StaticSites[i].Root = root
			s.config.StaticSites[i].Index = index
			s.config.StaticSites[i].Enabled = true
			updated = true
			break
		}
	}
	if !updated {
		s.config.StaticSites = append(s.config.StaticSites, config.StaticSite{Domain: domain, Root: root, Index: index, Enabled: true})
	}

	// 允许域名触发证书申请（若启用 ACME）
	if s.sslManager != nil {
		_ = s.sslManager.EnsureDomainCert(domain)
	}

	_ = s.config.Save(s.config.ConfigFile)
	http.Redirect(w, r, s.config.AdminPrefix+"/static-sites", http.StatusFound)
}

// handleStaticSitesDelete 删除静态站点
func (s *Server) handleStaticSitesDelete(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	domain := strings.ToLower(strings.TrimSpace(r.FormValue("domain")))
	var out []config.StaticSite
	for _, ss := range s.config.StaticSites {
		if !strings.EqualFold(ss.Domain, domain) {
			out = append(out, ss)
		}
	}
	s.config.StaticSites = out
	_ = s.config.Save(s.config.ConfigFile)
	http.Redirect(w, r, s.config.AdminPrefix+"/static-sites", http.StatusFound)
}

// serveStatic 若命中静态站点规则则服务本地文件
func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) bool {
	host := r.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	for _, site := range s.config.StaticSites {
		if !site.Enabled {
			continue
		}
		if strings.EqualFold(site.Domain, host) {
			// 规范化请求路径，禁止目录列出与越权
			reqPath := r.URL.Path
			if reqPath == "/" || reqPath == "" {
				reqPath = "/" + site.Index
			}
			clean := strings.TrimPrefix(filepath.Clean(reqPath), "/")
			full := filepath.Join(site.Root, clean)
			if rel, err := filepath.Rel(site.Root, full); err != nil || strings.HasPrefix(rel, "..") {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return true
			}
			// 如果是目录，追加 index；不存在则404
			if fi, err := os.Stat(full); err == nil && fi.IsDir() {
				idxFile := filepath.Join(full, site.Index)
				if _, err := os.Stat(idxFile); err == nil {
					http.ServeFile(w, r, idxFile)
					return true
				}
				http.NotFound(w, r)
				return true
			}
			http.ServeFile(w, r, full)
			return true
		}
	}
	return false
}

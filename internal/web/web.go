package web

import (
	"fmt"
	"mime"
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

	// 检查模板是否存在，如果不存在则回退到前端 SPA
	if !s.templateRenderer.TemplateExists("static_sites.html") {
		s.handleSPA(w, r)
		return
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
			// 优先检查并应用路径前缀代理规则（最长前缀优先）
			if len(site.PathPrefixRules) > 0 {
				var (
					matchedRule   *config.PathPrefixRule
					matchedPrefix string
				)
				// 选择最长匹配前缀的规则
				for i := range site.PathPrefixRules {
					rule := &site.PathPrefixRules[i]
					if !rule.Enabled {
						continue
					}
					// 遍历所有前缀，找出匹配且最长的前缀
					for _, prefix := range rule.Prefixes {
						if (rule.Exact && r.URL.Path == prefix) || (!rule.Exact && strings.HasPrefix(r.URL.Path, prefix)) {
							if len(prefix) > len(matchedPrefix) {
								matchedPrefix = prefix
								matchedRule = rule
							}
						}
					}
				}

				// 命中路径前缀规则则走代理逻辑
				if matchedRule != nil {
					s.log.Debugf("Static site %s matched path-prefix rule (prefix=%s), proxying to backends", host, matchedPrefix)
					// 选择一个可用后端（当前采用第一个启用的后端）
					var selectedBackend *config.ProxyBackend
					for i := range matchedRule.Backends {
						if matchedRule.Backends[i].Enabled {
							selectedBackend = &matchedRule.Backends[i]
							break
						}
					}
					if selectedBackend == nil {
						s.log.Warnf("No enabled backend for matched static path-prefix rule on %s (prefix=%s)", host, matchedPrefix)
						http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
						return true
					}

					// 构造临时 ProxyRule（单后端，避免走全局LB缓存）
					tempRule := &config.ProxyRule{
						Domain:       host,
						Enabled:      true,
						PathPrefixes: matchedRule.Prefixes,
						PathExact:    matchedRule.Exact,
						// 同步一份单后端（并设置 Target/Port 以走传统代理路径）
						Backends:               []config.ProxyBackend{*selectedBackend},
						Target:                 selectedBackend.Host,
						Port:                   selectedBackend.Port,
						LoadBalancerAlgorithm:  matchedRule.LoadBalancerAlgorithm,
						SessionAffinityEnabled: matchedRule.SessionAffinityEnabled,
						SessionAffinityMethod:  matchedRule.SessionAffinityMethod,
						SessionAffinityCookie:  matchedRule.SessionAffinityCookie,
						SessionAffinityHeader:  matchedRule.SessionAffinityHeader,
						SessionAffinityTTL:     matchedRule.SessionAffinityTTL,
						HealthCheckEnabled:     matchedRule.HealthCheckEnabled,
						HealthCheckPath:        matchedRule.HealthCheckPath,
						HealthCheckInterval:    matchedRule.HealthCheckInterval,
						HealthCheckTimeout:     matchedRule.HealthCheckTimeout,
						HealthCheckMethod:      matchedRule.HealthCheckMethod,
						ExpectedStatusCode:     matchedRule.ExpectedStatusCode,
						FailoverEnabled:        matchedRule.FailoverEnabled,
						MaxRetries:             matchedRule.MaxRetries,
						RetryInterval:          matchedRule.RetryInterval,
						FailureThreshold:       matchedRule.FailureThreshold,
						RecoveryThreshold:      matchedRule.RecoveryThreshold,
					}

					// 通过带鉴权的代理入口执行
					s.ProxyRequestWithAuth(w, r, tempRule)
					return true
				}
			}
			// 检查路径前缀匹配
			if !site.MatchesPath(r.URL.Path) {
				s.log.Debugf("Request path %s does not match any prefix for static site %s", r.URL.Path, host)
				continue
			}
			s.log.Debugf("Request path %s matches prefix for static site %s", r.URL.Path, host)
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
					// 在 http.ServeFile 之前先设置正确的 MIME 类型
					if contentType := mime.TypeByExtension(filepath.Ext(idxFile)); contentType != "" {
						s.log.Debugf("Setting Content-Type for index file %s: %s", idxFile, contentType)
						w.Header().Set("Content-Type", contentType)
					} else {
						s.log.Debugf("No MIME type found for index file extension: %s", filepath.Ext(idxFile))
					}
					http.ServeFile(w, r, idxFile)
					return true
				}
				http.NotFound(w, r)
				return true
			}
			// 在 http.ServeFile 之前先设置正确的 MIME 类型
			if contentType := mime.TypeByExtension(filepath.Ext(full)); contentType != "" {
				s.log.Debugf("Setting Content-Type for %s: %s", full, contentType)
				w.Header().Set("Content-Type", contentType)
			} else {
				s.log.Debugf("No MIME type found for extension: %s", filepath.Ext(full))
			}
			s.applyCustomSiteHeaders(w, site.ResponseHeaders)
			http.ServeFile(w, r, full)
			return true
		}
	}
	return false
}

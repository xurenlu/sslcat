package web

import (
	"net/http"
	"strconv"

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
			newRule := config.ProxyRule{
				Domain: domain,
				Target: target,
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

		if domain != "" && target != "" {
			s.config.Proxy.Rules[index].Domain = domain
			s.config.Proxy.Rules[index].Target = target

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

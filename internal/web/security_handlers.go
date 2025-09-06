package web

import (
	"encoding/json"
	"net/http"
)

// 安全设置

func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 获取安全信息
	blockedIPs := s.securityManager.GetBlockedIPs()

	data := map[string]interface{}{
		"AdminPrefix":    s.config.AdminPrefix,
		"BlockedIPs":     blockedIPs,
		"SecurityConfig": s.config.Security,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateSecurityManagementHTML(data)
	w.Write([]byte(html))
}

func (s *Server) handleBlockedIPs(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	blockedIPs := s.securityManager.GetBlockedIPs()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(blockedIPs)
}

func (s *Server) handleUnblock(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method == "POST" {
		ip := r.FormValue("ip")
		if ip != "" {
			s.securityManager.UnblockIP(ip)
		}
	}

	// 重定向回安全设置页面
	http.Redirect(w, r, s.config.AdminPrefix+"/security", http.StatusFound)
}

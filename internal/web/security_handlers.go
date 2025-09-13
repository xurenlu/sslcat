package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// 安全设置

func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 获取安全信息
	blockedIPs := s.securityManager.GetBlockedIPs()
	ddosStats := map[string]interface{}{}
	if s.ddosProtector != nil {
		ddosStats = s.ddosProtector.GetStats()
	}

	data := map[string]interface{}{
		"AdminPrefix":    s.config.AdminPrefix,
		"BlockedIPs":     blockedIPs,
		"SecurityConfig": s.config.Security,
		"DDOSStats":      ddosStats,
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

// handleSecuritySave 保存安全设置
func (s *Server) handleSecuritySave(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 人机验证开关
	s.config.Security.EnableCaptcha = r.FormValue("enable_captcha") == "on"
	s.config.Security.EnablePoW = r.FormValue("enable_pow") == "on"

	// PoW 参数
	if bits := strings.TrimSpace(r.FormValue("pow_bits")); bits != "" {
		if v, err := strconv.Atoi(bits); err == nil && v >= 10 && v <= 30 {
			s.config.Security.PoWBits = v
		}
	}
	if minMs := strings.TrimSpace(r.FormValue("min_form_ms")); minMs != "" {
		if v, err := strconv.Atoi(minMs); err == nil && v >= 0 && v <= 10000 {
			s.config.Security.MinFormMs = v
		}
	}

	// DDoS 防护开关
	s.config.Security.EnableDDOS = r.FormValue("enable_ddos") == "on"

	// 保存配置
	_ = s.config.Save(s.config.ConfigFile)

	http.Redirect(w, r, s.config.AdminPrefix+"/security", http.StatusFound)
}

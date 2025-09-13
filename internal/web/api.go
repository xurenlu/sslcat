package web

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// API处理器

func (s *Server) authorizeAPI(w http.ResponseWriter, r *http.Request, readOnly bool) bool {
	// 1) 如果是面板登录用户（cookie session），允许访问；写接口也允许
	if c, err := r.Cookie("sslcat_session"); err == nil && c.Value == "authenticated" {
		return true
	}
	// 2) 检查 Authorization: Bearer <token>
	authz := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		tok := strings.TrimSpace(authz[len("Bearer "):])
		if role, ok := s.tokenStore.Validate(tok); ok {
			if readOnly {
				return true
			}
			// 写操作需要 write 角色
			if role == "write" {
				return true
			}
		}
	}
	w.WriteHeader(http.StatusUnauthorized)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"error":"unauthorized"}`))
	return false
}

func (s *Server) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	stats := s.getSystemStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleAPICDNCacheStats 返回类CDN缓存的简单统计
func (s *Server) handleAPICDNCacheStats(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}
	// 通过 proxyManager 间接访问 cdn cache
	type cacher interface{ Stats() map[string]any }
	var stats map[string]any = map[string]any{"enabled": false}
	if pm, ok := interface{}(s.proxyManager).(interface{ GetCDNCache() cacher }); ok {
		if c := pm.GetCDNCache(); c != nil {
			stats = c.Stats()
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleAPIProxyRules(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.config.Proxy.Rules)
}

func (s *Server) handleAPISSLCerts(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	certs := s.sslManager.GetCertificateList()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(certs)
}

func (s *Server) handleAPISecurityLogs(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	limit := 100
	if ls := r.URL.Query().Get("limit"); ls != "" {
		if v, err := strconv.Atoi(ls); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}
	onlyFailed := r.URL.Query().Get("only_failed") == "1"

	type logItem struct {
		IP        string    `json:"ip"`
		UserAgent string    `json:"user_agent"`
		Path      string    `json:"path"`
		Timestamp time.Time `json:"timestamp"`
		Success   bool      `json:"success"`
	}
	var all []logItem

	// 通过只读访问器遍历
	for ip, logs := range s.securityManager.AccessLogsSnapshot() {
		for _, l := range logs {
			if onlyFailed && l.Success {
				continue
			}
			all = append(all, logItem{IP: ip, UserAgent: l.UserAgent, Path: l.Path, Timestamp: l.Timestamp, Success: l.Success})
		}
	}
	if len(all) > limit {
		all = all[len(all)-limit:]
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"logs": all})
}

func (s *Server) handleAPIAudit(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}
	data, err := os.ReadFile("./data/audit.log")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{\"logs\":[]}"))
		return
	}
	lines := strings.Split(string(data), "\n")
	type item map[string]any
	var out []item
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		var it item
		if err := json.Unmarshal([]byte(ln), &it); err == nil {
			out = append(out, it)
		}
	}
	// 下载模式
	if r.URL.Query().Get("download") == "1" {
		fname := "audit-" + time.Now().Format("20060102-150405") + ".json"
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename="+fname)
		json.NewEncoder(w).Encode(map[string]any{"logs": out})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"logs": out})
}

func (s *Server) handleAPITLSFingerprints(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	stats := s.securityManager.GetTLSFingerprintStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"fingerprints": stats})
}

// handleAPICaptcha 处理验证码API请求
func (s *Server) handleAPICaptcha(w http.ResponseWriter, r *http.Request) {
	// 验证码API不需要登录认证，但只有在需要验证码时才能访问
	if !s.sslManager.HasValidSSLCertificates() {
		// 调试模式允许在无证书时使用 captcha API
		if !(strings.EqualFold(r.URL.Query().Get("debug"), "true") || r.URL.Query().Get("debug") == "1") {
			w.WriteHeader(http.StatusNotFound)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"error":"captcha not required"}`))
			return
		}
	}

	if r.Method == "GET" {
		// 生成新的验证码
		captchaData, err := s.captchaManager.GenerateCaptcha()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"error":"failed to generate captcha"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(captchaData)
		return
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"error":"method not allowed"}`))
}

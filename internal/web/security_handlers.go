package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/xurenlu/sslcat/internal/i18n"
)

// 安全设置

func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 检测并设置语言
	lang := s.detectLanguage(r)
	s.translator.SetLanguage(lang)

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

// detectLanguage 检测用户语言偏好
func (s *Server) detectLanguage(r *http.Request) i18n.SupportedLanguage {
	// 1. 检查 URL 参数
	if langParam := r.URL.Query().Get("lang"); langParam != "" {
		if lang := i18n.SupportedLanguage(langParam); s.isValidLanguage(lang) {
			return lang
		}
	}

	// 2. 检查 Cookie
	if cookie, err := r.Cookie("language"); err == nil {
		if lang := i18n.SupportedLanguage(cookie.Value); s.isValidLanguage(lang) {
			return lang
		}
	}

	// 3. 检查 Accept-Language 头
	acceptLang := r.Header.Get("Accept-Language")
	if acceptLang != "" {
		// 简单解析，取第一个语言
		langs := s.parseAcceptLanguage(acceptLang)
		for _, lang := range langs {
			if supportedLang := s.mapToSupportedLanguage(lang); s.isValidLanguage(supportedLang) {
				return supportedLang
			}
		}
	}

	// 4. 默认语言
	return i18n.LangZhCN
}

// parseAcceptLanguage 解析 Accept-Language 头
func (s *Server) parseAcceptLanguage(acceptLang string) []string {
	// 简化实现，实际应该考虑权重
	var langs []string
	parts := strings.Split(acceptLang, ",")
	for _, part := range parts {
		lang := strings.TrimSpace(strings.Split(part, ";")[0])
		if lang != "" {
			langs = append(langs, lang)
		}
	}
	return langs
}

// mapToSupportedLanguage 将语言代码映射到支持的语言
func (s *Server) mapToSupportedLanguage(lang string) i18n.SupportedLanguage {
	switch strings.ToLower(lang) {
	case "zh", "zh-cn", "zh-hans":
		return i18n.LangZhCN
	case "en", "en-us":
		return i18n.LangEnUS
	case "ja", "ja-jp":
		return i18n.LangJaJP
	case "es", "es-es":
		return i18n.LangEsES
	case "fr", "fr-fr":
		return i18n.LangFrFR
	case "ru", "ru-ru":
		return i18n.LangRuRU
	default:
		return i18n.LangZhCN
	}
}

// isValidLanguage 检查是否为有效的支持语言
func (s *Server) isValidLanguage(lang i18n.SupportedLanguage) bool {
	supportedLangs := s.translator.GetSupportedLanguages()
	_, exists := supportedLangs[lang]
	return exists
}

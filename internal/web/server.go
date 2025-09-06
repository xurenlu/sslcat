package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/assets"
	"github.com/xurenlu/sslcat/internal/cluster"
	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/i18n"
	"github.com/xurenlu/sslcat/internal/notify"
	"github.com/xurenlu/sslcat/internal/proxy"
	"github.com/xurenlu/sslcat/internal/security"
	"github.com/xurenlu/sslcat/internal/ssl"

	"github.com/sirupsen/logrus"
)

// ClusterManager 集群管理器接口
type ClusterManager interface {
	Start() error
	Stop()
	IsSlaveMode() bool
	IsMasterMode() bool
	IsStandaloneMode() bool
	GetNodes() map[string]interface{}
	SetSlaveMode(masterHost string, masterPort int, authKey string) error
	SetStandaloneMode() error
	HandleSyncRequest(w http.ResponseWriter, r *http.Request)
}

// Server Web服务器
type Server struct {
	config           *config.Config
	proxyManager     *proxy.Manager
	securityManager  *security.Manager
	sslManager       *ssl.Manager
	notifier         *notify.Notifier
	templateRenderer *TemplateRenderer
	translator       *i18n.Translator
	mux              *http.ServeMux
	log              *logrus.Entry
	startTime        time.Time
	// 导入配置暂存
	pendingImportJSON string
	pendingImport     *config.Config
	pendingDiff       *config.ConfigDiff
	// Token 管理
	tokenStore *security.TokenStore
	// 验证码管理
	captchaManager *CaptchaManager
	clusterManager ClusterManager
}

// NewServer 创建Web服务器
func NewServer(cfg *config.Config, proxyMgr *proxy.Manager, secMgr *security.Manager, sslMgr *ssl.Manager) *Server {
	// 初始化翻译器（从嵌入读取）
	translator := i18n.NewTranslator(i18n.LangZhCN, "")
	// 通过嵌入 i18n 文件加载翻译
	if files, err := assets.ListI18nFiles(); err == nil {
		for _, f := range files {
			if b, err := assets.ReadI18nFile(f); err == nil {
				code := i18n.SupportedLanguage(strings.TrimSuffix(f, ".json"))
				_ = translator.SaveTranslations(code, func() map[string]string {
					m := make(map[string]string)
					_ = json.Unmarshal(b, &m)
					return m
				}())
			}
		}
	} else {
		logrus.Warnf("Failed to read embedded i18n files: %v", err)
	}

	// 初始化模板渲染器
	templateRenderer := NewTemplateRenderer(translator)

	server := &Server{
		config:           cfg,
		proxyManager:     proxyMgr,
		securityManager:  secMgr,
		sslManager:       sslMgr,
		notifier:         notify.NewFromEnv(),
		templateRenderer: templateRenderer,
		translator:       translator,
		mux:              http.NewServeMux(),
		startTime:        time.Now(),
		log: logrus.WithFields(logrus.Fields{
			"component": "web_server",
		}),
	}

	// 初始化 TokenStore
	server.tokenStore = security.NewTokenStore("./data/tokens.json")

	// 初始化验证码管理器
	server.captchaManager = NewCaptchaManager()

	// 初始化集群管理器（如果需要）
	if cfg.Cluster.Mode != "standalone" && cfg.Cluster.Mode != "" {
		configAdapter := NewConfigAdapter(cfg)
		server.clusterManager = cluster.NewManager(configAdapter, logrus.StandardLogger())
	}

	server.setupRoutes()
	return server
}

// UpdateConfig 更新配置并重新设置路由
func (s *Server) UpdateConfig(cfg *config.Config) {
	s.config = cfg
	// 重新创建路由器
	s.mux = http.NewServeMux()
	s.setupRoutes()
}

// setupRoutes 设置路由
func (s *Server) setupRoutes() {
	// 根路径重定向
	s.mux.HandleFunc("/", s.handleRoot)

	// 管理面板路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/", s.handleAdmin)
	s.mux.HandleFunc(s.config.AdminPrefix+"/login", s.handleLogin)
	s.mux.HandleFunc(s.config.AdminPrefix+"/logout", s.handleLogout)
	s.mux.HandleFunc(s.config.AdminPrefix+"/dashboard", s.handleDashboard)
	s.mux.HandleFunc(s.config.AdminPrefix+"/mobile", s.handleMobile)
	s.mux.HandleFunc(s.config.AdminPrefix+"/charts", s.handleCharts)

	// 代理管理路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/proxy", s.handleProxy)
	s.mux.HandleFunc(s.config.AdminPrefix+"/proxy/add", s.handleProxyAdd)
	s.mux.HandleFunc(s.config.AdminPrefix+"/proxy/edit", s.handleProxyEdit)
	s.mux.HandleFunc(s.config.AdminPrefix+"/proxy/delete", s.handleProxyDelete)

	// SSL管理路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/ssl", s.handleSSL)
	s.mux.HandleFunc(s.config.AdminPrefix+"/ssl/generate", s.handleSSLGenerate)
	s.mux.HandleFunc(s.config.AdminPrefix+"/ssl/upload", s.handleSSLUpload)
	s.mux.HandleFunc(s.config.AdminPrefix+"/ssl/download", s.handleSSLDownload)
	s.mux.HandleFunc(s.config.AdminPrefix+"/ssl/delete", s.handleSSLDelete)
	// 从 acme-cache 同步证书到 certs/keys
	s.mux.HandleFunc(s.config.AdminPrefix+"/ssl/sync-acme", s.handleSSLSyncACME)

	// 安全设置路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/security", s.handleSecurity)
	s.mux.HandleFunc(s.config.AdminPrefix+"/security/blocked-ips", s.handleBlockedIPs)
	s.mux.HandleFunc(s.config.AdminPrefix+"/security/unblock", s.handleUnblock)

	// 系统设置路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/settings", s.handleSettings)
	s.mux.HandleFunc(s.config.AdminPrefix+"/settings/save", s.handleSettingsSave)
	s.mux.HandleFunc(s.config.AdminPrefix+"/settings/first-setup", s.handleFirstTimeSetup)
	s.mux.HandleFunc(s.config.AdminPrefix+"/settings/change-password", s.handleChangePassword)

	// 紧急修复（忘记密码）
	s.mux.HandleFunc(s.config.AdminPrefix+"/help/recover", s.handleRecoverHelp)

	// 首启向导
	s.mux.HandleFunc(s.config.AdminPrefix+"/wizard", s.handleWizard)
	s.mux.HandleFunc(s.config.AdminPrefix+"/wizard/step2", s.handleWizardStep2)
	s.mux.HandleFunc(s.config.AdminPrefix+"/wizard/step3", s.handleWizardStep3)
	s.mux.HandleFunc(s.config.AdminPrefix+"/wizard/finish", s.handleWizardFinish)

	// 配置导出/导入/预览/应用
	s.mux.HandleFunc(s.config.AdminPrefix+"/config/export", s.handleConfigExport)
	s.mux.HandleFunc(s.config.AdminPrefix+"/config/import", s.handleConfigImport)
	s.mux.HandleFunc(s.config.AdminPrefix+"/config/preview", s.handleConfigPreview)
	s.mux.HandleFunc(s.config.AdminPrefix+"/config/apply", s.handleConfigApply)

	// API路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/stats", s.handleAPIStats)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/proxy-rules", s.handleAPIProxyRules)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/ssl-certs", s.handleAPISSLCerts)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/security-logs", s.handleAPISecurityLogs)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/audit", s.handleAPIAudit)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/tls-fingerprints", s.handleAPITLSFingerprints)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/captcha", s.handleAPICaptcha)

	// Token 管理路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/tokens", s.handleTokensPage)
	s.mux.HandleFunc(s.config.AdminPrefix+"/tokens/generate", s.handleTokenGeneratePage)
	s.mux.HandleFunc(s.config.AdminPrefix+"/tokens/delete", s.handleTokenDeleteAction)

	// 证书批量操作
	s.mux.HandleFunc(s.config.AdminPrefix+"/ssl/download-all", s.handleSSLDownloadAll)
	s.mux.HandleFunc(s.config.AdminPrefix+"/ssl/upload-all", s.handleSSLBulkUpload)
}

// ServeHTTP 实现http.Handler接口
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 语言切换：如果存在 ?lang= 参数，则设置 cookie 并重定向到去掉 lang 的同一路径
	if langParam := r.URL.Query().Get("lang"); langParam != "" {
		if s.isSupportedLanguage(langParam) {
			// 设置语言 cookie（180 天）
			http.SetCookie(w, &http.Cookie{
				Name:     "language",
				Value:    langParam,
				Path:     "/",
				MaxAge:   180 * 24 * 3600,
				HttpOnly: false,
				Secure:   r.TLS != nil,
			})
			// 立即切换当前会话语言
			s.translator.SetLanguage(i18n.SupportedLanguage(langParam))
			// 构造重定向URL（去掉 lang 参数）
			q := r.URL.Query()
			q.Del("lang")
			r.URL.RawQuery = q.Encode()
			http.Redirect(w, r, r.URL.String(), http.StatusFound)
			return
		}
	}

	// 安全中间件
	if !s.securityMiddleware(w, r) {
		return
	}

	// 可选：WAF 检测（开启时才生效）
	if s.config.Security.EnableWAF {
		// 这里假设后续我们会在 Server 中集成一个 wafEngine（如 s.wafEngine），
		// 当前版本仅预留接口示意。如果已存在 waf 引擎实例，可在此调用：
		// if evt, blocked := s.wafEngine.CheckRequest(r); blocked { ... }
		// 为保持稳定，此处不引入新字段，仅做占位以便后续扩展。
	}

	// 代理中间件
	if s.proxyMiddleware(w, r) {
		return
	}

	// 处理请求
	s.mux.ServeHTTP(w, r)
}

func (s *Server) isSupportedLanguage(lang string) bool {
	langs := s.translator.GetSupportedLanguages()
	if _, ok := langs[i18n.SupportedLanguage(lang)]; ok {
		return true
	}
	return false
}

// securityMiddleware 安全中间件
func (s *Server) securityMiddleware(w http.ResponseWriter, r *http.Request) bool {
	// 获取客户端信息
	clientIP := s.getClientIP(r)
	userAgent := r.Header.Get("User-Agent")
	path := r.URL.Path

	// 检查是否被封禁
	if s.securityManager.IsBlocked(clientIP) {
		s.log.Warnf("Blocked IP attempted to access: %s", clientIP)
		http.Error(w, "IP address blocked", http.StatusForbidden)
		return false
	}

	// 检查User-Agent
	if strings.HasPrefix(path, s.config.AdminPrefix) && (userAgent == "" || s.isCommonBotUserAgent(userAgent)) {
		s.log.Warnf("Suspicious User-Agent attempted to access admin panel: %s from %s", userAgent, clientIP)
		s.securityManager.LogAccess(clientIP, userAgent, path, false)
		http.Error(w, "Access denied", http.StatusForbidden)
		return false
	}

	// 记录访问日志
	s.securityManager.LogAccess(clientIP, userAgent, path, true)

	return true
}

// proxyMiddleware 代理中间件
func (s *Server) proxyMiddleware(w http.ResponseWriter, r *http.Request) bool {
	// 如果是管理面板路径，跳过代理
	if strings.HasPrefix(r.URL.Path, s.config.AdminPrefix) {
		return false
	}

	// 获取域名
	host := r.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// 查找代理配置
	rule := s.proxyManager.GetProxyConfig(host)
	if rule != nil && rule.Enabled {
		// 若仅允许HTTPS且当前为HTTP，则跳转到HTTPS
		if rule.SSLOnly && r.TLS == nil {
			target := "https://" + host + r.URL.RequestURI()
			s.log.Warnf("SSL-only rule, redirecting http->https for host=%s", host)
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return true
		}
		// 执行代理
		s.proxyManager.ProxyRequest(w, r, rule)
		return true
	}

	// 没有找到（或规则未启用）代理配置，依据配置项处理
	switch s.config.Proxy.UnmatchedBehavior {
	case "302":
		target := s.config.Proxy.UnmatchedRedirectURL
		if target == "" {
			target = "https://sslcat.com"
		}
		s.log.Warnf("Unmatched proxy for host=%s path=%s, redirecting to %s", host, r.URL.Path, target)
		http.Redirect(w, r, target, http.StatusFound)
	case "blank":
		s.log.Warnf("Unmatched proxy for host=%s path=%s, returning blank", host, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	case "404":
		s.log.Warnf("Unmatched proxy for host=%s path=%s, returning 404", host, r.URL.Path)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("\n  ____  ____  _      _      _          \n" +
			" / ___||  _ \\| | ___| | ___| |_ __ _ \n" +
			" \\___ \\| |_) | |/ _ \\ |/ _ \\ __/ _` |\n" +
			"  ___) |  __/| |  __/ |  __/ || (_| |\n" +
			" |____/|_|   |_|\\___|_|\\___|\\__\\__,_|\n\n" +
			"This server is enhanced and managed by SSLcat.\n" +
			"Visit: https://sslcat.com\n"))
		return true
	default: // "502"
		s.log.Warnf("Unmatched proxy for host=%s path=%s, returning 502", host, r.URL.Path)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("\n  ____  ____  _      _      _          \n" +
			" / ___||  _ \\| | ___| | ___| |_ __ _ \n" +
			" \\___ \\| |_) | |/ _ \\ |/ _ \\ __/ _` |\n" +
			"  ___) |  __/| |  __/ |  __/ || (_| |\n" +
			" |____/|_|   |_|\\___|_|\\___|\\__\\__,_|\n\n" +
			"This server is enhanced and managed by SSLcat.\n" +
			"Visit: https://sslcat.com\n"))
	}
	return true
}

// 工具函数

func (s *Server) getClientIP(r *http.Request) string {
	// 优先检查Cloudflare头
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		return strings.TrimSpace(cfIP)
	}

	// 检查X-Real-IP
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return strings.TrimSpace(realIP)
	}

	// 检查X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			// 只返回第一个非私有IP
			if !s.isPrivateIP(ip) {
				return ip
			}
		}
	}

	// 使用RemoteAddr
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

func (s *Server) isPrivateIP(ip string) bool {
	// 简单检查私有IP段
	return strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "172.16.") ||
		strings.HasPrefix(ip, "127.") ||
		ip == "::1"
}

func (s *Server) isCommonBotUserAgent(ua string) bool {
	botUAs := []string{
		"bot", "crawler", "spider", "scraper", "curl", "wget",
	}
	uaLower := strings.ToLower(ua)
	for _, bot := range botUAs {
		if strings.Contains(uaLower, bot) {
			return true
		}
	}
	return false
}

func (s *Server) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	session, err := r.Cookie("sslcat_session")
	if err != nil || session.Value != "authenticated" {
		http.Redirect(w, r, s.config.AdminPrefix+"/login", http.StatusFound)
		return false
	}
	return true
}

func (s *Server) getSystemStats() map[string]interface{} {
	proxyStats := s.proxyManager.GetProxyStats()
	uptime := time.Since(s.startTime)

	return map[string]interface{}{
		"ActiveRules":     len(s.config.Proxy.Rules),
		"CachedProxies":   proxyStats["cached_proxies"],
		"TotalRequests":   proxyStats["total_requests"],
		"ErrorRate":       proxyStats["error_rate"],
		"QPS":             proxyStats["qps"],
		"AvgResponseTime": proxyStats["avg_response_time"],
		"Uptime":          int64(uptime.Seconds()),
		"UptimeString":    s.formatDuration(uptime),
		"SSLCertificates": len(s.sslManager.GetCertificateList()),
		"BlockedIPs":      len(s.securityManager.GetBlockedIPs()),
	}
}

func (s *Server) formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%d小时%d分钟", hours, minutes)
	} else if minutes > 0 {
		return fmt.Sprintf("%d分钟%d秒", minutes, seconds)
	} else {
		return fmt.Sprintf("%d秒", seconds)
	}
}

// 简单审计：写入 data/audit.log 为 JSON Lines
func (s *Server) audit(action, detail string) {
	t := time.Now().Format(time.RFC3339)
	rec := map[string]string{"time": t, "user": s.config.Admin.Username, "action": action, "detail": detail}
	b, _ := json.Marshal(rec)
	_ = os.MkdirAll("./data", 0755)
	f, err := os.OpenFile("./data/audit.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		defer f.Close()
		f.Write(append(b, '\n'))
	}
	if s.notifier != nil && s.notifier.Enabled() {
		m := map[string]any{"ts": t, "level": "info", "action": action, "detail": detail}
		s.notifier.SendJSON(m)
	}
}

package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/assets"
	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/ddos"
	"github.com/xurenlu/sslcat/internal/i18n"
	"github.com/xurenlu/sslcat/internal/logger"
	"github.com/xurenlu/sslcat/internal/notify"
	"github.com/xurenlu/sslcat/internal/proxy"
	"github.com/xurenlu/sslcat/internal/security"
	"github.com/xurenlu/sslcat/internal/ssl"

	"io"

	"github.com/fsnotify/fsnotify"
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
	leRedirectHost   string
	lastLECheck      time.Time
	lastConfigHash   string
	// 导入配置暂存
	pendingImportJSON string
	pendingImport     *config.Config
	pendingDiff       *config.ConfigDiff
	// Token 管理
	tokenStore *security.TokenStore
	// 验证码管理
	captchaManager *CaptchaManager
	// PoW 管理器
	powManager *PowManager
	// DDoS 防护器
	ddosProtector  *ddos.Protector
	clusterManager ClusterManager
	// 审计轮转器
	auditRotator *logger.Rotator
	// 访问日志记录器
	accessLogger *logger.AccessLogger
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
	// 初始化 PoW 管理器
	server.powManager = NewPowManager()
	// 初始化 DDoS 防护器
	server.ddosProtector = ddos.NewProtector()

	// 初始化审计日志轮转器（10MB*10）
	if rot, err := logger.NewRotator("./data/audit.log", 10*1024*1024, 10); err == nil {
		server.auditRotator = rot
	}

	// 初始化访问日志记录器（可配置）
	if cfg.Server.AccessLogEnabled {
		format := logger.FormatNginx
		switch strings.ToLower(cfg.Server.AccessLogFormat) {
		case "apache":
			format = logger.FormatApache
		case "json":
			format = logger.FormatJSON
		}
		al, err := logger.NewAccessLogger(format, cfg.Server.AccessLogPath, true)
		if err == nil {
			// 覆盖默认大小/数量
			if cfg.Server.AccessLogMaxSize > 0 {
				al.SetMaxSize(cfg.Server.AccessLogMaxSize)
			}
			if cfg.Server.AccessLogMaxFiles > 0 {
				al.SetMaxFiles(cfg.Server.AccessLogMaxFiles)
			}
			server.accessLogger = al
		}
	}

	server.setupRoutes()

	// 初始化配置文件哈希并启动热加载监听（Slave 模式）
	server.initConfigWatch()

	// 启动定时检查有效LE证书对应域名是否解析到本机公网IP
	go server.refreshLEPreferredHostLoop()
	return server
}

// initConfigWatch 计算初始哈希并启动后台监听
func (s *Server) initConfigWatch() {
	path := s.config.ConfigFile
	if path == "" {
		path = "/etc/sslcat/sslcat.conf"
	}
	if b, err := os.ReadFile(path); err == nil {
		sum := sha256.Sum256(b)
		s.lastConfigHash = hex.EncodeToString(sum[:])
	}
	go s.watchConfigFileLoop()
	go s.watchConfigFileFS()
}

// watchConfigFileLoop 定时检查配置文件变化并热加载（仅在 Slave 模式生效）
func (s *Server) watchConfigFileLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if !s.config.IsSlaveMode() {
			continue
		}
		path := s.config.ConfigFile
		if path == "" {
			path = "/etc/sslcat/sslcat.conf"
		}
		b, err := os.ReadFile(path)
		if err != nil || len(b) == 0 {
			continue
		}
		sum := sha256.Sum256(b)
		hash := hex.EncodeToString(sum[:])
		if hash == s.lastConfigHash || hash == "" {
			continue
		}
		var newCfg config.Config
		if err := json.Unmarshal(b, &newCfg); err != nil {
			s.log.Warnf("Failed to parse synced config: %v", err)
			continue
		}
		// 保持配置文件路径
		newCfg.ConfigFile = s.config.ConfigFile
		// 应用新配置（就地更新）
		oldPrefix := s.config.AdminPrefix
		s.applyConfigInPlace(&newCfg)
		s.lastConfigHash = hash
		// 若前缀变化，重建路由
		if oldPrefix != s.config.AdminPrefix {
			s.mux = http.NewServeMux()
			s.setupRoutes()
		}
		s.log.Infof("Config reloaded from %s (cluster sync)", path)
	}
}

// watchConfigFileFS 使用 fsnotify 监听文件变化，触发热加载
func (s *Server) watchConfigFileFS() {
	// 仅 Slave 模式生效
	if !s.config.IsSlaveMode() {
		return
	}
	path := s.config.ConfigFile
	if path == "" {
		path = "/etc/sslcat/sslcat.conf"
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		s.log.Warnf("fsnotify init failed: %v", err)
		return
	}
	defer watcher.Close()

	dir := filepath.Dir(path)
	if err := watcher.Add(dir); err != nil {
		s.log.Warnf("fsnotify add failed: %v", err)
		return
	}
	for {
		select {
		case ev, ok := <-watcher.Events:
			if !ok {
				return
			}
			// 关注写入或重命名到目标文件
			if ev.Name == path && (ev.Op&fsnotify.Write == fsnotify.Write || ev.Op&fsnotify.Create == fsnotify.Create || ev.Op&fsnotify.Rename == fsnotify.Rename) {
				// 轻微延迟，等待写完成
				time.Sleep(150 * time.Millisecond)
				if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
					var newCfg config.Config
					if err := json.Unmarshal(b, &newCfg); err == nil {
						newCfg.ConfigFile = s.config.ConfigFile
						oldPrefix := s.config.AdminPrefix
						s.applyConfigInPlace(&newCfg)
						// 计算新哈希
						sum := sha256.Sum256(b)
						s.lastConfigHash = hex.EncodeToString(sum[:])
						if oldPrefix != s.config.AdminPrefix {
							s.mux = http.NewServeMux()
							s.setupRoutes()
						}
						s.log.Infof("Config reloaded by fsnotify from %s", path)
					}
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			s.log.Debugf("fsnotify error: %v", err)
		}
	}
}

// applyConfigInPlace 将 newCfg 内容拷贝到现有 s.config，保持指针不变
func (s *Server) applyConfigInPlace(newCfg *config.Config) {
	if newCfg == nil {
		return
	}
	// 顶层字段拷贝
	s.config.Server = newCfg.Server
	s.config.SSL = newCfg.SSL
	s.config.Admin = newCfg.Admin
	s.config.Proxy = newCfg.Proxy
	s.config.Security = newCfg.Security
	s.config.AdminPrefix = newCfg.AdminPrefix
	s.config.Cluster = newCfg.Cluster
	s.config.StaticSites = newCfg.StaticSites
	s.config.PHPSites = newCfg.PHPSites
	s.config.CDNCache = newCfg.CDNCache
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
	s.mux.HandleFunc(s.config.AdminPrefix+"/security/save", s.handleSecuritySave)
	s.mux.HandleFunc(s.config.AdminPrefix+"/security/blocked-ips", s.handleBlockedIPs)
	s.mux.HandleFunc(s.config.AdminPrefix+"/security/unblock", s.handleUnblock)

	// 系统设置路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/settings", s.handleSettings)
	s.mux.HandleFunc(s.config.AdminPrefix+"/settings/save", s.handleSettingsSave)
	s.mux.HandleFunc(s.config.AdminPrefix+"/settings/first-setup", s.handleFirstTimeSetup)
	s.mux.HandleFunc(s.config.AdminPrefix+"/settings/change-password", s.handleChangePassword)
	s.mux.HandleFunc(s.config.AdminPrefix+"/settings/totp", s.handleTOTPSetup)

	// CDN 缓存设置与管理
	s.mux.HandleFunc(s.config.AdminPrefix+"/cdn-cache", s.handleCDNCache)
	s.mux.HandleFunc(s.config.AdminPrefix+"/cdn-cache/save", s.handleCDNCacheSave)
	s.mux.HandleFunc(s.config.AdminPrefix+"/cdn-cache/clear", s.handleCDNCacheClear)

	// 静态站点管理
	s.mux.HandleFunc(s.config.AdminPrefix+"/static-sites", s.handleStaticSites)
	s.mux.HandleFunc(s.config.AdminPrefix+"/static-sites/add", s.handleStaticSitesAdd)
	s.mux.HandleFunc(s.config.AdminPrefix+"/static-sites/delete", s.handleStaticSitesDelete)

	// PHP 站点管理
	s.mux.HandleFunc(s.config.AdminPrefix+"/php-sites", s.handlePHPSites)
	s.mux.HandleFunc(s.config.AdminPrefix+"/php-sites/add", s.handlePHPSitesAdd)
	s.mux.HandleFunc(s.config.AdminPrefix+"/php-sites/delete", s.handlePHPSitesDelete)

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
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/security/attacks", s.handleAPISecurityAttacks)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/cdn-cache/stats", s.handleAPICDNCacheStats)
	// Prometheus 指标
	s.mux.HandleFunc("/metrics", s.handleMetrics)
	// 图形验证码
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/captcha/image", s.handleAPIImageCaptcha)
	// s.mux.HandleFunc(s.config.AdminPrefix+"/api/captcha", s.handleAPICaptcha) // 关闭验证码API

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
	// 若通过IP访问且存在可用的LE域名，强制跳转到 https://域名 + AdminPrefix（仅限管理面板路径或根）
	host := r.Host
	hostOnly := host
	if idx := strings.Index(host, ":"); idx != -1 {
		hostOnly = host[:idx]
	}
	if net.ParseIP(hostOnly) != nil {
		// 仅当访问管理面板路径时才重定向
		if s.leRedirectHost != "" && strings.HasPrefix(r.URL.Path, s.config.AdminPrefix) {
			target := "https://" + s.leRedirectHost + s.config.AdminPrefix
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}
	}

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

	// DDoS 防护检测（开启时才生效，但跳过管理面板登录）
	if s.config.Security.EnableDDOS && s.ddosProtector != nil && !strings.HasPrefix(r.URL.Path, s.config.AdminPrefix+"/login") {
		if blocked, reason := s.ddosProtector.CheckRequest(r); blocked {
			s.log.Warnf("DDoS protection blocked request from %s: %s", s.getClientIP(r), reason)
			http.Error(w, "Request blocked by DDoS protection", http.StatusTooManyRequests)
			return
		}
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

	// 若命中 PHP 站点，则先交给 PHP 处理
	if s.tryServePHP(w, r) {
		return true
	}

	// 若匹配静态站点，则直接本地文件服务
	if s.serveStatic(w, r) {
		return true
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
		w.Write([]byte("404 Not Found\n"))
		return true
	default: // "502"
		s.log.Warnf("Unmatched proxy for host=%s path=%s, returning 502", host, r.URL.Path)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("502 Bad Gateway\n"))
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
		"PublicIP":        s.fetchPublicIPv4(),
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
	// 使用轮转写入器（若可用）
	if s.auditRotator != nil {
		_, _ = s.auditRotator.Write(append(b, '\n'))
	} else {
		f, err := os.OpenFile("./data/audit.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			defer f.Close()
			f.Write(append(b, '\n'))
		}
	}
	if s.notifier != nil && s.notifier.Enabled() {
		m := map[string]any{"ts": t, "level": "info", "action": action, "detail": detail}
		s.notifier.SendJSON(m)
	}
}

// 保留扩展点：若未来需要根路径也跳转，可在此扩展

// 每30秒刷新一次首选LE域名（证书有效且解析到本机公网IP）
func (s *Server) refreshLEPreferredHostLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.refreshLEPreferredHost()
	}
}

func (s *Server) refreshLEPreferredHost() {
	if s.sslManager == nil {
		s.leRedirectHost = ""
		return
	}
	domain := s.sslManager.GetFirstValidLEDomain()
	if domain == "" {
		s.leRedirectHost = ""
		return
	}
	// 查询公网IP
	publicIP := s.fetchPublicIPv4()
	if publicIP == "" {
		// 获取不到公网IP，允许IP访问
		s.leRedirectHost = ""
		return
	}
	// DNS 解析 domain 并检查是否包含本机公网IP
	ips, err := net.LookupIP(domain)
	if err != nil {
		s.leRedirectHost = ""
		return
	}
	for _, ip := range ips {
		if ip.To4() != nil && ip.String() == publicIP {
			s.leRedirectHost = domain
			return
		}
	}
	s.leRedirectHost = ""
}

func (s *Server) fetchPublicIPv4() string {
	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", "https://ip4.dev/myip", nil)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	ip := strings.TrimSpace(string(b))
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

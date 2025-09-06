package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/i18n"
	"github.com/xurenlu/sslcat/internal/notify"
	"github.com/xurenlu/sslcat/internal/proxy"
	"github.com/xurenlu/sslcat/internal/security"
	"github.com/xurenlu/sslcat/internal/ssl"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/assets"
)

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
		logrus.Warnf("读取嵌入的 i18n 文件失败: %v", err)
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

	server.setupRoutes()
	return server
}

// setupRoutes 设置路由
func (s *Server) setupRoutes() {
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

	// 安全设置路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/security", s.handleSecurity)
	s.mux.HandleFunc(s.config.AdminPrefix+"/security/blocked-ips", s.handleBlockedIPs)
	s.mux.HandleFunc(s.config.AdminPrefix+"/security/unblock", s.handleUnblock)

	// 系统设置路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/settings", s.handleSettings)
	s.mux.HandleFunc(s.config.AdminPrefix+"/settings/save", s.handleSettingsSave)
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

	// 设置根路径
	s.mux.HandleFunc("/", s.handleRoot)
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
		s.log.Warnf("封禁的IP尝试访问: %s", clientIP)
		http.Error(w, "IP地址已被封禁", http.StatusForbidden)
		return false
	}

	// 检查User-Agent
	if strings.HasPrefix(path, s.config.AdminPrefix) && (userAgent == "" || s.isCommonBotUserAgent(userAgent)) {
		s.log.Warnf("可疑User-Agent访问管理面板: %s from %s", userAgent, clientIP)
		s.securityManager.LogAccess(clientIP, userAgent, path, false)
		http.Error(w, "访问被拒绝", http.StatusForbidden)
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
	if rule != nil {
		// 执行代理
		s.proxyManager.ProxyRequest(w, r, rule)
		return true
	}

	// 没有找到代理配置，返回默认页面
	s.handleDefault(w, r, host)
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

func (s *Server) processLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// 计算有效管理员密码：优先使用密码文件，其次使用配置中的密码
	effective := s.getEffectiveAdminPassword()

	// 验证用户名和密码
	if username == s.config.Admin.Username && password == effective {
		// 设置session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "sslcat_session",
			Value:    "authenticated",
			Path:     "/",
			MaxAge:   3600 * 8, // 8小时
			HttpOnly: true,
			Secure:   r.TLS != nil,
		})

		// 审计
		s.audit("login_success", "admin")

		// 如果首次运行或未设置过密码文件，要求强制修改密码
		if s.needForcePasswordReset() {
			http.Redirect(w, r, s.config.AdminPrefix+"/settings/change-password", http.StatusFound)
			return
		}
		// 若处于首启向导状态
		if s.needWizard() {
			http.Redirect(w, r, s.config.AdminPrefix+"/wizard", http.StatusFound)
			return
		}

		// 重定向到仪表板
		http.Redirect(w, r, s.config.AdminPrefix+"/dashboard", http.StatusFound)
		return
	}

	// 登录失败，记录安全日志
	clientIP := s.getClientIP(r)
	s.securityManager.LogAccess(clientIP, r.Header.Get("User-Agent"), r.URL.Path, false)
	s.audit("login_failed", clientIP)

	// 显示错误页面（带紧急修复链接，模板内根据 Error 判断显示链接）
	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"Error":       s.translator.T("login.invalid"),
	}
	s.templateRenderer.DetectLanguageAndRender(w, r, "login.html", data)
}

func (s *Server) getEffectiveAdminPassword() string {
	passFile := s.config.Admin.PasswordFile
	if passFile != "" {
		if b, err := os.ReadFile(passFile); err == nil {
			trim := strings.TrimSpace(string(b))
			if trim != "" {
				return trim
			}
		}
	}
	return s.config.Admin.Password
}

func (s *Server) needForcePasswordReset() bool {
	// 若 admin.pass 不存在，或内容与默认密码一致，则需要强制修改
	passFile := s.config.Admin.PasswordFile
	if passFile == "" {
		return true
	}
	b, err := os.ReadFile(passFile)
	if err != nil {
		return true
	}
	stored := strings.TrimSpace(string(b))
	return stored == "" || stored == "admin*9527"
}

// 页面处理器

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, s.config.AdminPrefix, http.StatusFound)
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	// 检查是否已登录
	if !s.checkAuth(w, r) {
		return
	}

	// 重定向到仪表板
	http.Redirect(w, r, s.config.AdminPrefix+"/dashboard", http.StatusFound)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		data := map[string]interface{}{
			"AdminPrefix": s.config.AdminPrefix,
			"Error":       "",
		}
		s.templateRenderer.DetectLanguageAndRender(w, r, "login.html", data)
		return
	}

	if r.Method == "POST" {
		s.processLogin(w, r)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// 清除session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "sslcat_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	// 重定向到登录页面
	http.Redirect(w, r, s.config.AdminPrefix+"/login", http.StatusFound)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// 检查认证
	if !s.checkAuth(w, r) {
		return
	}

	stats := s.getSystemStats()

	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"Stats":       stats,
		"GoVersion":   runtime.Version(),
	}

	s.templateRenderer.DetectLanguageAndRender(w, r, "dashboard.html", data)
}

func (s *Server) handleMobile(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	stats := s.getSystemStats()

	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"Stats":       stats,
	}
	s.templateRenderer.DetectLanguageAndRender(w, r, "mobile.html", data)
}

func (s *Server) handleCharts(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	stats := s.getSystemStats()

	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"Stats":       stats,
	}
	s.templateRenderer.DetectLanguageAndRender(w, r, "charts.html", data)
}

func (s *Server) handleDefault(w http.ResponseWriter, r *http.Request, domain string) {
	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"Domain":      domain,
	}
	s.templateRenderer.DetectLanguageAndRender(w, r, "default.html", data)
}

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
					s.log.Warnf("预取证书失败 %s: %v", domain, err)
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
		http.Error(w, "无效的规则索引", http.StatusBadRequest)
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
					s.log.Warnf("预取证书失败 %s: %v", domain, err)
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
		http.Error(w, "无效的规则索引", http.StatusBadRequest)
		return
	}

	// 删除规则
	s.config.Proxy.Rules = append(s.config.Proxy.Rules[:index], s.config.Proxy.Rules[index+1:]...)

	// 保存配置
	s.config.Save(s.config.ConfigFile)

	// 重定向回代理管理页面
	http.Redirect(w, r, s.config.AdminPrefix+"/proxy", http.StatusFound)
}

// SSL管理

func (s *Server) handleSSL(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 获取SSL证书信息（扫描磁盘）
	certs := s.sslManager.ListCertificatesFromDisk()

	data := map[string]interface{}{
		"AdminPrefix":  s.config.AdminPrefix,
		"Certificates": certs,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateSSLManagementHTML(data)
	w.Write([]byte(html))
}

func (s *Server) handleSSLGenerate(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method == "POST" {
		domains := r.FormValue("domains")
		if domains != "" {
			domainList := strings.Split(domains, ",")
			for i, domain := range domainList {
				domainList[i] = strings.TrimSpace(domain)
			}

			// 生成证书
			_, err := s.sslManager.GenerateMultiDomainCert(domainList)
			if err != nil {
				s.log.Errorf("生成证书失败: %v", err)
				http.Error(w, "生成证书失败: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// 重定向回SSL管理页面
			http.Redirect(w, r, s.config.AdminPrefix+"/ssl", http.StatusFound)
			return
		}
	}

	// 显示生成表单
	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateSSLGenerateHTML(data)
	w.Write([]byte(html))
}

func (s *Server) handleSSLUpload(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	switch r.Method {
	case "GET":
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>上传证书</title>
		<link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head><body>
		<div class="container mt-4"><h3>上传证书</h3>
		<form method="POST" enctype="multipart/form-data" class="mt-3">
			<div class="mb-3">
				<label class="form-label">域名</label>
				<input class="form-control" name="domain" required>
			</div>
			<div class="mb-3">
				<label class="form-label">证书(.crt/.pem)</label>
				<input class="form-control" type="file" name="cert" accept=".crt,.pem" required>
			</div>
			<div class="mb-3">
				<label class="form-label">私钥(.key/.pem)</label>
				<input class="form-control" type="file" name="key" accept=".key,.pem" required>
			</div>
			<button class="btn btn-primary" type="submit">上传</button>
			<a class="btn btn-secondary" href="%s/ssl">返回</a>
		</form></div></body></html>`, s.config.AdminPrefix)
		return
	case "POST":
		domain := strings.TrimSpace(r.FormValue("domain"))
		if domain == "" {
			http.Error(w, "缺少domain", http.StatusBadRequest)
			return
		}

		certFile, _, err := r.FormFile("cert")
		if err != nil {
			http.Error(w, "读取证书失败", http.StatusBadRequest)
			return
		}
		defer certFile.Close()
		keyFile, _, err := r.FormFile("key")
		if err != nil {
			http.Error(w, "读取私钥失败", http.StatusBadRequest)
			return
		}
		defer keyFile.Close()

		certPath := s.config.SSL.CertDir + "/" + domain + ".crt"
		keyPath := s.config.SSL.KeyDir + "/" + domain + ".key"

		if err := writeAllFromReader(certFile, certPath, 0644); err != nil {
			http.Error(w, "保存证书失败", http.StatusInternalServerError)
			return
		}
		if err := writeAllFromReader(keyFile, keyPath, 0600); err != nil {
			http.Error(w, "保存私钥失败", http.StatusInternalServerError)
			return
		}

		if err := s.sslManager.LoadCertificateFromDisk(domain); err != nil {
			s.log.Warnf("上传后加载证书失败: %v", err)
		}
		http.Redirect(w, r, s.config.AdminPrefix+"/ssl", http.StatusFound)
		return
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func (s *Server) handleSSLDownload(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	typ := strings.TrimSpace(r.URL.Query().Get("type"))
	if domain == "" {
		http.Error(w, "缺少domain", http.StatusBadRequest)
		return
	}
	if typ == "" {
		typ = "cert"
	}

	var path, filename string
	switch typ {
	case "cert":
		path, filename = s.config.SSL.CertDir+"/"+domain+".crt", domain+".crt"
	case "key":
		path, filename = s.config.SSL.KeyDir+"/"+domain+".key", domain+".key"
	case "bundle":
		path, filename = s.config.SSL.CertDir+"/"+domain+".crt", domain+"-bundle.pem"
	default:
		http.Error(w, "type无效", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	http.ServeFile(w, r, path)
}

func writeAllFromReader(rdr interface{ Read([]byte) (int, error) }, dest string, mode os.FileMode) error {
	data := make([]byte, 0, 64*1024)
	buf := make([]byte, 32*1024)
	for {
		n, err := rdr.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if err != nil {
			break
		}
		if n == 0 {
			break
		}
	}
	return os.WriteFile(dest, data, mode)
}

func (s *Server) handleSSLDelete(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain != "" {
		err := s.sslManager.DeleteCertificate(domain)
		if err != nil {
			s.log.Errorf("删除证书失败: %v", err)
			http.Error(w, "删除证书失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// 重定向回SSL管理页面
	http.Redirect(w, r, s.config.AdminPrefix+"/ssl", http.StatusFound)
}

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

// 忘记密码紧急修复页面
func (s *Server) handleRecoverHelp(w http.ResponseWriter, r *http.Request) {
	// 无需登录，允许直接访问
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 多语言内容使用 translator
	title := s.translator.T("recover.title")
	intro := s.translator.T("recover.intro")
	s1 := s.translator.T("recover.step1")
	s2 := s.translator.T("recover.step2")
	s3 := s.translator.T("recover.step3")
	s4 := s.translator.T("recover.step4")
	paths := s.translator.T("recover.paths")
	cmds := s.translator.T("recover.commands")
	back := s.translator.T("recover.back_to_login")
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>%s</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head><body>
    <div class="container mt-4">
      <h3>%s</h3>
      <p class="text-muted">%s</p>
      <ol>
        <li>%s</li>
        <li>%s</li>
        <li>%s</li>
        <li>%s</li>
      </ol>
      <div class="alert alert-secondary"><strong>Info</strong><br>%s<br>%s</div>
      <a class="btn btn-primary" href="%s/login">%s</a>
    </div></body></html>`, title, title, intro, s1, s2, s3, s4, paths, cmds, s.config.AdminPrefix, back)
}

// 系统设置

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"Config":      s.config,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateSettingsHTML(data)
	w.Write([]byte(html))
}

func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method == "POST" {
		// 更新配置
		if newPrefix := r.FormValue("admin_prefix"); newPrefix != "" {
			s.config.AdminPrefix = newPrefix
		}

		if newUsername := r.FormValue("admin_username"); newUsername != "" {
			s.config.Admin.Username = newUsername
		}

		if newPassword := r.FormValue("admin_password"); newPassword != "" {
			s.config.Admin.Password = newPassword
		}

		// SSL 邮箱与禁用自签
		if v := strings.TrimSpace(r.FormValue("ssl_email")); v != "" {
			s.config.SSL.Email = v
			// 尝试启用 ACME
			if err := s.sslManager.EnableACME(); err != nil {
				s.log.Warnf("启用 ACME 失败: %v", err)
			}
		}
		if v := r.FormValue("ssl_disable_self_signed"); v != "" {
			s.config.SSL.DisableSelfSigned = (v == "on" || v == "true" || v == "1")
		}

		// 保存配置
		s.config.Save(s.config.ConfigFile)
	}

	// 重定向回设置页面
	http.Redirect(w, r, s.config.AdminPrefix+"/settings", http.StatusFound)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method == "GET" {
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>修改密码</title>
		<link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head><body>
		<div class="container mt-4"><h3>首次登录，请设置新密码</h3>
		<form method="POST">
			<div class="mb-3"><label class="form-label">新密码</label><input class="form-control" type="password" name="new" required></div>
			<div class="mb-3"><label class="form-label">确认新密码</label><input class="form-control" type="password" name="confirm" required></div>
			<button class="btn btn-primary" type="submit">保存</button>
			<a class="btn btn-secondary ms-2" href="%s/logout">退出</a>
		</form></div></body></html>`, s.config.AdminPrefix)
		return
	}
	if r.Method == "POST" {
		newp := r.FormValue("new")
		conf := r.FormValue("confirm")
		if newp == "" || newp != conf {
			http.Error(w, "密码不一致或为空", http.StatusBadRequest)
			return
		}
		// 更新内存与持久化密码文件
		s.config.Admin.Password = "" // 避免将明文写入 withssl.conf
		if err := os.WriteFile(s.config.Admin.PasswordFile, []byte(newp+"\n"), 0600); err != nil {
			http.Error(w, "写入密码文件失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// 保存配置（不包含密码）
		if err := s.config.Save(s.config.ConfigFile); err != nil {
			http.Error(w, "保存配置失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, s.config.AdminPrefix+"/dashboard", http.StatusFound)
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// API处理器

func (s *Server) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	stats := s.getSystemStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleAPIProxyRules(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.config.Proxy.Rules)
}

func (s *Server) handleAPISSLCerts(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	certs := s.sslManager.ListCertificatesFromDisk()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(certs)
}

func (s *Server) handleAPISecurityLogs(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
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
	if !s.checkAuth(w, r) {
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

// 工具函数

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

// HTML生成函数

func (s *Server) generateProxyManagementHTML(data map[string]interface{}) string {
	title := s.translator.T("proxy.title")
	addRule := s.translator.T("proxy.add_rule")
	thDomain := s.translator.T("proxy.domain")
	thTarget := s.translator.T("proxy.target")
	thStatus := s.translator.T("proxy.status")
	thActions := s.translator.T("proxy.actions")
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">%s</h1>
                    <a href="%s/proxy/add" class="btn btn-primary">
                        <i class="bi bi-plus-circle"></i> %s
                    </a>
                </div>
                
                <div class="card">
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>%s</th>
                                        <th>%s</th>
                                        <th>%s</th>
                                        <th>%s</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    %s
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>
    <script src="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>`,
		title,
		s.generateSidebar(data["AdminPrefix"].(string), "proxy"),
		title,
		data["AdminPrefix"].(string),
		addRule,
		thDomain,
		thTarget,
		thStatus,
		thActions,
		s.generateProxyRulesTable(data))
}

func (s *Server) generateProxyRulesTable(data map[string]interface{}) string {
	rules, ok := data["Rules"].([]config.ProxyRule)
	if !ok || len(rules) == 0 {
		return `<tr><td colspan="4" class="text-center">` + s.translator.T("proxy.no_rules") + `</td></tr>`
	}

	var rows strings.Builder
	for i, rule := range rules {
		rows.WriteString(fmt.Sprintf(`
                    <tr>
                        <td>%s</td>
                        <td>%s</td>
                        <td><span class="badge bg-success">`+s.translator.T("proxy.active")+`</span></td>
                        <td>
                            <a href="%s/proxy/edit?index=%d" class="btn btn-sm btn-outline-primary">`+s.translator.T("proxy.edit")+`</a>
                            <a href="%s/proxy/delete?index=%d" class="btn btn-sm btn-outline-danger" onclick="return confirm('`+s.translator.T("proxy.delete_confirm")+`')">`+s.translator.T("proxy.delete")+`</a>
                        </td>
                    </tr>`,
			rule.Domain, rule.Target, data["AdminPrefix"].(string), i, data["AdminPrefix"].(string), i))
	}
	return rows.String()
}

func (s *Server) generateProxyAddHTML(data map[string]interface{}) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>添加代理规则 - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">添加代理规则</h1>
                    <a href="%s/proxy" class="btn btn-secondary">返回</a>
                </div>
                
                <div class="card">
                    <div class="card-body">
                        <form method="POST">
                            <div class="mb-3">
                                <label for="domain" class="form-label">域名</label>
                                <input type="text" class="form-control" id="domain" name="domain" required 
                                       placeholder="example.com">
                                <div class="form-text">输入要代理的域名，支持通配符 *.example.com</div>
                            </div>
                            <div class="mb-3">
                                <label for="target" class="form-label">目标地址</label>
                                <input type="text" class="form-control" id="target" name="target" required 
                                       placeholder="http://192.168.1.100:8080">
                                <div class="form-text">输入后端服务地址，包括协议和端口</div>
                            </div>
                            <button type="submit" class="btn btn-primary">添加规则</button>
                            <a href="%s/proxy" class="btn btn-secondary">取消</a>
                        </form>
                    </div>
                </div>
            </main>
        </div>
    </div>
</body>
</html>`,
		s.generateSidebar(data["AdminPrefix"].(string), "proxy"),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string))
}

func (s *Server) generateProxyEditHTML(data map[string]interface{}) string {
	rule := data["Rule"].(config.ProxyRule)
	_ = data["Index"].(int)

	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>编辑代理规则 - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">编辑代理规则</h1>
                    <a href="%s/proxy" class="btn btn-secondary">返回</a>
                </div>
                
                <div class="card">
                    <div class="card-body">
                        <form method="POST">
                            <div class="mb-3">
                                <label for="domain" class="form-label">域名</label>
                                <input type="text" class="form-control" id="domain" name="domain" required 
                                       value="%s">
                            </div>
                            <div class="mb-3">
                                <label for="target" class="form-label">目标地址</label>
                                <input type="text" class="form-control" id="target" name="target" required 
                                       value="%s">
                            </div>
                            <button type="submit" class="btn btn-primary">保存更改</button>
                            <a href="%s/proxy" class="btn btn-secondary">取消</a>
                        </form>
                    </div>
                </div>
            </main>
        </div>
    </div>
</body>
</html>`,
		s.generateSidebar(data["AdminPrefix"].(string), "proxy"),
		data["AdminPrefix"].(string),
		rule.Domain,
		rule.Target,
		data["AdminPrefix"].(string))
}

func (s *Server) generateSSLManagementHTML(data map[string]interface{}) string {
	title := s.translator.T("ssl.title")
	genBtn := s.translator.T("ssl.generate")
	thDomain := s.translator.T("ssl.columns.domain")
	thIssued := s.translator.T("ssl.columns.issued")
	thExpires := s.translator.T("ssl.columns.expires")
	thStatus := s.translator.T("ssl.columns.status")
	thActions := s.translator.T("ssl.columns.actions")
	thType := s.translator.T("ssl.columns.type")
	uploadTitle := s.translator.T("ssl.upload_title")
	uploadNote := s.translator.T("ssl.upload_note")
	uploadBtn := s.translator.T("ssl.upload_button")
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">%s</h1>
                    <a href="%s/ssl/generate" class="btn btn-primary">
                        <i class="bi bi-plus-circle"></i> %s
                    </a>
                </div>
                
                <div class="card mb-3">
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>%s</th>
                                        <th>%s</th>
                                        <th>%s</th>
                                        <th>%s</th>
                                        <th>%s</th>
                                        <th>%s</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    %s
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">%s</h5>
                        <p class="text-muted">%s</p>
                        <a class="btn btn-outline-primary" href="%s/ssl/upload">%s</a>
                    </div>
                </div>
            </main>
        </div>
    </div>
    <script src="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>`,
		title,
		s.generateSidebar(data["AdminPrefix"].(string), "ssl"),
		title,
		data["AdminPrefix"].(string),
		genBtn,
		thDomain, thIssued, thExpires, thStatus, thActions, thType,
		s.generateSSLCertsTable(data),
		uploadTitle, uploadNote,
		data["AdminPrefix"].(string), uploadBtn)
}

func (s *Server) generateSSLCertsTable(data map[string]interface{}) string {
	certs, _ := data["Certificates"].([]ssl.CertificateInfo)
	if len(certs) == 0 {
		return `<tr><td colspan="5" class="text-center">` + s.translator.T("ssl.none") + `</td></tr>`
	}
	var b strings.Builder
	for _, c := range certs {
		ctype := s.translator.T("ssl.type.ca")
		if c.SelfSigned {
			ctype = s.translator.T("ssl.type.self_signed")
		}
		b.WriteString(fmt.Sprintf(`
			<tr>
				<td>%s</td>
				<td>%s</td>
				<td>%s</td>
				<td>%s</td>
				<td>%s</td>
				<td>
					<a class="btn btn-sm btn-outline-primary" href="%s/ssl/download?domain=%s&type=cert">`+s.translator.T("ssl.download_cert")+`</a>
					<a class="btn btn-sm btn-outline-secondary" href="%s/ssl/download?domain=%s&type=key">`+s.translator.T("ssl.download_key")+`</a>
					<a class="btn btn-sm btn-outline-danger" href="%s/ssl/delete?domain=%s" onclick="return confirm('`+s.translator.T("ssl.delete_confirm")+`')">`+s.translator.T("proxy.delete")+`</a>
				</td>
			</tr>`,
			c.Domain,
			c.IssuedAt.Format("2006-01-02"),
			c.ExpiresAt.Format("2006-01-02"),
			c.Status,
			ctype,
			data["AdminPrefix"].(string), c.Domain,
			data["AdminPrefix"].(string), c.Domain,
			data["AdminPrefix"].(string), c.Domain,
		))
	}
	return b.String()
}

func (s *Server) generateSSLGenerateHTML(data map[string]interface{}) string {
	pageTitle := s.translator.T("ssl.generate")
	back := s.translator.T("common.back")
	labelDomains := s.translator.T("ssl.domain")
	help := s.translator.T("ssl.generate_help")
	btnGenerate := s.translator.T("ssl.generate")
	btnCancel := s.translator.T("proxy.cancel")
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">%s</h1>
                    <a href="%s/ssl" class="btn btn-secondary">%s</a>
                </div>
                
                <div class="card">
                    <div class="card-body">
                        <form method="POST">
                            <div class="mb-3">
                                <label for="domains" class="form-label">%s</label>
                                <textarea class="form-control" id="domains" name="domains" rows="4" required 
                                         placeholder="example.com, www.example.com, *.example.com"></textarea>
                                <div class="form-text">%s</div>
                            </div>
                            <button type="submit" class="btn btn-primary">%s</button>
                            <a href="%s/ssl" class="btn btn-secondary">%s</a>
                        </form>
                    </div>
                </div>
            </main>
        </div>
    </div>
</body>
</html>`,
		pageTitle,
		s.generateSidebar(data["AdminPrefix"].(string), "ssl"),
		pageTitle,
		data["AdminPrefix"].(string), back,
		labelDomains,
		help,
		btnGenerate,
		data["AdminPrefix"].(string), btnCancel)
}

func (s *Server) generateSecurityManagementHTML(data map[string]interface{}) string {
	title := s.translator.T("security.title")
	blockedIPs := s.translator.T("security.blocked_ips")
	thIP := s.translator.T("security.ip")
	thBlockTime := s.translator.T("security.block_time")
	thActions := s.translator.T("security.actions")
	securityConfig := s.translator.T("security.config")
	maxAttempts := s.translator.T("security.max_attempts")
	maxAttempts5 := s.translator.T("security.max_attempts_5min")
	blockDuration := s.translator.T("security.block_duration")
	uaCheck := s.translator.T("security.ua_check")
	auditLog := s.translator.T("security.audit_log")
	exportJSON := s.translator.T("security.export_json")
	auditTime := s.translator.T("audit.time")
	auditUser := s.translator.T("audit.user_ip")
	auditAction := s.translator.T("audit.action")
	auditDetail := s.translator.T("audit.detail")
	loading := s.translator.T("security.loading")
	noRecords := s.translator.T("security.no_records")
	loadFailed := s.translator.T("security.load_failed")
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">%s</h1>
                </div>
                
                <div class="row">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">%s</h5>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-sm">
                                        <thead>
                                            <tr>
                                                <th>%s</th>
                                                <th>%s</th>
                                                <th>%s</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            %s
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">%s</h5>
                            </div>
                            <div class="card-body">
                                <p><strong>%s:</strong> 3/1min</p>
                                <p><strong>%s:</strong> 10/5min</p>
                                <p><strong>%s:</strong> 1h</p>
                                <p><strong>%s:</strong> ON</p>
                            </div>
                        </div>
                    </div>
                </div>
 
                <div class="row mt-3">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h5 class="mb-0">%s</h5>
                                <a class="btn btn-sm btn-outline-secondary" href="%s/api/audit?download=1">%s</a>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-sm table-striped">
                                        <thead>
                                            <tr>
                                                <th style="width: 22%%">%s</th>
                                                <th style="width: 18%%">%s</th>
                                                <th style="width: 20%%">%s</th>
                                                <th>%s</th>
                                            </tr>
                                        </thead>
                                        <tbody id="audit-body">
                                            <tr><td colspan="4" class="text-center text-muted">%s</td></tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>
    <script src="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    (function(){
      fetch('%s/api/audit').then(r=>r.json()).then(data=>{
        const body = document.getElementById('audit-body');
        body.innerHTML = '';
        const logs = (data && data.logs) || [];
        if (logs.length === 0) {
          body.innerHTML = '<tr><td colspan="4" class="text-center text-muted">%s</td></tr>';
          return;
        }
        logs.slice(-100).forEach(it=>{
          const tr = document.createElement('tr');
          tr.innerHTML = '<td>'+(it.time||'')+'</td>'+
                         '<td>'+(it.user||'')+'</td>'+
                         '<td>'+(it.action||'')+'</td>'+
                         '<td><code>'+(it.detail||'')+'</code></td>';
          body.appendChild(tr);
        });
      }).catch(()=>{
        const body = document.getElementById('audit-body');
        body.innerHTML = '<tr><td colspan="4" class="text-center text-muted">%s</td></tr>';
      });
    })();
    </script>
</body>
</html>`,
		title,
		s.generateSidebar(data["AdminPrefix"].(string), "security"),
		title,
		blockedIPs,
		thIP, thBlockTime, thActions,
		s.generateBlockedIPsTable(data),
		securityConfig,
		maxAttempts, maxAttempts5, blockDuration, uaCheck,
		auditLog, data["AdminPrefix"].(string), exportJSON,
		auditTime, auditUser, auditAction, auditDetail, loading,
		data["AdminPrefix"].(string), noRecords, loadFailed)
}

func (s *Server) generateBlockedIPsTable(data map[string]interface{}) string {
	// 暂时返回示例，实际应该从SecurityManager获取
	return `<tr><td colspan="3" class="text-center">` + s.translator.T("security.no_blocked") + `</td></tr>`
}

func (s *Server) generateSettingsHTML(data map[string]interface{}) string {
	title := s.translator.T("settings.title")
	adminPrefixLabel := s.translator.T("settings.admin_prefix")
	adminUserLabel := s.translator.T("settings.admin_username")
	adminPassLabel := s.translator.T("settings.admin_password")
	saveBtn := s.translator.T("settings.save")
	exportBtn := s.translator.T("settings.export")
	importPreview := s.translator.T("settings.import_preview")
	viewLastDiff := s.translator.T("settings.view_last_diff")
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">%s</h1>
                </div>
                
                <div class="card">
                    <div class="card-body">
                        <form method="POST" action="%s/settings/save">
                            <h5 class="mb-3">系统设置</h5>
                            <div class="mb-3">
                                <label for="admin_prefix" class="form-label">%s</label>
                                <input type="text" class="form-control" id="admin_prefix" name="admin_prefix" 
                                       value="%s">
                            </div>
                            <div class="mb-3">
                                <label for="admin_username" class="form-label">%s</label>
                                <input type="text" class="form-control" id="admin_username" name="admin_username" 
                                       value="%s">
                            </div>
                            <div class="mb-3">
                                <label for="admin_password" class="form-label">%s</label>
                                <input type="password" class="form-control" id="admin_password" name="admin_password" 
                                       placeholder="留空表示不修改">
                            </div>
                            <hr>
                            <h5 class="mb-3">SSL 设置</h5>
                            <div class="mb-3">
                                <label for="ssl_email" class="form-label">ACME 邮箱（Let's Encrypt）</label>
                                <input type="email" class="form-control" id="ssl_email" name="ssl_email" value="%s" placeholder="admin@example.com">
                                <div class="form-text">填写有效邮箱以启用 ACME 自动签发与到期提醒</div>
                            </div>
                            <div class="form-check form-switch mb-3">
                                <input class="form-check-input" type="checkbox" id="ssl_disable_self_signed" name="ssl_disable_self_signed" %s>
                                <label class="form-check-label" for="ssl_disable_self_signed">禁用自签名证书回退</label>
                            </div>
                            <button type="submit" class="btn btn-primary">%s</button>
                            <a href="%s/config/export" class="btn btn-outline-secondary ms-2">%s</a>
                            <a href="%s/config/import" class="btn btn-outline-primary ms-2">%s</a>
                            <a href="%s/config/preview" class="btn btn-warning ms-2">%s</a>
                        </form>
                    </div>
                </div>
            </main>
        </div>
    </div>
</body>
</html>`,
		title,
		s.generateSidebar(data["AdminPrefix"].(string), "settings"),
		title,
		data["AdminPrefix"].(string),
		adminPrefixLabel,
		data["AdminPrefix"].(string),
		adminUserLabel,
		s.config.Admin.Username,
		adminPassLabel,
		s.config.SSL.Email,
		func() string {
			if s.config.SSL.DisableSelfSigned {
				return "checked"
			}
			return ""
		}(),
		saveBtn,
		data["AdminPrefix"].(string), exportBtn,
		data["AdminPrefix"].(string), importPreview,
		data["AdminPrefix"].(string), viewLastDiff)
}

func (s *Server) generateSidebar(adminPrefix, activePage string) string {
	title := s.translator.T("app.description")
	navDashboard := s.translator.T("nav.dashboard")
	navProxy := s.translator.T("nav.proxy")
	navSSL := s.translator.T("nav.ssl")
	navSecurity := s.translator.T("nav.security")
	navSettings := s.translator.T("nav.settings")
	logout := s.translator.T("menu.logout")
	official := s.translator.T("menu.official_site")
	return fmt.Sprintf(`
                <nav class="d-md-block sidebar collapse">
                    <div class="position-sticky pt-3">
                        <div class="text-center mb-4">
                            <h4 class="navbar-brand text-primary">SSLcat</h4>
                            <small class="text-muted">%s</small>
                            <div class="mt-2">
                                <a class="btn btn-sm btn-outline-primary" href="https://sslcat.com" target="_blank" rel="noopener">%s</a>
                            </div>
                        </div>
                        
                        <div class="dropdown mb-3 px-3">
                            <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">
                                语言 Language
                            </button>
                            <ul class="dropdown-menu">
                                <li><a class="dropdown-item" href="?lang=zh-CN">简体中文</a></li>
                                <li><a class="dropdown-item" href="?lang=en-US">English</a></li>
                                <li><a class="dropdown-item" href="?lang=ja-JP">日本語</a></li>
                                <li><a class="dropdown-item" href="?lang=es-ES">Español</a></li>
                                <li><a class="dropdown-item" href="?lang=fr-FR">Français</a></li>
                                <li><a class="dropdown-item" href="?lang=ru-RU">Русский</a></li>
                            </ul>
                        </div>
                        
                        <ul class="nav flex-column">
                            <li class="nav-item">
                                <a class="nav-link %s" href="%s/">
                                    <i class="bi bi-speedometer2"></i> %s
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link %s" href="%s/proxy">
                                    <i class="bi bi-arrow-left-right"></i> %s
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link %s" href="%s/ssl">
                                    <i class="bi bi-shield-lock"></i> %s
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link %s" href="%s/security">
                                    <i class="bi bi-shield-check"></i> %s
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link %s" href="%s/settings">
                                    <i class="bi bi-gear"></i> %s
                                </a>
                            </li>
                        </ul>
                        
                        <hr>
                        <div class="dropdown">
                            <a href="%s/logout" class="btn btn-outline-danger btn-sm">
                                <i class="bi bi-box-arrow-right"></i> %s
                            </a>
                        </div>
                    </div>
                </nav>`,
		title,
		official,
		func() string {
			if activePage == "dashboard" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navDashboard,
		func() string {
			if activePage == "proxy" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navProxy,
		func() string {
			if activePage == "ssl" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navSSL,
		func() string {
			if activePage == "security" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navSecurity,
		func() string {
			if activePage == "settings" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navSettings,
		adminPrefix,
		logout)
}

func (s *Server) handleConfigExport(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	data, err := json.MarshalIndent(s.config, "", "  ")
	if err != nil {
		http.Error(w, "导出配置失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	filename := "sslcat-" + time.Now().Format("20060102-150405") + ".json"
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Write(data)
}

func (s *Server) handleConfigImport(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method == "GET" {
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>导入配置</title>
		<link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head><body>
		<div class="container mt-4"><h3>导入配置(JSON)</h3>
		<form method="POST" enctype="multipart/form-data" class="mt-3">
			<div class="mb-3">
				<label class="form-label">选择JSON文件</label>
				<input class="form-control" type="file" name="file" accept="application/json">
			</div>
			<div class="mb-3">
				<label class="form-label">或直接粘贴JSON</label>
				<textarea class="form-control" name="json" rows="10"></textarea>
			</div>
			<button class="btn btn-primary" type="submit">预览变更</button>
			<a class="btn btn-secondary" href="%s/settings">返回</a>
		</form></div></body></html>`, s.config.AdminPrefix)
		return
	}
	// POST
	var payload []byte
	if f, _, err := r.FormFile("file"); err == nil {
		defer f.Close()
		buf := make([]byte, 0, 64*1024)
		tmp := make([]byte, 32*1024)
		for {
			n, er := f.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if er != nil {
				break
			}
		}
		payload = buf
	} else {
		payload = []byte(r.FormValue("json"))
	}
	if len(payload) == 0 {
		http.Error(w, "未提供配置", http.StatusBadRequest)
		return
	}
	var proposed config.Config
	if err := json.Unmarshal(payload, &proposed); err != nil {
		http.Error(w, "JSON解析失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	// 保存到pending
	s.pendingImportJSON = string(payload)
	s.pendingImport = &proposed
	d := config.CompareConfigs(s.config, &proposed)
	s.pendingDiff = &d
	http.Redirect(w, r, s.config.AdminPrefix+"/config/preview", http.StatusFound)
}

func (s *Server) handleConfigPreview(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if s.pendingImport == nil || s.pendingDiff == nil {
		http.Error(w, "没有待预览的配置", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(s.renderDiffHTML(*s.pendingDiff)))
}

func (s *Server) renderDiffHTML(d config.ConfigDiff) string {
	section := func(title string, rows []config.KeyChange) string {
		if len(rows) == 0 {
			return ""
		}
		b := &strings.Builder{}
		fmt.Fprintf(b, `<div class="card mb-3">
		<div class="card-header fw-bold">%s</div>
		<div class="card-body p-0">
		<table class="table table-striped table-hover mb-0">
		<thead><tr><th style="width:35%%">键</th><th style="width:32.5%%">当前</th><th style="width:32.5%%">导入</th></tr></thead><tbody>`, title)
		for _, r := range rows {
			fmt.Fprintf(b, `<tr><td class="text-muted">%s</td><td><code>%s</code></td><td><code>%s</code></td></tr>`, r.Key, htmlEscape(r.Old), htmlEscape(r.New))
		}
		b.WriteString(`</tbody></table></div></div>`)
		return b.String()
	}

	proxySection := func(d config.ConfigDiff) string {
		if len(d.ProxyAdded)+len(d.ProxyRemoved)+len(d.ProxyModified) == 0 {
			return ""
		}
		b := &strings.Builder{}
		b.WriteString(`<div class="card mb-3">
		<div class="card-header fw-bold">Proxy 规则变更</div>
		<div class="card-body">
		`)
		if len(d.ProxyAdded) > 0 {
			b.WriteString(`<div class="mb-2"><span class="badge bg-success me-1">新增</span></div>`)
			b.WriteString(`<ul class="list-group mb-3">`)
			for _, a := range d.ProxyAdded {
				fmt.Fprintf(b, `<li class="list-group-item"><span class="text-success">+ %s</span> → target=%s port=%d enabled=%t ssl_only=%t</li>`, htmlEscape(a.Domain), htmlEscape(a.Target), a.Port, a.Enabled, a.SSLOnly)
			}
			b.WriteString(`</ul>`)
		}
		if len(d.ProxyRemoved) > 0 {
			b.WriteString(`<div class="mb-2"><span class="badge bg-danger me-1">删除</span></div>`)
			b.WriteString(`<ul class="list-group mb-3">`)
			for _, r := range d.ProxyRemoved {
				fmt.Fprintf(b, `<li class="list-group-item"><span class="text-danger">- %s</span> → target=%s port=%d enabled=%t ssl_only=%t</li>`, htmlEscape(r.Domain), htmlEscape(r.Target), r.Port, r.Enabled, r.SSLOnly)
			}
			b.WriteString(`</ul>`)
		}
		if len(d.ProxyModified) > 0 {
			b.WriteString(`<div class="mb-2"><span class="badge bg-warning text-dark me-1">修改</span></div>`)
			for _, m := range d.ProxyModified {
				fmt.Fprintf(b, `<div class="mb-2"><div class="fw-semibold">%s</div>`, htmlEscape(m.Domain))
				b.WriteString(`<table class="table table-sm table-bordered"><thead><tr><th>字段</th><th>当前</th><th>导入</th></tr></thead><tbody>`)
				for _, fc := range m.FieldChanges {
					fmt.Fprintf(b, `<tr><td class="text-muted">%s</td><td><code>%s</code></td><td><code>%s</code></td></tr>`, fc.Key, htmlEscape(fc.Old), htmlEscape(fc.New))
				}
				b.WriteString(`</tbody></table></div>`)
			}
		}
		b.WriteString(`</div></div>`)
		return b.String()
	}

	head := `<link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">`
	b := &strings.Builder{}
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>配置变更预览</title>` + head + `</head><body>`)
	b.WriteString(`<div class="container mt-4">
	<div class="d-flex justify-content-between align-items-center mb-3">
		<h3 class="mb-0">配置变更预览</h3>
		<div>
			<form method="POST" action="` + s.config.AdminPrefix + `/config/apply" class="d-inline">
				<button class="btn btn-danger">确认应用变更</button>
			</form>
			<a class="btn btn-secondary ms-2" href="` + s.config.AdminPrefix + `/settings">取消</a>
		</div>
	</div>
	`)

	b.WriteString(section("Server", d.ServerChanges))
	b.WriteString(section("SSL", d.SSLChanges))
	b.WriteString(section("Admin", d.AdminChanges))
	b.WriteString(section("Security", d.SecurityChanges))
	if d.AdminPrefix != nil {
		b.WriteString(section("Admin Prefix", []config.KeyChange{*d.AdminPrefix}))
	}
	b.WriteString(proxySection(d))

	b.WriteString(`<div class="mt-3">
	<form method="POST" action="` + s.config.AdminPrefix + `/config/apply" class="d-inline">
		<button class="btn btn-danger">确认应用变更</button>
	</form>
	<a class="btn btn-secondary ms-2" href="` + s.config.AdminPrefix + `/settings">取消</a>
	</div>`)

	b.WriteString(`</div></body></html>`)
	return b.String()
}

func htmlEscape(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}

func (s *Server) handleConfigApply(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.pendingImport == nil {
		http.Error(w, "没有待应用的配置", http.StatusBadRequest)
		return
	}
	// 写回文件：保留原路径，避免被导入配置覆盖
	oldPath := s.config.ConfigFile
	*s.config = *s.pendingImport
	// 恢复原有配置文件路径
	s.config.ConfigFile = oldPath
	if err := s.config.Save(oldPath); err != nil {
		http.Error(w, "保存配置失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// 清理pending
	s.pendingImport = nil
	s.pendingDiff = nil
	s.pendingImportJSON = ""
	http.Redirect(w, r, s.config.AdminPrefix+"/settings", http.StatusFound)
}

func (s *Server) renderDiffPlain(d config.ConfigDiff) string {
	b := &strings.Builder{}
	w := func(title string, items []config.KeyChange) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(b, "%s\n", title)
		for _, it := range items {
			fmt.Fprintf(b, "- %s: %s => %s\n", it.Key, it.Old, it.New)
		}
		b.WriteString("\n")
	}
	w("[Server]", d.ServerChanges)
	w("[SSL]", d.SSLChanges)
	w("[Admin]", d.AdminChanges)
	w("[Security]", d.SecurityChanges)
	if d.AdminPrefix != nil {
		fmt.Fprintf(b, "[AdminPrefix]\n- %s: %s => %s\n\n", d.AdminPrefix.Key, d.AdminPrefix.Old, d.AdminPrefix.New)
	}
	if len(d.ProxyAdded)+len(d.ProxyRemoved)+len(d.ProxyModified) > 0 {
		fmt.Fprintf(b, "[Proxy]\n")
		for _, a := range d.ProxyAdded {
			fmt.Fprintf(b, "+ add %s => %v\n", a.Domain, a)
		}
		for _, r := range d.ProxyRemoved {
			fmt.Fprintf(b, "- remove %s => %v\n", r.Domain, r)
		}
		for _, m := range d.ProxyModified {
			fmt.Fprintf(b, "~ modify %s\n", m.Domain)
			for _, fc := range m.FieldChanges {
				fmt.Fprintf(b, "  - %s: %s => %s\n", fc.Key, fc.Old, fc.New)
			}
		}
	}
	return b.String()
}

func (s *Server) needWizard() bool {
	return s.config.Admin.FirstRun
}

// 向导首页
func (s *Server) handleWizard(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>首次启动向导</title>
	<link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head><body>
	<div class="container mt-4">
	<h3>首次启动向导</h3>
	<div class="card mb-3"><div class="card-body">
		<h5 class="card-title">步骤一：设置管理员密码</h5>
		<p class="card-text">%s</p>
		<a class="btn btn-%s" href="%s">%s</a>
	</div></div>
	<div class="card mb-3"><div class="card-body">
		<h5 class="card-title">步骤二：基础配置</h5>
		<form method="POST" action="%s/wizard/step2" class="row g-3">
			<div class="col-md-6"><label class="form-label">证书邮箱(必填，用于 Let's Encrypt)</label><input class="form-control" type="email" name="email" value="%s" required></div>
			<div class="col-md-6 form-check mt-4"><input class="form-check-input" type="checkbox" name="auto_renew" %s id="ar"><label class="form-check-label" for="ar">启用自动续期</label></div>
			<div class="col-12"><button class="btn btn-primary" type="submit">保存基础配置</button></div>
		</form>
	</div></div>
	<div class="card mb-3"><div class="card-body">
		<h5 class="card-title">步骤三：添加首条代理规则(可选)</h5>
		<form method="POST" action="%s/wizard/step3" class="row g-3">
			<div class="col-md-4"><label class="form-label">域名</label><input class="form-control" name="domain" placeholder="example.com"></div>
			<div class="col-md-6"><label class="form-label">目标(含协议与端口)</label><input class="form-control" name="target" placeholder="http://127.0.0.1:8080"></div>
			<div class="col-12"><button class="btn btn-secondary" type="submit">添加(可跳过)</button></div>
		</form>
	</div></div>
	<form method="POST" action="%s/wizard/finish"><button class="btn btn-success">完成向导</button></form>
	</div></body></html>`,
		func() string {
			if s.needForcePasswordReset() {
				return "当前未设置安全密码，请先设置"
			}
			return "已设置安全密码"
		}(),
		func() string {
			if s.needForcePasswordReset() {
				return "warning"
			}
			return "outline-secondary"
		}(),
		func() string {
			if s.needForcePasswordReset() {
				return s.config.AdminPrefix + "/settings/change-password"
			}
			return s.config.AdminPrefix + "/dashboard"
		}(),
		func() string {
			if s.needForcePasswordReset() {
				return "去设置"
			}
			return "已完成"
		}(),
		s.config.AdminPrefix,
		s.config.SSL.Email,
		func() string {
			if s.config.SSL.AutoRenew {
				return "checked"
			}
			return ""
		}(),
		s.config.AdminPrefix,
		s.config.AdminPrefix)
}

func (s *Server) handleWizardStep2(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	auto := r.FormValue("auto_renew") == "on"
	if email == "" || !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		http.Error(w, "请填写合法的邮箱地址（用于 ACME）", http.StatusBadRequest)
		return
	}
	s.config.SSL.Email = email
	s.config.SSL.AutoRenew = auto
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		http.Error(w, "保存失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.sslManager.EnableACME(); err != nil {
		s.log.Warnf("启用 ACME 失败: %v", err)
	}
	s.audit("wizard_step2_saved", email)
	http.Redirect(w, r, s.config.AdminPrefix+"/wizard", http.StatusFound)
}

func (s *Server) handleWizardStep3(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	domain := strings.TrimSpace(r.FormValue("domain"))
	target := strings.TrimSpace(r.FormValue("target"))
	if domain != "" && target != "" {
		newRule := config.ProxyRule{Domain: domain, Target: target, Port: 0, Enabled: true, SSLOnly: true}
		s.config.Proxy.Rules = append(s.config.Proxy.Rules, newRule)
		if err := s.config.Save(s.config.ConfigFile); err != nil {
			http.Error(w, "保存失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.audit("wizard_step3_add_rule", domain+" -> "+target)
	}
	http.Redirect(w, r, s.config.AdminPrefix+"/wizard", http.StatusFound)
}

func (s *Server) handleWizardFinish(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if strings.TrimSpace(s.config.SSL.Email) == "" {
		http.Error(w, "请先在向导第二步填写用于 ACME 的证书邮箱", http.StatusBadRequest)
		return
	}
	s.config.Admin.FirstRun = false
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		http.Error(w, "保存失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit("wizard_finished", "")
	http.Redirect(w, r, s.config.AdminPrefix+"/dashboard", http.StatusFound)
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

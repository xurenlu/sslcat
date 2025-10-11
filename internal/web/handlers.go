package web

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// 基础页面处理器

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
	// 使用Info级别确保能看到日志
	s.log.Infof("=== handleLogin called: method=%s, path=%s ===", r.Method, r.URL.Path)

	if r.Method == "GET" {
		debugForced := strings.EqualFold(r.URL.Query().Get("debug"), "true") || r.URL.Query().Get("debug") == "1"

		// 下发人机验证要素（TOTP启用时禁用PoW）
		startTs := time.Now().UnixMilli()
		honeypotName := "hp_seed000"

		data := map[string]interface{}{
			"AdminPrefix":    s.config.AdminPrefix,
			"Error":          "",
			"RequireCaptcha": s.config.Security.EnableCaptcha,
			"RequireTOTP":    s.config.Admin.EnableTOTP,
			"Debug":          debugForced,
			"HoneypotName":   honeypotName,
			"FormStartTs":    startTs,
		}

		s.templateRenderer.DetectLanguageAndRender(w, r, "login.html", data)
		return
	}

	if r.Method == "POST" {
		s.log.Infof("=== POST login received ===")
		_ = r.ParseForm()
		s.log.Infof("Form parsed, values: username='%s', password_len=%d",
			r.FormValue("username"), len(r.FormValue("password")))

		// 蜜罐：检测非空值填写（空值不算填写）
		for k, v := range r.Form {
			if strings.HasPrefix(k, "hp_") && len(v) > 0 {
				trimmed := strings.TrimSpace(v[0])
				if trimmed != "" {
					hp := "hp_seed000"
					startTs := time.Now().UnixMilli()
					data := map[string]interface{}{
						"AdminPrefix":    s.config.AdminPrefix,
						"Error":          "疑似自动化提交（蜜罐触发）",
						"RequireCaptcha": s.config.Security.EnableCaptcha && !s.config.Admin.EnableTOTP,
						"RequireTOTP":    s.config.Admin.EnableTOTP,
						"Debug":          false,
						"HoneypotName":   hp,
						"FormStartTs":    startTs,
					}
					s.templateRenderer.DetectLanguageAndRender(w, r, "login.html", data)
					return
				}
			}
		}

		// 最小填写时长：<MinFormMs 拒绝
		s.log.Infof("Checking minimum form duration...")
		if ts := strings.TrimSpace(r.FormValue("form_start_ts")); ts != "" {
			s.log.Infof("form_start_ts found: %s", ts)
			if ms, err := strconv.ParseInt(ts, 10, 64); err == nil {
				s.log.Infof("Parsed timestamp: %d", ms)
				minMs := int64(800)
				if s.config.Security.MinFormMs > 0 {
					minMs = int64(s.config.Security.MinFormMs)
				}
				duration := time.Now().UnixMilli() - ms
				s.log.Infof("Form duration: %dms, required: %dms", duration, minMs)
				if duration < minMs {
					s.log.Infof("FORM TOO FAST: %dms < %dms", duration, minMs)
					hp := "hp_seed000"
					startTs := time.Now().UnixMilli()
					data := map[string]interface{}{
						"AdminPrefix":    s.config.AdminPrefix,
						"Error":          "提交过快，请重试",
						"RequireCaptcha": s.config.Security.EnableCaptcha,
						"Debug":          false,
						"HoneypotName":   hp,
						"FormStartTs":    startTs,
					}
					s.templateRenderer.DetectLanguageAndRender(w, r, "login.html", data)
					return
				}
			} else {
				s.log.Infof("Failed to parse form_start_ts: %s", ts)
			}
		} else {
			s.log.Infof("No form_start_ts found")
		}

		// 图形验证码校验（按开关，TOTP启用时跳过）
		enableCaptcha := s.config.Security.EnableCaptcha && !s.config.Admin.EnableTOTP
		s.log.Infof("Captcha check: enabled=%v (EnableCaptcha=%v, EnableTOTP=%v)", enableCaptcha, s.config.Security.EnableCaptcha, s.config.Admin.EnableTOTP)
		if enableCaptcha {
			sid := strings.TrimSpace(r.FormValue("captcha_session_id"))
			code := strings.TrimSpace(r.FormValue("captcha_text"))
			s.log.Infof("Captcha values: sid='%s', code='%s'", sid, code)
			captchaResult := s.captchaManager.VerifyCaptchaString(sid, code)
			s.log.Infof("Captcha verification result: %v", captchaResult)
			if sid == "" || code == "" || !captchaResult {
				s.log.Infof("CAPTCHA FAILED: sid_empty=%v, code_empty=%v, verify_result=%v", sid == "", code == "", captchaResult)
				hp := "hp_seed000"
				startTs := time.Now().UnixMilli()
				data := map[string]interface{}{
					"AdminPrefix":    s.config.AdminPrefix,
					"Error":          "验证码错误，请重试",
					"RequireCaptcha": s.config.Security.EnableCaptcha,
					"RequireTOTP":    s.config.Admin.EnableTOTP,
					"Debug":          false,
					"HoneypotName":   hp,
					"FormStartTs":    startTs,
				}
				s.templateRenderer.DetectLanguageAndRender(w, r, "login.html", data)
				return
			}
		} else {
			s.log.Infof("Captcha disabled, skipping check")
		}

		// 用户名密码校验（支持 bcrypt/明文，明文将自动迁移为 bcrypt）
		s.log.Infof("Starting password verification...")
		username := r.FormValue("username")
		password := r.FormValue("password")
		totpCode := strings.TrimSpace(r.FormValue("totp_code"))

		s.log.Infof("Login attempt: username='%s', password_len=%d, expected_username='%s'",
			username, len(password), s.config.Admin.Username)

		usernameMatch := username == s.config.Admin.Username
		passwordMatch := s.verifyAdminPassword(password)

		s.log.Infof("Login verification: username_match=%v, password_match=%v", usernameMatch, passwordMatch)

		if usernameMatch && passwordMatch {
			// TOTP 二次验证（如果启用）
			if s.config.Admin.EnableTOTP && !s.verifyTOTP(totpCode) {
				hp := "hp_seed000"
				startTs := time.Now().UnixMilli()
				data := map[string]interface{}{
					"AdminPrefix":    s.config.AdminPrefix,
					"Error":          "TOTP验证码错误",
					"RequireCaptcha": s.config.Security.EnableCaptcha,
					"RequireTOTP":    s.config.Admin.EnableTOTP,
					"Debug":          false,
					"HoneypotName":   hp,
					"FormStartTs":    startTs,
				}
				s.templateRenderer.DetectLanguageAndRender(w, r, "login.html", data)
				return
			}

			s.processLogin(w, r)
			return
		}

		// 登录失败，记录安全日志
		clientIP := s.getClientIP(r)
		s.securityManager.LogAccess(clientIP, r.Header.Get("User-Agent"), r.URL.Path, false)
		s.audit("login_failed", clientIP)

		// 显示错误页面（重新生成完整表单数据）
		startTs := time.Now().UnixMilli()
		honeypotName := "hp_seed000"

		data := map[string]interface{}{
			"AdminPrefix":    s.config.AdminPrefix,
			"Error":          s.translator.T("login.invalid"),
			"RequireCaptcha": s.config.Security.EnableCaptcha,
			"RequireTOTP":    s.config.Admin.EnableTOTP,
			"Debug":          false,
			"HoneypotName":   honeypotName,
			"FormStartTs":    startTs,
		}
		s.templateRenderer.DetectLanguageAndRender(w, r, "login.html", data)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// verifyAdminPassword 校验管理员密码；支持 bcrypt；若存储为明文且匹配，会自动迁移为 bcrypt
func (s *Server) verifyAdminPassword(input string) bool {
	passFile := s.config.Admin.PasswordFile
	stored := strings.TrimSpace(s.config.Admin.Password)

	s.log.Debugf("=== Password Verification Debug ===")
	s.log.Debugf("Password file: %s", passFile)
	s.log.Debugf("Config password: '%s'", stored)
	s.log.Debugf("Input password: '%s' (len=%d)", input, len(input))

	// 优先从文件读取
	if passFile != "" {
		if b, err := os.ReadFile(passFile); err == nil {
			stored = strings.TrimSpace(string(b))
			s.log.Debugf("Read from password file: '%s' (len=%d)", stored, len(stored))
		} else {
			s.log.Debugf("Failed to read password file %s: %v", passFile, err)
		}
	}

	if stored == "" {
		s.log.Debug("No password found in file or config")
		return false
	}

	// 检查是否为bcrypt格式
	isBcrypt := strings.HasPrefix(stored, "$2a$") || strings.HasPrefix(stored, "$2b$") || strings.HasPrefix(stored, "$2y$")
	s.log.Debugf("Password format: bcrypt=%v, stored_prefix='%s'", isBcrypt, stored[:min(10, len(stored))])

	if isBcrypt {
		err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(input))
		if err == nil {
			s.log.Debug("✅ bcrypt password verification SUCCESSFUL")
			return true
		}
		s.log.Debugf("❌ bcrypt password verification FAILED: %v", err)
		return false
	}

	// 明文比较（常量时间）
	s.log.Debugf("Comparing plaintext: stored='%s' vs input='%s'", stored, input)
	if subtle.ConstantTimeCompare([]byte(stored), []byte(input)) == 1 {
		s.log.Debug("✅ Plain password matched, migrating to bcrypt")
		// 迁移为 bcrypt
		if passFile != "" {
			if hash, err := bcrypt.GenerateFromPassword([]byte(input), bcrypt.DefaultCost); err == nil {
				_ = os.WriteFile(passFile, append(hash, '\n'), 0600)
				s.log.Debug("Password migrated to bcrypt successfully")
			} else {
				s.log.Debugf("Failed to migrate password to bcrypt: %v", err)
			}
		}
		return true
	}

	s.log.Debug("❌ Password verification FAILED - no match")
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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

func (s *Server) processLogin(w http.ResponseWriter, r *http.Request) {
	s.log.Infof("=== processLogin called ===")
	username := r.FormValue("username")
	password := r.FormValue("password")

	s.log.Infof("processLogin: username='%s', password_len=%d", username, len(password))

	// 多账户认证逻辑
	var authenticatedUser *User
	var isSuperAdmin bool

	// 1. 首先尝试普通用户认证
	user, err := s.userManager.AuthenticateUser(username, password)
	if err == nil {
		authenticatedUser = user
		s.log.Infof("普通用户认证成功: %s (角色: %s)", username, user.Role)
	} else {
		s.log.Debugf("普通用户认证失败: %v", err)

		// 2. 如果普通用户认证失败，尝试超级管理员认证
		usernameMatch := username == s.config.Admin.Username
		passwordMatch := s.verifyAdminPassword(password)

		if usernameMatch && passwordMatch {
			// 创建超级管理员用户对象
			authenticatedUser = &User{
				Username: username,
				Role:     RoleSuperAdmin,
				IsActive: true,
			}
			isSuperAdmin = true
			s.log.Infof("超级管理员认证成功: %s", username)
		}
	}

	if authenticatedUser != nil {
		s.log.Infof("✅ LOGIN SUCCESS - Setting session cookie")

		// 创建会话
		clientIP := s.getClientIP(r)
		userAgent := r.Header.Get("User-Agent")
		session, err := s.sessionManager.CreateSession(
			authenticatedUser.Username,
			authenticatedUser.Role,
			clientIP,
			userAgent,
		)
		if err != nil {
			s.log.Errorf("创建会话失败: %v", err)
			s.renderLoginError(w, r, "登录失败，请重试")
			return
		}

		// 设置会话Cookie
		s.sessionManager.SetSessionCookie(w, session.SessionID, r.TLS != nil)

		// 记录用户操作日志
		s.userManager.LogUserAction(
			authenticatedUser.Username,
			"login_success",
			"system",
			fmt.Sprintf("用户登录成功，角色: %s", authenticatedUser.Role),
			clientIP,
			userAgent,
		)

		// 审计
		s.audit("login_success", authenticatedUser.Username)

		// 超级管理员首次设置检查（已合并 wizard 功能）
		if isSuperAdmin && s.needFirstTimeSetup() {
			http.Redirect(w, r, s.config.AdminPrefix+"/settings/first-setup", http.StatusFound)
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

	// 显示错误页面（重新生成完整表单数据）
	s.renderLoginError(w, r, s.translator.T("login.invalid"))
}

// renderLoginError 渲染登录错误页面
func (s *Server) renderLoginError(w http.ResponseWriter, r *http.Request, errorMsg string) {
	startTs := time.Now().UnixMilli()
	honeypotName := "hp_seed000"

	data := map[string]interface{}{
		"AdminPrefix":    s.config.AdminPrefix,
		"Error":          errorMsg,
		"RequireCaptcha": s.config.Security.EnableCaptcha,
		"RequireTOTP":    s.config.Admin.EnableTOTP,
		"Debug":          false,
		"HoneypotName":   honeypotName,
		"FormStartTs":    startTs,
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

func (s *Server) needFirstTimeSetup() bool {
	// 检查是否需要首次设置（密码和邮箱）

	// 首先检查是否已经有完成标记
	setupCompleteFile := filepath.Join("./data", ".first-setup-complete")
	if _, err := os.Stat(setupCompleteFile); err == nil {
		// 标记文件存在，说明已经完成过首次设置
		return false
	}

	// 检查 FirstRun 配置
	if s.config.Admin.FirstRun {
		return true
	}

	// 1. 检查密码文件
	passFile := s.config.Admin.PasswordFile
	if passFile == "" {
		return true
	}
	b, err := os.ReadFile(passFile)
	if err != nil {
		return true
	}
	stored := strings.TrimSpace(string(b))
	if stored == "" || stored == "admin*9527" {
		return true
	}

	// 2. 检查是否设置了管理员邮箱
	if s.config.SSL.Email == "" {
		return true
	}

	return false
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
    <link href="/static/css/bootstrap.min.css" rel="stylesheet"></head><body>
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

	// 检测并设置语言
	lang := s.detectLanguage(r)
	s.translator.SetLanguage(lang)

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
		// 记录旧的前缀
		oldPrefix := s.config.AdminPrefix

		// 更新配置
		if newPrefix := r.FormValue("admin_prefix"); newPrefix != "" {
			s.config.AdminPrefix = newPrefix
		}

		if newUsername := r.FormValue("admin_username"); newUsername != "" {
			s.config.Admin.Username = newUsername
		}

		if newPassword := r.FormValue("admin_password"); newPassword != "" {
			// 存储 bcrypt 哈希
			if hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost); err == nil {
				_ = os.WriteFile(s.config.Admin.PasswordFile, append(hash, '\n'), 0600)
				// 避免明文落入配置
				s.config.Admin.Password = ""
			}
		}

		// SSL 邮箱与禁用自签
		if v := strings.TrimSpace(r.FormValue("ssl_email")); v != "" {
			s.config.SSL.Email = v
			// 尝试启用 ACME
			if err := s.sslManager.EnableACME(); err != nil {
				s.log.Warnf("Failed to enable ACME: %v", err)
			}
		}
		if v := r.FormValue("ssl_disable_self_signed"); v != "" {
			s.config.SSL.DisableSelfSigned = (v == "on" || v == "true" || v == "1")
		}

		// 代理未命中行为与重定向URL
		if b := r.FormValue("proxy_unmatched_behavior"); b != "" {
			s.config.Proxy.UnmatchedBehavior = b
		}
		if u := strings.TrimSpace(r.FormValue("proxy_unmatched_redirect_url")); u != "" {
			s.config.Proxy.UnmatchedRedirectURL = u
		}
		// 如果选择302但未提供URL，返回错误
		if s.config.Proxy.UnmatchedBehavior == "302" && strings.TrimSpace(s.config.Proxy.UnmatchedRedirectURL) == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write([]byte("proxy_unmatched_redirect_url is required when behavior is 302"))
			return
		}

		// 保存配置
		s.config.Save(s.config.ConfigFile)

		// 如果管理前缀发生了变化，重新设置路由并发送通知
		if oldPrefix != s.config.AdminPrefix {
			s.mux = http.NewServeMux()
			s.setupRoutes()
			// 清理模板缓存，确保使用新的配置
			s.templateRenderer.ClearCache()

			// 发送前缀变更通知
			s.sendAdminPrefixChangeNotification(oldPrefix, s.config.AdminPrefix)
		}
	}

	// 重定向回设置页面
	http.Redirect(w, r, s.config.AdminPrefix+"/settings", http.StatusFound)
}

// 首次设置页面（合并了 wizard 功能）
func (s *Server) handleFirstTimeSetup(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method == "GET" {
		currentEmail := s.config.SSL.Email
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>首次设置向导</title>
		<link href="/static/css/bootstrap.min.css" rel="stylesheet">
		<link href="/static/css/bootstrap-icons.css" rel="stylesheet">
		</head><body class="bg-light">
		<div class="container mt-4">
			<div class="row justify-content-center">
				<div class="col-md-8">
					<div class="card shadow">
						<div class="card-header bg-primary text-white">
							<h4 class="mb-0"><i class="bi bi-gear"></i> 首次设置向导</h4>
						</div>
						<div class="card-body">
							<p class="text-muted mb-4">欢迎使用 SSLcat！请完成以下初始设置：</p>
							
							<form method="POST" id="setupForm">
								<!-- 步骤一：管理员设置 -->
								<div class="card mb-4">
									<div class="card-header">
										<h5 class="mb-0"><i class="bi bi-person-gear"></i> 步骤一：管理员设置</h5>
									</div>
									<div class="card-body">
										<div class="row">
											<div class="col-md-6">
												<div class="mb-3">
													<label class="form-label"><i class="bi bi-lock"></i> 新密码</label>
													<input class="form-control" type="password" name="new_password" required placeholder="请输入新的管理员密码">
												</div>
											</div>
											<div class="col-md-6">
												<div class="mb-3">
													<label class="form-label"><i class="bi bi-lock-fill"></i> 确认新密码</label>
													<input class="form-control" type="password" name="confirm_password" required placeholder="请再次输入新密码">
												</div>
											</div>
										</div>
									</div>
								</div>

								<!-- 步骤二：SSL 配置 -->
								<div class="card mb-4">
									<div class="card-header">
										<h5 class="mb-0"><i class="bi bi-shield-check"></i> 步骤二：SSL 配置</h5>
									</div>
									<div class="card-body">
										<div class="row">
											<div class="col-md-6">
												<div class="mb-3">
													<label class="form-label"><i class="bi bi-envelope"></i> 管理员邮箱</label>
													<input class="form-control" type="email" name="admin_email" required placeholder="用于SSL证书申请和通知" value="%s">
													<div class="form-text">此邮箱将用于 Let's Encrypt 证书申请和系统通知</div>
												</div>
											</div>
											<div class="col-md-6">
												<div class="form-check mt-4">
													<input class="form-check-input" type="checkbox" name="auto_renew" %s id="auto_renew">
													<label class="form-check-label" for="auto_renew">
														<i class="bi bi-arrow-clockwise"></i> 启用自动续期
													</label>
												</div>
											</div>
										</div>
									</div>
								</div>

								<!-- 步骤三：代理规则（可选） -->
								<div class="card mb-4">
									<div class="card-header">
										<h5 class="mb-0"><i class="bi bi-diagram-3"></i> 步骤三：添加首条代理规则（可选）</h5>
									</div>
									<div class="card-body">
										<div class="row">
											<div class="col-md-4">
												<div class="mb-3">
													<label class="form-label">域名</label>
													<input class="form-control" name="domain" placeholder="example.com">
												</div>
											</div>
											<div class="col-md-6">
												<div class="mb-3">
													<label class="form-label">目标（含协议与端口）</label>
													<input class="form-control" name="target" placeholder="http://127.0.0.1:8080">
												</div>
											</div>
											<div class="col-md-2">
												<div class="mb-3">
													<label class="form-label">&nbsp;</label>
													<div class="form-text">可跳过此步骤</div>
												</div>
											</div>
										</div>
									</div>
								</div>

								<!-- 提交按钮 -->
								<div class="d-grid gap-2">
									<button class="btn btn-primary btn-lg" type="submit">
										<i class="bi bi-check-circle"></i> 完成设置
									</button>
									<a class="btn btn-outline-secondary" href="%s/logout">
										<i class="bi bi-box-arrow-right"></i> 退出登录
									</a>
								</div>
							</form>
						</div>
					</div>
				</div>
			</div>
		</div>
		</body></html>`,
			currentEmail,
			func() string {
				if s.config.SSL.AutoRenew {
					return "checked"
				}
				return ""
			}(),
			s.config.AdminPrefix)
		return
	}

	if r.Method == "POST" {
		// 解析表单数据
		if err := r.ParseForm(); err != nil {
			http.Error(w, "解析表单失败: "+err.Error(), http.StatusBadRequest)
			return
		}

		newPassword := r.FormValue("new_password")
		confirmPassword := r.FormValue("confirm_password")
		adminEmail := strings.TrimSpace(r.FormValue("admin_email"))
		autoRenew := r.FormValue("auto_renew") == "on"
		domain := strings.TrimSpace(r.FormValue("domain"))
		target := strings.TrimSpace(r.FormValue("target"))

		// 调试日志
		passwordStatus := "[已设置]"
		if newPassword == "" {
			passwordStatus = "[空]"
		}
		confirmStatus := "[已设置]"
		if confirmPassword == "" {
			confirmStatus = "[空]"
		}
		s.log.Infof("首次设置表单数据: new_password=%s, confirm_password=%s, admin_email=%s, auto_renew=%t, domain=%s, target=%s",
			passwordStatus, confirmStatus, adminEmail, autoRenew, domain, target)

		// 验证密码
		if newPassword == "" || newPassword != confirmPassword {
			http.Error(w, "passwords do not match or empty", http.StatusBadRequest)
			return
		}

		// 验证邮箱
		if adminEmail == "" {
			http.Error(w, "admin email is required", http.StatusBadRequest)
			return
		}

		// 简单的邮箱格式验证
		if !strings.Contains(adminEmail, "@") || !strings.Contains(adminEmail, ".") {
			http.Error(w, "invalid email address", http.StatusBadRequest)
			return
		}

		// 更新内存与持久化密码文件（bcrypt）
		s.config.Admin.Password = "" // 避免将明文写入 sslcat.conf
		if hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost); err == nil {
			if err := os.WriteFile(s.config.Admin.PasswordFile, append(hash, '\n'), 0600); err != nil {
				http.Error(w, "failed to write password file: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(w, "failed to hash password", http.StatusInternalServerError)
			return
		}

		// 更新邮箱和自动续期配置
		s.config.SSL.Email = adminEmail
		s.config.SSL.AutoRenew = autoRenew

		// 添加代理规则（如果提供了）
		if domain != "" && target != "" {
			newRule := config.ProxyRule{
				Domain:  domain,
				Target:  target,
				Port:    0,
				Enabled: true,
				SSLOnly: true,
			}
			s.config.Proxy.Rules = append(s.config.Proxy.Rules, newRule)
		}

		// 设置 FirstRun 为 false
		s.config.Admin.FirstRun = false

		// 保存配置（不包含密码）
		if err := s.config.Save(s.config.ConfigFile); err != nil {
			http.Error(w, "failed to save config: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// 尝试启用 ACME（现在有邮箱了）
		if err := s.sslManager.EnableACME(); err != nil {
			s.log.Warnf("Failed to enable ACME: %v", err)
		}

		// 创建首次设置完成标记文件
		setupCompleteFile := filepath.Join("./data", ".first-setup-complete")
		if err := os.WriteFile(setupCompleteFile, []byte(fmt.Sprintf("首次设置完成时间: %s\n管理员邮箱: %s\n自动续期: %t\n代理规则: %s",
			time.Now().Format("2006-01-02 15:04:05"),
			adminEmail,
			autoRenew,
			func() string {
				if domain != "" && target != "" {
					return fmt.Sprintf("%s -> %s", domain, target)
				}
				return "无"
			}())), 0644); err != nil {
			s.log.Warnf("创建首次设置完成标记失败: %v", err)
		}

		// 审计日志
		s.audit("first_time_setup_complete", fmt.Sprintf("email:%s,auto_renew:%t,proxy_rule:%s", adminEmail, autoRenew, func() string {
			if domain != "" && target != "" {
				return fmt.Sprintf("%s->%s", domain, target)
			}
			return "none"
		}()))

		http.Redirect(w, r, s.config.AdminPrefix+"/dashboard", http.StatusFound)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method == "GET" {
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>修改密码</title>
		<link href="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head><body>
		<div class="container mt-4"><h3>修改密码</h3>
		<form method="POST">
			<div class="mb-3"><label class="form-label">新密码</label><input class="form-control" type="password" name="new" required></div>
			<div class="mb-3"><label class="form-label">确认新密码</label><input class="form-control" type="password" name="confirm" required></div>
			<button class="btn btn-primary" type="submit">保存</button>
			<a class="btn btn-secondary ms-2" href="%s/dashboard">返回</a>
		</form></div></body></html>`, s.config.AdminPrefix)
		return
	}
	if r.Method == "POST" {
		newp := r.FormValue("new")
		conf := r.FormValue("confirm")
		if newp == "" || newp != conf {
			http.Error(w, "passwords do not match or empty", http.StatusBadRequest)
			return
		}
		// 更新内存与持久化密码文件（bcrypt）
		s.config.Admin.Password = "" // 避免将明文写入 sslcat.conf
		if hash, err := bcrypt.GenerateFromPassword([]byte(newp), bcrypt.DefaultCost); err == nil {
			if err := os.WriteFile(s.config.Admin.PasswordFile, append(hash, '\n'), 0600); err != nil {
				http.Error(w, "failed to write password file: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(w, "failed to hash password", http.StatusInternalServerError)
			return
		}
		// 保存配置（不包含密码）
		if err := s.config.Save(s.config.ConfigFile); err != nil {
			http.Error(w, "failed to save config: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, s.config.AdminPrefix+"/dashboard", http.StatusFound)
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// 获取当前会话
	session, exists := s.sessionManager.GetSessionFromRequest(r)
	if exists {
		// 记录登出日志
		s.userManager.LogUserAction(
			session.Username,
			"logout",
			"system",
			"用户登出",
			s.getClientIP(r),
			r.Header.Get("User-Agent"),
		)

		// 删除会话
		s.sessionManager.DeleteSession(session.SessionID)
	}

	// 清除session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "sslcat_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	// 重定向到登录页
	http.Redirect(w, r, s.config.AdminPrefix+"/login", http.StatusFound)
}

// handleAPICloudStorageDetect 云存储服务检测API
func (s *Server) handleAPICloudStorageDetect(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "target parameter required", http.StatusBadRequest)
		return
	}

	// 使用proxy manager的检测功能
	if pm, ok := interface{}(s.proxyManager).(interface {
		DetectCloudStorageInfo(target string) interface{}
	}); ok {
		info := pm.DetectCloudStorageInfo(target)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    info,
		})
		return
	}

	// 简单的检测逻辑
	targetLower := strings.ToLower(target)
	var cloudInfo interface{}

	if strings.Contains(targetLower, "aliyuncs.com") || strings.Contains(targetLower, "oss-") {
		cloudInfo = map[string]interface{}{
			"type":        "aliyun_oss",
			"name":        "阿里云OSS",
			"icon":        "🌩️",
			"description": "检测到阿里云OSS服务，建议启用云存储优化配置",
		}
	} else if strings.Contains(targetLower, "amazonaws.com") || strings.Contains(targetLower, ".s3.") {
		cloudInfo = map[string]interface{}{
			"type":        "aws_s3",
			"name":        "AWS S3",
			"icon":        "☁️",
			"description": "检测到AWS S3服务，建议启用云存储优化配置",
		}
	} else if strings.Contains(targetLower, "qcloud.com") || strings.Contains(targetLower, "myqcloud.com") || strings.Contains(targetLower, ".cos.") {
		cloudInfo = map[string]interface{}{
			"type":        "tencent_cos",
			"name":        "腾讯云COS",
			"icon":        "🔵",
			"description": "检测到腾讯云COS服务，建议启用云存储优化配置",
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if cloudInfo != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    cloudInfo,
		})
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"data":    nil,
		})
	}
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	stats := s.getSystemStats()
	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"Stats":       stats,
	}
	s.templateRenderer.DetectLanguageAndRender(w, r, "dashboard.html", data)
}

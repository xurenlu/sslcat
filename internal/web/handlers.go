package web

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/xurenlu/sslcat/internal/assets"
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

func (s *Server) recordFirstSetupMetric(status, reason string) {
	if s.prometheusMetrics != nil {
		s.prometheusMetrics.RecordFirstSetup(status, reason)
	}
}

func isValidFirstSetupDomain(domain string) bool {
	if domain == "" {
		return false
	}

	if strings.Contains(domain, " ") {
		return false
	}

	if len(domain) > 253 {
		return false
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}

	for _, label := range parts {
		if label == "" || len(label) > 63 {
			return false
		}

		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}

		for _, r := range label {
			if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-') {
				return false
			}
		}
	}

	return true
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// 直接返回 React SPA 登录页面（不检查认证）
	// React SPA 使用 /api/auth/login API 端点进行登录
	fsys, err := assets.GetFrontendFS()
	if err != nil {
		s.log.Errorf("Failed to get frontend filesystem: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 读取 index.html
	indexFile, err := fsys.Open("index.html")
	if err != nil {
		s.log.Errorf("Failed to open index.html: %v", err)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	defer indexFile.Close()

	// 读取HTML内容
	htmlContent, err := io.ReadAll(indexFile)
	if err != nil {
		s.log.Errorf("Failed to read index.html: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 动态重写资源路径，将相对路径替换为当前管理面板路径
	htmlStr := string(htmlContent)
	// 替换 /assets/ 为当前管理面板路径 + /assets/
	htmlStr = strings.ReplaceAll(htmlStr, `src="/assets/`, `src="`+s.config.AdminPrefix+`/assets/`)
	htmlStr = strings.ReplaceAll(htmlStr, `href="/assets/`, `href="`+s.config.AdminPrefix+`/assets/`)
	// 替换 favicon 路径
	htmlStr = strings.ReplaceAll(htmlStr, `href="/favicon.ico"`, `href="`+s.config.AdminPrefix+`/favicon.ico"`)

	// 设置内容类型
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	// 写入修改后的HTML内容
	w.Write([]byte(htmlStr))
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

// handleMobile, handleCharts, handleDefault 已移除，使用 React SPA

func (s *Server) processLogin(w http.ResponseWriter, r *http.Request) {
	s.log.Infof("=== processLogin called ===")
	username := r.FormValue("username")
	password := r.FormValue("password")

	s.log.Infof("processLogin: username='%s', password_len=%d", username, len(password))

	// 多账户认证逻辑
	var authenticatedUser *User
	var isSuperAdmin bool

	// 1. 首先检查是否为超管用户名，如果是则优先使用超管认证
	usernameMatch := username == s.config.Admin.Username
	if usernameMatch {
		// 超管用户名，优先使用超管认证
		passwordMatch := s.verifyAdminPassword(password)
		if passwordMatch {
			// 创建超级管理员用户对象
			authenticatedUser = &User{
				Username: username,
				Role:     RoleSuperAdmin,
				IsActive: true,
			}
			isSuperAdmin = true
			s.log.Infof("超级管理员认证成功: %s", username)
		} else {
			s.log.Debugf("超级管理员认证失败: %s", username)
		}
	} else {
		// 2. 非超管用户名，尝试普通用户认证
		user, err := s.userManager.AuthenticateUser(username, password)
		if err == nil {
			authenticatedUser = user
			s.log.Infof("普通用户认证成功: %s (角色: %s)", username, user.Role)
		} else {
			s.log.Debugf("普通用户认证失败: %v", err)
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
			http.Redirect(w, r, s.config.AdminPrefix+"/login?error=登录失败，请重试", http.StatusFound)
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

	// 重定向到登录页面（React SPA 会处理错误显示）
	http.Redirect(w, r, s.config.AdminPrefix+"/login?error="+url.QueryEscape(s.translator.T("login.invalid")), http.StatusFound)
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

	// GET 请求应该由前端 SPA 处理，不应该到达这里
	// 如果路由配置正确，GET 请求会被 setupFrontendRoutes 中的路由拦截
	// 但为了兼容性，如果 GET 请求到达这里，也返回前端 SPA
	if r.Method == "GET" {
		s.handleSPA(w, r)
		return
	}

	// 只处理 POST 请求
	// 解析表单数据
	if err := r.ParseForm(); err != nil {
		s.recordFirstSetupMetric("failure", "parse_form")
		http.Error(w, "解析表单失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")
	adminEmail := strings.TrimSpace(r.FormValue("admin_email"))
	autoRenew := r.FormValue("auto_renew") == "on"
	domain := strings.TrimSpace(r.FormValue("domain"))
	target := strings.TrimSpace(r.FormValue("target"))
	const minPasswordLength = 10

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

	// 密码策略校验
	if len(newPassword) < minPasswordLength {
		s.recordFirstSetupMetric("failure", "password_length")
		http.Error(w, fmt.Sprintf("password too short: require at least %d characters", minPasswordLength), http.StatusBadRequest)
		return
	}

	if newPassword != confirmPassword {
		s.recordFirstSetupMetric("failure", "password_mismatch")
		http.Error(w, "passwords do not match", http.StatusBadRequest)
		return
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false
	for _, r := range newPassword {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r), unicode.IsSymbol(r):
			hasSpecial = true
		}
	}
	complexity := 0
	for _, passed := range []bool{hasUpper, hasLower, hasDigit, hasSpecial} {
		if passed {
			complexity++
		}
	}
	if complexity < 3 {
		s.recordFirstSetupMetric("failure", "password_complexity")
		http.Error(w, "password complexity requirement not met", http.StatusBadRequest)
		return
	}

	// 验证邮箱
	if adminEmail == "" {
		s.recordFirstSetupMetric("failure", "email_empty")
		http.Error(w, "admin email is required", http.StatusBadRequest)
		return
	}

	if _, err := mail.ParseAddress(adminEmail); err != nil {
		s.recordFirstSetupMetric("failure", "email_invalid")
		http.Error(w, "invalid email address", http.StatusBadRequest)
		return
	}

	// 验证代理规则
	if (domain != "" && target == "") || (domain == "" && target != "") {
		s.recordFirstSetupMetric("failure", "proxy_pair")
		http.Error(w, "domain and target must be provided together", http.StatusBadRequest)
		return
	}

	if domain != "" && !isValidFirstSetupDomain(domain) {
		s.recordFirstSetupMetric("failure", "domain_invalid")
		http.Error(w, "invalid domain", http.StatusBadRequest)
		return
	}

	if target != "" {
		parsedTarget, err := url.Parse(target)
		if err != nil || parsedTarget.Host == "" {
			s.recordFirstSetupMetric("failure", "target_invalid")
			http.Error(w, "invalid target", http.StatusBadRequest)
			return
		}
		if parsedTarget.Scheme != "http" && parsedTarget.Scheme != "https" {
			s.recordFirstSetupMetric("failure", "target_scheme")
			http.Error(w, "target must use http or https scheme", http.StatusBadRequest)
			return
		}
	}

	// 更新内存与持久化密码文件（bcrypt）
	s.config.Admin.Password = "" // 避免将明文写入 sslcat.conf
	if hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost); err == nil {
		if err := os.WriteFile(s.config.Admin.PasswordFile, append(hash, '\n'), 0600); err != nil {
			s.recordFirstSetupMetric("failure", "password_file")
			http.Error(w, "failed to write password file: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		s.recordFirstSetupMetric("failure", "password_hash")
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

	// 保存配置（不包含密码）
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		s.recordFirstSetupMetric("failure", "config_save")
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
	s.recordFirstSetupMetric("success", "completed")

	http.Redirect(w, r, s.config.AdminPrefix+"/dashboard", http.StatusFound)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method == "GET" {
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>修改密码</title>
		<link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head><body>
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

// handleDashboard 已移除，使用 React SPA

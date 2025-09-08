package web

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
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
	if r.Method == "GET" {
		// 关闭验证码功能
		debugForced := strings.EqualFold(r.URL.Query().Get("debug"), "true") || r.URL.Query().Get("debug") == "1"

		data := map[string]interface{}{
			"AdminPrefix":    s.config.AdminPrefix,
			"Error":          "",
			"RequireCaptcha": false,
			"Debug":          debugForced,
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

		// 如果首次运行或未设置过密码/邮箱，要求强制设置
		if s.needFirstTimeSetup() {
			http.Redirect(w, r, s.config.AdminPrefix+"/settings/first-setup", http.StatusFound)
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

func (s *Server) needFirstTimeSetup() bool {
	// 检查是否需要首次设置（密码和邮箱）

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
			s.config.Admin.Password = newPassword
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

		// 如果管理前缀发生了变化，重新设置路由
		if oldPrefix != s.config.AdminPrefix {
			s.mux = http.NewServeMux()
			s.setupRoutes()
			// 清理模板缓存，确保使用新的配置
			s.templateRenderer.ClearCache()
		}
	}

	// 重定向回设置页面
	http.Redirect(w, r, s.config.AdminPrefix+"/settings", http.StatusFound)
}

// 首次设置页面（密码和邮箱）
func (s *Server) handleFirstTimeSetup(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method == "GET" {
		currentEmail := s.config.SSL.Email
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>首次设置</title>
		<link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
		<link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
		</head><body class="bg-light">
		<div class="container mt-5">
			<div class="row justify-content-center">
				<div class="col-md-6">
					<div class="card shadow">
						<div class="card-header bg-primary text-white">
							<h4 class="mb-0"><i class="bi bi-gear"></i> 首次设置</h4>
						</div>
						<div class="card-body">
							<p class="text-muted mb-4">欢迎使用 SSLcat！请完成以下初始设置：</p>
							<form method="POST">
								<div class="mb-3">
									<label class="form-label"><i class="bi bi-lock"></i> 新密码</label>
									<input class="form-control" type="password" name="new_password" required placeholder="请输入新的管理员密码">
								</div>
								<div class="mb-3">
									<label class="form-label"><i class="bi bi-lock-fill"></i> 确认新密码</label>
									<input class="form-control" type="password" name="confirm_password" required placeholder="请再次输入新密码">
								</div>
								<div class="mb-3">
									<label class="form-label"><i class="bi bi-envelope"></i> 管理员邮箱</label>
									<input class="form-control" type="email" name="admin_email" required placeholder="用于SSL证书申请和通知" value="%s">
									<div class="form-text">此邮箱将用于 Let's Encrypt 证书申请和系统通知</div>
								</div>
								<div class="d-grid gap-2">
									<button class="btn btn-primary" type="submit">
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
		</body></html>`, currentEmail, s.config.AdminPrefix)
		return
	}

	if r.Method == "POST" {
		newPassword := r.FormValue("new_password")
		confirmPassword := r.FormValue("confirm_password")
		adminEmail := strings.TrimSpace(r.FormValue("admin_email"))

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

		// 更新内存与持久化密码文件
		s.config.Admin.Password = "" // 避免将明文写入 withssl.conf
		if err := os.WriteFile(s.config.Admin.PasswordFile, []byte(newPassword+"\n"), 0600); err != nil {
			http.Error(w, "failed to write password file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// 更新邮箱配置
		s.config.SSL.Email = adminEmail

		// 保存配置（不包含密码）
		if err := s.config.Save(s.config.ConfigFile); err != nil {
			http.Error(w, "failed to save config: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// 尝试启用 ACME（现在有邮箱了）
		if err := s.sslManager.EnableACME(); err != nil {
			s.log.Warnf("Failed to enable ACME: %v", err)
		}

		// 审计日志
		s.audit("first_time_setup", fmt.Sprintf("password_and_email_set:%s", adminEmail))

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
		// 更新内存与持久化密码文件
		s.config.Admin.Password = "" // 避免将明文写入 withssl.conf
		if err := os.WriteFile(s.config.Admin.PasswordFile, []byte(newp+"\n"), 0600); err != nil {
			http.Error(w, "failed to write password file: "+err.Error(), http.StatusInternalServerError)
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

// renderLoginError 渲染登录错误页面
func (s *Server) renderLoginError(w http.ResponseWriter, r *http.Request, errorMsg string) {
	// 关闭验证码功能
	data := map[string]interface{}{
		"AdminPrefix":    s.config.AdminPrefix,
		"Error":          errorMsg,
		"RequireCaptcha": false,
		"Debug":          false,
	}

	s.templateRenderer.DetectLanguageAndRender(w, r, "login.html", data)
}

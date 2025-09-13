package web

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
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
	if r.Method == "GET" {
		debugForced := strings.EqualFold(r.URL.Query().Get("debug"), "true") || r.URL.Query().Get("debug") == "1"

		// 下发人机验证要素（TOTP启用时禁用PoW）
		clientIP := s.getClientIP(r)
		nonce := ""
		bits := 0
		enablePoW := s.config.Security.EnablePoW && !s.config.Admin.EnableTOTP
		if enablePoW {
			n, b := s.powManager.Issue(clientIP)
			nonce, bits = n, b
			if s.config.Security.PoWBits > 0 {
				bits = s.config.Security.PoWBits
			}
		}
		startTs := time.Now().UnixMilli()
		honeypotName := "hp_" + func() string {
			if nonce == "" {
				return "seed000"
			}
			return nonce[:6]
		}()

		data := map[string]interface{}{
			"AdminPrefix":    s.config.AdminPrefix,
			"Error":          "",
			"RequireCaptcha": s.config.Security.EnableCaptcha,
			"RequireTOTP":    s.config.Admin.EnableTOTP,
			"Debug":          debugForced,
			// PoW
			"PowNonce": nonce,
			"PowBits":  bits,
			// 蜜罐与时长
			"HoneypotName": honeypotName,
			"FormStartTs":  startTs,
		}

		s.templateRenderer.DetectLanguageAndRender(w, r, "login.html", data)
		return
	}

	if r.Method == "POST" {
		_ = r.ParseForm()

		// 蜜罐：任何以 hp_ 开头的字段被填写则拒绝
		for k, v := range r.Form {
			if strings.HasPrefix(k, "hp_") && len(v) > 0 && strings.TrimSpace(v[0]) != "" {
				clientIP := s.getClientIP(r)
				n2, b2 := "", 0
				enablePoW := s.config.Security.EnablePoW && !s.config.Admin.EnableTOTP
				if enablePoW {
					n2, b2 = s.powManager.Issue(clientIP)
				}
				hp := "hp_" + func() string {
					if n2 == "" {
						return "seed000"
					}
					return n2[:6]
				}()
				startTs := time.Now().UnixMilli()
				data := map[string]interface{}{
					"AdminPrefix":    s.config.AdminPrefix,
					"Error":          "疑似自动化提交（蜜罐触发）",
					"RequireCaptcha": s.config.Security.EnableCaptcha,
					"RequireTOTP":    s.config.Admin.EnableTOTP,
					"Debug":          false,
					"PowNonce":       n2,
					"PowBits": func() int {
						if s.config.Security.PoWBits > 0 {
							return s.config.Security.PoWBits
						}
						return b2
					}(),
					"HoneypotName": hp,
					"FormStartTs":  startTs,
				}
				s.templateRenderer.DetectLanguageAndRender(w, r, "login.html", data)
				return
			}
		}

		// 最小填写时长：<MinFormMs 拒绝
		if ts := strings.TrimSpace(r.FormValue("form_start_ts")); ts != "" {
			if ms, err := strconv.ParseInt(ts, 10, 64); err == nil {
				minMs := int64(800)
				if s.config.Security.MinFormMs > 0 {
					minMs = int64(s.config.Security.MinFormMs)
				}
				if time.Now().UnixMilli()-ms < minMs {
					clientIP := s.getClientIP(r)
					n2, b2 := "", 0
					if s.config.Security.EnablePoW {
						n2, b2 = s.powManager.Issue(clientIP)
					}
					hp := "hp_" + func() string {
						if n2 == "" {
							return "seed000"
						}
						return n2[:6]
					}()
					startTs := time.Now().UnixMilli()
					data := map[string]interface{}{
						"AdminPrefix":    s.config.AdminPrefix,
						"Error":          "提交过快，请重试",
						"RequireCaptcha": s.config.Security.EnableCaptcha,
						"Debug":          false,
						"PowNonce":       n2,
						"PowBits": func() int {
							if s.config.Security.PoWBits > 0 {
								return s.config.Security.PoWBits
							}
							return b2
						}(),
						"HoneypotName": hp,
						"FormStartTs":  startTs,
					}
					s.templateRenderer.DetectLanguageAndRender(w, r, "login.html", data)
					return
				}
			}
		}

		// PoW 校验（按开关，TOTP启用时跳过）
		enablePoW := s.config.Security.EnablePoW && !s.config.Admin.EnableTOTP
		if enablePoW {
			n := strings.TrimSpace(r.FormValue("pow_nonce"))
			sol := strings.TrimSpace(r.FormValue("pow_solution"))
			if n == "" || sol == "" || !s.powManager.Verify(n, sol) {
				clientIP := s.getClientIP(r)
				n2, b2 := s.powManager.Issue(clientIP)
				hp := "hp_" + n2[:6]
				startTs := time.Now().UnixMilli()
				data := map[string]interface{}{
					"AdminPrefix":    s.config.AdminPrefix,
					"Error":          "人机校验失败，请重试",
					"RequireCaptcha": s.config.Security.EnableCaptcha,
					"RequireTOTP":    s.config.Admin.EnableTOTP,
					"Debug":          false,
					"PowNonce":       n2,
					"PowBits": func() int {
						if s.config.Security.PoWBits > 0 {
							return s.config.Security.PoWBits
						}
						return b2
					}(),
					"HoneypotName": hp,
					"FormStartTs":  startTs,
				}
				s.templateRenderer.DetectLanguageAndRender(w, r, "login.html", data)
				return
			}
		}

		// 图形验证码校验（按开关）
		if s.config.Security.EnableCaptcha {
			sid := strings.TrimSpace(r.FormValue("captcha_session_id"))
			code := strings.TrimSpace(r.FormValue("captcha_text"))
			if sid == "" || code == "" || !s.captchaManager.VerifyCaptchaString(sid, code) {
				clientIP := s.getClientIP(r)
				n2, b2 := s.powManager.Issue(clientIP)
				hp := "hp_" + n2[:6]
				startTs := time.Now().UnixMilli()
				data := map[string]interface{}{
					"AdminPrefix":    s.config.AdminPrefix,
					"Error":          "验证码错误，请重试",
					"RequireCaptcha": s.config.Security.EnableCaptcha,
					"RequireTOTP":    s.config.Admin.EnableTOTP,
					"Debug":          false,
					"PowNonce":       n2,
					"PowBits": func() int {
						if s.config.Security.PoWBits > 0 {
							return s.config.Security.PoWBits
						}
						return b2
					}(),
					"HoneypotName": hp,
					"FormStartTs":  startTs,
				}
				s.templateRenderer.DetectLanguageAndRender(w, r, "login.html", data)
				return
			}
		}

		// 用户名密码校验（支持 bcrypt/明文，明文将自动迁移为 bcrypt）
		username := r.FormValue("username")
		password := r.FormValue("password")
		totpCode := strings.TrimSpace(r.FormValue("totp_code"))

		if username == s.config.Admin.Username && s.verifyAdminPassword(password) {
			// TOTP 二次验证（如果启用）
			if s.config.Admin.EnableTOTP && !s.verifyTOTP(totpCode) {
				clientIP := s.getClientIP(r)
				n2, b2 := "", 0
				enablePoW := s.config.Security.EnablePoW && !s.config.Admin.EnableTOTP
				if enablePoW {
					n2, b2 = s.powManager.Issue(clientIP)
				}
				hp := "hp_" + func() string {
					if n2 == "" {
						return "seed000"
					}
					return n2[:6]
				}()
				startTs := time.Now().UnixMilli()
				data := map[string]interface{}{
					"AdminPrefix":    s.config.AdminPrefix,
					"Error":          "TOTP验证码错误",
					"RequireCaptcha": s.config.Security.EnableCaptcha,
					"RequireTOTP":    s.config.Admin.EnableTOTP,
					"Debug":          false,
					"PowNonce":       n2,
					"PowBits": func() int {
						if s.config.Security.PoWBits > 0 {
							return s.config.Security.PoWBits
						}
						return b2
					}(),
					"HoneypotName": hp,
					"FormStartTs":  startTs,
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
		nonce := ""
		bits := 0
		enablePoWForError := s.config.Security.EnablePoW && !s.config.Admin.EnableTOTP
		if enablePoWForError {
			n, b := s.powManager.Issue(clientIP)
			nonce, bits = n, b
			if s.config.Security.PoWBits > 0 {
				bits = s.config.Security.PoWBits
			}
		}
		startTs := time.Now().UnixMilli()
		honeypotName := "hp_" + func() string {
			if nonce == "" {
				return "seed000"
			}
			return nonce[:6]
		}()

		data := map[string]interface{}{
			"AdminPrefix":    s.config.AdminPrefix,
			"Error":          s.translator.T("login.invalid"),
			"RequireCaptcha": s.config.Security.EnableCaptcha,
			"RequireTOTP":    s.config.Admin.EnableTOTP,
			"Debug":          false,
			"PowNonce":       nonce,
			"PowBits":        bits,
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
	// 优先从文件读取
	if passFile != "" {
		if b, err := os.ReadFile(passFile); err == nil {
			stored = strings.TrimSpace(string(b))
		} else {
			s.log.Debugf("Failed to read password file %s: %v", passFile, err)
		}
	}
	if stored == "" {
		s.log.Debug("No password found in file or config")
		return false
	}
	
	// 调试信息
	s.log.Debugf("Password verification: file=%s, stored_prefix=%s, input_len=%d", 
		passFile, stored[:min(10, len(stored))], len(input))
	
	// bcrypt 前缀
	if strings.HasPrefix(stored, "$2a$") || strings.HasPrefix(stored, "$2b$") || strings.HasPrefix(stored, "$2y$") {
		if err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(input)); err == nil {
			s.log.Debug("bcrypt password verification successful")
			return true
		}
		s.log.Debugf("bcrypt password verification failed: %v", err)
		return false
	}
	// 明文比较（常量时间），并尝试迁移为 bcrypt
	if subtle.ConstantTimeCompare([]byte(stored), []byte(input)) == 1 {
		s.log.Debug("Plain password matched, migrating to bcrypt")
		// 迁移为 bcrypt
		if passFile != "" {
			if hash, err := bcrypt.GenerateFromPassword([]byte(input), bcrypt.DefaultCost); err == nil {
				_ = os.WriteFile(passFile, append(hash, '\n'), 0600)
				s.log.Debug("Password migrated to bcrypt successfully")
			}
		}
		return true
	}
	s.log.Debug("Password verification failed")
	return false
}

func min(a, b int) int {
	if a < b { return a }
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

	// 显示错误页面（重新生成完整表单数据）
	nonce := ""
	bits := 0
	enablePoWForFinal := s.config.Security.EnablePoW && !s.config.Admin.EnableTOTP
	if enablePoWForFinal {
		n, b := s.powManager.Issue(clientIP)
		nonce, bits = n, b
		if s.config.Security.PoWBits > 0 {
			bits = s.config.Security.PoWBits
		}
	}
	startTs := time.Now().UnixMilli()
	honeypotName := "hp_" + func() string {
		if nonce == "" {
			return "seed000"
		}
		return nonce[:6]
	}()
	
	data := map[string]interface{}{
		"AdminPrefix":    s.config.AdminPrefix,
		"Error":          s.translator.T("login.invalid"),
		"RequireCaptcha": s.config.Security.EnableCaptcha,
		"RequireTOTP":    s.config.Admin.EnableTOTP,
		"Debug":          false,
		"PowNonce":       nonce,
		"PowBits":        bits,
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

		// 更新内存与持久化密码文件（bcrypt）
		s.config.Admin.Password = "" // 避免将明文写入 withssl.conf
		if hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost); err == nil {
			if err := os.WriteFile(s.config.Admin.PasswordFile, append(hash, '\n'), 0600); err != nil {
				http.Error(w, "failed to write password file: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(w, "failed to hash password", http.StatusInternalServerError)
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
		// 更新内存与持久化密码文件（bcrypt）
		s.config.Admin.Password = "" // 避免将明文写入 withssl.conf
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

// renderLoginError 渲染登录错误页面
func (s *Server) renderLoginError(w http.ResponseWriter, r *http.Request, errorMsg string) {
	// 重新生成完整表单数据
	clientIP := s.getClientIP(r)
	nonce := ""
	bits := 0
	enablePoW := s.config.Security.EnablePoW && !s.config.Admin.EnableTOTP
	if enablePoW {
		n, b := s.powManager.Issue(clientIP)
		nonce, bits = n, b
		if s.config.Security.PoWBits > 0 {
			bits = s.config.Security.PoWBits
		}
	}
	startTs := time.Now().UnixMilli()
	honeypotName := "hp_" + func() string {
		if nonce == "" {
			return "seed000"
		}
		return nonce[:6]
	}()
	
	data := map[string]interface{}{
		"AdminPrefix":    s.config.AdminPrefix,
		"Error":          errorMsg,
		"RequireCaptcha": s.config.Security.EnableCaptcha,
		"RequireTOTP":    s.config.Admin.EnableTOTP,
		"Debug":          false,
		"PowNonce":       nonce,
		"PowBits":        bits,
		"HoneypotName":   honeypotName,
		"FormStartTs":    startTs,
	}

	s.templateRenderer.DetectLanguageAndRender(w, r, "login.html", data)
}

// CDN 缓存设置页
func (s *Server) handleCDNCache(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"CDN":         s.config.CDNCache,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateCDNCacheHTML(data)
	w.Write([]byte(html))
}

// 保存 CDN 缓存设置
func (s *Server) handleCDNCacheSave(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	enabled := r.FormValue("enabled") == "on" || r.FormValue("enabled") == "true" || r.FormValue("enabled") == "1"
	cacheDir := strings.TrimSpace(r.FormValue("cache_dir"))
	maxSize := strings.TrimSpace(r.FormValue("max_size_bytes"))
	defTTL := strings.TrimSpace(r.FormValue("default_ttl_seconds"))
	cleanInt := strings.TrimSpace(r.FormValue("clean_interval_seconds"))
	maxObj := strings.TrimSpace(r.FormValue("max_object_bytes"))

	if cacheDir != "" {
		s.config.CDNCache.CacheDir = cacheDir
	}
	s.config.CDNCache.Enabled = enabled
	if v, err := strconv.ParseInt(maxSize, 10, 64); err == nil && v >= 0 {
		s.config.CDNCache.MaxSizeBytes = v
	}
	if v, err := strconv.Atoi(defTTL); err == nil && v >= 0 {
		s.config.CDNCache.DefaultTTLSeconds = v
	}
	if v, err := strconv.Atoi(cleanInt); err == nil && v > 0 {
		s.config.CDNCache.CleanIntervalSec = v
	}
	if v, err := strconv.ParseInt(maxObj, 10, 64); err == nil && v >= 0 {
		s.config.CDNCache.MaxObjectBytes = v
	}

	// 规则：每行 matchType|patternOrMediaCSV|ttl
	rulesRaw := strings.TrimSpace(r.FormValue("rules"))
	var rules []config.CDNCacheRule
	if rulesRaw != "" {
		for _, line := range strings.Split(rulesRaw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Split(line, "|")
			if len(parts) < 3 {
				continue
			}
			matchType := strings.TrimSpace(parts[0])
			ttl, _ := strconv.Atoi(strings.TrimSpace(parts[2]))
			if strings.EqualFold(matchType, "media") {
				medias := []string{}
				for _, m := range strings.Split(parts[1], ",") {
					m = strings.TrimSpace(m)
					if m != "" {
						medias = append(medias, m)
					}
				}
				rules = append(rules, config.CDNCacheRule{MatchType: "media", MediaTypes: medias, TTLSeconds: ttl})
			} else {
				rules = append(rules, config.CDNCacheRule{MatchType: matchType, Pattern: strings.TrimSpace(parts[1]), TTLSeconds: ttl})
			}
		}
	}
	s.config.CDNCache.Rules = rules
	if s.config.CDNCache.CacheDir != "" {
		_ = os.MkdirAll(s.config.CDNCache.CacheDir, 0755)
	}
	_ = s.config.Save(s.config.ConfigFile)
	http.Redirect(w, r, s.config.AdminPrefix+"/cdn-cache", http.StatusFound)
}

// 一键清理缓存
func (s *Server) handleCDNCacheClear(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	t := strings.TrimSpace(r.FormValue("type"))
	pattern := strings.TrimSpace(r.FormValue("pattern"))
	medias := strings.TrimSpace(r.FormValue("media_types"))
	if pm, ok := interface{}(s.proxyManager).(interface {
		PurgeCDN(string, string, string) error
	}); ok {
		_ = pm.PurgeCDN(t, pattern, medias)
	}
	http.Redirect(w, r, s.config.AdminPrefix+"/cdn-cache", http.StatusFound)
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
	// 重定向到登录页
	http.Redirect(w, r, s.config.AdminPrefix+"/login", http.StatusFound)
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

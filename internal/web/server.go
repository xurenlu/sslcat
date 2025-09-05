package web

import (
	"fmt"
	"net/http"
	"strings"

	"withssl/internal/config"
	"withssl/internal/proxy"
	"withssl/internal/security"

	"github.com/sirupsen/logrus"
)

// Server Web服务器
type Server struct {
	config          *config.Config
	proxyManager    *proxy.Manager
	securityManager *security.Manager
	mux             *http.ServeMux
	log             *logrus.Entry
}

// NewServer 创建Web服务器
func NewServer(cfg *config.Config, proxyMgr *proxy.Manager, secMgr *security.Manager) *Server {
	server := &Server{
		config:          cfg,
		proxyManager:    proxyMgr,
		securityManager: secMgr,
		mux:             http.NewServeMux(),
		log: logrus.WithFields(logrus.Fields{
			"component": "web_server",
		}),
	}

	server.setupRoutes()
	return server
}

// setupRoutes 设置路由
func (s *Server) setupRoutes() {
	// 设置管理面板路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/", s.handleAdmin)
	s.mux.HandleFunc(s.config.AdminPrefix+"/login", s.handleLogin)
	s.mux.HandleFunc(s.config.AdminPrefix+"/dashboard", s.handleDashboard)
	s.mux.HandleFunc(s.config.AdminPrefix+"/proxy", s.handleProxy)
	s.mux.HandleFunc(s.config.AdminPrefix+"/ssl", s.handleSSL)
	s.mux.HandleFunc(s.config.AdminPrefix+"/security", s.handleSecurity)
	s.mux.HandleFunc(s.config.AdminPrefix+"/settings", s.handleSettings)

	// 设置API路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/stats", s.handleAPIStats)

	// 注意：项目使用 CDN 资源，无需本地静态文件服务
	// 如需本地静态文件，请创建 web/static/ 目录并取消下面的注释
	// s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static/"))))

	// 设置根路径
	s.mux.HandleFunc("/", s.handleRoot)
}

// ServeHTTP 实现http.Handler接口
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

// getClientIP 获取客户端IP
func (s *Server) getClientIP(r *http.Request) string {
	// 优先使用X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// 使用X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// 使用RemoteAddr
	return r.RemoteAddr
}

// 处理器函数

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, s.config.AdminPrefix, http.StatusFound)
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	// 检查是否已登录
	session, err := r.Cookie("withssl_session")
	if err != nil || session.Value != "authenticated" {
		http.Redirect(w, r, s.config.AdminPrefix+"/login", http.StatusFound)
		return
	}

	// 重定向到仪表板
	http.Redirect(w, r, s.config.AdminPrefix+"/dashboard", http.StatusFound)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s.renderLoginPage(w, r, "")
		return
	}

	if r.Method == "POST" {
		s.processLogin(w, r)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) renderLoginPage(w http.ResponseWriter, r *http.Request, errorMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	html := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录 - WithSSL</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); min-height: 100vh; display: flex; align-items: center; }
        .login-card { background: white; border-radius: 15px; box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1); overflow: hidden; }
        .login-header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 2rem; text-align: center; }
        .login-body { padding: 2rem; }
        .form-control { border-radius: 10px; border: 2px solid #e9ecef; padding: 0.75rem 1rem; }
        .form-control:focus { border-color: #667eea; box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25); }
        .btn-login { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); border: none; border-radius: 10px; padding: 0.75rem 2rem; font-weight: 600; }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 col-lg-4">
                <div class="login-card">
                    <div class="login-header">
                        <h3>WithSSL</h3>
                        <p class="mb-0">SSL 代理服务器管理面板</p>
                    </div>
                    <div class="login-body">
                        %s
                        <form method="POST" action="%s/login">
                            <div class="mb-3">
                                <label for="username" class="form-label">用户名</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="mb-4">
                                <label for="password" class="form-label">密码</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary btn-login">登录</button>
                            </div>
                        </form>
                        <div class="text-center mt-4">
                            <small class="text-muted">默认用户名: admin<br>默认密码: admin*9527</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>`,
		func() string {
			if errorMsg != "" {
				return fmt.Sprintf(`<div class="alert alert-danger" role="alert">%s</div>`, errorMsg)
			}
			return ""
		}(),
		s.config.AdminPrefix)

	w.Write([]byte(html))
}

func (s *Server) processLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// 验证用户名和密码
	if username == s.config.Admin.Username && password == s.config.Admin.Password {
		// 设置session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "withssl_session",
			Value:    "authenticated",
			Path:     "/",
			MaxAge:   3600,
			HttpOnly: true,
			Secure:   true,
		})

		// 重定向到仪表板
		http.Redirect(w, r, s.config.AdminPrefix+"/dashboard", http.StatusFound)
		return
	}

	// 登录失败，记录安全日志
	clientIP := s.getClientIP(r)
	s.securityManager.LogAccess(clientIP, r.Header.Get("User-Agent"), r.URL.Path, false)

	// 显示错误页面
	s.renderLoginPage(w, r, "用户名或密码错误")
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// 检查认证
	if !s.checkAuth(w, r) {
		return
	}

	stats := s.proxyManager.GetProxyStats()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>仪表板 - WithSSL</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-4">
        <h1>WithSSL 仪表板</h1>
        <div class="row">
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">活跃代理规则</h5>
                        <p class="card-text">%v</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">缓存的代理</h5>
                        <p class="card-text">%v</p>
                    </div>
                </div>
            </div>
        </div>
        <div class="mt-4">
            <a href="%s/proxy" class="btn btn-primary">管理代理规则</a>
            <a href="%s/ssl" class="btn btn-success">管理SSL证书</a>
            <a href="%s/security" class="btn btn-warning">安全设置</a>
            <a href="%s/settings" class="btn btn-info">系统设置</a>
        </div>
    </div>
</body>
</html>`,
		stats["active_rules"],
		stats["cached_proxies"],
		s.config.AdminPrefix,
		s.config.AdminPrefix,
		s.config.AdminPrefix,
		s.config.AdminPrefix)

	w.Write([]byte(html))
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>代理配置 - WithSSL</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-4">
        <h1>代理配置</h1>
        <p>代理规则管理功能正在开发中...</p>
        <a href="%s/dashboard" class="btn btn-secondary">返回仪表板</a>
    </div>
</body>
</html>`, s.config.AdminPrefix)

	w.Write([]byte(html))
}

func (s *Server) handleSSL(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSL证书 - WithSSL</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-4">
        <h1>SSL证书管理</h1>
        <p>SSL证书管理功能正在开发中...</p>
        <a href="%s/dashboard" class="btn btn-secondary">返回仪表板</a>
    </div>
</body>
</html>`, s.config.AdminPrefix)

	w.Write([]byte(html))
}

func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全设置 - WithSSL</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-4">
        <h1>安全设置</h1>
        <p>安全设置功能正在开发中...</p>
        <a href="%s/dashboard" class="btn btn-secondary">返回仪表板</a>
    </div>
</body>
</html>`, s.config.AdminPrefix)

	w.Write([]byte(html))
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>系统设置 - WithSSL</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-4">
        <h1>系统设置</h1>
        <p>系统设置功能正在开发中...</p>
        <a href="%s/dashboard" class="btn btn-secondary">返回仪表板</a>
    </div>
</body>
</html>`, s.config.AdminPrefix)

	w.Write([]byte(html))
}

func (s *Server) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	stats := s.proxyManager.GetProxyStats()

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"active_rules": %v, "cached_proxies": %v}`,
		stats["active_rules"], stats["cached_proxies"])
}

func (s *Server) handleDefault(w http.ResponseWriter, r *http.Request, domain string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WithSSL - SSL 代理服务器</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); min-height: 100vh; display: flex; align-items: center; }
        .main-card { background: white; border-radius: 15px; box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1); overflow: hidden; }
        .main-header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 3rem 2rem; text-align: center; }
        .main-body { padding: 3rem 2rem; }
        .btn-admin { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); border: none; border-radius: 10px; padding: 0.75rem 2rem; font-weight: 600; color: white; text-decoration: none; display: inline-block; }
        .btn-admin:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4); color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-8 col-lg-6">
                <div class="main-card">
                    <div class="main-header">
                        <h1>WithSSL</h1>
                        <p class="mb-0">SSL 代理服务器</p>
                    </div>
                    <div class="main-body text-center">
                        <h3>域名未配置</h3>
                        <p class="text-muted">域名 <strong>%s</strong> 尚未配置代理转发规则</p>
                        <div class="d-grid gap-2">
                            <a href="%s" class="btn-admin">进入管理面板</a>
                        </div>
                        <div class="mt-4">
                            <small class="text-muted">请通过管理面板配置域名转发规则</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>`, domain, s.config.AdminPrefix)

	w.Write([]byte(html))
}

// checkAuth 检查认证状态
func (s *Server) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	session, err := r.Cookie("withssl_session")
	if err != nil || session.Value != "authenticated" {
		http.Redirect(w, r, s.config.AdminPrefix+"/login", http.StatusFound)
		return false
	}
	return true
}

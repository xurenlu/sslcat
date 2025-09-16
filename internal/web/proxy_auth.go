package web

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

// ProxyAuthSession 代理访问控制会话
type ProxyAuthSession struct {
	Domain    string    `json:"domain"`
	Username  string    `json:"username"`
	LoginTime time.Time `json:"login_time"`
	ExpiresAt time.Time `json:"expires_at"`
	SessionID string    `json:"session_id"`
}

// ProxyAuthManager 代理访问控制管理器
type ProxyAuthManager struct {
	sessions map[string]*ProxyAuthSession // sessionID -> session
	log      Logger
}

type Logger interface {
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// NewProxyAuthManager 创建代理访问控制管理器
func NewProxyAuthManager(log Logger) *ProxyAuthManager {
	manager := &ProxyAuthManager{
		sessions: make(map[string]*ProxyAuthSession),
		log:      log,
	}

	// 启动会话清理 goroutine
	go manager.cleanupExpiredSessions()

	return manager
}

// CheckAuth 检查访问权限，返回是否已认证
func (p *ProxyAuthManager) CheckAuth(r *http.Request, rule *config.ProxyRule) bool {
	if !rule.AuthEnabled {
		return true // 未开启认证则直接通过
	}

	// 从cookie中获取session
	cookie, err := r.Cookie(p.getSessionCookieName(rule.Domain))
	if err != nil {
		return false // 没有session cookie
	}

	session, exists := p.sessions[cookie.Value]
	if !exists {
		return false // session不存在
	}

	// 检查session是否过期
	if time.Now().After(session.ExpiresAt) {
		delete(p.sessions, cookie.Value)
		return false // session已过期
	}

	// 检查domain匹配
	if session.Domain != rule.Domain {
		return false // domain不匹配
	}

	return true
}

// ShowLoginPage 显示登录页面
func (p *ProxyAuthManager) ShowLoginPage(w http.ResponseWriter, r *http.Request, rule *config.ProxyRule, errorMsg string) {
	// 生成简单的登录页面HTML
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>访问认证 - %s</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .login-container {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            width: 100%%;
            max-width: 400px;
        }
        .login-header {
            text-align: center;
            margin-bottom: 2rem;
        }
        .login-header h1 {
            color: #333;
            margin: 0;
            font-size: 1.5rem;
        }
        .domain-info {
            color: #666;
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }
        .form-group {
            margin-bottom: 1rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            color: #333;
            font-weight: 500;
        }
        input[type="text"], input[type="password"] {
            width: 100%%;
            padding: 0.75rem;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 1rem;
            box-sizing: border-box;
        }
        input[type="text"]:focus, input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
        }
        .login-btn {
            width: 100%%;
            padding: 0.75rem;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 1rem;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        .login-btn:hover {
            background: #5a67d8;
        }
        .error-msg {
            background: #fee;
            color: #c53030;
            padding: 0.75rem;
            border-radius: 5px;
            margin-bottom: 1rem;
            border: 1px solid #feb2b2;
        }
        .footer {
            text-align: center;
            margin-top: 1rem;
            color: #666;
            font-size: 0.8rem;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>访问认证</h1>
            <div class="domain-info">%s</div>
        </div>
        
        %s
        
        <form method="POST" action="">
            <div class="form-group">
                <label for="username">用户名</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">密码</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="login-btn">登录</button>
        </form>
        
        <div class="footer">
            由 SSLcat 提供服务
        </div>
    </div>
</body>
</html>`, rule.Domain, rule.Domain, func() string {
		if errorMsg != "" {
			return fmt.Sprintf(`<div class="error-msg">%s</div>`, errorMsg)
		}
		return ""
	}())

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// ProcessLogin 处理登录请求
func (p *ProxyAuthManager) ProcessLogin(w http.ResponseWriter, r *http.Request, rule *config.ProxyRule) bool {
	if r.Method != "POST" {
		return false
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := strings.TrimSpace(r.FormValue("password"))

	if username == "" || password == "" {
		p.ShowLoginPage(w, r, rule, "用户名和密码不能为空")
		return true
	}

	// 验证用户名密码
	var validUser *config.ProxyAuthUser
	for _, user := range rule.AuthUsers {
		if user.Username == username && user.Password == password {
			validUser = &user
			break
		}
	}

	if validUser == nil {
		p.ShowLoginPage(w, r, rule, "用户名或密码错误")
		return true
	}

	// 创建会话
	sessionID := p.generateSessionID()
	session := &ProxyAuthSession{
		Domain:    rule.Domain,
		Username:  validUser.Username,
		LoginTime: time.Now(),
		ExpiresAt: time.Now().Add(time.Duration(rule.AuthSessionTimeout) * time.Second),
		SessionID: sessionID,
	}

	p.sessions[sessionID] = session

	// 设置cookie
	cookie := &http.Cookie{
		Name:     p.getSessionCookieName(rule.Domain),
		Value:    sessionID,
		Path:     "/",
		Domain:   rule.AuthCookieDomain,
		MaxAge:   rule.AuthSessionTimeout,
		HttpOnly: true,
		Secure:   r.TLS != nil, // 如果是HTTPS则设置Secure
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, cookie)

	p.log.Infof("用户 %s 成功登录代理域名 %s", validUser.Username, rule.Domain)

	// 重定向到原始URL
	redirectURL := r.URL.String()
	if redirectURL == "" {
		redirectURL = "/"
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
	return true
}

// generateSessionID 生成会话ID
func (p *ProxyAuthManager) generateSessionID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

// getSessionCookieName 获取会话cookie名称
func (p *ProxyAuthManager) getSessionCookieName(domain string) string {
	return fmt.Sprintf("sslcat_proxy_auth_%s", strings.ReplaceAll(domain, ".", "_"))
}

// cleanupExpiredSessions 定期清理过期会话
func (p *ProxyAuthManager) cleanupExpiredSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		for sessionID, session := range p.sessions {
			if now.After(session.ExpiresAt) {
				delete(p.sessions, sessionID)
				p.log.Infof("清理过期会话: domain=%s, username=%s", session.Domain, session.Username)
			}
		}
	}
}

// LogoutUser 注销用户
func (p *ProxyAuthManager) LogoutUser(w http.ResponseWriter, r *http.Request, domain string) {
	cookie, err := r.Cookie(p.getSessionCookieName(domain))
	if err == nil {
		delete(p.sessions, cookie.Value)

		// 清除cookie
		http.SetCookie(w, &http.Cookie{
			Name:     p.getSessionCookieName(domain),
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		})
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

// GetSessionInfo 获取会话信息（用于调试）
func (p *ProxyAuthManager) GetSessionInfo(domain string) map[string]interface{} {
	count := 0
	users := make([]string, 0)

	for _, session := range p.sessions {
		if session.Domain == domain && time.Now().Before(session.ExpiresAt) {
			count++
			users = append(users, session.Username)
		}
	}

	return map[string]interface{}{
		"domain":       domain,
		"active_count": count,
		"active_users": users,
	}
}

package web

import (
	"encoding/json"
	"net/http"
)

// handleAPIAuthLogin 处理登录 API
func (s *Server) handleAPIAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Username == "" || req.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "username and password are required"})
		return
	}

	// 使用现有的认证逻辑
	s.log.Infof("API Login attempt: username='%s'", req.Username)

	// 多账户认证逻辑
	var authenticatedUser *User

	// 1. 首先尝试普通用户认证
	user, err := s.userManager.AuthenticateUser(req.Username, req.Password)
	if err == nil {
		authenticatedUser = user
		s.log.Infof("普通用户认证成功: %s (角色: %s)", req.Username, user.Role)
	} else {
		s.log.Debugf("普通用户认证失败: %v", err)

		// 2. 如果普通用户认证失败，尝试超级管理员认证
		usernameMatch := req.Username == s.config.Admin.Username
		passwordMatch := s.verifyAdminPassword(req.Password)

		if usernameMatch && passwordMatch {
			// 创建超级管理员用户对象
			authenticatedUser = &User{
				Username: req.Username,
				Role:     RoleSuperAdmin,
				IsActive: true,
			}
			s.log.Infof("超级管理员认证成功: %s", req.Username)
		}
	}

	if authenticatedUser != nil {
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
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "failed to create session"})
			return
		}

		// 设置会话Cookie
		s.sessionManager.SetSessionCookie(w, session.SessionID, r.TLS != nil)

		// 记录用户操作日志
		s.userManager.LogUserAction(
			authenticatedUser.Username,
			"login_success",
			"system",
			"API登录成功",
			clientIP,
			userAgent,
		)

		// 审计
		s.audit("login_success", authenticatedUser.Username)

		// 返回用户信息
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"user": map[string]interface{}{
				"username": authenticatedUser.Username,
				"role":     authenticatedUser.Role,
			},
		})
		return
	}

	// 登录失败，记录安全日志
	clientIP := s.getClientIP(r)
	s.securityManager.LogAccess(clientIP, r.Header.Get("User-Agent"), r.URL.Path, false)
	s.audit("login_failed", clientIP)

	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"})
}

// handleAPIAuthLogout 处理登出 API
func (s *Server) handleAPIAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取当前会话
	session, exists := s.sessionManager.GetSessionFromRequest(r)
	if exists {
		// 记录登出日志
		s.userManager.LogUserAction(
			session.Username,
			"logout",
			"system",
			"API登出",
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "logged out successfully",
	})
}

// handleAPIAuthMe 获取当前用户信息
func (s *Server) handleAPIAuthMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取当前会话
	session, exists := s.sessionManager.GetSessionFromRequest(r)
	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "not authenticated"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username": session.Username,
		"role":     session.Role,
	})
}

package web

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnSessionStore WebAuthn 会话数据临时存储
var webauthnSessionStore = struct {
	sync.RWMutex
	data map[string]*webauthn.SessionData
}{
	data: make(map[string]*webauthn.SessionData),
}

// saveWebAuthnSession 保存会话数据
func saveWebAuthnSession(key string, sessionData *webauthn.SessionData) {
	webauthnSessionStore.Lock()
	defer webauthnSessionStore.Unlock()
	webauthnSessionStore.data[key] = sessionData
	
	// 5分钟后自动清理
	go func() {
		time.Sleep(5 * time.Minute)
		webauthnSessionStore.Lock()
		delete(webauthnSessionStore.data, key)
		webauthnSessionStore.Unlock()
	}()
}

// getWebAuthnSession 获取会话数据
func getWebAuthnSession(key string) *webauthn.SessionData {
	webauthnSessionStore.RLock()
	defer webauthnSessionStore.RUnlock()
	return webauthnSessionStore.data[key]
}

// deleteWebAuthnSession 删除会话数据
func deleteWebAuthnSession(key string) {
	webauthnSessionStore.Lock()
	defer webauthnSessionStore.Unlock()
	delete(webauthnSessionStore.data, key)
}

// handleAPIWebAuthnBeginRegistration 开始 WebAuthn 注册
func (s *Server) handleAPIWebAuthnBeginRegistration(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username   string `json:"username"`
		DeviceName string `json:"device_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	// 获取当前登录用户
	session, exists := s.sessionManager.GetSessionFromRequest(r)
	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "not authenticated"})
		return
	}

	// 只能为自己的账户注册
	if req.Username != session.Username {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "只能为自己的账户注册 WebAuthn"})
		return
	}

	// 获取用户
	user, err := s.webauthnManager.GetUser(req.Username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "获取用户失败"})
		return
	}

	// 生成注册选项
	options, sessionData, err := s.webauthnManager.webauthn.BeginRegistration(user)
	if err != nil {
		s.log.Errorf("生成 WebAuthn 注册选项失败: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "生成注册选项失败"})
		return
	}

	// 保存会话数据（临时存储，用于后续验证）
	sessionKey := "webauthn_reg_" + session.Username + "_" + time.Now().Format("20060102150405")
	saveWebAuthnSession(sessionKey, sessionData)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"options":      options,
		"session_key":  sessionKey,
		"device_name":  req.DeviceName,
	})
}

// handleAPIWebAuthnFinishRegistration 完成 WebAuthn 注册
func (s *Server) handleAPIWebAuthnFinishRegistration(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 读取请求体（需要保存以便后续传递给 webauthn 库）
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "读取请求体失败"})
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	var req struct {
		SessionKey string `json:"session_key"`
		DeviceName string `json:"device_name"`
	}

	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	// 获取当前登录用户
	session, exists := s.sessionManager.GetSessionFromRequest(r)
	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "not authenticated"})
		return
	}

	// 从临时存储获取 sessionData
	sessionData := getWebAuthnSession(req.SessionKey)
	if sessionData == nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "会话已过期，请重新开始注册"})
		return
	}

	// 获取用户
	user, err := s.webauthnManager.GetUser(session.Username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "获取用户失败"})
		return
	}

	// 恢复请求体供 webauthn 库使用
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// 验证并完成注册（直接使用 http.Request）
	credential, err := s.webauthnManager.webauthn.FinishRegistration(user, *sessionData, r)
	if err != nil {
		s.log.Errorf("完成 WebAuthn 注册失败: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "注册失败: " + err.Error()})
		return
	}

	// 保存凭证并删除会话数据
	if err := s.webauthnManager.SaveCredential(user.ID, user.Username, credential, req.DeviceName); err != nil {
		s.log.Errorf("保存 WebAuthn 凭证失败: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "保存凭证失败"})
		return
	}
	deleteWebAuthnSession(req.SessionKey)

	// 审计日志
	s.audit("webauthn_registered", session.Username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "WebAuthn 凭证注册成功",
	})
}

// handleAPIWebAuthnBeginLogin 开始 WebAuthn 登录
func (s *Server) handleAPIWebAuthnBeginLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	// 获取用户
	user, err := s.webauthnManager.GetUser(req.Username)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "用户不存在或未注册 WebAuthn"})
		return
	}

	// 生成登录选项
	options, sessionData, err := s.webauthnManager.webauthn.BeginLogin(user)
	if err != nil {
		s.log.Errorf("生成 WebAuthn 登录选项失败: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "生成登录选项失败"})
		return
	}

	// 保存会话数据
	sessionKey := "webauthn_login_" + req.Username + "_" + time.Now().Format("20060102150405")
	saveWebAuthnSession(sessionKey, sessionData)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"options":     options,
		"session_key": sessionKey,
	})
}

// handleAPIWebAuthnFinishLogin 完成 WebAuthn 登录
func (s *Server) handleAPIWebAuthnFinishLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 读取请求体（需要保存以便后续传递给 webauthn 库）
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "读取请求体失败"})
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	var req struct {
		Username   string `json:"username"`
		SessionKey string `json:"session_key"`
	}

	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	// 从临时存储获取 sessionData
	sessionData := getWebAuthnSession(req.SessionKey)
	if sessionData == nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "会话已过期，请重新开始登录"})
		return
	}

	// 获取用户
	user, err := s.webauthnManager.GetUser(req.Username)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "用户不存在"})
		return
	}

	// 恢复请求体供 webauthn 库使用
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// 验证并完成登录（直接使用 http.Request）
	credential, err := s.webauthnManager.webauthn.FinishLogin(user, *sessionData, r)
	if err != nil {
		s.log.Errorf("完成 WebAuthn 登录失败: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "登录失败: " + err.Error()})
		return
	}

	// 更新凭证计数器并删除会话数据
	credentialIDBase64 := base64.RawURLEncoding.EncodeToString(credential.ID)
	if err := s.webauthnManager.UpdateCredentialCounter(credentialIDBase64, credential.Authenticator.SignCount); err != nil {
		s.log.Warnf("更新凭证计数器失败: %v", err)
	}
	deleteWebAuthnSession(req.SessionKey)

	// 创建会话
	clientIP := s.getClientIP(r)
	userAgent := r.Header.Get("User-Agent")
	
	// 确定用户角色（这里简化处理，实际应该从数据库获取）
	userRole := RoleSuperAdmin // 默认超级管理员
	if req.Username != s.config.Admin.Username {
		// 尝试从用户管理器获取
		if dbUser, err := s.userManager.GetUserByUsername(req.Username); err == nil {
			userRole = dbUser.Role
		}
	}

	session, err := s.sessionManager.CreateSession(
		req.Username,
		userRole,
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

	// 审计日志
	s.audit("webauthn_login_success", req.Username)
	s.log.Infof("WebAuthn 登录成功: %s (IP: %s)", req.Username, clientIP)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"user": map[string]interface{}{
			"username": req.Username,
			"role":     userRole,
		},
	})
}

// handleAPIWebAuthnListCredentials 列出用户的 WebAuthn 凭证
func (s *Server) handleAPIWebAuthnListCredentials(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取当前登录用户
	session, exists := s.sessionManager.GetSessionFromRequest(r)
	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "not authenticated"})
		return
	}

	credentials, err := s.webauthnManager.GetCredentials(session.Username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "获取凭证列表失败"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"credentials": credentials,
	})
}

// handleAPIWebAuthnDeleteCredential 删除 WebAuthn 凭证
func (s *Server) handleAPIWebAuthnDeleteCredential(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		CredentialID string `json:"credential_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	// 获取当前登录用户
	session, exists := s.sessionManager.GetSessionFromRequest(r)
	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "not authenticated"})
		return
	}

	if err := s.webauthnManager.DeleteCredential(req.CredentialID, session.Username); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// 审计日志
	s.audit("webauthn_credential_deleted", session.Username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "凭证已删除",
	})
}


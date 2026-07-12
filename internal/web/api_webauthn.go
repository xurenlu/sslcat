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

	// 将 options 序列化为 JSON，然后反序列化以确保格式正确
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		s.log.Errorf("序列化 WebAuthn 选项失败: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "序列化选项失败"})
		return
	}

	// 调试：打印序列化后的 JSON（前500字符）
	jsonStr := string(optionsJSON)
	if len(jsonStr) > 500 {
		s.log.Infof("WebAuthn 注册选项 JSON (前500字符): %s...", jsonStr[:500])
	} else {
		s.log.Infof("WebAuthn 注册选项 JSON: %s", jsonStr)
	}

	var optionsMap map[string]interface{}
	if err := json.Unmarshal(optionsJSON, &optionsMap); err != nil {
		s.log.Errorf("反序列化 WebAuthn 选项失败: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "处理选项失败"})
		return
	}

	// 调试：打印 optionsMap 的键
	keys := make([]string, 0, len(optionsMap))
	for k := range optionsMap {
		keys = append(keys, k)
	}
	s.log.Infof("WebAuthn 注册选项的键: %v", keys)

	// CredentialCreation 结构：{ Response: { PublicKey: {...} } }
	// 序列化后可能是 { Response: { PublicKey: {...} } } 或 { publicKey: {...} }
	var publicKeyOptions map[string]interface{}

	// 先检查 Response.PublicKey
	if response, ok := optionsMap["Response"].(map[string]interface{}); ok {
		s.log.Infof("找到 Response 字段")
		if publicKey, ok := response["PublicKey"].(map[string]interface{}); ok {
			s.log.Infof("找到 Response.PublicKey 字段")
			publicKeyOptions = publicKey
		} else if publicKey, ok := response["publicKey"].(map[string]interface{}); ok {
			s.log.Infof("找到 Response.publicKey 字段（小写）")
			publicKeyOptions = publicKey
		} else {
			s.log.Infof("Response 中没有 PublicKey，直接使用 Response")
			publicKeyOptions = response
		}
	} else if publicKey, ok := optionsMap["PublicKey"].(map[string]interface{}); ok {
		s.log.Infof("找到 PublicKey 字段（顶层）")
		publicKeyOptions = publicKey
	} else if publicKey, ok := optionsMap["publicKey"].(map[string]interface{}); ok {
		s.log.Infof("找到 publicKey 字段（顶层，小写）")
		publicKeyOptions = publicKey
	} else {
		s.log.Infof("未找到嵌套结构，直接使用整个 optionsMap")
		publicKeyOptions = optionsMap
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"options":     publicKeyOptions, // 直接返回 publicKeyOptions，不再包装
		"session_key": sessionKey,
		"device_name": req.DeviceName,
		"rp_id":       s.webauthnManager.RPID(),
		"rp_origin":   s.webauthnManager.RPOrigin(),
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

	// 读取请求体
	bodyBytes, err := s.readLimitedRequestBody(w, r, defaultJSONBodyLimit)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "读取请求体失败"})
		return
	}

	// 解析请求，提取 session_key、device_name 和 response
	var req struct {
		SessionKey string                 `json:"session_key"`
		DeviceName string                 `json:"device_name"`
		Response   map[string]interface{} `json:"response"`
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

	// 将 response 转换为 JSON，作为新的请求体传递给 webauthn 库
	// go-webauthn 库期望请求体直接是 CredentialCreationResponse
	responseBytes, err := json.Marshal(req.Response)
	if err != nil {
		s.log.Errorf("序列化 WebAuthn 响应失败: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "处理响应失败"})
		return
	}

	// 创建新的请求体供 webauthn 库使用
	r.Body = io.NopCloser(bytes.NewBuffer(responseBytes))

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

	// 将 options 序列化为 JSON，然后反序列化以确保格式正确
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		s.log.Errorf("序列化 WebAuthn 选项失败: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "序列化选项失败"})
		return
	}

	// 调试：打印序列化后的 JSON（前500字符）
	jsonStr := string(optionsJSON)
	if len(jsonStr) > 500 {
		s.log.Infof("WebAuthn 登录选项 JSON (前500字符): %s...", jsonStr[:500])
	} else {
		s.log.Infof("WebAuthn 登录选项 JSON: %s", jsonStr)
	}

	var optionsMap map[string]interface{}
	if err := json.Unmarshal(optionsJSON, &optionsMap); err != nil {
		s.log.Errorf("反序列化 WebAuthn 选项失败: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "处理选项失败"})
		return
	}

	// 调试：打印 optionsMap 的键
	keys := make([]string, 0, len(optionsMap))
	for k := range optionsMap {
		keys = append(keys, k)
	}
	s.log.Infof("WebAuthn 登录选项的键: %v", keys)

	// CredentialAssertion 结构包含 Response 字段，Response 字段又包含 PublicKey 字段
	// 需要提取 PublicKeyCredentialRequestOptions
	var publicKeyOptions map[string]interface{}
	if response, ok := optionsMap["Response"].(map[string]interface{}); ok {
		s.log.Infof("找到 Response 字段")
		// 如果存在 Response 字段，检查是否有 PublicKey 字段
		if publicKey, ok := response["PublicKey"].(map[string]interface{}); ok {
			s.log.Infof("找到 Response.PublicKey 字段")
			publicKeyOptions = publicKey
		} else if publicKey, ok := response["publicKey"].(map[string]interface{}); ok {
			s.log.Infof("找到 Response.publicKey 字段（小写）")
			publicKeyOptions = publicKey
		} else {
			// 如果没有 PublicKey 字段，直接使用 Response
			s.log.Infof("Response 中没有 PublicKey，直接使用 Response")
			publicKeyOptions = response
		}
	} else if publicKey, ok := optionsMap["PublicKey"].(map[string]interface{}); ok {
		s.log.Infof("找到 PublicKey 字段（顶层）")
		publicKeyOptions = publicKey
	} else if publicKey, ok := optionsMap["publicKey"].(map[string]interface{}); ok {
		s.log.Infof("找到 publicKey 字段（顶层，小写）")
		publicKeyOptions = publicKey
	} else {
		// 如果没有找到，直接使用整个 optionsMap
		s.log.Infof("未找到嵌套结构，直接使用整个 optionsMap")
		publicKeyOptions = optionsMap
	}

	// 调试：打印选项的键和 challenge 字段
	publicKeyKeys := make([]string, 0, len(publicKeyOptions))
	for k := range publicKeyOptions {
		publicKeyKeys = append(publicKeyKeys, k)
	}
	s.log.Infof("WebAuthn 登录选项的键: %v", publicKeyKeys)
	if challenge, ok := publicKeyOptions["challenge"]; ok {
		s.log.Infof("WebAuthn 登录选项的 challenge 类型: %T, 值: %v", challenge, challenge)
	} else {
		s.log.Warnf("WebAuthn 登录选项中没有找到 challenge 字段")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"options":     publicKeyOptions, // 直接返回 publicKeyOptions，不再包装
		"session_key": sessionKey,
		"rp_id":       s.webauthnManager.RPID(),
		"rp_origin":   s.webauthnManager.RPOrigin(),
	})
}

// handleAPIWebAuthnFinishLogin 完成 WebAuthn 登录
func (s *Server) handleAPIWebAuthnFinishLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 读取请求体
	bodyBytes, err := s.readLimitedRequestBody(w, r, defaultJSONBodyLimit)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "读取请求体失败"})
		return
	}

	// 解析请求，提取 username、session_key 和 response
	var req struct {
		Username   string                 `json:"username"`
		SessionKey string                 `json:"session_key"`
		Response   map[string]interface{} `json:"response"`
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

	// 将 response 转换为 JSON，作为新的请求体传递给 webauthn 库
	// go-webauthn 库期望请求体直接是 CredentialAssertionResponse
	responseBytes, err := json.Marshal(req.Response)
	if err != nil {
		s.log.Errorf("序列化 WebAuthn 响应失败: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "处理响应失败"})
		return
	}

	// 创建新的请求体供 webauthn 库使用
	r.Body = io.NopCloser(bytes.NewBuffer(responseBytes))

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

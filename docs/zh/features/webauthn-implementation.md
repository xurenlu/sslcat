# 指纹登录实现文档

## 概述

SSLcat 的指纹登录功能基于 **WebAuthn（Web Authentication）** 标准实现。WebAuthn 是 W3C 制定的 Web 认证标准，允许用户使用生物识别（指纹、Face ID、Touch ID）或设备 PIN 码进行身份验证，无需输入密码。

### 功能特性

- ✅ 支持指纹识别（Chrome、Edge、Safari）
- ✅ 支持 Face ID / Touch ID（macOS、iOS）
- ✅ 支持 Windows Hello
- ✅ 支持硬件安全密钥（如 YubiKey）
- ✅ 多设备管理：可以为同一账户注册多个设备
- ✅ 安全的公钥加密：私钥存储在设备安全区域，服务器只存储公钥
- ✅ 防重放攻击：使用挑战-响应机制
- ✅ 凭证计数器：防止凭证克隆攻击

## 技术架构

### 核心组件

1. **后端组件**
   - `WebAuthnManager` (`internal/web/webauthn_manager.go`): WebAuthn 管理器，负责凭证存储和管理
   - `api_webauthn.go`: WebAuthn API 路由处理
   - SQLite 数据库：存储 WebAuthn 凭证

2. **前端组件**
   - `Login.tsx`: 登录页面，包含 WebAuthn 登录入口
   - `Settings.tsx`: 设置页面，管理 WebAuthn 凭证
   - `FirstTimeSetup.tsx`: 首次设置向导，引导用户注册 WebAuthn

3. **依赖库**
   - 后端：`github.com/go-webauthn/webauthn`
   - 前端：浏览器原生 WebAuthn API (`navigator.credentials`)

## 后端实现

### 1. WebAuthn 管理器初始化

在 `internal/web/server.go` 的 `NewServer` 函数中初始化 WebAuthn 管理器：

```321:368:internal/web/server.go
	// 初始化 WebAuthn 管理器
	// 确定 RPID 和 RPOrigin
	// WebAuthn 要求 RPID 必须是有效的域名，不能是 IP 地址
	rpID := cfg.Server.Host
	if rpID == "" || rpID == "0.0.0.0" {
		rpID = "localhost"
	}
	// 移除端口号（如果有）
	if idx := strings.Index(rpID, ":"); idx != -1 {
		rpID = rpID[:idx]
	}
	// 检查是否是 IP 地址，如果是则使用 localhost
	if net.ParseIP(rpID) != nil {
		rpID = "localhost"
	}

	// 确定 RPOrigin
	port := 8080
	if cfg.Server.PortMode == "custom" && cfg.Server.CustomPort != 0 {
		port = cfg.Server.CustomPort
	}

	protocol := "http"
	if cfg.Server.EnableHTTPS || port == 443 {
		protocol = "https"
	}

	// 构建 RPOrigin（标准端口不需要显示端口号）
	var rpOrigin string
	if (protocol == "http" && port == 80) || (protocol == "https" && port == 443) {
		rpOrigin = fmt.Sprintf("%s://%s", protocol, rpID)
	} else {
		rpOrigin = fmt.Sprintf("%s://%s:%d", protocol, rpID, port)
	}

	webauthnManager, err := NewWebAuthnManager(
		server.log.WithField("component", "webauthn"),
		dataDir,
		rpID,
		rpOrigin,
	)
	if err != nil {
		server.log.Warnf("WebAuthn 初始化失败（功能将不可用）: %v", err)
		// 不阻止服务器启动，WebAuthn 功能将不可用
	} else {
		server.webauthnManager = webauthnManager
		server.log.Infof("WebAuthn 管理器已初始化，RPID: %s, RPOrigin: %s", rpID, rpOrigin)
	}
```

### 2. WebAuthn 管理器结构

`WebAuthnManager` 负责管理 WebAuthn 凭证的存储和验证：

```61:126:internal/web/webauthn_manager.go
// WebAuthnManager WebAuthn 管理器
type WebAuthnManager struct {
	db       *sql.DB
	webauthn *webauthn.WebAuthn
	dbPath   string
	log      WebAuthnLogger
}

// WebAuthnLogger WebAuthn 日志接口
type WebAuthnLogger interface {
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
}

// NewWebAuthnManager 创建 WebAuthn 管理器
func NewWebAuthnManager(log WebAuthnLogger, dataDir string, rpID string, rpOrigin string) (*WebAuthnManager, error) {
	dbPath := filepath.Join(dataDir, "webauthn.db")

	// 确保数据目录存在
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %v", err)
	}

	// 配置SQLite连接
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_synchronous=NORMAL&_cache_size=10000&_timeout=30000&_busy_timeout=30000", dbPath)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %v", err)
	}

	// 配置连接池
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	manager := &WebAuthnManager{
		db:     db,
		dbPath: dbPath,
		log:    log,
	}

	// 初始化数据库表
	if err := manager.initDatabase(); err != nil {
		return nil, fmt.Errorf("初始化数据库失败: %v", err)
	}

	// 初始化 WebAuthn
	wconfig := &webauthn.Config{
		RPDisplayName: "SSLcat",
		RPID:          rpID,
		RPOrigin:      rpOrigin,
		// 使用默认的挑战超时时间（5分钟）
		Timeout: 300000, // 毫秒
	}

	wa, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("初始化 WebAuthn 失败: %v", err)
	}

	manager.webauthn = wa

	return manager, nil
}
```

### 3. 数据库设计

WebAuthn 凭证存储在 SQLite 数据库中：

```128:163:internal/web/webauthn_manager.go
// initDatabase 初始化数据库表
func (wm *WebAuthnManager) initDatabase() error {
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS webauthn_credentials (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		username TEXT NOT NULL,
		credential_id TEXT NOT NULL UNIQUE,
		public_key TEXT NOT NULL,
		counter INTEGER DEFAULT 0,
		device_name TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_used_at DATETIME,
		is_active BOOLEAN DEFAULT 1
	);
	`

	if _, err := wm.db.Exec(createTableSQL); err != nil {
		return fmt.Errorf("创建 WebAuthn 凭证表失败: %v", err)
	}

	// 创建索引
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_webauthn_user_id ON webauthn_credentials(user_id);",
		"CREATE INDEX IF NOT EXISTS idx_webauthn_username ON webauthn_credentials(username);",
		"CREATE INDEX IF NOT EXISTS idx_webauthn_credential_id ON webauthn_credentials(credential_id);",
	}

	for _, indexSQL := range indexes {
		if _, err := wm.db.Exec(indexSQL); err != nil {
			wm.log.Warnf("创建索引失败: %v", err)
		}
	}

	return nil
}
```

**表结构说明：**
- `id`: 主键，Base64 编码的凭证 ID
- `user_id`: 用户 ID（与用户名相同）
- `username`: 用户名
- `credential_id`: 凭证 ID（Base64 编码，唯一）
- `public_key`: 公钥（JSON 格式）
- `counter`: 签名计数器，用于防止重放攻击
- `device_name`: 设备名称（如 "Chrome on MacBook"）
- `created_at`: 创建时间
- `last_used_at`: 最后使用时间
- `is_active`: 是否激活（软删除）

### 4. API 路由注册

WebAuthn API 路由在 `server.go` 的 `setupRoutes` 函数中注册：

```go
// WebAuthn API 路由
s.mux.HandleFunc(s.config.AdminPrefix+"/api/webauthn/register/begin", s.handleAPIWebAuthnBeginRegistration)
s.mux.HandleFunc(s.config.AdminPrefix+"/api/webauthn/register/finish", s.handleAPIWebAuthnFinishRegistration)
s.mux.HandleFunc(s.config.AdminPrefix+"/api/webauthn/login/begin", s.handleAPIWebAuthnBeginLogin)
s.mux.HandleFunc(s.config.AdminPrefix+"/api/webauthn/login/finish", s.handleAPIWebAuthnFinishLogin)
s.mux.HandleFunc(s.config.AdminPrefix+"/api/webauthn/credentials", s.handleAPIWebAuthnListCredentials)
s.mux.HandleFunc(s.config.AdminPrefix+"/api/webauthn/credentials/delete", s.handleAPIWebAuthnDeleteCredential)
```

## 完整流程

### 注册流程

1. **开始注册** (`handleAPIWebAuthnBeginRegistration`)
   - 用户在前端输入设备名称
   - 前端调用 `/api/webauthn/register/begin`
   - 后端生成注册选项（challenge、RP 信息等）
   - 保存会话数据到内存（5 分钟过期）
   - 返回注册选项和会话密钥

```52:177:internal/web/api_webauthn.go
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
		"success":      true,
		"options":      publicKeyOptions, // 直接返回 publicKeyOptions，不再包装
		"session_key":  sessionKey,
		"device_name":  req.DeviceName,
	})
}
```

2. **浏览器验证**
   - 前端调用 `navigator.credentials.create()` 
   - 浏览器弹出生物识别验证（指纹、Face ID 等）
   - 用户完成验证后，浏览器生成凭证

3. **完成注册** (`handleAPIWebAuthnFinishRegistration`)
   - 前端将凭证响应发送到 `/api/webauthn/register/finish`
   - 后端验证凭证签名
   - 保存凭证到数据库
   - 删除临时会话数据

```179:283:internal/web/api_webauthn.go
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
	bodyBytes, err := io.ReadAll(r.Body)
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

	// 调试：打印响应内容（前500字符）
	responseStr := string(responseBytes)
	if len(responseStr) > 500 {
		s.log.Infof("WebAuthn 注册响应 (前500字符): %s...", responseStr[:500])
	} else {
		s.log.Infof("WebAuthn 注册响应: %s", responseStr)
	}

	// 创建新的请求体供 webauthn 库使用
	r.Body = io.NopCloser(bytes.NewBuffer(responseBytes))

	// 验证并完成注册（直接使用 http.Request）
	credential, err := s.webauthnManager.webauthn.FinishRegistration(user, *sessionData, r)
	if err != nil {
		s.log.Errorf("完成 WebAuthn 注册失败: %v", err)
		s.log.Errorf("请求体内容: %s", string(responseBytes))
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
```

### 登录流程

1. **开始登录** (`handleAPIWebAuthnBeginLogin`)
   - 用户在前端输入用户名
   - 前端调用 `/api/webauthn/login/begin`
   - 后端查询用户的已注册凭证
   - 生成登录选项（challenge、允许的凭证列表等）
   - 保存会话数据到内存
   - 返回登录选项和会话密钥

```285:402:internal/web/api_webauthn.go
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
	})
}
```

2. **浏览器验证**
   - 前端调用 `navigator.credentials.get()`
   - 浏览器弹出生物识别验证
   - 用户完成验证后，浏览器生成断言响应

3. **完成登录** (`handleAPIWebAuthnFinishLogin`)
   - 前端将断言响应发送到 `/api/webauthn/login/finish`
   - 后端验证签名和计数器
   - 更新凭证计数器
   - 创建用户会话
   - 删除临时会话数据

```404:518:internal/web/api_webauthn.go
// handleAPIWebAuthnFinishLogin 完成 WebAuthn 登录
func (s *Server) handleAPIWebAuthnFinishLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 读取请求体
	bodyBytes, err := io.ReadAll(r.Body)
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
```

## 前端实现

### 登录页面实现

登录页面 (`frontend/src/pages/Login.tsx`) 提供 WebAuthn 登录入口：

```297:437:frontend/src/pages/Login.tsx
  // WebAuthn 登录
  const handleWebAuthnLogin = async () => {
    if (!webauthnUsername.trim()) {
      setError('请输入用户名')
      return
    }

    setIsLoading(true)
    setError('')

    try {
      // 1. 开始登录流程
      const beginResponse = await fetch(buildApiPath(adminPrefix, '/api/webauthn/login/begin'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ username: webauthnUsername }),
      })

      if (!beginResponse.ok) {
        const errorData = await beginResponse.json()
        setError(errorData.error || 'WebAuthn 登录失败')
        setIsLoading(false)
        return
      }

      const beginData = await beginResponse.json()
      if (!beginData.success) {
        setError(beginData.error || 'WebAuthn 登录失败')
        setIsLoading(false)
        return
      }

      // 辅助函数：将 Base64 URL 编码的字符串转换为 ArrayBuffer
      const base64URLToArrayBuffer = (base64URL: string): ArrayBuffer => {
        // Base64 URL 编码使用 - 和 _ 而不是 + 和 /
        const base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/')
        // 添加填充
        const padded = base64 + '='.repeat((4 - base64.length % 4) % 4)
        // 转换为二进制字符串
        const binary = atob(padded)
        // 转换为 ArrayBuffer
        const bytes = new Uint8Array(binary.length)
        for (let i = 0; i < binary.length; i++) {
          bytes[i] = binary.charCodeAt(i)
        }
        return bytes.buffer
      }

      // 2. 调用浏览器 WebAuthn API
      let credential: PublicKeyCredential
      try {
        // options 现在直接就是 PublicKeyCredentialRequestOptions 对象
        // 但是需要将字符串字段转换为 ArrayBuffer
        console.log('beginData:', beginData) // 调试日志
        console.log('beginData.options:', beginData.options) // 调试日志
        console.log('beginData.options.challenge:', beginData.options?.challenge) // 调试日志
        
        const publicKeyOptions = { ...beginData.options }
        
        // 转换 challenge (Base64 URL 编码的字符串 -> ArrayBuffer)
        if (publicKeyOptions.challenge) {
          if (typeof publicKeyOptions.challenge === 'string') {
            console.log('转换 challenge 从字符串:', publicKeyOptions.challenge) // 调试日志
            publicKeyOptions.challenge = base64URLToArrayBuffer(publicKeyOptions.challenge)
            console.log('转换后的 challenge 类型:', publicKeyOptions.challenge instanceof ArrayBuffer) // 调试日志
          } else {
            console.warn('challenge 不是字符串类型:', typeof publicKeyOptions.challenge, publicKeyOptions.challenge) // 调试日志
          }
        } else {
          console.error('challenge 字段不存在或为空') // 调试日志
        }
        
        // 转换 allowCredentials[].id (如果存在)
        if (publicKeyOptions.allowCredentials && Array.isArray(publicKeyOptions.allowCredentials)) {
          publicKeyOptions.allowCredentials = publicKeyOptions.allowCredentials.map((cred: any) => ({
            ...cred,
            id: typeof cred.id === 'string' ? base64URLToArrayBuffer(cred.id) : cred.id
          }))
        }
        
        console.log('传递给 navigator.credentials.get 的 publicKey:', publicKeyOptions) // 调试日志
        
        credential = await navigator.credentials.get({
          publicKey: publicKeyOptions,
        }) as PublicKeyCredential
      } catch (err: any) {
        if (err.name === 'NotAllowedError')
```

### 会话数据管理

WebAuthn 会话数据存储在内存中，使用全局变量和互斥锁保护：

```15:50:internal/web/api_webauthn.go
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
```

## 安全机制

### 1. 挑战-响应机制

每次登录/注册都生成唯一的 challenge，防止重放攻击：

- 服务器生成随机 challenge
- 浏览器使用私钥对 challenge 签名
- 服务器验证签名

### 2. 凭证计数器

每次使用凭证时，计数器都会递增：

```277:291:internal/web/webauthn_manager.go
// UpdateCredentialCounter 更新凭证计数器
func (wm *WebAuthnManager) UpdateCredentialCounter(credentialID string, counter uint32) error {
	updateSQL := `
	UPDATE webauthn_credentials
	SET counter = ?, last_used_at = ?
	WHERE credential_id = ?
	`

	_, err := wm.db.Exec(updateSQL, counter, time.Now(), credentialID)
	if err != nil {
		return fmt.Errorf("更新凭证计数器失败: %v", err)
	}

	return nil
}
```

如果检测到计数器回退或重复，说明凭证可能被克隆，登录将被拒绝。

### 3. 私钥保护

- 私钥永远不离开设备
- 存储在设备的安全区域（如 TPM、Secure Enclave）
- 服务器只存储公钥，无法伪造签名

### 4. 域名验证

WebAuthn 要求 RPID（Relying Party ID）必须与实际访问域名匹配，防止钓鱼攻击。

### 5. HTTPS 要求

生产环境必须使用 HTTPS（localhost 除外），确保通信安全。

## API 接口文档

### 1. 开始注册

**请求：**
```http
POST /api/webauthn/register/begin
Content-Type: application/json
Cookie: session_id=...

{
  "username": "admin",
  "device_name": "Chrome on MacBook"
}
```

**响应：**
```json
{
  "success": true,
  "options": {
    "challenge": "...",
    "rp": {
      "name": "SSLcat",
      "id": "example.com"
    },
    "user": {
      "id": "...",
      "name": "admin",
      "displayName": "admin"
    },
    "pubKeyCredParams": [...],
    "timeout": 300000
  },
  "session_key": "webauthn_reg_admin_20231201120000"
}
```

### 2. 完成注册

**请求：**
```http
POST /api/webauthn/register/finish
Content-Type: application/json
Cookie: session_id=...

{
  "session_key": "webauthn_reg_admin_20231201120000",
  "device_name": "Chrome on MacBook",
  "response": {
    "id": "...",
    "rawId": "...",
    "response": {
      "attestationObject": "...",
      "clientDataJSON": "..."
    },
    "type": "public-key"
  }
}
```

**响应：**
```json
{
  "success": true,
  "message": "WebAuthn 凭证注册成功"
}
```

### 3. 开始登录

**请求：**
```http
POST /api/webauthn/login/begin
Content-Type: application/json

{
  "username": "admin"
}
```

**响应：**
```json
{
  "success": true,
  "options": {
    "challenge": "...",
    "allowCredentials": [
      {
        "id": "...",
        "type": "public-key"
      }
    ],
    "timeout": 300000
  },
  "session_key": "webauthn_login_admin_20231201120000"
}
```

### 4. 完成登录

**请求：**
```http
POST /api/webauthn/login/finish
Content-Type: application/json

{
  "username": "admin",
  "session_key": "webauthn_login_admin_20231201120000",
  "response": {
    "id": "...",
    "rawId": "...",
    "response": {
      "authenticatorData": "...",
      "clientDataJSON": "...",
      "signature": "...",
      "userHandle": "..."
    },
    "type": "public-key"
  }
}
```

**响应：**
```json
{
  "success": true,
  "user": {
    "username": "admin",
    "role": "super_admin"
  }
}
```

### 5. 列出凭证

**请求：**
```http
GET /api/webauthn/credentials
Cookie: session_id=...
```

**响应：**
```json
{
  "success": true,
  "credentials": [
    {
      "id": "...",
      "credential_id": "...",
      "device_name": "Chrome on MacBook",
      "created_at": "2023-12-01T12:00:00Z",
      "last_used_at": "2023-12-01T15:30:00Z",
      "is_active": true
    }
  ]
}
```

### 6. 删除凭证

**请求：**
```http
POST /api/webauthn/credentials/delete
Content-Type: application/json
Cookie: session_id=...

{
  "credential_id": "..."
}
```

**响应：**
```json
{
  "success": true,
  "message": "凭证已删除"
}
```

## 浏览器支持

- ✅ Chrome 67+
- ✅ Edge 18+
- ✅ Firefox 60+
- ✅ Safari 13+
- ✅ Opera 54+

## 故障排查

### 问题：注册时提示"不支持 WebAuthn"

**解决方案：**
- 确保使用支持的浏览器
- 确保设备支持生物识别
- 确保使用 HTTPS（生产环境）

### 问题：登录时找不到凭证

**解决方案：**
- 检查是否在同一设备上注册
- 检查浏览器是否允许存储凭证
- 清除浏览器缓存后重试

### 问题：RPID 不匹配错误

**解决方案：**
- 确保 RPID 配置与实际访问域名一致
- 检查域名是否包含协议和端口
- 生产环境不能使用 `localhost` 作为 RPID

### 问题：凭证计数器错误

**解决方案：**
- 可能是凭证被克隆或设备时间不同步
- 尝试删除并重新注册凭证
- 检查设备时间设置

## 总结

SSLcat 的指纹登录功能基于 WebAuthn 标准实现，提供了安全、便捷的无密码登录体验。通过公钥加密、挑战-响应机制和凭证计数器等多重安全机制，有效防止了各种攻击。用户可以在多个设备上注册凭证，并随时管理这些凭证。


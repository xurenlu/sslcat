package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/runner"
)

// GitServerAPI Git 服务器 API 处理器
type GitServerAPI struct {
	server    *runner.GitServer
	logger    *logrus.Logger
	webServer *Server // 添加对 web server 的引用，用于认证检查
}

// NewGitServerAPI 创建新的 Git 服务器 API
func NewGitServerAPI(gs *runner.GitServer, webServer *Server) *GitServerAPI {
	return &GitServerAPI{
		server:    gs,
		webServer: webServer,
		logger:    logrus.WithField("component", "git_server_api").Logger,
	}
}

// checkAuthWithLocalhostBypass 检查认证，但对 localhost 请求豁免
// 用于支持 sslcat-git-hook 等内部工具的 API 调用
func (api *GitServerAPI) checkAuthWithLocalhostBypass(w http.ResponseWriter, r *http.Request) bool {
	// 检查是否是 localhost 请求
	if api.webServer != nil && api.webServer.isLocalhostRequest(r) {
		api.logger.Debugf("Localhost request detected from %s, bypassing authentication", api.webServer.getClientIP(r))
		return true
	}

	// 非 localhost 请求，需要正常认证
	if api.webServer != nil && !api.webServer.checkAuth(w, r) {
		return false
	}

	return true
}

// HandleApps 处理应用列表的GET和POST请求
func (api *GitServerAPI) HandleApps(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		api.ListApps(w, r)
	case "POST":
		api.CreateApp(w, r)
	default:
		api.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ListApps 列出所有应用
func (api *GitServerAPI) ListApps(w http.ResponseWriter, r *http.Request) {
	if api.server == nil {
		api.logger.Warn("Git Deploy 服务未启用，返回空应用列表")
		response := map[string]interface{}{
			"success": true,
			"data":    []interface{}{},
			"count":   0,
		}
		api.writeJSON(w, response)
		return
	}

	apps := api.server.ListApps()
	api.logger.Infof("获取应用列表: 共 %d 个应用", len(apps))

	// 输出应用详情
	if len(apps) > 0 {
		for _, app := range apps {
			api.logger.Debugf("  - %s (状态: %s, 域名: %s)", app.Name, app.Status, app.Domain)
		}
	} else {
		api.logger.Info("  当前没有应用")
	}

	// 转换为 map 数组，添加 autoSSL 字段
	appsWithAutoSSL := make([]map[string]interface{}, 0, len(apps))
	for _, app := range apps {
		// 使用 json.Marshal/Unmarshal 转换为 map
		appJSON, _ := json.Marshal(app)
		var appMap map[string]interface{}
		json.Unmarshal(appJSON, &appMap)

		// 添加 autoSSL 字段
		if app.DeployConfig != nil {
			appMap["autoSSL"] = app.DeployConfig.SSL.Enabled
		} else {
			appMap["autoSSL"] = false
		}

		appsWithAutoSSL = append(appsWithAutoSSL, appMap)
	}

	response := map[string]interface{}{
		"success": true,
		"data":    appsWithAutoSSL,
		"count":   len(apps),
	}

	api.writeJSON(w, response)
}

// GetApp 获取应用详情
func (api *GitServerAPI) GetApp(w http.ResponseWriter, r *http.Request) {
	appName := r.URL.Query().Get("name")
	if appName == "" {
		api.writeError(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}

	app, err := api.server.GetApp(appName)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}

	// 转换为 map 并添加 autoSSL 字段
	appJSON, _ := json.Marshal(app)
	var appMap map[string]interface{}
	json.Unmarshal(appJSON, &appMap)

	if app.DeployConfig != nil {
		appMap["autoSSL"] = app.DeployConfig.SSL.Enabled
	} else {
		appMap["autoSSL"] = false
	}

	response := map[string]interface{}{
		"success": true,
		"data":    appMap,
	}

	api.writeJSON(w, response)
}

// CreateApp 创建应用
func (api *GitServerAPI) CreateApp(w http.ResponseWriter, r *http.Request) {
	// 认证检查（localhost 请求豁免，用于支持 sslcat-git-hook）
	if !api.checkAuthWithLocalhostBypass(w, r) {
		return
	}

	var req struct {
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
		AutoSSL     bool   `json:"auto_ssl"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.logger.Errorf("解析创建应用请求失败: %v", err)
		api.writeError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	api.logger.Infof("开始创建应用: %s (AutoSSL: %v) [来自: %s]",
		req.Name, req.AutoSSL,
		func() string {
			if api.webServer != nil {
				return api.webServer.getClientIP(r)
			}
			return "unknown"
		}())

	// 验证必填字段
	if req.Name == "" {
		api.logger.Warn("应用名称为空")
		api.writeError(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}

	// 检查 Git 服务器是否为 nil（未启用）
	if api.server == nil {
		api.logger.Error("Git Deploy 服务未启用，无法创建应用")
		api.writeError(w, "Git Deploy 服务未启用，请在配置文件中启用 runners.git.enabled", http.StatusServiceUnavailable)
		return
	}

	api.logger.Infof("调用 GitServer.CreateApp(%s, %v)...", req.Name, req.AutoSSL)
	app, err := api.server.CreateApp(req.Name, req.AutoSSL)
	if err != nil {
		api.logger.Errorf("创建应用 %s 失败: %v", req.Name, err)
		// 提供更友好的错误消息
		errMsg := err.Error()
		if strings.Contains(errMsg, "目录") || strings.Contains(errMsg, "directory") {
			errMsg = "创建应用目录失败，请检查 runners.git.repos_dir 配置和目录权限: " + errMsg
		}
		api.writeError(w, "创建应用失败: "+errMsg, http.StatusInternalServerError)
		return
	}

	api.logger.Infof("✅ 应用 %s 创建成功: 域名=%s, 端口=%d, Git地址=%s, AutoSSL=%v",
		app.Name, app.Domain, app.Port, app.GitURL, req.AutoSSL)

	// 转换为 map 并添加 autoSSL 字段
	appJSON, _ := json.Marshal(app)
	var appMap map[string]interface{}
	json.Unmarshal(appJSON, &appMap)

	if app.DeployConfig != nil {
		appMap["autoSSL"] = app.DeployConfig.SSL.Enabled
	} else {
		appMap["autoSSL"] = false
	}

	response := map[string]interface{}{
		"success": true,
		"message": "应用创建成功",
		"data":    appMap,
	}

	api.writeJSON(w, response)
	api.logger.Infof("响应已发送: 应用 %s 创建成功", req.Name)
}

// DeleteApp 删除应用
func (api *GitServerAPI) DeleteApp(w http.ResponseWriter, r *http.Request) {
	appName := r.URL.Query().Get("name")
	if appName == "" {
		api.writeError(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}

	if err := api.server.DeleteApp(appName); err != nil {
		api.writeError(w, "删除应用失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "应用删除成功",
	}

	api.writeJSON(w, response)
}

// HandleServerConfig 处理服务器配置的GET和PUT请求
func (api *GitServerAPI) HandleServerConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		api.GetServerConfig(w, r)
	case "PUT":
		api.UpdateServerConfig(w, r)
	default:
		api.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// GetServerConfig 获取服务器配置
func (api *GitServerAPI) GetServerConfig(w http.ResponseWriter, r *http.Request) {
	config := api.server.GetServerConfig()

	response := map[string]interface{}{
		"success": true,
		"data":    config,
	}

	api.writeJSON(w, response)
}

// UpdateServerConfig 更新服务器配置
func (api *GitServerAPI) UpdateServerConfig(w http.ResponseWriter, r *http.Request) {
	var config runner.GitServerConfig

	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		api.writeError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := api.server.UpdateServerConfig(&config); err != nil {
		api.writeError(w, "更新服务器配置失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "服务器配置已更新",
	}

	api.writeJSON(w, response)
}

// UpdateAppEnv 更新应用环境变量
func (api *GitServerAPI) UpdateAppEnv(w http.ResponseWriter, r *http.Request) {
	appName := r.URL.Query().Get("name")
	if appName == "" {
		api.writeError(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}

	var req struct {
		EnvVars map[string]string `json:"env_vars"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.EnvVars == nil {
		api.writeError(w, "env_vars 字段不能为空", http.StatusBadRequest)
		return
	}

	if err := api.server.UpdateAppEnv(appName, req.EnvVars); err != nil {
		api.writeError(w, "更新环境变量失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success":         true,
		"message":         "环境变量已更新，请重新部署应用以应用更改",
		"pending_restart": true,
	}

	api.writeJSON(w, response)
}

// RedeployApp 手动触发应用重新部署
func (api *GitServerAPI) RedeployApp(w http.ResponseWriter, r *http.Request) {
	appName := r.URL.Query().Get("name")
	if appName == "" {
		api.writeError(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}

	if err := api.server.RedeployApp(appName); err != nil {
		api.writeError(w, "触发重新部署失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "应用重新部署已启动",
	}

	api.writeJSON(w, response)
}

// ==================== SSH 密钥管理 API ====================

// HandleSSHKeys 处理SSH密钥的GET和POST请求
func (api *GitServerAPI) HandleSSHKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		api.ListSSHKeys(w, r)
	case "POST":
		api.AddSSHKey(w, r)
	default:
		api.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ListSSHKeys 列出所有 SSH 密钥
func (api *GitServerAPI) ListSSHKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := api.server.ListSSHKeys()
	if err != nil {
		api.writeError(w, "获取 SSH 密钥失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"data":    keys,
	}

	api.writeJSON(w, response)
}

// UpdateAppRouting 更新应用的域名与端口
func (api *GitServerAPI) UpdateAppRouting(w http.ResponseWriter, r *http.Request) {
	appName := r.URL.Query().Get("name")
	if appName == "" {
		api.writeError(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}

	var req struct {
		Domain string `json:"domain"`
		Port   int    `json:"port"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := api.server.UpdateAppRouting(appName, req.Port, req.Domain); err != nil {
		api.writeError(w, "更新域名/端口失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "域名与端口已更新",
	}

	api.writeJSON(w, response)
}

// AddSSHKey 添加 SSH 密钥
func (api *GitServerAPI) AddSSHKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string `json:"name"`
		PublicKey  string `json:"public_key"`
		PublicKey2 string `json:"publicKey"` // 兼容前端的驼峰命名
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 优先使用 public_key，如果为空则使用 publicKey
	publicKey := req.PublicKey
	if publicKey == "" {
		publicKey = req.PublicKey2
	}

	if req.Name == "" || publicKey == "" {
		api.writeError(w, "密钥名称和公钥不能为空", http.StatusBadRequest)
		return
	}

	// 去除公钥末尾的换行符
	publicKey = strings.TrimSpace(publicKey)

	if err := api.server.AddSSHKey(req.Name, publicKey); err != nil {
		api.writeError(w, "添加 SSH 密钥失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "SSH 密钥添加成功",
	}

	api.writeJSON(w, response)
}

// RemoveSSHKey 删除 SSH 密钥
func (api *GitServerAPI) RemoveSSHKey(w http.ResponseWriter, r *http.Request) {
	fingerprint := r.URL.Query().Get("fingerprint")
	if fingerprint == "" {
		api.writeError(w, "密钥指纹不能为空", http.StatusBadRequest)
		return
	}

	if err := api.server.RemoveSSHKey(fingerprint); err != nil {
		api.writeError(w, "删除 SSH 密钥失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "SSH 密钥删除成功",
	}

	api.writeJSON(w, response)
}

// ==================== 日志查看 API ====================

// GetAppLogs 获取应用日志
func (api *GitServerAPI) GetAppLogs(w http.ResponseWriter, r *http.Request) {
	appName := r.URL.Query().Get("app")
	linesStr := r.URL.Query().Get("lines")

	if appName == "" {
		api.writeError(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}

	lines := 100 // 默认返回最后100行
	if linesStr != "" {
		if l, err := strconv.Atoi(linesStr); err == nil && l > 0 {
			lines = l
		}
	}

	logs, err := api.server.GetAppLogs(appName, lines)
	if err != nil {
		api.writeError(w, "获取应用日志失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"data":    logs,
	}

	api.writeJSON(w, response)
}

// GetAppLogFiles 获取应用日志文件列表
func (api *GitServerAPI) GetAppLogFiles(w http.ResponseWriter, r *http.Request) {
	appName := r.URL.Query().Get("app")

	if appName == "" {
		api.writeError(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}

	files, err := api.server.GetAppLogFiles(appName)
	if err != nil {
		api.writeError(w, "获取日志文件列表失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"data":    files,
	}

	api.writeJSON(w, response)
}

// GetAppLogsStream 获取应用实时日志流 (SSE)
func (api *GitServerAPI) GetAppLogsStream(w http.ResponseWriter, r *http.Request) {
	appName := r.URL.Query().Get("app")
	api.logger.Infof("📡 SSE 日志流请求: app=%s, 来自 %s", appName, r.RemoteAddr)

	if appName == "" {
		api.logger.Warn("SSE 请求缺少应用名称参数")
		api.writeError(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}

	// 检查 Git 服务器是否启用
	if api.server == nil {
		api.logger.Error("❌ Git Deploy 服务未启用，无法建立 SSE 连接")
		api.writeError(w, "Git Deploy 服务未启用", http.StatusServiceUnavailable)
		return
	}

	// 检查应用是否存在
	_, err := api.server.GetApp(appName)
	if err != nil {
		api.logger.Errorf("❌ 应用 %s 不存在: %v", appName, err)
		api.writeError(w, "应用不存在: "+err.Error(), http.StatusNotFound)
		return
	}

	api.logger.Infof("✅ 建立 SSE 连接: app=%s", appName)

	// 使用日志流管理器处理实时日志连接 (SSE)
	api.server.GetLogStreamManager().HandleWebSocketLogs(w, r, appName)
}

// GetAppLogsStreamWS 获取应用实时日志流 (WebSocket)
func (api *GitServerAPI) GetAppLogsStreamWS(w http.ResponseWriter, r *http.Request) {
	appName := r.URL.Query().Get("app")
	api.logger.Infof("📡 WebSocket 日志流请求: app=%s, 来自 %s", appName, r.RemoteAddr)

	if appName == "" {
		api.logger.Warn("WebSocket 请求缺少应用名称参数")
		api.writeError(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}

	// 检查 Git 服务器是否启用
	if api.server == nil {
		api.logger.Error("❌ Git Deploy 服务未启用，无法建立 WebSocket 连接")
		api.writeError(w, "Git Deploy 服务未启用", http.StatusServiceUnavailable)
		return
	}

	// 检查应用是否存在
	_, err := api.server.GetApp(appName)
	if err != nil {
		api.logger.Errorf("❌ 应用 %s 不存在: %v", appName, err)
		api.writeError(w, "应用不存在: "+err.Error(), http.StatusNotFound)
		return
	}

	api.logger.Infof("✅ 建立 WebSocket 连接: app=%s", appName)

	// 使用日志流管理器处理 WebSocket 日志连接
	api.server.GetLogStreamManager().HandleWebSocketLogsWS(w, r, appName)
}

// GetAppLogsHistory 获取应用历史日志
func (api *GitServerAPI) GetAppLogsHistory(w http.ResponseWriter, r *http.Request) {
	appName := r.URL.Query().Get("app")
	if appName == "" {
		api.writeError(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	// 获取日志流
	stream := api.server.GetLogStreamManager().GetStream(appName)
	if stream == nil {
		api.writeError(w, "日志流不存在", http.StatusNotFound)
		return
	}

	// 获取历史日志
	logs, err := stream.GetHistoryLogs(limit)
	if err != nil {
		api.writeError(w, "获取历史日志失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"data":    logs,
		"count":   len(logs),
	}

	api.writeJSON(w, response)
}

// ==================== Docker Registry API ====================

// GetDockerImages 获取Docker镜像列表
func (api *GitServerAPI) GetDockerImages(w http.ResponseWriter, r *http.Request) {
	appName := r.URL.Query().Get("app")
	if appName == "" {
		api.writeError(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}

	images, err := api.server.GetDockerRegistry().ListImages(appName)
	if err != nil {
		api.writeError(w, "获取Docker镜像失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"data":    images,
		"count":   len(images),
	}

	api.writeJSON(w, response)
}

// GetDockerConfig 获取Docker Registry配置
func (api *GitServerAPI) GetDockerConfig(w http.ResponseWriter, r *http.Request) {
	stats := api.server.GetDockerRegistry().GetStats()

	response := map[string]interface{}{
		"success": true,
		"data":    stats,
	}

	api.writeJSON(w, response)
}

// UpdateDockerConfig 更新Docker Registry配置
func (api *GitServerAPI) UpdateDockerConfig(w http.ResponseWriter, r *http.Request) {
	var config runner.DockerRegistryConfig

	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		api.writeError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 更新配置
	if err := api.server.UpdateDockerRegistryConfig(&config); err != nil {
		api.writeError(w, "更新配置失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "Docker Registry配置已更新",
	}

	api.writeJSON(w, response)
}

// TestDockerConnection 测试Docker连接
func (api *GitServerAPI) TestDockerConnection(w http.ResponseWriter, r *http.Request) {
	api.logger.Info("收到 Docker Registry 测试连接请求")

	// 从请求中读取配置（如果有），否则使用当前配置
	var config runner.DockerRegistryConfig

	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		api.logger.Warnf("解析请求配置失败，使用当前配置: %v", err)
		// 如果没有传递配置，使用当前配置
		err = api.server.GetDockerRegistry().TestConnection()

		response := map[string]interface{}{
			"success":   err == nil,
			"connected": err == nil,
		}

		if err != nil {
			api.logger.Errorf("测试连接失败: %v", err)
			response["error"] = err.Error()
		} else {
			api.logger.Info("测试连接成功")
			response["message"] = "Docker Registry连接正常"
		}

		api.writeJSON(w, response)
		return
	}

	api.logger.Info("使用前端传递的配置测试连接")

	// 使用传递的配置测试连接
	err := api.server.GetDockerRegistry().TestConnectionWithConfig(&config)

	response := map[string]interface{}{
		"success":   err == nil,
		"connected": err == nil,
	}

	if err != nil {
		api.logger.Errorf("测试连接失败: %v", err)
		response["error"] = err.Error()
	} else {
		api.logger.Info("测试连接成功")
		response["message"] = "Docker Registry连接正常"
	}

	api.writeJSON(w, response)
}

// ==================== 推送历史 API ====================

// GetPushHistory 获取推送历史
func (api *GitServerAPI) GetPushHistory(w http.ResponseWriter, r *http.Request) {
	appName := r.URL.Query().Get("app")
	if appName == "" {
		api.writeError(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 50 // 默认返回最后50条
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	history, err := api.server.GetPushHistory(appName, limit)
	if err != nil {
		api.writeError(w, "获取推送历史失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"data":    history,
		"count":   len(history),
	}

	api.writeJSON(w, response)
}

// ==================== SSH 密钥绑定 API ====================

// BindKeyToApp 绑定SSH密钥到应用
func (api *GitServerAPI) BindKeyToApp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AppName        string `json:"app_name"`
		KeyFingerprint string `json:"key_fingerprint"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.AppName == "" || req.KeyFingerprint == "" {
		api.writeError(w, "应用名称和密钥指纹不能为空", http.StatusBadRequest)
		return
	}

	if err := api.server.BindKeyToApp(req.AppName, req.KeyFingerprint); err != nil {
		api.writeError(w, "绑定SSH密钥失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "SSH密钥绑定成功",
	}

	api.writeJSON(w, response)
}

// UnbindKeyFromApp 解绑SSH密钥
func (api *GitServerAPI) UnbindKeyFromApp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AppName        string `json:"app_name"`
		KeyFingerprint string `json:"key_fingerprint"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.AppName == "" || req.KeyFingerprint == "" {
		api.writeError(w, "应用名称和密钥指纹不能为空", http.StatusBadRequest)
		return
	}

	if err := api.server.UnbindKeyFromApp(req.AppName, req.KeyFingerprint); err != nil {
		api.writeError(w, "解绑SSH密钥失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "SSH密钥解绑成功",
	}

	api.writeJSON(w, response)
}

// RuntimeDetectorAPI 运行时检测器 API
type RuntimeDetectorAPI struct {
	detector *runner.RuntimeDetector
	logger   *logrus.Logger
}

// NewRuntimeDetectorAPI 创建新的运行时检测器 API
func NewRuntimeDetectorAPI() *RuntimeDetectorAPI {
	return &RuntimeDetectorAPI{
		detector: runner.NewRuntimeDetector(),
		logger:   logrus.WithField("component", "runtime_detector_api").Logger,
	}
}

// DetectProject 检测项目类型
func (api *RuntimeDetectorAPI) DetectProject(w http.ResponseWriter, r *http.Request) {
	projectPath := r.URL.Query().Get("path")
	if projectPath == "" {
		api.writeError(w, "项目路径不能为空", http.StatusBadRequest)
		return
	}

	info, err := api.detector.DetectProjectType(projectPath)
	if err != nil {
		api.writeError(w, "检测项目类型失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"data":    info,
	}

	api.writeJSON(w, response)
}

func (api *GitServerAPI) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (api *GitServerAPI) writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func (api *RuntimeDetectorAPI) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (api *RuntimeDetectorAPI) writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// handleRunners Runners管理页面处理器
func (s *Server) handleRunners(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 检测并设置语言
	lang := s.detectLanguage(r)
	s.translator.SetLanguage(lang)

	// 获取各Runner的状态
	// Docker功能已移除，暂时返回空数据
	dockerTasks := make([]interface{}, 0)

	data := map[string]interface{}{
		"AdminPrefix":   s.config.AdminPrefix,
		"DockerTasks":   dockerTasks,
		"DockerEnabled": false, // Docker功能已移除
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateRunnersManagementHTML(data)
	w.Write([]byte(html))
}

// handleGitServer Git Deploy Server管理页面处理器
func (s *Server) handleGitServer(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 检测并设置语言
	lang := s.detectLanguage(r)
	s.translator.SetLanguage(lang)

	// 获取Git Deploy Server的状态
	gitApps := s.gitServer.ListApps()

	data := map[string]interface{}{
		"AdminPrefix":         s.config.AdminPrefix,
		"GitApps":             gitApps,
		"GitEnabled":          s.config.Runners.Git.Enabled,
		"Title":               s.translator.T("git_deploy_server.title"),
		"FunctionDescription": s.translator.T("git_deploy_server.function_description"),
		"Description":         s.translator.T("git_deploy_server.description"),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateGitServerManagementHTML(data)
	w.Write([]byte(html))
}

// RestartSSHD 重启 SSH 服务
func (api *GitServerAPI) RestartSSHD(w http.ResponseWriter, r *http.Request) {
	if api.server == nil {
		api.writeError(w, "Git Deploy 服务未启用", http.StatusServiceUnavailable)
		return
	}

	// 调用 GitServer 的 restartSSHD 方法
	if err := api.server.RestartSSHD(); err != nil {
		api.logger.Errorf("重启 SSH 服务失败: %v", err)
		api.writeError(w, "重启 SSH 服务失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "SSH 服务重启成功",
	}
	api.writeJSON(w, response)
}

// HandleDeployNotification 处理部署通知（内部 API，由 hook 调用）
func (api *GitServerAPI) HandleDeployNotification(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		api.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if api.server == nil {
		api.writeError(w, "Git Deploy 服务未启用", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Type         string `json:"type"` // stuck, timeout, success, failed
		AppName      string `json:"app_name"`
		CommitSHA    string `json:"commit_sha"`
		CommitMsg    string `json:"commit_msg"`
		IdleDuration string `json:"idle_duration"` // for stuck
		Duration     string `json:"duration"`      // for timeout
		Reason       string `json:"reason"`        // for failed
		ErrorDetails string `json:"error_details"` // for failed
		Domain       string `json:"domain"`        // for success
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.logger.Errorf("解析部署通知请求失败: %v", err)
		api.writeError(w, "解析请求失败", http.StatusBadRequest)
		return
	}

	// 调用 GitServer 的通知方法
	if err := api.server.SendDeployNotification(req.Type, req.AppName, req.CommitSHA, req.CommitMsg,
		req.IdleDuration, req.Duration, req.Reason, req.ErrorDetails, req.Domain); err != nil {
		api.logger.Errorf("发送部署通知失败: %v", err)
		api.writeError(w, "发送通知失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "通知已发送",
	}
	api.writeJSON(w, response)
}

// ReinstallHooks 重新安装应用的 Git hooks
func (api *GitServerAPI) ReinstallHooks(w http.ResponseWriter, r *http.Request) {
	// 认证检查（localhost 请求豁免）
	if !api.checkAuthWithLocalhostBypass(w, r) {
		return
	}

	if r.Method != "POST" {
		api.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appName := r.URL.Query().Get("name")
	if appName == "" {
		api.writeError(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}

	if api.server == nil {
		api.writeError(w, "Git Deploy 服务未启用", http.StatusServiceUnavailable)
		return
	}

	api.logger.Infof("重新安装应用 %s 的 Git hooks", appName)
	
	// 获取应用（注意：这里获取的是副本）
	app, err := api.server.GetApp(appName)
	if err != nil || app == nil {
		api.writeError(w, "应用不存在: "+appName, http.StatusNotFound)
		return
	}
	
	// 重新安装 hooks（会更新 app.BareRepo）
	if err := api.server.SetupGitHooksForApp(app); err != nil {
		api.logger.Errorf("重新安装 hooks 失败: %v", err)
		api.writeError(w, "重新安装 hooks 失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	// 重新获取应用以获得更新后的 BareRepo
	app, _ = api.server.GetApp(appName)
	
	response := map[string]interface{}{
		"success": true,
		"message": "Git hooks 已重新安装",
		"data": map[string]interface{}{
			"app_name":  appName,
			"bare_repo": app.BareRepo,
		},
	}

	api.writeJSON(w, response)
}

// HandleAppAction 处理应用相关的操作 (RESTful风格)
// 支持 /api/git-server/apps/{name}/deploy
func (api *GitServerAPI) HandleAppAction(w http.ResponseWriter, r *http.Request) {
	// 解析 URL 路径: /api/git-server/apps/{name}/{action}
	path := r.URL.Path
	parts := strings.Split(strings.Trim(path, "/"), "/")

	// 找到 apps 后面的部分
	appsIndex := -1
	for i, part := range parts {
		if part == "apps" {
			appsIndex = i
			break
		}
	}

	if appsIndex == -1 || len(parts) < appsIndex+3 {
		api.writeError(w, "Invalid URL path", http.StatusBadRequest)
		return
	}

	appName := parts[appsIndex+1]
	action := parts[appsIndex+2]

	api.logger.Infof("App action: %s -> %s (method: %s)", appName, action, r.Method)

	switch action {
	case "deploy":
		api.TriggerDeploy(w, r, appName)
	default:
		api.writeError(w, "Unknown action: "+action, http.StatusNotFound)
	}
}

// TriggerDeploy 触发应用部署 (由 post-receive hook 调用)
func (api *GitServerAPI) TriggerDeploy(w http.ResponseWriter, r *http.Request, appName string) {
	// 认证检查（localhost 请求豁免）
	if !api.checkAuthWithLocalhostBypass(w, r) {
		return
	}

	if r.Method != "POST" {
		api.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Commit  string `json:"commit"`
		Ref     string `json:"ref"`
		Message string `json:"message"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.logger.Warnf("解析部署请求失败: %v (使用空数据)", err)
		// 允许空 body
	}

	api.logger.Infof("触发应用部署: %s (commit: %s, ref: %s)", appName, req.Commit, req.Ref)

	if api.server == nil {
		api.writeError(w, "Git Deploy 服务未启用", http.StatusServiceUnavailable)
		return
	}

	// 获取应用
	app, err := api.server.GetApp(appName)
	if err != nil || app == nil {
		api.writeError(w, "应用不存在: "+appName, http.StatusNotFound)
		return
	}

	// 触发部署 - 直接调用 ProcessGitPush
	go func() {
		api.logger.Infof("开始异步部署应用: %s", appName)
		// 使用 ProcessGitPush 触发部署流程
		if err := api.server.ProcessGitPush(appName, "web-trigger", req.Ref, "", req.Commit); err != nil {
			api.logger.Errorf("部署应用失败: %v", err)
		}
	}()

	response := map[string]interface{}{
		"success": true,
		"message": "部署已触发",
		"data": map[string]interface{}{
			"app_name": appName,
			"commit":   req.Commit,
			"ref":      req.Ref,
		},
	}

	api.writeJSON(w, response)
}

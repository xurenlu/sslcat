package web

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/runner"
)

// LocalRunnerAPI Local Runner API 处理器
type LocalRunnerAPI struct {
	runner *runner.LocalRunner
	logger *logrus.Logger
}

// NewLocalRunnerAPI 创建新的 Local Runner API
func NewLocalRunnerAPI(lr *runner.LocalRunner) *LocalRunnerAPI {
	return &LocalRunnerAPI{
		runner: lr,
		logger: logrus.WithField("component", "local_runner_api").Logger,
	}
}

// ListTasks 列出所有任务
func (api *LocalRunnerAPI) ListTasks(w http.ResponseWriter, r *http.Request) {
	tasks := api.runner.ListTasks()

	response := map[string]interface{}{
		"success": true,
		"data":    tasks,
		"count":   len(tasks),
	}

	api.writeJSON(w, response)
}

// GetTask 获取任务详情
func (api *LocalRunnerAPI) GetTask(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Query().Get("id")
	if taskID == "" {
		api.writeError(w, "任务ID不能为空", http.StatusBadRequest)
		return
	}

	task, err := api.runner.GetTask(taskID)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"data":    task,
	}

	api.writeJSON(w, response)
}

// AddTask 添加任务
func (api *LocalRunnerAPI) AddTask(w http.ResponseWriter, r *http.Request) {
	var task config.LocalRunnerTask
	if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
		api.writeError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 验证必填字段
	if task.Name == "" {
		api.writeError(w, "任务名称不能为空", http.StatusBadRequest)
		return
	}
	if task.Type == "" {
		api.writeError(w, "任务类型不能为空", http.StatusBadRequest)
		return
	}
	if task.BinaryPath == "" {
		api.writeError(w, "二进制文件路径不能为空", http.StatusBadRequest)
		return
	}
	if task.Port <= 0 {
		api.writeError(w, "端口号必须大于0", http.StatusBadRequest)
		return
	}

	// 设置默认值
	if task.Env == nil {
		task.Env = make(map[string]string)
	}
	if task.Args == nil {
		task.Args = []string{}
	}

	if err := api.runner.AddTask(&task); err != nil {
		api.writeError(w, "添加任务失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "任务添加成功",
		"data":    task,
	}

	api.writeJSON(w, response)
}

// StartTask 启动任务
func (api *LocalRunnerAPI) StartTask(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Query().Get("id")
	if taskID == "" {
		api.writeError(w, "任务ID不能为空", http.StatusBadRequest)
		return
	}

	if err := api.runner.StartTask(taskID); err != nil {
		api.writeError(w, "启动任务失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "任务启动成功",
	}

	api.writeJSON(w, response)
}

// StopTask 停止任务
func (api *LocalRunnerAPI) StopTask(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Query().Get("id")
	if taskID == "" {
		api.writeError(w, "任务ID不能为空", http.StatusBadRequest)
		return
	}

	if err := api.runner.StopTask(taskID); err != nil {
		api.writeError(w, "停止任务失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "任务停止成功",
	}

	api.writeJSON(w, response)
}

// RemoveTask 删除任务
func (api *LocalRunnerAPI) RemoveTask(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Query().Get("id")
	if taskID == "" {
		api.writeError(w, "任务ID不能为空", http.StatusBadRequest)
		return
	}

	if err := api.runner.RemoveTask(taskID); err != nil {
		api.writeError(w, "删除任务失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "任务删除成功",
	}

	api.writeJSON(w, response)
}

// DockerRunnerAPI Docker Runner API 处理器
type DockerRunnerAPI struct {
	runner *runner.DockerRunner
	logger *logrus.Logger
}

// NewDockerRunnerAPI 创建新的 Docker Runner API
func NewDockerRunnerAPI(dr *runner.DockerRunner) *DockerRunnerAPI {
	return &DockerRunnerAPI{
		runner: dr,
		logger: logrus.WithField("component", "docker_runner_api").Logger,
	}
}

// ListTasks 列出所有任务
func (api *DockerRunnerAPI) ListTasks(w http.ResponseWriter, r *http.Request) {
	tasks := api.runner.ListTasks()

	response := map[string]interface{}{
		"success": true,
		"data":    tasks,
		"count":   len(tasks),
	}

	api.writeJSON(w, response)
}

// GetTask 获取任务详情
func (api *DockerRunnerAPI) GetTask(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Query().Get("id")
	if taskID == "" {
		api.writeError(w, "任务ID不能为空", http.StatusBadRequest)
		return
	}

	task, err := api.runner.GetTask(taskID)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"data":    task,
	}

	api.writeJSON(w, response)
}

// AddTask 添加任务
func (api *DockerRunnerAPI) AddTask(w http.ResponseWriter, r *http.Request) {
	var task config.DockerRunnerTask
	if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
		api.writeError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 验证必填字段
	if task.Name == "" {
		api.writeError(w, "任务名称不能为空", http.StatusBadRequest)
		return
	}
	if task.GitURL == "" {
		api.writeError(w, "Git URL不能为空", http.StatusBadRequest)
		return
	}
	if task.Port <= 0 {
		api.writeError(w, "端口号必须大于0", http.StatusBadRequest)
		return
	}

	// 设置默认值
	if task.Env == nil {
		task.Env = make(map[string]string)
	}
	if task.GitBranch == "" {
		task.GitBranch = "main"
	}

	if err := api.runner.AddTask(&task); err != nil {
		api.writeError(w, "添加任务失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "任务添加成功",
		"data":    task,
	}

	api.writeJSON(w, response)
}

// StartTask 启动任务
func (api *DockerRunnerAPI) StartTask(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Query().Get("id")
	if taskID == "" {
		api.writeError(w, "任务ID不能为空", http.StatusBadRequest)
		return
	}

	if err := api.runner.StartTask(taskID); err != nil {
		api.writeError(w, "启动任务失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "任务启动成功",
	}

	api.writeJSON(w, response)
}

// StopTask 停止任务
func (api *DockerRunnerAPI) StopTask(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Query().Get("id")
	if taskID == "" {
		api.writeError(w, "任务ID不能为空", http.StatusBadRequest)
		return
	}

	if err := api.runner.StopTask(taskID); err != nil {
		api.writeError(w, "停止任务失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "任务停止成功",
	}

	api.writeJSON(w, response)
}

// RemoveTask 删除任务
func (api *DockerRunnerAPI) RemoveTask(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Query().Get("id")
	if taskID == "" {
		api.writeError(w, "任务ID不能为空", http.StatusBadRequest)
		return
	}

	if err := api.runner.RemoveTask(taskID); err != nil {
		api.writeError(w, "删除任务失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "任务删除成功",
	}

	api.writeJSON(w, response)
}

// GitServerAPI Git 服务器 API 处理器
type GitServerAPI struct {
	server *runner.GitServer
	logger *logrus.Logger
}

// NewGitServerAPI 创建新的 Git 服务器 API
func NewGitServerAPI(gs *runner.GitServer) *GitServerAPI {
	return &GitServerAPI{
		server: gs,
		logger: logrus.WithField("component", "git_server_api").Logger,
	}
}

// ListApps 列出所有应用
func (api *GitServerAPI) ListApps(w http.ResponseWriter, r *http.Request) {
	apps := api.server.ListApps()

	response := map[string]interface{}{
		"success": true,
		"data":    apps,
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

	response := map[string]interface{}{
		"success": true,
		"data":    app,
	}

	api.writeJSON(w, response)
}

// CreateApp 创建应用
func (api *GitServerAPI) CreateApp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
		AutoSSL     bool   `json:"auto_ssl"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 验证必填字段
	if req.Name == "" {
		api.writeError(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}

	app, err := api.server.CreateApp(req.Name)
	if err != nil {
		api.writeError(w, "创建应用失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "应用创建成功",
		"data":    app,
	}

	api.writeJSON(w, response)
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

// ==================== SSH 密钥管理 API ====================

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

// AddSSHKey 添加 SSH 密钥
func (api *GitServerAPI) AddSSHKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.PublicKey == "" {
		api.writeError(w, "密钥名称和公钥不能为空", http.StatusBadRequest)
		return
	}

	if err := api.server.AddSSHKey(req.Name, req.PublicKey); err != nil {
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

// 通用方法
func (api *LocalRunnerAPI) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (api *LocalRunnerAPI) writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

func (api *DockerRunnerAPI) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (api *DockerRunnerAPI) writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
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

	// 获取各Runner的状态
	localTasks := s.localRunner.ListTasks()
	dockerTasks := s.dockerRunner.ListTasks()

	data := map[string]interface{}{
		"AdminPrefix":   s.config.AdminPrefix,
		"LocalTasks":    localTasks,
		"DockerTasks":   dockerTasks,
		"LocalEnabled":  s.config.Runners.Local.Enabled,
		"DockerEnabled": s.config.Runners.Docker.Enabled,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateRunnersManagementHTML(data)
	w.Write([]byte(html))
}

// handleGitServer Git Server管理页面处理器
func (s *Server) handleGitServer(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 获取Git Server的状态
	gitApps := s.gitServer.ListApps()

	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"GitApps":     gitApps,
		"GitEnabled":  s.config.Runners.Git.Enabled,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateGitServerManagementHTML(data)
	w.Write([]byte(html))
}

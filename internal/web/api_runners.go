package web

import (
	"encoding/json"
	"net/http"

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

// ListRepositories 列出所有仓库
func (api *GitServerAPI) ListRepositories(w http.ResponseWriter, r *http.Request) {
	repos := api.server.ListRepositories()

	response := map[string]interface{}{
		"success": true,
		"data":    repos,
		"count":   len(repos),
	}

	api.writeJSON(w, response)
}

// GetRepository 获取仓库详情
func (api *GitServerAPI) GetRepository(w http.ResponseWriter, r *http.Request) {
	repoID := r.URL.Query().Get("id")
	if repoID == "" {
		api.writeError(w, "仓库ID不能为空", http.StatusBadRequest)
		return
	}

	repo, err := api.server.GetRepository(repoID)
	if err != nil {
		api.writeError(w, err.Error(), http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"data":    repo,
	}

	api.writeJSON(w, response)
}

// AddRepository 添加仓库
func (api *GitServerAPI) AddRepository(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		URL    string `json:"url"`
		Branch string `json:"branch"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 验证必填字段
	if req.Name == "" {
		api.writeError(w, "仓库名称不能为空", http.StatusBadRequest)
		return
	}
	if req.URL == "" {
		api.writeError(w, "仓库URL不能为空", http.StatusBadRequest)
		return
	}
	if req.Branch == "" {
		req.Branch = "main"
	}

	if err := api.server.AddRepository(req.Name, req.URL, req.Branch); err != nil {
		api.writeError(w, "添加仓库失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "仓库添加成功",
	}

	api.writeJSON(w, response)
}

// UpdateRepository 更新仓库
func (api *GitServerAPI) UpdateRepository(w http.ResponseWriter, r *http.Request) {
	repoID := r.URL.Query().Get("id")
	if repoID == "" {
		api.writeError(w, "仓库ID不能为空", http.StatusBadRequest)
		return
	}

	if err := api.server.UpdateRepository(repoID); err != nil {
		api.writeError(w, "更新仓库失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "仓库更新成功",
	}

	api.writeJSON(w, response)
}

// RemoveRepository 删除仓库
func (api *GitServerAPI) RemoveRepository(w http.ResponseWriter, r *http.Request) {
	repoID := r.URL.Query().Get("id")
	if repoID == "" {
		api.writeError(w, "仓库ID不能为空", http.StatusBadRequest)
		return
	}

	if err := api.server.RemoveRepository(repoID); err != nil {
		api.writeError(w, "删除仓库失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "仓库删除成功",
	}

	api.writeJSON(w, response)
}

// ExecuteCommand 在仓库中执行命令
func (api *GitServerAPI) ExecuteCommand(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RepoID  string   `json:"repo_id"`
		Command []string `json:"command"`
		WorkDir string   `json:"work_dir"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, "解析请求失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 验证必填字段
	if req.RepoID == "" {
		api.writeError(w, "仓库ID不能为空", http.StatusBadRequest)
		return
	}
	if len(req.Command) == 0 {
		api.writeError(w, "命令不能为空", http.StatusBadRequest)
		return
	}

	result, err := api.server.ExecuteInRepository(req.RepoID, req.Command, req.WorkDir)
	if err != nil {
		api.writeError(w, "执行命令失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"data":    result,
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
	gitRepos := s.gitServer.ListRepositories()

	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"GitRepos":    gitRepos,
		"GitEnabled":  s.config.Runners.Git.Enabled,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateGitServerManagementHTML(data)
	w.Write([]byte(html))
}

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/runner"
)

// TemplateDeployAPI 模板部署 API
type TemplateDeployAPI struct {
	gitServer *runner.GitServer
	logger    *logrus.Entry
}

// NewTemplateDeployAPI 创建模板部署 API
func NewTemplateDeployAPI(gs *runner.GitServer, logger *logrus.Logger) *TemplateDeployAPI {
	return &TemplateDeployAPI{
		gitServer: gs,
		logger:    logger.WithField("component", "template_deploy_api"),
	}
}

// DeployFromTemplateRequest 从模板部署的请求
type DeployFromTemplateRequest struct {
	AppName       string                 `json:"app_name"`
	TemplateID    string                 `json:"template_id"`
	PrimaryDomain string                 `json:"primary_domain,omitempty"`
	Domains       []string               `json:"domains,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
	AutoSSL       bool                   `json:"auto_ssl,omitempty"`
}

// DeployFromTemplate 从模板部署应用
func (api *TemplateDeployAPI) DeployFromTemplate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorJSON(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var req DeployFromTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorJSON(w, fmt.Sprintf("解析请求失败: %v", err), http.StatusBadRequest)
		return
	}

	// 验证请求
	if req.AppName == "" {
		writeErrorJSON(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}
	if req.TemplateID == "" {
		writeErrorJSON(w, "模板ID不能为空", http.StatusBadRequest)
		return
	}

	// 检查应用是否已存在
	existingApp, err := api.gitServer.GetApp(req.AppName)
	if err == nil && existingApp != nil {
		writeErrorJSON(w, fmt.Sprintf("应用 %s 已存在", req.AppName), http.StatusConflict)
		return
	}

	// 生成部署ID
	deployID := uuid.New().String()

	// 创建应用目录结构
	appPath := filepath.Join(api.gitServer.GetConfig().Runners.Git.ReposDir, req.AppName)
	logsDir := filepath.Join(appPath, "logs")
	logFile := filepath.Join(logsDir, fmt.Sprintf("deploy-%s.log", time.Now().Format("20060102-150405")))

	// 创建部署日志记录器
	logger, err := runner.NewDeployLogger(req.AppName, deployID, logFile)
	if err != nil {
		writeErrorJSON(w, fmt.Sprintf("创建部署日志失败: %v", err), http.StatusInternalServerError)
		return
	}
	defer logger.Close()

	// 创建应用
	app := &runner.GitApp{
		Name:     req.AppName,
		RepoDir:  filepath.Join(appPath, "git", "repo"),
		LogsDir:  logsDir,
		Domains:  make([]string, 0),
		EnvVars:  make(map[string]string),
		Services: make([]runner.AppServiceInfo, 0),
	}

	// 准备部署参数
	params := runner.DeployFromTemplateParams{
		AppName:       req.AppName,
		TemplateID:    req.TemplateID,
		PrimaryDomain: req.PrimaryDomain,
		Domains:       req.Domains,
		Variables:     req.Variables,
		AutoSSL:       req.AutoSSL,
	}

	// 执行部署
	orchestrator := api.gitServer.GetDeployOrchestrator()
	if orchestrator == nil {
		writeErrorJSON(w, "部署编排器未初始化", http.StatusInternalServerError)
		return
	}

	tm := api.gitServer.GetTemplateManager()
	if tm == nil {
		writeErrorJSON(w, "模板管理器未初始化", http.StatusInternalServerError)
		return
	}

	result, err := orchestrator.DeployFromTemplate(r.Context(), tm, app, params, logger)
	if err != nil {
		logger.WriteLog("error", "deploy", fmt.Sprintf("部署失败: %v", err))
		writeErrorJSON(w, fmt.Sprintf("部署失败: %v", err), http.StatusInternalServerError)
		return
	}

	// 将应用添加到 GitServer
	if err := api.gitServer.AddApp(app); err != nil {
		logger.WriteLog("error", "deploy", fmt.Sprintf("添加应用到 GitServer 失败: %v", err))
		writeErrorJSON(w, fmt.Sprintf("添加应用失败: %v", err), http.StatusInternalServerError)
		return
	}

	// 保存应用
	if err := api.gitServer.SaveApps(); err != nil {
		logger.WriteLog("warn", "deploy", fmt.Sprintf("保存应用失败: %v", err))
		// 不返回错误，因为应用已经在内存中
	}

	// 返回结果
	response := map[string]interface{}{
		"success":         true,
		"app":             app,
		"services":        result.Services,
		"credentials":     result.Credentials,
		"deployment_uuid": result.DeploymentUUID,
	}

	writeJSON(w, response)
}


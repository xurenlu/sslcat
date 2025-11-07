package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// DeployOrchestrator 负责协调多服务部署流程
type DeployOrchestrator struct {
	composeGen  *ComposeGenerator
	credManager *CredentialManager
	domainMgr   *DomainManager
	logger      *logrus.Entry
}

// NewDeployOrchestrator 创建部署编排器
func NewDeployOrchestrator(
	composeGen *ComposeGenerator,
	credManager *CredentialManager,
	domainMgr *DomainManager,
	logger *logrus.Logger,
) *DeployOrchestrator {
	return &DeployOrchestrator{
		composeGen:  composeGen,
		credManager: credManager,
		domainMgr:   domainMgr,
		logger:      logger.WithField("component", "deploy_orchestrator"),
	}
}

// DeployFromTemplateParams 从模板部署的参数
type DeployFromTemplateParams struct {
	AppName       string
	TemplateID    string
	PrimaryDomain string
	Domains       []string
	Variables     map[string]interface{}
	AutoSSL       bool
}

// DeployFromTemplateResult 部署结果
type DeployFromTemplateResult struct {
	App            *GitApp
	ComposeFile    string
	Services       []AppServiceInfo
	Credentials    map[string]AppServiceCredential
	DeploymentUUID string
}

// DeployFromTemplate 从模板部署应用
func (do *DeployOrchestrator) DeployFromTemplate(
	ctx context.Context,
	tm *TemplateManager,
	app *GitApp,
	params DeployFromTemplateParams,
	logger *DeployLogger,
) (*DeployFromTemplateResult, error) {
	if tm == nil {
		return nil, fmt.Errorf("模板管理器未初始化")
	}

	tpl, ok := tm.Get(params.TemplateID)
	if !ok {
		return nil, fmt.Errorf("模板 %s 不存在", params.TemplateID)
	}

	logger.WriteLog("info", "orchestrator", fmt.Sprintf("开始从模板 %s 部署应用 %s", params.TemplateID, params.AppName))

	// 生成凭证
	logger.WriteLog("info", "orchestrator", "生成服务凭证...")
	credentials, err := do.credManager.Generate(tpl.Meta, params.AppName)
	if err != nil {
		return nil, fmt.Errorf("生成凭证失败: %w", err)
	}

	// 转换凭证格式
	credMap := make(map[string]map[string]string)
	for svc, creds := range credentials {
		credMap[svc] = creds
	}

	// 生成 Compose 文件
	logger.WriteLog("info", "orchestrator", "生成 Docker Compose 配置...")
	genParams := ComposeGenerationParams{
		AppName:       params.AppName,
		PrimaryDomain: params.PrimaryDomain,
		Domains:       params.Domains,
		Variables:     params.Variables,
		Credentials:   credMap,
		ExtraEnv:      make(map[string]string),
	}

	result, err := do.composeGen.Generate(tpl, genParams)
	if err != nil {
		return nil, fmt.Errorf("生成 Compose 文件失败: %w", err)
	}
	defer func() {
		if err != nil {
			if cleanupErr := result.Cleanup(); cleanupErr != nil {
				do.logger.WithError(cleanupErr).Warn("清理临时文件失败")
			}
		}
	}()

	logger.WriteLog("info", "orchestrator", fmt.Sprintf("Compose 文件已生成: %s", result.ComposeFile))

	// 执行部署
	logger.WriteLog("info", "orchestrator", "开始执行 Docker Compose 部署...")
	if err := do.executeComposeDeploy(ctx, result, logger); err != nil {
		return nil, fmt.Errorf("执行部署失败: %w", err)
	}

	// 等待服务就绪
	logger.WriteLog("info", "orchestrator", "等待服务启动...")
	if err := do.waitForServices(ctx, result, tpl, logger); err != nil {
		logger.WriteLog("warn", "orchestrator", fmt.Sprintf("服务健康检查警告: %v", err))
	}

	// 构建服务信息列表
	services := do.buildServiceInfoList(tpl.Meta)

	// 构建凭证信息（完整版本，用于存储）
	appCredsFull := do.buildAppCredentialsFull(credentials, tpl.Meta)

	// 更新应用信息
	app.TemplateID = params.TemplateID
	app.TemplateType = "application"
	app.ComposeFile = result.ComposeFile
	app.Services = services
	app.ServiceCredentials = appCredsFull // 存储完整凭证
	app.ServiceCredentialsRaw = credentials // 存储原始凭证映射

	if do.domainMgr != nil {
		if params.PrimaryDomain != "" {
			do.domainMgr.SetPrimaryDomain(app, params.PrimaryDomain)
		}
	} else {
		app.Domain = params.PrimaryDomain
		if params.PrimaryDomain != "" {
			app.Domains = append([]string{params.PrimaryDomain}, params.Domains...)
		}
	}

	logger.WriteLog("success", "orchestrator", "模板部署完成")

	return &DeployFromTemplateResult{
		App:            app,
		ComposeFile:    result.ComposeFile,
		Services:       services,
		Credentials:    appCredsFull,
		DeploymentUUID: logger.GetDeployID(),
	}, nil
}

func (do *DeployOrchestrator) executeComposeDeploy(ctx context.Context, result *ComposeRenderResult, logger *DeployLogger) error {
	// 从变量中获取应用名称
	appName := result.Variables["APP_NAME"]
	if appName == "" {
		appName = result.Variables["SSLCAT_APP_NAME"]
	}
	if appName == "" {
		appName = "sslcat-app"
	}
	projectName := fmt.Sprintf("sslcat-%s", sanitizeProjectName(appName))

	// 验证 Compose 文件
	logger.WriteLog("info", "compose", "验证 Compose 配置...")
	validateCmd := exec.CommandContext(ctx, "docker-compose", "-f", result.ComposeFile, "config", "--quiet")
	validateCmd.Dir = filepath.Dir(result.ComposeFile)
	if err := validateCmd.Run(); err != nil {
		return fmt.Errorf("Compose 配置验证失败: %w", err)
	}

	// 拉取镜像
	logger.WriteLog("info", "compose", "拉取 Docker 镜像...")
	pullCmd := exec.CommandContext(ctx, "docker-compose", "-f", result.ComposeFile, "-p", projectName, "pull", "--ignore-pull-failures")
	pullCmd.Dir = filepath.Dir(result.ComposeFile)
	if output, err := pullCmd.CombinedOutput(); err != nil {
		logger.WriteLog("warn", "compose", fmt.Sprintf("部分镜像拉取失败: %s", string(output)))
	}

	// 构建镜像（如果有 build 指令）
	logger.WriteLog("info", "compose", "构建自定义镜像...")
	buildCmd := exec.CommandContext(ctx, "docker-compose", "-f", result.ComposeFile, "-p", projectName, "build", "--pull")
	buildCmd.Dir = filepath.Dir(result.ComposeFile)
	if output, err := buildCmd.CombinedOutput(); err != nil {
		logger.WriteLog("warn", "compose", fmt.Sprintf("镜像构建警告: %s", string(output)))
	}

	// 停止旧服务（如果存在）
	logger.WriteLog("info", "compose", "停止旧版本服务...")
	downCmd := exec.CommandContext(ctx, "docker-compose", "-f", result.ComposeFile, "-p", projectName, "down", "--remove-orphans")
	downCmd.Dir = filepath.Dir(result.ComposeFile)
	_ = downCmd.Run()

	// 启动新服务
	logger.WriteLog("info", "compose", "启动新版本服务...")
	upCmd := exec.CommandContext(ctx, "docker-compose", "-f", result.ComposeFile, "-p", projectName, "up", "-d", "--remove-orphans")
	upCmd.Dir = filepath.Dir(result.ComposeFile)
	upCmd.Env = append(os.Environ(), do.buildComposeEnv(result.Variables)...)

	if output, err := upCmd.CombinedOutput(); err != nil {
		logger.WriteLog("error", "compose", fmt.Sprintf("启动失败: %s", string(output)))
		return fmt.Errorf("启动服务失败: %w", err)
	}

	logger.WriteLog("success", "compose", "服务已启动")
	return nil
}

func (do *DeployOrchestrator) waitForServices(ctx context.Context, result *ComposeRenderResult, tpl *AppTemplate, logger *DeployLogger) error {
	// 从变量中获取应用名称
	appName := result.Variables["APP_NAME"]
	if appName == "" {
		appName = result.Variables["SSLCAT_APP_NAME"]
	}
	if appName == "" {
		appName = "sslcat-app"
	}
	projectName := fmt.Sprintf("sslcat-%s", sanitizeProjectName(appName))
	timeout := 5 * time.Minute
	if tpl.Meta.Healthcheck.Timeout > 0 {
		timeout = tpl.Meta.Healthcheck.Timeout
	}

	deadline := time.Now().Add(timeout)
	interval := 5 * time.Second
	if tpl.Meta.Healthcheck.Interval > 0 {
		interval = tpl.Meta.Healthcheck.Interval
	}

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// 检查容器状态
		psCmd := exec.CommandContext(ctx, "docker-compose", "-f", result.ComposeFile, "-p", projectName, "ps", "--format", "json")
		psCmd.Dir = filepath.Dir(result.ComposeFile)
		output, err := psCmd.Output()
		if err != nil {
			time.Sleep(interval)
			continue
		}

		// 简单检查：所有容器都在运行
		if strings.Contains(string(output), "\"State\":\"running\"") {
			logger.WriteLog("info", "healthcheck", "所有服务已就绪")
			return nil
		}

		time.Sleep(interval)
	}

	return fmt.Errorf("服务健康检查超时（%v）", timeout)
}

func (do *DeployOrchestrator) buildServiceInfoList(meta TemplateMeta) []AppServiceInfo {
	services := make([]AppServiceInfo, 0, len(meta.Services))
	for _, svc := range meta.Services {
		info := AppServiceInfo{
			Name:        svc.Name,
			Type:        svc.Type,
			Description: svc.Description,
			Status:      "running",
		}
		if len(svc.Ports) > 0 {
			info.Port = svc.Ports[0].Internal
			if svc.Ports[0].External != nil {
				info.TargetPort = *svc.Ports[0].External
			}
		}
		services = append(services, info)
	}
	return services
}

func (do *DeployOrchestrator) buildAppCredentials(
	credentials map[string]map[string]string,
	meta TemplateMeta,
) map[string]AppServiceCredential {
	result := make(map[string]AppServiceCredential)

	for svc, creds := range credentials {
		appCred := AppServiceCredential{
			Username: creds["username"],
			Password: maskPassword(creds["password"]),
			Database: creds["database"],
			Token:    maskPassword(creds["token"]),
			Secret:   maskPassword(creds["secret"]),
			Endpoint: creds["endpoint"],
			Host:     creds["host"],
		}

		// 解析端口
		if portStr := creds["port"]; portStr != "" {
			var port int
			if _, err := fmt.Sscanf(portStr, "%d", &port); err == nil {
				appCred.Port = port
			}
		}

		// 生成连接字符串
		if connStr, ok := meta.ConnectionStrings[svc]; ok {
			appCred.ConnectionString = do.renderConnectionString(connStr, creds)
		}

		result[svc] = appCred
	}

	return result
}

// buildAppCredentialsFull 构建完整凭证（不脱敏）
func (do *DeployOrchestrator) buildAppCredentialsFull(
	credentials map[string]map[string]string,
	meta TemplateMeta,
) map[string]AppServiceCredential {
	result := make(map[string]AppServiceCredential)

	for svc, creds := range credentials {
		appCred := AppServiceCredential{
			Username: creds["username"],
			Password: creds["password"], // 完整密码
			Database: creds["database"],
			Token:    creds["token"], // 完整 token
			Secret:   creds["secret"], // 完整 secret
			Endpoint: creds["endpoint"],
			Host:     creds["host"],
		}

		// 解析端口
		if portStr := creds["port"]; portStr != "" {
			var port int
			if _, err := fmt.Sscanf(portStr, "%d", &port); err == nil {
				appCred.Port = port
			}
		}

		// 生成连接字符串
		if connStr, ok := meta.ConnectionStrings[svc]; ok {
			appCred.ConnectionString = do.renderConnectionString(connStr, creds)
		}

		result[svc] = appCred
	}

	return result
}

// BuildAppCredentials 构建应用凭证（公共方法，供外部调用，返回脱敏版本）
func (do *DeployOrchestrator) BuildAppCredentials(
	credentials map[string]map[string]string,
	meta TemplateMeta,
) map[string]AppServiceCredential {
	return do.buildAppCredentials(credentials, meta)
}

func (do *DeployOrchestrator) renderConnectionString(template string, creds map[string]string) string {
	result := template
	for k, v := range creds {
		result = strings.ReplaceAll(result, "{"+k+"}", v)
		result = strings.ReplaceAll(result, "{username}", creds["username"])
		result = strings.ReplaceAll(result, "{password}", creds["password"])
		result = strings.ReplaceAll(result, "{database}", creds["database"])
		result = strings.ReplaceAll(result, "{host}", creds["host"])
		result = strings.ReplaceAll(result, "{port}", creds["port"])
	}
	return result
}

func (do *DeployOrchestrator) buildComposeEnv(vars map[string]string) []string {
	env := make([]string, 0, len(vars))
	for k, v := range vars {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	return env
}

func maskPassword(pwd string) string {
	if pwd == "" {
		return ""
	}
	if len(pwd) <= 4 {
		return "****"
	}
	return pwd[:2] + "****" + pwd[len(pwd)-2:]
}

func sanitizeProjectName(name string) string {
	// Docker Compose 项目名只能包含小写字母、数字、下划线和连字符
	result := strings.ToLower(name)
	result = strings.ReplaceAll(result, " ", "-")
	result = strings.ReplaceAll(result, "_", "-")
	// 移除非法字符
	var builder strings.Builder
	for _, r := range result {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			builder.WriteRune(r)
		}
	}
	result = builder.String()
	if result == "" {
		result = "app"
	}
	return result
}


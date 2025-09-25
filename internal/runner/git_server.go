package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

// GitServer Git 服务器管理器 - 类似 Dokku/Heroku 的部署平台
type GitServer struct {
	config *config.Config
	apps   map[string]*GitApp // 应用列表，key 是应用名称
	mutex  sync.RWMutex
	logger *logrus.Logger

	// Git 服务器配置
	serverConfig *GitServerConfig

	// WebHook 配置
	webhookSecret string
	webhookPort   int

	// SSH 配置
	sshUser            string // SSH 用户名，默认为 "git"
	sshHomeDir         string // SSH 用户主目录
	sshKeysDir         string // SSH 密钥目录
	authorizedKeysFile string // authorized_keys 文件路径

	// 日志管理器
	logManager *LogManager
}

// GitServerConfig Git 服务器配置
type GitServerConfig struct {
	// 主域名后缀，如 "your-domain.com"
	DomainSuffix string `json:"domain_suffix"`

	// 端口范围，如 [8000, 9000]
	PortRange [2]int `json:"port_range"`

	// Git 推送欢迎语
	WelcomeMessage string `json:"welcome_message"`

	// 是否启用自动 SSL
	AutoSSL bool `json:"auto_ssl"`

	// SSL 证书邮箱
	SSLEmail string `json:"ssl_email"`

	// 默认部署策略
	DefaultStrategy string `json:"default_strategy"`

	// 构建超时时间（秒）
	BuildTimeout int `json:"build_timeout"`

	// 是否启用自动域名分配
	AutoDomain bool `json:"auto_domain"`
}

// SSHKey SSH 密钥信息
type SSHKey struct {
	ID          string    `json:"id"`          // 密钥唯一标识
	Name        string    `json:"name"`        // 密钥名称
	PublicKey   string    `json:"public_key"`  // 公钥内容
	Fingerprint string    `json:"fingerprint"` // 密钥指纹
	CreatedAt   time.Time `json:"created_at"`  // 创建时间
	LastUsed    time.Time `json:"last_used"`   // 最后使用时间
	Enabled     bool      `json:"enabled"`     // 是否启用
}

// SSHUser SSH 用户信息
type SSHUser struct {
	Username  string    `json:"username"`   // 用户名
	HomeDir   string    `json:"home_dir"`   // 主目录
	Shell     string    `json:"shell"`      // Shell 路径
	Keys      []SSHKey  `json:"keys"`       // SSH 密钥列表
	CreatedAt time.Time `json:"created_at"` // 创建时间
	LastLogin time.Time `json:"last_login"` // 最后登录时间
	Enabled   bool      `json:"enabled"`    // 是否启用
}

// GitApp Git 应用信息 - 类似 Dokku 的 app
type GitApp struct {
	// 应用名称（唯一标识）
	Name string `json:"name"`

	// 应用显示名称
	DisplayName string `json:"display_name"`

	// Git 仓库路径
	GitPath string `json:"git_path"`

	// 应用类型（自动检测）
	AppType string `json:"app_type"` // "nodejs" | "python" | "go" | "php" | "static" | "docker"

	// 分配的域名
	Domain string `json:"domain"`

	// 分配的端口
	Port int `json:"port"`

	// 部署状态
	Status string `json:"status"` // "idle" | "building" | "deploying" | "running" | "failed"

	// 最后部署时间
	LastDeploy time.Time `json:"last_deploy"`

	// 部署配置
	DeployConfig *AppDeployConfig `json:"deploy_config,omitempty"`

	// 部署状态详情
	DeployStatus *DeployStatus `json:"deploy_status,omitempty"`

	// 部署历史
	DeployHistory []DeployRecord `json:"deploy_history,omitempty"`

	// 环境变量
	EnvVars map[string]string `json:"env_vars,omitempty"`

	// 构建包信息
	Buildpack string `json:"buildpack,omitempty"`

	// 日志相关
	LogsDir    string `json:"logs_dir,omitempty"`    // 日志目录
	CurrentLog string `json:"current_log,omitempty"` // 当前日志文件路径
}

// AppDeployConfig 应用部署配置
type AppDeployConfig struct {
	// 部署策略
	Strategy string `json:"strategy"` // "auto" | "docker" | "static" | "php"

	// 构建命令
	BuildCommands []string `json:"build_commands,omitempty"`

	// 启动命令
	StartCommand string `json:"start_command,omitempty"`

	// 工作目录
	WorkDir string `json:"work_dir,omitempty"`

	// 输出目录
	OutputDir string `json:"output_dir,omitempty"`

	// 环境变量
	EnvVars map[string]string `json:"env_vars,omitempty"`

	// 域名配置
	Domains []string `json:"domains,omitempty"`

	// SSL 配置
	SSL SSLConfig `json:"ssl"`

	// 资源限制
	Resources ResourceLimits `json:"resources,omitempty"`
}

// SSLConfig SSL 配置
type SSLConfig struct {
	// 是否启用 SSL
	Enabled bool `json:"enabled"`

	// 是否强制 HTTPS
	ForceHTTPS bool `json:"force_https"`

	// SSL 证书邮箱
	Email string `json:"email,omitempty"`

	// 自定义证书路径
	CertPath string `json:"cert_path,omitempty"`
	KeyPath  string `json:"key_path,omitempty"`
}

// ResourceLimits 资源限制
type ResourceLimits struct {
	// 内存限制（MB）
	Memory int `json:"memory,omitempty"`

	// CPU 限制（核心数）
	CPU float64 `json:"cpu,omitempty"`

	// 磁盘限制（MB）
	Disk int `json:"disk,omitempty"`
}

// DeployConfig 部署配置
type DeployConfig struct {
	// 是否启用自动部署
	AutoDeploy bool `json:"auto_deploy"`

	// 部署策略: "local" | "docker" | "static" | "php"
	Strategy string `json:"strategy"`

	// 部署目标配置
	Target DeployTarget `json:"target"`

	// 构建配置
	Build BuildConfig `json:"build"`

	// 环境变量
	EnvVars map[string]string `json:"env_vars,omitempty"`

	// 部署后钩子
	PostDeployHooks []string `json:"post_deploy_hooks,omitempty"`

	// 域名绑定
	Domains []string `json:"domains,omitempty"`

	// SSL配置
	SSL SSLDeployConfig `json:"ssl"`
}

// DeployTarget 部署目标
type DeployTarget struct {
	// 部署目录
	Path string `json:"path"`

	// 端口（用于本地部署）
	Port int `json:"port"`

	// Docker镜像名称（用于Docker部署）
	ImageName string `json:"image_name,omitempty"`

	// Docker容器名称
	ContainerName string `json:"container_name,omitempty"`

	// 静态文件根目录（用于静态部署）
	StaticRoot string `json:"static_root,omitempty"`

	// PHP-FPM地址（用于PHP部署）
	PHPFPMAddr string `json:"php_fpm_addr,omitempty"`
}

// BuildConfig 构建配置
type BuildConfig struct {
	// 构建命令
	Commands []string `json:"commands,omitempty"`

	// 构建目录
	WorkDir string `json:"work_dir,omitempty"`

	// 构建超时时间（秒）
	Timeout int `json:"timeout"`

	// 是否在构建前清理
	CleanBeforeBuild bool `json:"clean_before_build"`

	// 构建产物目录
	OutputDir string `json:"output_dir,omitempty"`
}

// SSLDeployConfig SSL部署配置
type SSLDeployConfig struct {
	// 是否自动申请SSL证书
	AutoSSL bool `json:"auto_ssl"`

	// 是否强制HTTPS
	ForceHTTPS bool `json:"force_https"`

	// SSL证书邮箱
	Email string `json:"email,omitempty"`
}

// DeployStatus 部署状态
type DeployStatus struct {
	// 当前部署状态: "idle" | "building" | "deploying" | "success" | "failed"
	Status string `json:"status"`

	// 当前部署ID
	DeployID string `json:"deploy_id"`

	// 部署开始时间
	StartTime time.Time `json:"start_time"`

	// 部署结束时间
	EndTime *time.Time `json:"end_time,omitempty"`

	// 部署进度（0-100）
	Progress int `json:"progress"`

	// 部署消息
	Message string `json:"message"`

	// 部署日志
	Logs []string `json:"logs,omitempty"`

	// 错误信息
	Error string `json:"error,omitempty"`
}

// DeployRecord 部署记录
type DeployRecord struct {
	// 部署ID
	ID string `json:"id"`

	// 部署时间
	Timestamp time.Time `json:"timestamp"`

	// 部署状态
	Status string `json:"status"`

	// 提交哈希
	CommitHash string `json:"commit_hash"`

	// 提交消息
	CommitMessage string `json:"commit_message"`

	// 部署时长（毫秒）
	Duration int64 `json:"duration"`

	// 部署日志
	Logs []string `json:"logs,omitempty"`

	// 错误信息
	Error string `json:"error,omitempty"`
}

// NewGitServer 创建新的 Git 服务器
func NewGitServer(cfg *config.Config) *GitServer {
	// 默认服务器配置
	defaultConfig := &GitServerConfig{
		DomainSuffix:    "localhost",
		PortRange:       [2]int{8000, 9000},
		WelcomeMessage:  "欢迎使用 SSLcat Git 部署平台！",
		AutoSSL:         true,
		DefaultStrategy: "auto",
		BuildTimeout:    300,
		AutoDomain:      true,
	}

	// SSH 配置
	sshUser := "git"
	sshHomeDir := "/home/git"
	sshKeysDir := "/home/git/.ssh"
	authorizedKeysFile := "/home/git/.ssh/authorized_keys"

	// 日志管理器
	logsDir := filepath.Join(cfg.Runners.Git.ReposDir, "logs")
	logManager := NewLogManager(logsDir)

	return &GitServer{
		config:             cfg,
		apps:               make(map[string]*GitApp),
		logger:             logrus.WithField("component", "git_server").Logger,
		serverConfig:       defaultConfig,
		sshUser:            sshUser,
		sshHomeDir:         sshHomeDir,
		sshKeysDir:         sshKeysDir,
		authorizedKeysFile: authorizedKeysFile,
		logManager:         logManager,
	}
}

// Start 启动 Git 服务器
func (gs *GitServer) Start() error {
	if !gs.config.Runners.Git.Enabled {
		gs.logger.Info("Git 服务器未启用")
		return nil
	}

	// 检查 Git 是否可用
	if err := gs.checkGit(); err != nil {
		return fmt.Errorf("Git 不可用: %w", err)
	}

	// 设置 SSH 用户和目录
	if err := gs.setupSSHUser(); err != nil {
		gs.logger.Warnf("设置 SSH 用户失败: %v", err)
	}

	// 创建应用目录
	if err := os.MkdirAll(gs.config.Runners.Git.ReposDir, 0755); err != nil {
		return fmt.Errorf("创建应用目录失败: %w", err)
	}

	// 加载现有应用
	if err := gs.loadApps(); err != nil {
		gs.logger.Warnf("加载应用失败: %v", err)
	}

	// 启动清理协程
	if gs.config.Runners.Git.AutoCleanup {
		go gs.cleanupRoutine()
	}

	gs.logger.Info("Git 服务器已启动")
	return nil
}

// Stop 停止 Git 服务器
func (gs *GitServer) Stop() {
	gs.logger.Info("Git 服务器已停止")
}

// ==================== Git 服务器配置管理 ====================

// GetServerConfig 获取服务器配置
func (gs *GitServer) GetServerConfig() *GitServerConfig {
	gs.mutex.RLock()
	defer gs.mutex.RUnlock()

	configCopy := *gs.serverConfig
	return &configCopy
}

// UpdateServerConfig 更新服务器配置
func (gs *GitServer) UpdateServerConfig(config *GitServerConfig) error {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	gs.serverConfig = config

	// 保存配置到文件
	if err := gs.saveServerConfig(); err != nil {
		return fmt.Errorf("保存服务器配置失败: %w", err)
	}

	gs.logger.Info("服务器配置已更新")
	return nil
}

// ==================== 应用管理 ====================

// CreateApp 创建新应用
func (gs *GitServer) CreateApp(appName string) (*GitApp, error) {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	// 检查应用是否已存在
	if _, exists := gs.apps[appName]; exists {
		return nil, fmt.Errorf("应用 %s 已存在", appName)
	}

	// 分配端口
	port, err := gs.allocatePort()
	if err != nil {
		return nil, fmt.Errorf("分配端口失败: %w", err)
	}

	// 生成域名
	domain := gs.generateDomain(appName)

	// 创建应用目录
	appPath := filepath.Join(gs.config.Runners.Git.ReposDir, appName)
	if err := os.MkdirAll(appPath, 0755); err != nil {
		return nil, fmt.Errorf("创建应用目录失败: %w", err)
	}

	// 初始化 Git 仓库
	gitPath := filepath.Join(appPath, "git")

	// 创建日志目录
	logsDir := filepath.Join(appPath, "logs")
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return nil, fmt.Errorf("创建日志目录失败: %w", err)
	}

	// 创建应用对象
	app := &GitApp{
		Name:        appName,
		DisplayName: appName,
		GitPath:     gitPath,
		Domain:      domain,
		Port:        port,
		Status:      "idle",
		LogsDir:     logsDir,
		CurrentLog:  filepath.Join(logsDir, fmt.Sprintf("deploy-%s.log", time.Now().Format("2006-01-02"))),
		EnvVars:     make(map[string]string),
		DeployConfig: &AppDeployConfig{
			Strategy: gs.serverConfig.DefaultStrategy,
			SSL: SSLConfig{
				Enabled: gs.serverConfig.AutoSSL,
				Email:   gs.serverConfig.SSLEmail,
			},
		},
	}

	gs.apps[appName] = app

	// 设置 Git 钩子
	if err := gs.setupGitHooks(app); err != nil {
		gs.logger.Warnf("设置 Git 钩子失败: %v", err)
	}

	// 保存应用信息
	if err := gs.saveApps(); err != nil {
		return nil, fmt.Errorf("保存应用信息失败: %w", err)
	}

	gs.logger.Infof("应用 %s 已创建，域名: %s，端口: %d", appName, domain, port)
	return app, nil
}

// GetApp 获取应用信息
func (gs *GitServer) GetApp(appName string) (*GitApp, error) {
	gs.mutex.RLock()
	defer gs.mutex.RUnlock()

	app, exists := gs.apps[appName]
	if !exists {
		return nil, fmt.Errorf("应用 %s 不存在", appName)
	}

	// 返回应用副本
	appCopy := *app
	return &appCopy, nil
}

// ListApps 列出所有应用
func (gs *GitServer) ListApps() []*GitApp {
	gs.mutex.RLock()
	defer gs.mutex.RUnlock()

	apps := make([]*GitApp, 0, len(gs.apps))
	for _, app := range gs.apps {
		appCopy := *app
		apps = append(apps, &appCopy)
	}

	return apps
}

// DeleteApp 删除应用
func (gs *GitServer) DeleteApp(appName string) error {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	app, exists := gs.apps[appName]
	if !exists {
		return fmt.Errorf("应用 %s 不存在", appName)
	}

	// 停止应用（如果正在运行）
	if app.Status == "running" {
		if err := gs.stopApp(app); err != nil {
			gs.logger.Warnf("停止应用失败: %v", err)
		}
	}

	// 删除应用目录
	appPath := filepath.Join(gs.config.Runners.Git.ReposDir, appName)
	if err := os.RemoveAll(appPath); err != nil {
		gs.logger.Warnf("删除应用目录失败: %v", err)
	}

	// 释放端口
	gs.releasePort(app.Port)

	// 从应用列表中删除
	delete(gs.apps, appName)

	// 保存应用信息
	if err := gs.saveApps(); err != nil {
		return fmt.Errorf("保存应用信息失败: %w", err)
	}

	gs.logger.Infof("应用 %s 已删除", appName)
	return nil
}

// ==================== Git 推送处理 ====================

// HandleGitPush 处理 Git 推送 - 类似 Dokku 的 git-receive-pack
func (gs *GitServer) HandleGitPush(appName string, pushData []byte) error {
	gs.mutex.Lock()
	app, exists := gs.apps[appName]
	if !exists {
		gs.mutex.Unlock()
		return fmt.Errorf("应用 %s 不存在", appName)
	}
	gs.mutex.Unlock()

	// 更新应用状态
	gs.mutex.Lock()
	app.Status = "building"
	app.LastDeploy = time.Now()
	gs.mutex.Unlock()

	// 在 goroutine 中处理推送
	go gs.processGitPush(app, pushData)

	gs.logger.Infof("开始处理应用 %s 的 Git 推送", appName)
	return nil
}

// processGitPush 处理 Git 推送
func (gs *GitServer) processGitPush(app *GitApp, pushData []byte) {
	// 检测应用类型
	appType, err := gs.detectAppType(app)
	if err != nil {
		gs.handleDeployError(app, fmt.Errorf("检测应用类型失败: %w", err))
		return
	}

	gs.mutex.Lock()
	app.AppType = appType
	gs.mutex.Unlock()

	// 执行构建和部署
	if err := gs.buildAndDeployApp(app); err != nil {
		gs.handleDeployError(app, err)
		return
	}

	// 部署成功
	gs.handleDeploySuccess(app)
}

// detectAppType 检测应用类型
func (gs *GitServer) detectAppType(app *GitApp) (string, error) {
	// 检查各种项目文件来确定应用类型
	checks := []struct {
		file    string
		appType string
	}{
		{"package.json", "nodejs"},
		{"requirements.txt", "python"},
		{"go.mod", "go"},
		{"composer.json", "php"},
		{"Dockerfile", "docker"},
		{"index.html", "static"},
	}

	for _, check := range checks {
		filePath := filepath.Join(app.GitPath, check.file)
		if _, err := os.Stat(filePath); err == nil {
			return check.appType, nil
		}
	}

	// 默认返回静态类型
	return "static", nil
}

// buildAndDeployApp 构建和部署应用
func (gs *GitServer) buildAndDeployApp(app *GitApp) error {
	// 根据应用类型执行不同的构建策略
	switch app.AppType {
	case "nodejs":
		return gs.buildNodeJSApp(app)
	case "python":
		return gs.buildPythonApp(app)
	case "go":
		return gs.buildGoApp(app)
	case "php":
		return gs.buildPHPApp(app)
	case "docker":
		return gs.buildDockerApp(app)
	case "static":
		return gs.buildStaticApp(app)
	default:
		return fmt.Errorf("不支持的应用类型: %s", app.AppType)
	}
}

// ==================== 应用构建方法 ====================

// buildNodeJSApp 构建 Node.js 应用
func (gs *GitServer) buildNodeJSApp(app *GitApp) error {
	// 检查 package.json
	packageJSONPath := filepath.Join(app.GitPath, "package.json")
	if _, err := os.Stat(packageJSONPath); os.IsNotExist(err) {
		return fmt.Errorf("未找到 package.json 文件")
	}

	// 执行 npm install
	if err := gs.runCommand(app.GitPath, "npm", "install"); err != nil {
		return fmt.Errorf("npm install 失败: %w", err)
	}

	// 检查是否有构建脚本
	if gs.hasBuildScript(app.GitPath) {
		if err := gs.runCommand(app.GitPath, "npm", "run", "build"); err != nil {
			return fmt.Errorf("npm run build 失败: %w", err)
		}
	}

	// 启动应用
	return gs.startNodeJSApp(app)
}

// buildPythonApp 构建 Python 应用
func (gs *GitServer) buildPythonApp(app *GitApp) error {
	// 检查 requirements.txt
	requirementsPath := filepath.Join(app.GitPath, "requirements.txt")
	if _, err := os.Stat(requirementsPath); os.IsNotExist(err) {
		gs.logger.Warn("未找到 requirements.txt 文件")
	} else {
		// 安装依赖
		if err := gs.runCommand(app.GitPath, "pip", "install", "-r", "requirements.txt"); err != nil {
			return fmt.Errorf("pip install 失败: %w", err)
		}
	}

	// 启动应用
	return gs.startPythonApp(app)
}

// buildGoApp 构建 Go 应用
func (gs *GitServer) buildGoApp(app *GitApp) error {
	// 检查 go.mod
	goModPath := filepath.Join(app.GitPath, "go.mod")
	if _, err := os.Stat(goModPath); os.IsNotExist(err) {
		return fmt.Errorf("未找到 go.mod 文件")
	}

	// 下载依赖
	if err := gs.runCommand(app.GitPath, "go", "mod", "download"); err != nil {
		return fmt.Errorf("go mod download 失败: %w", err)
	}

	// 构建应用
	if err := gs.runCommand(app.GitPath, "go", "build", "-o", "app"); err != nil {
		return fmt.Errorf("go build 失败: %w", err)
	}

	// 启动应用
	return gs.startGoApp(app)
}

// buildPHPApp 构建 PHP 应用
func (gs *GitServer) buildPHPApp(app *GitApp) error {
	// 检查 composer.json
	composerPath := filepath.Join(app.GitPath, "composer.json")
	if _, err := os.Stat(composerPath); os.IsNotExist(err) {
		gs.logger.Warn("未找到 composer.json 文件")
	} else {
		// 安装依赖
		if err := gs.runCommand(app.GitPath, "composer", "install"); err != nil {
			return fmt.Errorf("composer install 失败: %w", err)
		}
	}

	// PHP 应用直接部署到 Web 目录
	return gs.deployPHPApp(app)
}

// buildDockerApp 构建 Docker 应用
func (gs *GitServer) buildDockerApp(app *GitApp) error {
	// 检查 Dockerfile
	dockerfilePath := filepath.Join(app.GitPath, "Dockerfile")
	if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
		return fmt.Errorf("未找到 Dockerfile 文件")
	}

	// 构建 Docker 镜像
	imageName := fmt.Sprintf("sslcat-%s", app.Name)
	if err := gs.runCommand(app.GitPath, "docker", "build", "-t", imageName, "."); err != nil {
		return fmt.Errorf("Docker 构建失败: %w", err)
	}

	// 启动 Docker 容器
	return gs.startDockerApp(app, imageName)
}

// buildStaticApp 构建静态应用
func (gs *GitServer) buildStaticApp(app *GitApp) error {
	// 静态应用直接部署
	return gs.deployStaticApp(app)
}

// ==================== 应用启动方法 ====================

// startNodeJSApp 启动 Node.js 应用
func (gs *GitServer) startNodeJSApp(app *GitApp) error {
	// 检查启动脚本
	startCommand := "node server.js"
	if gs.hasStartScript(app.GitPath) {
		startCommand = "npm start"
	}

	// 启动应用
	return gs.startAppProcess(app, startCommand)
}

// startPythonApp 启动 Python 应用
func (gs *GitServer) startPythonApp(app *GitApp) error {
	// 检查启动文件
	startFiles := []string{"app.py", "main.py", "server.py", "wsgi.py"}
	var startFile string
	for _, file := range startFiles {
		if _, err := os.Stat(filepath.Join(app.GitPath, file)); err == nil {
			startFile = file
			break
		}
	}

	if startFile == "" {
		return fmt.Errorf("未找到 Python 启动文件")
	}

	// 启动应用
	return gs.startAppProcess(app, fmt.Sprintf("python %s", startFile))
}

// startGoApp 启动 Go 应用
func (gs *GitServer) startGoApp(app *GitApp) error {
	// 启动应用
	return gs.startAppProcess(app, "./app")
}

// startDockerApp 启动 Docker 应用
func (gs *GitServer) startDockerApp(app *GitApp, imageName string) error {
	// 停止现有容器
	containerName := fmt.Sprintf("sslcat-%s", app.Name)
	gs.runCommand("", "docker", "stop", containerName)
	gs.runCommand("", "docker", "rm", containerName)

	// 启动新容器
	cmd := fmt.Sprintf("docker run -d --name %s -p %d:80 %s", containerName, app.Port, imageName)
	return gs.runCommand("", "sh", "-c", cmd)
}

// deployPHPApp 部署 PHP 应用
func (gs *GitServer) deployPHPApp(app *GitApp) error {
	// 复制文件到 Web 目录
	webDir := filepath.Join(gs.config.Runners.Git.ReposDir, "web", app.Name)
	if err := os.MkdirAll(webDir, 0755); err != nil {
		return fmt.Errorf("创建 Web 目录失败: %w", err)
	}

	// 复制 PHP 文件
	if err := gs.runCommand("", "cp", "-r", app.GitPath+"/*", webDir); err != nil {
		return fmt.Errorf("复制 PHP 文件失败: %w", err)
	}

	gs.mutex.Lock()
	app.Status = "running"
	gs.mutex.Unlock()

	return nil
}

// deployStaticApp 部署静态应用
func (gs *GitServer) deployStaticApp(app *GitApp) error {
	// 复制文件到 Web 目录
	webDir := filepath.Join(gs.config.Runners.Git.ReposDir, "web", app.Name)
	if err := os.MkdirAll(webDir, 0755); err != nil {
		return fmt.Errorf("创建 Web 目录失败: %w", err)
	}

	// 复制静态文件
	if err := gs.runCommand("", "cp", "-r", app.GitPath+"/*", webDir); err != nil {
		return fmt.Errorf("复制静态文件失败: %w", err)
	}

	gs.mutex.Lock()
	app.Status = "running"
	gs.mutex.Unlock()

	return nil
}

// startAppProcess 启动应用进程
func (gs *GitServer) startAppProcess(app *GitApp, command string) error {
	// 这里应该实现进程管理，类似 PM2 或 systemd
	// 简化实现：记录启动命令
	gs.mutex.Lock()
	app.Status = "running"
	gs.mutex.Unlock()

	gs.logger.Infof("应用 %s 已启动，命令: %s", app.Name, command)
	return nil
}

// ==================== 辅助函数 ====================

// runCommand 执行命令
func (gs *GitServer) runCommand(workDir, command string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(gs.serverConfig.BuildTimeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)
	if workDir != "" {
		cmd.Dir = workDir
	}

	output, err := cmd.Output()
	if err != nil {
		gs.logger.Errorf("命令执行失败: %s %v, 输出: %s", command, args, string(output))
		return err
	}

	gs.logger.Debugf("命令执行成功: %s %v, 输出: %s", command, args, string(output))
	return nil
}

// hasBuildScript 检查是否有构建脚本
func (gs *GitServer) hasBuildScript(workDir string) bool {
	packageJSONPath := filepath.Join(workDir, "package.json")
	data, err := os.ReadFile(packageJSONPath)
	if err != nil {
		return false
	}

	var pkg map[string]interface{}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return false
	}

	scripts, ok := pkg["scripts"].(map[string]interface{})
	if !ok {
		return false
	}

	_, hasBuild := scripts["build"]
	return hasBuild
}

// hasStartScript 检查是否有启动脚本
func (gs *GitServer) hasStartScript(workDir string) bool {
	packageJSONPath := filepath.Join(workDir, "package.json")
	data, err := os.ReadFile(packageJSONPath)
	if err != nil {
		return false
	}

	var pkg map[string]interface{}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return false
	}

	scripts, ok := pkg["scripts"].(map[string]interface{})
	if !ok {
		return false
	}

	_, hasStart := scripts["start"]
	return hasStart
}

// allocatePort 分配端口
func (gs *GitServer) allocatePort() (int, error) {
	// 简单的端口分配策略：从端口范围中分配第一个可用端口
	// 实际实现中应该检查端口是否被占用
	for port := gs.serverConfig.PortRange[0]; port <= gs.serverConfig.PortRange[1]; port++ {
		// 检查端口是否已被使用
		if !gs.isPortInUse(port) {
			return port, nil
		}
	}

	return 0, fmt.Errorf("没有可用的端口")
}

// releasePort 释放端口
func (gs *GitServer) releasePort(port int) {
	// 实际实现中应该从已使用端口列表中移除
	gs.logger.Debugf("释放端口: %d", port)
}

// isPortInUse 检查端口是否被使用
func (gs *GitServer) isPortInUse(port int) bool {
	// 简化实现：检查所有应用是否使用了该端口
	gs.mutex.RLock()
	defer gs.mutex.RUnlock()

	for _, app := range gs.apps {
		if app.Port == port {
			return true
		}
	}

	return false
}

// generateDomain 生成域名
func (gs *GitServer) generateDomain(appName string) string {
	if gs.serverConfig.AutoDomain {
		return fmt.Sprintf("%s.%s", appName, gs.serverConfig.DomainSuffix)
	}
	return ""
}

// stopApp 停止应用
func (gs *GitServer) stopApp(app *GitApp) error {
	// 根据应用类型停止应用
	switch app.AppType {
	case "docker":
		containerName := fmt.Sprintf("sslcat-%s", app.Name)
		gs.runCommand("", "docker", "stop", containerName)
		gs.runCommand("", "docker", "rm", containerName)
	default:
		// 其他类型的应用停止逻辑
		gs.logger.Infof("停止应用: %s", app.Name)
	}

	gs.mutex.Lock()
	app.Status = "idle"
	gs.mutex.Unlock()

	return nil
}

// handleDeploySuccess 处理部署成功
func (gs *GitServer) handleDeploySuccess(app *GitApp) {
	gs.mutex.Lock()
	app.Status = "running"
	app.LastDeploy = time.Now()
	gs.mutex.Unlock()

	gs.logger.Infof("应用 %s 部署成功", app.Name)
}

// handleDeployError 处理部署错误
func (gs *GitServer) handleDeployError(app *GitApp, err error) {
	gs.mutex.Lock()
	app.Status = "failed"
	gs.mutex.Unlock()

	gs.logger.Errorf("应用 %s 部署失败: %v", app.Name, err)
}

// ==================== 数据持久化 ====================

// loadApps 加载应用
func (gs *GitServer) loadApps() error {
	appsFile := filepath.Join(gs.config.Runners.Git.ReposDir, "apps.json")
	if _, err := os.Stat(appsFile); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(appsFile)
	if err != nil {
		return fmt.Errorf("读取应用文件失败: %w", err)
	}

	var apps map[string]*GitApp
	if err := json.Unmarshal(data, &apps); err != nil {
		return fmt.Errorf("解析应用文件失败: %w", err)
	}

	gs.apps = apps
	return nil
}

// saveApps 保存应用
func (gs *GitServer) saveApps() error {
	appsFile := filepath.Join(gs.config.Runners.Git.ReposDir, "apps.json")
	data, err := json.MarshalIndent(gs.apps, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化应用失败: %w", err)
	}

	if err := os.WriteFile(appsFile, data, 0644); err != nil {
		return fmt.Errorf("写入应用文件失败: %w", err)
	}

	return nil
}

// saveServerConfig 保存服务器配置
func (gs *GitServer) saveServerConfig() error {
	configFile := filepath.Join(gs.config.Runners.Git.ReposDir, "server_config.json")
	data, err := json.MarshalIndent(gs.serverConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化服务器配置失败: %w", err)
	}

	if err := os.WriteFile(configFile, data, 0644); err != nil {
		return fmt.Errorf("写入服务器配置失败: %w", err)
	}

	return nil
}

// checkGit 检查 Git 是否可用
func (gs *GitServer) checkGit() error {
	cmd := exec.Command("git", "version")
	return cmd.Run()
}

// cleanupRoutine 清理协程
func (gs *GitServer) cleanupRoutine() {
	ticker := time.NewTicker(time.Duration(gs.config.Runners.Git.CleanupInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		gs.cleanupOldApps()
	}
}

// cleanupOldApps 清理旧应用
func (gs *GitServer) cleanupOldApps() {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	cutoffTime := time.Now().Add(-time.Duration(gs.config.Runners.Git.CleanupInterval) * time.Second)

	for _, app := range gs.apps {
		if app.LastDeploy.Before(cutoffTime) {
			// 停止应用
			if app.Status == "running" {
				gs.stopApp(app)
			}
			// 删除应用目录
			appPath := filepath.Join(gs.config.Runners.Git.ReposDir, app.Name)
			os.RemoveAll(appPath)
			delete(gs.apps, app.Name)
		}
	}

	gs.saveApps()
}

// ==================== SSH 用户管理 ====================

// setupSSHUser 设置 SSH 用户和目录
func (gs *GitServer) setupSSHUser() error {
	// 检查是否为 root 用户
	if os.Geteuid() != 0 {
		gs.logger.Warn("非 root 用户，跳过 SSH 用户设置")
		return nil
	}

	// 创建 git 用户（如果不存在）
	if err := gs.createGitUser(); err != nil {
		return fmt.Errorf("创建 git 用户失败: %w", err)
	}

	// 创建 SSH 目录
	if err := os.MkdirAll(gs.sshKeysDir, 0700); err != nil {
		return fmt.Errorf("创建 SSH 目录失败: %w", err)
	}

	// 设置目录权限
	if err := os.Chown(gs.sshKeysDir, 1000, 1000); err != nil { // git 用户 UID
		gs.logger.Warnf("设置 SSH 目录权限失败: %v", err)
	}

	// 创建 authorized_keys 文件（如果不存在）
	if _, err := os.Stat(gs.authorizedKeysFile); os.IsNotExist(err) {
		if err := os.WriteFile(gs.authorizedKeysFile, []byte{}, 0600); err != nil {
			return fmt.Errorf("创建 authorized_keys 文件失败: %w", err)
		}
		if err := os.Chown(gs.authorizedKeysFile, 1000, 1000); err != nil {
			gs.logger.Warnf("设置 authorized_keys 文件权限失败: %v", err)
		}
	}

	gs.logger.Info("SSH 用户设置完成")
	return nil
}

// createGitUser 创建 git 用户
func (gs *GitServer) createGitUser() error {
	// 检查用户是否已存在
	cmd := exec.Command("id", "-u", gs.sshUser)
	if err := cmd.Run(); err == nil {
		gs.logger.Info("git 用户已存在")
		return nil
	}

	// 创建用户
	cmd = exec.Command("useradd", "-r", "-s", "/bin/bash", "-m", "-d", gs.sshHomeDir, gs.sshUser)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("创建 git 用户失败: %w", err)
	}

	gs.logger.Info("git 用户创建成功")
	return nil
}

// AddSSHKey 添加 SSH 密钥
func (gs *GitServer) AddSSHKey(keyName, publicKey string) error {
	// 验证公钥格式
	if !gs.validatePublicKey(publicKey) {
		return fmt.Errorf("无效的公钥格式")
	}

	// 生成密钥指纹
	fingerprint := gs.generateFingerprint(publicKey)

	// 检查密钥是否已存在
	if gs.keyExists(fingerprint) {
		return fmt.Errorf("密钥已存在")
	}

	// 确保SSH目录存在
	if err := os.MkdirAll(gs.sshKeysDir, 0700); err != nil {
		return fmt.Errorf("创建 SSH 目录失败: %w", err)
	}

	// 添加密钥到 authorized_keys
	keyEntry := fmt.Sprintf("# %s\n%s\n", keyName, publicKey)

	file, err := os.OpenFile(gs.authorizedKeysFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("打开 authorized_keys 文件失败: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(keyEntry); err != nil {
		return fmt.Errorf("写入 authorized_keys 文件失败: %w", err)
	}

	gs.logger.Infof("SSH 密钥已添加: %s", keyName)
	return nil
}

// RemoveSSHKey 删除 SSH 密钥
func (gs *GitServer) RemoveSSHKey(fingerprint string) error {
	// 检查文件是否存在
	if _, err := os.Stat(gs.authorizedKeysFile); os.IsNotExist(err) {
		gs.logger.Warn("authorized_keys 文件不存在，无需删除密钥")
		return nil
	}

	// 读取 authorized_keys 文件
	content, err := os.ReadFile(gs.authorizedKeysFile)
	if err != nil {
		return fmt.Errorf("读取 authorized_keys 文件失败: %w", err)
	}

	// 解析并过滤密钥
	lines := strings.Split(string(content), "\n")
	var newLines []string

	for _, line := range lines {
		if !strings.Contains(line, fingerprint) && line != "" {
			newLines = append(newLines, line)
		}
	}

	// 写回文件
	newContent := strings.Join(newLines, "\n")
	if err := os.WriteFile(gs.authorizedKeysFile, []byte(newContent), 0600); err != nil {
		return fmt.Errorf("更新 authorized_keys 文件失败: %w", err)
	}

	gs.logger.Infof("SSH 密钥已删除: %s", fingerprint)
	return nil
}

// ListSSHKeys 列出所有 SSH 密钥
func (gs *GitServer) ListSSHKeys() ([]SSHKey, error) {
	// 检查文件是否存在，如果不存在则返回空列表
	if _, err := os.Stat(gs.authorizedKeysFile); os.IsNotExist(err) {
		gs.logger.Warn("authorized_keys 文件不存在，返回空列表")
		return []SSHKey{}, nil
	}

	content, err := os.ReadFile(gs.authorizedKeysFile)
	if err != nil {
		return nil, fmt.Errorf("读取 authorized_keys 文件失败: %w", err)
	}

	var keys []SSHKey
	lines := strings.Split(string(content), "\n")

	for i, line := range lines {
		if strings.HasPrefix(line, "# ") {
			// 这是注释行，包含密钥名称
			keyName := strings.TrimPrefix(line, "# ")
			if i+1 < len(lines) && !strings.HasPrefix(lines[i+1], "#") && lines[i+1] != "" {
				publicKey := lines[i+1]
				fingerprint := gs.generateFingerprint(publicKey)
				keys = append(keys, SSHKey{
					ID:          fingerprint,
					Name:        keyName,
					PublicKey:   publicKey,
					Fingerprint: fingerprint,
					CreatedAt:   time.Now(),
					Enabled:     true,
				})
			}
		}
	}

	return keys, nil
}

// validatePublicKey 验证公钥格式
func (gs *GitServer) validatePublicKey(publicKey string) bool {
	// 基本的公钥格式检查
	parts := strings.Fields(publicKey)
	if len(parts) < 2 {
		return false
	}

	// 检查密钥类型
	keyTypes := []string{"ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}
	keyType := parts[0]

	for _, validType := range keyTypes {
		if keyType == validType {
			return true
		}
	}

	return false
}

// generateFingerprint 生成密钥指纹
func (gs *GitServer) generateFingerprint(publicKey string) string {
	// 简单的指纹生成（实际应该使用 MD5 或 SHA256）
	parts := strings.Fields(publicKey)
	if len(parts) >= 2 {
		return parts[1][:16] // 取密钥数据的前16个字符作为指纹
	}
	return ""
}

// keyExists 检查密钥是否已存在
func (gs *GitServer) keyExists(fingerprint string) bool {
	keys, err := gs.ListSSHKeys()
	if err != nil {
		return false
	}

	for _, key := range keys {
		if key.Fingerprint == fingerprint {
			return true
		}
	}

	return false
}

// ==================== 日志管理 ====================

// LogEntry 日志条目
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"` // "info" | "warn" | "error" | "debug"
	Message   string    `json:"message"`
	Source    string    `json:"source"` // "git" | "build" | "deploy" | "run"
	AppName   string    `json:"app_name"`
}

// LogManager 日志管理器
type LogManager struct {
	logsDir string
	logger  *logrus.Logger
}

// NewLogManager 创建日志管理器
func NewLogManager(logsDir string) *LogManager {
	return &LogManager{
		logsDir: logsDir,
		logger:  logrus.WithField("component", "log_manager").Logger,
	}
}

// WriteLog 写入日志
func (lm *LogManager) WriteLog(appName, level, source, message string) error {
	// 确保日志目录存在
	appLogsDir := filepath.Join(lm.logsDir, appName)
	if err := os.MkdirAll(appLogsDir, 0755); err != nil {
		return fmt.Errorf("创建应用日志目录失败: %w", err)
	}

	// 生成日志文件名（按日期）
	logFile := filepath.Join(appLogsDir, fmt.Sprintf("deploy-%s.log", time.Now().Format("2006-01-02")))

	// 创建日志条目
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
		Source:    source,
		AppName:   appName,
	}

	// 写入日志文件
	logLine := fmt.Sprintf("[%s] [%s] [%s] %s\n",
		entry.Timestamp.Format("2006-01-02 15:04:05"),
		entry.Level,
		entry.Source,
		entry.Message)

	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(logLine); err != nil {
		return fmt.Errorf("写入日志失败: %w", err)
	}

	return nil
}

// GetLogs 获取应用日志
func (lm *LogManager) GetLogs(appName string, lines int) ([]LogEntry, error) {
	appLogsDir := filepath.Join(lm.logsDir, appName)

	// 获取最新的日志文件
	logFiles, err := filepath.Glob(filepath.Join(appLogsDir, "deploy-*.log"))
	if err != nil {
		return nil, fmt.Errorf("查找日志文件失败: %w", err)
	}

	if len(logFiles) == 0 {
		return []LogEntry{}, nil
	}

	// 按文件名排序（最新的在前）
	sort.Strings(logFiles)
	latestLogFile := logFiles[len(logFiles)-1]

	// 读取日志文件
	content, err := os.ReadFile(latestLogFile)
	if err != nil {
		return nil, fmt.Errorf("读取日志文件失败: %w", err)
	}

	// 解析日志
	var entries []LogEntry
	logLines := strings.Split(string(content), "\n")

	// 如果指定了行数，只取最后几行
	startLine := 0
	if lines > 0 && len(logLines) > lines {
		startLine = len(logLines) - lines
	}

	for i := startLine; i < len(logLines); i++ {
		line := strings.TrimSpace(logLines[i])
		if line == "" {
			continue
		}

		// 解析日志行格式: [timestamp] [level] [source] message
		parts := strings.SplitN(line, " ", 4)
		if len(parts) >= 4 {
			timestamp, _ := time.Parse("2006-01-02 15:04:05", strings.Trim(parts[0], "[]"))
			level := strings.Trim(parts[1], "[]")
			source := strings.Trim(parts[2], "[]")
			message := parts[3]

			entries = append(entries, LogEntry{
				Timestamp: timestamp,
				Level:     level,
				Message:   message,
				Source:    source,
				AppName:   appName,
			})
		}
	}

	return entries, nil
}

// GetLogFiles 获取应用的所有日志文件
func (lm *LogManager) GetLogFiles(appName string) ([]string, error) {
	appLogsDir := filepath.Join(lm.logsDir, appName)

	logFiles, err := filepath.Glob(filepath.Join(appLogsDir, "deploy-*.log"))
	if err != nil {
		return nil, fmt.Errorf("查找日志文件失败: %w", err)
	}

	// 按文件名排序（最新的在前）
	sort.Strings(logFiles)

	return logFiles, nil
}

// ==================== Git 钩子管理 ====================

// setupGitHooks 设置 Git 钩子
func (gs *GitServer) setupGitHooks(app *GitApp) error {
	// 创建 Git 仓库（如果不存在）
	if err := gs.initGitRepo(app); err != nil {
		return fmt.Errorf("初始化 Git 仓库失败: %w", err)
	}

	// 设置 post-receive 钩子
	hookPath := filepath.Join(app.GitPath, "hooks", "post-receive")
	hookContent := gs.generatePostReceiveHook(app)

	if err := os.WriteFile(hookPath, []byte(hookContent), 0755); err != nil {
		return fmt.Errorf("创建 post-receive 钩子失败: %w", err)
	}

	gs.logger.Infof("Git 钩子已设置: %s", app.Name)
	return nil
}

// generatePostReceiveHook 生成 post-receive 钩子内容
func (gs *GitServer) generatePostReceiveHook(app *GitApp) string {
	return fmt.Sprintf(`#!/bin/bash
# SSLcat Git Hook - 自动部署钩子
# 应用: %s
# 时间: %s

set -e

APP_NAME="%s"
APP_PATH="%s"
LOGS_DIR="%s"

# 记录推送开始
echo "[$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] [info] [git] Git 推送开始" >> "$LOGS_DIR/deploy-$(date '+%%Y-%%m-%%d').log"

# 更新工作目录
cd "$APP_PATH"
git --work-tree="$APP_PATH" --git-dir="$APP_PATH/.git" checkout -f

# 触发部署
echo "[$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] [info] [git] 触发自动部署" >> "$LOGS_DIR/deploy-$(date '+%%Y-%%m-%%d').log"

# 调用部署脚本
/opt/sslcat/withssl --deploy-app "$APP_NAME" >> "$LOGS_DIR/deploy-$(date '+%%Y-%%m-%%d').log" 2>&1

echo "[$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] [info] [git] Git 推送完成" >> "$LOGS_DIR/deploy-$(date '+%%Y-%%m-%%d').log"
`, app.Name, time.Now().Format("2006-01-02 15:04:05"), app.Name, app.GitPath, app.LogsDir)
}

// initGitRepo 初始化 Git 仓库
func (gs *GitServer) initGitRepo(app *GitApp) error {
	// 创建应用目录
	if err := os.MkdirAll(app.GitPath, 0755); err != nil {
		return fmt.Errorf("创建应用目录失败: %w", err)
	}

	// 初始化 Git 仓库
	cmd := exec.Command("git", "init", "--bare", app.GitPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("初始化 Git 仓库失败: %w", err)
	}

	// 设置 Git 配置
	cmd = exec.Command("git", "config", "core.bare", "true")
	cmd.Dir = app.GitPath
	if err := cmd.Run(); err != nil {
		gs.logger.Warnf("设置 Git 配置失败: %v", err)
	}

	return nil
}

// ==================== 日志查看 API ====================

// GetAppLogs 获取应用日志
func (gs *GitServer) GetAppLogs(appName string, lines int) ([]LogEntry, error) {
	gs.mutex.RLock()
	defer gs.mutex.RUnlock()

	// 检查应用是否存在
	app, exists := gs.apps[appName]
	if !exists {
		return nil, fmt.Errorf("应用 %s 不存在", appName)
	}

	// 使用应用的日志目录
	appLogManager := NewLogManager(app.LogsDir)
	return appLogManager.GetLogs(appName, lines)
}

// GetAppLogFiles 获取应用的所有日志文件
func (gs *GitServer) GetAppLogFiles(appName string) ([]string, error) {
	gs.mutex.RLock()
	defer gs.mutex.RUnlock()

	// 检查应用是否存在
	app, exists := gs.apps[appName]
	if !exists {
		return nil, fmt.Errorf("应用 %s 不存在", appName)
	}

	// 使用应用的日志目录
	appLogManager := NewLogManager(app.LogsDir)
	return appLogManager.GetLogFiles(appName)
}

// WriteAppLog 写入应用日志
func (gs *GitServer) WriteAppLog(appName, level, source, message string) error {
	gs.mutex.RLock()
	defer gs.mutex.RUnlock()

	// 检查应用是否存在
	app, exists := gs.apps[appName]
	if !exists {
		return fmt.Errorf("应用 %s 不存在", appName)
	}

	// 使用应用的日志目录
	appLogManager := NewLogManager(app.LogsDir)
	return appLogManager.WriteLog(appName, level, source, message)
}

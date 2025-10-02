package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
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
	gitCmdDir          string // git-shell-commands 目录
	sshConfigDir       string // sshd 配置目录
	uid                int
	gid                int

	// 日志管理器
	logManager       *LogManager
	logStreamManager *LogStreamManager

	// Docker Registry
	dockerRegistry *DockerRegistry

	// Builder Registry
	builderRegistry *BuilderRegistry
}

// GitServerConfig Git 服务器配置
type GitServerConfig struct {
	// 是否启用Git服务器
	Enabled bool `json:"enabled"`

	// SSH端口
	Port int `json:"port"`

	// Webhook基础URL
	Webhook string `json:"webhook"`

	// 默认分支
	DefaultBranch string `json:"defaultBranch"`

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

	// Git 推送地址（用于显示给用户）
	GitURL string `json:"git_url"`

	// 应用类型（自动检测）
	AppType string `json:"app_type"` // "nodejs" | "python" | "go" | "php" | "static" | "docker"

	// 分配的域名
	Domain string `json:"domain"`

	// 分配的端口
	Port int `json:"port"`

	// 部署状态
	Status string `json:"status"` // "idle" | "building" | "deploying" | "running" | "failed"

	// 最后提交哈希
	LastCommit string `json:"last_commit"`

	// Docker镜像名称
	DockerImage string `json:"docker_image"`

	// 启动命令
	StartCommand string `json:"start_command"`

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
	RepoDir    string `json:"repo_dir,omitempty"`    // 工作仓库目录
	BareRepo   string `json:"bare_repo,omitempty"`   // 裸仓库路径

	// 推送记录
	PushHistory []PushRecord `json:"push_history,omitempty"` // 推送历史

	// SSH密钥绑定
	AllowedKeys []string `json:"allowed_keys,omitempty"` // 允许推送的SSH密钥指纹列表
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

// PushRecord Git 推送记录
type PushRecord struct {
	ID            string    `json:"id"`
	AppName       string    `json:"app_name"`
	PusherKey     string    `json:"pusher_key"`     // SSH密钥指纹
	PusherName    string    `json:"pusher_name"`    // 推送者名称
	CommitHash    string    `json:"commit_hash"`    // 提交哈希
	CommitMessage string    `json:"commit_message"` // 提交消息
	RefName       string    `json:"ref_name"`       // 分支/标签名
	Status        string    `json:"status"`         // pending/success/failed
	StartTime     time.Time `json:"start_time"`     // 推送开始时间
	EndTime       time.Time `json:"end_time"`       // 推送结束时间
	Duration      int64     `json:"duration"`       // 推送耗时（毫秒）
	ErrorMessage  string    `json:"error_message"`  // 错误信息
	LogFile       string    `json:"log_file"`       // 日志文件路径
	PushSize      int64     `json:"push_size"`      // 推送大小（字节）
	ClientIP      string    `json:"client_ip"`      // 客户端IP
}

// NewGitServer 创建新的 Git 服务器
func NewGitServer(cfg *config.Config) *GitServer {
	// 默认服务器配置
	defaultConfig := &GitServerConfig{
		Enabled:         true,
		Port:            22,
		Webhook:         "",
		DefaultBranch:   "main",
		DomainSuffix:    "localhost",
		PortRange:       [2]int{8000, 9000},
		WelcomeMessage:  "欢迎使用 SSLcat Git 部署平台！",
		AutoSSL:         true,
		SSLEmail:        "",
		DefaultStrategy: "auto",
		BuildTimeout:    300,
		AutoDomain:      true,
	}

	// SSH 配置 - 使用数据目录而不是系统目录
	sshUser := "git"
	// 使用data/keys目录存储SSH密钥，避免权限问题
	dataDir := filepath.Dir(cfg.Runners.Git.ReposDir)
	sshKeysDir := filepath.Join(dataDir, "keys", "ssh")
	sshHomeDir := sshKeysDir // 开发环境下使用相同目录
	authorizedKeysFile := filepath.Join(sshKeysDir, "authorized_keys")
	sshConfigDir := "/etc/ssh/sshd_config.d"

	// 日志管理器
	logsDir := filepath.Join(cfg.Runners.Git.ReposDir, "logs")
	logManager := NewLogManager(logsDir)

	// 日志流管理器
	logStreamManager := NewLogStreamManager()

	// Docker Registry配置
	dockerRegistryConfig := &DockerRegistryConfig{
		Enabled:     false, // 默认禁用，需要用户配置
		UseHTTPS:    true,
		Timeout:     30,
		TagStrategy: "commit",
		AutoPush:    false, // 默认不自动推送
		Namespace:   "sslcat",
		CleanupPolicy: DockerCleanupPolicy{
			Enabled:       true,
			KeepImages:    10,
			KeepDays:      30,
			CleanInterval: 24,
		},
	}
	dockerRegistry := NewDockerRegistry(dockerRegistryConfig)

	gs := &GitServer{
		config:             cfg,
		apps:               make(map[string]*GitApp),
		logger:             logrus.WithField("component", "git_server").Logger,
		serverConfig:       defaultConfig,
		sshUser:            sshUser,
		sshHomeDir:         sshHomeDir,
		sshKeysDir:         sshKeysDir,
		authorizedKeysFile: authorizedKeysFile,
		sshConfigDir:       sshConfigDir,
		logManager:         logManager,
		logStreamManager:   logStreamManager,
		dockerRegistry:     dockerRegistry,
	}

	// 初始化 Builder Registry
	gs.builderRegistry = gs.InitBuilders()

	// 加载持久化的应用
	if err := gs.loadApps(); err != nil {
		gs.logger.Warnf("加载应用列表失败: %v", err)
	}

	// 确保应用拥有环境变量映射
	gs.mutex.Lock()
	for _, app := range gs.apps {
		if app.EnvVars == nil {
			app.EnvVars = make(map[string]string)
		}
		if app.DeployConfig == nil {
			app.DeployConfig = &AppDeployConfig{}
		}
		if app.DeployConfig.EnvVars == nil {
			app.DeployConfig.EnvVars = make(map[string]string)
		}
	}
	gs.mutex.Unlock()

	return gs
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

	// 启动部署触发监听协程
	go gs.WatchDeployTriggers()

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
	gs.logger.Infof("🚀 开始创建应用: %s", appName)
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	// 检查应用是否已存在
	if _, exists := gs.apps[appName]; exists {
		gs.logger.Warnf("应用 %s 已存在", appName)
		return nil, fmt.Errorf("应用 %s 已存在", appName)
	}

	// 分配端口
	gs.logger.Debugf("为应用 %s 分配端口...", appName)
	gs.logger.Debugf("端口范围: %d-%d", gs.serverConfig.PortRange[0], gs.serverConfig.PortRange[1])
	gs.logger.Debugf("当前应用数量: %d", len(gs.apps))
	port, err := gs.allocatePort()
	if err != nil {
		gs.logger.Errorf("分配端口失败: %v", err)
		return nil, fmt.Errorf("分配端口失败: %w", err)
	}
	gs.logger.Infof("  ✓ 分配端口: %d", port)

	// 生成域名
	domain := gs.generateDomain(appName)
	gs.logger.Infof("  ✓ 生成域名: %s", domain)

	// 生成Git推送地址
	gitURL := gs.generateGitURL(appName)
	gs.logger.Infof("  ✓ Git 地址: %s", gitURL)

	// 创建应用目录
	appPath := filepath.Join(gs.config.Runners.Git.ReposDir, appName)
	gs.logger.Infof("  创建应用目录: %s", appPath)
	if err := os.MkdirAll(appPath, 0755); err != nil {
		gs.logger.Errorf("创建应用目录失败: %v", err)
		return nil, fmt.Errorf("创建应用目录失败: %w", err)
	}
	gs.logger.Infof("  ✓ 应用目录已创建")

	// 初始化 Git 仓库
	gitPath := filepath.Join(appPath, "git")

	// 创建日志目录
	logsDir := filepath.Join(appPath, "logs")
	gs.logger.Debugf("  创建日志目录: %s", logsDir)
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		gs.logger.Errorf("创建日志目录失败: %v", err)
		return nil, fmt.Errorf("创建日志目录失败: %w", err)
	}
	gs.logger.Infof("  ✓ 日志目录已创建")

	// 创建应用对象
	app := &GitApp{
		Name:        appName,
		DisplayName: appName,
		GitPath:     gitPath,
		GitURL:      gitURL,
		BareRepo:    filepath.Join(gitPath, "repo.git"),
		RepoDir:     filepath.Join(gitPath, "repo"),
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
	gs.logger.Infof("  ✓ 应用对象已添加到内存 (当前共 %d 个应用)", len(gs.apps))

	// 设置 Git 钩子
	gs.logger.Debugf("  设置 Git 钩子...")
	if err := gs.setupGitHooks(app); err != nil {
		gs.logger.Warnf("设置 Git 钩子失败: %v", err)
	} else {
		gs.logger.Infof("  ✓ Git 钩子已设置")
	}

	// 创建日志流
	gs.logger.Debugf("  创建日志流...")
	if err := gs.logStreamManager.CreateStreamForApp(appName, app.CurrentLog); err != nil {
		gs.logger.Warnf("创建日志流失败: %v", err)
	} else {
		gs.logger.Infof("  ✓ 日志流已创建")
	}

	// 保存应用信息
	gs.logger.Infof("  💾 保存应用信息到文件...")
	if err := gs.saveApps(); err != nil {
		gs.logger.Errorf("❌ 保存应用信息失败: %v", err)
		return nil, fmt.Errorf("保存应用信息失败: %w", err)
	}
	gs.logger.Infof("  ✓ 应用信息已保存")

	gs.logger.Infof("✅ 应用 %s 创建完成！域名: %s, 端口: %d, Git: %s",
		appName, domain, port, gitURL)
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
		if appCopy.EnvVars == nil {
			appCopy.EnvVars = make(map[string]string)
		}
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

	// 删除关联的代理规则
	if err := gs.removeProxyRuleForApp(app); err != nil {
		gs.logger.Warnf("删除应用 %s 的代理规则失败: %v", appName, err)
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

// UpdateAppEnv 更新应用环境变量
func (gs *GitServer) UpdateAppEnv(appName string, envVars map[string]string) error {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	app, exists := gs.apps[appName]
	if !exists {
		return fmt.Errorf("应用 %s 不存在", appName)
	}

	if envVars == nil {
		envVars = make(map[string]string)
	}

	// 更新环境变量
	app.EnvVars = envVars
	if app.DeployConfig == nil {
		app.DeployConfig = &AppDeployConfig{}
	}
	if app.DeployConfig.EnvVars == nil {
		app.DeployConfig.EnvVars = make(map[string]string)
	}
	// 清空旧的再赋值，避免引用共享导致的问题
	for k := range app.DeployConfig.EnvVars {
		delete(app.DeployConfig.EnvVars, k)
	}
	for k, v := range envVars {
		app.DeployConfig.EnvVars[k] = v
	}

	if err := gs.saveApps(); err != nil {
		return fmt.Errorf("保存应用信息失败: %w", err)
	}

	gs.logger.Infof("应用 %s 环境变量已更新", appName)
	return nil
}

// UpdateAppRouting 更新应用的域名和端口，并同步代理规则
func (gs *GitServer) UpdateAppRouting(appName string, port int, domain string) error {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	app, exists := gs.apps[appName]
	if !exists {
		return fmt.Errorf("应用 %s 不存在", appName)
	}

	if port <= 0 {
		return fmt.Errorf("端口必须为正整数")
	}

	// 检查端口是否被其他应用使用
	for name, existing := range gs.apps {
		if name != appName && existing.Port == port {
			return fmt.Errorf("端口 %d 已被应用 %s 使用", port, name)
		}
	}

	// 更新应用信息
	gs.releasePort(app.Port)

	app.Port = port
	app.Domain = domain

	if err := gs.saveApps(); err != nil {
		return fmt.Errorf("保存应用信息失败: %w", err)
	}

	if err := gs.addProxyRuleForApp(app); err != nil {
		return fmt.Errorf("更新代理规则失败: %w", err)
	}

	gs.logger.Infof("应用 %s 的路由信息已更新，域名: %s, 端口: %d", appName, domain, port)
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
	// 生成部署ID
	deployID := fmt.Sprintf("deploy_%d", time.Now().Unix())

	// 创建部署日志记录器
	logFile := filepath.Join(app.LogsDir, fmt.Sprintf("deploy-%s.log", time.Now().Format("2006-01-02")))
	deployLogger, err := NewDeployLogger(app.Name, deployID, logFile)
	if err != nil {
		gs.handleDeployError(app, fmt.Errorf("创建部署日志记录器失败: %w", err))
		return
	}
	defer deployLogger.Close()

	// 启动实时日志流
	logStream := gs.logStreamManager.GetOrCreateStream(app.Name, logFile)
	if logStream == nil {
		gs.logger.Warnf("Failed to create log stream for app: %s", app.Name)
	}

	// 广播部署开始状态
	gs.logStreamManager.BroadcastDeployStatus(DeployStatusUpdate{
		AppName:   app.Name,
		DeployID:  deployID,
		Status:    "building",
		Progress:  10,
		Message:   "开始部署流程",
		Timestamp: time.Now(),
	})

	// 检测应用类型
	deployLogger.WriteLog("info", "git", "开始检测应用类型")
	appType, err := gs.detectAppType(app)
	if err != nil {
		deployLogger.WriteError(fmt.Errorf("检测应用类型失败: %w", err))
		gs.handleDeployError(app, err)
		return
	}

	gs.mutex.Lock()
	app.AppType = appType
	gs.mutex.Unlock()

	deployLogger.WriteLog("info", "git", fmt.Sprintf("检测到应用类型: %s", appType))

	// 广播构建状态
	gs.logStreamManager.BroadcastDeployStatus(DeployStatusUpdate{
		AppName:   app.Name,
		DeployID:  deployID,
		Status:    "building",
		Progress:  30,
		Message:   fmt.Sprintf("检测到应用类型: %s，开始构建", appType),
		Timestamp: time.Now(),
	})

	// 执行构建和部署
	deployLogger.WriteLog("info", "deploy", "开始构建和部署应用")

	// 广播部署中状态
	gs.logStreamManager.BroadcastDeployStatus(DeployStatusUpdate{
		AppName:   app.Name,
		DeployID:  deployID,
		Status:    "deploying",
		Progress:  60,
		Message:   "正在部署应用",
		Timestamp: time.Now(),
	})

	if err := gs.buildAndDeployAppWithLogging(app, deployLogger); err != nil {
		deployLogger.WriteError(err)

		// 广播部署失败状态
		gs.logStreamManager.BroadcastDeployStatus(DeployStatusUpdate{
			AppName:   app.Name,
			DeployID:  deployID,
			Status:    "failed",
			Progress:  100,
			Message:   "部署失败",
			Error:     err.Error(),
			Timestamp: time.Now(),
		})

		gs.handleDeployError(app, err)
		return
	}

	// 部署成功
	deployLogger.WriteSuccess(time.Since(deployLogger.startTime))

	// 广播部署成功状态
	gs.logStreamManager.BroadcastDeployStatus(DeployStatusUpdate{
		AppName:   app.Name,
		DeployID:  deployID,
		Status:    "success",
		Progress:  100,
		Message:   fmt.Sprintf("部署成功 - 耗时: %v", time.Since(deployLogger.startTime)),
		Timestamp: time.Now(),
	})
	gs.handleDeploySuccess(app)
}

// detectAppType 检测应用类型（使用 Builder Registry）
func (gs *GitServer) detectAppType(app *GitApp) (string, error) {
	builder, err := gs.builderRegistry.DetectBuilder(app.GitPath)
	if err != nil {
		// 如果检测失败，默认使用静态文件
		gs.logger.Warnf("应用类型检测失败，使用静态文件类型: %v", err)
		return "static", nil
	}

	appType := builder.GetType()
	gs.logger.Infof("检测到应用类型: %s (%s)", appType, builder.GetDisplayName())
	return appType, nil
}

// buildAndDeployAppWithLogging 构建和部署应用（带日志记录）使用 Builder Registry
func (gs *GitServer) buildAndDeployAppWithLogging(app *GitApp, deployLogger *DeployLogger) error {
	// 获取对应的 Builder
	builder, err := gs.builderRegistry.GetBuilder(app.AppType)
	if err != nil {
		deployLogger.WriteLog("error", "system", fmt.Sprintf("未找到支持的构建器: %s", app.AppType))
		return fmt.Errorf("不支持的应用类型: %s", app.AppType)
	}

	deployLogger.WriteLog("info", "system", fmt.Sprintf("使用构建器: %s", builder.GetDisplayName()))

	// 构建应用
	if err := builder.BuildWithLogging(app, deployLogger); err != nil {
		deployLogger.WriteLog("error", builder.GetType(), fmt.Sprintf("构建失败: %v", err))
		return fmt.Errorf("构建失败: %w", err)
	}

	// 启动应用
	if err := builder.StartWithLogging(app, deployLogger); err != nil {
		deployLogger.WriteLog("error", builder.GetType(), fmt.Sprintf("启动失败: %v", err))
		return fmt.Errorf("启动失败: %w", err)
	}

	deployLogger.WriteLog("success", "system", "应用部署成功")
	return nil
}

// buildAndDeployApp 构建和部署应用（保持向后兼容）
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

// buildAndDeployDockerAppWithLogging 构建和部署Docker应用（带日志）
func (gs *GitServer) buildAndDeployDockerAppWithLogging(app *GitApp, deployLogger *DeployLogger) error {
	deployLogger.WriteLog("info", "docker", "开始Docker应用构建流程")

	// 构建并推送Docker镜像
	image, err := gs.dockerRegistry.BuildAndPushImage(app, deployLogger)
	if err != nil {
		return fmt.Errorf("Docker镜像构建失败: %w", err)
	}

	// 更新应用信息
	gs.mutex.Lock()
	app.DockerImage = image.FullName
	app.Status = "running"
	gs.mutex.Unlock()

	deployLogger.WriteLog("info", "docker", fmt.Sprintf("Docker应用部署完成，镜像: %s", image.FullName))
	return nil
}

// buildAndDeployNodeJSAppWithLogging 构建和部署Node.js应用（带日志）
func (gs *GitServer) buildAndDeployNodeJSAppWithLogging(app *GitApp, deployLogger *DeployLogger) error {
	deployLogger.WriteLog("info", "nodejs", "开始Node.js应用构建流程")

	// 安装依赖
	if err := gs.runCommandWithLogging(app.GitPath, deployLogger, "npm", "install"); err != nil {
		return fmt.Errorf("npm install失败: %w", err)
	}

	// 执行构建脚本（如果存在）
	if gs.hasBuildScript(app.GitPath) {
		deployLogger.WriteLog("info", "nodejs", "执行构建脚本")
		if err := gs.runCommandWithLogging(app.GitPath, deployLogger, "npm", "run", "build"); err != nil {
			deployLogger.WriteLog("warn", "nodejs", "构建脚本执行失败，继续部署")
		}
	}

	// 启动应用
	if err := gs.startNodeJSAppWithLogging(app, deployLogger); err != nil {
		return fmt.Errorf("启动Node.js应用失败: %w", err)
	}

	deployLogger.WriteLog("info", "nodejs", "Node.js应用部署完成")
	return nil
}

// buildAndDeployPythonAppWithLogging 构建和部署Python应用（带日志）
func (gs *GitServer) buildAndDeployPythonAppWithLogging(app *GitApp, deployLogger *DeployLogger) error {
	deployLogger.WriteLog("info", "python", "开始Python应用构建流程")

	// 安装依赖
	if _, err := os.Stat(filepath.Join(app.GitPath, "requirements.txt")); err == nil {
		if err := gs.runCommandWithLogging(app.GitPath, deployLogger, "pip", "install", "-r", "requirements.txt"); err != nil {
			return fmt.Errorf("pip install失败: %w", err)
		}
	}

	// 启动应用
	if err := gs.startPythonAppWithLogging(app, deployLogger); err != nil {
		return fmt.Errorf("启动Python应用失败: %w", err)
	}

	deployLogger.WriteLog("info", "python", "Python应用部署完成")
	return nil
}

// buildAndDeployGoAppWithLogging 构建和部署Go应用（带日志）
func (gs *GitServer) buildAndDeployGoAppWithLogging(app *GitApp, deployLogger *DeployLogger) error {
	deployLogger.WriteLog("info", "go", "开始Go应用构建流程")

	// 下载依赖
	if err := gs.runCommandWithLogging(app.GitPath, deployLogger, "go", "mod", "download"); err != nil {
		return fmt.Errorf("go mod download失败: %w", err)
	}

	// 构建应用
	outputPath := filepath.Join(app.GitPath, "app")
	if err := gs.runCommandWithLogging(app.GitPath, deployLogger, "go", "build", "-o", outputPath, "."); err != nil {
		return fmt.Errorf("go build失败: %w", err)
	}

	// 启动应用
	if err := gs.startGoAppWithLogging(app, deployLogger); err != nil {
		return fmt.Errorf("启动Go应用失败: %w", err)
	}

	deployLogger.WriteLog("info", "go", "Go应用部署完成")
	return nil
}

// deployPHPAppWithLogging 部署PHP应用（带日志）
func (gs *GitServer) deployPHPAppWithLogging(app *GitApp, deployLogger *DeployLogger) error {
	deployLogger.WriteLog("info", "php", "开始PHP应用部署流程")

	// 复制文件到Web目录
	webDir := filepath.Join(gs.config.Runners.Git.ReposDir, "web", app.Name)
	if err := os.MkdirAll(webDir, 0755); err != nil {
		return fmt.Errorf("创建Web目录失败: %w", err)
	}

	if err := gs.runCommandWithLogging("", deployLogger, "cp", "-r", app.GitPath+"/*", webDir); err != nil {
		return fmt.Errorf("复制PHP文件失败: %w", err)
	}

	gs.mutex.Lock()
	app.Status = "running"
	gs.mutex.Unlock()

	deployLogger.WriteLog("info", "php", "PHP应用部署完成")
	return nil
}

// deployStaticAppWithLogging 部署静态应用（带日志）
func (gs *GitServer) deployStaticAppWithLogging(app *GitApp, deployLogger *DeployLogger) error {
	deployLogger.WriteLog("info", "static", "开始静态应用部署流程")

	// 复制文件到Web目录
	webDir := filepath.Join(gs.config.Runners.Git.ReposDir, "web", app.Name)
	if err := os.MkdirAll(webDir, 0755); err != nil {
		return fmt.Errorf("创建Web目录失败: %w", err)
	}

	if err := gs.runCommandWithLogging("", deployLogger, "cp", "-r", app.GitPath+"/*", webDir); err != nil {
		return fmt.Errorf("复制静态文件失败: %w", err)
	}

	gs.mutex.Lock()
	app.Status = "running"
	gs.mutex.Unlock()

	deployLogger.WriteLog("info", "static", "静态应用部署完成")
	return nil
}

// runCommandWithLogging 执行命令并记录日志
func (gs *GitServer) runCommandWithLogging(workDir string, deployLogger *DeployLogger, command string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(gs.serverConfig.BuildTimeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)
	if workDir != "" {
		cmd.Dir = workDir
	}

	// 记录命令
	deployLogger.WriteCommand(command, args)

	// 捕获输出
	output, err := cmd.CombinedOutput()
	if err != nil {
		deployLogger.WriteCommandOutput(string(output))
		deployLogger.WriteError(fmt.Errorf("命令执行失败: %s %v", command, args))
		return err
	}

	deployLogger.WriteCommandOutput(string(output))
	return nil
}

// startNodeJSAppWithLogging 启动Node.js应用（带日志）
func (gs *GitServer) startNodeJSAppWithLogging(app *GitApp, deployLogger *DeployLogger) error {
	// 检查启动脚本
	startCommand := "node server.js"
	if gs.hasStartScript(app.GitPath) {
		startCommand = "npm start"
	}

	deployLogger.WriteLog("info", "nodejs", fmt.Sprintf("启动命令: %s", startCommand))

	// 启动应用进程
	return gs.startAppProcessWithLogging(app, startCommand, deployLogger)
}

// startPythonAppWithLogging 启动Python应用（带日志）
func (gs *GitServer) startPythonAppWithLogging(app *GitApp, deployLogger *DeployLogger) error {
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
		return fmt.Errorf("未找到Python启动文件")
	}

	startCommand := fmt.Sprintf("python %s", startFile)
	deployLogger.WriteLog("info", "python", fmt.Sprintf("启动命令: %s", startCommand))

	// 启动应用进程
	return gs.startAppProcessWithLogging(app, startCommand, deployLogger)
}

// startGoAppWithLogging 启动Go应用（带日志）
func (gs *GitServer) startGoAppWithLogging(app *GitApp, deployLogger *DeployLogger) error {
	startCommand := "./app"
	deployLogger.WriteLog("info", "go", fmt.Sprintf("启动命令: %s", startCommand))

	// 启动应用进程
	return gs.startAppProcessWithLogging(app, startCommand, deployLogger)
}

// startAppProcessWithLogging 启动应用进程（带日志）
func (gs *GitServer) startAppProcessWithLogging(app *GitApp, command string, deployLogger *DeployLogger) error {
	// 这里应该实现完整的进程管理
	// 当前简化实现：记录启动信息

	gs.mutex.Lock()
	app.Status = "running"
	app.StartCommand = command
	gs.mutex.Unlock()

	deployLogger.WriteLog("info", "process", fmt.Sprintf("应用进程已启动: %s", command))
	gs.logger.Infof("应用 %s 已启动，命令: %s", app.Name, command)

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
// 注意：此方法假设调用者已经持有锁
func (gs *GitServer) isPortInUse(port int) bool {
	// 简化实现：检查所有应用是否使用了该端口
	// 不需要加锁，因为调用者（CreateApp）已经持有 gs.mutex.Lock()
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

// generateGitURL 生成Git推送地址
func (gs *GitServer) generateGitURL(appName string) string {
	// 使用域名后缀作为主机名，如果没有则使用localhost
	hostname := gs.serverConfig.DomainSuffix
	if hostname == "" {
		hostname = "localhost"
	}

	// SSH端口
	port := gs.serverConfig.Port
	if port == 22 {
		// 默认SSH端口，不需要在URL中指定
		return fmt.Sprintf("%s@%s:%s.git", gs.sshUser, hostname, appName)
	}

	// 非标准SSH端口，使用ssh://协议格式
	return fmt.Sprintf("ssh://%s@%s:%d/%s.git", gs.sshUser, hostname, port, appName)
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

	// 自动添加代理规则
	if app.Domain != "" && app.Port > 0 {
		if err := gs.addProxyRuleForApp(app); err != nil {
			gs.logger.Errorf("为应用 %s 添加代理规则失败: %v", app.Name, err)
		} else {
			gs.logger.Infof("已为应用 %s 自动添加代理规则: %s -> 127.0.0.1:%d", app.Name, app.Domain, app.Port)
		}
	}

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
	// 确保目录存在
	if err := os.MkdirAll(gs.config.Runners.Git.ReposDir, 0755); err != nil {
		return fmt.Errorf("创建应用目录失败: %w", err)
	}

	appsFile := filepath.Join(gs.config.Runners.Git.ReposDir, "apps.json")
	data, err := json.MarshalIndent(gs.apps, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化应用失败: %w", err)
	}

	if err := os.WriteFile(appsFile, data, 0644); err != nil {
		return fmt.Errorf("写入应用文件失败: %w", err)
	}

	gs.logger.Infof("应用数据已保存到 %s (%d 个应用)", appsFile, len(gs.apps))
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
	gitUser, err := user.Lookup(gs.sshUser)
	if err != nil {
		gs.logger.Warnf("SSH用户 %s 不存在，请手动创建: %v", gs.sshUser, err)
		return nil
	}

	if err := os.MkdirAll(gs.sshKeysDir, 0700); err != nil {
		return fmt.Errorf("创建 SSH 目录失败: %w", err)
	}

	// 解析UID和GID
	uid, _ := strconv.Atoi(gitUser.Uid)
	gid, _ := strconv.Atoi(gitUser.Gid)

	if err := os.Chown(gs.sshKeysDir, uid, gid); err != nil {
		gs.logger.Warnf("设置 SSH 目录权限失败: %v", err)
	}

	if _, err := os.Stat(gs.authorizedKeysFile); os.IsNotExist(err) {
		if err := os.WriteFile(gs.authorizedKeysFile, []byte{}, 0600); err != nil {
			return fmt.Errorf("创建 authorized_keys 文件失败: %w", err)
		}
		os.Chown(gs.authorizedKeysFile, uid, gid)
	}

	sshdConfig := fmt.Sprintf("Match User %s\n  ForceCommand git-shell -c \"$SSH_ORIGINAL_COMMAND\"\n  AllowTcpForwarding no\n  X11Forwarding no\n", gs.sshUser)
	configPath := filepath.Join(gs.sshConfigDir, "sslcat_git.conf")
	os.WriteFile(configPath, []byte(sshdConfig), 0644)

	// 创建 git-shell-commands 目录
	gitCmdDir := filepath.Join(gs.sshHomeDir, "git-shell-commands")
	if err := os.MkdirAll(gitCmdDir, 0755); err == nil {
		os.Chown(gitCmdDir, uid, gid)
		noLoginScript := filepath.Join(gitCmdDir, "no-interactive-login")
		os.WriteFile(noLoginScript, []byte("#!/bin/sh\necho 'Interactive shell disabled.'\n"), 0755)
		os.Chown(noLoginScript, uid, gid)
	}

	gs.logger.Info("SSH 用户配置完成")
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
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"` // "info" | "warn" | "error" | "debug"
	Message   string                 `json:"message"`
	Source    string                 `json:"source"` // "git" | "build" | "deploy" | "run" | "deploy_status"
	AppName   string                 `json:"app_name"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"` // 额外元数据
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

	// 设置 receive-pack 服务脚本
	generatePath := filepath.Join(app.GitPath, "hooks")
	if err := os.MkdirAll(generatePath, 0755); err != nil {
		return fmt.Errorf("创建 hooks 目录失败: %w", err)
	}

	preReceivePath := filepath.Join(generatePath, "pre-receive")
	if err := os.WriteFile(preReceivePath, []byte(gs.generatePreReceiveHook(app)), 0755); err != nil {
		return fmt.Errorf("创建 pre-receive 钩子失败: %w", err)
	}

	updatePath := filepath.Join(generatePath, "update")
	if err := os.WriteFile(updatePath, []byte(gs.generateUpdateHook(app)), 0755); err != nil {
		return fmt.Errorf("创建 update 钩子失败: %w", err)
	}

	postReceivePath := filepath.Join(generatePath, "post-receive")
	if err := os.WriteFile(postReceivePath, []byte(gs.generatePostReceiveHook(app)), 0755); err != nil {
		return fmt.Errorf("创建 post-receive 钩子失败: %w", err)
	}

	receivePackPath := filepath.Join(generatePath, "receive-pack")
	if err := os.WriteFile(receivePackPath, []byte(gs.generateReceivePackWrapper(app)), 0755); err != nil {
		return fmt.Errorf("创建 receive-pack 脚本失败: %w", err)
	}

	serviceFile := filepath.Join(app.GitPath, "config")
	configContent := fmt.Sprintf("[core]\n\trepositoryformatversion = 0\n\tbare = true\n\tlogallrefupdates = true\n\treceivepack = %s\n", receivePackPath)
	if err := os.WriteFile(serviceFile, []byte(configContent), 0644); err != nil {
		gs.logger.Warnf("写入仓库配置失败: %v", err)
	}

	gs.logger.Infof("Git 钩子已设置: %s", app.Name)
	return nil
}

// generatePreReceiveHook 生成 pre-receive 钩子内容
func (gs *GitServer) generatePreReceiveHook(app *GitApp) string {
	return fmt.Sprintf(`#!/bin/bash
# SSLcat Git Pre-Receive Hook
# 应用: %s
# 功能: 推送前的验证和权限检查

set -e

APP_NAME="%s"
LOGS_DIR="%s"
BARE_REPO="%s"

# 记录推送信息
while read oldrev newrev refname; do
    echo "[$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] [info] [git] Pre-receive: $oldrev -> $newrev ($refname)" >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log"
    
    # 检查推送大小（限制为100MB）
    if [ "$oldrev" != "0000000000000000000000000000000000000000" ]; then
        SIZE=$(git --git-dir="$BARE_REPO" rev-list --objects $oldrev..$newrev | 
               git --git-dir="$BARE_REPO" cat-file --batch-check='%%(objectsize)' | 
               awk '{sum+=$1} END {print sum}')
        MAX_SIZE=$((100*1024*1024)) # 100MB
        if [ "$SIZE" -gt "$MAX_SIZE" ]; then
            echo "Error: Push size ($SIZE bytes) exceeds limit ($MAX_SIZE bytes)" >&2
            echo "[$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] [error] [git] Push rejected: size limit exceeded" >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log"
            exit 1
        fi
    fi
done

echo "[$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] [info] [git] Pre-receive checks passed" >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log"
exit 0
`, app.Name, app.Name, app.LogsDir, app.BareRepo)
}

// generateUpdateHook 生成 update 钩子内容
func (gs *GitServer) generateUpdateHook(app *GitApp) string {
	return fmt.Sprintf(`#!/bin/bash
# SSLcat Git Update Hook
# 应用: %s
# 功能: 分支更新验证

set -e

APP_NAME="%s"
LOGS_DIR="%s"
REF_NAME=$1
OLD_REV=$2
NEW_REV=$3

# 记录分支更新
echo "[$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] [info] [git] Update: $REF_NAME from $OLD_REV to $NEW_REV" >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log"

# 这里可以添加分支保护逻辑
# 例如：禁止删除master分支、要求特定格式的提交消息等

exit 0
`, app.Name, app.Name, app.LogsDir)
}

// generatePostReceiveHook 生成 post-receive 钩子内容
func (gs *GitServer) generatePostReceiveHook(app *GitApp) string {
	// 获取当前可执行文件路径
	execPath, err := os.Executable()
	if err != nil {
		execPath = "/usr/local/bin/sslcat"
	}

	return fmt.Sprintf(`#!/bin/bash
# SSLcat Git Post-Receive Hook
# 应用: %s
# 功能: 推送后自动部署

set -e

APP_NAME="%s"
REPO_DIR="%s"
BARE_REPO="%s"
LOGS_DIR="%s"
SSLCAT_BIN="%s"

# 记录推送信息
while read oldrev newrev refname; do
    echo "[$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] [info] [git] Post-receive: $oldrev -> $newrev ($refname)" >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log"
    
    # 获取提交信息
    if [ "$oldrev" != "0000000000000000000000000000000000000000" ]; then
        COMMIT_MSG=$(git --git-dir="$BARE_REPO" log -1 --pretty=format:"%%s" $newrev)
    else
        COMMIT_MSG="Initial commit"
    fi
    
    echo "[$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] [info] [git] Commit: $newrev - $COMMIT_MSG" >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log"
    
    # 更新工作目录
    if [ ! -d "$REPO_DIR/.git" ]; then
        echo "[$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] [info] [git] Cloning repository to work directory..." >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log"
        git clone "$BARE_REPO" "$REPO_DIR" >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log" 2>&1
    else
        echo "[$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] [info] [git] Updating work directory..." >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log"
        cd "$REPO_DIR"
        git fetch origin >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log" 2>&1
        git reset --hard $newrev >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log" 2>&1
    fi
    
    # 触发部署 - 通过HTTP API调用SSLcat内部部署流程
    echo "[$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] [info] [git] Triggering deployment..." >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log"
    
    # 这里调用内部部署API或通过Unix socket通信
    # 简化实现：创建一个标记文件，让SSLcat主进程检测并触发部署
    DEPLOY_TRIGGER="/tmp/sslcat-deploy-$APP_NAME-$(date +%%s)"
    echo "$newrev|$refname|$COMMIT_MSG" > "$DEPLOY_TRIGGER"
    
    echo "[$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] [info] [git] Post-receive completed" >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log"
done

exit 0
`, app.Name, app.Name, app.RepoDir, app.BareRepo, app.LogsDir, execPath)
}

// generateReceivePackWrapper 生成 receive-pack 包装脚本
func (gs *GitServer) generateReceivePackWrapper(app *GitApp) string {
	return fmt.Sprintf(`#!/bin/bash
# SSLcat Git Receive-Pack Wrapper
# 应用: %s
# 功能: Git接收包装器，记录推送信息

APP_NAME="%s"
BARE_REPO="%s"
LOGS_DIR="%s"

# 记录推送开始
echo "[$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] [info] [git] Receive-pack started for $APP_NAME" >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log"

# 记录环境信息
echo "[$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] [info] [git] SSH_CONNECTION: $SSH_CONNECTION" >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log"
echo "[$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] [info] [git] SSH_CLIENT: $SSH_CLIENT" >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log"

# 执行真正的 git-receive-pack
exec git-receive-pack "$BARE_REPO" 2>> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log"
`, app.Name, app.Name, app.BareRepo, app.LogsDir)
}

// initGitRepo 初始化 Git 仓库
func (gs *GitServer) initGitRepo(app *GitApp) error {
	// 创建应用目录
	if err := os.MkdirAll(app.GitPath, 0755); err != nil {
		return fmt.Errorf("创建应用目录失败: %w", err)
	}

	if err := os.MkdirAll(app.RepoDir, 0755); err != nil {
		return fmt.Errorf("创建工作仓库目录失败: %w", err)
	}

	bearRepo := app.BareRepo
	if err := os.MkdirAll(bearRepo, 0755); err != nil {
		return fmt.Errorf("创建裸仓库目录失败: %w", err)
	}

	// 初始化 Git 仓库
	cmd := exec.Command("git", "init", "--bare", bearRepo)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("初始化 Git 仓库失败: %w", err)
	}

	// 设置 Git 配置
	cmd = exec.Command("git", "config", "core.bare", "true")
	cmd.Dir = bearRepo
	if err := cmd.Run(); err != nil {
		gs.logger.Warnf("设置 Git 配置失败: %v", err)
	}

	// 初始克隆到工作目录
	cmd = exec.Command("git", "clone", bearRepo, app.RepoDir)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("克隆裸仓库失败: %w", err)
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
// GetLogStreamManager 获取日志流管理器
func (gs *GitServer) GetLogStreamManager() *LogStreamManager {
	return gs.logStreamManager
}

// GetDockerRegistry 获取Docker Registry
func (gs *GitServer) GetDockerRegistry() *DockerRegistry {
	return gs.dockerRegistry
}

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

// addProxyRuleForApp 为应用自动添加代理规则
func (gs *GitServer) addProxyRuleForApp(app *GitApp) error {
	// 检查代理规则是否已存在
	for i, rule := range gs.config.Proxy.Rules {
		// 如果已经存在该域名的规则
		if rule.Domain == app.Domain {
			// 如果是Git部署服务管理的规则，更新它
			if rule.ManagedByGitDeploy && rule.GitDeployAppName == app.Name {
				gs.config.Proxy.Rules[i].Target = "127.0.0.1"
				gs.config.Proxy.Rules[i].Port = app.Port
				gs.config.Proxy.Rules[i].Enabled = true
				gs.logger.Infof("更新应用 %s 的代理规则", app.Name)
				return gs.config.Save(gs.config.ConfigFile)
			}
			// 如果是手动创建的规则，不覆盖
			gs.logger.Warnf("域名 %s 已存在代理规则，跳过自动添加", app.Domain)
			return nil
		}
	}

	// 创建新的代理规则
	rule := config.ProxyRule{
		Domain:             app.Domain,
		Target:             "127.0.0.1",
		Port:               app.Port,
		Enabled:            true,
		SSLOnly:            app.DeployConfig.SSL.Enabled,
		ManagedByGitDeploy: true,
		GitDeployAppName:   app.Name,
		GitDeployAppID:     app.Name, // 使用应用名称作为ID
	}

	// 添加代理规则
	gs.config.Proxy.Rules = append(gs.config.Proxy.Rules, rule)

	// 保存配置
	if err := gs.config.Save(gs.config.ConfigFile); err != nil {
		return fmt.Errorf("保存配置失败: %w", err)
	}

	gs.logger.Infof("已为应用 %s 添加代理规则: %s -> 127.0.0.1:%d", app.Name, app.Domain, app.Port)
	return nil
}

// removeProxyRuleForApp 删除应用的代理规则
func (gs *GitServer) removeProxyRuleForApp(app *GitApp) error {
	// 查找并删除该应用的代理规则
	for i, rule := range gs.config.Proxy.Rules {
		if rule.ManagedByGitDeploy && rule.GitDeployAppName == app.Name {
			// 删除规则
			gs.config.Proxy.Rules = append(gs.config.Proxy.Rules[:i], gs.config.Proxy.Rules[i+1:]...)

			// 保存配置
			if err := gs.config.Save(gs.config.ConfigFile); err != nil {
				return fmt.Errorf("保存配置失败: %w", err)
			}

			gs.logger.Infof("已删除应用 %s 的代理规则", app.Name)
			return nil
		}
	}

	gs.logger.Infof("应用 %s 没有关联的代理规则", app.Name)
	return nil
}

// ==================== 推送记录管理 ====================

// AddPushRecord 添加推送记录
func (gs *GitServer) AddPushRecord(appName string, record PushRecord) error {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	app, exists := gs.apps[appName]
	if !exists {
		return fmt.Errorf("应用 %s 不存在", appName)
	}

	// 添加推送记录
	if app.PushHistory == nil {
		app.PushHistory = make([]PushRecord, 0)
	}
	app.PushHistory = append(app.PushHistory, record)

	// 限制历史记录数量（保留最近100条）
	if len(app.PushHistory) > 100 {
		app.PushHistory = app.PushHistory[len(app.PushHistory)-100:]
	}

	// 保存应用信息
	if err := gs.saveApps(); err != nil {
		return fmt.Errorf("保存推送记录失败: %w", err)
	}

	return nil
}

// GetPushHistory 获取推送历史
func (gs *GitServer) GetPushHistory(appName string, limit int) ([]PushRecord, error) {
	gs.mutex.RLock()
	defer gs.mutex.RUnlock()

	app, exists := gs.apps[appName]
	if !exists {
		return nil, fmt.Errorf("应用 %s 不存在", appName)
	}

	history := app.PushHistory
	if history == nil {
		return []PushRecord{}, nil
	}

	// 如果指定了限制，返回最后的N条记录
	if limit > 0 && len(history) > limit {
		return history[len(history)-limit:], nil
	}

	return history, nil
}

// UpdatePushRecordStatus 更新推送记录状态
func (gs *GitServer) UpdatePushRecordStatus(appName, pushID, status string, errorMsg string) error {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	app, exists := gs.apps[appName]
	if !exists {
		return fmt.Errorf("应用 %s 不存在", appName)
	}

	// 查找并更新推送记录
	for i := range app.PushHistory {
		if app.PushHistory[i].ID == pushID {
			app.PushHistory[i].Status = status
			app.PushHistory[i].EndTime = time.Now()
			app.PushHistory[i].Duration = time.Since(app.PushHistory[i].StartTime).Milliseconds()
			if errorMsg != "" {
				app.PushHistory[i].ErrorMessage = errorMsg
			}

			// 保存应用信息
			if err := gs.saveApps(); err != nil {
				return fmt.Errorf("保存推送记录失败: %w", err)
			}

			return nil
		}
	}

	return fmt.Errorf("推送记录 %s 不存在", pushID)
}

// ==================== SSH 密钥绑定管理 ====================

// BindKeyToApp 绑定SSH密钥到应用
func (gs *GitServer) BindKeyToApp(appName, keyFingerprint string) error {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	app, exists := gs.apps[appName]
	if !exists {
		return fmt.Errorf("应用 %s 不存在", appName)
	}

	// 检查密钥是否已绑定
	for _, key := range app.AllowedKeys {
		if key == keyFingerprint {
			return fmt.Errorf("密钥 %s 已绑定到应用 %s", keyFingerprint, appName)
		}
	}

	// 添加密钥绑定
	if app.AllowedKeys == nil {
		app.AllowedKeys = make([]string, 0)
	}
	app.AllowedKeys = append(app.AllowedKeys, keyFingerprint)

	// 保存应用信息
	if err := gs.saveApps(); err != nil {
		return fmt.Errorf("保存密钥绑定失败: %w", err)
	}

	gs.logger.Infof("已绑定密钥 %s 到应用 %s", keyFingerprint, appName)
	return nil
}

// UnbindKeyFromApp 解绑SSH密钥
func (gs *GitServer) UnbindKeyFromApp(appName, keyFingerprint string) error {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	app, exists := gs.apps[appName]
	if !exists {
		return fmt.Errorf("应用 %s 不存在", appName)
	}

	// 查找并删除密钥绑定
	for i, key := range app.AllowedKeys {
		if key == keyFingerprint {
			app.AllowedKeys = append(app.AllowedKeys[:i], app.AllowedKeys[i+1:]...)

			// 保存应用信息
			if err := gs.saveApps(); err != nil {
				return fmt.Errorf("保存密钥绑定失败: %w", err)
			}

			gs.logger.Infof("已解绑密钥 %s 从应用 %s", keyFingerprint, appName)
			return nil
		}
	}

	return fmt.Errorf("密钥 %s 未绑定到应用 %s", keyFingerprint, appName)
}

// CheckPushPermission 检查推送权限
func (gs *GitServer) CheckPushPermission(appName, keyFingerprint string) bool {
	gs.mutex.RLock()
	defer gs.mutex.RUnlock()

	app, exists := gs.apps[appName]
	if !exists {
		return false
	}

	// 如果应用没有设置密钥限制，则允许所有已添加的密钥推送
	if len(app.AllowedKeys) == 0 {
		return true
	}

	// 检查密钥是否在允许列表中
	for _, key := range app.AllowedKeys {
		if key == keyFingerprint {
			return true
		}
	}

	return false
}

// ==================== Git 推送处理增强 ====================

// ProcessGitPush 处理 Git 推送并创建应用（如果不存在）
func (gs *GitServer) ProcessGitPush(appName, keyFingerprint, refName, oldRev, newRev string) error {
	gs.mutex.Lock()
	app, exists := gs.apps[appName]
	gs.mutex.Unlock()

	// 如果应用不存在，自动创建
	if !exists {
		gs.logger.Infof("应用 %s 不存在，自动创建", appName)
		var err error
		app, err = gs.CreateApp(appName)
		if err != nil {
			return fmt.Errorf("自动创建应用失败: %w", err)
		}
	}

	// 检查推送权限
	if !gs.CheckPushPermission(appName, keyFingerprint) {
		return fmt.Errorf("SSH密钥 %s 没有权限推送到应用 %s", keyFingerprint, appName)
	}

	// 创建推送记录
	pushID := fmt.Sprintf("push_%d", time.Now().Unix())
	pushRecord := PushRecord{
		ID:         pushID,
		AppName:    appName,
		PusherKey:  keyFingerprint,
		CommitHash: newRev,
		RefName:    refName,
		Status:     "pending",
		StartTime:  time.Now(),
	}

	// 获取提交消息
	if newRev != "0000000000000000000000000000000000000000" {
		cmd := exec.Command("git", "--git-dir="+app.BareRepo, "log", "-1", "--pretty=format:%s", newRev)
		if output, err := cmd.Output(); err == nil {
			pushRecord.CommitMessage = string(output)
		}
	}

	// 添加推送记录
	if err := gs.AddPushRecord(appName, pushRecord); err != nil {
		gs.logger.Warnf("添加推送记录失败: %v", err)
	}

	// 触发部署
	go gs.processGitPushWithRecord(app, pushID, pushRecord)

	gs.logger.Infof("开始处理应用 %s 的 Git 推送，Push ID: %s", appName, pushID)
	return nil
}

// processGitPushWithRecord 处理推送并更新记录
func (gs *GitServer) processGitPushWithRecord(app *GitApp, pushID string, pushRecord PushRecord) {
	// 使用现有的 processGitPush 逻辑
	gs.processGitPush(app, nil)

	// 更新推送记录状态
	if app.Status == "running" {
		gs.UpdatePushRecordStatus(app.Name, pushID, "success", "")
	} else if app.Status == "failed" {
		gs.UpdatePushRecordStatus(app.Name, pushID, "failed", "部署失败，请查看日志")
	}
}

// WatchDeployTriggers 监听部署触发文件
func (gs *GitServer) WatchDeployTriggers() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// 扫描 /tmp 目录下的部署触发文件
		pattern := "/tmp/sslcat-deploy-*"
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}

		for _, triggerFile := range matches {
			// 读取触发文件
			data, err := os.ReadFile(triggerFile)
			if err != nil {
				continue
			}

			// 解析触发信息
			parts := strings.Split(string(data), "|")
			if len(parts) < 2 {
				os.Remove(triggerFile)
				continue
			}

			// 提取应用名称
			filename := filepath.Base(triggerFile)
			appName := strings.TrimPrefix(filename, "sslcat-deploy-")
			appName = appName[:strings.LastIndex(appName, "-")]

			newRev := parts[0]
			refName := parts[1]
			commitMsg := ""
			if len(parts) > 2 {
				commitMsg = parts[2]
			}

			// 触发部署
			go gs.ProcessGitPush(appName, "system", refName, "", newRev)

			// 删除触发文件
			os.Remove(triggerFile)

			gs.logger.Infof("检测到部署触发: 应用=%s, 提交=%s, 分支=%s, 消息=%s",
				appName, newRev, refName, commitMsg)
		}
	}
}

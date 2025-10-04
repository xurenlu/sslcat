package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	"github.com/xurenlu/sslcat/internal/i18n"
	"github.com/xurenlu/sslcat/internal/notification"
)

// GitServer Git 服务器管理器 - 类似 Dokku/Heroku 的部署平台
type GitServer struct {
	config *config.Config
	apps   map[string]*GitApp // 应用列表，key 是应用名称
	mutex  sync.RWMutex
	logger *logrus.Logger

	// 翻译器
	translator *i18n.Translator

	// Git 服务器配置
	serverConfig *GitServerConfig

	// WebHook 配置
	webhookSecret string
	webhookPort   int

	// SSH 配置
	sshUser                   string // SSH 用户名，默认为 "git"
	sshHomeDir                string // SSH 用户主目录
	sshKeysDir                string // SSH 密钥目录
	authorizedKeysFile        string // authorized_keys 文件路径
	managedSSHDir             string // 受管 SSH 密钥目录（回退）
	managedAuthorizedKeysFile string // 受管目录下的 authorized_keys 文件
	useManagedKeys            bool   // 是否启用受管目录
	gitCmdDir                 string // git-shell-commands 目录
	sshConfigDir              string // sshd 配置目录
	uid                       int
	gid                       int

	// 日志管理器
	logManager       *LogManager
	logStreamManager *LogStreamManager

	// Docker Registry
	dockerRegistry *DockerRegistry

	// Builder Registry
	builderRegistry *BuilderRegistry

	// 部署数据库
	deployDB *DeployDatabase

	// 通知管理器
	notificationManager *notification.NotificationManager
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

	// 配置变更标记
	PendingRestart bool `json:"pending_restart,omitempty"` // 是否有未应用的配置变更需要重启

	// 容器信息（蓝绿部署）
	ContainerID     string `json:"container_id,omitempty"`     // 当前活跃容器ID
	OldContainerID  string `json:"old_container_id,omitempty"` // 旧容器ID（等待停止）
	ContainerStatus string `json:"container_status,omitempty"` // 容器状态
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
func NewGitServer(cfg *config.Config, translator *i18n.Translator) *GitServer {
	// 默认服务器配置
	defaultConfig := &GitServerConfig{
		Enabled:         true,
		Port:            22,
		Webhook:         "",
		DefaultBranch:   "main",
		DomainSuffix:    "localhost",
		PortRange:       [2]int{8000, 9000},
		WelcomeMessage:  translator.T("git_server.welcome_message"),
		AutoSSL:         true,
		SSLEmail:        "",
		DefaultStrategy: "auto",
		BuildTimeout:    300,
		AutoDomain:      true,
	}

	// SSH 配置 - 使用标准的用户 home 目录
	sshUser := "git"
	// 使用标准的 /home/git/.ssh 目录，符合常规实践
	sshHomeDir := "/home/git"
	sshKeysDir := filepath.Join(sshHomeDir, ".ssh")
	authorizedKeysFile := filepath.Join(sshKeysDir, "authorized_keys")
	runnerDataDir := filepath.Dir(cfg.Runners.Git.ReposDir)
	managedSSHDir := filepath.Join(runnerDataDir, "keys", "ssh")
	if absPath, err := filepath.Abs(managedSSHDir); err == nil {
		managedSSHDir = absPath
	}
	managedAuthorizedKeysFile := filepath.Join(managedSSHDir, "authorized_keys")
	useManagedKeys := false
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

	// 初始化部署数据库
	dataDir := filepath.Dir(cfg.Runners.Git.ReposDir)
	deployDB, err := NewDeployDatabase(dataDir)
	if err != nil {
		logrus.Errorf("初始化部署数据库失败: %v", err)
		deployDB = nil // 继续运行，但没有数据库支持
	}

	// 初始化通知管理器 - 从配置文件读取
	var notificationMgr *notification.NotificationManager
	if cfg.Notification.Enabled {
		notificationMgr = notification.NewNotificationManagerFromConfig(cfg.Notification)
		logrus.Infof("通知管理器已从配置文件初始化")
	} else {
		// 如果配置文件未启用，尝试从环境变量读取（向后兼容）
		notificationMgr = notification.NewNotificationManager()
		logrus.Infof("通知管理器已从环境变量初始化（向后兼容）")
	}

	gs := &GitServer{
		config:                    cfg,
		apps:                      make(map[string]*GitApp),
		logger:                    logrus.WithField("component", "git_server").Logger,
		translator:                translator,
		serverConfig:              defaultConfig,
		sshUser:                   sshUser,
		sshHomeDir:                sshHomeDir,
		sshKeysDir:                sshKeysDir,
		authorizedKeysFile:        authorizedKeysFile,
		managedSSHDir:             managedSSHDir,
		managedAuthorizedKeysFile: managedAuthorizedKeysFile,
		useManagedKeys:            useManagedKeys,
		sshConfigDir:              sshConfigDir,
		logManager:                logManager,
		logStreamManager:          logStreamManager,
		dockerRegistry:            dockerRegistry,
		deployDB:                  deployDB,
		notificationManager:       notificationMgr,
	}

	// 初始化 Builder Registry
	gs.builderRegistry = gs.InitBuilders()

	// 加载持久化的应用
	if err := gs.loadApps(); err != nil {
		gs.logger.Warnf(gs.translator.T("git_server.load_apps_failed")+": %v", err)
	}

	// 加载 Docker Registry 配置
	if err := gs.loadDockerRegistryConfig(); err != nil {
		gs.logger.Warnf("加载 Docker Registry 配置失败: %v", err)
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
		gs.logger.Info(gs.translator.T("git_server.not_enabled"))
		return nil
	}

	// 检查 Git 是否可用
	if err := gs.checkGit(); err != nil {
		return fmt.Errorf(gs.translator.T("git_server.unavailable")+": %w", err)
	}

	// 尝试自动创建 git 用户（如果不存在）
	if err := gs.createGitUser(); err != nil {
		gs.logger.Warnf(gs.translator.T("git_server.create_user_failed")+": %v，如果需要请手动创建: sudo useradd -r -s /bin/bash -m -d /home/git git", err)
	}

	// 设置 SSH 用户和目录
	if err := gs.setupSSHUser(); err != nil {
		gs.logger.Warnf(gs.translator.T("git_server.setup_ssh_failed")+": %v", err)
	}

	// 自动安装 git hook wrapper 脚本
	if err := gs.installGitHook(); err != nil {
		gs.logger.Warnf("自动安装 git hook wrapper 脚本失败: %v", err)
	}

	// 创建应用目录
	if err := os.MkdirAll(gs.config.Runners.Git.ReposDir, 0755); err != nil {
		return fmt.Errorf(gs.translator.T("git_server.create_app_dir_failed")+": %w", err)
	}

	// 加载现有应用
	if err := gs.loadApps(); err != nil {
		gs.logger.Warnf(gs.translator.T("git_server.load_app_failed")+": %v", err)
	}

	// 启动清理协程
	if gs.config.Runners.Git.AutoCleanup {
		go gs.cleanupRoutine()
	}

	// 启动部署触发监听协程
	go gs.WatchDeployTriggers()

	// 输出关键路径信息
	gs.logger.Infof("authorized_keys 文件路径: %s", gs.authorizedKeysFile)
	gs.logger.Infof("SSH 密钥目录: %s", gs.sshKeysDir)

	gs.logger.Info(gs.translator.T("git_server.started"))
	return nil
}

// Stop 停止 Git 服务器
func (gs *GitServer) Stop() {
	gs.logger.Info(gs.translator.T("git_server.stopped"))
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

	// 同步更新主配置文件中的 runners.git.enabled
	// 这样重启服务后配置才会生效
	gs.config.Runners.Git.Enabled = config.Enabled

	// 保存主配置文件
	if err := gs.config.Save(gs.config.ConfigFile); err != nil {
		gs.logger.Warnf("保存主配置文件失败: %v", err)
		// 继续执行，不中断流程
	} else {
		gs.logger.Info("主配置文件已更新")
	}

	// 保存 Git Server 内部配置到文件
	if err := gs.saveServerConfig(); err != nil {
		return fmt.Errorf(gs.translator.T("git_server.save_config_failed")+": %w", err)
	}

	gs.logger.Info(gs.translator.T("git_server.config_updated"))
	return nil
}

// ==================== 应用管理 ====================

// CreateApp 创建新应用
func (gs *GitServer) CreateApp(appName string, autoSSL bool) (*GitApp, error) {
	gs.logger.Infof("🚀 %s: %s (AutoSSL: %v)", gs.translator.T("git_server.creating_app"), appName, autoSSL)
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	// 检查应用是否已存在
	if _, exists := gs.apps[appName]; exists {
		gs.logger.Warnf(gs.translator.T("git_server.app_exists")+" %s", appName)
		return nil, fmt.Errorf(gs.translator.T("git_server.app_exists")+" %s", appName)
	}

	// 分配端口
	gs.logger.Debugf(gs.translator.T("git_server.allocating_port")+" %s...", appName)
	gs.logger.Debugf(gs.translator.T("git_server.port_range")+": %d-%d", gs.serverConfig.PortRange[0], gs.serverConfig.PortRange[1])
	gs.logger.Debugf(gs.translator.T("git_server.current_apps")+": %d", len(gs.apps))
	port, err := gs.allocatePort()
	if err != nil {
		gs.logger.Errorf(gs.translator.T("git_server.port_allocation_failed")+": %v", err)
		return nil, fmt.Errorf(gs.translator.T("git_server.port_allocation_failed")+": %w", err)
	}
	gs.logger.Infof("  ✓ %s: %d", gs.translator.T("git_server.port_allocated"), port)

	// 生成域名
	domain := gs.generateDomain(appName)
	gs.logger.Infof("  ✓ %s: %s", gs.translator.T("git_server.domain_generated"), domain)

	// 生成Git推送地址
	gitURL := gs.generateGitURL(appName)
	gs.logger.Infof("  ✓ %s: %s", gs.translator.T("git_server.git_url"), gitURL)

	// 创建应用目录
	appPath := filepath.Join(gs.config.Runners.Git.ReposDir, appName)
	gs.logger.Infof("  %s: %s", gs.translator.T("git_server.creating_app_dir"), appPath)
	if err := os.MkdirAll(appPath, 0755); err != nil {
		gs.logger.Errorf(gs.translator.T("git_server.create_app_dir_failed")+": %v", err)
		return nil, fmt.Errorf(gs.translator.T("git_server.create_app_dir_failed")+": %w", err)
	}
	gs.logger.Infof("  ✓ %s", gs.translator.T("git_server.app_dir_created"))

	// 初始化 Git 仓库
	gitPath := filepath.Join(appPath, "git")

	// 创建日志目录
	logsDir := filepath.Join(appPath, "logs")
	gs.logger.Debugf("  创建日志目录: %s", logsDir)
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		gs.logger.Errorf(gs.translator.T("git_server.creating_logs_dir")+": %v", err)
		return nil, fmt.Errorf(gs.translator.T("git_server.creating_logs_dir")+": %w", err)
	}
	gs.logger.Infof("  ✓ %s", gs.translator.T("git_server.logs_dir_created"))

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
				Enabled: autoSSL, // 使用传入的参数
				Email:   gs.serverConfig.SSLEmail,
			},
		},
	}

	gs.logger.Infof("  ✓ SSL 配置: Enabled=%v, Email=%s", autoSSL, gs.serverConfig.SSLEmail)

	gs.apps[appName] = app
	gs.logger.Infof("  ✓ 应用对象已添加到内存 (当前共 %d 个应用)", len(gs.apps))

	// 初始化 Git 仓库（必须在设置钩子之前）
	gs.logger.Debugf("  初始化 Git 裸仓库...")
	if err := gs.initGitRepo(app); err != nil {
		gs.logger.Errorf("初始化 Git 仓库失败: %v", err)
		// 清理已创建的数据
		delete(gs.apps, appName)
		return nil, fmt.Errorf("初始化 Git 仓库失败: %w", err)
	}
	gs.logger.Infof("  ✓ Git 仓库已初始化")

	// 设置 Git 钩子
	gs.logger.Debugf("  设置 Git 钩子...")
	if err := gs.setupGitHooks(app); err != nil {
		gs.logger.Warnf("设置 Git 钩子失败: %v", err)
	} else {
		gs.logger.Infof("  ✓ Git 钩子已设置")
	}

	// 创建符号链接，让 git-shell 能够找到仓库
	gs.logger.Debugf("  创建 Git SSH 符号链接...")
	if err := gs.createGitSymlink(app); err != nil {
		gs.logger.Errorf("❌ 创建 Git SSH 符号链接失败: %v", err)
		gs.logger.Errorf("   这会导致 SSH push 失败！")
		gs.logger.Errorf("   请确保：1) git 用户存在 2) /home/git 目录可写 3) 以 root 权限运行 sslcat")
		// 不要因为符号链接失败而中止创建，但要清楚地记录错误
	} else {
		gs.logger.Infof("  ✓ Git SSH 符号链接已创建")
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

	// 删除 Git SSH 符号链接
	symlinkPath := filepath.Join(gs.sshHomeDir, appName+".git")
	if _, err := os.Lstat(symlinkPath); err == nil {
		if err := os.Remove(symlinkPath); err != nil {
			gs.logger.Warnf("删除 Git SSH 符号链接失败: %v", err)
		} else {
			gs.logger.Infof("Git SSH 符号链接已删除: %s", symlinkPath)
		}
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

	// 标记为需要重启
	app.PendingRestart = true

	if err := gs.saveApps(); err != nil {
		return fmt.Errorf("保存应用信息失败: %w", err)
	}

	gs.logger.Infof("应用 %s 环境变量已更新，需要重新部署以应用更改", appName)
	return nil
}

// RedeployApp 手动触发应用重新部署
func (gs *GitServer) RedeployApp(appName string) error {
	gs.mutex.Lock()
	app, exists := gs.apps[appName]
	if !exists {
		gs.mutex.Unlock()
		return fmt.Errorf("应用 %s 不存在", appName)
	}

	// 检查应用是否正在部署中
	if app.Status == "building" || app.Status == "deploying" {
		gs.mutex.Unlock()
		return fmt.Errorf("应用正在部署中，请稍后再试")
	}

	// 清除重启标记
	app.PendingRestart = false
	app.Status = "building"
	app.LastDeploy = time.Now()
	gs.mutex.Unlock()

	// 在后台执行部署
	go gs.processGitPush(app, nil)

	gs.logger.Infof("手动触发应用 %s 的重新部署", appName)
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

// startDockerApp 启动 Docker 应用（蓝绿部署）
func (gs *GitServer) startDockerApp(app *GitApp, imageName string) error {
	// 为新容器分配一个临时端口
	newPort, err := gs.allocatePort()
	if err != nil {
		return fmt.Errorf("无法分配新端口: %w", err)
	}

	// 生成新容器名称（带时间戳）
	timestamp := time.Now().Unix()
	newContainerName := fmt.Sprintf("sslcat-%s-%d", app.Name, timestamp)

	// 启动新容器
	cmd := fmt.Sprintf("docker run -d --name %s -p %d:80 %s", newContainerName, newPort, imageName)
	if err := gs.runCommand("", "sh", "-c", cmd); err != nil {
		gs.releasePort(newPort)
		return fmt.Errorf("启动新容器失败: %w", err)
	}

	gs.logger.Infof("新容器已启动: %s, 端口: %d", newContainerName, newPort)

	// 获取容器ID
	getIDCmd := exec.Command("docker", "inspect", "-f", "{{.Id}}", newContainerName)
	containerIDBytes, err := getIDCmd.Output()
	if err != nil {
		gs.logger.Errorf("获取容器ID失败: %v", err)
		return fmt.Errorf("获取容器ID失败: %w", err)
	}
	newContainerID := strings.TrimSpace(string(containerIDBytes))

	// 执行蓝绿部署
	if err := gs.BlueGreenDeploy(app, newContainerID, newPort); err != nil {
		// 蓝绿部署失败，清理新容器
		gs.logger.Errorf("蓝绿部署失败: %v", err)
		gs.stopContainer(newContainerID)
		gs.releasePort(newPort)
		return fmt.Errorf("蓝绿部署失败: %w", err)
	}

	return nil
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
	gs.mutex.Unlock()

	deployLogger.WriteLog("info", "docker", fmt.Sprintf("Docker镜像构建完成: %s", image.FullName))

	// 启动Docker容器（使用蓝绿部署）
	deployLogger.WriteLog("info", "docker", "开始启动新容器（蓝绿部署）")
	if err := gs.startDockerApp(app, image.FullName); err != nil {
		return fmt.Errorf("启动Docker容器失败: %w", err)
	}

	deployLogger.WriteLog("info", "docker", "Docker应用部署完成")
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

	// 为已存在的应用补充缺失的符号链接（仅当 home 目录可写时）
	testFile := filepath.Join(gs.sshHomeDir, ".sslcat_symlink_test")
	if err := os.WriteFile(testFile, []byte("test"), 0600); err == nil {
		os.Remove(testFile)
		gs.logger.Infof("检查并创建缺失的 Git SSH 符号链接...")
		for _, app := range gs.apps {
			symlinkPath := filepath.Join(gs.sshHomeDir, app.Name+".git")
			// 检查符号链接是否存在
			if _, err := os.Lstat(symlinkPath); os.IsNotExist(err) {
				// 符号链接不存在，创建它
				if err := gs.createGitSymlink(app); err != nil {
					gs.logger.Warnf("为应用 %s 创建符号链接失败: %v", app.Name, err)
				} else {
					gs.logger.Infof("已为应用 %s 补充 Git SSH 符号链接", app.Name)
				}
			}
		}
	} else {
		gs.logger.Warnf("Git home 目录不可写，跳过符号链接检查")
	}

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

// saveDockerRegistryConfig 保存 Docker Registry 配置
func (gs *GitServer) saveDockerRegistryConfig() error {
	if gs.dockerRegistry == nil {
		return fmt.Errorf("Docker Registry not initialized")
	}

	configFile := filepath.Join(gs.config.Runners.Git.ReposDir, "docker_registry_config.json")

	// 获取当前配置
	config := gs.dockerRegistry.GetConfig()

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 Docker Registry 配置失败: %w", err)
	}

	if err := os.WriteFile(configFile, data, 0644); err != nil {
		return fmt.Errorf("写入 Docker Registry 配置失败: %w", err)
	}

	gs.logger.Infof("Docker Registry 配置已保存到 %s", configFile)
	return nil
}

// loadDockerRegistryConfig 加载 Docker Registry 配置
func (gs *GitServer) loadDockerRegistryConfig() error {
	if gs.dockerRegistry == nil {
		return fmt.Errorf("Docker Registry not initialized")
	}

	configFile := filepath.Join(gs.config.Runners.Git.ReposDir, "docker_registry_config.json")

	// 如果文件不存在，使用默认配置
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		gs.logger.Info("Docker Registry 配置文件不存在，使用默认配置")
		return nil
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("读取 Docker Registry 配置失败: %w", err)
	}

	var config DockerRegistryConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("解析 Docker Registry 配置失败: %w", err)
	}

	gs.dockerRegistry.UpdateConfig(&config)
	gs.logger.Infof("Docker Registry 配置已从 %s 加载", configFile)
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

	// 解析UID和GID
	uid, _ := strconv.Atoi(gitUser.Uid)
	gid, _ := strconv.Atoi(gitUser.Gid)

	// 使用实际的用户 home 目录（而不是硬编码的 /home/git）
	actualHomeDir := gitUser.HomeDir
	actualSSHKeysDir := filepath.Join(actualHomeDir, ".ssh")
	actualAuthorizedKeysFile := filepath.Join(actualSSHKeysDir, "authorized_keys")

	// 更新路径（使用实际的 home 目录）
	gs.sshHomeDir = actualHomeDir
	gs.sshKeysDir = actualSSHKeysDir
	gs.authorizedKeysFile = actualAuthorizedKeysFile
	gs.uid = uid
	gs.gid = gid

	gs.logger.Infof("使用 git 用户的实际 home 目录: %s", actualHomeDir)

	// 直接使用受管目录，避免各种权限问题
	gs.logger.Infof("使用受管 SSH 密钥目录（避免系统目录权限问题）: %s", gs.managedSSHDir)
	gs.useManagedKeys = true
	
	// 确保受管目录存在
	if err := os.MkdirAll(gs.managedSSHDir, 0700); err != nil {
		return fmt.Errorf("创建受管 SSH 目录失败: %w", err)
	}
	
	// 更新路径指向受管目录
	gs.sshKeysDir = gs.managedSSHDir
	gs.authorizedKeysFile = gs.managedAuthorizedKeysFile
	
	gs.logger.Infof("SSH 密钥目录: %s", gs.sshKeysDir)
	gs.logger.Infof("authorized_keys 文件: %s", gs.authorizedKeysFile)

	// 设置目录所有者为 git 用户
	if err := os.Chown(gs.sshKeysDir, uid, gid); err != nil {
		gs.logger.Warnf("设置 .ssh 目录权限失败: %v", err)
	}

	// 确保 home 目录权限正确（SSH StrictModes 要求）
	// home 目录不能被 group/others 写入
	if err := os.Chmod(gs.sshHomeDir, 0755); err != nil {
		gs.logger.Warnf("设置 home 目录权限失败: %v", err)
	}

	// 创建或确保 authorized_keys 文件存在
	if _, err := os.Stat(gs.authorizedKeysFile); os.IsNotExist(err) {
		if err := os.WriteFile(gs.authorizedKeysFile, []byte{}, 0600); err != nil {
			return fmt.Errorf("创建 authorized_keys 文件失败: %w", err)
		}
	}

	// 始终设置正确的所有者和权限（即使文件已存在）
	// SSH 要求 authorized_keys 必须由用户拥有且权限为 600
	if err := os.Chown(gs.authorizedKeysFile, uid, gid); err != nil {
		gs.logger.Warnf("设置 authorized_keys 文件所有者失败: %v", err)
	}
	if err := os.Chmod(gs.authorizedKeysFile, 0600); err != nil {
		gs.logger.Warnf("设置 authorized_keys 文件权限失败: %v", err)
	}

	// 生成 sshd 配置（总是在最后写入，确保 useManagedKeys 已设置）
	// 这个配置会在函数末尾再次写入，确保使用正确的路径
	gs.writeSshdConfig()

	// 创建 git-shell-commands 目录和友好提示脚本
	gitCmdDir := filepath.Join(gs.sshHomeDir, "git-shell-commands")
	if err := os.MkdirAll(gitCmdDir, 0755); err == nil {
		os.Chown(gitCmdDir, uid, gid)

		// 创建友好的 no-interactive-login 提示脚本
		noLoginScript := filepath.Join(gitCmdDir, "no-interactive-login")
		welcomeMessage := `#!/bin/sh
cat << 'WELCOME'
┌──────────────────────────────────────────────────────┐
│        欢迎使用 SSLcat Git 部署服务                  │
│        Welcome to SSLcat Git Deploy Service          │
└──────────────────────────────────────────────────────┘

⚠️  此账户仅用于 Git 操作，不支持交互式 Shell 登录。
    This account is for Git operations only, 
    interactive shell login is disabled.

📝 使用方法 / Usage:
   git clone git@` + gs.config.Server.Host + `:your-app.git
   git push origin main

📚 更多信息 / More info:
   https://sslcat.com

WELCOME
`
		if err := os.WriteFile(noLoginScript, []byte(welcomeMessage), 0755); err != nil {
			gs.logger.Warnf("创建 no-interactive-login 脚本失败: %v", err)
		} else {
			os.Chown(noLoginScript, uid, gid)
			gs.logger.Info("git-shell 欢迎脚本已创建")
		}
	}

	gs.logger.Info("SSH 用户配置完成")

	// 最后再次写入 sshd 配置，确保使用正确的 AuthorizedKeysFile 路径
	gs.writeSshdConfig()

	// 尝试自动重启 sshd 服务
	if err := gs.restartSSHD(); err != nil {
		gs.logger.Warnf("自动重启 SSH 服务失败: %v，请手动执行: sudo systemctl restart sshd", err)
	} else {
		gs.logger.Info("SSH 服务已自动重启")
	}

	return nil
}

// createGitUser 创建 git 用户（智能选择 home 目录）
func (gs *GitServer) createGitUser() error {
	// 检查用户是否已存在
	cmd := exec.Command("id", "-u", gs.sshUser)
	if err := cmd.Run(); err == nil {
		gs.logger.Infof("git 用户已存在")
		return nil
	}

	// 智能选择 home 目录，优先使用标准位置，如果不可用则使用替代位置
	homeDir := gs.findAvailableHomeDir()

	// 查找 git-shell 路径
	gitShellPath := "/usr/bin/git-shell" // 默认路径
	if path, err := exec.LookPath("git-shell"); err == nil {
		gitShellPath = path
	}

	// 创建用户 - 需要 root 权限，shell 设置为 git-shell
	cmd = exec.Command("useradd", "-r", "-s", gitShellPath, "-m", "-d", homeDir, gs.sshUser)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 检查是否是权限问题
		if strings.Contains(string(output), "Permission denied") || strings.Contains(err.Error(), "permission") {
			return fmt.Errorf("权限不足（需要 root/sudo 权限）: %w", err)
		}
		return fmt.Errorf("创建用户失败: %s, %w", string(output), err)
	}

	gs.logger.Infof("git 用户创建成功，home 目录: %s", homeDir)
	return nil
}

// findAvailableHomeDir 查找可用的 home 目录
func (gs *GitServer) findAvailableHomeDir() string {
	// 按优先级尝试不同的目录
	candidates := []string{
		"/home/git",      // 标准位置
		"/var/lib/git",   // 系统用户常用位置
		"/opt/git",       // 替代位置
		"/usr/local/git", // 本地安装位置
		"/tmp/git",       // 临时位置（最后选择）
	}

	for _, dir := range candidates {
		// 检查目录是否已存在且可写
		if info, err := os.Stat(dir); err == nil {
			if info.IsDir() {
				// 检查是否可写
				if err := os.MkdirAll(filepath.Join(dir, ".test"), 0755); err == nil {
					os.RemoveAll(filepath.Join(dir, ".test"))
					gs.logger.Infof("找到可用的 home 目录: %s", dir)
					return dir
				}
			}
		} else if os.IsNotExist(err) {
			// 目录不存在，尝试创建
			if err := os.MkdirAll(dir, 0755); err == nil {
				gs.logger.Infof("创建新的 home 目录: %s", dir)
				return dir
			}
		}
	}

	// 如果所有候选目录都不可用，使用默认位置并记录警告
	gs.logger.Warnf("所有候选 home 目录都不可用，使用默认位置 /home/git")
	return "/home/git"
}

// AddSSHKey 添加 SSH 密钥（Dokku 风格：支持自动创建应用）
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

	// 确保 SSH 目录存在（useManagedKeys 已在 setupSSHUser 中设置为 true）
	if err := os.MkdirAll(gs.sshKeysDir, 0700); err != nil {
		return fmt.Errorf("创建 SSH 目录失败: %w", err)
	}
	gs.logger.Infof("SSH 密钥目录: %s", gs.sshKeysDir)

	// 确保 authorized_keys 文件存在
	if err := gs.ensureAuthorizedKeysFile(); err != nil {
		return fmt.Errorf("确保 authorized_keys 文件存在失败: %w", err)
	}

	// Dokku 风格：添加 command= 参数来拦截 git 命令
	// 这样可以实现 git push 时自动创建应用

	// wrapper 脚本路径（安装时会复制到 /usr/local/bin）
	wrapperScript := "/usr/local/bin/sslcat-git-hook"

	// 构建 authorized_keys 条目
	// 格式：command="wrapper KEY_NAME",限制选项 公钥
	restrictions := "no-agent-forwarding,no-user-rc,no-X11-forwarding,no-port-forwarding"
	keyEntry := fmt.Sprintf("# %s\ncommand=\"%s %s\",%s %s\n",
		keyName, wrapperScript, keyName, restrictions, publicKey)

	// 在打开文件前，再次确保文件存在
	if err := gs.ensureAuthorizedKeysFile(); err != nil {
		return fmt.Errorf("确保 authorized_keys 文件存在失败: %w", err)
	}

	// 检查文件权限和所有者
	if info, err := os.Stat(gs.authorizedKeysFile); err != nil {
		return fmt.Errorf("检查 authorized_keys 文件状态失败: %w", err)
	} else {
		gs.logger.Debugf("authorized_keys 文件信息: 权限=%s, 所有者=%d:%d",
			info.Mode().String(), gs.uid, gs.gid)
	}

	file, err := os.OpenFile(gs.authorizedKeysFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		// 提供更详细的错误信息
		gs.logger.Errorf("打开 authorized_keys 文件失败: %v", err)
		gs.logger.Errorf("文件路径: %s", gs.authorizedKeysFile)
		gs.logger.Errorf("当前用户: %d:%d", gs.uid, gs.gid)

		// 检查父目录权限
		if parentInfo, parentErr := os.Stat(filepath.Dir(gs.authorizedKeysFile)); parentErr == nil {
			gs.logger.Errorf("父目录权限: %s", parentInfo.Mode().String())
		}

		return fmt.Errorf("打开 authorized_keys 文件失败: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(keyEntry); err != nil {
		return fmt.Errorf("写入 authorized_keys 文件失败: %w", err)
	}

	// 设置正确的所有者和权限
	if gs.uid > 0 && gs.gid > 0 {
		if err := os.Chown(gs.authorizedKeysFile, gs.uid, gs.gid); err != nil {
			gs.logger.Warnf("设置 authorized_keys 文件所有者失败: %v", err)
		}
	}

	gs.logger.Infof("SSH 密钥已添加（Dokku 风格）: %s -> %s", keyName, gs.authorizedKeysFile)
	gs.logger.Infof("  ✓ 支持 git push 自动创建应用")
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

	gs.logger.Infof("SSH 密钥已删除: %s -> %s", fingerprint, gs.authorizedKeysFile)
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
				keyLine := lines[i+1]

				// 提取公钥（可能包含 command= 前缀）
				var publicKey string
				if strings.Contains(keyLine, "command=") {
					// Dokku 风格：command="..." ssh-rsa AAAA...
					// 找到公钥类型开始的位置
					for _, keyType := range []string{"ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"} {
						if idx := strings.Index(keyLine, keyType); idx != -1 {
							publicKey = keyLine[idx:]
							break
						}
					}
				} else {
					// 标准格式：ssh-rsa AAAA...
					publicKey = keyLine
				}

				if publicKey != "" {
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

// writeSshdConfig 写入 sshd 配置文件
func (gs *GitServer) writeSshdConfig() {
	var sshdConfig string
	if gs.useManagedKeys {
		// 使用受管目录时，需要指定 AuthorizedKeysFile
		sshdConfig = fmt.Sprintf("Match User %s\n  AuthorizedKeysFile %s\n  AllowTcpForwarding no\n  X11Forwarding no\n",
			gs.sshUser, gs.managedAuthorizedKeysFile)
		gs.logger.Infof("使用受管 authorized_keys 文件: %s", gs.managedAuthorizedKeysFile)
	} else {
		sshdConfig = fmt.Sprintf("Match User %s\n  AllowTcpForwarding no\n  X11Forwarding no\n", gs.sshUser)
	}
	configPath := filepath.Join(gs.sshConfigDir, "sslcat_git.conf")
	if err := os.WriteFile(configPath, []byte(sshdConfig), 0644); err != nil {
		gs.logger.Warnf("创建 sshd 配置文件失败 (%s): %v", configPath, err)
	} else {
		gs.logger.Infof("sshd 配置文件已创建: %s", configPath)
	}
}

// restartSSHD 重启 SSH 服务
func (gs *GitServer) restartSSHD() error {
	// 检测操作系统类型
	osType := gs.detectOSType()

	var cmd *exec.Cmd
	var needsSudo bool

	switch osType {
	case "linux":
		// Linux 系统使用 systemctl（需要 sudo）
		cmd = exec.Command("sudo", "systemctl", "restart", "sshd")
		needsSudo = true
	case "darwin":
		// macOS 系统使用新的 launchctl kickstart API（需要 sudo）
		// kickstart 会重启服务，-k 表示先停止再启动
		cmd = exec.Command("sudo", "launchctl", "kickstart", "-k", "system/com.openssh.sshd")
		needsSudo = true
	default:
		return fmt.Errorf("不支持的操作系统: %s", osType)
	}

	gs.logger.Infof("尝试重启 SSH 服务 (OS: %s, 需要sudo: %v)...", osType, needsSudo)

	output, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	if err != nil {
		// 检查是否是权限问题
		if strings.Contains(outputStr, "permission") || strings.Contains(outputStr, "not permitted") {
			return fmt.Errorf("权限不足：SSH 服务重启需要 sudo 权限。请在服务器上手动执行：\nsudo launchctl kickstart -k system/com.openssh.sshd (macOS)\n或\nsudo systemctl restart sshd (Linux)")
		}
		return fmt.Errorf("重启 SSH 服务失败: %s, %w", outputStr, err)
	}

	if outputStr != "" {
		gs.logger.Infof("SSH 服务重启成功: %s", outputStr)
	} else {
		gs.logger.Info("SSH 服务重启命令已执行")
	}
	return nil
}

// detectOSType 检测操作系统类型
func (gs *GitServer) detectOSType() string {
	// 检查是否存在 systemctl 命令（Linux）
	if _, err := exec.LookPath("systemctl"); err == nil {
		// 进一步检查是否是 systemd 系统
		cmd := exec.Command("systemctl", "--version")
		if err := cmd.Run(); err == nil {
			return "linux"
		}
	}

	// 检查是否是 macOS
	if _, err := exec.LookPath("launchctl"); err == nil {
		return "darwin"
	}

	// 默认返回 linux
	return "linux"
}

// RestartSSHD 公开的 SSH 服务重启方法（供 API 调用）
func (gs *GitServer) RestartSSHD() error {
	return gs.restartSSHD()
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
	// 获取服务器配置
	adminPort := gs.config.Server.Port
	adminPrefix := gs.config.AdminPrefix
	domain := app.Domain
	protocol := "http"
	if app.DeployConfig != nil && app.DeployConfig.SSL.Enabled {
		protocol = "https"
	}

	return fmt.Sprintf(`#!/bin/bash
# SSLcat Git Post-Receive Hook
# 应用: %s
# 功能: 推送后实时部署并输出日志

set -e

APP_NAME="%s"
REPO_DIR="%s"
BARE_REPO="%s"
LOGS_DIR="%s"
ADMIN_PORT="%d"
ADMIN_PREFIX="%s"
APP_DOMAIN="%s"
APP_PROTOCOL="%s"

# 颜色定义
COLOR_RESET='\033[0m'
COLOR_BOLD='\033[1m'
COLOR_GREEN='\033[0;32m'
COLOR_BLUE='\033[0;34m'
COLOR_YELLOW='\033[0;33m'
COLOR_CYAN='\033[0;36m'
COLOR_RED='\033[0;31m'

# 输出函数
print_header() {
    echo -e "${COLOR_BOLD}${COLOR_CYAN}"
    echo "-----> $1"
    echo -e "${COLOR_RESET}"
}

print_info() {
    echo -e "${COLOR_GREEN}       $1${COLOR_RESET}"
}

print_warning() {
    echo -e "${COLOR_YELLOW}       ⚠ $1${COLOR_RESET}"
}

print_error() {
    echo -e "${COLOR_RED}       ✗ $1${COLOR_RESET}"
}

print_success() {
    echo -e "${COLOR_BOLD}${COLOR_GREEN}       ✓ $1${COLOR_RESET}"
}

# 记录推送信息
while read oldrev newrev refname; do
    # 写入日志文件
    echo "[$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] [info] [git] Post-receive: $oldrev -> $newrev ($refname)" >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log"
    
    # 获取提交信息
    if [ "$oldrev" != "0000000000000000000000000000000000000000" ]; then
        COMMIT_MSG=$(git --git-dir="$BARE_REPO" log -1 --pretty=format:"%%s" $newrev)
        COMMIT_AUTHOR=$(git --git-dir="$BARE_REPO" log -1 --pretty=format:"%%an" $newrev)
        SHORT_SHA=$(git --git-dir="$BARE_REPO" rev-parse --short $newrev)
    else
        COMMIT_MSG="Initial commit"
        COMMIT_AUTHOR="Unknown"
        SHORT_SHA=$(echo $newrev | cut -c1-7)
    fi
    
    # 显示欢迎信息
    echo ""
    echo -e "${COLOR_BOLD}${COLOR_BLUE}╔═══════════════════════════════════════════════════════════════╗${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_BLUE}║${COLOR_RESET}                    ${COLOR_BOLD}SSLcat Git Deploy${COLOR_RESET}                       ${COLOR_BOLD}${COLOR_BLUE}║${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_BLUE}╚═══════════════════════════════════════════════════════════════╝${COLOR_RESET}"
    echo ""
    echo -e "${COLOR_CYAN}Application:${COLOR_RESET} ${COLOR_BOLD}$APP_NAME${COLOR_RESET}"
    echo -e "${COLOR_CYAN}Commit:${COLOR_RESET}      $SHORT_SHA - $COMMIT_MSG"
    echo -e "${COLOR_CYAN}Author:${COLOR_RESET}      $COMMIT_AUTHOR"
    echo -e "${COLOR_CYAN}Branch:${COLOR_RESET}      ${refname##refs/heads/}"
    echo ""
    
    # 更新工作目录
    print_header "Updating repository"
    if [ ! -d "$REPO_DIR/.git" ]; then
        print_info "Cloning repository to work directory..."
        if git clone "$BARE_REPO" "$REPO_DIR" >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log" 2>&1; then
            print_success "Repository cloned"
        else
            print_error "Failed to clone repository"
            exit 1
        fi
    else
        print_info "Fetching latest changes..."
        cd "$REPO_DIR"
        if git fetch origin >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log" 2>&1 && \
           git reset --hard $newrev >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log" 2>&1; then
            print_success "Repository updated"
        else
            print_error "Failed to update repository"
            exit 1
        fi
    fi
    
    # 触发部署
    print_header "Deploying application"
    
    # 创建触发文件
    DEPLOY_TRIGGER="/tmp/sslcat-deploy-$APP_NAME-$(date +%%s)"
    echo "$newrev|$refname|$COMMIT_MSG" > "$DEPLOY_TRIGGER"
    
    # 等待部署开始并监控日志
    print_info "Waiting for deployment to start..."
    
    # 简单的日志监控 - 读取最新的部署日志
    DEPLOY_LOG="$LOGS_DIR/deploy-$(date '+%%Y-%%m-%%d').log"
    
    # 等待几秒让部署开始
    sleep 2
    
    # 跟踪日志文件的最后位置
    if [ -f "$DEPLOY_LOG" ]; then
        # 获取当前文件大小作为起始点
        START_POS=$(wc -c < "$DEPLOY_LOG" 2>/dev/null || echo 0)
        
        print_info "Streaming deployment logs..."
        echo ""
        
        # 监控日志 - 只要有新日志就持续等待
        # 只有在 IDLE_TIMEOUT 秒内没有新日志时才超时退出
        MAX_TOTAL_TIME=600    # 最长总等待时间 10 分钟
        IDLE_TIMEOUT=30       # 无新日志超时时间 30 秒
        TOTAL_ELAPSED=0
        IDLE_ELAPSED=0
        DEPLOY_DONE=false
        
        while [ $TOTAL_ELAPSED -lt $MAX_TOTAL_TIME ] && [ "$DEPLOY_DONE" = "false" ]; do
            if [ -f "$DEPLOY_LOG" ]; then
                # 读取新增的日志内容
                CURRENT_POS=$(wc -c < "$DEPLOY_LOG" 2>/dev/null || echo 0)
                
                if [ $CURRENT_POS -gt $START_POS ]; then
                    # 有新日志，重置空闲计时器
                    IDLE_ELAPSED=0
                    
                    # 提取新的日志行
                    NEW_LOGS=$(tail -c +$((START_POS + 1)) "$DEPLOY_LOG" 2>/dev/null || echo "")
                    
                    # 逐行处理并格式化输出
                    echo "$NEW_LOGS" | while IFS= read -r line; do
                        if [ -n "$line" ]; then
                            # 尝试解析JSON格式的日志
                            if echo "$line" | grep -q '"level"'; then
                                # JSON格式日志
                                LEVEL=$(echo "$line" | grep -o '"level":"[^"]*"' | cut -d'"' -f4 || echo "info")
                                MESSAGE=$(echo "$line" | grep -o '"message":"[^"]*"' | cut -d'"' -f4 || echo "$line")
                                SOURCE=$(echo "$line" | grep -o '"source":"[^"]*"' | cut -d'"' -f4 || echo "")
                                
                                case "$LEVEL" in
                                    "error")
                                        echo -e "${COLOR_RED}       [$SOURCE] $MESSAGE${COLOR_RESET}"
                                        ;;
                                    "warn")
                                        echo -e "${COLOR_YELLOW}       [$SOURCE] $MESSAGE${COLOR_RESET}"
                                        ;;
                                    "info")
                                        echo -e "${COLOR_GREEN}       [$SOURCE] $MESSAGE${COLOR_RESET}"
                                        ;;
                                    *)
                                        echo -e "       [$SOURCE] $MESSAGE"
                                        ;;
                                esac
                                
                                # 检查是否部署完成
                                if echo "$MESSAGE" | grep -q "部署成功\|部署完成\|deployment.*success\|deployment.*complete"; then
                                    DEPLOY_DONE=true
                                fi
                                if echo "$MESSAGE" | grep -q "部署失败\|deployment.*failed"; then
                                    DEPLOY_DONE=true
                                fi
                            else
                                # 纯文本日志
                                echo "       $line"
                            fi
                        fi
                    done
                    
                    START_POS=$CURRENT_POS
                else
                    # 没有新日志，增加空闲计时
                    IDLE_ELAPSED=$((IDLE_ELAPSED + 1))
                    
                    # 空闲超时检查
                    if [ $IDLE_ELAPSED -ge $IDLE_TIMEOUT ]; then
                        print_warning "No new logs for ${IDLE_TIMEOUT}s, deployment may still be running in background"
                        print_info "Check admin panel or logs for details: tail -f $DEPLOY_LOG"
                        
                        # 发送部署卡住通知 API
                        curl -s -X POST "http://localhost:${ADMIN_PORT}${ADMIN_PREFIX}/api/internal/deploy-notification" \
                          -H "Content-Type: application/json" \
                          -d "{\"type\":\"stuck\",\"app_name\":\"$APP_NAME\",\"commit_sha\":\"$SHORT_SHA\",\"idle_duration\":\"${IDLE_TIMEOUT}s\"}" \
                          >/dev/null 2>&1 || true
                        
                        break
                    fi
                fi
            fi
            
            sleep 1
            TOTAL_ELAPSED=$((TOTAL_ELAPSED + 1))
        done
        
        # 检查是否超过最大总时间
        if [ $TOTAL_ELAPSED -ge $MAX_TOTAL_TIME ]; then
            print_warning "Deployment timeout after ${MAX_TOTAL_TIME}s, but may still be running"
            print_info "Check admin panel or logs for status"
            
            # 发送部署超时通知 API
            curl -s -X POST "http://localhost:${ADMIN_PORT}${ADMIN_PREFIX}/api/internal/deploy-notification" \
              -H "Content-Type: application/json" \
              -d "{\"type\":\"timeout\",\"app_name\":\"$APP_NAME\",\"commit_sha\":\"$SHORT_SHA\",\"duration\":\"${MAX_TOTAL_TIME}s\"}" \
              >/dev/null 2>&1 || true
        fi
        
        echo ""
    else
        print_warning "Deployment log file not found, check admin panel for details"
    fi
    
    # 显示部署结果
    echo ""
    echo -e "${COLOR_BOLD}${COLOR_GREEN}╔═══════════════════════════════════════════════════════════════╗${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_GREEN}║${COLOR_RESET}                    ${COLOR_BOLD}Deployment Complete${COLOR_RESET}                      ${COLOR_BOLD}${COLOR_GREEN}║${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_GREEN}╚═══════════════════════════════════════════════════════════════╝${COLOR_RESET}"
    echo ""
    echo -e "${COLOR_CYAN}Application URL:${COLOR_RESET}"
    echo -e "  ${COLOR_BOLD}${APP_PROTOCOL}://${APP_DOMAIN}${COLOR_RESET}"
    echo ""
    echo -e "${COLOR_CYAN}Admin Panel:${COLOR_RESET}"
    echo -e "  http://localhost:${ADMIN_PORT}${ADMIN_PREFIX}"
    echo ""
    echo -e "${COLOR_CYAN}View Logs:${COLOR_RESET}"
    echo -e "  tail -f $DEPLOY_LOG"
    echo ""
    
    print_success "Push accepted and deployed to ${APP_PROTOCOL}://${APP_DOMAIN}"
    echo ""
    
    echo "[$(date '+%%Y-%%m-%%d %%H:%%M:%%S')] [info] [git] Post-receive completed" >> "$LOGS_DIR/push-$(date '+%%Y-%%m-%%d').log"
done

exit 0
`, app.Name, app.Name, app.RepoDir, app.BareRepo, app.LogsDir, adminPort, adminPrefix, domain, protocol)
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

	// 设置 git 用户所有权（如果 git 用户存在）
	if gs.uid > 0 && gs.gid > 0 {
		gs.logger.Debugf("设置 Git 仓库所有者为 git 用户 (uid:%d, gid:%d)", gs.uid, gs.gid)

		// 递归设置整个应用目录的所有者
		// 使用 chown -R 命令会更高效
		cmd = exec.Command("chown", "-R", fmt.Sprintf("%d:%d", gs.uid, gs.gid), filepath.Dir(app.GitPath))
		if output, err := cmd.CombinedOutput(); err != nil {
			gs.logger.Warnf("设置 Git 仓库所有者失败: %v, output: %s", err, string(output))
		} else {
			gs.logger.Infof("✓ Git 仓库所有者已设置为 git 用户")
		}
	} else {
		gs.logger.Warnf("未找到 git 用户，跳过所有者设置（文件所有者将是当前运行用户）")
	}

	return nil
}

// createGitSymlink 创建符号链接，让 git-shell 能够通过 SSH 访问仓库
// 当用户执行 git push git@host:appname.git 时，git-shell 会在 /home/git/ 下查找 appname.git
// 因此需要创建符号链接指向实际的裸仓库位置
func (gs *GitServer) createGitSymlink(app *GitApp) error {
	// 检查 home 目录是否可写
	testFile := filepath.Join(gs.sshHomeDir, ".sslcat_symlink_test")
	if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
		// home 目录不可写，跳过符号链接创建
		gs.logger.Warnf("Git home 目录 %s 不可写，跳过符号链接创建（Git push 仍可通过绝对路径工作）", gs.sshHomeDir)
		return nil
	}
	os.Remove(testFile)

	// 符号链接路径：/home/git/appname.git -> /path/to/repos/appname/git/repo.git
	symlinkPath := filepath.Join(gs.sshHomeDir, app.Name+".git")
	targetPath := app.BareRepo

	// 检查符号链接是否已存在
	if _, err := os.Lstat(symlinkPath); err == nil {
		// 符号链接已存在，先删除旧的
		gs.logger.Debugf("符号链接已存在，删除旧链接: %s", symlinkPath)
		if err := os.Remove(symlinkPath); err != nil {
			return fmt.Errorf("删除旧符号链接失败: %w", err)
		}
	}

	// 创建符号链接
	gs.logger.Debugf("创建符号链接: %s -> %s", symlinkPath, targetPath)
	if err := os.Symlink(targetPath, symlinkPath); err != nil {
		return fmt.Errorf("创建符号链接失败: %w", err)
	}

	// 设置符号链接的所有者为 git 用户
	if gs.uid > 0 && gs.gid > 0 {
		// Lchown 修改符号链接本身的所有者，而不是目标文件
		if err := os.Lchown(symlinkPath, gs.uid, gs.gid); err != nil {
			gs.logger.Warnf("设置符号链接所有者失败: %v", err)
		}
	}

	gs.logger.Infof("Git SSH 符号链接已创建: %s -> %s", symlinkPath, targetPath)
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

// UpdateDockerRegistryConfig 更新 Docker Registry 配置
func (gs *GitServer) UpdateDockerRegistryConfig(config *DockerRegistryConfig) error {
	if gs.dockerRegistry == nil {
		return fmt.Errorf("Docker Registry not initialized")
	}

	gs.dockerRegistry.UpdateConfig(config)
	gs.logger.Info("Docker Registry configuration updated successfully")

	// 持久化配置
	if err := gs.saveDockerRegistryConfig(); err != nil {
		gs.logger.Warnf("保存 Docker Registry 配置失败: %v", err)
		// 不返回错误，配置已更新到内存
	}

	return nil
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
		gs.logger.Infof("应用 %s 不存在，自动创建（使用服务器默认SSL配置: %v）", appName, gs.serverConfig.AutoSSL)
		var err error
		app, err = gs.CreateApp(appName, gs.serverConfig.AutoSSL)
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

// ==================== 蓝绿部署功能 ====================

// healthCheck 健康检查
func (gs *GitServer) healthCheck(port int, timeout time.Duration) bool {
	// 尝试连接应用端口
	url := fmt.Sprintf("http://localhost:%d", port)
	client := http.Client{
		Timeout: timeout,
	}

	start := time.Now()
	deadline := start.Add(timeout)

	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			// 只要能连接上就认为健康
			if resp.StatusCode < 500 {
				gs.logger.Infof("健康检查成功: 端口=%d, 状态码=%d, 耗时=%v", port, resp.StatusCode, time.Since(start))
				return true
			}
		}

		// 等待1秒后重试
		time.Sleep(1 * time.Second)
	}

	gs.logger.Warnf("健康检查失败: 端口=%d, 超时=%v", port, timeout)
	return false
}

// BlueGreenDeploy 蓝绿部署
func (gs *GitServer) BlueGreenDeploy(app *GitApp, newContainerID string, newPort int) error {
	deployID := fmt.Sprintf("bg_deploy_%d", time.Now().Unix())

	gs.logger.Infof("开始蓝绿部署: 应用=%s, 新容器=%s, 新端口=%d", app.Name, newContainerID, newPort)

	// 记录部署事件
	if gs.deployDB != nil {
		gs.deployDB.AddDeployEvent(
			app.Name, deployID, "blue_green_start",
			app.ContainerID, newContainerID,
			app.Port, newPort,
			"started", "开始蓝绿部署",
		)
	}

	// 1. 保存旧容器信息
	oldContainerID := app.ContainerID
	oldPort := app.Port

	gs.logger.Infof("旧容器信息: ID=%s, 端口=%d", oldContainerID, oldPort)

	// 2. 更新应用信息（指向新容器）
	gs.mutex.Lock()
	app.OldContainerID = oldContainerID
	app.ContainerID = newContainerID
	app.Port = newPort
	app.ContainerStatus = "switching"
	gs.mutex.Unlock()

	// 3. 健康检查（最多等待30秒）
	gs.logger.Infof("开始健康检查: 新端口=%d", newPort)
	if !gs.healthCheck(newPort, 30*time.Second) {
		// 健康检查失败，回滚
		gs.logger.Errorf("新容器健康检查失败，开始回滚")

		gs.mutex.Lock()
		app.ContainerID = oldContainerID
		app.Port = oldPort
		app.OldContainerID = ""
		app.ContainerStatus = "active"
		gs.mutex.Unlock()

		// 停止新容器
		go gs.stopContainer(newContainerID)

		if gs.deployDB != nil {
			gs.deployDB.AddDeployEvent(
				app.Name, deployID, "blue_green_rollback",
				oldContainerID, newContainerID,
				oldPort, newPort,
				"failed", "健康检查失败，已回滚",
			)
		}

		return fmt.Errorf("新容器健康检查失败")
	}

	// 4. 更新数据库中的容器状态
	if gs.deployDB != nil {
		// 添加新容器记录
		newVersion := &ContainerVersion{
			AppName:     app.Name,
			ContainerID: newContainerID,
			ImageName:   app.DockerImage,
			Port:        newPort,
			Status:      "active",
			CommitHash:  app.LastCommit,
			StartedAt:   time.Now(),
			HealthCheck: true,
		}
		gs.deployDB.AddContainerVersion(newVersion)

		// 更新旧容器状态为停止中
		if oldContainerID != "" {
			gs.deployDB.UpdateContainerStatus(oldContainerID, "stopping")
		}
	}

	// 5. 切换代理规则到新端口
	gs.logger.Infof("切换代理规则: %s -> localhost:%d", app.Domain, newPort)
	if err := gs.addProxyRuleForApp(app); err != nil {
		gs.logger.Errorf("切换代理规则失败: %v", err)
		// 继续执行，不回滚
	}

	if gs.deployDB != nil {
		gs.deployDB.AddDeployEvent(
			app.Name, deployID, "proxy_switched",
			oldContainerID, newContainerID,
			oldPort, newPort,
			"success", "代理规则已切换",
		)
	}

	// 6. 延迟停止旧容器（1分钟后）
	if oldContainerID != "" {
		gs.logger.Infof("将在60秒后停止旧容器: %s", oldContainerID)

		go func() {
			time.Sleep(60 * time.Second)

			gs.logger.Infof("开始停止旧容器: %s", oldContainerID)
			if err := gs.stopContainer(oldContainerID); err != nil {
				gs.logger.Errorf("停止旧容器失败: %v", err)
			} else {
				gs.logger.Infof("旧容器已停止: %s", oldContainerID)

				// 更新数据库状态
				if gs.deployDB != nil {
					gs.deployDB.UpdateContainerStatus(oldContainerID, "stopped")
					gs.deployDB.AddDeployEvent(
						app.Name, deployID, "old_container_stopped",
						oldContainerID, newContainerID,
						oldPort, newPort,
						"success", "旧容器已停止",
					)
				}
			}

			// 清理应用的旧容器ID
			gs.mutex.Lock()
			if app.OldContainerID == oldContainerID {
				app.OldContainerID = ""
			}
			app.ContainerStatus = "active"
			gs.mutex.Unlock()

			gs.saveApps()
		}()
	}

	// 7. 保存应用状态
	gs.saveApps()

	gs.logger.Infof("蓝绿部署完成: 应用=%s, 新容器=%s, 新端口=%d", app.Name, newContainerID, newPort)

	if gs.deployDB != nil {
		gs.deployDB.AddDeployEvent(
			app.Name, deployID, "blue_green_complete",
			oldContainerID, newContainerID,
			oldPort, newPort,
			"success", "蓝绿部署完成",
		)
	}

	return nil
}

// stopContainer 停止容器
func (gs *GitServer) stopContainer(containerID string) error {
	if containerID == "" {
		return nil
	}

	cmd := exec.Command("docker", "stop", containerID)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("停止容器失败: %v, 输出: %s", err, string(output))
	}

	// 删除容器
	cmd = exec.Command("docker", "rm", containerID)
	output, err = cmd.CombinedOutput()
	if err != nil {
		gs.logger.Warnf("删除容器失败: %v, 输出: %s", err, string(output))
	}

	return nil
}

// ==================== 部署通知集成 ====================

// SendDeployNotification 发送部署通知
func (gs *GitServer) SendDeployNotification(notifType, appName, commitSHA, commitMsg,
	idleDuration, duration, reason, errorDetails, domain string) error {

	if gs.notificationManager == nil {
		gs.logger.Warn("通知管理器未初始化，跳过通知发送")
		return nil
	}

	gs.logger.Infof("发送部署通知: type=%s, app=%s, commit=%s", notifType, appName, commitSHA)

	switch notifType {
	case "stuck":
		// 部署卡住通知
		return gs.notificationManager.SendDeployStuck(appName, commitSHA, "", idleDuration)

	case "timeout":
		// 部署超时通知
		return gs.notificationManager.SendDeployTimeout(appName, commitSHA, duration)

	case "failed":
		// 部署失败通知
		return gs.notificationManager.SendDeployFailed(appName, commitSHA, commitMsg, reason, errorDetails)

	case "success":
		// 部署成功通知（可选，根据配置决定是否发送）
		// 计算部署时间（这里简化处理，实际可以从日志中提取）
		durationTime, _ := time.ParseDuration(duration)
		if durationTime == 0 {
			durationTime = 1 * time.Minute // 默认值
		}
		return gs.notificationManager.SendDeploySuccess(appName, commitSHA, commitMsg, domain, durationTime)

	default:
		gs.logger.Warnf("未知的通知类型: %s", notifType)
		return fmt.Errorf("未知的通知类型: %s", notifType)
	}
}

// installGitHook 自动安装 git hook wrapper 脚本
func (gs *GitServer) installGitHook() error {
	// 检查 wrapper 脚本是否已经安装
	wrapperPath := "/usr/local/bin/sslcat-git-hook"
	if info, err := os.Stat(wrapperPath); err == nil && info.Mode().IsRegular() {
		gs.logger.Infof("git hook wrapper 脚本已存在: %s", wrapperPath)
		return nil
	}

	gs.logger.Infof("开始自动安装 git hook wrapper 脚本...")

	// 尝试找到 install-git-hook.sh 脚本
	scriptPaths := []string{
		"/opt/sslcat/scripts/install-git-hook.sh", // 标准安装路径
		"/usr/local/bin/install-git-hook.sh",      // 可能的安装路径
		"./scripts/install-git-hook.sh",           // 开发环境
		"scripts/install-git-hook.sh",             // 相对路径
	}

	var scriptPath string
	for _, path := range scriptPaths {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			scriptPath = path
			break
		}
	}

	if scriptPath == "" {
		// 如果找不到脚本，尝试手动安装
		return gs.manualInstallGitHook()
	}

	gs.logger.Infof("找到安装脚本: %s", scriptPath)

	// 执行安装脚本
	cmd := exec.Command("bash", scriptPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		gs.logger.Errorf("执行 git hook 安装脚本失败: %v, 输出: %s", err, string(output))
		// 如果脚本执行失败，尝试手动安装
		return gs.manualInstallGitHook()
	}

	gs.logger.Infof("git hook wrapper 脚本安装成功")
	gs.logger.Debugf("安装输出: %s", string(output))
	return nil
}

// manualInstallGitHook 手动安装 git hook wrapper 脚本
func (gs *GitServer) manualInstallGitHook() error {
	gs.logger.Infof("尝试手动安装 git hook wrapper 脚本...")

	// 检查 wrapper 脚本源码是否存在
	wrapperSourcePaths := []string{
		"/opt/sslcat/scripts/sslcat-git-hook", // 标准安装路径
		"/usr/local/bin/sslcat-git-hook",      // 可能的安装路径
		"./scripts/sslcat-git-hook",           // 开发环境
		"scripts/sslcat-git-hook",             // 相对路径
	}

	var sourcePath string
	for _, path := range wrapperSourcePaths {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			sourcePath = path
			break
		}
	}

	if sourcePath == "" {
		return fmt.Errorf("找不到 sslcat-git-hook 脚本源码")
	}

	// 复制脚本到目标位置
	targetPath := "/usr/local/bin/sslcat-git-hook"

	// 读取源文件
	sourceData, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("读取源脚本失败: %w", err)
	}

	// 写入目标文件
	if err := os.WriteFile(targetPath, sourceData, 0755); err != nil {
		return fmt.Errorf("写入目标脚本失败: %w", err)
	}

	gs.logger.Infof("手动安装 git hook wrapper 脚本成功: %s", targetPath)

	// 尝试创建配置文件
	return gs.createGitHookConfig()
}

// createGitHookConfig 创建 git hook 配置文件
func (gs *GitServer) createGitHookConfig() error {
	configDir := "/etc/sslcat"
	configFile := filepath.Join(configDir, "git-hook.conf")

	// 检查配置文件是否已存在
	if _, err := os.Stat(configFile); err == nil {
		gs.logger.Infof("git hook 配置文件已存在: %s", configFile)
		return nil
	}

	// 创建配置目录
	if err := os.MkdirAll(configDir, 0755); err != nil {
		gs.logger.Warnf("创建配置目录失败: %v", err)
		return nil // 非致命错误
	}

	// 构建 API URL
	var apiURL string
	if gs.config.Server.Port == 443 {
		// 当端口为 443 时，使用 HTTP (80) 进行 API 调用
		apiURL = fmt.Sprintf("http://localhost:80%s", gs.config.AdminPrefix)
	} else {
		apiURL = fmt.Sprintf("http://localhost:%d%s", gs.config.Server.Port, gs.config.AdminPrefix)
	}

	// 创建配置文件内容
	configContent := fmt.Sprintf(`# SSLcat Git Hook 配置文件
# 自动生成于: %s
# 
# 此配置从 SSLcat 主配置文件自动检测而来
# 如果 SSLcat 配置变更，请重新运行安装脚本或手动修改此文件

# SSLcat API 地址
export SSLCAT_API_URL="%s"

# Git 仓库存储目录
export SSLCAT_REPOS_DIR="%s"

# 注意：如果修改了 SSLcat 的 admin_prefix 或端口，需要同步更新此文件
`, time.Now().Format("2006-01-02 15:04:05"), apiURL, gs.config.Runners.Git.ReposDir)

	// 写入配置文件
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		gs.logger.Warnf("创建 git hook 配置文件失败: %v", err)
		return nil // 非致命错误
	}

	gs.logger.Infof("git hook 配置文件创建成功: %s", configFile)
	return nil
}

// ensureAuthorizedKeysFile 确保 authorized_keys 文件存在并具有正确的权限
func (gs *GitServer) ensureAuthorizedKeysFile() error {
	// 检查文件是否已存在
	if info, err := os.Stat(gs.authorizedKeysFile); err == nil {
		if info.Mode().IsRegular() {
			gs.logger.Infof("authorized_keys 文件已存在: %s", gs.sshKeysDir)
			// 确保权限正确
			if err := os.Chmod(gs.authorizedKeysFile, 0600); err != nil {
				gs.logger.Warnf("设置 authorized_keys 文件权限失败: %v", err)
			}
			// 设置正确的所有者
			if gs.uid > 0 && gs.gid > 0 {
				if err := os.Chown(gs.authorizedKeysFile, gs.uid, gs.gid); err != nil {
					gs.logger.Warnf("设置 authorized_keys 文件所有者失败: %v", err)
				}
			}
			return nil
		} else {
			return fmt.Errorf("authorized_keys 路径被目录占用: %s", gs.authorizedKeysFile)
		}
	} else if os.IsNotExist(err) {
		// 文件不存在，创建它
		gs.logger.Infof("创建 authorized_keys 文件: %s", gs.authorizedKeysFile)

		// 确保父目录存在，并设置正确的权限
		sshDir := filepath.Dir(gs.authorizedKeysFile)
		if err := os.MkdirAll(sshDir, 0700); err != nil {
			return fmt.Errorf("创建 .ssh 目录失败: %w", err)
		}

		// 确保 .ssh 目录权限正确（SSH StrictModes 要求）
		if err := os.Chmod(sshDir, 0700); err != nil {
			gs.logger.Warnf("设置 .ssh 目录权限失败: %v", err)
		}

		// 确保 home 目录权限正确（SSH StrictModes 要求）
		// home 目录不能被 group/others 写入
		if err := os.Chmod(gs.sshHomeDir, 0755); err != nil {
			gs.logger.Warnf("设置 home 目录权限失败: %v", err)
		}

		// 创建空文件
		if err := os.WriteFile(gs.authorizedKeysFile, []byte{}, 0600); err != nil {
			return fmt.Errorf("创建 authorized_keys 文件失败: %w", err)
		}

		// 设置正确的所有者
		if gs.uid > 0 && gs.gid > 0 {
			if err := os.Chown(gs.authorizedKeysFile, gs.uid, gs.gid); err != nil {
				gs.logger.Warnf("设置 authorized_keys 文件所有者失败: %v", err)
			}
			// 同时设置目录的所有者
			if err := os.Chown(filepath.Dir(gs.authorizedKeysFile), gs.uid, gs.gid); err != nil {
				gs.logger.Warnf("设置 .ssh 目录所有者失败: %v", err)
			}
		}

		gs.logger.Infof("authorized_keys 文件创建成功: %s", gs.authorizedKeysFile)
		return nil
	} else {
		return fmt.Errorf("检查 authorized_keys 文件状态失败: %w", err)
	}
}

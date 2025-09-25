package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config 应用配置结构
type Config struct {
	Server      ServerConfig   `json:"server"`
	SSL         SSLConfig      `json:"ssl"`
	Admin       AdminConfig    `json:"admin"`
	Proxy       ProxyConfig    `json:"proxy"`
	Security    SecurityConfig `json:"security"`
	CDNCache    CDNCacheConfig `json:"cdn_cache"`
	AdminPrefix string         `json:"admin_prefix"`
	ConfigFile  string         `json:"-"` // 配置文件路径，不序列化

	// 集群配置
	Cluster ClusterConfig `json:"cluster"`
	// 静态站点
	StaticSites []StaticSite `json:"static_sites"`
	// PHP 站点
	PHPSites []PHPSite `json:"php_sites"`
	// Runner 配置
	Runners RunnerConfig `json:"runners"`
	// 威胁情报配置
	ThreatIntel ThreatIntelConfig `json:"threat_intel"`
	// 通知配置
	Notification NotificationConfig `json:"notification"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Host  string `json:"host"`
	Port  int    `json:"port"`
	Debug bool   `json:"debug"`
	// 访问日志
	AccessLogEnabled  bool   `json:"access_log_enabled"`
	AccessLogFormat   string `json:"access_log_format"` // nginx|apache|json
	AccessLogPath     string `json:"access_log_path"`
	AccessLogMaxSize  int64  `json:"access_log_max_size"` // bytes
	AccessLogMaxFiles int    `json:"access_log_max_files"`

	// 客户端连接超时（秒）
	ReadTimeoutSec  int `json:"read_timeout_sec"`
	WriteTimeoutSec int `json:"write_timeout_sec"`
	IdleTimeoutSec  int `json:"idle_timeout_sec"`
	// 最大上传大小（字节），用于限制 multipart 上传体积
	MaxUploadBytes int64 `json:"max_upload_bytes"`
}

// SSLConfig SSL证书配置
type SSLConfig struct {
	Email             string   `json:"email"`
	Staging           bool     `json:"staging"`
	Domains           []string `json:"domains"`
	CertDir           string   `json:"cert_dir"`
	KeyDir            string   `json:"key_dir"`
	AutoRenew         bool     `json:"auto_renew"`
	DisableSelfSigned bool     `json:"disable_self_signed"`

	// DNS验证配置
	DNSProviders       []DNSProvider `json:"dns_providers"`
	DefaultDNSProvider string        `json:"default_dns_provider"`
	ChallengeMethods   []string      `json:"challenge_methods"` // ["http-01", "dns-01"]
}

// DNSProvider DNS服务商配置
type DNSProvider struct {
	Name      string `json:"name"`       // 服务商名称
	Type      string `json:"type"`       // cloudflare/aliyun/tencent/aws/godaddy/custom
	Enabled   bool   `json:"enabled"`    // 是否启用
	APIKey    string `json:"api_key"`    // API密钥
	APISecret string `json:"api_secret"` // API密钥(部分服务商需要)
	ZoneID    string `json:"zone_id"`    // 域名区域ID
	Endpoint  string `json:"endpoint"`   // 自定义API端点
	Priority  int    `json:"priority"`   // 优先级，数字越小优先级越高
}

// AdminConfig 管理面板配置
type AdminConfig struct {
	Username     string `json:"username"`
	Password     string `json:"password,omitempty"`
	FirstRun     bool   `json:"first_run"`
	PasswordFile string `json:"password_file"`
	// TOTP 二次验证
	EnableTOTP     bool   `json:"enable_totp"`
	TOTPSecret     string `json:"totp_secret,omitempty"`
	TOTPSecretFile string `json:"totp_secret_file"`
}

// ProxyConfig 代理配置
type ProxyConfig struct {
	Rules []ProxyRule `json:"rules"`
	// 未命中代理规则时的行为: "404" | "302" | "blank" | "502"
	UnmatchedBehavior string `json:"unmatched_behavior"`
	// 当 UnmatchedBehavior=="302" 时的跳转URL
	UnmatchedRedirectURL string `json:"unmatched_redirect_url"`
}

// ProxyRule 代理规则
type ProxyRule struct {
	Domain  string `json:"domain"`
	Target  string `json:"target"`
	Port    int    `json:"port"`
	Enabled bool   `json:"enabled"`
	SSLOnly bool   `json:"ssl_only"`
	// HTTP Host头部优化设置
	OptimizeHostHeader bool `json:"optimize_host_header"`
	// 每域名的类CDN设置
	CDNEnabled           bool   `json:"cdn_enabled"`
	CDNPreset            string `json:"cdn_preset"`      // none|static|images|cloud_storage
	CDNDefaultTTLSeconds int    `json:"cdn_ttl_seconds"` // 0 表示使用全局规则

	// 云存储后端配置
	CloudStorageType      string `json:"cloud_storage_type"`       // aliyun_oss|aws_s3|tencent_cos|auto
	CloudStorageRegion    string `json:"cloud_storage_region"`     // 云存储区域
	CloudStorageBucket    string `json:"cloud_storage_bucket"`     // 存储桶名称
	CloudStorageEndpoint  string `json:"cloud_storage_endpoint"`   // 自定义端点
	CloudStoragePath      string `json:"cloud_storage_path"`       // 存储路径前缀
	CloudStorageAccessKey string `json:"cloud_storage_access_key"` // 访问密钥
	CloudStorageSecretKey string `json:"cloud_storage_secret_key"` // 秘密密钥

	// 访问控制设置
	AuthEnabled        bool            `json:"auth_enabled"`         // 是否开启访问控制
	AuthUsers          []ProxyAuthUser `json:"auth_users,omitempty"` // 用户密码列表
	AuthSessionTimeout int             `json:"auth_session_timeout"` // 登录有效期（秒），默认3600
	AuthCookieDomain   string          `json:"auth_cookie_domain"`   // Cookie作用域，默认为代理域名
}

// ProxyAuthUser 代理访问控制用户
type ProxyAuthUser struct {
	Username string `json:"username"`
	Password string `json:"password"` // 明文存储（内部使用，不暴露给前端）
}

// SecurityConfig 安全配置
type SecurityConfig struct {
	MaxAttempts       int      `json:"max_attempts"`
	BlockDurationStr  string   `json:"block_duration"`
	MaxAttempts5Min   int      `json:"max_attempts_5min"`
	BlockFile         string   `json:"block_file"`
	AllowedUserAgents []string `json:"allowed_user_agents"`
	// 可疑 UA 计数阈值（达到后封禁）
	UAInvalidMax1Min int `json:"ua_invalid_max_1min"`
	UAInvalidMax5Min int `json:"ua_invalid_max_5min"`
	// TLS 指纹统计配置
	TLSFingerprintWindowSec int `json:"tls_fp_window_sec"`
	TLSFingerprintMaxPerMin int `json:"tls_fp_max_per_min"`
	TLSFingerprintTopN      int `json:"tls_fp_top_n"`

	// 安全功能开关
	EnableUAFilter bool `json:"enable_ua_filter"`
	EnableWAF      bool `json:"enable_waf"`
	EnableDDOS     bool `json:"enable_ddos"`

	// 人机验证配置
	EnableCaptcha bool `json:"enable_captcha"`
	MinFormMs     int  `json:"min_form_ms"`

	// 解析后的时间字段
	BlockDuration time.Duration `json:"-"`
}

// CDNCacheRule CDN 类缓存规则
type CDNCacheRule struct {
	// 匹配类型: prefix | suffix | media
	MatchType string `json:"match_type"`
	// 当 MatchType==media 时按 Content-Type 前缀匹配，如 image/, text/css
	MediaTypes []string `json:"media_types,omitempty"`
	// 当 MatchType==prefix/suffix 时按路径匹配
	Pattern string `json:"pattern,omitempty"`
	// 该规则命中的 TTL（秒）
	TTLSeconds int `json:"ttl_seconds"`
}

// CDNCacheConfig CDN 类缓存配置
type CDNCacheConfig struct {
	Enabled           bool           `json:"enabled"`
	CacheDir          string         `json:"cache_dir"`
	MaxSizeBytes      int64          `json:"max_size_bytes"`
	DefaultTTLSeconds int            `json:"default_ttl_seconds"`
	CleanIntervalSec  int            `json:"clean_interval_seconds"`
	MaxObjectBytes    int64          `json:"max_object_bytes"`
	Rules             []CDNCacheRule `json:"rules"`
}

// ClusterConfig 集群配置
type ClusterConfig struct {
	// 集群模式: "master", "slave", "standalone"
	Mode string `json:"mode"`

	// 节点ID（自动生成）
	NodeID string `json:"node_id"`

	// 节点名称
	NodeName string `json:"node_name"`

	// Master配置（当模式为slave时使用）
	Master MasterConfig `json:"master"`

	// 同步配置
	Sync SyncConfig `json:"sync"`

	// 集群通信端口
	Port int `json:"port"`

	// 集群通信密钥
	AuthKey string `json:"auth_key"`
}

// MasterConfig Master节点配置
type MasterConfig struct {
	// Master节点地址
	Host string `json:"host"`

	// Master节点端口
	Port int `json:"port"`

	// 认证密钥
	AuthKey string `json:"auth_key"`

	// 连接超时时间（秒）
	Timeout int `json:"timeout"`

	// 重连间隔（秒）
	RetryInterval int `json:"retry_interval"`
}

// SyncConfig 同步配置
type SyncConfig struct {
	// 是否启用配置同步
	ConfigEnabled bool `json:"config_enabled"`

	// 是否启用证书同步
	CertEnabled bool `json:"cert_enabled"`

	// 同步间隔（秒）
	Interval int `json:"interval"`

	// 同步超时时间（秒）
	Timeout int `json:"timeout"`

	// 排除的配置项
	ExcludeConfigs []string `json:"exclude_configs"`
}

// StaticSite 静态站点配置
type StaticSite struct {
	Domain  string `json:"domain"`
	Root    string `json:"root"`
	Index   string `json:"index"`
	Enabled bool   `json:"enabled"`
}

// PHPSite PHP 站点配置
type PHPSite struct {
	Domain   string            `json:"domain"`
	Root     string            `json:"root"`
	Index    string            `json:"index"`
	Enabled  bool              `json:"enabled"`
	FCGIAddr string            `json:"fcgi_addr"` // unix:/path/php-fpm.sock 或 127.0.0.1:9000
	Vars     map[string]string `json:"vars"`

	// 新增优化配置
	OptimizationConfig *PHPOptimizationConfig `json:"optimization_config,omitempty"`

	// 安全配置
	SecurityConfig *PHPSecurityConfig `json:"security_config,omitempty"`

	// 监控配置
	MonitoringConfig *PHPMonitoringConfig `json:"monitoring_config,omitempty"`
}

// PHPOptimizationConfig PHP 优化配置
type PHPOptimizationConfig struct {
	// OPcache 配置
	OPcacheEnabled            bool `json:"opcache_enabled"`
	OPcacheMemorySize         int  `json:"opcache_memory_size"` // MB
	OPcacheMaxFiles           int  `json:"opcache_max_files"`
	OPcacheValidateTimestamps bool `json:"opcache_validate_timestamps"`

	// 性能优化
	EnableGzipCompression bool `json:"enable_gzip_compression"`
	EnableStaticCaching   bool `json:"enable_static_caching"`
	CacheTTL              int  `json:"cache_ttl"` // 秒

	// 安全优化
	HidePHPVersion            bool `json:"hide_php_version"`
	DisableDangerousFunctions bool `json:"disable_dangerous_functions"`

	// 框架特定优化
	LaravelOptimizations bool `json:"laravel_optimizations"`
	SymfonyOptimizations bool `json:"symfony_optimizations"`
}

// PHPSecurityConfig PHP 安全配置
type PHPSecurityConfig struct {
	// 文件上传安全
	MaxUploadSize     int64    `json:"max_upload_size"`    // 字节
	AllowedExtensions []string `json:"allowed_extensions"` // 允许的文件扩展名
	BlockedExtensions []string `json:"blocked_extensions"` // 禁止的文件扩展名

	// 路径安全
	DisablePathTraversal bool     `json:"disable_path_traversal"`
	AllowedPaths         []string `json:"allowed_paths"` // 允许访问的路径

	// 执行安全
	DisableEval      bool     `json:"disable_eval"`
	DisableShellExec bool     `json:"disable_shell_exec"`
	AllowedFunctions []string `json:"allowed_functions"` // 允许的函数

	// 会话安全
	SessionSecure   bool   `json:"session_secure"`
	SessionHttpOnly bool   `json:"session_http_only"`
	SessionSameSite string `json:"session_same_site"` // Strict|Lax|None
}

// PHPMonitoringConfig PHP 监控配置
type PHPMonitoringConfig struct {
	// 性能监控
	EnablePerformanceMonitoring bool `json:"enable_performance_monitoring"`
	PerformanceThreshold        int  `json:"performance_threshold"` // 毫秒

	// 错误监控
	EnableErrorMonitoring bool `json:"enable_error_monitoring"`
	ErrorReportingLevel   int  `json:"error_reporting_level"`
	LogSlowQueries        bool `json:"log_slow_queries"`
	SlowQueryThreshold    int  `json:"slow_query_threshold"` // 毫秒

	// 资源监控
	EnableResourceMonitoring bool `json:"enable_resource_monitoring"`
	MemoryLimit              int  `json:"memory_limit"`  // MB
	CPUThreshold             int  `json:"cpu_threshold"` // 百分比

	// 日志配置
	LogLevel    string `json:"log_level"` // debug|info|warn|error
	LogFile     string `json:"log_file"`
	LogMaxSize  int64  `json:"log_max_size"` // 字节
	LogMaxFiles int    `json:"log_max_files"`
}

// ThreatIntelConfig 威胁情报配置
type ThreatIntelConfig struct {
	// 是否启用威胁情报
	Enabled bool `json:"enabled"`

	// 威胁情报源配置
	Sources map[string]ThreatIntelSourceConfig `json:"sources"`

	// 检测配置
	Detection DetectionConfig `json:"detection"`

	// 更新配置
	Update UpdateConfig `json:"update"`

	// 日志配置
	Log LogConfig `json:"log"`
}

// ThreatIntelSourceConfig 威胁情报源配置
type ThreatIntelSourceConfig struct {
	Name       string        `json:"name"`
	URL        string        `json:"url"`
	APIKey     string        `json:"api_key"`
	Enabled    bool          `json:"enabled"`
	UpdateFreq time.Duration `json:"update_freq"`
	Timeout    time.Duration `json:"timeout"`
	MaxRetries int           `json:"max_retries"`
}

// DetectionConfig 检测配置
type DetectionConfig struct {
	// 是否启用实时检测
	RealTimeEnabled bool `json:"real_time_enabled"`

	// 检测阈值
	ThreatScoreThreshold float64 `json:"threat_score_threshold"`

	// 自动响应
	AutoResponse AutoResponseConfig `json:"auto_response"`

	// 白名单
	Whitelist []string `json:"whitelist"`
}

// AutoResponseConfig 自动响应配置
type AutoResponseConfig struct {
	// 是否启用自动响应
	Enabled bool `json:"enabled"`

	// 响应动作
	Actions []string `json:"actions"` // block|monitor|log|alert

	// 响应阈值
	ResponseThreshold float64 `json:"response_threshold"`
}

// UpdateConfig 更新配置
type UpdateConfig struct {
	// 更新频率
	UpdateFreq time.Duration `json:"update_freq"`

	// 并发更新数
	ConcurrentUpdates int `json:"concurrent_updates"`

	// 更新超时
	UpdateTimeout time.Duration `json:"update_timeout"`
}

// LogConfig 日志配置
type LogConfig struct {
	// 日志级别
	Level string `json:"level"`

	// 日志文件
	LogFile string `json:"log_file"`

	// 最大文件大小
	MaxSize int64 `json:"max_size"`

	// 最大文件数
	MaxFiles int `json:"max_files"`
}

// RunnerConfig Runner 配置
type RunnerConfig struct {
	// Git 服务器配置
	Git GitServerConfig `json:"git"`
}

// GitServerConfig Git 服务器配置
type GitServerConfig struct {
	Enabled bool `json:"enabled"`
	// Git 仓库目录
	ReposDir string `json:"repos_dir"`
	// 最大并发克隆数
	MaxConcurrent int `json:"max_concurrent"`
	// 克隆超时时间（秒）
	CloneTimeout int `json:"clone_timeout"`
	// 自动清理仓库
	AutoCleanup bool `json:"auto_cleanup"`
	// 清理间隔（秒）
	CleanupInterval int `json:"cleanup_interval"`
}

// Load 加载配置文件
func Load(configFile string) (*Config, error) {
	// 设置默认值
	config := &Config{
		Server: ServerConfig{
			Host:              "0.0.0.0",
			Port:              443,
			Debug:             false,
			AccessLogEnabled:  true,
			AccessLogFormat:   "nginx",
			AccessLogPath:     "./data/access.log",
			AccessLogMaxSize:  100 * 1024 * 1024,
			AccessLogMaxFiles: 10,
			ReadTimeoutSec:    1800,    // 30分钟
			WriteTimeoutSec:   1800,    // 30分钟
			IdleTimeoutSec:    120,     // 2分钟（可调）
			MaxUploadBytes:    1 << 30, // 1 GiB
		},
		SSL: SSLConfig{
			Staging:            false,
			CertDir:            "./data/certs",
			KeyDir:             "./data/keys",
			AutoRenew:          true,
			DisableSelfSigned:  true,
			DNSProviders:       []DNSProvider{},
			DefaultDNSProvider: "",
			ChallengeMethods:   []string{"http-01"},
		},
		Admin: AdminConfig{
			Username:       "admin",
			Password:       "admin*9527",
			FirstRun:       true,
			PasswordFile:   "./data/admin.pass",
			EnableTOTP:     false,
			TOTPSecretFile: "./data/admin.totp",
		},
		Proxy: ProxyConfig{
			Rules:                []ProxyRule{},
			UnmatchedBehavior:    "502",
			UnmatchedRedirectURL: "",
		},
		CDNCache: CDNCacheConfig{
			Enabled:           false,
			CacheDir:          "./data/cache/static",
			MaxSizeBytes:      5 * 1024 * 1024 * 1024, // 5GB
			DefaultTTLSeconds: 3600,                   // 1h
			CleanIntervalSec:  60,                     // 1min
			MaxObjectBytes:    20 * 1024 * 1024,       // 20MB
			Rules:             []CDNCacheRule{},
		},
		Security: SecurityConfig{
			MaxAttempts:      900,
			BlockDurationStr: "5s",
			MaxAttempts5Min:  3000,
			BlockFile:        "./data/sslcat.block",
			AllowedUserAgents: []string{
				"Mozilla/",
				"Chrome/",
				"Firefox/",
				"Safari/",
				"Edge/",
			},
			UAInvalidMax1Min:        30,
			UAInvalidMax5Min:        100,
			TLSFingerprintWindowSec: 60,
			TLSFingerprintMaxPerMin: 60000,
			TLSFingerprintTopN:      20,
			EnableUAFilter:          false,
			EnableWAF:               false,
			EnableDDOS:              true,
			EnableCaptcha:           false,
			MinFormMs:               800,
		},
		AdminPrefix: "/sslcat-panel",
		Cluster: ClusterConfig{
			Mode:     "standalone",
			NodeID:   generateNodeID(),
			NodeName: "Node-1",
			Master: MasterConfig{
				Timeout:       30,
				RetryInterval: 10,
			},
			Sync: SyncConfig{
				ConfigEnabled: true,
				CertEnabled:   true,
				Interval:      30,
				Timeout:       10,
				ExcludeConfigs: []string{
					"admin.password",
					"admin.password_file",
					"admin_prefix",
					"cluster",
				},
			},
			Port:    8443,
			AuthKey: "",
		},
		StaticSites: []StaticSite{},
		PHPSites:    []PHPSite{},
		Runners: RunnerConfig{
			Git: GitServerConfig{
				Enabled:         false,
				ReposDir:        "./data/runners/git",
				MaxConcurrent:   3,
				CloneTimeout:    300, // 5分钟
				AutoCleanup:     true,
				CleanupInterval: 7200, // 2小时
			},
		},
	}

	// 如果配置文件存在，则加载
	if _, err := os.Stat(configFile); err == nil {
		data, err := os.ReadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("读取配置文件失败: %w", err)
		}

		if err := json.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("解析配置文件失败: %w", err)
		}
	}

	// 解析时间字符串
	if config.Security.BlockDurationStr != "" {
		duration, err := time.ParseDuration(config.Security.BlockDurationStr)
		if err != nil {
			return nil, fmt.Errorf("解析 block_duration 失败: %w", err)
		}
		config.Security.BlockDuration = duration
	} else {
		config.Security.BlockDuration = time.Minute // 默认1分钟
	}

	// 创建必要的目录
	if err := os.MkdirAll(config.SSL.CertDir, 0755); err != nil {
		return nil, fmt.Errorf("创建证书目录失败: %w", err)
	}
	if err := os.MkdirAll(config.SSL.KeyDir, 0755); err != nil {
		return nil, fmt.Errorf("创建密钥目录失败: %w", err)
	}
	// 创建 CDN 缓存目录（若配置启用或指定目录）
	if config.CDNCache.CacheDir != "" {
		if err := os.MkdirAll(config.CDNCache.CacheDir, 0755); err != nil {
			return nil, fmt.Errorf("创建CDN缓存目录失败: %w", err)
		}
	}
	// 确保密码文件目录存在，并且如存在则覆盖内存密码
	if config.Admin.PasswordFile != "" {
		if err := os.MkdirAll(filepath.Dir(config.Admin.PasswordFile), 0755); err != nil {
			return nil, fmt.Errorf("创建密码文件目录失败: %w", err)
		}
		if b, err := os.ReadFile(config.Admin.PasswordFile); err == nil {
			config.Admin.Password = strings.TrimSpace(string(b))
		}
	}

	// 确保TOTP密钥文件目录存在，并加载TOTP密钥
	if config.Admin.TOTPSecretFile != "" {
		if err := os.MkdirAll(filepath.Dir(config.Admin.TOTPSecretFile), 0755); err != nil {
			return nil, fmt.Errorf("创建TOTP密钥文件目录失败: %w", err)
		}
		if b, err := os.ReadFile(config.Admin.TOTPSecretFile); err == nil {
			secret := strings.TrimSpace(string(b))
			if secret != "" {
				config.Admin.TOTPSecret = secret
				config.Admin.EnableTOTP = true // 有密钥文件就自动启用
			}
		} else {
			// 文件不存在或读取失败，自动关闭TOTP
			if config.Admin.EnableTOTP {
				config.Admin.EnableTOTP = false
				config.Admin.TOTPSecret = ""
			}
		}
	}

	// 保存配置文件路径
	config.ConfigFile = configFile

	return config, nil
}

// generateNodeID 生成节点ID
func generateNodeID() string {
	// 使用时间戳和随机数生成节点ID
	data := make([]byte, 8)
	_, err := rand.Read(data)
	if err != nil {
		// 如果随机数生成失败，使用时间戳
		data = []byte(fmt.Sprintf("%d", time.Now().UnixNano()))
	}
	timestamp := time.Now().Unix()
	combined := fmt.Sprintf("%d-%x", timestamp, data)
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:8])
}

// IsSlaveMode 检查是否为Slave模式
func (c *Config) IsSlaveMode() bool {
	return c.Cluster.Mode == "slave"
}

// IsMasterMode 检查是否为Master模式
func (c *Config) IsMasterMode() bool {
	return c.Cluster.Mode == "master"
}

// IsStandaloneMode 检查是否为独立模式
func (c *Config) IsStandaloneMode() bool {
	return c.Cluster.Mode == "standalone" || c.Cluster.Mode == ""
}

// 实现集群配置接口方法
func (c *Config) GetClusterMode() string {
	return c.Cluster.Mode
}

func (c *Config) GetNodeID() string {
	return c.Cluster.NodeID
}

func (c *Config) GetNodeName() string {
	return c.Cluster.NodeName
}

func (c *Config) GetMasterConfig() interface{} {
	return struct {
		Host          string
		Port          int
		AuthKey       string
		Timeout       int
		RetryInterval int
	}{
		Host:          c.Cluster.Master.Host,
		Port:          c.Cluster.Master.Port,
		AuthKey:       c.Cluster.Master.AuthKey,
		Timeout:       c.Cluster.Master.Timeout,
		RetryInterval: c.Cluster.Master.RetryInterval,
	}
}

func (c *Config) GetSyncConfig() interface{} {
	return struct {
		ConfigEnabled  bool
		CertEnabled    bool
		Interval       int
		Timeout        int
		ExcludeConfigs []string
	}{
		ConfigEnabled:  c.Cluster.Sync.ConfigEnabled,
		CertEnabled:    c.Cluster.Sync.CertEnabled,
		Interval:       c.Cluster.Sync.Interval,
		Timeout:        c.Cluster.Sync.Timeout,
		ExcludeConfigs: c.Cluster.Sync.ExcludeConfigs,
	}
}

func (c *Config) GetClusterPort() int {
	return c.Cluster.Port
}

func (c *Config) GetClusterAuthKey() string {
	return c.Cluster.AuthKey
}

func (c *Config) GetServicePort() int {
	return c.Server.Port
}

func (c *Config) GetCertDir() string {
	return c.SSL.CertDir
}

func (c *Config) GetProxyRules() []interface{} {
	rules := make([]interface{}, len(c.Proxy.Rules))
	for i, rule := range c.Proxy.Rules {
		rules[i] = rule
	}
	return rules
}

func (c *Config) GetSSLDomains() []string {
	return c.SSL.Domains
}

// Save 保存配置文件
func (c *Config) Save(configFile string) error {
	// 智能选择配置文件路径
	actualConfigFile := c.getWritableConfigPath(configFile)

	// 确保配置目录存在
	configDir := filepath.Dir(actualConfigFile)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("创建配置目录失败 (%s): %w", configDir, err)
	}

	// 验证配置完整性
	if err := c.Validate(); err != nil {
		return fmt.Errorf("配置验证失败: %w", err)
	}

	// 序列化时避免写入敏感信息
	shadow := *c
	shadow.Security.BlockDurationStr = c.Security.BlockDuration.String()
	shadow.Admin.Password = ""
	shadow.Admin.TOTPSecret = "" // 不保存TOTP密钥到配置文件

	data, err := json.MarshalIndent(&shadow, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	// 创建临时文件，然后原子性重命名
	tempFile := actualConfigFile + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("写入临时配置文件失败 (%s): %w", tempFile, err)
	}

	// 原子性重命名
	if err := os.Rename(tempFile, actualConfigFile); err != nil {
		os.Remove(tempFile) // 清理临时文件
		return fmt.Errorf("重命名配置文件失败 (%s -> %s): %w", tempFile, actualConfigFile, err)
	}

	return nil
}

// getWritableConfigPath 智能选择可写的配置文件路径
func (c *Config) getWritableConfigPath(originalPath string) string {
	// 首先尝试原始路径
	if c.canWriteToPath(originalPath) {
		return originalPath
	}

	// 如果原始路径不可写，尝试运行时目录
	runtimeDir := "./data"
	if err := os.MkdirAll(runtimeDir, 0755); err == nil {
		runtimePath := filepath.Join(runtimeDir, "sslcat.conf")
		if c.canWriteToPath(runtimePath) {
			return runtimePath
		}
	}

	// 最后尝试当前目录
	currentDirPath := "./sslcat.conf"
	if c.canWriteToPath(currentDirPath) {
		return currentDirPath
	}

	// 如果都不可写，返回原始路径（让调用者处理错误）
	return originalPath
}

// canWriteToPath 检查是否可以写入指定路径
func (c *Config) canWriteToPath(path string) bool {
	// 检查目录是否存在，如果不存在则尝试创建
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return false
	}

	// 尝试创建一个临时文件来测试写入权限
	tempFile := path + ".test"
	if err := os.WriteFile(tempFile, []byte("test"), 0644); err != nil {
		return false
	}

	// 清理测试文件
	os.Remove(tempFile)
	return true
}

// GetProxyRule 获取指定域名的代理规则
func (c *Config) GetProxyRule(domain string) *ProxyRule {
	for i := range c.Proxy.Rules {
		if c.Proxy.Rules[i].Domain == domain && c.Proxy.Rules[i].Enabled {
			return &c.Proxy.Rules[i]
		}
	}
	return nil
}

// AddProxyRule 添加代理规则
func (c *Config) AddProxyRule(rule ProxyRule) {
	// 检查是否已存在
	for i := range c.Proxy.Rules {
		if c.Proxy.Rules[i].Domain == rule.Domain {
			c.Proxy.Rules[i] = rule
			return
		}
	}
	// 添加新规则
	c.Proxy.Rules = append(c.Proxy.Rules, rule)
}

// Validate 验证配置完整性
func (c *Config) Validate() error {
	// 验证代理规则
	for i, rule := range c.Proxy.Rules {
		if rule.Domain == "" {
			return fmt.Errorf("代理规则 %d: 域名不能为空", i)
		}
		if rule.Target == "" {
			return fmt.Errorf("代理规则 %d: 目标地址不能为空", i)
		}
		if rule.Port < 0 || rule.Port > 65535 {
			return fmt.Errorf("代理规则 %d: 端口号必须在0-65535范围内", i)
		}
	}

	// 验证SSL配置
	if c.SSL.Email == "" && !c.SSL.DisableSelfSigned {
		return fmt.Errorf("SSL配置: 当禁用自签名证书时，必须提供邮箱地址")
	}

	// 验证服务器配置
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("服务器配置: 端口号必须在1-65535范围内")
	}

	return nil
}

// RemoveProxyRule 删除代理规则
func (c *Config) RemoveProxyRule(domain string) {
	for i := range c.Proxy.Rules {
		if c.Proxy.Rules[i].Domain == domain {
			c.Proxy.Rules = append(c.Proxy.Rules[:i], c.Proxy.Rules[i+1:]...)
			return
		}
	}
}

// NotificationConfig 通知配置
type NotificationConfig struct {
	Enabled  bool           `json:"enabled"`  // 是否启用通知系统
	Channels ChannelsConfig `json:"channels"` // 通知渠道配置
}

// ChannelsConfig 通知渠道配置
type ChannelsConfig struct {
	Email   EmailChannelConfig   `json:"email"`   // 邮件通知配置
	Webhook WebhookChannelConfig `json:"webhook"` // Webhook通知配置
	Syslog  SyslogChannelConfig  `json:"syslog"`  // 系统日志通知配置
	Console ConsoleChannelConfig `json:"console"` // 控制台通知配置
}

// EmailChannelConfig 邮件通知渠道配置
type EmailChannelConfig struct {
	Enabled  bool     `json:"enabled"`   // 是否启用
	SMTPHost string   `json:"smtp_host"` // SMTP服务器地址
	SMTPPort int      `json:"smtp_port"` // SMTP端口
	Username string   `json:"username"`  // 用户名
	Password string   `json:"password"`  // 密码
	From     string   `json:"from"`      // 发件人地址
	To       []string `json:"to"`        // 收件人地址列表
	UseTLS   bool     `json:"use_tls"`   // 是否使用TLS
}

// WebhookChannelConfig Webhook通知渠道配置
type WebhookChannelConfig struct {
	Enabled bool              `json:"enabled"` // 是否启用
	URL     string            `json:"url"`     // Webhook URL
	Headers map[string]string `json:"headers"` // 自定义HTTP头部
	Timeout int               `json:"timeout"` // 超时时间（秒）
}

// SyslogChannelConfig 系统日志通知渠道配置
type SyslogChannelConfig struct {
	Enabled bool   `json:"enabled"` // 是否启用
	Address string `json:"address"` // syslog服务器地址
	Network string `json:"network"` // 网络协议 (udp/tcp)
}

// ConsoleChannelConfig 控制台通知渠道配置
type ConsoleChannelConfig struct {
	Enabled bool `json:"enabled"` // 是否启用
}

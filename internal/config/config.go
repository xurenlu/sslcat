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
	// 每域名的类CDN设置
	CDNEnabled           bool   `json:"cdn_enabled"`
	CDNPreset            string `json:"cdn_preset"`      // none|static|images
	CDNDefaultTTLSeconds int    `json:"cdn_ttl_seconds"` // 0 表示使用全局规则
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
	EnablePoW     bool `json:"enable_pow"`
	PoWBits       int  `json:"pow_bits"`
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
			Staging:           false,
			CertDir:           "./data/certs",
			KeyDir:            "./data/keys",
			AutoRenew:         true,
			DisableSelfSigned: true,
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
			EnableCaptcha:           true,
			EnablePoW:               true,
			PoWBits:                 16,  // 降低到16位，约2^15次尝试，快很多
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
	// 确保配置目录存在
	configDir := filepath.Dir(configFile)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("创建配置目录失败 (%s): %w", configDir, err)
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

	if err := os.WriteFile(configFile, data, 0644); err != nil {
		return fmt.Errorf("写入配置文件失败 (%s): %w", configFile, err)
	}
	return nil
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

// RemoveProxyRule 删除代理规则
func (c *Config) RemoveProxyRule(domain string) {
	for i := range c.Proxy.Rules {
		if c.Proxy.Rules[i].Domain == domain {
			c.Proxy.Rules = append(c.Proxy.Rules[:i], c.Proxy.Rules[i+1:]...)
			return
		}
	}
}

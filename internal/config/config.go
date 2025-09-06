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
	AdminPrefix string         `json:"admin_prefix"`
	ConfigFile  string         `json:"-"` // 配置文件路径，不序列化

	// 集群配置
	Cluster ClusterConfig `json:"cluster"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Host  string `json:"host"`
	Port  int    `json:"port"`
	Debug bool   `json:"debug"`
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

	// 解析后的时间字段
	BlockDuration time.Duration `json:"-"`
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

// Load 加载配置文件
func Load(configFile string) (*Config, error) {
	// 设置默认值
	config := &Config{
		Server: ServerConfig{
			Host:  "0.0.0.0",
			Port:  443,
			Debug: false,
		},
		SSL: SSLConfig{
			Staging:           false,
			CertDir:           "./data/certs",
			KeyDir:            "./data/keys",
			AutoRenew:         true,
			DisableSelfSigned: true,
		},
		Admin: AdminConfig{
			Username:     "admin",
			Password:     "admin*9527",
			FirstRun:     true,
			PasswordFile: "./data/admin.pass",
		},
		Proxy: ProxyConfig{
			Rules:                []ProxyRule{},
			UnmatchedBehavior:    "502",
			UnmatchedRedirectURL: "",
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
			UAInvalidMax1Min: 30,
			UAInvalidMax5Min: 100,
			TLSFingerprintWindowSec: 60,
			TLSFingerprintMaxPerMin: 60000,
			TLSFingerprintTopN:      20,
			EnableUAFilter:          false,
			EnableWAF:               false,
			EnableDDOS:              true,
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
	// 确保密码文件目录存在，并且如存在则覆盖内存密码
	if config.Admin.PasswordFile != "" {
		if err := os.MkdirAll(filepath.Dir(config.Admin.PasswordFile), 0755); err != nil {
			return nil, fmt.Errorf("创建密码文件目录失败: %w", err)
		}
		if b, err := os.ReadFile(config.Admin.PasswordFile); err == nil {
			config.Admin.Password = strings.TrimSpace(string(b))
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

	// 序列化时避免写入明文密码
	shadow := *c
	shadow.Security.BlockDurationStr = c.Security.BlockDuration.String()
	shadow.Admin.Password = ""

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

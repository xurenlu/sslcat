package config

import (
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

	// 解析后的时间字段
	BlockDuration time.Duration `json:"-"`
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
			Rules: []ProxyRule{},
		},
		Security: SecurityConfig{
			MaxAttempts:      90,
			BlockDurationStr: "5s",
			MaxAttempts5Min:  300,
			BlockFile:        "./data/sslcat.block",
			AllowedUserAgents: []string{
				"Mozilla/",
				"Chrome/",
				"Firefox/",
				"Safari/",
				"Edge/",
			},
		},
		AdminPrefix: "/sslcat-panel",
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

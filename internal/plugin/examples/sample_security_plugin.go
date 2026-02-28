//go:build ignore
// +build ignore

package main

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/plugin"
)

// SampleSecurityPlugin 示例安全插件
type SampleSecurityPlugin struct {
	info    *plugin.PluginInfo
	config  map[string]interface{}
	enabled bool
	rules   []plugin.SecurityRule
	stats   *PluginStats
	mutex   sync.RWMutex
	log     *logrus.Entry
}

// PluginStats 插件统计信息
type PluginStats struct {
	RequestsChecked int64     `json:"requests_checked"`
	ThreatsBlocked  int64     `json:"threats_blocked"`
	FalsePositives  int64     `json:"false_positives"`
	LastCheck       time.Time `json:"last_check"`
}

// NewPlugin 创建插件实例（插件入口点）
func NewPlugin() plugin.Plugin {
	return &SampleSecurityPlugin{
		info: &plugin.PluginInfo{
			ID:           "sample_security_plugin",
			Name:         "示例安全插件",
			Version:      "1.0.0",
			Description:  "一个用于演示的安全插件，检测常见的Web攻击",
			Author:       "SSLcat Team",
			Website:      "https://github.com/xurenlu/sslcat",
			License:      "MIT",
			Tags:         []string{"security", "waf", "protection"},
			Category:     "security",
			Interfaces:   []string{"Plugin", "SecurityPlugin"},
			Dependencies: []string{},
			Config: &plugin.PluginConfig{
				Schema: map[string]*plugin.ConfigField{
					"enabled": {
						Type:        "bool",
						Description: "是否启用插件",
						Default:     true,
						Required:    false,
					},
					"strict_mode": {
						Type:        "bool",
						Description: "严格模式，更严格的检测规则",
						Default:     false,
						Required:    false,
					},
					"blocked_patterns": {
						Type:        "array",
						Description: "自定义阻止模式列表",
						Default:     []string{},
						Required:    false,
					},
					"whitelist_ips": {
						Type:        "array",
						Description: "IP白名单",
						Default:     []string{},
						Required:    false,
					},
				},
				Defaults: map[string]interface{}{
					"enabled":          true,
					"strict_mode":      false,
					"blocked_patterns": []string{},
					"whitelist_ips":    []string{},
				},
				Required: []string{},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		enabled: true,
		rules:   []plugin.SecurityRule{},
		stats: &PluginStats{
			LastCheck: time.Now(),
		},
		log: logrus.WithFields(logrus.Fields{
			"component": "sample_security_plugin",
		}),
	}
}

// GetInfo 获取插件信息
func (p *SampleSecurityPlugin) GetInfo() *plugin.PluginInfo {
	return p.info
}

// Initialize 初始化插件
func (p *SampleSecurityPlugin) Initialize(config map[string]interface{}) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.config = config

	// 从配置中获取启用状态
	if enabled, ok := config["enabled"].(bool); ok {
		p.enabled = enabled
	}

	// 初始化默认安全规则
	p.initDefaultRules()

	p.log.Info("Sample security plugin initialized")
	return nil
}

// Start 启动插件
func (p *SampleSecurityPlugin) Start(ctx context.Context) error {
	p.log.Info("Sample security plugin started")
	return nil
}

// Stop 停止插件
func (p *SampleSecurityPlugin) Stop(ctx context.Context) error {
	p.log.Info("Sample security plugin stopped")
	return nil
}

// IsEnabled 检查插件是否启用
func (p *SampleSecurityPlugin) IsEnabled() bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.enabled
}

// SetEnabled 设置插件启用状态
func (p *SampleSecurityPlugin) SetEnabled(enabled bool) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.enabled = enabled
	p.log.Infof("Plugin enabled status changed to: %t", enabled)
}

// GetConfig 获取插件配置
func (p *SampleSecurityPlugin) GetConfig() map[string]interface{} {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	result := make(map[string]interface{})
	for k, v := range p.config {
		result[k] = v
	}
	return result
}

// UpdateConfig 更新插件配置
func (p *SampleSecurityPlugin) UpdateConfig(config map[string]interface{}) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.config = config

	// 更新启用状态
	if enabled, ok := config["enabled"].(bool); ok {
		p.enabled = enabled
	}

	// 重新初始化规则
	p.initDefaultRules()

	p.log.Info("Plugin configuration updated")
	return nil
}

// GetHealth 获取插件健康状态
func (p *SampleSecurityPlugin) GetHealth() *plugin.PluginHealth {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	status := "healthy"
	message := "Plugin is running normally"

	// 简单的健康检查逻辑
	if !p.enabled {
		status = "disabled"
		message = "Plugin is disabled"
	}

	return &plugin.PluginHealth{
		Status:  status,
		Message: message,
		Details: map[string]interface{}{
			"requests_checked": p.stats.RequestsChecked,
			"threats_blocked":  p.stats.ThreatsBlocked,
			"false_positives":  p.stats.FalsePositives,
			"rules_count":      len(p.rules),
		},
		CheckedAt: time.Now(),
	}
}

// CheckRequest 检查请求安全性
func (p *SampleSecurityPlugin) CheckRequest(ctx context.Context, r *http.Request) (*plugin.SecurityResult, error) {
	if !p.enabled {
		return &plugin.SecurityResult{
			Allowed: true,
			Reason:  "Plugin disabled",
		}, nil
	}

	p.mutex.Lock()
	p.stats.RequestsChecked++
	p.stats.LastCheck = time.Now()
	p.mutex.Unlock()

	// 检查IP白名单
	clientIP := p.getClientIP(r)
	if p.isWhitelistedIP(clientIP) {
		return &plugin.SecurityResult{
			Allowed:    true,
			Risk:       "low",
			Reason:     "IP in whitelist",
			Confidence: 1.0,
		}, nil
	}

	// 检查各种攻击模式
	if result := p.checkSQLInjection(r); result != nil {
		p.mutex.Lock()
		p.stats.ThreatsBlocked++
		p.mutex.Unlock()
		return result, nil
	}

	if result := p.checkXSS(r); result != nil {
		p.mutex.Lock()
		p.stats.ThreatsBlocked++
		p.mutex.Unlock()
		return result, nil
	}

	if result := p.checkPathTraversal(r); result != nil {
		p.mutex.Lock()
		p.stats.ThreatsBlocked++
		p.mutex.Unlock()
		return result, nil
	}

	// 检查自定义模式
	if result := p.checkCustomPatterns(r); result != nil {
		p.mutex.Lock()
		p.stats.ThreatsBlocked++
		p.mutex.Unlock()
		return result, nil
	}

	return &plugin.SecurityResult{
		Allowed:    true,
		Risk:       "low",
		Reason:     "Request passed all security checks",
		Confidence: 0.9,
	}, nil
}

// ProcessAttack 处理攻击事件
func (p *SampleSecurityPlugin) ProcessAttack(ctx context.Context, attack *plugin.AttackEvent) error {
	p.log.WithFields(logrus.Fields{
		"attack_id":   attack.ID,
		"attack_type": attack.Type,
		"client_ip":   attack.ClientIP,
		"url":         attack.URL,
		"severity":    attack.Severity,
	}).Warn("Processing attack event")

	// 这里可以实现攻击事件的处理逻辑
	// 比如更新黑名单、发送通知等

	return nil
}

// GetSecurityRules 获取安全规则
func (p *SampleSecurityPlugin) GetSecurityRules() []plugin.SecurityRule {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	rules := make([]plugin.SecurityRule, len(p.rules))
	copy(rules, p.rules)
	return rules
}

// UpdateSecurityRules 更新安全规则
func (p *SampleSecurityPlugin) UpdateSecurityRules(rules []plugin.SecurityRule) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.rules = rules
	p.log.Infof("Updated %d security rules", len(rules))
	return nil
}

// initDefaultRules 初始化默认规则
func (p *SampleSecurityPlugin) initDefaultRules() {
	p.rules = []plugin.SecurityRule{
		{
			ID:       "sql_injection_basic",
			Name:     "基础SQL注入检测",
			Type:     "sql_injection",
			Pattern:  `(?i)(union.*select|select.*from|insert.*into|update.*set|delete.*from)`,
			Action:   "block",
			Priority: 100,
			Enabled:  true,
			Tags:     []string{"sql", "injection"},
			Conditions: map[string]interface{}{
				"check_url":    true,
				"check_body":   true,
				"check_params": true,
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:       "xss_basic",
			Name:     "基础XSS检测",
			Type:     "xss",
			Pattern:  `(?i)(<script|javascript:|on\w+\s*=)`,
			Action:   "block",
			Priority: 200,
			Enabled:  true,
			Tags:     []string{"xss", "script"},
			Conditions: map[string]interface{}{
				"check_url":    true,
				"check_body":   true,
				"check_params": true,
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
}

// checkSQLInjection 检查SQL注入
func (p *SampleSecurityPlugin) checkSQLInjection(r *http.Request) *plugin.SecurityResult {
	patterns := []string{
		`(?i)(union.*select|select.*from.*where)`,
		`(?i)(insert.*into.*values|update.*set.*where)`,
		`(?i)(drop\s+table|delete\s+from)`,
		`(?i)('.*'.*=.*'.*'|".*".*=.*".*")`,
	}

	for _, pattern := range patterns {
		if p.matchesPattern(r, pattern) {
			return &plugin.SecurityResult{
				Allowed:    false,
				Blocked:    true,
				Risk:       "high",
				Reason:     "SQL injection attempt detected",
				Actions:    []string{"block", "log"},
				Confidence: 0.85,
				Metadata: map[string]interface{}{
					"attack_type": "sql_injection",
					"pattern":     pattern,
				},
			}
		}
	}

	return nil
}

// checkXSS 检查XSS攻击
func (p *SampleSecurityPlugin) checkXSS(r *http.Request) *plugin.SecurityResult {
	patterns := []string{
		`(?i)<script.*?>.*?</script>`,
		`(?i)javascript:`,
		`(?i)on\w+\s*=`,
		`(?i)<(iframe|object|embed)`,
	}

	for _, pattern := range patterns {
		if p.matchesPattern(r, pattern) {
			return &plugin.SecurityResult{
				Allowed:    false,
				Blocked:    true,
				Risk:       "medium",
				Reason:     "XSS attack attempt detected",
				Actions:    []string{"block", "log"},
				Confidence: 0.8,
				Metadata: map[string]interface{}{
					"attack_type": "xss",
					"pattern":     pattern,
				},
			}
		}
	}

	return nil
}

// checkPathTraversal 检查路径遍历
func (p *SampleSecurityPlugin) checkPathTraversal(r *http.Request) *plugin.SecurityResult {
	patterns := []string{
		`\.\.\/`,
		`\.\.\\`,
		`%2e%2e%2f`,
		`%2e%2e%5c`,
	}

	for _, pattern := range patterns {
		if p.matchesPattern(r, pattern) {
			return &plugin.SecurityResult{
				Allowed:    false,
				Blocked:    true,
				Risk:       "high",
				Reason:     "Path traversal attempt detected",
				Actions:    []string{"block", "log"},
				Confidence: 0.9,
				Metadata: map[string]interface{}{
					"attack_type": "path_traversal",
					"pattern":     pattern,
				},
			}
		}
	}

	return nil
}

// checkCustomPatterns 检查自定义模式
func (p *SampleSecurityPlugin) checkCustomPatterns(r *http.Request) *plugin.SecurityResult {
	blockedPatterns, ok := p.config["blocked_patterns"].([]string)
	if !ok {
		return nil
	}

	for _, pattern := range blockedPatterns {
		if p.matchesPattern(r, pattern) {
			return &plugin.SecurityResult{
				Allowed:    false,
				Blocked:    true,
				Risk:       "medium",
				Reason:     "Custom pattern match detected",
				Actions:    []string{"block", "log"},
				Confidence: 0.7,
				Metadata: map[string]interface{}{
					"attack_type": "custom",
					"pattern":     pattern,
				},
			}
		}
	}

	return nil
}

// matchesPattern 检查请求是否匹配模式
func (p *SampleSecurityPlugin) matchesPattern(r *http.Request, pattern string) bool {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		p.log.Errorf("Invalid regex pattern: %s", pattern)
		return false
	}

	// 检查URL
	if regex.MatchString(r.URL.String()) {
		return true
	}

	// 检查URL参数
	for key, values := range r.URL.Query() {
		if regex.MatchString(key) {
			return true
		}
		for _, value := range values {
			if regex.MatchString(value) {
				return true
			}
		}
	}

	// 检查请求头
	for key, values := range r.Header {
		if regex.MatchString(key) {
			return true
		}
		for _, value := range values {
			if regex.MatchString(value) {
				return true
			}
		}
	}

	// 检查User-Agent
	if regex.MatchString(r.Header.Get("User-Agent")) {
		return true
	}

	return false
}

// getClientIP 获取客户端IP
func (p *SampleSecurityPlugin) getClientIP(r *http.Request) string {
	// 优先使用X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// 使用X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// 使用RemoteAddr
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}

	return r.RemoteAddr
}

// isWhitelistedIP 检查IP是否在白名单中
func (p *SampleSecurityPlugin) isWhitelistedIP(ip string) bool {
	whitelistIPs, ok := p.config["whitelist_ips"].([]string)
	if !ok {
		return false
	}

	for _, whiteIP := range whitelistIPs {
		if ip == whiteIP {
			return true
		}
	}

	return false
}

// 确保插件实现了所有必要的接口
var _ plugin.Plugin = (*SampleSecurityPlugin)(nil)
var _ plugin.SecurityPlugin = (*SampleSecurityPlugin)(nil)

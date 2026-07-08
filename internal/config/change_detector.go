package config

import (
	"fmt"
	"reflect"
	"strings"
)

// ChangeLevel 配置变更级别
type ChangeLevel int

const (
	// NoReloadNeeded 不需要重载（只记录日志）
	NoReloadNeeded ChangeLevel = 0

	// SoftReload 软重载（不中断连接，热更新）
	SoftReload ChangeLevel = 1

	// HardReload 硬重载（需要重启服务）
	HardReload ChangeLevel = 2
)

// String 返回变更级别的字符串表示
func (cl ChangeLevel) String() string {
	switch cl {
	case NoReloadNeeded:
		return "NoReloadNeeded"
	case SoftReload:
		return "SoftReload"
	case HardReload:
		return "HardReload"
	default:
		return "Unknown"
	}
}

// ConfigChange 配置变更信息
type ConfigChange struct {
	Field       string      // 变更的字段名
	OldValue    interface{} // 旧值
	NewValue    interface{} // 新值
	Level       ChangeLevel // 变更级别
	Description string      // 变更描述
}

// ChangeDetector 配置变更检测器
type ChangeDetector struct {
	changes []ConfigChange
}

// NewChangeDetector 创建配置变更检测器
func NewChangeDetector() *ChangeDetector {
	return &ChangeDetector{
		changes: make([]ConfigChange, 0),
	}
}

// DetectChanges 检测配置变更
func (cd *ChangeDetector) DetectChanges(oldConfig, newConfig *Config) []ConfigChange {
	cd.changes = make([]ConfigChange, 0)

	// 检测服务器配置变更
	cd.detectServerChanges(&oldConfig.Server, &newConfig.Server)

	// 检测SSL配置变更
	cd.detectSSLChanges(&oldConfig.SSL, &newConfig.SSL)

	// 检测代理规则变更
	cd.detectProxyChanges(&oldConfig.Proxy, &newConfig.Proxy)

	// 检测安全配置变更
	cd.detectSecurityChanges(&oldConfig.Security, &newConfig.Security)

	// 检测压缩配置变更
	cd.detectCompressionChanges(&oldConfig.Compression, &newConfig.Compression)

	// 检测日志配置变更
	cd.detectLoggingChanges(oldConfig, newConfig)

	// 检测监控配置变更
	cd.detectMonitoringChanges(&oldConfig.Monitoring, &newConfig.Monitoring)

	// 兜底检测未单独列出的配置段，避免漏字段导致运行时不重载
	cd.detectRemainingConfigChanges(oldConfig, newConfig)

	return cd.changes
}

// GetMaxChangeLevel 获取最高变更级别
func (cd *ChangeDetector) GetMaxChangeLevel() ChangeLevel {
	maxLevel := NoReloadNeeded
	for _, change := range cd.changes {
		if change.Level > maxLevel {
			maxLevel = change.Level
		}
	}
	return maxLevel
}

// detectServerChanges 检测服务器配置变更
func (cd *ChangeDetector) detectServerChanges(old, new *ServerConfig) {
	// 端口变更 - 硬重载
	if old.Port != new.Port {
		cd.addChange("Server.Port", old.Port, new.Port, HardReload, "服务器端口变更需要重启")
	}

	// 端口模式变更 - 硬重载
	if old.PortMode != new.PortMode {
		cd.addChange("Server.PortMode", old.PortMode, new.PortMode, HardReload, "端口模式变更需要重启")
	}

	// 自定义端口变更 - 硬重载
	if old.CustomPort != new.CustomPort {
		cd.addChange("Server.CustomPort", old.CustomPort, new.CustomPort, HardReload, "自定义端口变更需要重启")
	}

	// 调试模式变更 - 软重载
	if old.Debug != new.Debug {
		cd.addChange("Server.Debug", old.Debug, new.Debug, SoftReload, "调试模式变更")
	}

	// 日志级别变更 - 不需要重载
	if old.LogLevel != new.LogLevel {
		cd.addChange("Server.LogLevel", old.LogLevel, new.LogLevel, NoReloadNeeded, "日志级别变更")
	}

	// 访问日志配置变更 - 软重载
	if old.AccessLogEnabled != new.AccessLogEnabled {
		cd.addChange("Server.AccessLogEnabled", old.AccessLogEnabled, new.AccessLogEnabled, SoftReload, "访问日志开关变更")
	}
}

// detectSSLChanges 检测SSL配置变更
func (cd *ChangeDetector) detectSSLChanges(old, new *SSLConfig) {
	// Email变更 - 软重载
	if old.Email != new.Email {
		cd.addChange("SSL.Email", old.Email, new.Email, SoftReload, "SSL邮箱变更")
	}

	// 自动续期变更 - 软重载（比较生效值：省略字段默认为 true）
	if old.IsAutoRenewEnabled() != new.IsAutoRenewEnabled() {
		cd.addChange("SSL.AutoRenew", old.IsAutoRenewEnabled(), new.IsAutoRenewEnabled(), SoftReload, "SSL自动续期设置变更")
	}

	// DNS提供商变更 - 软重载
	if !reflect.DeepEqual(old.DNSProviders, new.DNSProviders) {
		cd.addChange("SSL.DNSProviders", len(old.DNSProviders), len(new.DNSProviders), SoftReload, "DNS提供商配置变更")
	}

	// 证书挑战方式变更 - 软重载
	if !reflect.DeepEqual(old.ChallengeMethods, new.ChallengeMethods) {
		cd.addChange("SSL.ChallengeMethods", old.ChallengeMethods, new.ChallengeMethods, SoftReload, "SSL证书挑战方式变更")
	}
}

// detectProxyChanges 检测代理规则变更
func (cd *ChangeDetector) detectProxyChanges(old, new *ProxyConfig) {
	// 代理规则变更 - 软重载
	if !reflect.DeepEqual(old.Rules, new.Rules) {
		cd.addChange("Proxy.Rules", len(old.Rules), len(new.Rules), SoftReload, "代理规则变更")
	}

	// 未匹配行为变更 - 软重载
	if old.UnmatchedBehavior != new.UnmatchedBehavior {
		cd.addChange("Proxy.UnmatchedBehavior", old.UnmatchedBehavior, new.UnmatchedBehavior, SoftReload, "未匹配行为变更")
	}
}

// detectSecurityChanges 检测安全配置变更
func (cd *ChangeDetector) detectSecurityChanges(old, new *SecurityConfig) {
	// 最大尝试次数变更 - 软重载
	if old.MaxAttempts != new.MaxAttempts {
		cd.addChange("Security.MaxAttempts", old.MaxAttempts, new.MaxAttempts, SoftReload, "最大尝试次数变更")
	}

	// 封禁时长变更 - 软重载
	if old.BlockDurationStr != new.BlockDurationStr {
		cd.addChange("Security.BlockDuration", old.BlockDurationStr, new.BlockDurationStr, SoftReload, "封禁时长变更")
	}

	// IP白名单变更 - 软重载
	if !reflect.DeepEqual(old.IPWhitelist, new.IPWhitelist) {
		cd.addChange("Security.IPWhitelist", len(old.IPWhitelist), len(new.IPWhitelist), SoftReload, "IP白名单变更")
	}

	// IP黑名单变更 - 软重载
	if !reflect.DeepEqual(old.IPBlacklist, new.IPBlacklist) {
		cd.addChange("Security.IPBlacklist", len(old.IPBlacklist), len(new.IPBlacklist), SoftReload, "IP黑名单变更")
	}

	// WAF开关变更 - 软重载
	if old.EnableWAF != new.EnableWAF {
		cd.addChange("Security.EnableWAF", old.EnableWAF, new.EnableWAF, SoftReload, "WAF开关变更")
	}

	// DDoS防护开关变更 - 软重载
	if old.EnableDDOS != new.EnableDDOS {
		cd.addChange("Security.EnableDDOS", old.EnableDDOS, new.EnableDDOS, SoftReload, "DDoS防护开关变更")
	}

	// 过老浏览器检测变更 - 软重载
	if old.OutdatedBrowser.Enabled != new.OutdatedBrowser.Enabled ||
		old.OutdatedBrowser.BlockVeryOutdated != new.OutdatedBrowser.BlockVeryOutdated {
		cd.addChange("Security.OutdatedBrowser", old.OutdatedBrowser, new.OutdatedBrowser, SoftReload, "过老浏览器检测配置变更")
	}
}

// detectCompressionChanges 检测压缩配置变更
func (cd *ChangeDetector) detectCompressionChanges(old, new *CompressionConfig) {
	// 压缩开关变更 - 软重载
	if old.Enabled != new.Enabled {
		cd.addChange("Compression.Enabled", old.Enabled, new.Enabled, SoftReload, "压缩开关变更")
	}

	// 压缩级别变更 - 软重载
	if old.Level.Gzip != new.Level.Gzip || old.Level.Brotli != new.Level.Brotli {
		cd.addChange("Compression.Level", old.Level, new.Level, SoftReload, "压缩级别变更")
	}

	// 最小压缩大小变更 - 软重载
	if old.MinSize != new.MinSize {
		cd.addChange("Compression.MinSize", old.MinSize, new.MinSize, SoftReload, "最小压缩大小变更")
	}
}

// detectLoggingChanges 检测日志配置变更
func (cd *ChangeDetector) detectLoggingChanges(old, new *Config) {
	// 日志级别在Server配置中已检测
	// 这里可以添加其他日志相关的检测
}

// detectMonitoringChanges 检测监控配置变更
func (cd *ChangeDetector) detectMonitoringChanges(old, new *MonitoringConfig) {
	// 监控开关变更 - 软重载
	if old.Enabled != new.Enabled {
		cd.addChange("Monitoring.Enabled", old.Enabled, new.Enabled, SoftReload, "监控开关变更")
	}
}

// detectRemainingConfigChanges 兜底检测未单独列出的配置段。
func (cd *ChangeDetector) detectRemainingConfigChanges(old, new *Config) {
	cd.addSectionChangeIfNeeded("Server", old.Server, new.Server, SoftReload, "服务器其他配置变更")
	cd.addSectionChangeIfNeeded("SSL", old.SSL, new.SSL, SoftReload, "SSL其他配置变更")
	cd.addSectionChangeIfNeeded("Proxy", old.Proxy, new.Proxy, SoftReload, "代理其他配置变更")
	cd.addSectionChangeIfNeeded("Security", old.Security, new.Security, SoftReload, "安全其他配置变更")
	cd.addSectionChangeIfNeeded("CDNCache", old.CDNCache, new.CDNCache, SoftReload, "CDN缓存配置变更")
	cd.addSectionChangeIfNeeded("Compression", old.Compression, new.Compression, SoftReload, "压缩其他配置变更")
	cd.addSectionChangeIfNeeded("Cluster", old.Cluster, new.Cluster, SoftReload, "集群配置变更")
	cd.addSectionChangeIfNeeded("StaticSites", old.StaticSites, new.StaticSites, SoftReload, "静态站点配置变更")
	cd.addSectionChangeIfNeeded("PHPSites", old.PHPSites, new.PHPSites, SoftReload, "PHP站点配置变更")
	cd.addSectionChangeIfNeeded("Runners", old.Runners, new.Runners, SoftReload, "Runner配置变更")
	cd.addSectionChangeIfNeeded("ThreatIntel", old.ThreatIntel, new.ThreatIntel, SoftReload, "威胁情报配置变更")
	cd.addSectionChangeIfNeeded("Notification", old.Notification, new.Notification, SoftReload, "通知配置变更")
	cd.addSectionChangeIfNeeded("UpstreamCache", old.UpstreamCache, new.UpstreamCache, SoftReload, "上游缓存配置变更")
	cd.addSectionChangeIfNeeded("AISecurity", old.AISecurity, new.AISecurity, SoftReload, "AI安全配置变更")
	cd.addSectionChangeIfNeeded("ImageOptimization", old.ImageOptimization, new.ImageOptimization, SoftReload, "图片优化配置变更")
	cd.addSectionChangeIfNeeded("Monitoring", old.Monitoring, new.Monitoring, SoftReload, "监控其他配置变更")
	cd.addSectionChangeIfNeeded("CacheWarmup", old.CacheWarmup, new.CacheWarmup, SoftReload, "缓存预热配置变更")
	cd.addSectionChangeIfNeeded("Report", old.Report, new.Report, SoftReload, "报告配置变更")
	cd.addSectionChangeIfNeeded("MCP", old.MCP, new.MCP, SoftReload, "MCP配置变更")
	cd.addSectionChangeIfNeeded("Admin", old.Admin, new.Admin, SoftReload, "管理员配置变更")
	cd.addSectionChangeIfNeeded("AdminPrefix", old.AdminPrefix, new.AdminPrefix, HardReload, "管理前缀变更需要重启")
	cd.addSectionChangeIfNeeded("BotAPIPrefix", old.BotAPIPrefix, new.BotAPIPrefix, HardReload, "机器人检测API前缀变更需要重启")
}

func (cd *ChangeDetector) addSectionChangeIfNeeded(field string, oldValue, newValue interface{}, level ChangeLevel, description string) {
	if reflect.DeepEqual(oldValue, newValue) || cd.hasChangeAtLeast(field, SoftReload) {
		return
	}
	cd.addChange(field, oldValue, newValue, level, description)
}

func (cd *ChangeDetector) hasChangeAtLeast(field string, minLevel ChangeLevel) bool {
	for _, change := range cd.changes {
		if change.Level < minLevel {
			continue
		}
		if change.Field == field || strings.HasPrefix(change.Field, field+".") {
			return true
		}
	}
	return false
}

// addChange 添加配置变更记录
func (cd *ChangeDetector) addChange(field string, oldValue, newValue interface{}, level ChangeLevel, description string) {
	cd.changes = append(cd.changes, ConfigChange{
		Field:       field,
		OldValue:    oldValue,
		NewValue:    newValue,
		Level:       level,
		Description: description,
	})
}

// ValidateConfig 验证配置的合法性
func ValidateConfig(cfg *Config) []error {
	errors := make([]error, 0)

	// 验证服务器配置
	if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
		errors = append(errors, fmt.Errorf("invalid server port: %d (must be 1-65535)", cfg.Server.Port))
	}

	if cfg.Server.CustomPort != 0 {
		if cfg.Server.CustomPort < 1 || cfg.Server.CustomPort > 65535 {
			errors = append(errors, fmt.Errorf("invalid custom port: %d (must be 1-65535)", cfg.Server.CustomPort))
		}
	}

	// 验证SSL配置
	if !cfg.SSL.DisableSelfSigned && cfg.SSL.Email == "" {
		errors = append(errors, fmt.Errorf("SSL email is required when self-signed certificates are disabled"))
	}

	// 验证代理规则
	for i, rule := range cfg.Proxy.Rules {
		if rule.Domain == "" {
			errors = append(errors, fmt.Errorf("proxy rule %d: domain cannot be empty", i))
		}
		if rule.Target == "" && len(rule.Backends) == 0 {
			errors = append(errors, fmt.Errorf("proxy rule %d: must have either target or backends", i))
		}
	}

	// 验证安全配置
	if cfg.Security.MaxAttempts < 1 {
		errors = append(errors, fmt.Errorf("invalid max_attempts: %d (must be >= 1)", cfg.Security.MaxAttempts))
	}

	// 验证压缩配置
	if cfg.Compression.Enabled {
		if cfg.Compression.Level.Gzip < -3 || cfg.Compression.Level.Gzip > 9 {
			errors = append(errors, fmt.Errorf("invalid gzip level: %d (must be -3 to 9)", cfg.Compression.Level.Gzip))
		}
		if cfg.Compression.Level.Brotli < 0 || cfg.Compression.Level.Brotli > 11 {
			errors = append(errors, fmt.Errorf("invalid brotli level: %d (must be 0 to 11)", cfg.Compression.Level.Brotli))
		}
	}

	return errors
}

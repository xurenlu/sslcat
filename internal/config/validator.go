package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// ValidationResult 验证结果
type ValidationResult struct {
	Valid    bool                `json:"valid"`
	Errors   []ValidationError   `json:"errors"`
	Warnings []ValidationWarning `json:"warnings"`
	Info     []ValidationInfo    `json:"info"`
	Summary  ValidationSummary   `json:"summary"`
}

// ValidationError 验证错误
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   string `json:"value"`
}

// ValidationWarning 验证警告
type ValidationWarning struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   string `json:"value"`
}

// ValidationInfo 验证信息
type ValidationInfo struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   string `json:"value"`
}

// ValidationSummary 验证摘要
type ValidationSummary struct {
	TotalRules         int    `json:"total_rules"`
	LoadBalancerRules  int    `json:"load_balancer_rules"`
	SingleBackendRules int    `json:"single_backend_rules"`
	TotalBackends      int    `json:"total_backends"`
	HealthCheckEnabled int    `json:"health_check_enabled"`
	CompressionEnabled bool   `json:"compression_enabled"`
	CDNCacheEnabled    bool   `json:"cdn_cache_enabled"`
	SSLEmail           string `json:"ssl_email"`
	AdminPrefix        string `json:"admin_prefix"`
}

// ConfigValidator 配置验证器
type ConfigValidator struct {
	result *ValidationResult
}

// NewConfigValidator 创建配置验证器
func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{
		result: &ValidationResult{
			Valid:    true,
			Errors:   make([]ValidationError, 0),
			Warnings: make([]ValidationWarning, 0),
			Info:     make([]ValidationInfo, 0),
		},
	}
}

// ValidateConfig 验证配置
func (v *ConfigValidator) ValidateConfig(cfg *Config) *ValidationResult {
	// 重置结果
	v.result = &ValidationResult{
		Valid:    true,
		Errors:   make([]ValidationError, 0),
		Warnings: make([]ValidationWarning, 0),
		Info:     make([]ValidationInfo, 0),
	}

	// 验证服务器配置
	v.validateServerConfig(&cfg.Server)

	// 验证SSL配置
	v.validateSSLConfig(&cfg.SSL)

	// 验证管理员配置
	v.validateAdminConfig(&cfg.Admin)

	// 验证代理配置
	v.validateProxyConfig(&cfg.Proxy)

	// 验证安全配置
	v.validateSecurityConfig(&cfg.Security)

	// 验证压缩配置
	v.validateCompressionConfig(&cfg.Compression)

	// 验证CDN缓存配置
	v.validateCDNCacheConfig(&cfg.CDNCache)

	// 生成摘要
	v.generateSummary(cfg)

	// 如果有错误，标记为无效
	if len(v.result.Errors) > 0 {
		v.result.Valid = false
	}

	return v.result
}

// validateServerConfig 验证服务器配置
func (v *ConfigValidator) validateServerConfig(cfg *ServerConfig) {
	// 验证端口
	if cfg.Port <= 0 || cfg.Port > 65535 {
		v.addError("server.port", "端口必须在1-65535之间", strconv.Itoa(cfg.Port))
	}

	// 验证主机地址
	if cfg.Host == "" {
		v.addError("server.host", "主机地址不能为空", cfg.Host)
	}

	// 验证超时配置
	if cfg.ReadTimeoutSec < 0 {
		v.addWarning("server.read_timeout_sec", "读取超时不应为负数", strconv.Itoa(cfg.ReadTimeoutSec))
	}

	if cfg.WriteTimeoutSec < 0 {
		v.addWarning("server.write_timeout_sec", "写入超时不应为负数", strconv.Itoa(cfg.WriteTimeoutSec))
	}

	// 建议配置
	if cfg.MaxUploadBytes == 0 {
		v.addInfo("server.max_upload_bytes", "建议设置最大上传大小限制", "0")
	}
}

// validateSSLConfig 验证SSL配置
func (v *ConfigValidator) validateSSLConfig(cfg *SSLConfig) {
	// 验证邮箱
	if cfg.Email == "" {
		v.addError("ssl.email", "SSL证书邮箱不能为空", cfg.Email)
	} else if !strings.Contains(cfg.Email, "@") {
		v.addError("ssl.email", "SSL证书邮箱格式不正确", cfg.Email)
	}

	// 验证证书目录
	if cfg.CertDir == "" {
		v.addWarning("ssl.cert_dir", "建议设置证书目录", cfg.CertDir)
	}

	if cfg.KeyDir == "" {
		v.addWarning("ssl.key_dir", "建议设置密钥目录", cfg.KeyDir)
	}

	// 检查目录是否存在（如果配置了）
	if cfg.CertDir != "" {
		if _, err := os.Stat(cfg.CertDir); os.IsNotExist(err) {
			v.addWarning("ssl.cert_dir", "证书目录不存在，将自动创建", cfg.CertDir)
		}
	}
}

// validateAdminConfig 验证管理员配置
func (v *ConfigValidator) validateAdminConfig(cfg *AdminConfig) {
	// 验证用户名
	if cfg.Username == "" {
		v.addError("admin.username", "管理员用户名不能为空", cfg.Username)
	}

	// 验证密码文件
	if cfg.PasswordFile == "" {
		v.addWarning("admin.password_file", "建议设置密码文件路径", cfg.PasswordFile)
	}

	// TOTP配置检查
	if cfg.EnableTOTP && cfg.TOTPSecretFile == "" {
		v.addWarning("admin.totp_secret_file", "启用TOTP时建议设置密钥文件", cfg.TOTPSecretFile)
	}
}

// validateProxyConfig 验证代理配置
func (v *ConfigValidator) validateProxyConfig(cfg *ProxyConfig) {
	if len(cfg.Rules) == 0 {
		v.addWarning("proxy.rules", "没有配置代理规则", "0")
		return
	}

	// 验证每个代理规则
	for i, rule := range cfg.Rules {
		v.validateProxyRule(&rule, i)
	}
}

// validateProxyRule 验证单个代理规则
func (v *ConfigValidator) validateProxyRule(rule *ProxyRule, index int) {
	prefix := fmt.Sprintf("proxy.rules[%d]", index)

	// 验证域名
	if rule.Domain == "" {
		v.addError(prefix+".domain", "域名不能为空", rule.Domain)
	}

	// 使用统一的后端验证
	effectiveBackends := rule.GetEffectiveBackends()
	if len(effectiveBackends) == 0 {
		v.addError(prefix+".backends", "至少需要一个后端服务器", "0")
		return
	}

	// 验证后端服务器
	enabledBackends := 0
	hasHTTPSURLBackend := false
	for j, backend := range effectiveBackends {
		v.validateBackend(&backend, prefix, j)
		if backend.Enabled {
			enabledBackends++
		}
		// 检查是否为HTTPS URL后端（非IP地址）
		if v.isHTTPSURL(backend.Host) {
			hasHTTPSURLBackend = true
		}
	}

	if enabledBackends == 0 {
		v.addError(prefix+".backends", "至少需要一个启用的后端服务器", strconv.Itoa(enabledBackends))
	}

	// 如果存在HTTPS URL后端，限制只能配置一个后端
	if hasHTTPSURLBackend && len(effectiveBackends) > 1 {
		v.addError(prefix+".backends", "HTTPS URL后端仅支持单后端配置，不支持负载均衡", fmt.Sprintf("%d backends", len(effectiveBackends)))
		return // 提前返回，避免继续验证负载均衡相关配置
	}

	// 验证负载均衡算法（多后端时）
	if len(effectiveBackends) > 1 {
		validAlgorithms := []string{"round_robin", "weighted_round_robin", "least_conn", "ip_hash", "random", "consistent_hash"}
		if !v.contains(validAlgorithms, rule.LoadBalancerAlgorithm) {
			v.addError(prefix+".load_balancer_algorithm", "不支持的负载均衡算法", rule.LoadBalancerAlgorithm)
		}

		// 会话保持配置验证
		if rule.SessionAffinityEnabled {
			v.validateSessionAffinity(rule, prefix)
		}
	}

	// 健康检查配置验证
	if rule.HealthCheckEnabled {
		v.validateHealthCheck(rule, prefix)
	}
}

// validateBackend 验证后端服务器配置
func (v *ConfigValidator) validateBackend(backend *ProxyBackend, rulePrefix string, index int) {
	prefix := fmt.Sprintf("%s.load_balancer_backends[%d]", rulePrefix, index)

	// 验证主机地址
	if backend.Host == "" {
		v.addError(prefix+".host", "后端主机地址不能为空", backend.Host)
	} else if !v.isValidHostOrIP(backend.Host) {
		v.addWarning(prefix+".host", "主机地址格式可能不正确", backend.Host)
	}

	// 验证端口
	if backend.Port <= 0 || backend.Port > 65535 {
		v.addError(prefix+".port", "端口必须在1-65535之间", strconv.Itoa(backend.Port))
	}

	// 验证权重
	if backend.Weight < 0 {
		v.addError(prefix+".weight", "权重不能为负数", strconv.Itoa(backend.Weight))
	} else if backend.Weight == 0 {
		v.addInfo(prefix+".weight", "权重为0将使用默认值1", strconv.Itoa(backend.Weight))
	}

	// 验证连接限制
	if backend.MaxConnections < 0 {
		v.addError(prefix+".max_connections", "最大连接数不能为负数", strconv.Itoa(backend.MaxConnections))
	}

	// 健康检查配置
	if backend.HealthCheckEnabled {
		if backend.HealthCheckPath == "" {
			v.addInfo(prefix+".health_check_path", "健康检查路径为空，将使用默认值'/'", backend.HealthCheckPath)
		}

		if backend.ExpectedStatusCode <= 0 {
			v.addInfo(prefix+".expected_status_code", "期望状态码为0，将使用默认值200", strconv.Itoa(backend.ExpectedStatusCode))
		}
	}
}

// validateSessionAffinity 验证会话保持配置
func (v *ConfigValidator) validateSessionAffinity(rule *ProxyRule, prefix string) {
	switch rule.SessionAffinityMethod {
	case "cookie":
		if rule.SessionAffinityCookie == "" {
			v.addError(prefix+".session_affinity_cookie", "使用Cookie会话保持时必须指定Cookie名称", rule.SessionAffinityCookie)
		}
	case "header":
		if rule.SessionAffinityHeader == "" {
			v.addError(prefix+".session_affinity_header", "使用Header会话保持时必须指定Header名称", rule.SessionAffinityHeader)
		}
	case "ip":
		// IP方式不需要额外配置
	case "":
		v.addInfo(prefix+".session_affinity_method", "会话保持方法为空，将使用默认值'ip'", rule.SessionAffinityMethod)
	default:
		v.addError(prefix+".session_affinity_method", "不支持的会话保持方法", rule.SessionAffinityMethod)
	}

	if rule.SessionAffinityTTL <= 0 {
		v.addInfo(prefix+".session_affinity_ttl", "会话保持TTL为0，将使用默认值3600秒", strconv.Itoa(rule.SessionAffinityTTL))
	}
}

// validateHealthCheck 验证健康检查配置
func (v *ConfigValidator) validateHealthCheck(rule *ProxyRule, prefix string) {
	if rule.HealthCheckInterval <= 0 {
		v.addInfo(prefix+".health_check_interval", "健康检查间隔为0，将使用默认值30秒", strconv.Itoa(rule.HealthCheckInterval))
	} else if rule.HealthCheckInterval < 5 {
		v.addWarning(prefix+".health_check_interval", "健康检查间隔过短可能影响性能", strconv.Itoa(rule.HealthCheckInterval))
	}

	if rule.HealthCheckTimeout <= 0 {
		v.addInfo(prefix+".health_check_timeout", "健康检查超时为0，将使用默认值5秒", strconv.Itoa(rule.HealthCheckTimeout))
	} else if rule.HealthCheckTimeout >= rule.HealthCheckInterval {
		v.addWarning(prefix+".health_check_timeout", "健康检查超时不应大于等于检查间隔", strconv.Itoa(rule.HealthCheckTimeout))
	}

	// 验证HTTP方法
	validMethods := []string{"GET", "HEAD", "POST", "PUT", "PATCH"}
	if rule.HealthCheckMethod != "" && !v.contains(validMethods, strings.ToUpper(rule.HealthCheckMethod)) {
		v.addWarning(prefix+".health_check_method", "不常见的HTTP方法", rule.HealthCheckMethod)
	}
}

// validateSecurityConfig 验证安全配置
func (v *ConfigValidator) validateSecurityConfig(cfg *SecurityConfig) {
	// 验证最大尝试次数
	if cfg.MaxAttempts <= 0 {
		v.addWarning("security.max_attempts", "最大尝试次数应大于0", strconv.Itoa(cfg.MaxAttempts))
	} else if cfg.MaxAttempts > 100 {
		v.addWarning("security.max_attempts", "最大尝试次数过大可能影响安全性", strconv.Itoa(cfg.MaxAttempts))
	}

	// 验证封禁时长
	if cfg.BlockDurationStr == "" {
		v.addWarning("security.block_duration", "建议设置封禁时长", cfg.BlockDurationStr)
	}

	// 注意：IP白名单和黑名单功能需要在SecurityConfig中添加相应字段
	// 当前SecurityConfig中没有IPWhitelist和IPBlacklist字段
	// 这是一个待实现的功能
}

// validateCompressionConfig 验证压缩配置
func (v *ConfigValidator) validateCompressionConfig(cfg *CompressionConfig) {
	if !cfg.Enabled {
		v.addInfo("compression.enabled", "压缩功能已禁用", "false")
		return
	}

	// 验证算法
	validAlgorithms := []string{"br", "brotli", "gzip", "deflate"}
	for i, alg := range cfg.Algorithms {
		if !v.contains(validAlgorithms, strings.ToLower(alg)) {
			v.addError(fmt.Sprintf("compression.algorithms[%d]", i), "不支持的压缩算法", alg)
		}
	}

	// 验证最小文件大小
	if cfg.MinSize < 0 {
		v.addError("compression.min_size", "最小文件大小不能为负数", strconv.FormatInt(cfg.MinSize, 10))
	} else if cfg.MinSize < 100 {
		v.addWarning("compression.min_size", "最小文件大小过小可能影响性能", strconv.FormatInt(cfg.MinSize, 10))
	}

	// 验证压缩级别
	if cfg.Level.Gzip < -3 || cfg.Level.Gzip > 9 {
		v.addError("compression.level.gzip", "Gzip压缩级别必须在-3到9之间", strconv.Itoa(cfg.Level.Gzip))
	}

	if cfg.Level.Brotli < 0 || cfg.Level.Brotli > 11 {
		v.addError("compression.level.brotli", "Brotli压缩级别必须在0到11之间", strconv.Itoa(cfg.Level.Brotli))
	}
}

// validateCDNCacheConfig 验证CDN缓存配置
func (v *ConfigValidator) validateCDNCacheConfig(cfg *CDNCacheConfig) {
	if !cfg.Enabled {
		v.addInfo("cdn_cache.enabled", "CDN缓存功能已禁用", "false")
		return
	}

	// 验证缓存目录
	if cfg.CacheDir == "" {
		v.addWarning("cdn_cache.cache_dir", "建议设置缓存目录", cfg.CacheDir)
	}

	// 验证最大缓存大小
	if cfg.MaxSizeBytes <= 0 {
		v.addWarning("cdn_cache.max_size_bytes", "建议设置最大缓存大小", strconv.FormatInt(cfg.MaxSizeBytes, 10))
	}

	// 验证默认TTL
	if cfg.DefaultTTLSeconds <= 0 {
		v.addInfo("cdn_cache.default_ttl_seconds", "默认TTL为0，将使用系统默认值", strconv.Itoa(cfg.DefaultTTLSeconds))
	}
}

// generateSummary 生成验证摘要
func (v *ConfigValidator) generateSummary(cfg *Config) {
	summary := ValidationSummary{
		TotalRules:         len(cfg.Proxy.Rules),
		CompressionEnabled: cfg.Compression.Enabled,
		CDNCacheEnabled:    cfg.CDNCache.Enabled,
		SSLEmail:           cfg.SSL.Email,
		AdminPrefix:        cfg.AdminPrefix,
	}

	// 统计负载均衡和后端数量
	for _, rule := range cfg.Proxy.Rules {
		if rule.LoadBalancerEnabled {
			summary.LoadBalancerRules++
			summary.TotalBackends += len(rule.LoadBalancerBackends)
		} else {
			summary.SingleBackendRules++
		}

		if rule.HealthCheckEnabled {
			summary.HealthCheckEnabled++
		}
	}

	v.result.Summary = summary
}

// 辅助方法
func (v *ConfigValidator) addError(field, message, value string) {
	v.result.Errors = append(v.result.Errors, ValidationError{
		Field:   field,
		Message: message,
		Value:   value,
	})
}

func (v *ConfigValidator) addWarning(field, message, value string) {
	v.result.Warnings = append(v.result.Warnings, ValidationWarning{
		Field:   field,
		Message: message,
		Value:   value,
	})
}

func (v *ConfigValidator) addInfo(field, message, value string) {
	v.result.Info = append(v.result.Info, ValidationInfo{
		Field:   field,
		Message: message,
		Value:   value,
	})
}

func (v *ConfigValidator) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// isHTTPSURL 检查后端主机是否为HTTPS URL（非IP地址）
func (v *ConfigValidator) isHTTPSURL(host string) bool {
	// 检查是否以 https:// 开头
	if !strings.HasPrefix(strings.ToLower(host), "https://") {
		return false
	}
	
	// 解析URL
	parsedURL, err := url.Parse(host)
	if err != nil {
		return false
	}
	
	// 提取主机名（去除端口）
	hostname := parsedURL.Hostname()
	if hostname == "" {
		return false
	}
	
	// 检查主机名是否为IP地址
	return net.ParseIP(hostname) == nil
}

func (v *ConfigValidator) isValidHostOrIP(host string) bool {
	// 检查是否为有效的IP地址
	if net.ParseIP(host) != nil {
		return true
	}

	// 检查是否为有效的域名格式
	if len(host) == 0 || len(host) > 253 {
		return false
	}

	// 简单的域名格式检查
	if strings.Contains(host, "..") || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}

	return true
}

func (v *ConfigValidator) isValidIPOrCIDR(ipOrCIDR string) bool {
	// 检查是否为单个IP地址
	if net.ParseIP(ipOrCIDR) != nil {
		return true
	}

	// 检查是否为CIDR格式
	_, _, err := net.ParseCIDR(ipOrCIDR)
	return err == nil
}

// ValidateConfigFile 验证配置文件
func ValidateConfigFile(configFile string) (*ValidationResult, error) {
	// 检查文件是否存在
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return &ValidationResult{
			Valid: false,
			Errors: []ValidationError{
				{
					Field:   "config_file",
					Message: "配置文件不存在",
					Value:   configFile,
				},
			},
		}, nil
	}

	// 加载配置
	cfg, err := Load(configFile)
	if err != nil {
		return &ValidationResult{
			Valid: false,
			Errors: []ValidationError{
				{
					Field:   "config_file",
					Message: "配置文件解析失败: " + err.Error(),
					Value:   configFile,
				},
			},
		}, nil
	}

	// 验证配置
	validator := NewConfigValidator()
	return validator.ValidateConfig(cfg), nil
}

// PrintValidationResult 打印验证结果
func PrintValidationResult(result *ValidationResult, configFile string) {
	fmt.Printf("📋 配置文件验证结果: %s\n", configFile)
	fmt.Println("=" + strings.Repeat("=", 50))

	if result.Valid {
		fmt.Println("✅ 配置文件验证通过")
	} else {
		fmt.Println("❌ 配置文件验证失败")
	}

	fmt.Println()

	// 打印摘要
	fmt.Println("📊 配置摘要:")
	fmt.Printf("   代理规则总数: %d\n", result.Summary.TotalRules)
	fmt.Printf("   负载均衡规则: %d\n", result.Summary.LoadBalancerRules)
	fmt.Printf("   单后端规则: %d\n", result.Summary.SingleBackendRules)
	fmt.Printf("   后端服务器总数: %d\n", result.Summary.TotalBackends)
	fmt.Printf("   启用健康检查: %d\n", result.Summary.HealthCheckEnabled)
	fmt.Printf("   压缩功能: %v\n", result.Summary.CompressionEnabled)
	fmt.Printf("   CDN缓存: %v\n", result.Summary.CDNCacheEnabled)
	fmt.Printf("   SSL邮箱: %s\n", result.Summary.SSLEmail)
	fmt.Printf("   管理面板前缀: %s\n", result.Summary.AdminPrefix)
	fmt.Println()

	// 打印错误
	if len(result.Errors) > 0 {
		fmt.Printf("❌ 错误 (%d):\n", len(result.Errors))
		for _, err := range result.Errors {
			fmt.Printf("   %s: %s (值: %s)\n", err.Field, err.Message, err.Value)
		}
		fmt.Println()
	}

	// 打印警告
	if len(result.Warnings) > 0 {
		fmt.Printf("⚠️  警告 (%d):\n", len(result.Warnings))
		for _, warn := range result.Warnings {
			fmt.Printf("   %s: %s (值: %s)\n", warn.Field, warn.Message, warn.Value)
		}
		fmt.Println()
	}

	// 打印信息
	if len(result.Info) > 0 {
		fmt.Printf("💡 信息 (%d):\n", len(result.Info))
		for _, info := range result.Info {
			fmt.Printf("   %s: %s (值: %s)\n", info.Field, info.Message, info.Value)
		}
		fmt.Println()
	}

	// 打印建议
	if result.Valid {
		fmt.Println("🎯 建议:")
		fmt.Println("   1. 定期备份配置文件")
		fmt.Println("   2. 监控后端服务器健康状态")
		fmt.Println("   3. 根据访问模式调整缓存策略")
		fmt.Println("   4. 启用压缩功能以提升性能")
	} else {
		fmt.Println("🔧 修复建议:")
		fmt.Println("   1. 修复上述错误后重新验证")
		fmt.Println("   2. 参考示例配置文件")
		fmt.Println("   3. 查看详细文档获取帮助")
	}
}

package web

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

// PHPOptimizer PHP 性能优化器
type PHPOptimizer struct {
	config *config.Config
	log    *logrus.Entry
}

// NewPHPOptimizer 创建 PHP 优化器
func NewPHPOptimizer(cfg *config.Config) *PHPOptimizer {
	return &PHPOptimizer{
		config: cfg,
		log:    logrus.WithFields(logrus.Fields{"component": "php_optimizer"}),
	}
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

// GetOptimizationConfig 获取优化配置
func (po *PHPOptimizer) GetOptimizationConfig(domain string) (*PHPOptimizationConfig, error) {
	// 查找对应的 PHP 站点
	var site *config.PHPSite
	for i := range po.config.PHPSites {
		if strings.EqualFold(po.config.PHPSites[i].Domain, domain) {
			site = &po.config.PHPSites[i]
			break
		}
	}

	if site == nil {
		return nil, fmt.Errorf("PHP site not found for domain: %s", domain)
	}

	// 检测远程环境
	remoteDetector := NewPHPRemoteDetector(po.config)
	envInfo, err := remoteDetector.DetectRemoteEnvironment(site)
	if err != nil {
		po.log.Errorf("检测远程环境失败: %v", err)
	}

	// 从站点配置中读取优化设置
	config := &PHPOptimizationConfig{
		OPcacheEnabled:            true,
		OPcacheMemorySize:         128,
		OPcacheMaxFiles:           10000,
		OPcacheValidateTimestamps: false,
		EnableGzipCompression:     true,
		EnableStaticCaching:       true,
		CacheTTL:                  3600,
		HidePHPVersion:            true,
		DisableDangerousFunctions: true,
		LaravelOptimizations:      false,
		SymfonyOptimizations:      false,
	}

	// 如果站点有自定义优化配置，则使用
	if site.OptimizationConfig != nil {
		// 转换配置类型
		config.OPcacheEnabled = site.OptimizationConfig.OPcacheEnabled
		config.OPcacheMemorySize = site.OptimizationConfig.OPcacheMemorySize
		config.OPcacheMaxFiles = site.OptimizationConfig.OPcacheMaxFiles
		config.OPcacheValidateTimestamps = site.OptimizationConfig.OPcacheValidateTimestamps
		config.EnableGzipCompression = site.OptimizationConfig.EnableGzipCompression
		config.EnableStaticCaching = site.OptimizationConfig.EnableStaticCaching
		config.CacheTTL = site.OptimizationConfig.CacheTTL
		config.HidePHPVersion = site.OptimizationConfig.HidePHPVersion
		config.DisableDangerousFunctions = site.OptimizationConfig.DisableDangerousFunctions
		config.LaravelOptimizations = site.OptimizationConfig.LaravelOptimizations
		config.SymfonyOptimizations = site.OptimizationConfig.SymfonyOptimizations
	}

	// 如果是远程环境，禁用某些功能
	if err == nil && envInfo.IsRemote {
		po.log.Warnf("远程环境检测到，某些优化功能将被禁用: %s", domain)
		config.LaravelOptimizations = false
		config.SymfonyOptimizations = false
	}

	return config, nil
}

// GenerateOPcacheConfig 生成 OPcache 配置
func (po *PHPOptimizer) GenerateOPcacheConfig(domain string) (string, error) {
	config, err := po.GetOptimizationConfig(domain)
	if err != nil {
		return "", err
	}

	opcacheConfig := fmt.Sprintf(`
; OPcache 配置 - 为 %s 生成
opcache.enable=1
opcache.enable_cli=1
opcache.memory_consumption=%d
opcache.interned_strings_buffer=8
opcache.max_accelerated_files=%d
opcache.revalidate_freq=0
opcache.validate_timestamps=%d
opcache.save_comments=1
opcache.fast_shutdown=1
opcache.enable_file_override=1
opcache.optimization_level=0x7FFFBFFF
opcache.max_wasted_percentage=10
opcache.use_cwd=1
opcache.validate_permission=1
opcache.validate_root=1
opcache.file_update_protection=2
opcache.huge_code_pages=1
`, domain, config.OPcacheMemorySize, config.OPcacheMaxFiles,
		boolToInt(config.OPcacheValidateTimestamps))

	return opcacheConfig, nil
}

// GeneratePHPIni 生成优化的 PHP.ini 配置
func (po *PHPOptimizer) GeneratePHPIni(domain string) (string, error) {
	config, err := po.GetOptimizationConfig(domain)
	if err != nil {
		return "", err
	}

	phpIni := fmt.Sprintf(`
; PHP 优化配置 - 为 %s 生成
; 性能优化
max_execution_time=30
max_input_time=60
memory_limit=256M
post_max_size=64M
upload_max_filesize=64M
max_file_uploads=20

; 安全设置
expose_php=%s
allow_url_fopen=Off
allow_url_include=Off
auto_prepend_file=
auto_append_file=

; 错误处理
display_errors=Off
log_errors=On
error_log=/var/log/php_errors.log
error_reporting=E_ALL & ~E_DEPRECATED & ~E_STRICT

; 会话安全
session.cookie_httponly=1
session.cookie_secure=1
session.use_strict_mode=1

; 禁用危险函数
%s

; 压缩设置
zlib.output_compression=%s
zlib.output_compression_level=6

; 时区设置
date.timezone=Asia/Shanghai
`, domain,
		boolToString(!config.HidePHPVersion),
		po.getDisabledFunctions(config.DisableDangerousFunctions),
		boolToString(config.EnableGzipCompression))

	return phpIni, nil
}

// ApplyFrameworkOptimizations 应用框架特定优化
func (po *PHPOptimizer) ApplyFrameworkOptimizations(domain string, frameworks []string) error {
	config, err := po.GetOptimizationConfig(domain)
	if err != nil {
		return err
	}

	for _, framework := range frameworks {
		switch framework {
		case "laravel":
			if config.LaravelOptimizations {
				err := po.applyLaravelOptimizations(domain)
				if err != nil {
					po.log.Errorf("应用 Laravel 优化失败: %v", err)
				}
			}
		case "symfony":
			if config.SymfonyOptimizations {
				err := po.applySymfonyOptimizations(domain)
				if err != nil {
					po.log.Errorf("应用 Symfony 优化失败: %v", err)
				}
			}
		}
	}

	return nil
}

// applyLaravelOptimizations 应用 Laravel 优化
func (po *PHPOptimizer) applyLaravelOptimizations(domain string) error {
	// 查找 Laravel 项目路径
	var site *config.PHPSite
	for i := range po.config.PHPSites {
		if strings.EqualFold(po.config.PHPSites[i].Domain, domain) {
			site = &po.config.PHPSites[i]
			break
		}
	}

	if site == nil {
		return fmt.Errorf("PHP site not found for domain: %s", domain)
	}

	// 生成 Laravel 优化配置
	optimizations := []string{
		"# Laravel 优化配置",
		"# 1. 启用路由缓存",
		"php artisan route:cache",
		"# 2. 启用配置缓存",
		"php artisan config:cache",
		"# 3. 启用视图缓存",
		"php artisan view:cache",
		"# 4. 启用事件缓存",
		"php artisan event:cache",
		"# 5. 优化 Composer 自动加载",
		"composer dump-autoload --optimize --no-dev",
	}

	// 写入优化脚本
	scriptPath := filepath.Join(site.Root, "optimize.sh")
	scriptContent := strings.Join(optimizations, "\n")

	err := os.WriteFile(scriptPath, []byte(scriptContent), 0755)
	if err != nil {
		return fmt.Errorf("写入 Laravel 优化脚本失败: %v", err)
	}

	po.log.Infof("Laravel 优化脚本已生成: %s", scriptPath)
	return nil
}

// applySymfonyOptimizations 应用 Symfony 优化
func (po *PHPOptimizer) applySymfonyOptimizations(domain string) error {
	// 查找 Symfony 项目路径
	var site *config.PHPSite
	for i := range po.config.PHPSites {
		if strings.EqualFold(po.config.PHPSites[i].Domain, domain) {
			site = &po.config.PHPSites[i]
			break
		}
	}

	if site == nil {
		return fmt.Errorf("PHP site not found for domain: %s", domain)
	}

	// 生成 Symfony 优化配置
	optimizations := []string{
		"# Symfony 优化配置",
		"# 1. 清除缓存",
		"php bin/console cache:clear --env=prod",
		"# 2. 预热缓存",
		"php bin/console cache:warmup --env=prod",
		"# 3. 优化 Composer 自动加载",
		"composer dump-autoload --optimize --no-dev --classmap-authoritative",
	}

	// 写入优化脚本
	scriptPath := filepath.Join(site.Root, "optimize.sh")
	scriptContent := strings.Join(optimizations, "\n")

	err := os.WriteFile(scriptPath, []byte(scriptContent), 0755)
	if err != nil {
		return fmt.Errorf("写入 Symfony 优化脚本失败: %v", err)
	}

	po.log.Infof("Symfony 优化脚本已生成: %s", scriptPath)
	return nil
}

// GetPerformanceMetrics 获取性能指标
func (po *PHPOptimizer) GetPerformanceMetrics(domain string) (map[string]interface{}, error) {
	// 这里可以集成 APM 工具或监控系统
	metrics := map[string]interface{}{
		"domain":         domain,
		"timestamp":      time.Now().Unix(),
		"opcache_hits":   0,
		"opcache_misses": 0,
		"memory_usage":   0,
		"execution_time": 0,
		"request_count":  0,
		"error_count":    0,
	}

	return metrics, nil
}

// 辅助函数
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func boolToString(b bool) string {
	if b {
		return "On"
	}
	return "Off"
}

func (po *PHPOptimizer) getDisabledFunctions(disable bool) string {
	if !disable {
		return ""
	}

	dangerousFunctions := []string{
		"exec", "passthru", "shell_exec", "system",
		"proc_open", "popen", "curl_exec", "curl_multi_exec",
		"parse_ini_file", "show_source", "file_get_contents",
		"fopen", "fwrite", "fputs", "fgets", "fread",
		"file", "readfile", "file_put_contents",
		"move_uploaded_file", "copy", "rename", "unlink",
		"chmod", "chown", "chgrp", "touch", "mkdir", "rmdir",
		"opendir", "readdir", "scandir", "glob",
		"ini_set", "ini_get", "ini_restore",
		"set_time_limit", "ignore_user_abort",
		"dl", "eval", "assert", "create_function",
		"call_user_func", "call_user_func_array",
		"register_shutdown_function", "register_tick_function",
		"unregister_tick_function", "set_error_handler",
		"set_exception_handler", "restore_error_handler",
		"restore_exception_handler", "error_reporting",
		"ini_alter", "ini_get_all", "ini_parse_quantity",
		"get_cfg_var", "get_current_user", "get_defined_constants",
		"get_extension_funcs", "get_include_path", "get_included_files",
		"get_loaded_extensions", "get_magic_quotes_gpc", "get_magic_quotes_runtime",
		"get_required_files", "get_resource_type", "getenv",
		"putenv", "getopt", "getrusage", "gettimeofday",
		"microtime", "getmypid", "getmyuid", "getmygid",
		"getmyinode", "getlastmod", "getmygid", "getmyuid",
		"getmypid", "getmyinode", "getlastmod",
	}

	return strings.Join(dangerousFunctions, ",")
}

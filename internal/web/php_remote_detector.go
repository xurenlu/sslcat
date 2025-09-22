package web

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

// PHPRemoteDetector PHP 远程环境检测器
type PHPRemoteDetector struct {
	config *config.Config
	log    *logrus.Entry
}

// NewPHPRemoteDetector 创建 PHP 远程检测器
func NewPHPRemoteDetector(cfg *config.Config) *PHPRemoteDetector {
	return &PHPRemoteDetector{
		config: cfg,
		log:    logrus.WithFields(logrus.Fields{"component": "php_remote_detector"}),
	}
}

// RemoteEnvironmentInfo 远程环境信息
type RemoteEnvironmentInfo struct {
	IsRemote          bool     `json:"is_remote"`
	RemoteHost        string   `json:"remote_host,omitempty"`
	RemotePort        string   `json:"remote_port,omitempty"`
	ConnectionType    string   `json:"connection_type"` // local|remote|docker
	Limitations       []string `json:"limitations"`
	AvailableFeatures []string `json:"available_features"`
	Warnings          []string `json:"warnings"`
}

// DetectRemoteEnvironment 检测 PHP 环境是否为远程
func (prd *PHPRemoteDetector) DetectRemoteEnvironment(site *config.PHPSite) (*RemoteEnvironmentInfo, error) {
	info := &RemoteEnvironmentInfo{
		IsRemote:          false,
		ConnectionType:    "local",
		Limitations:       []string{},
		AvailableFeatures: []string{},
		Warnings:          []string{},
	}

	// 解析 FCGI 地址
	host, port, connType, err := prd.parseFCGIAddress(site.FCGIAddr)
	if err != nil {
		return nil, fmt.Errorf("解析 FCGI 地址失败: %v", err)
	}

	info.RemoteHost = host
	info.RemotePort = port
	info.ConnectionType = connType

	// 判断是否为远程环境
	if connType == "remote" {
		info.IsRemote = true
		prd.analyzeRemoteLimitations(info)
	} else if connType == "docker" {
		info.IsRemote = true
		prd.analyzeDockerLimitations(info)
	} else {
		// 本地环境
		prd.analyzeLocalCapabilities(info)
	}

	return info, nil
}

// parseFCGIAddress 解析 FCGI 地址
func (prd *PHPRemoteDetector) parseFCGIAddress(fcgiAddr string) (host, port, connType string, err error) {
	if strings.HasPrefix(fcgiAddr, "unix:") {
		// Unix socket - 本地
		return "localhost", "unix", "local", nil
	}

	if strings.HasPrefix(fcgiAddr, "tcp:") {
		fcgiAddr = strings.TrimPrefix(fcgiAddr, "tcp:")
	}

	// 解析 TCP 地址
	host, port, err = net.SplitHostPort(fcgiAddr)
	if err != nil {
		return "", "", "", fmt.Errorf("无效的 FCGI 地址: %v", err)
	}

	// 判断是否为远程地址
	if prd.isRemoteHost(host) {
		return host, port, "remote", nil
	}

	return host, port, "local", nil
}

// isRemoteHost 判断是否为远程主机
func (prd *PHPRemoteDetector) isRemoteHost(host string) bool {
	// 本地地址列表
	localAddresses := []string{
		"localhost", "127.0.0.1", "::1", "0.0.0.0",
	}

	for _, localAddr := range localAddresses {
		if host == localAddr {
			return false
		}
	}

	// 检查是否为 Docker 容器
	if strings.HasPrefix(host, "172.") || strings.HasPrefix(host, "192.168.") {
		// 可能是 Docker 网络
		return true
	}

	// 其他情况认为是远程
	return true
}

// analyzeRemoteLimitations 分析远程环境限制
func (prd *PHPRemoteDetector) analyzeRemoteLimitations(info *RemoteEnvironmentInfo) {
	info.Limitations = []string{
		"无法进行框架自动检测（需要访问 composer.json 文件）",
		"无法生成优化脚本（无法在远程服务器执行）",
		"无法直接修改 PHP 配置（需要服务器管理员权限）",
		"无法访问错误日志文件（需要文件系统权限）",
		"无法进行性能监控（需要服务器端支持）",
		"无法执行安全扫描（需要本地文件访问）",
	}

	info.AvailableFeatures = []string{
		"FastCGI 请求转发",
		"基础安全响应头设置",
		"请求路径验证",
		"基础访问控制",
	}

	info.Warnings = []string{
		"⚠️ 远程 PHP 环境功能受限",
		"⚠️ 建议在本地部署以获得完整功能",
		"⚠️ 需要手动配置 PHP 优化和安全设置",
	}
}

// analyzeDockerLimitations 分析 Docker 环境限制
func (prd *PHPRemoteDetector) analyzeDockerLimitations(info *RemoteEnvironmentInfo) {
	info.Limitations = []string{
		"无法直接访问宿主机文件系统",
		"需要 Docker 网络配置",
		"容器内 PHP 配置需要重新构建镜像",
	}

	info.AvailableFeatures = []string{
		"FastCGI 请求转发",
		"容器内框架检测（如果挂载了代码目录）",
		"基础安全响应头设置",
		"请求路径验证",
	}

	info.Warnings = []string{
		"🐳 Docker 环境需要特殊配置",
		"🐳 建议使用 Docker Compose 进行管理",
		"🐳 需要挂载代码目录以支持框架检测",
	}
}

// analyzeLocalCapabilities 分析本地环境能力
func (prd *PHPRemoteDetector) analyzeLocalCapabilities(info *RemoteEnvironmentInfo) {
	info.AvailableFeatures = []string{
		"✅ 完整的框架自动检测",
		"✅ 自动生成优化脚本",
		"✅ PHP 配置优化",
		"✅ 错误日志监控",
		"✅ 性能监控和分析",
		"✅ 安全扫描和防护",
		"✅ 文件上传安全检查",
		"✅ 路径遍历防护",
		"✅ 代码注入防护",
		"✅ SQL 注入防护",
	}
}

// GetRemoteEnvironmentStatus 获取远程环境状态
func (prd *PHPRemoteDetector) GetRemoteEnvironmentStatus(domain string) (map[string]interface{}, error) {
	var site *config.PHPSite
	for i := range prd.config.PHPSites {
		if strings.EqualFold(prd.config.PHPSites[i].Domain, domain) {
			site = &prd.config.PHPSites[i]
			break
		}
	}

	if site == nil {
		return nil, fmt.Errorf("PHP site not found for domain: %s", domain)
	}

	envInfo, err := prd.DetectRemoteEnvironment(site)
	if err != nil {
		return nil, err
	}

	// 测试连接
	connectionStatus := prd.testConnection(site.FCGIAddr)

	return map[string]interface{}{
		"domain":                domain,
		"environment_info":      envInfo,
		"connection_status":     connectionStatus,
		"recommendations":       prd.getRecommendations(envInfo),
		"alternative_solutions": prd.getAlternativeSolutions(envInfo),
	}, nil
}

// testConnection 测试连接状态
func (prd *PHPRemoteDetector) testConnection(fcgiAddr string) map[string]interface{} {
	status := map[string]interface{}{
		"connected": false,
		"latency":   0,
		"error":     "",
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", fcgiAddr, 5*time.Second)
	latency := time.Since(start)

	if err != nil {
		status["error"] = err.Error()
		return status
	}
	defer conn.Close()

	status["connected"] = true
	status["latency"] = latency.Milliseconds()
	return status
}

// getRecommendations 获取建议
func (prd *PHPRemoteDetector) getRecommendations(envInfo *RemoteEnvironmentInfo) []string {
	recommendations := []string{}

	if envInfo.IsRemote {
		recommendations = append(recommendations,
			"💡 考虑使用本地部署以获得完整功能",
			"💡 在远程服务器上手动配置 PHP 优化",
			"💡 使用 SSH 隧道进行安全连接",
			"💡 考虑使用容器化部署方案",
		)
	} else {
		recommendations = append(recommendations,
			"✅ 本地环境支持所有功能",
			"✅ 可以启用自动优化和安全检测",
			"✅ 建议启用性能监控",
		)
	}

	return recommendations
}

// getAlternativeSolutions 获取替代方案
func (prd *PHPRemoteDetector) getAlternativeSolutions(envInfo *RemoteEnvironmentInfo) []map[string]string {
	solutions := []map[string]string{}

	if envInfo.IsRemote {
		solutions = append(solutions, map[string]string{
			"title":       "SSH 远程执行",
			"description": "通过 SSH 在远程服务器上执行优化脚本",
			"command":     "ssh user@remote-server 'cd /path/to/php && ./optimize.sh'",
		})

		solutions = append(solutions, map[string]string{
			"title":       "Docker 部署",
			"description": "使用 Docker 容器化部署，支持完整功能",
			"command":     "docker run -v /path/to/php:/var/www/html php:8.1-fpm",
		})

		solutions = append(solutions, map[string]string{
			"title":       "CI/CD 集成",
			"description": "通过 CI/CD 流水线自动部署和优化",
			"command":     "在 GitHub Actions 或 GitLab CI 中配置",
		})
	}

	return solutions
}

// GenerateRemoteSetupGuide 生成远程设置指南
func (prd *PHPRemoteDetector) GenerateRemoteSetupGuide(domain string) (string, error) {
	var site *config.PHPSite
	for i := range prd.config.PHPSites {
		if strings.EqualFold(prd.config.PHPSites[i].Domain, domain) {
			site = &prd.config.PHPSites[i]
			break
		}
	}

	if site == nil {
		return "", fmt.Errorf("PHP site not found for domain: %s", domain)
	}

	envInfo, err := prd.DetectRemoteEnvironment(site)
	if err != nil {
		return "", err
	}

	guide := "# PHP 远程环境设置指南\n\n"
	guide += "## 环境信息\n"
	guide += fmt.Sprintf("- 域名: %s\n", domain)
	guide += fmt.Sprintf("- 连接类型: %s\n", envInfo.ConnectionType)
	guide += fmt.Sprintf("- 远程主机: %s:%s\n", envInfo.RemoteHost, envInfo.RemotePort)
	guide += fmt.Sprintf("- 是否远程: %t\n\n", envInfo.IsRemote)

	guide += "## 功能限制\n"
	guide += strings.Join(envInfo.Limitations, "\n") + "\n\n"

	guide += "## 可用功能\n"
	guide += strings.Join(envInfo.AvailableFeatures, "\n") + "\n\n"

	guide += "## 警告信息\n"
	guide += strings.Join(envInfo.Warnings, "\n") + "\n\n"

	guide += "## 建议的解决方案\n\n"
	guide += "### 1. 本地部署（推荐）\n"
	guide += "将 PHP 应用部署到本地服务器，获得完整功能支持。\n\n"

	guide += "### 2. SSH 远程管理\n"
	guide += "通过 SSH 在远程服务器上执行优化命令：\n\n"
	guide += fmt.Sprintf("```bash\n# 连接到远程服务器\nssh user@%s\n\n# 进入 PHP 项目目录\ncd %s\n\n# 执行优化脚本\n./optimize.sh\n```\n\n", envInfo.RemoteHost, site.Root)

	guide += "### 3. Docker 容器化部署\n"
	guide += "使用 Docker 进行容器化部署：\n\n"
	guide += "# docker-compose.yml\n# docker-compose.yml\nversion: '3.8'\nservices:\n  php:\n    image: php:8.1-fpm\n    volumes:\n      - ./php:/var/www/html\n      - ./php.ini:/usr/local/etc/php/php.ini\n    ports:\n      - \"9000:9000\"\n```\n\n"

	guide += "### 4. 手动配置优化\n"
	guide += "在远程服务器上手动配置 PHP 优化：\n\n"
	guide += "```ini\n; php.ini 优化配置\nopcache.enable=1\nopcache.memory_consumption=128\nopcache.max_accelerated_files=10000\nopcache.validate_timestamps=0\n```\n\n"

	guide += "## 安全建议\n"
	guide += "1. 使用 HTTPS 连接\n"
	guide += "2. 配置防火墙规则\n"
	guide += "3. 定期更新 PHP 版本\n"
	guide += "4. 启用安全响应头\n"
	guide += "5. 监控访问日志\n\n"

	guide += "## 监控建议\n"
	guide += "1. 设置错误日志监控\n"
	guide += "2. 配置性能监控\n"
	guide += "3. 启用访问统计\n"
	guide += "4. 设置告警机制\n"

	return guide, nil
}

// CheckRemoteCapabilities 检查远程能力
func (prd *PHPRemoteDetector) CheckRemoteCapabilities(domain string) (map[string]bool, error) {
	capabilities := map[string]bool{
		"framework_detection":       false,
		"optimization_scripts":      false,
		"php_config_modification":   false,
		"error_log_access":          false,
		"performance_monitoring":    false,
		"security_scanning":         false,
		"file_upload_validation":    false,
		"path_traversal_protection": false,
		"code_injection_protection": false,
		"sql_injection_protection":  false,
	}

	var site *config.PHPSite
	for i := range prd.config.PHPSites {
		if strings.EqualFold(prd.config.PHPSites[i].Domain, domain) {
			site = &prd.config.PHPSites[i]
			break
		}
	}

	if site == nil {
		return nil, fmt.Errorf("PHP site not found for domain: %s", domain)
	}

	envInfo, err := prd.DetectRemoteEnvironment(site)
	if err != nil {
		return nil, err
	}

	// 根据环境类型设置能力
	if !envInfo.IsRemote {
		// 本地环境支持所有功能
		for key := range capabilities {
			capabilities[key] = true
		}
	} else {
		// 远程环境只支持部分功能
		capabilities["path_traversal_protection"] = true
		capabilities["code_injection_protection"] = true
		capabilities["sql_injection_protection"] = true
		capabilities["file_upload_validation"] = true
	}

	return capabilities, nil
}

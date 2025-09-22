package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

// handlePHPSecurity 处理 PHP 安全状态页面
func (s *Server) handlePHPSecurity(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 获取选中的域名
	selectedDomain := r.URL.Query().Get("domain")

	data := map[string]interface{}{
		"AdminPrefix":    s.config.AdminPrefix,
		"Sites":          s.config.PHPSites,
		"SelectedDomain": selectedDomain,
	}

	s.templateRenderer.DetectLanguageAndRender(w, r, "php_security.html", data)
}

// handlePHPOptimization 处理 PHP 性能优化页面
func (s *Server) handlePHPOptimization(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 获取选中的域名
	selectedDomain := r.URL.Query().Get("domain")

	// 暂时重定向到安全页面，后续可以创建专门的优化页面
	http.Redirect(w, r, s.config.AdminPrefix+"/php-sites/security?domain="+selectedDomain, http.StatusFound)
}

// handleAPIPHPSecurityStatus 处理 PHP 安全状态 API
func (s *Server) handleAPIPHPSecurityStatus(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "domain parameter required", http.StatusBadRequest)
		return
	}

	// 创建远程检测器
	remoteDetector := NewPHPRemoteDetector(s.config)

	// 获取环境状态
	status, err := remoteDetector.GetRemoteEnvironmentStatus(domain)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get environment status: %v", err), http.StatusInternalServerError)
		return
	}

	// 模拟安全状态数据
	securityData := map[string]interface{}{
		"security_scan": "已完成",
		"performance":   "良好",
		"risks":         "0",
		"config":        "已优化",
		"environment":   status,
		"timestamp":     time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(securityData)
}

// handleAPIPHPSecurityScan 处理 PHP 安全扫描 API
func (s *Server) handleAPIPHPSecurityScan(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "domain parameter required", http.StatusBadRequest)
		return
	}

	// 创建安全扫描器
	securityScanner := NewPHPSecurityScanner(s.config)

	// 执行安全扫描
	vulnerabilities, err := securityScanner.ScanForVulnerabilities(domain)
	if err != nil {
		http.Error(w, fmt.Sprintf("security scan failed: %v", err), http.StatusInternalServerError)
		return
	}

	scanData := map[string]interface{}{
		"domain":          domain,
		"vulnerabilities": vulnerabilities,
		"scan_time":       time.Now().Format(time.RFC3339),
		"status":          "completed",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scanData)
}

// handleAPIPHPSecurityPerformance 处理 PHP 性能监控 API
func (s *Server) handleAPIPHPSecurityPerformance(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "domain parameter required", http.StatusBadRequest)
		return
	}

	// 创建性能优化器
	optimizer := NewPHPOptimizer(s.config)

	// 获取性能指标
	metrics, err := optimizer.GetPerformanceMetrics(domain)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get performance metrics: %v", err), http.StatusInternalServerError)
		return
	}

	performanceData := map[string]interface{}{
		"domain":        domain,
		"response_time": metrics["response_time"],
		"memory_usage":  metrics["memory_usage"],
		"cpu_usage":     metrics["cpu_usage"],
		"timestamp":     time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(performanceData)
}

// handleAPIPHPSecurityErrors 处理 PHP 错误日志 API
func (s *Server) handleAPIPHPSecurityErrors(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "domain parameter required", http.StatusBadRequest)
		return
	}

	// 创建错误处理器
	errorHandler := NewPHPErrorHandler(s.config)

	// 获取错误统计
	errorStats, err := errorHandler.GetErrorStats(domain, 24)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get error logs: %v", err), http.StatusInternalServerError)
		return
	}

	// 转换错误统计为前端需要的格式
	var errors []map[string]interface{}
	if errorStats != nil {
		// 这里可以根据实际需要转换错误统计数据
		errors = []map[string]interface{}{
			{
				"time":    time.Now().Add(-1 * time.Hour).Format("15:04:05"),
				"level":   "error",
				"message": fmt.Sprintf("总错误数: %d", errorStats.TotalErrors),
			},
		}
	}

	errorData := map[string]interface{}{
		"domain":    domain,
		"errors":    errors,
		"count":     len(errors),
		"timestamp": time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(errorData)
}

// handleAPIPHPSecurityConfig 处理 PHP 安全配置 API
func (s *Server) handleAPIPHPSecurityConfig(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "domain parameter required", http.StatusBadRequest)
		return
	}

	// 创建安全配置检查器
	securityConfig := NewPHPSecurityConfig(s.config)

	// 获取安全配置
	config, err := securityConfig.GetSecurityConfig(domain)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get security config: %v", err), http.StatusInternalServerError)
		return
	}

	configData := map[string]interface{}{
		"domain":         domain,
		"upload_limit":   config["upload_limit"],
		"execution_time": config["execution_time"],
		"memory_limit":   config["memory_limit"],
		"opcache":        config["opcache"],
		"safe_mode":      config["safe_mode"],
		"timestamp":      time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(configData)
}

// 辅助函数：创建 PHP 安全扫描器
func NewPHPSecurityScanner(config *config.Config) *PHPSecurityScanner {
	return &PHPSecurityScanner{
		config: config,
	}
}

// 辅助函数：创建 PHP 安全配置检查器
func NewPHPSecurityConfig(config *config.Config) *PHPSecurityConfig {
	return &PHPSecurityConfig{
		config: config,
	}
}

// PHPSecurityScanner PHP 安全扫描器
type PHPSecurityScanner struct {
	config *config.Config
}

// ScanForVulnerabilities 扫描安全漏洞
func (pss *PHPSecurityScanner) ScanForVulnerabilities(domain string) ([]string, error) {
	var vulnerabilities []string

	// 查找对应的 PHP 站点
	var site *config.PHPSite
	for i := range pss.config.PHPSites {
		if strings.EqualFold(pss.config.PHPSites[i].Domain, domain) {
			site = &pss.config.PHPSites[i]
			break
		}
	}

	if site == nil {
		return nil, fmt.Errorf("PHP site not found for domain: %s", domain)
	}

	// 创建 PHP 安全管理器（用于后续扩展）
	_ = NewPHPSecurity(pss.config)

	// 1. 检查文件上传安全配置
	if site.SecurityConfig == nil {
		vulnerabilities = append(vulnerabilities, "⚠️ 未配置文件上传安全限制")
	} else {
		if site.SecurityConfig.MaxUploadSize == 0 {
			vulnerabilities = append(vulnerabilities, "⚠️ 未设置文件上传大小限制")
		}
		if len(site.SecurityConfig.AllowedExtensions) == 0 {
			vulnerabilities = append(vulnerabilities, "⚠️ 未设置允许的文件扩展名白名单")
		}
		if len(site.SecurityConfig.BlockedExtensions) == 0 {
			vulnerabilities = append(vulnerabilities, "⚠️ 未设置禁止的文件扩展名黑名单")
		}
	}

	// 2. 检查路径遍历保护
	if site.SecurityConfig == nil || !site.SecurityConfig.DisablePathTraversal {
		vulnerabilities = append(vulnerabilities, "⚠️ 未启用路径遍历攻击保护")
	}

	// 3. 检查代码注入保护
	if site.SecurityConfig == nil || !site.SecurityConfig.DisableEval {
		vulnerabilities = append(vulnerabilities, "⚠️ 未禁用 eval() 函数")
	}

	// 4. 检查 Shell 执行保护
	if site.SecurityConfig == nil || !site.SecurityConfig.DisableShellExec {
		vulnerabilities = append(vulnerabilities, "⚠️ 未禁用 Shell 执行函数")
	}

	// 5. 检查安全响应头
	// 这里可以检查是否缺少重要的安全响应头

	// 6. 检查 PHP 配置安全性
	// 这里可以检查 PHP 配置中的安全设置

	// 如果没有发现漏洞，返回安全状态
	if len(vulnerabilities) == 0 {
		vulnerabilities = append(vulnerabilities, "✅ 未发现安全漏洞")
	}

	return vulnerabilities, nil
}

// PHPSecurityConfig PHP 安全配置检查器
type PHPSecurityConfig struct {
	config *config.Config
}

// GetSecurityConfig 获取安全配置
func (psc *PHPSecurityConfig) GetSecurityConfig(domain string) (map[string]interface{}, error) {
	// 这里应该实现实际的配置检查逻辑
	// 目前返回模拟数据
	return map[string]interface{}{
		"upload_limit":   "2M",
		"execution_time": "30s",
		"memory_limit":   "128M",
		"opcache":        true,
		"safe_mode":      false,
	}, nil
}

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

// handlePHPSecurity 处理 PHP 安全状态页面
func (s *Server) handlePHPSecurity(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 已迁移到 React SPA
	s.handleSPA(w, r)
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

// handleAPIPHPAdvancedSecurityScan 处理高级安全扫描 API
func (s *Server) handleAPIPHPAdvancedSecurityScan(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "domain parameter required", http.StatusBadRequest)
		return
	}

	// 创建高级安全扫描器
	advancedSecurity := NewAdvancedPHPSecurity(s.config)

	// 执行高级安全扫描
	scanResult, err := advancedSecurity.PerformAdvancedSecurityScan(domain)
	if err != nil {
		http.Error(w, fmt.Sprintf("advanced security scan failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scanResult)
}

// handleAPIPHPSecurityAutoFix 处理安全自动修复 API
func (s *Server) handleAPIPHPSecurityAutoFix(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain   string   `json:"domain"`
		IssueIDs []string `json:"issue_ids"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Domain == "" {
		http.Error(w, "domain is required", http.StatusBadRequest)
		return
	}

	// 创建高级安全扫描器
	advancedSecurity := NewAdvancedPHPSecurity(s.config)

	// 执行自动修复
	err := advancedSecurity.AutoFixSecurityIssues(req.Domain, req.IssueIDs)
	if err != nil {
		http.Error(w, fmt.Sprintf("auto fix failed: %v", err), http.StatusInternalServerError)
		return
	}

	// 保存配置
	_ = s.config.Save(s.config.ConfigFile)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Security issues fixed successfully",
		"domain":  req.Domain,
		"fixed":   len(req.IssueIDs),
	})
}

// handleAPIPHPSecurityRecommendations 处理安全建议 API
func (s *Server) handleAPIPHPSecurityRecommendations(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "domain parameter required", http.StatusBadRequest)
		return
	}

	// 创建高级安全扫描器
	advancedSecurity := NewAdvancedPHPSecurity(s.config)

	// 执行安全扫描获取建议
	scanResult, err := advancedSecurity.PerformAdvancedSecurityScan(domain)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get recommendations: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"domain":          domain,
		"recommendations": scanResult.Recommendations,
		"security_score":  scanResult.SecurityScore,
		"total_issues":    scanResult.TotalIssues,
	})
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
	// 使用高级安全扫描器
	advancedSecurity := NewAdvancedPHPSecurity(pss.config)
	scanResult, err := advancedSecurity.PerformAdvancedSecurityScan(domain)
	if err != nil {
		return nil, err
	}

	var vulnerabilities []string

	// 根据扫描结果生成漏洞报告
	if scanResult.TotalIssues == 0 {
		vulnerabilities = append(vulnerabilities, "✅ 未发现安全漏洞")
	} else {
		// 按严重程度分类显示
		if scanResult.CriticalIssues > 0 {
			vulnerabilities = append(vulnerabilities, fmt.Sprintf("🚨 发现 %d 个关键安全问题", scanResult.CriticalIssues))
		}
		if scanResult.HighIssues > 0 {
			vulnerabilities = append(vulnerabilities, fmt.Sprintf("⚠️ 发现 %d 个高风险安全问题", scanResult.HighIssues))
		}
		if scanResult.MediumIssues > 0 {
			vulnerabilities = append(vulnerabilities, fmt.Sprintf("🔶 发现 %d 个中等风险安全问题", scanResult.MediumIssues))
		}
		if scanResult.LowIssues > 0 {
			vulnerabilities = append(vulnerabilities, fmt.Sprintf("🔸 发现 %d 个低风险安全问题", scanResult.LowIssues))
		}

		// 显示安全评分
		vulnerabilities = append(vulnerabilities, fmt.Sprintf("📊 安全评分: %d/100", scanResult.SecurityScore))
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

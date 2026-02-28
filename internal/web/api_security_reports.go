package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Report 安全报告
type Report struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	Generated    time.Time `json:"generated"`
	DownloadPath string    `json:"download_path"`
}

// SecurityReportRequest 安全报告请求
type SecurityReportRequest struct {
	ReportType           string  `json:"report_type"`           // daily, weekly, monthly, custom
	StartDate            string  `json:"start_date"`            // YYYY-MM-DD
	EndDate              string  `json:"end_date"`              // YYYY-MM-DD
	IncludeCharts        bool    `json:"include_charts"`
	IncludeAttackDetails bool    `json:"include_attack_details"`
	IncludeRecommendations bool  `json:"include_recommendations"`
	Format               string  `json:"format"`               // pdf, html, json
}

// SecurityReportResponse 安全报告响应
type SecurityReportResponse struct {
	ReportID    string `json:"report_id"`
	Status      string `json:"status"`      // pending, generating, completed, failed
	DownloadURL string `json:"download_url,omitempty"`
	Error       string `json:"error,omitempty"`
}

// ReportListResponse 报告列表响应
type ReportListResponse struct {
	Reports []ReportStatus `json:"reports"`
}

// ReportStatus 报告状态
type ReportStatus struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Status    string    `json:"status"`
	Created   time.Time `json:"created"`
	Completed *time.Time `json:"completed,omitempty"`
	DownloadURL string  `json:"download_url,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// handleSecurityReportGenerate 生成安全报告
func (s *Server) handleSecurityReportGenerate(w http.ResponseWriter, r *http.Request) {
	var req SecurityReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 验证日期格式
	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		http.Error(w, "Invalid start_date format", http.StatusBadRequest)
		return
	}

	endDate, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		http.Error(w, "Invalid end_date format", http.StatusBadRequest)
		return
	}

	// 计算时间范围
	duration := endDate.Sub(startDate)
	if duration < 0 {
		http.Error(w, "end_date must be after start_date", http.StatusBadRequest)
		return
	}

	// 生成报告ID
	reportID := fmt.Sprintf("security_report_%s_%s", req.ReportType, time.Now().Format("20060102_150405"))

	// 创建报告目录
	reportDir := "./data/reports/security"
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		s.log.Errorf("Failed to create report directory: %v", err)
		http.Error(w, "Failed to create report directory", http.StatusInternalServerError)
		return
	}

	// 生成报告
	generatedReport, err := s.generateSecurityReport(reportID, req, startDate, endDate)
	if err != nil {
		s.log.Errorf("Failed to generate security report: %v", err)
		s.sendJSON(w, SecurityReportResponse{
			ReportID: reportID,
			Status:   "failed",
			Error:    err.Error(),
		})
		return
	}

	s.sendJSON(w, SecurityReportResponse{
		ReportID:    reportID,
		Status:      "completed",
		DownloadURL: generatedReport.DownloadPath,
	})
}

// generateSecurityReport 生成安全报告
func (s *Server) generateSecurityReport(reportID string, req SecurityReportRequest, startDate, endDate time.Time) (*Report, error) {
	s.log.Infof("Generating security report: %s from %s to %s", req.ReportType, startDate, endDate)

	// 收集安全事件数据
	securityData := s.collectSecurityData(startDate, endDate)

	// 生成报告内容
	var content string
	switch req.Format {
	case "html":
		content = s.generateHTMLReport(req, securityData)
	case "json":
		jsonData, _ := json.MarshalIndent(securityData, "", "  ")
		content = string(jsonData)
	default: // pdf
		content = s.generateTextReport(req, securityData)
	}

	// 保存报告
	fileName := fmt.Sprintf("%s.%s", reportID, req.Format)
	filePath := filepath.Join("./data/reports/security", fileName)

	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		return nil, fmt.Errorf("failed to write report: %w", err)
	}

	s.log.Infof("Security report generated: %s", filePath)

	return &Report{
		ID:           reportID,
		Type:         req.ReportType,
		Generated:    time.Now(),
		DownloadPath: "/api/security-reports/download/" + fileName,
	}, nil
}

// collectSecurityData 收集安全数据
func (s *Server) collectSecurityData(startDate, endDate time.Time) map[string]interface{} {
	data := make(map[string]interface{})

	// WAF 统计
	if s.wafEngine != nil {
		wafStats := s.getWAFStatistics(startDate, endDate)
		data["waf"] = wafStats
	}

	// 封禁统计
	if s.securityManager != nil {
		blockStats := s.getBlockStatistics(startDate, endDate)
		data["blocks"] = blockStats
	}

	// 攻击类型分布
	attackTypes := s.getAttackTypeDistribution(startDate, endDate)
	data["attack_types"] = attackTypes

	// 地理分布
	geoDistribution := s.getGeoDistribution(startDate, endDate)
	data["geo_distribution"] = geoDistribution

	// 时间趋势
	trends := s.getSecurityTrends(startDate, endDate)
	data["trends"] = trends

	return data
}

// getWAFStatistics 获取WAF统计
func (s *Server) getWAFStatistics(startDate, endDate time.Time) map[string]interface{} {
	// TODO: 从WAF引擎获取统计数据
	return map[string]interface{}{
		"total_checks":    0,
		"blocked_requests": 0,
		"attack_detected":  0,
		"by_type":         make(map[string]int),
	}
}

// getBlockStatistics 获取封禁统计
func (s *Server) getBlockStatistics(startDate, endDate time.Time) map[string]interface{} {
	// TODO: 从安全管理器获取封禁统计
	return map[string]interface{}{
		"blocked_ips":     0,
		"blocked_uas":     0,
		"blocked_fingerprints": 0,
	}
}

// getAttackTypeDistribution 获取攻击类型分布
func (s *Server) getAttackTypeDistribution(startDate, endDate time.Time) map[string]int {
	// TODO: 从攻击事件获取分布
	return make(map[string]int)
}

// getGeoDistribution 获取地理分布
func (s *Server) getGeoDistribution(startDate, endDate time.Time) map[string]int {
	// TODO: 从攻击事件获取地理分布
	return make(map[string]int)
}

// getSecurityTrends 获取安全趋势
func (s *Server) getSecurityTrends(startDate, endDate time.Time) []map[string]interface{} {
	// TODO: 计算时间趋势
	return make([]map[string]interface{}, 0)
}

// generateTextReport 生成文本报告
func (s *Server) generateTextReport(req SecurityReportRequest, data map[string]interface{}) string {
	report := fmt.Sprintf(`
========================================
SSLcat 安全报告
========================================

报告类型: %s
时间范围: %s 至 %s
生成时间: %s

========================================
1. 总览
========================================

本报告总结了指定时间段内的安全状况和威胁活动。

========================================
2. WAF 防护统计
========================================

Web应用防火墙(WAF)是保护您的应用免受恶意攻击的第一道防线。

检测到的攻击类型:
%s

========================================
3. 封禁统计
========================================

系统自动识别并阻止恶意来源，保护您的服务免受攻击。

========================================
4. 建议
========================================

1. 定期检查安全日志
2. 保持WAF规则更新
3. 监控异常流量模式
4. 及时更新系统补丁

========================================
报告结束
========================================
`, req.ReportType, req.StartDate, req.EndDate, time.Now().Format("2006-01-02 15:04:05"),
		formatAttackTypes(data["attack_types"]))

	return report
}

// generateHTMLReport 生成HTML报告
func (s *Server) generateHTMLReport(req SecurityReportRequest, data map[string]interface{}) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>SSLcat 安全报告 - %s</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
		.container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
		h1 { color: #2c5282; border-bottom: 3px solid #4299e1; padding-bottom: 10px; }
		h2 { color: #2d3748; margin-top: 30px; }
		.section { margin: 20px 0; }
		.stat { display: inline-block; margin: 10px; padding: 15px; background: #ebf8ff; border-radius: 4px; }
		.label { font-weight: bold; color: #4a5568; }
		.value { font-size: 24px; color: #2b6cb0; }
	</style>
</head>
<body>
	<div class="container">
		<h1>SSLcat 安全报告</h1>
		<p><strong>报告类型:</strong> %s</p>
		<p><strong>时间范围:</strong> %s 至 %s</p>
		<p><strong>生成时间:</strong> %s</p>

		<h2>1. 总览</h2>
		<div class="section">
			<p>本报告总结了指定时间段内的安全状况和威胁活动。</p>
		</div>

		<h2>2. WAF 防护统计</h2>
		<div class="section">
			<p>Web应用防火墙(WAF)是保护您的应用免受恶意攻击的第一道防线。</p>
		</div>

		<h2>3. 建议</h2>
		<div class="section">
			<ul>
				<li>定期检查安全日志</li>
				<li>保持WAF规则更新</li>
				<li>监控异常流量模式</li>
				<li>及时更新系统补丁</li>
			</ul>
		</div>
	</div>
</body>
</html>
`, req.ReportType, req.StartDate, req.EndDate, time.Now().Format("2006-01-02 15:04:05"))
}

// formatAttackTypes 格式化攻击类型
func formatAttackTypes(data interface{}) string {
	if attackTypes, ok := data.(map[string]int); ok {
		result := ""
		for attackType, count := range attackTypes {
			result += fmt.Sprintf("  - %s: %d 次\n", attackType, count)
		}
		if result == "" {
			result = "  (无攻击记录)"
		}
		return result
	}
	return "  (数据不可用)"
}

// handleSecurityReportList 获取报告列表
func (s *Server) handleSecurityReportList(w http.ResponseWriter, r *http.Request) {
	reports := s.getRecentSecurityReports()

	s.sendJSON(w, ReportListResponse{
		Reports: reports,
	})
}

// handleSecurityReportDownload 下载报告
func (s *Server) handleSecurityReportDownload(w http.ResponseWriter, r *http.Request) {
	// 从URL获取文件名
	fileName := filepath.Base(r.URL.Path)
	filePath := filepath.Join("./data/reports/security", fileName)

	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// 设置响应头
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))

	// 发送文件
	http.ServeFile(w, r, filePath)
}

// getRecentSecurityReports 获取最近的安全报告
func (s *Server) getRecentSecurityReports() []ReportStatus {
	reports := make([]ReportStatus, 0)

	// 扫描报告目录
	reportDir := "./data/reports/security"
	entries, err := os.ReadDir(reportDir)
	if err != nil {
		if !os.IsNotExist(err) {
			s.log.Errorf("Failed to read report directory: %v", err)
		}
		return reports
	}

	// 读取最近10个报告
	for i, entry := range entries {
		if i >= 10 {
			break
		}
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		modTime := info.ModTime()
		reports = append(reports, ReportStatus{
			ID:        entry.Name(),
			Type:      "security",
			Status:    "completed",
			Created:   modTime,
			Completed: &modTime,
			DownloadURL: "/api/security-reports/download/" + entry.Name(),
		})
	}

	return reports
}

// handleSecurityReportConfig 安全报告配置
func (s *Server) handleSecurityReportConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		enabled := s.reportGenerator != nil
		s.sendJSON(w, map[string]interface{}{
			"enabled": enabled,
		})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

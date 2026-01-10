package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/xurenlu/sslcat/internal/ai"
	"github.com/xurenlu/sslcat/internal/config"
)

// handleAISecurityPage AI 安全分析页面
func (s *Server) handleAISecurityPage(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 检查权限
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || (currentUser.Role != RoleSuperAdmin && currentUser.Role != RoleAdmin) {
		http.Error(w, "权限不足", http.StatusForbidden)
		return
	}

	// 已迁移到 React SPA
	s.handleSPA(w, r)
}

// handleAISecurityConfigAPI AI 安全配置 API
func (s *Server) handleAISecurityConfigAPI(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	switch r.Method {
	case "GET":
		s.handleGetAISecurityConfig(w, r)
	case "POST":
		s.handleSaveAISecurityConfig(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// formatDurationForFrontend 将 Duration 格式化为前端能识别的格式
// 例如：12h0m0s -> 12h, 3d0h0m0s -> 3d, 24h -> 24h
func formatDurationForFrontend(d time.Duration) string {
	if d <= 0 {
		return "1h"
	}

	// 转换为整数小时、天等
	totalHours := int(d.Hours())
	days := totalHours / 24
	hours := totalHours % 24
	minutes := int(d.Minutes()) % 60

	// 如果正好是24小时的倍数
	if hours == 0 && minutes == 0 {
		// 如果是24小时，返回 "24h"（前端有单独的24h选项）
		if days == 1 {
			return "24h"
		}
		// 如果是多天，返回天数（如 72h -> 3d）
		if days > 1 {
			return fmt.Sprintf("%dd", days)
		}
	}

	// 如果有天数但还有余数，也使用天数（如 3d12h -> 3d，因为前端选项是整数天）
	if days > 0 {
		return fmt.Sprintf("%dd", days)
	}
	// 使用小时
	if hours > 0 {
		return fmt.Sprintf("%dh", hours)
	}
	// 使用分钟
	if minutes > 0 {
		return fmt.Sprintf("%dm", minutes)
	}
	// 默认返回1小时
	return "1h"
}

// handleGetAISecurityConfig 获取 AI 安全配置
func (s *Server) handleGetAISecurityConfig(w http.ResponseWriter, r *http.Request) {
	// 将配置转换为前端需要的格式（Duration 转为字符串）
	cfg := s.config.AISecurity

	// 设置默认值
	checkInterval := "1h"
	if cfg.CheckInterval > 0 {
		checkInterval = formatDurationForFrontend(cfg.CheckInterval)
	}

	analysisWindow := "1h"
	if cfg.AnalysisWindow > 0 {
		analysisWindow = formatDurationForFrontend(cfg.AnalysisWindow)
	}

	language := cfg.Language
	if language == "" {
		language = "zh-CN" // 默认中文
	}

	frontendConfig := map[string]interface{}{
		"enabled":          cfg.Enabled,
		"api_key":          cfg.APIKey,
		"api_endpoint":     cfg.APIEndpoint,
		"model":            cfg.Model,
		"check_interval":   checkInterval,
		"max_tokens":       cfg.MaxTokens,
		"temperature":      cfg.Temperature,
		"language":         language,
		"analysis_window":  analysisWindow,
		"min_events":       cfg.MinEvents,
		"notify_on_threat": cfg.NotifyOnThreat,
		"min_threat_level": cfg.MinThreatLevel,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"config":  frontendConfig,
	})
}

// handleSaveAISecurityConfig 保存 AI 安全配置
func (s *Server) handleSaveAISecurityConfig(w http.ResponseWriter, r *http.Request) {
	// 使用中间结构体接收前端数据（string 类型的 duration）
	var frontendConfig struct {
		Enabled        bool    `json:"enabled"`
		APIKey         string  `json:"api_key"`
		APIEndpoint    string  `json:"api_endpoint"`
		Model          string  `json:"model"`
		CheckInterval  string  `json:"check_interval"` // 前端发送字符串，如 "1h"
		MaxTokens      int     `json:"max_tokens"`
		Temperature    float64 `json:"temperature"`
		Language       string  `json:"language"`
		AnalysisWindow string  `json:"analysis_window"` // 前端发送字符串
		MinEvents      int     `json:"min_events"`
		NotifyOnThreat bool    `json:"notify_on_threat"`
		MinThreatLevel string  `json:"min_threat_level"`
	}

	if err := json.NewDecoder(r.Body).Decode(&frontendConfig); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "无效的配置格式: " + err.Error(),
		})
		return
	}

	// 验证配置
	if frontendConfig.Enabled && frontendConfig.APIKey == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "启用 AI 分析时必须提供 API Key",
		})
		return
	}

	// 解析 duration 字符串（支持 d 单位，如 "3d"）
	checkIntervalStr := frontendConfig.CheckInterval
	// 如果包含 "d"（天），转换为小时
	if len(checkIntervalStr) > 1 && checkIntervalStr[len(checkIntervalStr)-1] == 'd' {
		var days int
		if _, err := fmt.Sscanf(checkIntervalStr, "%dd", &days); err == nil {
			checkIntervalStr = fmt.Sprintf("%dh", days*24)
		}
	}
	checkInterval, err := time.ParseDuration(checkIntervalStr)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "无效的检查间隔格式: " + err.Error(),
		})
		return
	}

	analysisWindow := checkInterval // 默认与检查间隔相同
	if frontendConfig.AnalysisWindow != "" {
		// 如果包含 "d"（天），转换为小时
		analysisWindowStr := frontendConfig.AnalysisWindow
		if len(analysisWindowStr) > 1 && analysisWindowStr[len(analysisWindowStr)-1] == 'd' {
			var days int
			if _, err := fmt.Sscanf(analysisWindowStr, "%dd", &days); err == nil {
				analysisWindowStr = fmt.Sprintf("%dh", days*24)
			}
		}
		if parsed, err := time.ParseDuration(analysisWindowStr); err == nil {
			analysisWindow = parsed
		}
	}

	// 构建后端配置结构
	newConfig := config.AISecurityConfig{
		Enabled:        frontendConfig.Enabled,
		APIKey:         frontendConfig.APIKey,
		APIEndpoint:    frontendConfig.APIEndpoint,
		Model:          frontendConfig.Model,
		CheckInterval:  checkInterval,
		MaxTokens:      frontendConfig.MaxTokens,
		Temperature:    frontendConfig.Temperature,
		Language:       frontendConfig.Language,
		AnalysisWindow: analysisWindow,
		MinEvents:      frontendConfig.MinEvents,
		NotifyOnThreat: frontendConfig.NotifyOnThreat,
		MinThreatLevel: frontendConfig.MinThreatLevel,
	}

	// 更新配置
	s.config.AISecurity = newConfig

	// 保存到文件
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		s.log.Errorf("保存配置失败: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "保存配置失败: " + err.Error(),
		})
		return
	}

	// 重新初始化 AI 安全分析器
	s.reinitAISecurityAnalyzer()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "配置保存成功",
	})
}

// handleAISecurityTest 测试 AI API 连接
func (s *Server) handleAISecurityTest(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var testConfig struct {
		APIKey      string `json:"api_key"`
		APIEndpoint string `json:"api_endpoint"`
		Model       string `json:"model"`
	}

	if err := json.NewDecoder(r.Body).Decode(&testConfig); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "无效的请求格式",
		})
		return
	}

	// 创建临时分析器进行测试
	tempConfig := config.AISecurityConfig{
		Enabled:     true,
		APIKey:      testConfig.APIKey,
		APIEndpoint: testConfig.APIEndpoint,
		Model:       testConfig.Model,
		MaxTokens:   100, // 测试时使用少量 tokens
		Temperature: 0.3,
	}

	analyzer := ai.NewSecurityAnalyzer(tempConfig, s.notificationIntegrator)

	// 构建测试请求
	testData := &ai.SecurityData{
		TimeRange:     "测试",
		TotalRequests: 100,
		AttackEvents:  make([]ai.AttackSummary, 0),
	}

	// 测试 API 调用
	startTime := time.Now()

	// 简化测试：直接测试 API 可用性
	result, err := analyzer.AnalyzeWithGPT(testData)
	responseTime := time.Since(startTime).Milliseconds()

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"model":         testConfig.Model,
		"response_time": responseTime,
		"threat_level":  result.ThreatLevel,
	})
}

// handleAISecurityAnalyzeNow 立即执行一次分析
func (s *Server) handleAISecurityAnalyzeNow(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 检查权限
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || (currentUser.Role != RoleSuperAdmin && currentUser.Role != RoleAdmin) {
		http.Error(w, "权限不足", http.StatusForbidden)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.aiSecurityAnalyzer == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "AI 安全分析器未初始化",
		})
		return
	}

	// 创建数据收集器
	dataCollector := ai.NewDataCollector(
		s.ddosProtector,
		s.securityManager,
		s.config.AISecurity.AnalysisWindow,
	)

	// 收集数据
	data := dataCollector.Collect()

	// 执行分析（同步）
	result, err := s.aiSecurityAnalyzer.AnalyzeWithGPT(data)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "分析失败: " + err.Error(),
		})
		return
	}

	// 发送通知（如果需要）
	if s.aiSecurityAnalyzer.ShouldNotify(result) {
		s.aiSecurityAnalyzer.SendNotification(result, data)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"threat_level": result.ThreatLevel,
		"confidence":   result.Confidence,
		"summary":      result.Summary,
		"threats":      len(result.Threats),
	})
}

// reinitAISecurityAnalyzer 重新初始化 AI 安全分析器
func (s *Server) reinitAISecurityAnalyzer() {
	if !s.config.AISecurity.Enabled || s.config.AISecurity.APIKey == "" {
		s.aiSecurityAnalyzer = nil
		s.log.Info("AI 安全分析器已禁用")
		return
	}

	// 设置默认值
	if s.config.AISecurity.AnalysisWindow == 0 {
		s.config.AISecurity.AnalysisWindow = 1 * time.Hour
	}

	// 创建新的分析器
	s.aiSecurityAnalyzer = ai.NewSecurityAnalyzer(s.config.AISecurity, s.notificationIntegrator)

	// 启动定时分析
	dataCollector := ai.NewDataCollector(
		s.ddosProtector,
		s.securityManager,
		s.config.AISecurity.AnalysisWindow,
	)

	s.aiSecurityAnalyzer.Start(dataCollector.Collect)

	s.log.Infof("AI 安全分析器已启动，模型: %s，间隔: %v",
		s.config.AISecurity.Model, s.config.AISecurity.CheckInterval)
}

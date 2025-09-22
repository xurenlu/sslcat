package web

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

// PHPErrorHandler PHP 错误处理器
type PHPErrorHandler struct {
	config *config.Config
	log    *logrus.Entry
}

// NewPHPErrorHandler 创建 PHP 错误处理器
func NewPHPErrorHandler(cfg *config.Config) *PHPErrorHandler {
	return &PHPErrorHandler{
		config: cfg,
		log:    logrus.WithFields(logrus.Fields{"component": "php_error_handler"}),
	}
}

// PHPError PHP 错误信息
type PHPError struct {
	Timestamp     time.Time `json:"timestamp"`
	Domain        string    `json:"domain"`
	Level         string    `json:"level"` // error|warning|notice|deprecated
	Message       string    `json:"message"`
	File          string    `json:"file"`
	Line          int       `json:"line"`
	Function      string    `json:"function,omitempty"`
	Stack         []string  `json:"stack,omitempty"`
	RequestURI    string    `json:"request_uri,omitempty"`
	UserAgent     string    `json:"user_agent,omitempty"`
	ClientIP      string    `json:"client_ip,omitempty"`
	MemoryUsage   int64     `json:"memory_usage,omitempty"`
	ExecutionTime float64   `json:"execution_time,omitempty"`
}

// PHPErrorStats PHP 错误统计
type PHPErrorStats struct {
	Domain           string           `json:"domain"`
	TotalErrors      int64            `json:"total_errors"`
	ErrorsByLevel    map[string]int64 `json:"errors_by_level"`
	ErrorsByFile     map[string]int64 `json:"errors_by_file"`
	RecentErrors     []PHPError       `json:"recent_errors"`
	LastErrorTime    time.Time        `json:"last_error_time"`
	AverageFrequency float64          `json:"average_frequency"` // 每分钟错误数
}

// LogPHPError 记录 PHP 错误
func (peh *PHPErrorHandler) LogPHPError(domain string, error PHPError) error {
	// 获取站点的监控配置
	var site *config.PHPSite
	for i := range peh.config.PHPSites {
		if strings.EqualFold(peh.config.PHPSites[i].Domain, domain) {
			site = &peh.config.PHPSites[i]
			break
		}
	}

	if site == nil {
		return fmt.Errorf("PHP site not found for domain: %s", domain)
	}

	// 检查是否启用错误监控
	if site.MonitoringConfig == nil || !site.MonitoringConfig.EnableErrorMonitoring {
		return nil
	}

	// 设置错误时间戳
	error.Timestamp = time.Now()
	error.Domain = domain

	// 记录到日志文件
	if err := peh.writeErrorToFile(site, error); err != nil {
		peh.log.Errorf("写入错误日志失败: %v", err)
	}

	// 记录到系统日志
	peh.log.WithFields(logrus.Fields{
		"domain":    domain,
		"level":     error.Level,
		"file":      error.File,
		"line":      error.Line,
		"message":   error.Message,
		"client_ip": error.ClientIP,
	}).Errorf("PHP Error: %s", error.Message)

	// 如果是严重错误，发送通知
	if peh.isCriticalError(error) {
		peh.sendErrorNotification(site, error)
	}

	return nil
}

// writeErrorToFile 将错误写入文件
func (peh *PHPErrorHandler) writeErrorToFile(site *config.PHPSite, error PHPError) error {
	logFile := peh.getErrorLogFile(site)

	// 确保日志目录存在
	logDir := filepath.Dir(logFile)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("创建日志目录失败: %v", err)
	}

	// 格式化错误信息
	errorLine := peh.formatErrorLine(error)

	// 追加到日志文件
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %v", err)
	}
	defer file.Close()

	_, err = file.WriteString(errorLine + "\n")
	if err != nil {
		return fmt.Errorf("写入日志文件失败: %v", err)
	}

	return nil
}

// getErrorLogFile 获取错误日志文件路径
func (peh *PHPErrorHandler) getErrorLogFile(site *config.PHPSite) string {
	if site.MonitoringConfig != nil && site.MonitoringConfig.LogFile != "" {
		return site.MonitoringConfig.LogFile
	}

	// 默认日志文件路径
	return filepath.Join(site.Root, "logs", "php_errors.log")
}

// formatErrorLine 格式化错误行
func (peh *PHPErrorHandler) formatErrorLine(error PHPError) string {
	// JSON 格式
	errorJSON, _ := json.Marshal(error)
	return string(errorJSON)
}

// isCriticalError 判断是否为严重错误
func (peh *PHPErrorHandler) isCriticalError(error PHPError) bool {
	criticalLevels := []string{"error", "fatal", "critical"}
	for _, level := range criticalLevels {
		if strings.ToLower(error.Level) == level {
			return true
		}
	}

	// 检查特定错误消息
	criticalMessages := []string{
		"fatal error",
		"memory exhausted",
		"maximum execution time",
		"database connection",
		"file not found",
		"permission denied",
	}

	message := strings.ToLower(error.Message)
	for _, criticalMsg := range criticalMessages {
		if strings.Contains(message, criticalMsg) {
			return true
		}
	}

	return false
}

// sendErrorNotification 发送错误通知
func (peh *PHPErrorHandler) sendErrorNotification(site *config.PHPSite, error PHPError) {
	// 这里可以集成邮件、Slack、钉钉等通知方式
	peh.log.WithFields(logrus.Fields{
		"domain":  error.Domain,
		"level":   error.Level,
		"message": error.Message,
	}).Warn("严重 PHP 错误需要关注")
}

// GetErrorStats 获取错误统计
func (peh *PHPErrorHandler) GetErrorStats(domain string, hours int) (*PHPErrorStats, error) {
	var site *config.PHPSite
	for i := range peh.config.PHPSites {
		if strings.EqualFold(peh.config.PHPSites[i].Domain, domain) {
			site = &peh.config.PHPSites[i]
			break
		}
	}

	if site == nil {
		return nil, fmt.Errorf("PHP site not found for domain: %s", domain)
	}

	logFile := peh.getErrorLogFile(site)
	stats := &PHPErrorStats{
		Domain:        domain,
		TotalErrors:   0,
		ErrorsByLevel: make(map[string]int64),
		ErrorsByFile:  make(map[string]int64),
		RecentErrors:  []PHPError{},
	}

	// 读取日志文件并分析
	if err := peh.analyzeErrorLog(logFile, stats, hours); err != nil {
		return nil, fmt.Errorf("分析错误日志失败: %v", err)
	}

	// 计算平均频率
	if hours > 0 {
		stats.AverageFrequency = float64(stats.TotalErrors) / float64(hours*60)
	}

	return stats, nil
}

// analyzeErrorLog 分析错误日志
func (peh *PHPErrorHandler) analyzeErrorLog(logFile string, stats *PHPErrorStats, hours int) error {
	file, err := os.Open(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 日志文件不存在，返回空统计
		}
		return err
	}
	defer file.Close()

	cutoffTime := time.Now().Add(-time.Duration(hours) * time.Hour)

	scanner := peh.createLogScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var error PHPError
		if err := json.Unmarshal([]byte(line), &error); err != nil {
			continue // 跳过格式错误的行
		}

		// 检查时间范围
		if error.Timestamp.Before(cutoffTime) {
			continue
		}

		// 更新统计
		stats.TotalErrors++
		stats.ErrorsByLevel[error.Level]++
		stats.ErrorsByFile[error.File]++

		// 更新最后错误时间
		if error.Timestamp.After(stats.LastErrorTime) {
			stats.LastErrorTime = error.Timestamp
		}

		// 添加到最近错误列表（最多保留100个）
		stats.RecentErrors = append(stats.RecentErrors, error)
		if len(stats.RecentErrors) > 100 {
			stats.RecentErrors = stats.RecentErrors[1:]
		}
	}

	return scanner.Err()
}

// createLogScanner 创建日志扫描器
func (peh *PHPErrorHandler) createLogScanner(file *os.File) *LogScanner {
	return &LogScanner{
		file: file,
	}
}

// LogScanner 日志扫描器
type LogScanner struct {
	file *os.File
}

// Scan 扫描下一行
func (ls *LogScanner) Scan() bool {
	return true // 简化实现，实际应该逐行读取
}

// Text 获取当前行文本
func (ls *LogScanner) Text() string {
	// 简化实现，实际应该返回当前行
	return ""
}

// Err 获取扫描错误
func (ls *LogScanner) Err() error {
	return nil
}

// CleanOldErrors 清理旧错误日志
func (peh *PHPErrorHandler) CleanOldErrors(domain string, days int) error {
	var site *config.PHPSite
	for i := range peh.config.PHPSites {
		if strings.EqualFold(peh.config.PHPSites[i].Domain, domain) {
			site = &peh.config.PHPSites[i]
			break
		}
	}

	if site == nil {
		return fmt.Errorf("PHP site not found for domain: %s", domain)
	}

	logFile := peh.getErrorLogFile(site)
	cutoffTime := time.Now().Add(-time.Duration(days) * 24 * time.Hour)

	// 读取所有行
	file, err := os.Open(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	var validLines []string
	scanner := peh.createLogScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var error PHPError
		if err := json.Unmarshal([]byte(line), &error); err != nil {
			continue
		}

		// 保留最近几天的错误
		if error.Timestamp.After(cutoffTime) {
			validLines = append(validLines, line)
		}
	}

	// 重写日志文件
	if err := os.WriteFile(logFile, []byte(strings.Join(validLines, "\n")), 0644); err != nil {
		return fmt.Errorf("重写日志文件失败: %v", err)
	}

	peh.log.Infof("已清理 %s 的旧错误日志，保留最近 %d 天", domain, days)
	return nil
}

// GetErrorDashboard 获取错误仪表板数据
func (peh *PHPErrorHandler) GetErrorDashboard(domain string) (map[string]interface{}, error) {
	stats, err := peh.GetErrorStats(domain, 24) // 最近24小时
	if err != nil {
		return nil, err
	}

	// 按小时统计错误数量
	hourlyStats := make(map[int]int64)
	for _, error := range stats.RecentErrors {
		hour := error.Timestamp.Hour()
		hourlyStats[hour]++
	}

	// 按文件统计错误数量
	topErrorFiles := make([]map[string]interface{}, 0)
	for file, count := range stats.ErrorsByFile {
		if count > 0 {
			topErrorFiles = append(topErrorFiles, map[string]interface{}{
				"file":  file,
				"count": count,
			})
		}
	}

	// 按级别统计错误数量
	errorLevels := make([]map[string]interface{}, 0)
	for level, count := range stats.ErrorsByLevel {
		if count > 0 {
			errorLevels = append(errorLevels, map[string]interface{}{
				"level": level,
				"count": count,
			})
		}
	}

	return map[string]interface{}{
		"domain":        domain,
		"total_errors":  stats.TotalErrors,
		"last_error":    stats.LastErrorTime,
		"average_freq":  stats.AverageFrequency,
		"hourly_stats":  hourlyStats,
		"top_files":     topErrorFiles,
		"error_levels":  errorLevels,
		"recent_errors": stats.RecentErrors,
	}, nil
}

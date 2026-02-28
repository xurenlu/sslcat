package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ErrorLogger 错误日志记录器
// 用于记录应用程序错误、PHP错误等
type ErrorLogger struct {
	writer        io.Writer
	file          *os.File
	mutex         sync.Mutex
	enabled       bool
	logPath       string          // 原始日志路径模板（可能包含占位符）
	logPathRaw    string          // 原始日志路径（未解析占位符）
	currentDate   string          // 当前日志文件对应的日期
	maxSize       int64           // 最大文件大小 (字节)
	maxFiles      int             // 最大文件数量
	currentSize   int64
	log           *logrus.Entry
	hasDatePattern bool           // 路径中是否包含日期占位符
}

// NewErrorLogger 创建错误日志记录器
func NewErrorLogger(logPath string, enabled bool) (*ErrorLogger, error) {
	now := time.Now()

	logger := &ErrorLogger{
		enabled:    enabled,
		logPathRaw: logPath,
		maxSize:    100 * 1024 * 1024, // 100MB
		maxFiles:   10,
		log: logrus.WithFields(logrus.Fields{
			"component": "error_logger",
		}),
	}

	// 检查并解析日期占位符
	if enabled && logPath != "" {
		logger.hasDatePattern = containsDatePattern(logPath)
		logger.logPath = logger.expandDatePattern(now)
		logger.currentDate = getCurrentDateKey(now)

		if err := logger.openLogFile(); err != nil {
			return nil, fmt.Errorf("打开错误日志文件失败: %w", err)
		}
	} else {
		logger.writer = os.Stdout
	}

	return logger, nil
}

// openLogFile 打开日志文件
func (e *ErrorLogger) openLogFile() error {
	// 创建日志目录
	dir := filepath.Dir(e.logPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建日志目录失败: %w", err)
	}

	// 打开或创建日志文件
	file, err := os.OpenFile(e.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %w", err)
	}

	// 获取文件大小
	if stat, err := file.Stat(); err == nil {
		e.currentSize = stat.Size()
	}

	e.file = file
	e.writer = file
	return nil
}

// expandDatePattern 展开日期占位符（复用 access.go 的逻辑）
func (e *ErrorLogger) expandDatePattern(t time.Time) string {
	path := e.logPathRaw

	// 先处理 Go 风格占位符
	replacements := []struct {
		pattern string
		value   string
	}{
		{goDatePatternDateTime, t.Format("2006-01-02_15-04-05")},
		{goDatePatternDate, t.Format("2006-01-02")},
		{goDatePatternTime, t.Format("15:04:05")},
		{goDatePatternYear, t.Format("2006")},
		{goDatePatternYear2, t.Format("06")},
		{goDatePatternMonth, t.Format("01")},
		{goDatePatternMonthN, t.Format("1")},
		{goDatePatternDay, t.Format("02")},
		{goDatePatternDayN, t.Format("2")},
		{goDatePatternHour, t.Format("15")},
		{goDatePatternHourN, t.Format("3")},
		{goDatePatternMinute, t.Format("04")},
		{goDatePatternMinuteN, t.Format("4")},
		{goDatePatternSecond, t.Format("05")},
		{goDatePatternSecondN, t.Format("5")},
	}

	for _, repl := range replacements {
		path = strings.ReplaceAll(path, repl.pattern, repl.value)
	}

	// 处理 strftime 风格占位符（nginx 兼容）
	strftimeReplacements := []struct {
		pattern string
		value   string
	}{
		{datePatternYear, t.Format("2006")},
		{datePatternMonth, t.Format("01")},
		{datePatternDay, t.Format("02")},
		{datePatternHour, t.Format("15")},
		{datePatternMinute, t.Format("04")},
		{datePatternSecond, t.Format("05")},
		{datePatternTime, fmt.Sprintf("%d", t.Unix())},
	}

	for _, repl := range strftimeReplacements {
		path = strings.ReplaceAll(path, repl.pattern, repl.value)
	}

	return path
}

// checkDateRotation 检查是否需要按日期轮转日志文件
func (e *ErrorLogger) checkDateRotation() error {
	if !e.hasDatePattern {
		return nil
	}

	now := time.Now()
	newDate := getCurrentDateKey(now)

	if newDate != e.currentDate {
		e.log.Infof("日期已变更，切换错误日志文件: %s -> %s", e.currentDate, newDate)

		// 关闭当前文件
		if e.file != nil {
			e.file.Close()
			e.file = nil
		}

		// 更新日期和路径
		e.currentDate = newDate
		newPath := e.expandDatePattern(now)

		// 如果路径发生变化，需要重新打开文件
		if newPath != e.logPath {
			e.logPath = newPath
			e.currentSize = 0
			return e.openLogFile()
		}
	}

	return nil
}

// rotateLogFile 按大小轮转日志文件
func (e *ErrorLogger) rotateLogFile() error {
	if e.file == nil {
		return nil
	}

	// 关闭当前文件
	e.file.Close()

	// 重命名当前文件
	timestamp := time.Now().Format("20060102-150405")
	rotatedPath := fmt.Sprintf("%s.%s", e.logPath, timestamp)
	if err := os.Rename(e.logPath, rotatedPath); err != nil {
		e.log.Errorf("重命名错误日志文件失败: %v", err)
	}

	// 清理旧文件
	go e.cleanOldFiles()

	// 重新打开新文件
	e.currentSize = 0
	return e.openLogFile()
}

// cleanOldFiles 清理旧的日志文件
func (e *ErrorLogger) cleanOldFiles() {
	dir := filepath.Dir(e.logPath)
	filename := filepath.Base(e.logPath)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	var logFiles []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), filename+".") {
			logFiles = append(logFiles, filepath.Join(dir, entry.Name()))
		}
	}

	// 按修改时间排序并删除多余的文件
	if len(logFiles) > e.maxFiles {
		for i := 0; i < len(logFiles)-e.maxFiles; i++ {
			os.Remove(logFiles[i])
		}
	}
}

// LogError 记录错误日志
func (e *ErrorLogger) LogError(level string, message string, fields map[string]interface{}) {
	if !e.enabled {
		return
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	// 检查日期变化（如果有日期占位符）
	if err := e.checkDateRotation(); err != nil {
		e.log.Errorf("日期轮转检查失败: %v", err)
	}

	// 构建日志行
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logLine := fmt.Sprintf("[%s] [%s] %s", timestamp, strings.ToUpper(level), message)

	// 添加额外字段
	if len(fields) > 0 {
		logLine += " "
		for k, v := range fields {
			logLine += fmt.Sprintf("%s=%v ", k, v)
		}
	}

	// 写入日志
	if _, err := fmt.Fprintln(e.writer, logLine); err != nil {
		e.log.Errorf("写入错误日志失败: %v", err)
		return
	}

	// 更新文件大小
	e.currentSize += int64(len(logLine) + 1)

	// 检查是否需要按大小轮转（不包含日期占位符的路径才需要大小轮转）
	if !e.hasDatePattern && e.file != nil && e.currentSize > e.maxSize {
		if err := e.rotateLogFile(); err != nil {
			e.log.Errorf("轮转错误日志文件失败: %v", err)
		}
	}
}

// LogPHPError 记录 PHP 错误
func (e *ErrorLogger) LogPHPError(domain, level, message, file string, line int) {
	fields := map[string]interface{}{
		"domain": domain,
		"type":   "php_error",
		"file":   file,
		"line":   line,
	}
	e.LogError(level, message, fields)
}

// LogApplicationError 记录应用程序错误
func (e *ErrorLogger) LogApplicationError(component, message string, err error) {
	fields := map[string]interface{}{
		"component": component,
		"type":      "app_error",
	}
	if err != nil {
		fields["error"] = err.Error()
	}
	e.LogError("error", message, fields)
}

// Close 关闭日志记录器
func (e *ErrorLogger) Close() error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.file != nil {
		return e.file.Close()
	}
	return nil
}

// SetMaxSize 设置最大文件大小（字节）
func (e *ErrorLogger) SetMaxSize(size int64) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	if size > 0 {
		e.maxSize = size
	}
}

// SetMaxFiles 设置最大保留文件数
func (e *ErrorLogger) SetMaxFiles(n int) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	if n > 0 {
		e.maxFiles = n
	}
}

// GetStats 获取日志统计信息
func (e *ErrorLogger) GetStats() map[string]interface{} {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	stats := map[string]interface{}{
		"enabled":       e.enabled,
		"log_path":      e.logPathRaw,
		"current_path":  e.logPath,
		"current_size":  e.currentSize,
		"max_size":      e.maxSize,
		"max_files":     e.maxFiles,
		"has_date_pattern": e.hasDatePattern,
		"current_date":  e.currentDate,
	}

	if e.file != nil {
		if stat, err := e.file.Stat(); err == nil {
			stats["file_modified"] = stat.ModTime()
		}
	}

	return stats
}

// Reload 重新加载日志文件（用于配置更新）
func (e *ErrorLogger) Reload(newLogPath string, enabled bool) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	// 关闭当前文件
	if e.file != nil {
		e.file.Close()
		e.file = nil
	}

	// 更新配置
	e.enabled = enabled
	e.logPathRaw = newLogPath

	if !enabled || newLogPath == "" {
		e.writer = os.Stdout
		e.hasDatePattern = false
		return nil
	}

	now := time.Now()
	e.hasDatePattern = containsDatePattern(newLogPath)
	e.logPath = e.expandDatePattern(now)
	e.currentDate = getCurrentDateKey(now)

	// 重新打开文件
	e.currentSize = 0
	return e.openLogFile()
}
